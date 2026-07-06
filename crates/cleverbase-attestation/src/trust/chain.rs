//! X.509 certification-path validation against trusted anchors (RFC 5280 §6.1; research D5, no
//! hand-rolled crypto).
//!
//! Trust anchoring asks one question: does the credential's signing certificate (the mdoc
//! `IssuerAuth` x5chain leaf or the SD-JWT VC JWS `x5c` leaf) **chain to** a certificate that the
//! configured trust anchor lists for the credential's role/format? This module answers it by
//! reusing the SDK's vetted X.509 stack — `x509-cert` for parsing, `p256`/`ecdsa` + `rsa` for the
//! signature math, `sha2` for the digest — and never hand-rolls crypto (Principle IV / research D1).
//!
//! ## Multi-tier path validation (RFC 5280 §6.1)
//!
//! A credential carries its full signing chain leaf-first: `x5c` / `x5chain = [leaf, intermediate₁,
//! …]`. eIDAS QTSP / EUDI issuer PKIs commonly issue the leaf from an **intermediate sub-CA** that
//! itself chains to the trust-list-pinned root (RFC 5280 permits a path length > 1; ETSI EN 319
//! 411), so a one-hop "anchor must directly issue the leaf" check would **false-reject** a conformant
//! credential. [`verify_chain`] therefore builds and validates a certification path
//! `leaf → intermediate₁ → … → a CONFIGURED ANCHOR` over the **supplied** chain plus the configured
//! anchors, enforcing the §6.1 rules at every hop:
//!
//! - **name chaining (§6.1.3 (a)(4))** — each certificate's `issuer` equals the next-up certificate's
//!   `subject`;
//! - **signature (§6.1.3 (a)(1))** — each certificate's signature verifies under the next-up
//!   certificate's subject public key;
//! - **validity (§6.1.3 (a)(2))** — **every** certificate on the path (leaf, each intermediate, and
//!   the terminating anchor) is within its own `notBefore..notAfter` window at the relevant time;
//! - **CA constraints (§6.1.4 (k)/(n), §4.2.1.9, §4.2.1.3)** — every certificate that **issues** the
//!   next one down (each intermediate and the anchor) is a CA: `basicConstraints` present, **marked
//!   critical**, `cA=TRUE`, and (when `keyUsage` is present) the `keyCertSign` bit set;
//! - **path length (§6.1.4 (m), §4.2.1.9)** — an issuing CA's `pathLenConstraint`, when present,
//!   bounds the number of intermediates that may follow it toward the leaf.
//!
//! The supplied intermediates are **attacker-controlled** path-building material: they are honoured
//! only as candidate issuers and the path is trusted **iff it terminates at a configured anchor**.
//! An attacker who supplies arbitrary intermediates that never reach a trusted anchor is rejected
//! ([`ChainError::IssuerMismatch`] / `SignatureInvalid`), so an attacker cannot manufacture trust by
//! presenting their own chain. The path length is also capped ([`MAX_PATH_LEN`]) so an absurdly long
//! supplied chain cannot turn validation into a denial-of-service.
//!
//! ## Direct pin
//!
//! The matcher also accepts an exact DER-equal certificate (a trusted-list entry that pins a specific
//! certificate — the leaf, or one of the supplied certs — directly). The direct-pin path still
//! enforces that pinned certificate's validity window (an expired pinned cert is rejected, never
//! trusted) but is deliberately **exempt from the CA constraint**: pinning a specific end-entity
//! certificate as trusted is an intentional, distinct trust model.

use der::{Decode as _, Encode as _};
use x509_cert::Certificate;

use crate::types::IssuerRole;

/// The role/format-appropriate **key purpose** the leaf (the credential's signing certificate) must
/// carry — enforced once, on the leaf, before the path walk, so a genuinely-chained-but-WRONG-PURPOSE
/// leaf is rejected (e.g. a TLS `serverAuth` cert issued under the same trusted root, or an mdoc DS
/// cert presented as the SD-JWT VC issuer leaf).
///
/// A chain that validates structurally (name/signature/CA/validity) is **not** sufficient: RFC 5280
/// and the format profiles constrain *what the leaf may be used for*. The verifier threads the
/// credential's format here (mdoc → [`Self::MdocDocumentSigner`], SD-JWT VC →
/// [`Self::SdJwtVcIssuer`]); the trust-list-signer-authentication call sites (the LOTL / national-TL
/// signer in `trust::xml` and `qualified`) pass [`Self::TrustListSigner`], which imposes no
/// credential-leaf purpose (a TL signer is governed by a different ETSI profile, not the credential
/// leaf profiles below).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeafPurpose {
    /// **ISO/IEC 18013-5:2021 Annex B (Table B.3, mDL document signer certificate).** The Document
    /// Signer leaf MUST satisfy the full Table B.3 leaf profile (verified online against the ISO DIS
    /// Table B.3 text + the auth0-lab/mdl and spruceid/isomdl reference verifiers):
    ///
    /// - `extendedKeyUsage` (Table B.3 row `m`, RFC 5280 §4.2.1.12) MUST include the mDL-DS key-purpose
    ///   OID `id-mso-mdl-DS` = `1.0.18013.5.1.2` ([`OID_MDL_DS`]). ISO marks the EKU row `m` (not `mc`),
    ///   and §4.2.1.12 leaves EKU criticality at the issuer's option, so criticality is not asserted —
    ///   only the OID's presence;
    /// - `keyUsage` (Table B.3 row **`mc`** = mandatory + critical) MUST assert `digitalSignature`. ISO
    ///   fixes the DS keyUsage to `digitalSignature` only; this guard requires the `digitalSignature`
    ///   bit (a `keyUsage` without it — present or absent — is rejected);
    /// - `basicConstraints` (Table B.3 row **`mc`**, §4.2.1.9) MUST be `cA=FALSE`. A DS leaf that asserts
    ///   `cA=TRUE` (so it could double as an issuing CA) is rejected even when it carries the mdlDS EKU.
    ///
    /// A DS leaf lacking the mdlDS EKU (or carrying only a foreign purpose such as `serverAuth`),
    /// lacking the `digitalSignature` keyUsage, or asserting `cA=TRUE`, is rejected
    /// ([`ChainError::WrongLeafPurpose`]). (No eIDAS QcStatement is required of an mdoc DS leaf — that is
    /// an ETSI/eIDAS concept for the SD-JWT VC issuer cert, see [`Self::SdJwtVcIssuer`].)
    MdocDocumentSigner,
    /// **SD-JWT VC issuer (PID / (Q)EAA) leaf**, keyed by the credential's [`IssuerRole`]. No governing
    /// specification mandates a specific EKU for the SD-JWT VC issuer certificate referenced by the JWS
    /// `x5c` (verified online: IETF `draft-ietf-oauth-sd-jwt-vc` §2.5 / RFC 9901 are silent on
    /// EKU/keyUsage; OpenID4VC HAIP 1.0 §6.1.1 mandates only chain-to-anchor structure; the EUDI ARF /
    /// Commission IRs distinguish issuer certs by **QcStatement** OIDs and `keyUsage`, never by an EKU;
    /// ETSI EN 319 412-2 §4.3.10 even forbids marking EKU critical and assigns no EKU value). The
    /// enforced policy is therefore two layered checks:
    ///
    /// 1. **The EN 319 412-2/-3 base-profile floor (every role).** The leaf **MUST NOT be a CA**
    ///    (`basicConstraints cA=TRUE` is rejected — a CA certificate must not double as an end-entity
    ///    signer), and a `keyUsage` extension **MUST be present** and assert a signing bit
    ///    (`digitalSignature` or `nonRepudiation`/content-commitment). ETSI EN 319 412-2 §4.3.2
    ///    (`NAT-4.3.2-1`) / EN 319 412-3 §4.3.1 (`LEG-4.3.1-2`, pulling in 412-2 §4.3.2 ¶1 + Table 1)
    ///    make keyUsage **SHALL-present**, and a content/seal-signing certificate is limited to keyUsage
    ///    Type A/B/F — each of which asserts a signing bit (verified online against the ETSI PDFs). So an
    ///    **absent** keyUsage is now rejected (tightened from the prior "absent allowed"), as is a present
    ///    keyUsage asserting only unrelated bits (e.g. `keyEncipherment` only). No EKU is required.
    /// 2. **The per-role eIDAS QcStatement check** (`leaf_has_required_qc_statements`). Under
    ///    chain-to-root anchoring, a plain eSeal/EAA certificate sharing a QTSP root would otherwise be
    ///    trusted as a PID/QEAA (conformance-audit T1.3); the in-band guard requires the role-appropriate
    ///    ETSI `qcStatements` (RFC 3739 ext OID `1.3.6.1.5.5.7.1.3`): **PID** → the `QcType` statement
    ///    carrying `id-etsi-qct-pid` (`0.4.0.194126.1.1`, ETSI TS 119 412-6 PID-4.5-01); **QEAA** →
    ///    `QcCompliance` (`0.4.0.1862.1.1`) **and** a `QcType` carrying `id-etsi-qct-esign`/`-eseal`
    ///    (`0.4.0.1862.1.6.{1,2}`, EN 319 412-5 §4.2 + TS 119 412-6 QEA-7.1); **PuB-EAA** → the `QcPSB`
    ///    statement (`id-etsi-qcs-QcPSB`, TS 119 412-6 PSB-8.3-01); **NonQualifiedEAA** → no Qc
    ///    requirement (EAA-6.x impose none). A leaf lacking the role's required statement is
    ///    [`ChainError::WrongLeafPurpose`]. (mdoc DS leaves are NOT subject to this — they follow the ISO
    ///    18013-5 Annex B profile, which assigns no QcStatement; see [`Self::MdocDocumentSigner`].)
    SdJwtVcIssuer(IssuerRole),
    /// **Trust-list signer authentication** (the LOTL / national Trusted List signer, not a credential
    /// leaf). Imposes no credential-leaf key-purpose constraint — the only requirement is that the
    /// signer chains to a configured scheme-operator anchor (the structural §6.1 path). Used by
    /// `trust::xml` and `qualified` when authenticating a signed trust list.
    TrustListSigner,
}

/// The ISO/IEC 18013-5 mDL Document Signer extended-key-usage OID `id-mso-mdl-DS`
/// (`{iso(1) standard(0) driving-licence(18013) part-5(5) kp(1) mdlDS(2)}`). A conformant mdoc DS leaf
/// MUST list this OID in its `extendedKeyUsage` (ISO/IEC 18013-5:2021 Annex B, Table B.3); it is the
/// purpose [`LeafPurpose::MdocDocumentSigner`] enforces.
pub const OID_MDL_DS: &str = "1.0.18013.5.1.2";

/// The PKIX `qcStatements` certificate-extension OID `id-pe-qcStatements` (`1.3.6.1.5.5.7.1.3`, RFC
/// 3739 §3.2.6). A `SEQUENCE OF QCStatement`, each `{ statementId OID, statementInfo ANY OPTIONAL }`.
/// The ETSI per-role guard ([`leaf_has_required_qc_statements`]) reads it on the SD-JWT VC issuer leaf.
/// EN 319 412-5 QCS-4.1-02 requires the extension be **non-critical**, so it is never marked critical.
const OID_QC_STATEMENTS: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.3");

/// `id-etsi-qcs-QcCompliance` (`0.4.0.1862.1.1`, ETSI EN 319 412-5 §4.2.1, `esi4-qcStatement-1`): the
/// certificate is an **EU qualified certificate**. Required (with a `QcType`) on a QEAA issuer leaf.
const OID_ETSI_QCS_QC_COMPLIANCE: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("0.4.0.1862.1.1");

/// `id-etsi-qcs-QcType` (`0.4.0.1862.1.6`, ETSI EN 319 412-5 §4.2.3, `esi4-qcStatement-6`): the
/// `statementInfo` is a `QcType ::= SEQUENCE OF OBJECT IDENTIFIER` listing the qualified-type OIDs.
const OID_ETSI_QCS_QC_TYPE: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("0.4.0.1862.1.6");

/// `id-etsi-qct-esign` (`0.4.0.1862.1.6.1`): QcType for an electronic-**signature** (natural-person)
/// qualified certificate (ETSI EN 319 412-5 §4.2.3). One of the QEAA-acceptable QcType values.
const OID_ETSI_QCT_ESIGN: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("0.4.0.1862.1.6.1");

/// `id-etsi-qct-eseal` (`0.4.0.1862.1.6.2`): QcType for an electronic-**seal** (legal-person) qualified
/// certificate (ETSI EN 319 412-5 §4.2.3). The QcType an EU-QC legal-person QEAA issuer carries.
const OID_ETSI_QCT_ESEAL: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("0.4.0.1862.1.6.2");

/// `id-etsi-qct-pid` (`0.4.0.194126.1.1`, ETSI TS 119 412-6 V1.1.1 Annex A, the eIDAS-2 `194126` arc):
/// the QcType value a **PID provider** certificate SHALL carry (requirement PID-4.5-01).
const OID_ETSI_QCT_PID: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("0.4.0.194126.1.1");

/// `id-etsi-qcs-QcPSB` (`0.4.0.1862.1.10`, `esi4-qcStatement-10`): the qcStatement that marks a
/// **public-body EAA** (PuB-EAA / PSBEAA, eIDAS Art. 45f) issuer (ETSI TS 119 412-6 PSB-8.3-01). NOTE:
/// TS 119 412-6 V1.1.1 references `id-etsi-qcs-QcPSB` by name (`esi4-qcStatement-10`) but its Annex A
/// does not print the literal dotted assignment, and EN 319 412-5 (through the V2.6.0 draft) stops at
/// statement-9; the `.10` value is derived from ETSI's consistent `esi4-qcStatement-N → { id-etsi-qcs
/// N }` convention (verified online — flagged as convention-derived, not literally quoted normative).
const OID_ETSI_QCS_QC_PSB: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("0.4.0.1862.1.10");

/// Why a candidate issuer certificate failed to chain to a trusted anchor.
///
/// Every rejection carries a specific reason so an untrusted verdict is never opaque. `resolve_chain`
/// folds these to a coarse-but-accurate [`crate::trust::TrustFailure`] on the [`crate::trust::TrustDecision`],
/// which the verifier maps to a [`crate::types::ReasonCode`]: [`Self::LeafExpired`]/[`Self::AnchorExpired`]
/// (a cert outside its validity window) → [`crate::types::ReasonCode::Expired`]; every other variant (no
/// path, bad signature, non-CA, wrong leaf purpose, unsupported algorithm, malformed, over-long) →
/// [`crate::types::ReasonCode::UntrustedIssuer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// A certificate (leaf, supplied intermediate, or anchor) could not be parsed as DER X.509.
    Malformed(String),
    /// No path could be built: at some hop the current certificate's `issuer` name matched no
    /// candidate issuer's `subject` (neither a supplied intermediate nor a configured anchor), so the
    /// path does not reach a trusted anchor. Also returned when the supplied chain is empty.
    IssuerMismatch,
    /// A certificate's signature did not verify under the name-matching candidate issuer's public key
    /// at some hop on the path (a supplied intermediate or a configured anchor whose subject matched
    /// but whose key did not produce the signature).
    SignatureInvalid,
    /// The supplied certification path is longer than [`MAX_PATH_LEN`] hops — rejected to bound the
    /// validation work an attacker-supplied chain can demand (a denial-of-service guard).
    PathTooLong,
    /// A certificate on the path carries a signature algorithm the SDK does not implement (outside the
    /// EUDI baseline: ES256/384/512 + RSA-PKCS#1v1.5 over SHA-256/384/512).
    UnsupportedAlgorithm(String),
    /// The leaf is outside its own validity window at the relevant time.
    LeafExpired,
    /// An issuing certificate on the path (an intermediate sub-CA or the terminating anchor) is itself
    /// outside its own validity window at the relevant time. Per RFC 5280 §6.1.3 (a)(2) **every**
    /// certificate in the path — each issuing CA included — must be valid at the validation time, so
    /// an expired (or not-yet-valid) intermediate/anchor cannot vouch for an otherwise-in-window
    /// certificate below it.
    AnchorExpired,
    /// An issuing certificate on the path (an intermediate sub-CA or the terminating anchor) does not
    /// assert the CA constraints required to issue certificates: per RFC 5280 §6.1.4 (k)/(n) and
    /// §4.2.1.9 an issuer MUST carry `basicConstraints` **marked critical** with `cA=TRUE`, (when
    /// `keyUsage` is present) the `keyCertSign` bit, and a `pathLenConstraint` (if present) wide enough
    /// for the intermediates that follow it. This closes the "any cert is a CA" gap — a non-CA
    /// (end-entity) certificate cannot act as a path intermediate or anchor. (The direct-pin path,
    /// where the configured anchor *is* the pinned certificate, is exempt: pinning a specific
    /// end-entity certificate as trusted is an intentional, distinct model.)
    NotACa,
    /// The leaf (the credential's signing certificate) does not carry the role/format-appropriate
    /// **key purpose** required by [`LeafPurpose`], so it is genuinely chained to a trusted anchor but
    /// **not fit for the purpose presented**:
    ///
    /// - an **mdoc Document Signer** leaf lacking the mdlDS EKU (`1.0.18013.5.1.2`), carrying a foreign
    ///   purpose (e.g. TLS `serverAuth`), lacking the `digitalSignature` keyUsage, or asserting
    ///   `cA=TRUE` (ISO/IEC 18013-5:2021 Annex B Table B.3, the `mc` keyUsage / basicConstraints rows);
    /// - an **SD-JWT VC issuer** leaf that is a CA, that has no (or a non-signing) `keyUsage` (ETSI EN
    ///   319 412-2/-3 require keyUsage present asserting a signing bit), or that lacks the per-role
    ///   eIDAS **QcStatement** its [`IssuerRole`] requires (PID → `id-etsi-qct-pid`; QEAA →
    ///   `QcCompliance` + a qualified `QcType`; PuB-EAA → `QcPSB`) — the in-band guard that closes the
    ///   chain-to-root false-trust where a plain eSeal/EAA cert sharing a QTSP root would be trusted as
    ///   PID/QEAA (conformance-audit T1.3).
    ///
    /// This closes the "right chain, wrong purpose" false-accept. Fail-closed on a malformed/duplicate
    /// `extendedKeyUsage` / `keyUsage` / `basicConstraints` / `qcStatements` extension.
    WrongLeafPurpose,
    /// A certificate on the processed path (the leaf or an intermediate — never the trust anchor itself,
    /// which RFC 5280 §6.1.1 treats as an input, not a path certificate) carries an extension marked
    /// **critical** whose OID this validator does not recognize/process, so per RFC 5280 §6.1.4 (o) /
    /// §6.1.5 (f) (and the §4.2 / §6 "MUST reject the certificate if it encounters a critical extension
    /// it does not recognize") the path is rejected fail-closed. The recognized critical extensions are
    /// `basicConstraints`, `keyUsage`, `extendedKeyUsage`, `nameConstraints`, and `subjectAltName`;
    /// carries the offending OID for diagnostics.
    UnsupportedCriticalExtension(String),
    /// A certificate on the processed path violates the RFC 5280 §4.2.1.10 **name constraints** imposed
    /// by a CA above it: its subject DN (or a `subjectAltName` entry) falls outside the accumulated
    /// `permitted_subtrees`, or inside an `excluded_subtrees` (§6.1.3 (b)/(c), §6.1.4 (g)). Also returned
    /// fail-closed when a CA imposes a name-constraint on a `GeneralName` type this validator does not
    /// enforce (only `directoryName` and `dNSName` subtrees are processed; any other constraint type, or
    /// a non-default `minimum`/`maximum` `BaseDistance`, is treated as unsupported → reject).
    NameConstraintViolation,
    /// A certificate's outer `signatureAlgorithm` (RFC 5280 §4.1.1.2) does not equal the inner
    /// `tbsCertificate.signature` algorithm identifier (§4.1.2.3) it is required to match — a malformed
    /// or tampered certificate (the unsigned outer field was substituted), rejected fail-closed.
    SignatureAlgorithmMismatch,
}

/// The maximum certification-path length [`verify_chain`] will validate, expressed as the cap on the
/// per-branch `hops` counter: a branch may promote at most `MAX_PATH_LEN` = **8** intermediate
/// certificates between the leaf and the terminating anchor. The anchor is reached at the head of a
/// `walk` frame (the direct-pin / issued-by-anchor termination) and is **not** counted as a hop, so the
/// longest path this admits is `leaf → up to 8 intermediates → anchor`. RFC 5280 places no hard ceiling
/// on path length, but the EUDI / eIDAS PKIs in scope are shallow (root → at most a small handful of
/// sub-CAs → leaf), so this small cap rejects an absurdly long **attacker-supplied** chain — bounding
/// the validation work it can demand — without rejecting any conformant credential.
pub const MAX_PATH_LEN: usize = 8;

/// A hard ceiling on the **total** number of issued-by ATTEMPTS (the dominant per-candidate
/// signature-verify work) the backtracking path-walk will perform across the whole search, independent
/// of the per-branch [`MAX_PATH_LEN`] depth cap.
///
/// The walk **backtracks** over candidate issuers, so when an attacker supplies many intermediates that
/// all name-match each other (e.g. dozens of mutually-issuing self-issued certs / cross-certificates),
/// the depth-bounded DFS could otherwise explore a combinatorial (worst-case factorial) number of
/// branches — an attacker-multiplied denial-of-service the depth cap alone does not bound. This global
/// budget bounds the total verify work to a fixed ceiling: a conformant credential reaches its anchor
/// after at most a handful of attempts (≤ [`MAX_PATH_LEN`] hops × the few configured anchors +
/// supplied intermediates), far under this budget, so it is never rejected; an adversarial branchy
/// chain that would blow up is cut off as [`ChainError::PathTooLong`]. The value is generous (thousands
/// of attempts) so only a genuinely pathological supplied chain can hit it.
const MAX_NODE_VISITS: u32 = 4096;

impl core::fmt::Display for ChainError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed(e) => write!(f, "certificate is not valid DER X.509: {e}"),
            Self::IssuerMismatch => write!(
                f,
                "certification path does not reach a trusted anchor (an issuer name matched no candidate)"
            ),
            Self::SignatureInvalid => {
                write!(f, "a certificate signature did not verify under its issuer on the path")
            }
            Self::PathTooLong => write!(
                f,
                "certification path exceeds the maximum permitted length ({MAX_PATH_LEN} certificates)"
            ),
            Self::UnsupportedAlgorithm(oid) => {
                write!(f, "unsupported certificate signature algorithm: {oid}")
            }
            Self::LeafExpired => write!(f, "leaf certificate is outside its validity window"),
            Self::AnchorExpired => {
                write!(f, "issuing anchor is outside its own validity window")
            }
            Self::NotACa => write!(
                f,
                "issuing anchor is not a CA (basicConstraints cA=TRUE / keyUsage keyCertSign required)"
            ),
            Self::WrongLeafPurpose => write!(
                f,
                "leaf certificate lacks the required key purpose for its role/format (e.g. mdoc DS EKU id-mso-mdl-DS / digitalSignature / cA=FALSE, or an SD-JWT VC issuer that is a CA, has no signing keyUsage, or lacks its role's eIDAS QcStatement)"
            ),
            Self::UnsupportedCriticalExtension(oid) => write!(
                f,
                "certificate carries an unrecognized critical extension this validator cannot process: {oid}"
            ),
            Self::NameConstraintViolation => write!(
                f,
                "a certificate's subject/SAN violates a CA's RFC 5280 name constraints (outside permitted, inside excluded, or an unsupported constraint type)"
            ),
            Self::SignatureAlgorithmMismatch => write!(
                f,
                "certificate outer signatureAlgorithm does not match the inner tbsCertificate.signature algorithm"
            ),
        }
    }
}

impl std::error::Error for ChainError {}

/// The supported certificate signature algorithms — the EUDI cryptographic baseline (HAIP 1.0 §7;
/// ECCG Agreed Cryptographic Mechanisms v2; ARF Annex 2).
///
/// The mandatory baseline is **ES256** (ECDSA / P-256 / SHA-256) for both formats, with RSA-PKCS#1
/// v1.5 over SHA-256/384/512 allowed. The SDK's vendored EC stack is P-256 (research D1), so
/// ES384/512 (which use P-384/P-521) surface as [`ChainError::UnsupportedAlgorithm`] — an honest
/// "not implemented", never a silent accept; they are deferrable until a Member-State profile needs
/// them (a new curve crate, not hand-rolled crypto). EdDSA is likewise deferred (outside the
/// mandatory baseline).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SigAlg {
    EcdsaP256Sha256,
    RsaSha256,
    RsaSha384,
    RsaSha512,
}

impl SigAlg {
    /// Classify an X.509 `AlgorithmIdentifier` OID against the supported baseline.
    fn from_oid(oid: der::asn1::ObjectIdentifier) -> Result<Self, ChainError> {
        use const_oid::db::rfc5912;
        Ok(match oid {
            x if x == rfc5912::ECDSA_WITH_SHA_256 => Self::EcdsaP256Sha256,
            x if x == rfc5912::SHA_256_WITH_RSA_ENCRYPTION => Self::RsaSha256,
            x if x == rfc5912::SHA_384_WITH_RSA_ENCRYPTION => Self::RsaSha384,
            x if x == rfc5912::SHA_512_WITH_RSA_ENCRYPTION => Self::RsaSha512,
            other => return Err(ChainError::UnsupportedAlgorithm(other.to_string())),
        })
    }
}

/// Whether the supplied certification path `supplied_chain` (leaf-first: `[leaf, intermediate₁, …]`)
/// builds a valid RFC 5280 §6.1 path to **any** of the trusted `anchor_certs_der`, with the leaf
/// carrying the `leaf_purpose`-appropriate key purpose.
///
/// ## Two validation times — the DS-validity-at-signing-time seam (ISO/IEC 18013-5 §9.3.1)
///
/// `now_unix` is the verification instant the **chain authentication** is checked at (each intermediate
/// and the terminating anchor must be within its own validity window at `now_unix` — RFC 5280 §6.1.3
/// (a)(2)). `leaf_validity_time` is the (optional) instant the **leaf's own** validity window is checked
/// at:
///
/// - **`None`** — the leaf window is checked at `now_unix` (the SD-JWT VC issuer leaf, the trust-list
///   signer: there is no distinct signing instant, so "now" is the right time);
/// - **`Some(t)`** — the leaf window is checked at `t` while the rest of the chain stays at `now_unix`.
///   ISO/IEC 18013-5 §9.3.1 requires the mdoc **Document Signer** certificate window to contain the MSO
///   `validityInfo.signed` time, not "now": DS certs rotate (~monthly) while mDLs live for years, so a
///   conformant mDL would be **false-rejected** at `now` once its DS cert expired even though it was
///   valid when it signed. The mdoc verifier passes `Some(mso.validityInfo.signed)` here (confirmed
///   online against auth0-lab/mdl `Verifier.ts`, which checks the DS window against `validityInfo.signed`
///   and the MSO's own `validFrom`/`validUntil` against the verification clock separately).
///
/// ## What is enforced
///
/// A path is trusted iff, starting from the leaf (`supplied_chain[0]`), it can be walked up — through
/// zero or more of the supplied intermediates — to a certificate that **is** a configured anchor (a
/// direct DER-equal pin) or is **issued by** a configured anchor, enforcing:
///
/// - **leaf key purpose** — the leaf carries the role/format-appropriate purpose required by
///   [`LeafPurpose`] (mdoc DS Table B.3 profile; SD-JWT VC issuer base floor + per-role QcStatement),
///   else [`ChainError::WrongLeafPurpose`]. Checked once, on the leaf, before the walk;
/// - **direct pin** — a cert byte-equal to a configured anchor terminates the path as trusted, still
///   subject to that cert's own validity window (an expired pinned cert is [`ChainError::LeafExpired`],
///   never trusted), but exempt from the CA / key-purpose / name-constraint / critical-extension checks
///   (pinning a specific certificate is a deliberate trust model, and a configured anchor is an RFC 5280
///   §6.1.1 trust-anchor input, not a processed path certificate);
/// - **issued-by** — the child's `issuer` equals the issuer's `subject`, the child's outer/inner
///   signature algorithms agree ([`ChainError::SignatureAlgorithmMismatch`]), the child's signature
///   verifies under the issuer's subject public key, the issuer is a CA ([`ChainError::NotACa`]
///   otherwise), and the issuer is within its validity window at `now_unix`
///   ([`ChainError::AnchorExpired`] otherwise);
/// - **name constraints + critical extensions** (`enforce_path_constraints`) — once a path reaches an
///   anchor, the processed certificates (leaf + intermediates, **not** the trust anchor) are walked
///   top-down: each is rejected if it carries an unrecognized **critical** extension
///   ([`ChainError::UnsupportedCriticalExtension`], RFC 5280 §6.1.4 (o) / §6.1.5 (f)), and each subject
///   DN / SAN is checked against the `permitted`/`excluded` name-constraint subtrees imposed by the CAs
///   above it ([`ChainError::NameConstraintViolation`], §4.2.1.10 / §6.1.3 (b)(c) / §6.1.4 (g)).
///
/// The walk is a **bounded depth-first search that backtracks** over candidate issuers: when several
/// supplied intermediates name-match the current certificate (e.g. a cross-certificate or an alternate
/// sub-CA), each is tried in turn, and a branch that dead-ends is unwound so an alternate is explored.
/// A conformant credential whose chain reaches a configured anchor via **some** valid path is therefore
/// accepted, even when a greedy first-match would have committed to a dead-end branch. Per RFC 5280
/// §6.1.4 (l) / §4.2.1.9 a **self-issued** intermediate (subject DN == issuer DN, e.g. a key-rollover
/// cert) does not consume path-length budget, so it is not counted toward a CA's `pathLenConstraint`.
///
/// The supplied intermediates are **attacker-controlled**: they are honoured only as candidate
/// issuers, never as trust roots, so a path that never reaches a configured anchor is rejected. The
/// path length is capped at [`MAX_PATH_LEN`] ([`ChainError::PathTooLong`]) to bound the work an
/// attacker-supplied chain can demand. Returns the most specific [`ChainError`] when no path validates.
///
/// # Errors
///
/// Returns [`ChainError`] when the supplied chain is empty or a certificate is malformed, the leaf has
/// the wrong key purpose ([`ChainError::WrongLeafPurpose`]), the path reaches no configured anchor
/// ([`ChainError::IssuerMismatch`]), a signature does not verify or its algorithms disagree, an
/// algorithm is unsupported, an issuing certificate is not a CA or is outside its validity window, the
/// leaf is outside its validity window at `leaf_validity_time`, a processed certificate carries an
/// unrecognized critical extension or violates a name constraint, or the path exceeds [`MAX_PATH_LEN`].
pub fn verify_chain(
    supplied_chain: &[&[u8]],
    anchor_certs_der: &[Vec<u8>],
    now_unix: i64,
    leaf_validity_time: Option<i64>,
    leaf_purpose: LeafPurpose,
) -> Result<(), ChainError> {
    // The leaf is the head of the supplied chain; the tail are candidate path-building intermediates.
    let (leaf_der, intermediates_der) = supplied_chain
        .split_first()
        .ok_or(ChainError::IssuerMismatch)?;
    let leaf =
        Certificate::from_der(leaf_der).map_err(|e| ChainError::Malformed(format!("leaf: {e}")))?;

    // Parse the supplied intermediates up front (a malformed supplied cert is a hard reject — it is
    // the credential's own claimed path material, not a configuration anchor we can skip past). Each is
    // kept as its `(DER slice, parsed cert)` so the walk can both compare-by-bytes (direct pin) and
    // verify-by-key (issued-by) without re-parsing.
    let mut intermediates: Vec<(&[u8], Certificate)> = Vec::with_capacity(intermediates_der.len());
    for (i, &der) in intermediates_der.iter().enumerate() {
        let cert = Certificate::from_der(der)
            .map_err(|e| ChainError::Malformed(format!("supplied intermediate {i}: {e}")))?;
        intermediates.push((der, cert));
    }

    // Pre-parse the configured anchors ONCE (like the intermediates) so each hop reuses the parsed
    // form instead of re-decoding every anchor per hop (efficiency: the anchors are invariant across
    // the whole walk). A malformed anchor is a CONFIGURATION fault, recorded in `last_err` only if
    // nothing more specific is known but skipped so it cannot mask a valid match (the documented
    // "only-unusable anchors ⇒ IssuerMismatch" contract).
    let mut last_err = ChainError::IssuerMismatch;
    let mut anchors: Vec<(&[u8], Certificate)> = Vec::with_capacity(anchor_certs_der.len());
    for anchor_der in anchor_certs_der {
        match Certificate::from_der(anchor_der) {
            Ok(cert) => anchors.push((anchor_der.as_slice(), cert)),
            Err(e) => {
                record_more_specific(&mut last_err, ChainError::Malformed(format!("anchor: {e}")));
            }
        }
    }

    // The leaf must carry the role/format-appropriate key purpose (mdoc DS EKU / SD-JWT VC issuer
    // not-a-CA + signing keyUsage) — enforced ONCE, on the leaf, before the walk, so a
    // genuinely-chained-but-WRONG-PURPOSE leaf is rejected up front (closing the "right chain, wrong
    // purpose" false-accept). EXCEPTION — a leaf byte-equal to a configured anchor is a deliberate
    // DIRECT PIN: the operator pinned this exact certificate as trusted for this role/format, an
    // intentional, distinct trust decision (the same model that exempts a directly-pinned cert from the
    // issued-by CA constraint). A direct pin is therefore exempt from the leaf-purpose check too — e.g.
    // an operator may pin an IACA root directly. (The pin still enforces the cert's validity window
    // below, so an expired pin is rejected; only the key-purpose floor is the operator's to waive.)
    let leaf_is_direct_pin = anchors.iter().any(|(a, _)| a == leaf_der);
    if !leaf_is_direct_pin {
        leaf_has_purpose(&leaf, leaf_purpose)?;
    }

    // The leaf's own validity is enforced once, before the walk, at `leaf_validity_time` when supplied
    // (the mdoc DS-validity-at-signing-time seam, ISO 18013-5 §9.3.1) else at `now_unix`; the issued-by
    // step enforces each promoted intermediate's window at `now_unix` as it is promoted.
    let leaf_time = leaf_validity_time.unwrap_or(now_unix);
    if !cert_is_valid_at(&leaf, leaf_time) {
        return Err(ChainError::LeafExpired);
    }

    // Walk the path leaf → intermediate → … → anchor as a bounded, BACKTRACKING depth-first search.
    // `used` marks supplied intermediates already on the current branch so a cycle cannot reuse one
    // (and `MAX_PATH_LEN` is a hard ceiling regardless). The walk threads two counters from the leaf
    // (both 0): `pathlen_depth` (non-self-issued intermediates, the input to a CA's `pathLenConstraint`)
    // and `hops` (every promotion, the DoS cap) — see [`walk`].
    let mut used = vec![false; intermediates.len()];
    let ctx = WalkCtx {
        anchors: &anchors,
        intermediates: &intermediates,
        now_unix,
    };
    let mut state = WalkState {
        used: &mut used,
        budget: MAX_NODE_VISITS,
        last_err,
    };
    match walk(&ctx, leaf_der, &leaf, 0, 0, &mut state) {
        // A structural path reached an anchor: enforce the per-path extension rules (unrecognized
        // critical extensions + RFC 5280 name constraints) over the processed certificates (leaf +
        // intermediates) top-down, with the terminating anchor (the trust-anchor INPUT) prepended so its
        // own name constraints are absorbed but its subject/extensions are not themselves checked.
        WalkResult::Reached { processed, anchor } => {
            let mut path_top_down: Vec<&Certificate> = Vec::with_capacity(processed.len() + 1);
            path_top_down.push(anchor);
            path_top_down.extend(processed.iter().rev());
            enforce_path_constraints(&path_top_down)
        }
        WalkResult::DeadEnd => Err(state.last_err),
        WalkResult::TooLong => Err(ChainError::PathTooLong),
    }
}

/// Read-only context shared across every recursive [`walk`] frame: the pre-parsed anchors and
/// supplied intermediates (each as `(DER slice, parsed cert)`) plus the validation instant. Bundling
/// these keeps the recursive signature small and avoids re-threading four invariants through the DFS.
struct WalkCtx<'a> {
    /// Pre-parsed configured anchors (DER slice + parsed cert); a path terminates at any of these.
    anchors: &'a [(&'a [u8], Certificate)],
    /// Pre-parsed supplied intermediates (DER slice + parsed cert) — attacker-controlled path material.
    intermediates: &'a [(&'a [u8], Certificate)],
    /// The verification instant (Unix seconds) every certificate's validity window is checked at.
    now_unix: i64,
}

/// The mutable search state threaded by `&mut` through the recursive [`walk`] (kept in one struct so
/// the DFS signature stays small): the per-branch `used` flags (cycle guard), the global work `budget`
/// (the DoS ceiling, [`MAX_NODE_VISITS`]), and the most-specific failure reason seen so far.
struct WalkState<'a> {
    /// Per-branch consumed-intermediate flags (index-aligned with [`WalkCtx::intermediates`]); set on
    /// descent and cleared on backtrack so a cert is never revisited on the current branch (no cycle).
    used: &'a mut [bool],
    /// The remaining global issued-by-attempt budget; charged per attempt, exhaustion ⇒ `TooLong`.
    budget: u32,
    /// The most specific [`ChainError`] seen across all candidate issuers (surfaced when no path validates).
    last_err: ChainError,
}

impl WalkState<'_> {
    /// Charge one unit of the global issued-by-attempt budget. Returns `true` if a unit was available
    /// (budget decremented), `false` when the budget is exhausted — the single source for the per-attempt
    /// charge shared by both the anchor and intermediate loops in [`walk`].
    fn charge(&mut self) -> bool {
        match self.budget.checked_sub(1) {
            Some(remaining) => {
                self.budget = remaining;
                true
            }
            None => false,
        }
    }
}

/// The outcome of one [`walk`] branch. On success it carries the **processed** certificates of the
/// reaching path (leaf-first, i.e. `[leaf, intermediate₁, …]`, **excluding** the terminating anchor)
/// plus the terminating `anchor`, so [`verify_chain`] can run the per-path extension / name-constraint
/// checks ([`enforce_path_constraints`]) over the ordered path it found. The references borrow the
/// pre-parsed leaf / intermediates / anchors for the lifetime `'c` of the walk.
enum WalkResult<'c> {
    /// A configured anchor was reached on this branch — the path is trusted, pending the per-path
    /// extension checks. `processed` is the leaf-first list of processed certs; `anchor` is the trust
    /// anchor the path terminated at (a direct pin or an issuing anchor).
    Reached {
        processed: Vec<&'c Certificate>,
        anchor: &'c Certificate,
    },
    /// This branch dead-ended (no anchor, every candidate issuer exhausted); `last_err` records why.
    DeadEnd,
    /// This branch hit the [`MAX_PATH_LEN`] cap before reaching an anchor — a hard reject.
    TooLong,
}

/// One recursion of the backtracking certification-path DFS: resolve the issuer of `current`
/// (`current_der` its DER), having already promoted `hops` intermediates below it of which
/// `pathlen_depth` were non-self-issued.
///
/// Two distinct counters are threaded because they answer two distinct questions (RFC 5280
/// distinguishes them — verified online):
/// - **`pathlen_depth`** is the number of **non-self-issued** intermediates already traversed below
///   `current` — the input to an issuing CA's `pathLenConstraint` check (§6.1.4 (l)/(m), §4.2.1.9: a
///   self-issued cert "is not counted when evaluating path length", so it does not consume budget);
/// - **`hops`** is the total number of intermediates promoted on this branch (self-issued **included**)
///   — the denial-of-service guard, bounded by [`MAX_PATH_LEN`] so an attacker cannot make the walk run
///   unbounded by stuffing the supplied chain with self-issued certs (which would never grow
///   `pathlen_depth`). The two must be separate: tying the DoS cap to `pathlen_depth` would let a chain
///   of self-issued certs evade it.
///
/// Termination, in order, mirroring the §6.1 path-build:
/// 1. **direct pin** — `current` is byte-equal to a configured anchor → [`WalkResult::Reached`]
///    (`current` is the trust anchor — exempt from the CA / sig-alg / per-path-extension checks by
///    design; its validity is already enforced before this frame). Returns an empty `processed` list.
/// 2. **issued-by an anchor** — a configured anchor name-matches and validly issued `current`
///    (signature + CA constraint for the `pathlen_depth` non-self-issued intermediates below it + the
///    anchor's own validity) → [`WalkResult::Reached`] with `processed = [current]`.
/// 3. **issued-by a supplied intermediate** — for EACH unused supplied intermediate that validly issued
///    `current`, recurse with it as the new `current`. A self-issued promoted intermediate increments
///    `hops` but NOT `pathlen_depth` (§6.1.4 (l)). On a child's success this frame prepends its own
///    `current` to the returned `processed` list (so the list assembles leaf-first as the recursion
///    unwinds). If a branch dead-ends, the intermediate is released (backtrack) and the next candidate
///    is tried; only when every candidate is exhausted does the frame report [`WalkResult::DeadEnd`].
///
/// Before resolving the issuer (steps 2/3), `current`'s outer `signatureAlgorithm` must equal its inner
/// `tbsCertificate.signature` (RFC 5280 §4.1.1.2 / §4.1.2.3) — a mismatch is a malformed/tampered cert
/// ([`ChainError::SignatureAlgorithmMismatch`]); this is checked on the leaf and every promoted
/// intermediate (each is some frame's `current`), but not on the trust anchor (a §6.1.1 input).
///
/// `state.used` prevents revisiting a supplied cert on the current branch (no cycle), the `hops` cap
/// bounds branch length, and the global `state.budget` (decremented per issued-by attempt) bounds TOTAL
/// work across all branches, so the backtracking search is finite — and cheaply so — even on
/// attacker-supplied material that name-matches combinatorially.
fn walk<'c>(
    ctx: &WalkCtx<'c>,
    current_der: &[u8],
    current: &'c Certificate,
    pathlen_depth: usize,
    hops: usize,
    state: &mut WalkState<'_>,
) -> WalkResult<'c> {
    // (a) Direct pin: `current` is byte-equal to a configured anchor → terminate as trusted. `current`
    // is the trust anchor itself (not a processed path cert), so `processed` is empty.
    if ctx.anchors.iter().any(|(a, _)| *a == current_der) {
        return WalkResult::Reached {
            processed: Vec::new(),
            anchor: current,
        };
    }

    // Inner/outer signature-algorithm consistency (RFC 5280 §4.1.1.2 / §4.1.2.3): the outer
    // `signatureAlgorithm` MUST equal the inner `tbsCertificate.signature` (including parameters). A
    // mismatch is a malformed/tampered cert (the unsigned outer field substituted) — reject this branch.
    // Checked here so it runs once per `current` (the leaf and each promoted intermediate), not per
    // candidate issuer; the trust anchor (a §6.1.1 input, reached at the head of step (a)/(b)) is exempt.
    if current.signature_algorithm != current.tbs_certificate.signature {
        record_more_specific(&mut state.last_err, ChainError::SignatureAlgorithmMismatch);
        return WalkResult::DeadEnd;
    }

    // (b) Issued-by a configured anchor → terminate as trusted (the path reaches a trust root). Compute
    // `current`'s TBS DER ONCE here: it is invariant across every candidate issuer at this hop, so the
    // signature check reuses it rather than re-encoding per candidate (efficiency).
    let Ok(tbs_der) = current.tbs_certificate.to_der() else {
        record_more_specific(
            &mut state.last_err,
            ChainError::Malformed("re-encode TBSCertificate".into()),
        );
        return WalkResult::DeadEnd;
    };
    for (_, anchor) in ctx.anchors {
        // Global work budget: charge one unit per issued-by ATTEMPT (the signature verify is the
        // dominant cost). Exhausting it means the supplied chain × anchors forced more path-building
        // work than any conformant credential needs → a denial-of-service reject.
        if !state.charge() {
            return WalkResult::TooLong;
        }
        match issued_by(current, &tbs_der, anchor, ctx.now_unix, pathlen_depth) {
            Ok(()) => {
                return WalkResult::Reached {
                    processed: vec![current],
                    anchor,
                }
            }
            Err(e) => record_more_specific(&mut state.last_err, e),
        }
    }

    // DoS cap: stepping to a further intermediate would exceed MAX_PATH_LEN total hops. Report TooLong
    // only when there is in fact an unused intermediate that name-matches (an actual over-long branch);
    // otherwise this is a plain dead-end (no candidate to step to), which must NOT masquerade as
    // PathTooLong.
    if hops >= MAX_PATH_LEN {
        let has_unused_candidate =
            state
                .used
                .iter()
                .zip(ctx.intermediates)
                .any(|(is_used, (_, cand))| {
                    !*is_used && current.tbs_certificate.issuer == cand.tbs_certificate.subject
                });
        return if has_unused_candidate {
            WalkResult::TooLong
        } else {
            WalkResult::DeadEnd
        };
    }

    // (c) Issued-by a supplied intermediate → try EACH unused candidate that validly issued `current`,
    // recursing into it, and BACKTRACK over the rest if a branch dead-ends.
    let mut saw_too_long = false;
    for idx in 0..ctx.intermediates.len() {
        // Resolve through `.get()` (no panicking index — the crate forbids `clippy::indexing_slicing`).
        let Some((cand_der, candidate)) = ctx.intermediates.get(idx) else {
            continue;
        };
        let Some(&is_used) = state.used.get(idx) else {
            continue;
        };
        if is_used {
            continue;
        }
        // Charge the global work budget per issued-by ATTEMPT (the dominant signature-verify cost),
        // bounding the TOTAL work the backtracking search can do across all branches.
        if !state.charge() {
            return WalkResult::TooLong;
        }
        if let Err(e) = issued_by(current, &tbs_der, candidate, ctx.now_unix, pathlen_depth) {
            record_more_specific(&mut state.last_err, e);
            continue;
        }
        // The candidate validly issued `current` and becomes the new `current`. It always consumes one
        // DoS hop; it consumes a pathLen unit only when it is NOT self-issued (subject DN == issuer DN
        // ⇒ a key-rollover / policy cert that §6.1.4 (l) does not count toward path length).
        let next_pathlen_depth = if is_self_issued(candidate) {
            pathlen_depth
        } else {
            pathlen_depth + 1
        };
        if let Some(flag) = state.used.get_mut(idx) {
            *flag = true;
        }
        match walk(
            ctx,
            cand_der,
            candidate,
            next_pathlen_depth,
            hops + 1,
            state,
        ) {
            // A child branch reached an anchor: prepend THIS frame's `current` so the processed list
            // assembles leaf-first as the recursion unwinds (the leaf ends up at index 0).
            WalkResult::Reached {
                mut processed,
                anchor,
            } => {
                processed.insert(0, current);
                return WalkResult::Reached { processed, anchor };
            }
            WalkResult::TooLong => saw_too_long = true,
            WalkResult::DeadEnd => {}
        }
        // Backtrack: release this intermediate so an alternate branch may consider it again.
        if let Some(flag) = state.used.get_mut(idx) {
            *flag = false;
        }
    }
    // No candidate issuer reached an anchor on any branch. Surface TooLong only if the sole obstacle
    // was the length cap (a deeper branch existed but was capped); otherwise this is a dead-end whose
    // specific reason is in `last_err`.
    if saw_too_long {
        WalkResult::TooLong
    } else {
        WalkResult::DeadEnd
    }
}

/// Whether `cert` is **self-issued** per RFC 5280 §6.1: the same distinguished name appears in its
/// `subject` and `issuer` fields (a CA cert issued to itself for key rollover / policy change). A
/// self-issued intermediate is not counted against a CA's `pathLenConstraint` (§6.1.4 (l) / §4.2.1.9).
fn is_self_issued(cert: &Certificate) -> bool {
    cert.tbs_certificate.subject == cert.tbs_certificate.issuer
}

/// Record `candidate` into `last_err` only when it is **more specific** than the current value, so a
/// generic "this isn't the issuer" reason never masks an actionable one already seen. `IssuerMismatch`
/// (a plain name mismatch) and a malformed *anchor* (a configuration fault, not a credential defect)
/// are the least specific: they must not overwrite a recorded `SignatureInvalid` / `NotACa` /
/// `AnchorExpired` / `LeafExpired` / `UnsupportedAlgorithm` from a real name-matching candidate. This
/// preserves the documented contract that a set containing **only** unusable anchors (all name
/// mismatches, or all malformed) yields the "no trusted anchor reached" verdict [`ChainError::IssuerMismatch`].
fn record_more_specific(last_err: &mut ChainError, candidate: ChainError) {
    let is_generic = |e: &ChainError| {
        matches!(e, ChainError::IssuerMismatch)
            || matches!(e, ChainError::Malformed(m) if m.starts_with("anchor:"))
    };
    // Record `candidate` only when it is actionable (NOT generic) and nothing actionable is recorded
    // yet: a generic candidate (a plain name mismatch, or a malformed *anchor* config fault) must
    // neither overwrite an actionable reason nor downgrade the `IssuerMismatch` default — so a set of
    // only-unusable anchors still surfaces "no trusted anchor reached".
    if !is_generic(&candidate) && is_generic(last_err) {
        *last_err = candidate;
    }
}

/// Whether `issuer` validly issued `child` per the RFC 5280 §6.1 issued-by requirements: the child's
/// `issuer` name equals the issuer's `subject` (§6.1.3 (a)(4)), the child's signature verifies under
/// the issuer's subject public key (§6.1.3 (a)(1)), the issuer is a CA wide enough for the
/// `intermediates_following` certs below it (§6.1.4 (k)/(m)/(n), §4.2.1.9, §4.2.1.3), and the issuer is
/// within its own validity window at `now_unix` (§6.1.3 (a)(2)). `child_tbs_der` is the child's
/// re-encoded `TBSCertificate` — computed ONCE per hop by the caller and reused across every candidate
/// issuer (it is invariant of the issuer). The order matters for error specificity: a name mismatch is
/// "not this issuer" (leave `IssuerMismatch`), then signature, then CA constraint, then validity.
fn issued_by(
    child: &Certificate,
    child_tbs_der: &[u8],
    issuer: &Certificate,
    now_unix: i64,
    intermediates_following: usize,
) -> Result<(), ChainError> {
    if child.tbs_certificate.issuer != issuer.tbs_certificate.subject {
        return Err(ChainError::IssuerMismatch);
    }
    verify_signed_under(child, child_tbs_der, issuer)?;
    // The issuer really signed the child — now it must be a CA permitted to do so (basicConstraints
    // critical cA=TRUE + keyCertSign, and a pathLenConstraint wide enough for the intermediates that
    // follow it toward the leaf), and itself be within its validity window at the relevant time.
    if !anchor_asserts_ca(issuer, intermediates_following) {
        return Err(ChainError::NotACa);
    }
    if !cert_is_valid_at(issuer, now_unix) {
        return Err(ChainError::AnchorExpired);
    }
    Ok(())
}

/// Verify `child`'s signature over its (already re-encoded) `child_tbs_der` `TBSCertificate` under the
/// `issuer`'s subject public key, routing the digest+signature through the SDK's existing RustCrypto
/// stack (no hand-rolled crypto). `child_tbs_der` is passed in (computed once per hop) so it is not
/// re-encoded per candidate issuer.
fn verify_signed_under(
    child: &Certificate,
    child_tbs_der: &[u8],
    issuer: &Certificate,
) -> Result<(), ChainError> {
    let alg = SigAlg::from_oid(child.signature_algorithm.oid)?;
    let signature = child
        .signature
        .as_bytes()
        .ok_or_else(|| ChainError::Malformed("certificate signature is not byte-aligned".into()))?;
    let spki_der = issuer
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| ChainError::Malformed(format!("issuer SPKI: {e}")))?;

    match alg {
        SigAlg::EcdsaP256Sha256 => verify_ecdsa_p256(&spki_der, child_tbs_der, signature),
        SigAlg::RsaSha256 => verify_rsa::<sha2::Sha256>(&spki_der, child_tbs_der, signature),
        SigAlg::RsaSha384 => verify_rsa::<sha2::Sha384>(&spki_der, child_tbs_der, signature),
        SigAlg::RsaSha512 => verify_rsa::<sha2::Sha512>(&spki_der, child_tbs_der, signature),
    }
}

/// Whether the leaf carries the role/format-appropriate **key purpose** ([`LeafPurpose`]), using
/// `x509-cert`'s typed `ExtendedKeyUsage` / `KeyUsage` / `BasicConstraints` decoders (no hand-rolled
/// ASN.1). Fail-closed: a malformed or duplicate `extendedKeyUsage` / `keyUsage` / `basicConstraints` /
/// `qcStatements` extension is rejected (a leaf whose purpose cannot be parsed is not trusted to act in
/// that role).
///
/// - **[`LeafPurpose::MdocDocumentSigner`]** — ISO/IEC 18013-5:2021 Annex B Table B.3, the full DS-leaf
///   profile: `extendedKeyUsage` (row `m`) MUST list `id-mso-mdl-DS` ([`OID_MDL_DS`]); `keyUsage` (row
///   `mc`) MUST assert `digitalSignature`; `basicConstraints` (row `mc`) MUST be `cA=FALSE`. Absent /
///   unparsable EKU, an EKU not listing the OID (e.g. only `serverAuth`), a `keyUsage` lacking
///   `digitalSignature` (present or absent), or `cA=TRUE` is [`ChainError::WrongLeafPurpose`]. EKU
///   criticality is not required (§4.2.1.12 leaves it at the issuer's option; ISO marks the EKU row `m`,
///   not `mc`).
/// - **[`LeafPurpose::SdJwtVcIssuer`]** — no spec mandates an EKU (verified online). Two layered checks:
///   (1) the ETSI EN 319 412-2 §4.3.2 / EN 319 412-3 §4.3.1 base floor — the leaf MUST NOT be a CA
///   (`basicConstraints cA=TRUE` ⇒ rejected) and `keyUsage` MUST be **present** and assert a signing bit
///   (`digitalSignature` or `nonRepudiation`/content-commitment; an absent or non-signing keyUsage is
///   rejected — tightened from the prior "absent allowed", which was laxer than the SHALL-present
///   profile); (2) the per-role QcStatement check ([`leaf_has_required_qc_statements`]).
/// - **[`LeafPurpose::TrustListSigner`]** — no credential-leaf purpose constraint (a TL signer is
///   governed by a separate ETSI profile); always accepted by this check.
fn leaf_has_purpose(leaf: &Certificate, purpose: LeafPurpose) -> Result<(), ChainError> {
    use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage};

    match purpose {
        LeafPurpose::TrustListSigner => Ok(()),
        LeafPurpose::MdocDocumentSigner => {
            // The mdlDS key-purpose OID the DS leaf's extendedKeyUsage MUST list (Table B.3 EKU row).
            let mdl_ds: der::asn1::ObjectIdentifier = OID_MDL_DS
                .parse()
                .map_err(|_| ChainError::WrongLeafPurpose)?;
            match leaf.tbs_certificate.get::<ExtendedKeyUsage>() {
                // EKU present and parsable: it MUST list id-mso-mdl-DS.
                Ok(Some((_critical, eku))) if eku.0.contains(&mdl_ds) => {}
                // EKU present but does not list the OID, EKU absent, or a parse error (duplicate /
                // malformed) ⇒ not a conformant DS leaf (fail closed).
                _ => return Err(ChainError::WrongLeafPurpose),
            }
            // Table B.3 row `mc`: keyUsage MUST assert digitalSignature (and only that bit, per ISO; the
            // load-bearing requirement here is the digitalSignature bit). Absent / non-signing / a
            // parse error (duplicate) ⇒ not a conformant DS leaf (fail closed).
            match leaf.tbs_certificate.get::<KeyUsage>() {
                Ok(Some((_critical, ku))) if ku.digital_signature() => {}
                _ => return Err(ChainError::WrongLeafPurpose),
            }
            // Table B.3 row `mc`: basicConstraints MUST be cA=FALSE — a DS leaf that asserts cA=TRUE (so
            // it could double as an issuing CA) is rejected even when it carries the mdlDS EKU. Absent
            // basicConstraints (cA defaults FALSE) or cA=FALSE is fine; a parse error ⇒ fail closed.
            match leaf.tbs_certificate.get::<BasicConstraints>() {
                Ok(Some((_critical, bc))) if bc.ca => Err(ChainError::WrongLeafPurpose),
                Ok(_) => Ok(()),
                Err(_) => Err(ChainError::WrongLeafPurpose),
            }
        }
        LeafPurpose::SdJwtVcIssuer(role) => {
            // (1) The issuer leaf MUST NOT be a CA: a basicConstraints with cA=TRUE (parsable) is
            // rejected; an absent basicConstraints (cA defaults FALSE) or cA=FALSE is fine. A parse error
            // ⇒ fail closed (a leaf whose basicConstraints cannot be decoded is not trusted as an EE).
            match leaf.tbs_certificate.get::<BasicConstraints>() {
                Ok(Some((_critical, bc))) if bc.ca => return Err(ChainError::WrongLeafPurpose),
                Ok(_) => {}
                Err(_) => return Err(ChainError::WrongLeafPurpose),
            }
            // keyUsage MUST be PRESENT and assert a signing bit (digitalSignature or the
            // content-commitment / nonRepudiation bit — ETSI EN 319 412-2 §4.3.2 / 412-3 §4.3.1 make
            // keyUsage SHALL-present and a content/seal-signing cert Type A/B/F, all of which carry a
            // signing bit). An ABSENT keyUsage, a present keyUsage asserting neither bit, or an
            // unparsable (duplicate) one is rejected (fail closed).
            match leaf.tbs_certificate.get::<KeyUsage>() {
                Ok(Some((_critical, ku))) if ku.digital_signature() || ku.non_repudiation() => {}
                _ => return Err(ChainError::WrongLeafPurpose),
            }
            // (2) The per-role eIDAS QcStatement check (closes the chain-to-root false-trust, T1.3).
            leaf_has_required_qc_statements(leaf, role)
        }
    }
}

/// Whether the SD-JWT VC issuer `leaf` carries the eIDAS `qcStatements` its [`IssuerRole`] requires
/// (the in-band guard against the chain-to-root false-trust, conformance-audit T1.3). Parsed via the
/// `der` typed decoders (no hand-rolled ASN.1): the `qcStatements` extension ([`OID_QC_STATEMENTS`]) is
/// a `SEQUENCE OF QCStatement`, each `{ statementId OID, statementInfo ANY OPTIONAL }` (RFC 3739).
///
/// Per-role requirements (verified online against ETSI EN 319 412-5 §4.2 + TS 119 412-6 V1.1.1):
/// - **PID** — a `QcType` statement ([`OID_ETSI_QCS_QC_TYPE`]) whose value SEQUENCE lists
///   `id-etsi-qct-pid` ([`OID_ETSI_QCT_PID`]) — TS 119 412-6 PID-4.5-01;
/// - **QEAA** — `QcCompliance` ([`OID_ETSI_QCS_QC_COMPLIANCE`], the cert is an EU qualified cert) AND a
///   `QcType` listing a qualified type (`id-etsi-qct-esign`/`-eseal`, [`OID_ETSI_QCT_ESIGN`] /
///   [`OID_ETSI_QCT_ESEAL`]) — EN 319 412-5 §4.2 + TS 119 412-6 QEA-7.1 / EN 319 412-3 §4.3;
/// - **PuB-EAA** — the `QcPSB` statement ([`OID_ETSI_QCS_QC_PSB`]) — TS 119 412-6 PSB-8.3-01;
/// - **NonQualifiedEAA** — no Qc requirement (EAA-6.x impose none) → always accepted.
///
/// Fail-closed: a missing required statement, or an unparsable `qcStatements` extension, is
/// [`ChainError::WrongLeafPurpose`].
fn leaf_has_required_qc_statements(leaf: &Certificate, role: IssuerRole) -> Result<(), ChainError> {
    // NonQualifiedEAA imposes no Qc requirement — short-circuit before any parsing.
    if role == IssuerRole::NonQualifiedEaa {
        return Ok(());
    }
    let statements = parse_qc_statements(leaf)?;
    let ok = match role {
        // PID: a QcType statement listing id-etsi-qct-pid (TS 119 412-6 PID-4.5-01).
        IssuerRole::Pid => qc_type_contains(&statements, &OID_ETSI_QCT_PID),
        // QEAA: QcCompliance + a qualified QcType (esign or eseal).
        IssuerRole::Qeaa => {
            has_statement(&statements, &OID_ETSI_QCS_QC_COMPLIANCE)
                && (qc_type_contains(&statements, &OID_ETSI_QCT_ESIGN)
                    || qc_type_contains(&statements, &OID_ETSI_QCT_ESEAL))
        }
        // PuB-EAA: the QcPSB statement (TS 119 412-6 PSB-8.3-01).
        IssuerRole::PubEaa => has_statement(&statements, &OID_ETSI_QCS_QC_PSB),
        // Unreachable (handled above), but keep the match exhaustive without a catch-all.
        IssuerRole::NonQualifiedEaa => true,
    };
    if ok {
        Ok(())
    } else {
        Err(ChainError::WrongLeafPurpose)
    }
}

/// One decoded entry of the `qcStatements` extension: `QCStatement ::= SEQUENCE { statementId OBJECT
/// IDENTIFIER, statementInfo ANY DEFINED BY statementId OPTIONAL }` (RFC 3739 §3.2.6). Decoded with the
/// `der` `Sequence` derive (typed, no hand-rolled ASN.1).
#[derive(der::Sequence)]
struct QcStatement {
    statement_id: der::asn1::ObjectIdentifier,
    statement_info: Option<der::Any>,
}

/// Decode the leaf's `qcStatements` extension ([`OID_QC_STATEMENTS`]) into its `QCStatement` entries
/// (`SEQUENCE OF QCStatement`). An ABSENT extension yields an empty list (so a role that requires a
/// statement is then rejected by the caller); a PRESENT-but-unparsable extension fails closed
/// ([`ChainError::WrongLeafPurpose`]). Uses the typed `der` decoders only.
fn parse_qc_statements(leaf: &Certificate) -> Result<Vec<QcStatement>, ChainError> {
    let Some(extensions) = leaf.tbs_certificate.extensions.as_ref() else {
        return Ok(Vec::new());
    };
    let mut matching = extensions
        .iter()
        .filter(|ext| ext.extn_id == OID_QC_STATEMENTS);
    let Some(ext) = matching.next() else {
        return Ok(Vec::new());
    };
    // A duplicate qcStatements extension is malformed ⇒ fail closed (cannot trust an ambiguous leaf).
    if matching.next().is_some() {
        return Err(ChainError::WrongLeafPurpose);
    }
    Vec::<QcStatement>::from_der(ext.extn_value.as_bytes())
        .map_err(|_| ChainError::WrongLeafPurpose)
}

/// Whether a bare-OID `qcStatements` entry with `statement_id == id` is present (e.g. `QcCompliance`,
/// `QcPSB`).
fn has_statement(statements: &[QcStatement], id: &der::asn1::ObjectIdentifier) -> bool {
    statements.iter().any(|s| &s.statement_id == id)
}

/// Whether the `QcType` statement ([`OID_ETSI_QCS_QC_TYPE`]) is present and its value SEQUENCE (`QcType
/// ::= SEQUENCE OF OBJECT IDENTIFIER`) lists the qualified-type OID `qc_type`. The `statementInfo` is
/// re-encoded and decoded as a typed `Vec<ObjectIdentifier>` (no hand-rolled ASN.1); a missing or
/// unparsable value SEQUENCE is treated as "not listed" (the role check then fails closed).
fn qc_type_contains(statements: &[QcStatement], qc_type: &der::asn1::ObjectIdentifier) -> bool {
    statements
        .iter()
        .filter(|s| s.statement_id == OID_ETSI_QCS_QC_TYPE)
        .any(|s| {
            s.statement_info
                .as_ref()
                .and_then(|info| info.to_der().ok())
                .and_then(|der| Vec::<der::asn1::ObjectIdentifier>::from_der(&der).ok())
                .is_some_and(|types| types.iter().any(|t| t == qc_type))
        })
}

/// Enforce the per-path extension rules over the reached certification path, **top-down** (`path[0]` is
/// the trust anchor, `path[last]` the leaf): the unrecognized-critical-extension reject (RFC 5280
/// §6.1.4 (o) / §6.1.5 (f)) and the name-constraints check (§4.2.1.10, §6.1.3 (b)(c), §6.1.4 (g)). Run
/// once, after the backtracking walk has found a structural path to an anchor.
///
/// The terminating anchor (`path[0]`) is the RFC 5280 §6.1.1 **trust-anchor input**, not a processed
/// path certificate: its own subject/extensions are NOT checked, but any name constraints it carries
/// ARE absorbed so they bound the certificates below it (the more-restrictive, fail-closed reading). For
/// each subsequent certificate the subject (and SAN entries) must lie within the accumulated
/// `permitted_subtrees` and outside the `excluded_subtrees`, with the §6.1.3 (b)/(c) exemption that a
/// **self-issued** non-final certificate's subject is not checked. After checking a certificate, its own
/// name constraints are intersected (permitted) / unioned (excluded) into the state (§6.1.4 (g)).
fn enforce_path_constraints(path_top_down: &[&Certificate]) -> Result<(), ChainError> {
    let mut nc = NameConstraintState::default();
    let last = path_top_down.len().saturating_sub(1);
    for (i, cert) in path_top_down.iter().enumerate() {
        let is_ta = i == 0;
        let is_final = i == last;
        if !is_ta {
            // (o)/(f): reject any unrecognized CRITICAL extension on a processed certificate.
            reject_unknown_critical_extensions(cert)?;
            // (b)/(c): check subject + SAN against the accumulated constraints, except for a self-issued
            // non-final certificate (§6.1.3 (b)(c) skip).
            if !is_self_issued(cert) || is_final {
                check_subject_within_constraints(cert, &nc)?;
            }
        }
        // (g): absorb this certificate's own name constraints (every cert, the anchor included, may
        // impose constraints on those below it).
        absorb_name_constraints(cert, &mut nc)?;
    }
    Ok(())
}

/// The name-constraint state accumulated top-down (RFC 5280 §6.1.4 (g)). Each permitted entry is a
/// per-CA subtree **set**: a subject must lie within ≥1 subtree of EVERY set (the §6.1.4 (g)(1)
/// intersection, expressed as "within all sets"). Excluded subtrees are a flat union (§6.1.4 (g)(2)): a
/// subject must lie within NONE. Only `directoryName` and `dNSName` name forms are tracked; a constraint
/// on any other form (or with a non-default `minimum`/`maximum`) is rejected at absorption time.
#[derive(Default)]
struct NameConstraintState {
    /// Per-CA permitted `directoryName` subtree base DNs (intersection across sets).
    permitted_dn: Vec<Vec<x509_cert::name::Name>>,
    /// Per-CA permitted `dNSName` subtree bases (intersection across sets).
    permitted_dns: Vec<Vec<String>>,
    /// The union of excluded `directoryName` subtree base DNs.
    excluded_dn: Vec<x509_cert::name::Name>,
    /// The union of excluded `dNSName` subtree bases.
    excluded_dns: Vec<String>,
}

impl NameConstraintState {
    /// Whether any name constraint is currently active (so a SAN that cannot be parsed must fail closed).
    fn is_constrained(&self) -> bool {
        !self.permitted_dn.is_empty()
            || !self.permitted_dns.is_empty()
            || !self.excluded_dn.is_empty()
            || !self.excluded_dns.is_empty()
    }
}

/// Reject the certificate if it carries any extension marked **critical** whose OID this validator does
/// not recognize/process (RFC 5280 §6.1.4 (o) / §6.1.5 (f) and the §4.2/§6 "MUST reject … unsupported
/// critical extension"). The recognized critical extensions are exactly the ones whose semantics this
/// validator enforces: `basicConstraints`, `keyUsage`, `extendedKeyUsage`, `nameConstraints`, and
/// `subjectAltName` (consulted for name constraints). Any other critical extension fails closed.
fn reject_unknown_critical_extensions(cert: &Certificate) -> Result<(), ChainError> {
    use const_oid::db::rfc5280::{
        ID_CE_BASIC_CONSTRAINTS, ID_CE_EXT_KEY_USAGE, ID_CE_KEY_USAGE, ID_CE_NAME_CONSTRAINTS,
        ID_CE_SUBJECT_ALT_NAME,
    };
    let Some(extensions) = cert.tbs_certificate.extensions.as_ref() else {
        return Ok(());
    };
    const RECOGNIZED: [der::asn1::ObjectIdentifier; 5] = [
        ID_CE_BASIC_CONSTRAINTS,
        ID_CE_KEY_USAGE,
        ID_CE_EXT_KEY_USAGE,
        ID_CE_NAME_CONSTRAINTS,
        ID_CE_SUBJECT_ALT_NAME,
    ];
    for ext in extensions {
        if ext.critical && !RECOGNIZED.contains(&ext.extn_id) {
            return Err(ChainError::UnsupportedCriticalExtension(
                ext.extn_id.to_string(),
            ));
        }
    }
    Ok(())
}

/// Check a processed certificate's subject DN — and each `subjectAltName` `directoryName`/`dNSName`
/// entry — against the accumulated name-constraint state: within EVERY permitted set, within NO excluded
/// subtree (RFC 5280 §6.1.3 (b)(c)). A present-but-unparsable `subjectAltName` fails closed when any
/// constraint is active (its compliance cannot be verified).
fn check_subject_within_constraints(
    cert: &Certificate,
    nc: &NameConstraintState,
) -> Result<(), ChainError> {
    use x509_cert::ext::pkix::name::GeneralName;
    use x509_cert::ext::pkix::SubjectAltName;

    check_dn_within(&cert.tbs_certificate.subject, nc)?;
    match cert.tbs_certificate.get::<SubjectAltName>() {
        Ok(Some((_critical, san))) => {
            for gn in &san.0 {
                match gn {
                    GeneralName::DirectoryName(dn) => check_dn_within(dn, nc)?,
                    GeneralName::DnsName(name) => check_dns_within(name.as_str(), nc)?,
                    // Other SAN forms are unconstrained here: any constraint on such a form is rejected
                    // at absorption time, so a permitted/excluded set for it never exists.
                    _ => {}
                }
            }
        }
        Ok(None) => {}
        // A duplicate/unparsable SAN extension: fail closed only when constraints are active (otherwise
        // it is irrelevant to name-constraint processing).
        Err(_) => {
            if nc.is_constrained() {
                return Err(ChainError::NameConstraintViolation);
            }
        }
    }
    Ok(())
}

/// Check one name value against permitted/excluded subtrees of its form (RFC 5280 §6.1.3 (b)(c)):
/// it must lie within ≥1 base of EVERY permitted set (the (g)(1) intersection) and within NO excluded
/// base ((g)(2)), else [`ChainError::NameConstraintViolation`]. The per-form `within` subtree predicate
/// (`dn_within_subtree` / `dns_within_subtree`, which hold the §7.1 DN / trailing-dot-dNSName
/// normalization) is passed in; the permitted/excluded control flow lives here once (DRY).
fn check_within<B, N: ?Sized>(
    permitted: &[Vec<B>],
    excluded: &[B],
    name: &N,
    within: impl Fn(&B, &N) -> bool,
) -> Result<(), ChainError> {
    for set in permitted {
        if !set.iter().any(|base| within(base, name)) {
            return Err(ChainError::NameConstraintViolation);
        }
    }
    if excluded.iter().any(|base| within(base, name)) {
        return Err(ChainError::NameConstraintViolation);
    }
    Ok(())
}

/// Check one `directoryName` value against the permitted/excluded `directoryName` subtrees.
fn check_dn_within(
    name: &x509_cert::name::Name,
    nc: &NameConstraintState,
) -> Result<(), ChainError> {
    check_within(&nc.permitted_dn, &nc.excluded_dn, name, dn_within_subtree)
}

/// Check one `dNSName` value against the permitted/excluded `dNSName` subtrees.
fn check_dns_within(name: &str, nc: &NameConstraintState) -> Result<(), ChainError> {
    check_within(&nc.permitted_dns, &nc.excluded_dns, name, |base, n| {
        dns_within_subtree(base, n)
    })
}

/// Absorb a certificate's `nameConstraints` extension into the state (§6.1.4 (g)): permitted subtrees
/// are pushed as a new per-CA set (intersection), excluded subtrees are unioned. Only `directoryName`
/// and `dNSName` subtree bases with the default `minimum`/`maximum` (`0`/absent) are supported; any
/// other base form or a non-default `BaseDistance` is treated as an unsupported constraint and fails
/// closed ([`ChainError::NameConstraintViolation`]), as does an unparsable `nameConstraints` extension.
fn absorb_name_constraints(
    cert: &Certificate,
    nc: &mut NameConstraintState,
) -> Result<(), ChainError> {
    use x509_cert::ext::pkix::name::GeneralName;
    use x509_cert::ext::pkix::NameConstraints;

    let constraints = match cert.tbs_certificate.get::<NameConstraints>() {
        Ok(Some((_critical, c))) => c,
        Ok(None) => return Ok(()),
        Err(_) => return Err(ChainError::NameConstraintViolation),
    };
    if let Some(permitted) = constraints.permitted_subtrees {
        let mut dn_set: Vec<x509_cert::name::Name> = Vec::new();
        let mut dns_set: Vec<String> = Vec::new();
        for subtree in permitted {
            if subtree.minimum != 0 || subtree.maximum.is_some() {
                return Err(ChainError::NameConstraintViolation);
            }
            match subtree.base {
                GeneralName::DirectoryName(dn) => dn_set.push(dn),
                GeneralName::DnsName(name) => dns_set.push(name.as_str().to_owned()),
                _ => return Err(ChainError::NameConstraintViolation),
            }
        }
        // Push only the non-empty per-type sets: a name type the constraint does not mention leaves that
        // type's state unchanged (§6.1.4 (g)(1)).
        if !dn_set.is_empty() {
            nc.permitted_dn.push(dn_set);
        }
        if !dns_set.is_empty() {
            nc.permitted_dns.push(dns_set);
        }
    }
    if let Some(excluded) = constraints.excluded_subtrees {
        for subtree in excluded {
            if subtree.minimum != 0 || subtree.maximum.is_some() {
                return Err(ChainError::NameConstraintViolation);
            }
            match subtree.base {
                GeneralName::DirectoryName(dn) => nc.excluded_dn.push(dn),
                GeneralName::DnsName(name) => nc.excluded_dns.push(name.as_str().to_owned()),
                _ => return Err(ChainError::NameConstraintViolation),
            }
        }
    }
    Ok(())
}

/// Whether `name` (a `directoryName`) is **within** the subtree rooted at `base` (RFC 5280 §4.2.1.10):
/// the subtree's RDN sequence is an initial prefix of `name`'s RDN sequence, each RDN compared per
/// RFC 5280 §7.1. DirectoryString attribute values use **caseIgnoreMatch** and are **encoding-agnostic**
/// (PrintableString vs UTF8String), so a byte-exact RDN compare fails **open in the EXCLUDED direction**:
/// a subject spelled `O=example` (case variant) or re-encoded PrintableString↔UTF8String would evade an
/// excluded `O=Example` subtree. Compare each RDN's RFC 4514 rendering, case-folded with collapsed
/// whitespace — which normalizes both case and string encoding. The normalization is symmetric on both
/// sides, so the PERMITTED direction stays correct (a genuine caseIgnore-equal name is still recognized
/// as within a permitted subtree — never a new fail-open there).
fn dn_within_subtree(base: &x509_cert::name::Name, name: &x509_cert::name::Name) -> bool {
    base.0.len() <= name.0.len()
        && base
            .0
            .iter()
            .zip(name.0.iter())
            .all(|(b, n)| normalize_rdn(b) == normalize_rdn(n))
}

/// Normalize one RDN for RFC 5280 §7.1 name-constraint comparison: render it (RFC 4514), lowercase it
/// (caseIgnoreMatch), and collapse insignificant whitespace (RFC 4518). The rendering is value-based, so
/// two RDNs that differ only in string encoding (PrintableString vs UTF8String) normalize identically.
fn normalize_rdn(rdn: &x509_cert::name::RelativeDistinguishedName) -> String {
    rdn.to_string()
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Whether `name` (a `dNSName`) is **within** the subtree rooted at `base` (RFC 5280 §4.2.1.10): equal
/// to `base`, or constructed by adding one or more labels to the left (`host.example.com` is within
/// `example.com`). Case-insensitive, label-aligned. A leading `.` on `base` (the alternate convention)
/// is tolerated.
fn dns_within_subtree(base: &str, name: &str) -> bool {
    // DNS labels are case-insensitive (RFC 5280 §7.2); compare lowercased copies (the constrained
    // dNSName path is rare, so the allocation is immaterial) and avoid any panicking byte/char indexing.
    // Normalize a trailing absolute-FQDN root dot on BOTH sides — `evil.example.com.` must be treated as
    // within `example.com`; an un-normalized trailing dot makes `strip_suffix` miss the match and lets a
    // leaf evade an EXCLUDED dNSName subtree (a fail-open in the excluded direction). A leading `.` on
    // `base` (the alternate subtree convention) is also tolerated.
    let base = base
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    // Within the subtree iff `name` equals `base`, or `name` is `base` with ≥1 label added on the left
    // (`host.example.com` within `example.com`) — i.e. it strips a trailing `.base` on a label boundary.
    name == base
        || name
            .strip_suffix(base.as_str())
            .is_some_and(|prefix| prefix.ends_with('.'))
}

/// Verify a P-256 / SHA-256 ECDSA certificate signature (DER-encoded `r,s`) over `message` — the
/// EUDI mandatory ES256 baseline. A non-P-256 ECDSA key surfaces as
/// [`ChainError::SignatureInvalid`] (it will not parse as a P-256 verifying key) rather than a
/// silent accept.
fn verify_ecdsa_p256(spki_der: &[u8], message: &[u8], signature: &[u8]) -> Result<(), ChainError> {
    use p256::ecdsa::signature::Verifier as _;
    use spki::DecodePublicKey as _;
    let vk = p256::ecdsa::VerifyingKey::from_public_key_der(spki_der)
        .map_err(|_| ChainError::SignatureInvalid)?;
    let sig =
        p256::ecdsa::Signature::from_der(signature).map_err(|_| ChainError::SignatureInvalid)?;
    vk.verify(message, &sig)
        .map_err(|_| ChainError::SignatureInvalid)
}

/// Verify an RSA-PKCS#1v1.5 certificate signature over `message`, hashed with `D`.
fn verify_rsa<D>(spki_der: &[u8], message: &[u8], signature: &[u8]) -> Result<(), ChainError>
where
    D: sha2::Digest + const_oid::AssociatedOid,
{
    use rsa::signature::Verifier as _;
    use spki::DecodePublicKey as _;
    let pk = rsa::RsaPublicKey::from_public_key_der(spki_der)
        .map_err(|_| ChainError::SignatureInvalid)?;
    let vk = rsa::pkcs1v15::VerifyingKey::<D>::new(pk);
    let sig =
        rsa::pkcs1v15::Signature::try_from(signature).map_err(|_| ChainError::SignatureInvalid)?;
    vk.verify(message, &sig)
        .map_err(|_| ChainError::SignatureInvalid)
}

/// Whether `cert` (leaf **or** issuing anchor) is within its `notBefore..=notAfter` validity window
/// at `now_unix`. Per RFC 5280 §6.1.3 (a)(2) every certificate in the path must satisfy this at the
/// validation time, so the same check applies to the leaf and to the issuing CA.
fn cert_is_valid_at(cert: &Certificate, now_unix: i64) -> bool {
    let validity = &cert.tbs_certificate.validity;
    let not_before = unix_secs_not_before(validity.not_before);
    let not_after = unix_secs_not_after(validity.not_after);
    now_unix >= not_before && now_unix <= not_after
}

/// Whether `anchor` asserts the CA constraints RFC 5280 requires of a certificate that issues other
/// certificates, parsed via `x509-cert`'s typed extension decoders (no hand-rolled ASN.1), where
/// `intermediates_following` is the number of intermediate certificates that follow this one toward
/// the leaf (the input to its `pathLenConstraint` check):
///
/// - **§6.1.4 (k) (the validation check) + §4.2.1.9 (the issuance requirement)** — §6.1.4 (k) is the
///   path-validation step "verify that the certificate is a CA certificate" (i.e. `basicConstraints
///   cA=TRUE`). The requirement that the extension be **present and marked critical** is **§4.2.1.9**,
///   not §6.1.4 (k): §4.2.1.9 states "Conforming CAs MUST include this extension in all CA certificates
///   … and MUST mark this extension as critical", so a non-critical `cA=TRUE` is NOT a conforming CA and
///   is rejected (closing the criticality-ignored gap). A certificate without `basicConstraints`, with
///   `cA=FALSE`, or with a non-critical `basicConstraints` is not a CA and may not issue certificates.
/// - **§6.1.4 (m) / §4.2.1.9** — a present `pathLenConstraint` bounds "the maximum number of
///   non-self-issued intermediate certificates that may follow this certificate in a valid
///   certification path"; reject when `intermediates_following` exceeds it.
/// - **§6.1.4 (n) / §4.2.1.3** — *if* a `keyUsage` extension is present, the `keyCertSign` bit MUST be
///   set. §4.2.1.3 says conforming CAs SHOULD mark `keyUsage` critical, so criticality is not required
///   here (a SHOULD); the load-bearing rule is the `keyCertSign` bit. (When `keyUsage` is absent the
///   spec leaves all usages permitted, so the bit is not required.)
///
/// A malformed or duplicate `basicConstraints` / `keyUsage` extension fails closed (treated as not a
/// CA): a certificate whose constraints cannot be parsed must not be trusted to issue.
fn anchor_asserts_ca(anchor: &Certificate, intermediates_following: usize) -> bool {
    use x509_cert::ext::pkix::{BasicConstraints, KeyUsage};

    // basicConstraints present, CRITICAL, AND cA=TRUE (a parse error, duplicate, absence, non-critical,
    // or cA=FALSE ⇒ not a CA). RFC 5280 §4.2.1.9 requires the extension be marked critical in a CA cert.
    let bc = match anchor.tbs_certificate.get::<BasicConstraints>() {
        Ok(Some((critical, bc))) if critical && bc.ca => bc,
        _ => return false,
    };

    // pathLenConstraint, if present, bounds how many intermediates may follow this CA toward the leaf.
    if let Some(max_following) = bc.path_len_constraint {
        if intermediates_following > usize::from(max_following) {
            return false;
        }
    }

    // keyUsage, if present, MUST assert keyCertSign (parse error ⇒ fail closed; absence ⇒ allowed).
    match anchor.tbs_certificate.get::<KeyUsage>() {
        Ok(Some((_critical, ku))) => ku.key_cert_sign(),
        Ok(None) => true,
        Err(_) => false,
    }
}

/// Clamp an unsigned-seconds X.509 time to `i64`, saturating an unrepresentable value to a supplied
/// **fail-closed** sentinel rather than fail-open.
///
/// A `notAfter` whose seconds overflow `i64` previously saturated to `i64::MAX` — "never expires" —
/// which is fail-OPEN on a validity boundary. The secure default is fail-CLOSED: the caller passes
/// `i64::MAX` for a `notBefore` (an unrepresentable lower bound reads "not yet valid") and `i64::MIN`
/// for a `notAfter` (an unrepresentable upper bound reads "already expired"), so neither boundary can
/// widen validity. Within standard X.509 (`UTCTime`/`GeneralizedTime`, year ≤ 9999) the seconds
/// always fit, so this never fires in practice; it is the boundary's secure default, mirroring the
/// fail-closed datetime parser ([`crate::datetime`]).
fn clamp_secs(secs: u64, on_overflow: i64) -> i64 {
    i64::try_from(secs).unwrap_or(on_overflow)
}

/// X.509 `notBefore` → Unix seconds, failing closed (unrepresentable ⇒ `i64::MAX` = not yet valid).
fn unix_secs_not_before(time: x509_cert::time::Time) -> i64 {
    clamp_secs(time.to_unix_duration().as_secs(), i64::MAX)
}

/// X.509 `notAfter` → Unix seconds, failing closed (unrepresentable ⇒ `i64::MIN` = already expired).
fn unix_secs_not_after(time: x509_cert::time::Time) -> i64 {
    clamp_secs(time.to_unix_duration().as_secs(), i64::MIN)
}

#[cfg(test)]
mod tests {
    use super::{clamp_secs, verify_chain, ChainError, LeafPurpose, SigAlg, MAX_PATH_LEN};
    use crate::types::IssuerRole;
    use der::{Decode as _, Encode as _};
    use x509_cert::Certificate;

    // The structural path-validation tests below predate the leaf key-purpose gate; their leaves are
    // generic CA:FALSE + digitalSignature end-entities. They use the SD-JWT VC issuer purpose keyed to
    // the NON-QUALIFIED-EAA role, which imposes NO QcStatement requirement (only the not-a-CA + signing
    // keyUsage floor), so they exercise the §6.1 path machinery without the per-role QcStatement gate
    // interfering. The dedicated purpose/QcStatement tests pick PID/QEAA roles (and mdoc) explicitly.
    const SDJWT: LeafPurpose = LeafPurpose::SdJwtVcIssuer(IssuerRole::NonQualifiedEaa);
    // The SD-JWT VC issuer purpose keyed to specific qualified roles (for the per-role QcStatement tests).
    const SDJWT_PID: LeafPurpose = LeafPurpose::SdJwtVcIssuer(IssuerRole::Pid);
    const SDJWT_QEAA: LeafPurpose = LeafPurpose::SdJwtVcIssuer(IssuerRole::Qeaa);
    // The mdoc Document Signer leaf purpose (requires the id-mso-mdl-DS EKU).
    const MDOC: LeafPurpose = LeafPurpose::MdocDocumentSigner;
    // A CA certificate presented directly as the "leaf" (a direct-pin of a root/sub-CA) carries CA
    // semantics, not a credential-leaf purpose; the trust-list-signer purpose imposes no leaf-purpose
    // constraint, the correct gate for these direct-pin-of-a-CA structural tests.
    const SIGNER: LeafPurpose = LeafPurpose::TrustListSigner;

    const CA_IACA: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/ca-iaca.cert.der");
    const SDJWT_ISSUER: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/sdjwt-issuer.cert.der");
    const MDOC_DS: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/mdoc-ds.cert.der");
    const WRONG_ISSUER: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/wrong-issuer.cert.der");
    // Chain-validation negative anchors (RFC 5280 §6.1.3 / §6.1.4): an EXPIRED issuing CA whose leaf
    // is itself in-window (only the anchor is out of its validity window), and a NON-CA "issuer"
    // (basicConstraints CA:FALSE, no keyCertSign) that nonetheless signs a leaf carrying its subject
    // as issuer. The genuine `ca-iaca` set cannot exercise these gates because it is a valid,
    // in-window CA. See tests/fixtures/attestation/gen.sh.
    const EXPIRED_CA: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/expired-ca.cert.der");
    const EXPIRED_CA_LEAF: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/expired-ca-leaf.cert.der");
    const NON_CA: &[u8] = include_bytes!("../../../../tests/fixtures/attestation/non-ca.cert.der");
    const NON_CA_LEAF: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/non-ca-leaf.cert.der");
    // Multi-tier (sub-CA) path fixtures (RFC 5280 §6.1 path length > 1): a dedicated root `mt-root`
    // (CA:TRUE,pathlen:1) anchoring a sub-CA `mt-intermediate` that issues `mt-leaf`, plus broken-hop
    // variants (non-CA intermediate, expired intermediate) and an attacker chain rooted at a
    // self-signed rogue CA. See tests/fixtures/attestation/gen.sh.
    const MT_ROOT: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/mt-root.cert.der");
    const MT_INTERMEDIATE: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/mt-intermediate.cert.der");
    const MT_LEAF: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/mt-leaf.cert.der");
    const MT_NOCA_INTERMEDIATE: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/mt-noca-intermediate.cert.der");
    const MT_NOCA_LEAF: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/mt-noca-leaf.cert.der");
    const MT_EXPIRED_INTERMEDIATE: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/mt-expired-intermediate.cert.der");
    const MT_EXPIRED_LEAF: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/mt-expired-leaf.cert.der");
    const ATTACKER_CA: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/attacker-ca.cert.der");
    const ATTACKER_LEAF: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/attacker-leaf.cert.der");
    // A self-signed CA with NO pathLenConstraint (CA:TRUE + keyCertSign), reusable as the issuer at
    // every hop of a synthetic over-cap chain — the pathLen gate does not short-circuit it, so the
    // length cap (PathTooLong) is the gate that fires. See tests/fixtures/attestation/gen.sh.
    const NOLEN_CA: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/nolen-ca.cert.der");
    const NOLEN_LEAF: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/nolen-leaf.cert.der");
    // Leaf key-purpose (EKU) fixtures, all issued by `mt-root` (a same-root trio): `mt-mdoc-ds` carries
    // the CORRECT mdlDS EKU (1.0.18013.5.1.2), `mt-mdoc-ds-serverauth` carries a FOREIGN serverAuth EKU,
    // and `mt-mdoc-ds-no-eku` carries NO EKU — isolating the leaf-purpose gate (only the EKU differs).
    // See tests/fixtures/attestation/gen.sh.
    const MT_MDOC_DS: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/mt-mdoc-ds.cert.der");
    const MT_MDOC_DS_SERVERAUTH: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/mt-mdoc-ds-serverauth.cert.der");
    const MT_MDOC_DS_NO_EKU: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/mt-mdoc-ds-no-eku.cert.der");
    // mdoc DS Table B.3 negatives (keyUsage / basicConstraints rows are `mc`): a cA=TRUE DS leaf and a
    // DS leaf whose keyUsage lacks digitalSignature (keyEncipherment only) — both carry the correct
    // mdlDS EKU and chain to mt-root, isolating the keyUsage/basicConstraints gates.
    const MT_MDOC_DS_CATRUE: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/mt-mdoc-ds-catrue.cert.der");
    const MT_MDOC_DS_WRONGKU: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/mt-mdoc-ds-wrongku.cert.der");
    // A leaf carrying an UNRECOGNIZED CRITICAL extension (private-arc OID, DER NULL value), issued by
    // mt-root — exercises the RFC 5280 §6.1.4 (o) / §6.1.5 (f) unknown-critical-extension reject.
    const MT_CRIT_UNKNOWN_LEAF: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/mt-crit-unknown-leaf.cert.der");
    // QEAA SD-JWT VC issuer leaf (QcCompliance + QcType id-etsi-qct-eseal), issued by ca-iaca — the
    // per-role QcStatement positive case for QEAA (and the negative case for PID, which needs qct-pid).
    const QC_QEAA_ISSUER: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/qc-qeaa-issuer.cert.der");
    // Name-constraints fixtures: `nc-intermediate` (issued by mt-root) permits directoryName subtree
    // `C=NL,O=Alkemio Test` and excludes `…,OU=Forbidden`; the three leaves sit in / out / inside the
    // excluded subtree (RFC 5280 §4.2.1.10 / §6.1.3 (b)(c) / §6.1.4 (g)).
    const NC_INTERMEDIATE: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/nc-intermediate.cert.der");
    const NC_LEAF_IN: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/nc-leaf-in.cert.der");
    const NC_LEAF_OUT: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/nc-leaf-out.cert.der");
    const NC_LEAF_EXCLUDED: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/nc-leaf-excluded.cert.der");
    // Cross-certificate / alternate-intermediate fixtures (backtracking path-walk): `xc-intermediate`
    // and `xc-deadend` share the SAME subject DN and key (so both validly issue `xc-leaf`) but have
    // DIFFERENT issuers — `xc-intermediate` is issued by `mt-root` (reaches the anchor), `xc-deadend` by
    // the rogue `attacker-ca` (a dead-end). Only a backtracking walk reaches mt-root when the dead-end is
    // tried first. See tests/fixtures/attestation/gen.sh.
    const XC_LEAF: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/xc-leaf.cert.der");
    const XC_INTERMEDIATE: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/xc-intermediate.cert.der");
    const XC_DEADEND: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/xc-deadend.cert.der");
    // Self-issued (key-rollover) fixtures (RFC 5280 §6.1.4 (l) / §4.2.1.9: self-issued certs are NOT
    // counted toward pathLenConstraint). Path si-leaf → si-subca → si-rollover → si-root: `si-root`
    // (pathlen:1) and `si-rollover` (SELF-ISSUED — subject DN == issuer DN — pathlen:1) precede the one
    // NON-self-issued sub-CA `si-subca`. Counting the rollover would exceed si-root's pathlen:1; excluding
    // it (per §6.1.4 (l)) the path validates. See tests/fixtures/attestation/gen.sh.
    const SI_ROOT: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/si-root.cert.der");
    const SI_ROLLOVER: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/si-rollover.cert.der");
    const SI_SUBCA: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/si-subca.cert.der");
    const SI_LEAF: &[u8] =
        include_bytes!("../../../../tests/fixtures/attestation/si-leaf.cert.der");
    // The signing-core RSA PKI (`sha256WithRSAEncryption`): an RSA CA that signs an RSA leaf —
    // exercises the RSA-PKCS#1v1.5 certificate-signature path, which the EC-only attestation
    // fixtures cannot. Reused (DRY) rather than minting a parallel RSA fixture set.
    const RSA_CA: &[u8] = include_bytes!("../../../../tests/fixtures/pki/ca.cert.der");
    const RSA_LEAF: &[u8] = include_bytes!("../../../../tests/fixtures/pki/signer-rsa.cert.der");

    // The fixtures are minted 2026-06-25 and the leaves are valid ~15 months (notBefore
    // 2026-06-25, notAfter 2027-09-23); pick a `now` inside every fixture's window (research D9 /
    // gen.sh DAYS_LEAF=455). The RSA leaf's window (2026-06-22..2028-09-24) also covers this. The
    // negative anchors' in-window leaves use a fixed 2026-01-01..2027-01-01 window that also covers
    // this instant, and the expired CA's window is 2018-01-01..2019-01-01 (long past).
    const NOW: i64 = 1_788_220_800; // 2026-09-01, comfortably inside the fixtures' validity.

    #[test]
    fn issuer_leaf_chains_to_trusted_iaca_root() {
        let anchors = vec![CA_IACA.to_vec()];
        assert!(verify_chain(&[SDJWT_ISSUER], &anchors, NOW, None, SDJWT).is_ok());
        assert!(verify_chain(&[MDOC_DS], &anchors, NOW, None, MDOC).is_ok());
    }

    #[test]
    fn self_issued_anchor_is_trusted_as_a_direct_pin() {
        // The root chained against itself: DER-equal direct pin (no issuer step needed).
        let anchors = vec![CA_IACA.to_vec()];
        assert!(verify_chain(&[CA_IACA], &anchors, NOW, None, SIGNER).is_ok());
    }

    #[test]
    fn expired_direct_pinned_leaf_is_rejected_not_trusted() {
        // A leaf that is byte-equal to a configured anchor (the direct-pin path — reachable for the
        // qualified-gate's TL-signer cert, pinned as both signer and scheme anchor) must STILL be
        // within its validity window. At a time past the cert's notAfter the direct pin must be
        // rejected as expired, not silently trusted (regression guard for the skipped-window bug).
        let anchors = vec![CA_IACA.to_vec()];
        let far_future = 4_000_000_000; // year ~2096, past every fixture's validity.
        assert_eq!(
            verify_chain(&[CA_IACA], &anchors, far_future, None, SIGNER),
            Err(ChainError::LeafExpired)
        );
    }

    #[test]
    fn leaf_chaining_to_an_expired_ca_anchor_is_rejected_not_trusted() {
        // RFC 5280 §6.1.3 (a)(2): EVERY certificate in the path (the issuing CA included) must be
        // valid at the time of interest. `expired-ca-leaf` is itself in-window at NOW, and its
        // signature verifies under `expired-ca` whose subject matches the leaf's issuer — but the
        // ANCHOR (expired-ca) is past its own notAfter (2018..2019). The leaf must be REJECTED as
        // `AnchorExpired`, never trusted (the anchor-validity-not-enforced fix).
        let anchors = vec![EXPIRED_CA.to_vec()];
        assert_eq!(
            verify_chain(&[EXPIRED_CA_LEAF], &anchors, NOW, None, SDJWT),
            Err(ChainError::AnchorExpired)
        );
    }

    #[test]
    fn leaf_chaining_to_a_non_ca_anchor_is_rejected_not_trusted() {
        // RFC 5280 §6.1.4 (k)/(n) + §4.2.1.9: an issuing certificate MUST assert basicConstraints
        // cA=TRUE and (if keyUsage is present) keyCertSign. `non-ca` is CA:FALSE with keyUsage
        // digitalSignature only, yet it signs `non-ca-leaf` (whose issuer is the non-ca subject and
        // whose signature verifies under it). The leaf must be REJECTED as `NotACa` — the classic
        // "any cert is a CA" gap — never trusted on the issued-by path.
        let anchors = vec![NON_CA.to_vec()];
        assert_eq!(
            verify_chain(&[NON_CA_LEAF], &anchors, NOW, None, SDJWT),
            Err(ChainError::NotACa)
        );
    }

    #[test]
    fn direct_pinned_end_entity_leaf_is_trusted_without_a_ca_constraint() {
        // The DIRECT-PIN model (anchor byte-equals the leaf) is a legitimate, distinct trust model:
        // pinning a specific END-ENTITY certificate as trusted is intentional and MUST NOT require
        // cA=TRUE. `sdjwt-issuer` is a CA:FALSE leaf; pinned directly and within its validity window
        // it is trusted as-is (no issued-by CA-constraint applies to the direct pin).
        let anchors = vec![SDJWT_ISSUER.to_vec()];
        assert!(verify_chain(&[SDJWT_ISSUER], &anchors, NOW, None, SDJWT).is_ok());
        // The non-CA fixture, pinned directly, is likewise trusted (CA constraint is issued-by only).
        let anchors = vec![NON_CA.to_vec()];
        assert!(verify_chain(&[NON_CA], &anchors, NOW, None, SDJWT).is_ok());
    }

    #[test]
    fn untrusted_leaf_not_chained_is_rejected_with_issuer_mismatch() {
        // wrong-issuer is self-signed under a different name → no anchor subject matches its issuer.
        let anchors = vec![CA_IACA.to_vec()];
        assert_eq!(
            verify_chain(&[WRONG_ISSUER], &anchors, NOW, None, SDJWT),
            Err(ChainError::IssuerMismatch)
        );
    }

    #[test]
    fn leaf_is_rejected_when_no_anchors_configured() {
        assert_eq!(
            verify_chain(&[SDJWT_ISSUER], &[], NOW, None, SDJWT),
            Err(ChainError::IssuerMismatch)
        );
    }

    #[test]
    fn empty_supplied_chain_is_rejected() {
        // A supplied chain with no leaf at all cannot validate (defensive: the production callers
        // always supply at least the leaf, but verify_chain must not panic on an empty slice).
        let anchors = vec![CA_IACA.to_vec()];
        assert_eq!(
            verify_chain(&[], &anchors, NOW, None, SDJWT),
            Err(ChainError::IssuerMismatch)
        );
    }

    #[test]
    fn leaf_outside_its_validity_window_is_rejected_as_expired() {
        // A time past the ~15-month leaf validity (notAfter 2027-09-23) but still WITHIN the IACA
        // root's window (notAfter 2036-06-22) → only the LEAF is expired, so the leaf-validity gate
        // fires (not the anchor-validity gate). The root still matches by name + signature.
        let anchors = vec![CA_IACA.to_vec()];
        let leaf_expired_root_valid = 1_893_456_000; // 2030-01-01: past the leaf, inside the root.
        assert_eq!(
            verify_chain(
                &[SDJWT_ISSUER],
                &anchors,
                leaf_expired_root_valid,
                None,
                SDJWT
            ),
            Err(ChainError::LeafExpired)
        );
    }

    #[test]
    fn malformed_leaf_is_rejected() {
        let anchors = vec![CA_IACA.to_vec()];
        let not_a_cert: &[u8] = b"not a certificate";
        match verify_chain(&[not_a_cert], &anchors, NOW, None, SDJWT) {
            Err(ChainError::Malformed(_)) => {}
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn tampered_leaf_signature_is_rejected() {
        // Flip the last byte of the issuer leaf's DER (inside its signature BIT STRING) → the
        // signature no longer verifies under the root. Re-parsing succeeds (DER still well-formed
        // enough), but the math fails.
        let mut tampered = SDJWT_ISSUER.to_vec();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xFF;
        let anchors = vec![CA_IACA.to_vec()];
        // Either the DER re-parse fails (Malformed) or the signature fails (SignatureInvalid);
        // both are correct rejections. The fixture flips a signature byte, so it must NOT be Ok.
        assert!(verify_chain(&[tampered.as_slice()], &anchors, NOW, None, SDJWT).is_err());
    }

    #[test]
    fn error_display_is_specific() {
        assert!(ChainError::IssuerMismatch.to_string().contains("anchor"));
        assert!(ChainError::SignatureInvalid.to_string().contains("verify"));
        assert!(ChainError::PathTooLong.to_string().contains("length"));
        assert!(ChainError::LeafExpired.to_string().contains("validity"));
        assert!(ChainError::AnchorExpired.to_string().contains("validity"));
        assert!(ChainError::NotACa.to_string().contains("CA"));
        assert!(ChainError::WrongLeafPurpose
            .to_string()
            .contains("key purpose"));
        assert!(ChainError::UnsupportedAlgorithm("1.2.3".into())
            .to_string()
            .contains("1.2.3"));
        assert!(ChainError::Malformed("x".into())
            .to_string()
            .contains("DER"));
        assert!(ChainError::UnsupportedCriticalExtension("9.9.9".into())
            .to_string()
            .contains("9.9.9"));
        assert!(ChainError::NameConstraintViolation
            .to_string()
            .contains("name constraint"));
        assert!(ChainError::SignatureAlgorithmMismatch
            .to_string()
            .contains("signatureAlgorithm"));
    }

    #[test]
    fn unrepresentable_validity_bounds_fail_closed() {
        // RFC 5280 §6.1.3 (a)(2) at the i64 boundary: a bound whose seconds overflow i64 must fail
        // CLOSED, never fail OPEN. `clamp_secs` saturates an unrepresentable bound to the supplied
        // rejecting sentinel: notBefore → i64::MAX (reads "not yet valid", since `now >= MAX` is
        // false for every real `now`), notAfter → i64::MIN (reads "already expired", since
        // `now <= MIN` is false). This is the boundary the prior `unwrap_or(i64::MAX)` got WRONG for
        // notAfter (an unrepresentable notAfter saturated to MAX = "never expires" = fail-open).
        // Representable seconds pass through unchanged (the common path).
        assert_eq!(clamp_secs(0, i64::MAX), 0);
        assert_eq!(clamp_secs(1_788_220_800, i64::MIN), 1_788_220_800);
        assert_eq!(
            clamp_secs(i64::MAX as u64, i64::MAX),
            i64::MAX,
            "the largest representable i64 second value round-trips"
        );
        // Unrepresentable seconds (> i64::MAX) saturate to the rejecting sentinel — fail closed.
        let overflow = (i64::MAX as u64) + 1;
        assert_eq!(
            clamp_secs(overflow, i64::MAX),
            i64::MAX,
            "notBefore that overflows i64 → i64::MAX (not-yet-valid) → reject"
        );
        assert_eq!(
            clamp_secs(overflow, i64::MIN),
            i64::MIN,
            "notAfter that overflows i64 → i64::MIN (already-expired) → reject"
        );
        assert_eq!(clamp_secs(u64::MAX, i64::MIN), i64::MIN);
        // End-to-end polarity (documented, not asserted to avoid a constant-assertion lint): a
        // notBefore sentinel of i64::MAX and a notAfter sentinel of i64::MIN both reject every real
        // `now` — `now >= i64::MAX` and `now <= i64::MIN` are both false for any finite instant such
        // as `NOW` — so the window collapses to empty and an unrepresentable bound never widens it.
    }

    #[test]
    fn rsa_leaf_chains_to_trusted_rsa_ca() {
        // Exercises the RSA-PKCS#1v1.5 (SHA-256) certificate-signature verification path. The RSA leaf
        // (the signing-core PKI's `signer-rsa`) carries no keyUsage extension, so it is validated under
        // the TrustListSigner purpose (which imposes no credential-leaf floor) — this test targets the
        // RSA signature math, not the SD-JWT VC issuer keyUsage/QcStatement profile.
        let anchors = vec![RSA_CA.to_vec()];
        assert!(verify_chain(&[RSA_LEAF], &anchors, NOW, None, SIGNER).is_ok());
    }

    #[test]
    fn rsa_leaf_with_wrong_anchor_is_issuer_mismatch() {
        // The RSA leaf's issuer is the RSA CA, not the EC IACA → no name match (TrustListSigner purpose,
        // as above, so the name/path gate is what fires, not the leaf profile).
        let anchors = vec![CA_IACA.to_vec()];
        assert_eq!(
            verify_chain(&[RSA_LEAF], &anchors, NOW, None, SIGNER),
            Err(ChainError::IssuerMismatch)
        );
    }

    #[test]
    fn unsupported_signature_algorithm_is_rejected() {
        // Re-encode the issuer leaf with BOTH its outer `signatureAlgorithm` AND its inner
        // `tbsCertificate.signature` OID swapped to Ed25519 (1.3.101.112) — a genuinely (if unsupported)
        // Ed25519-signed shape, outside the implemented baseline → UnsupportedAlgorithm (never a silent
        // accept). Both must be swapped so the inner/outer consistency gate (§4.1.1.2 / §4.1.2.3) does
        // not fire first; the name still matches the root, so the algorithm gate is what fires.
        let mut cert = Certificate::from_der(SDJWT_ISSUER).expect("parse leaf");
        let ed25519: der::asn1::ObjectIdentifier = "1.3.101.112".parse().expect("oid");
        cert.signature_algorithm.oid = ed25519;
        cert.tbs_certificate.signature.oid = ed25519;
        let mangled = cert.to_der().expect("re-encode");
        let anchors = vec![CA_IACA.to_vec()];
        match verify_chain(&[mangled.as_slice()], &anchors, NOW, None, SDJWT) {
            Err(ChainError::UnsupportedAlgorithm(oid)) => assert_eq!(oid, "1.3.101.112"),
            other => panic!("expected UnsupportedAlgorithm, got {other:?}"),
        }
    }

    #[test]
    fn malformed_anchor_is_skipped_and_a_good_anchor_still_matches() {
        // A malformed anchor in the set must not mask a valid match from a good anchor (the parser
        // records the malformed-anchor error but keeps scanning).
        let anchors = vec![b"garbage anchor".to_vec(), CA_IACA.to_vec()];
        assert!(verify_chain(&[SDJWT_ISSUER], &anchors, NOW, None, SDJWT).is_ok());
    }

    #[test]
    fn only_a_malformed_anchor_yields_a_specific_error() {
        // With *only* a malformed anchor, no name match is ever seen → IssuerMismatch (the engine
        // surfaces "no trusted anchor", not a parse panic).
        let anchors = vec![b"garbage anchor".to_vec()];
        assert_eq!(
            verify_chain(&[SDJWT_ISSUER], &anchors, NOW, None, SDJWT),
            Err(ChainError::IssuerMismatch)
        );
    }

    #[test]
    fn verify_rsa_supports_sha256_384_512_digests() {
        use super::verify_rsa;
        use der::Encode as _;
        // The RSA leaf is RSA-SHA256-signed; its TBS verifies under the CA's RSA key with SHA-256.
        let leaf = Certificate::from_der(RSA_LEAF).expect("parse rsa leaf");
        let ca = Certificate::from_der(RSA_CA).expect("parse rsa ca");
        let tbs = leaf.tbs_certificate.to_der().expect("tbs der");
        let sig = leaf.signature.as_bytes().expect("sig bytes");
        let spki = ca
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .expect("spki");
        // SHA-256 path: the genuine signature verifies.
        assert!(verify_rsa::<sha2::Sha256>(&spki, &tbs, sig).is_ok());
        // SHA-384 / SHA-512 paths: the function body runs end-to-end (key+sig parse), and the
        // wrong-digest signature is correctly rejected — covering the generic monomorphisations.
        assert!(verify_rsa::<sha2::Sha384>(&spki, &tbs, sig).is_err());
        assert!(verify_rsa::<sha2::Sha512>(&spki, &tbs, sig).is_err());
        // A malformed SPKI is rejected (not a panic).
        assert!(verify_rsa::<sha2::Sha256>(b"not spki", &tbs, sig).is_err());
    }

    #[test]
    fn verify_ecdsa_p256_rejects_a_non_p256_key() {
        use super::verify_ecdsa_p256;
        // Feeding an RSA SPKI to the P-256 path is a parse failure → SignatureInvalid, never panic.
        let ca = Certificate::from_der(RSA_CA).expect("parse rsa ca");
        let spki = der::Encode::to_der(&ca.tbs_certificate.subject_public_key_info).expect("spki");
        assert_eq!(
            verify_ecdsa_p256(&spki, b"msg", b"sig"),
            Err(ChainError::SignatureInvalid)
        );
    }

    #[test]
    fn anchor_asserts_ca_classifies_ca_and_non_ca_certs() {
        use super::anchor_asserts_ca;
        // The genuine IACA root asserts CRITICAL basicConstraints cA=TRUE + keyUsage keyCertSign → a
        // CA (with no intermediate following it, depth 0).
        let ca = Certificate::from_der(CA_IACA).expect("parse ca-iaca");
        assert!(
            anchor_asserts_ca(&ca, 0),
            "ca-iaca asserts critical cA=TRUE + keyCertSign"
        );
        // The RSA signing CA likewise asserts the CA constraints.
        let rsa_ca = Certificate::from_der(RSA_CA).expect("parse rsa ca");
        assert!(anchor_asserts_ca(&rsa_ca, 0), "the RSA test CA is a CA");
        // The non-CA fixture (CA:FALSE, keyUsage digitalSignature only) is NOT a CA.
        let non_ca = Certificate::from_der(NON_CA).expect("parse non-ca");
        assert!(!anchor_asserts_ca(&non_ca, 0), "CA:FALSE is not a CA");
        // The end-entity leaves (CA:FALSE) are not CAs either.
        let leaf = Certificate::from_der(SDJWT_ISSUER).expect("parse sdjwt-issuer");
        assert!(
            !anchor_asserts_ca(&leaf, 0),
            "an end-entity leaf is not a CA"
        );
    }

    #[test]
    fn anchor_asserts_ca_enforces_path_len_constraint() {
        use super::anchor_asserts_ca;
        // `ca-iaca` carries basicConstraints pathlen:0 → it may issue ONLY end-entity leaves (no
        // intermediate may follow it). depth 0 (issues a leaf directly) is permitted; depth 1 (one
        // intermediate below) exceeds pathLenConstraint and is rejected (§6.1.4 (m) / §4.2.1.9).
        let iaca = Certificate::from_der(CA_IACA).expect("parse ca-iaca");
        assert!(
            anchor_asserts_ca(&iaca, 0),
            "pathlen:0 permits 0 intermediates following"
        );
        assert!(
            !anchor_asserts_ca(&iaca, 1),
            "pathlen:0 rejects 1 intermediate following"
        );
        // `mt-root` carries pathlen:1 → at most one intermediate may follow it. depth 0 and depth 1 are
        // permitted; depth 2 exceeds the constraint and is rejected.
        let mt_root = Certificate::from_der(MT_ROOT).expect("parse mt-root");
        assert!(
            anchor_asserts_ca(&mt_root, 0),
            "pathlen:1 permits 0 intermediates following"
        );
        assert!(
            anchor_asserts_ca(&mt_root, 1),
            "pathlen:1 permits 1 intermediate following"
        );
        assert!(
            !anchor_asserts_ca(&mt_root, 2),
            "pathlen:1 rejects 2 intermediates following (§6.1.4 (m) / §4.2.1.9)"
        );
    }

    #[test]
    fn anchor_asserts_ca_rejects_non_critical_basic_constraints() {
        use super::anchor_asserts_ca;
        use const_oid::db::rfc5280::ID_CE_BASIC_CONSTRAINTS;
        // RFC 5280 §4.2.1.9: a conforming CA MUST mark basicConstraints CRITICAL. Take the genuine IACA
        // root (critical cA=TRUE) and clear the critical flag on its basicConstraints — it must then be
        // rejected as not-a-CA (a non-critical cA=TRUE is not a conforming CA; the criticality-ignored
        // gap fix).
        let mut ca = Certificate::from_der(CA_IACA).expect("parse ca-iaca");
        assert!(
            anchor_asserts_ca(&ca, 0),
            "baseline: critical cA=TRUE is a CA"
        );
        let bc = ca
            .tbs_certificate
            .extensions
            .as_mut()
            .expect("ca-iaca carries extensions")
            .iter_mut()
            .find(|e| e.extn_id == ID_CE_BASIC_CONSTRAINTS)
            .expect("ca-iaca carries basicConstraints");
        assert!(
            bc.critical,
            "fixture invariant: basicConstraints is minted critical"
        );
        bc.critical = false; // make it non-critical (the non-conforming shape §4.2.1.9 forbids).
        assert!(
            !anchor_asserts_ca(&ca, 0),
            "a NON-critical basicConstraints cA=TRUE must NOT be accepted as a CA (§4.2.1.9)"
        );
    }

    #[test]
    fn sig_alg_classifies_the_baseline_oids() {
        use const_oid::db::rfc5912;
        assert_eq!(
            SigAlg::from_oid(rfc5912::ECDSA_WITH_SHA_256),
            Ok(SigAlg::EcdsaP256Sha256)
        );
        assert_eq!(
            SigAlg::from_oid(rfc5912::SHA_256_WITH_RSA_ENCRYPTION),
            Ok(SigAlg::RsaSha256)
        );
        assert_eq!(
            SigAlg::from_oid(rfc5912::SHA_384_WITH_RSA_ENCRYPTION),
            Ok(SigAlg::RsaSha384)
        );
        assert_eq!(
            SigAlg::from_oid(rfc5912::SHA_512_WITH_RSA_ENCRYPTION),
            Ok(SigAlg::RsaSha512)
        );
        // ES384 (P-384) is outside the vendored P-256 stack → unsupported, honestly.
        assert!(matches!(
            SigAlg::from_oid(rfc5912::ECDSA_WITH_SHA_384),
            Err(ChainError::UnsupportedAlgorithm(_))
        ));
    }

    #[test]
    fn anchor_with_an_unparseable_key_usage_fails_closed_as_not_a_ca() {
        use super::anchor_asserts_ca;
        use const_oid::db::rfc5280::ID_CE_KEY_USAGE;
        // A CA whose basicConstraints say cA=TRUE but whose keyUsage extension cannot be decoded must
        // fail CLOSED (treated as not-a-CA), never trusted to issue. `x509-cert`'s typed
        // `get::<KeyUsage>()` returns Err when two keyUsage extensions are present, so duplicate the
        // extension on the genuine IACA root to drive the `Err(_) => false` fail-closed arm.
        let mut ca = Certificate::from_der(CA_IACA).expect("parse ca-iaca");
        let exts = ca
            .tbs_certificate
            .extensions
            .as_mut()
            .expect("ca-iaca carries extensions");
        let ku = exts
            .iter()
            .find(|e| e.extn_id == ID_CE_KEY_USAGE)
            .expect("ca-iaca carries keyUsage")
            .clone();
        exts.push(ku); // a second keyUsage ⇒ get::<KeyUsage>() is Err ⇒ fail closed.
        assert!(
            !anchor_asserts_ca(&ca, 0),
            "a cert with an unparseable (duplicate) keyUsage must fail closed as not-a-CA"
        );
    }

    // =============================================================================================
    // Multi-tier (sub-CA) path validation — RFC 5280 §6.1 path length > 1 over the SUPPLIED chain.
    // =============================================================================================

    #[test]
    fn two_tier_chain_through_intermediate_to_root_is_trusted() {
        // The conformant EUDI shape: x5c/x5chain = [leaf, intermediate] where the leaf is issued by an
        // intermediate sub-CA that chains to the trust-list-pinned root. The full supplied chain must
        // validate to the configured `mt-root` anchor (leaf → intermediate → root). This is the
        // one-hop-only regression: before path validation this was FALSE-REJECTED.
        let anchors = vec![MT_ROOT.to_vec()];
        assert!(
            verify_chain(&[MT_LEAF, MT_INTERMEDIATE], &anchors, NOW, None, SDJWT).is_ok(),
            "leaf → intermediate sub-CA → configured root must be trusted"
        );
    }

    #[test]
    fn two_tier_chain_rejected_when_root_not_configured() {
        // Same conformant chain, but the configured anchor is the unrelated `ca-iaca`, not `mt-root` —
        // the path cannot reach a configured anchor, so it is untrusted (no false-accept).
        let anchors = vec![CA_IACA.to_vec()];
        assert_eq!(
            verify_chain(&[MT_LEAF, MT_INTERMEDIATE], &anchors, NOW, None, SDJWT),
            Err(ChainError::IssuerMismatch)
        );
    }

    #[test]
    fn two_tier_chain_without_supplied_intermediate_cannot_reach_the_root() {
        // If the credential omits the intermediate (supplies only the leaf) the path cannot be built:
        // the leaf's issuer is the intermediate, which is neither supplied nor a configured anchor.
        let anchors = vec![MT_ROOT.to_vec()];
        assert_eq!(
            verify_chain(&[MT_LEAF], &anchors, NOW, None, SDJWT),
            Err(ChainError::IssuerMismatch)
        );
    }

    #[test]
    fn two_tier_chain_with_a_broken_intermediate_signature_is_rejected() {
        // Tamper the intermediate's DER (flip a signature byte) so its OWN signature under mt-root no
        // longer verifies. The leaf still chains to the (tampered) intermediate by name+signature, but
        // the intermediate→root hop fails → the path does not reach the anchor (rejected, not trusted).
        let mut bad_intermediate = MT_INTERMEDIATE.to_vec();
        let last = bad_intermediate.len() - 1;
        bad_intermediate[last] ^= 0xFF;
        let anchors = vec![MT_ROOT.to_vec()];
        assert!(
            verify_chain(
                &[MT_LEAF, bad_intermediate.as_slice()],
                &anchors,
                NOW,
                None,
                SDJWT
            )
            .is_err(),
            "a broken intermediate→root signature must not yield a trusted path"
        );
    }

    #[test]
    fn two_tier_chain_with_a_non_ca_intermediate_is_rejected_as_not_a_ca() {
        // RFC 5280 §6.1.4 (k)/(n): a path intermediate MUST be a CA. `mt-noca-intermediate` is CA:FALSE
        // (issued by mt-root) yet issues `mt-noca-leaf`. The leaf chains to it by name+signature, but
        // it cannot act as a path intermediate → NotACa (the CA-constraint gate on the intermediate).
        let anchors = vec![MT_ROOT.to_vec()];
        assert_eq!(
            verify_chain(
                &[MT_NOCA_LEAF, MT_NOCA_INTERMEDIATE],
                &anchors,
                NOW,
                None,
                SDJWT
            ),
            Err(ChainError::NotACa)
        );
    }

    #[test]
    fn two_tier_chain_with_an_expired_intermediate_is_rejected_as_anchor_expired() {
        // RFC 5280 §6.1.3 (a)(2): EVERY certificate on the path must be valid at the time of interest.
        // `mt-expired-intermediate` is a valid CA issued by mt-root but past its own window (2018..2019);
        // its leaf is in-window. The expired intermediate must reject the path (AnchorExpired), even
        // though the leaf's own window is current.
        let anchors = vec![MT_ROOT.to_vec()];
        assert_eq!(
            verify_chain(
                &[MT_EXPIRED_LEAF, MT_EXPIRED_INTERMEDIATE],
                &anchors,
                NOW,
                None,
                SDJWT
            ),
            Err(ChainError::AnchorExpired)
        );
    }

    #[test]
    fn attacker_supplied_intermediate_not_reaching_an_anchor_is_untrusted() {
        // The core security property: a supplied intermediate is attacker-controlled path-building
        // material, NEVER a trust root. The attacker presents [attacker-leaf, attacker-ca] where
        // attacker-ca is a self-signed CA that signs attacker-leaf — internally consistent (each hop
        // name-matches + verifies, attacker-ca is a CA) but terminating at a NON-anchor. It must be
        // rejected (the path never reaches the configured mt-root), so an attacker cannot manufacture
        // trust by supplying their own chain.
        let anchors = vec![MT_ROOT.to_vec()];
        assert_eq!(
            verify_chain(&[ATTACKER_LEAF, ATTACKER_CA], &anchors, NOW, None, SDJWT),
            Err(ChainError::IssuerMismatch),
            "an attacker chain that never reaches a configured anchor must be untrusted"
        );
        // Even configuring ca-iaca as well does not help the attacker — still no reachable anchor.
        let anchors = vec![MT_ROOT.to_vec(), CA_IACA.to_vec()];
        assert!(verify_chain(&[ATTACKER_LEAF, ATTACKER_CA], &anchors, NOW, None, SDJWT).is_err());
    }

    #[test]
    fn attacker_supplied_intermediate_is_ignored_when_the_leaf_directly_chains_to_an_anchor() {
        // A single-tier leaf that chains DIRECTLY to a configured anchor stays trusted even if the
        // attacker appends a bogus extra "intermediate": the path terminates at the anchor at the first
        // hop, so the trailing junk is never consulted (it is unreachable past the termination).
        let anchors = vec![CA_IACA.to_vec()];
        assert!(
            verify_chain(&[SDJWT_ISSUER, ATTACKER_CA], &anchors, NOW, None, SDJWT).is_ok(),
            "leaf chaining directly to the anchor is trusted; trailing supplied junk is ignored"
        );
    }

    #[test]
    fn intermediate_directly_pinned_as_an_anchor_is_trusted() {
        // A trusted-list entry may pin the INTERMEDIATE directly (anchor byte-equals mt-intermediate).
        // The leaf chains to the intermediate, which IS a configured anchor → trusted (direct pin of a
        // supplied cert terminates the path).
        let anchors = vec![MT_INTERMEDIATE.to_vec()];
        assert!(
            verify_chain(&[MT_LEAF, MT_INTERMEDIATE], &anchors, NOW, None, SDJWT).is_ok(),
            "an intermediate pinned directly as an anchor terminates the path as trusted"
        );
    }

    #[test]
    fn single_tier_chains_still_trusted_after_path_validation() {
        // Regression: the existing single-tier sdjwt-issuer / mdoc-ds → ca-iaca chains (the production
        // direct-IACA shape) remain trusted under the new path-validation primitive.
        let anchors = vec![CA_IACA.to_vec()];
        assert!(verify_chain(&[SDJWT_ISSUER], &anchors, NOW, None, SDJWT).is_ok());
        assert!(verify_chain(&[MDOC_DS], &anchors, NOW, None, MDOC).is_ok());
    }

    #[test]
    fn an_overlong_supplied_chain_is_rejected_as_path_too_long() {
        // DoS guard: a supplied chain longer than MAX_PATH_LEN must be rejected before the walk runs
        // unbounded. `nolen-ca` is SELF-SIGNED with NO pathLenConstraint (subject == issuer, and it
        // signed itself), so each copy supplied as a fresh entry name-matches AND signature-verifies as
        // the issuer of the previous one and, being a CA the pathLen gate never short-circuits, is
        // promoted — driving the `hops` DoS counter up one per hop. Because nolen-ca is SELF-ISSUED its
        // promotions do NOT grow the pathLen counter (RFC 5280 §6.1.4 (l)), which is exactly why the
        // DoS cap must be a SEPARATE total-hops counter: a self-issued-cert flood would otherwise evade
        // a pathLen-tied cap. With more than MAX_PATH_LEN such promotions and NO configured anchor to
        // terminate at, the hop cap (PathTooLong) fires (rather than NotACa/IssuerMismatch).
        let mut chain: Vec<&[u8]> = vec![NOLEN_LEAF];
        chain.extend(core::iter::repeat_n(NOLEN_CA, MAX_PATH_LEN + 2));
        let anchors = vec![MT_ROOT.to_vec()]; // present but never reached (rogue self-signed chain).
        assert_eq!(
            verify_chain(&chain, &anchors, NOW, None, SDJWT),
            Err(ChainError::PathTooLong),
            "a supplied chain longer than MAX_PATH_LEN must be rejected as PathTooLong"
        );
    }

    #[test]
    fn a_self_signed_nolen_ca_pinned_directly_is_trusted_but_not_via_an_issued_path() {
        // Coverage anchor for the nolen fixture's positive direction: pinned directly as an anchor the
        // self-signed CA is trusted (direct pin), and its leaf chains to it when it is the configured
        // anchor — confirming the fixture is a well-formed, usable CA (so the cap test's rejection is
        // the LENGTH cap, not a malformed/unusable cert).
        let anchors = vec![NOLEN_CA.to_vec()];
        assert!(verify_chain(&[NOLEN_LEAF, NOLEN_CA], &anchors, NOW, None, SDJWT).is_ok());
        assert!(verify_chain(&[NOLEN_LEAF], &anchors, NOW, None, SDJWT).is_ok());
    }

    // =============================================================================================
    // Leaf key-purpose (EKU) enforcement — ISO/IEC 18013-5:2021 Annex B (mdoc DS) + SD-JWT VC issuer.
    // =============================================================================================

    #[test]
    fn genuine_mdoc_ds_with_mdl_ds_eku_is_trusted_as_a_document_signer() {
        // The genuine ca-iaca-rooted DS fixture carries the critical mdlDS EKU (1.0.18013.5.1.2); under
        // the MdocDocumentSigner purpose it chains and is trusted (the EKU-present happy path).
        let anchors = vec![CA_IACA.to_vec()];
        assert!(verify_chain(&[MDOC_DS], &anchors, NOW, None, MDOC).is_ok());
        // The mt-root-rooted DS fixture (same correct EKU) is likewise trusted under its own root.
        let anchors = vec![MT_ROOT.to_vec()];
        assert!(verify_chain(&[MT_MDOC_DS], &anchors, NOW, None, MDOC).is_ok());
    }

    #[test]
    fn mdoc_ds_leaf_with_serverauth_eku_is_rejected_as_wrong_purpose() {
        // FALSE-ACCEPT guard: `mt-mdoc-ds-serverauth` chains PERFECTLY to the configured mt-root (same
        // root as the trusted `mt-mdoc-ds`), differing ONLY in its EKU — a foreign TLS serverAuth purpose
        // instead of mdlDS. Presented as an mdoc Document Signer leaf it MUST be rejected as
        // WrongLeafPurpose (ISO/IEC 18013-5 Annex B Table B.3 requires the DS EKU id-mso-mdl-DS), never
        // trusted just because the chain is sound.
        let anchors = vec![MT_ROOT.to_vec()];
        assert_eq!(
            verify_chain(&[MT_MDOC_DS_SERVERAUTH], &anchors, NOW, None, MDOC),
            Err(ChainError::WrongLeafPurpose),
            "a serverAuth leaf chained to the trusted root is NOT a valid mdoc DS"
        );
    }

    #[test]
    fn mdoc_ds_leaf_without_any_eku_is_rejected_as_wrong_purpose() {
        // The DS EKU is MANDATORY (ISO 18013-5 Annex B field type `m`); a DS leaf with NO EKU at all is
        // rejected even though it chains to the trusted root.
        let anchors = vec![MT_ROOT.to_vec()];
        assert_eq!(
            verify_chain(&[MT_MDOC_DS_NO_EKU], &anchors, NOW, None, MDOC),
            Err(ChainError::WrongLeafPurpose)
        );
    }

    #[test]
    fn serverauth_leaf_is_accepted_under_the_sdjwt_vc_issuer_purpose() {
        // The SAME serverAuth-EKU leaf, presented as an SD-JWT VC issuer (not an mdoc DS), is NOT
        // rejected for its EKU: no spec mandates an EKU for the SD-JWT VC issuer (verified online), and
        // the floor (not-a-CA + a signing keyUsage) is satisfied (it is CA:FALSE with digitalSignature).
        // This proves the purpose gate is FORMAT-SPECIFIC, not a blanket "must be mdlDS".
        let anchors = vec![MT_ROOT.to_vec()];
        assert!(
            verify_chain(&[MT_MDOC_DS_SERVERAUTH], &anchors, NOW, None, SDJWT).is_ok(),
            "a serverAuth EKU does not disqualify an SD-JWT VC issuer leaf (no mandated EKU)"
        );
    }

    #[test]
    fn genuine_sdjwt_issuer_is_trusted_under_the_issuer_purpose() {
        // The genuine SD-JWT VC issuer leaf (CA:FALSE, critical digitalSignature keyUsage, no EKU) is
        // trusted under the SdJwtVcIssuer purpose — the not-a-CA + signing-keyUsage floor is met.
        let anchors = vec![CA_IACA.to_vec()];
        assert!(verify_chain(&[SDJWT_ISSUER], &anchors, NOW, None, SDJWT).is_ok());
    }

    #[test]
    fn a_ca_certificate_presented_as_an_sdjwt_issuer_leaf_is_rejected() {
        // A CA certificate presented as an SD-JWT VC issuer LEAF is rejected (the issuer leaf MUST NOT be
        // a CA — a CA cert must not double as an end-entity signer). `mt-intermediate` is a CA:TRUE sub-CA
        // that CHAINS to the configured `mt-root` (so it is NOT a direct pin — the purpose floor applies);
        // under the SdJwtVcIssuer purpose it is WrongLeafPurpose despite the sound chain.
        let anchors = vec![MT_ROOT.to_vec()];
        assert_eq!(
            verify_chain(&[MT_INTERMEDIATE], &anchors, NOW, None, SDJWT),
            Err(ChainError::WrongLeafPurpose),
            "a CA certificate that chains to the anchor is still not a valid SD-JWT VC issuer leaf"
        );
    }

    #[test]
    fn a_directly_pinned_ca_root_is_exempt_from_the_leaf_purpose_check() {
        // The DIRECT-PIN exemption: a leaf byte-equal to a configured anchor is a deliberate operator
        // pin, exempt from the leaf-purpose floor (the same model that exempts a direct pin from the CA
        // constraint). An IACA / multi-tier root pinned directly is trusted under the SD-JWT VC issuer
        // purpose even though it is a CA (which the purpose floor would otherwise reject). The validity
        // window is still enforced — only the key-purpose floor is the operator's to waive.
        let anchors = vec![MT_ROOT.to_vec()];
        assert!(
            verify_chain(&[MT_ROOT], &anchors, NOW, None, SDJWT).is_ok(),
            "a directly-pinned CA root is trusted (purpose check waived for a direct pin)"
        );
        // And a directly-pinned CA root presented under the mdoc DS purpose is likewise exempt from the
        // mandatory-mdlDS-EKU floor (the operator pinned this exact cert).
        assert!(verify_chain(&[MT_ROOT], &anchors, NOW, None, MDOC).is_ok());
    }

    #[test]
    fn the_trust_list_signer_purpose_imposes_no_leaf_key_purpose_constraint() {
        // The TrustListSigner purpose (used for LOTL / national-TL signer authentication) imposes no
        // credential-leaf key purpose: a CA root pinned directly is trusted, and the serverAuth leaf
        // chained to mt-root is trusted — neither the not-a-CA nor the mdlDS-EKU rule applies.
        let anchors = vec![MT_ROOT.to_vec()];
        assert!(verify_chain(&[MT_ROOT], &anchors, NOW, None, SIGNER).is_ok());
        assert!(verify_chain(&[MT_MDOC_DS_SERVERAUTH], &anchors, NOW, None, SIGNER).is_ok());
    }

    #[test]
    fn a_malformed_or_duplicate_leaf_basic_constraints_fails_closed_under_the_issuer_purpose() {
        // Fail-closed: a leaf whose basicConstraints cannot be decoded (two basicConstraints extensions
        // ⇒ the typed `get::<BasicConstraints>()` returns Err) must be rejected under the SD-JWT VC
        // issuer purpose (we cannot prove it is not a CA), never trusted. Duplicate the extension on the
        // genuine issuer leaf and re-encode; it still chains by name+signature, but the purpose gate
        // fails closed first.
        use const_oid::db::rfc5280::ID_CE_BASIC_CONSTRAINTS;
        let mut cert = Certificate::from_der(SDJWT_ISSUER).expect("parse sdjwt-issuer");
        let exts = cert
            .tbs_certificate
            .extensions
            .as_mut()
            .expect("sdjwt-issuer carries extensions");
        let bc = exts
            .iter()
            .find(|e| e.extn_id == ID_CE_BASIC_CONSTRAINTS)
            .expect("sdjwt-issuer carries basicConstraints")
            .clone();
        exts.push(bc); // a second basicConstraints ⇒ get::<BasicConstraints>() is Err ⇒ fail closed.
        let mangled = cert.to_der().expect("re-encode");
        let anchors = vec![CA_IACA.to_vec()];
        assert_eq!(
            verify_chain(&[mangled.as_slice()], &anchors, NOW, None, SDJWT),
            Err(ChainError::WrongLeafPurpose)
        );
    }

    #[test]
    fn a_malformed_or_duplicate_leaf_key_usage_fails_closed_under_the_issuer_purpose() {
        // Fail-closed: a leaf whose keyUsage cannot be decoded (two keyUsage extensions ⇒ the typed
        // `get::<KeyUsage>()` returns Err) must be rejected under the SD-JWT VC issuer purpose, never
        // trusted. Duplicate the keyUsage extension on the genuine issuer leaf and re-encode.
        use const_oid::db::rfc5280::ID_CE_KEY_USAGE;
        let mut cert = Certificate::from_der(SDJWT_ISSUER).expect("parse sdjwt-issuer");
        let exts = cert
            .tbs_certificate
            .extensions
            .as_mut()
            .expect("sdjwt-issuer carries extensions");
        let ku = exts
            .iter()
            .find(|e| e.extn_id == ID_CE_KEY_USAGE)
            .expect("sdjwt-issuer carries keyUsage")
            .clone();
        exts.push(ku); // a second keyUsage ⇒ get::<KeyUsage>() is Err ⇒ fail closed.
        let mangled = cert.to_der().expect("re-encode");
        // The leaf still chains by name+signature to the root, but the purpose gate fails closed first.
        let anchors = vec![CA_IACA.to_vec()];
        assert_eq!(
            verify_chain(&[mangled.as_slice()], &anchors, NOW, None, SDJWT),
            Err(ChainError::WrongLeafPurpose)
        );
    }

    // =============================================================================================
    // Backtracking path-walk — an alternate / cross-certified intermediate must not false-reject.
    // =============================================================================================

    #[test]
    fn cross_certified_alternate_intermediate_is_found_by_backtracking() {
        // FALSE-REJECT guard: the supplied x5chain carries TWO intermediates that both validly issue the
        // leaf (same subject DN + same key) — `xc-deadend` (issued by the rogue attacker-ca, reaches no
        // anchor) and `xc-intermediate` (issued by mt-root, reaches the configured anchor). A greedy walk
        // that commits to the FIRST name-matching issuer (xc-deadend, supplied first) dead-ends and
        // false-rejects; a backtracking walk explores xc-intermediate and reaches mt-root. The dead-end
        // is supplied FIRST so the test fails without backtracking.
        let anchors = vec![MT_ROOT.to_vec()];
        assert!(
            verify_chain(
                &[XC_LEAF, XC_DEADEND, XC_INTERMEDIATE],
                &anchors,
                NOW,
                None,
                SDJWT
            )
            .is_ok(),
            "a credential reaching the anchor via SOME valid path must be trusted (backtracking)"
        );
        // Order-independence: the same chain with the reaching intermediate first is also trusted.
        assert!(verify_chain(
            &[XC_LEAF, XC_INTERMEDIATE, XC_DEADEND],
            &anchors,
            NOW,
            None,
            SDJWT
        )
        .is_ok());
    }

    #[test]
    fn cross_certified_chain_with_only_the_dead_end_intermediate_is_untrusted() {
        // Control: supplying ONLY the dead-end cross-cert (no path to mt-root) is correctly untrusted —
        // backtracking finds NO reaching path, so it does not manufacture trust.
        let anchors = vec![MT_ROOT.to_vec()];
        assert!(
            verify_chain(&[XC_LEAF, XC_DEADEND], &anchors, NOW, None, SDJWT).is_err(),
            "with no reaching intermediate the cross-cert leaf must stay untrusted"
        );
    }

    #[test]
    fn a_combinatorially_branchy_supplied_chain_is_bounded_not_exponential() {
        // DoS guard for the BACKTRACKING walk: an attacker supplies MANY MUTUALLY-name-matching certs —
        // `nolen-ca` is self-signed (subject DN == issuer DN), so EVERY supplied copy name-matches AND
        // signature-verifies as the issuer of EVERY other copy. A depth-bounded DFS that backtracks over
        // all of them would explore a FACTORIAL number of ordered branches (here ~30!/(30-8)! ≈ 10¹¹).
        // The global MAX_NODE_VISITS budget caps the TOTAL frames visited, so the walk terminates
        // promptly with a reject (PathTooLong) rather than hanging — and never trusts (no anchor is
        // reached). A hang here would be the unbounded-backtracking regression.
        let mut chain: Vec<&[u8]> = vec![NOLEN_LEAF];
        chain.extend(core::iter::repeat_n(NOLEN_CA, 30));
        let anchors = vec![MT_ROOT.to_vec()]; // present but never reached.
        assert_eq!(
            verify_chain(&chain, &anchors, NOW, None, SDJWT),
            Err(ChainError::PathTooLong),
            "a factorially-branchy attacker chain must be bounded-rejected, not hang or trust"
        );
    }

    // =============================================================================================
    // Self-issued (key-rollover) certificate path-length exclusion — RFC 5280 §6.1.4 (l) / §4.2.1.9.
    // =============================================================================================

    #[test]
    fn a_self_issued_rollover_cert_does_not_count_toward_path_length() {
        // FALSE-REJECT guard (RFC 5280 §6.1.4 (l) / §4.2.1.9): the path
        // si-leaf → si-subca → si-rollover → si-root has TWO intermediates following the pathlen:1 root,
        // but `si-rollover` is SELF-ISSUED (a key-rollover cert: subject DN == issuer DN), which is NOT
        // counted toward pathLenConstraint. The ONLY non-self-issued intermediate is si-subca (1 ≤ 1), so
        // the path validates. Counting the rollover (the bug) would make it 2 > 1 → a wrong NotACa reject.
        let anchors = vec![SI_ROOT.to_vec()];
        assert!(
            verify_chain(
                &[SI_LEAF, SI_SUBCA, SI_ROLLOVER],
                &anchors,
                NOW,
                None,
                SDJWT
            )
            .is_ok(),
            "a self-issued rollover cert mid-chain must not consume pathLen budget"
        );
    }

    #[test]
    fn the_self_issued_rollover_cert_is_classified_self_issued() {
        use super::is_self_issued;
        // The rollover cert's subject DN equals its issuer DN ⇒ self-issued; si-subca (a normal sub-CA)
        // is not. This is the property the pathLen-exclusion hinges on.
        let rollover = Certificate::from_der(SI_ROLLOVER).expect("parse si-rollover");
        assert!(is_self_issued(&rollover), "si-rollover is self-issued");
        let subca = Certificate::from_der(SI_SUBCA).expect("parse si-subca");
        assert!(!is_self_issued(&subca), "si-subca is not self-issued");
    }

    // =============================================================================================
    // Per-role eIDAS QcStatement enforcement on the SD-JWT VC issuer leaf (T1.3) — ETSI EN 319 412-5
    // / TS 119 412-6. The credential's role keys which QcStatement(s) the leaf SHALL carry.
    // =============================================================================================

    #[test]
    fn pid_issuer_with_qct_pid_is_trusted_as_pid_but_rejected_as_qeaa() {
        // `sdjwt-issuer` carries the QcType statement id-etsi-qct-pid (TS 119 412-6 PID-4.5-01): a valid
        // PID issuer leaf. As a PID it is trusted; presented as a QEAA it is rejected (a QEAA requires
        // QcCompliance + a qualified QcType, which the PID cert does not carry) — the in-band guard that
        // stops a PID/eSeal/EAA cert sharing a QTSP root from being trusted in the wrong qualified role.
        let anchors = vec![CA_IACA.to_vec()];
        assert!(verify_chain(&[SDJWT_ISSUER], &anchors, NOW, None, SDJWT_PID).is_ok());
        assert_eq!(
            verify_chain(&[SDJWT_ISSUER], &anchors, NOW, None, SDJWT_QEAA),
            Err(ChainError::WrongLeafPurpose),
            "a PID-QcType cert is not a valid QEAA issuer (no QcCompliance)"
        );
    }

    #[test]
    fn qeaa_issuer_with_qccompliance_is_trusted_as_qeaa_but_rejected_as_pid() {
        // `qc-qeaa-issuer` carries QcCompliance + QcType id-etsi-qct-eseal: a valid QEAA issuer leaf. As
        // a QEAA it is trusted; presented as a PID it is rejected (a PID requires id-etsi-qct-pid).
        let anchors = vec![CA_IACA.to_vec()];
        assert!(verify_chain(&[QC_QEAA_ISSUER], &anchors, NOW, None, SDJWT_QEAA).is_ok());
        assert_eq!(
            verify_chain(&[QC_QEAA_ISSUER], &anchors, NOW, None, SDJWT_PID),
            Err(ChainError::WrongLeafPurpose),
            "a QEAA (eseal) cert is not a valid PID issuer (no id-etsi-qct-pid)"
        );
    }

    #[test]
    fn a_leaf_without_qc_statements_is_rejected_for_qualified_roles_but_ok_as_non_qualified() {
        // A generic issuer leaf with NO qcStatements (the mt-root-rooted `mt-leaf`, CA:FALSE +
        // digitalSignature) chains to its anchor. Presented as a PID or QEAA it is rejected (the
        // role-required QcStatement is absent); as a NonQualifiedEAA (no Qc requirement) it is trusted.
        let anchors = vec![MT_ROOT.to_vec()];
        assert_eq!(
            verify_chain(&[MT_LEAF, MT_INTERMEDIATE], &anchors, NOW, None, SDJWT_PID),
            Err(ChainError::WrongLeafPurpose)
        );
        assert_eq!(
            verify_chain(&[MT_LEAF, MT_INTERMEDIATE], &anchors, NOW, None, SDJWT_QEAA),
            Err(ChainError::WrongLeafPurpose)
        );
        assert!(
            verify_chain(&[MT_LEAF, MT_INTERMEDIATE], &anchors, NOW, None, SDJWT).is_ok(),
            "a NonQualifiedEAA issuer imposes no QcStatement requirement"
        );
    }

    #[test]
    fn sd_jwt_issuer_leaf_without_key_usage_is_rejected() {
        // ETSI EN 319 412-2 §4.3.2 / 412-3 §4.3.1: keyUsage SHALL be present asserting a signing bit.
        // Strip the keyUsage extension from the genuine issuer leaf and re-encode — it still chains, but
        // the absent keyUsage now fails the issuer floor (the tightened "absent allowed" → "absent
        // rejected"). Use NonQualifiedEAA so only the keyUsage floor (not a QcStatement) is the gate.
        use const_oid::db::rfc5280::ID_CE_KEY_USAGE;
        let mut cert = Certificate::from_der(SDJWT_ISSUER).expect("parse sdjwt-issuer");
        let exts = cert
            .tbs_certificate
            .extensions
            .as_mut()
            .expect("sdjwt-issuer carries extensions");
        exts.retain(|e| e.extn_id != ID_CE_KEY_USAGE);
        let mangled = cert.to_der().expect("re-encode");
        let anchors = vec![CA_IACA.to_vec()];
        assert_eq!(
            verify_chain(&[mangled.as_slice()], &anchors, NOW, None, SDJWT),
            Err(ChainError::WrongLeafPurpose),
            "an SD-JWT VC issuer leaf with no keyUsage is rejected (keyUsage SHALL be present)"
        );
    }

    // =============================================================================================
    // mdoc DS leaf Table B.3 profile (ISO/IEC 18013-5:2021): keyUsage = digitalSignature + cA=FALSE.
    // =============================================================================================

    #[test]
    fn mdoc_ds_leaf_with_ca_true_is_rejected() {
        // Table B.3 basicConstraints row is `mc` = cA=FALSE: a DS leaf asserting cA=TRUE is rejected even
        // though it carries the mdlDS EKU + digitalSignature and chains to the trusted root.
        let anchors = vec![MT_ROOT.to_vec()];
        assert_eq!(
            verify_chain(&[MT_MDOC_DS_CATRUE], &anchors, NOW, None, MDOC),
            Err(ChainError::WrongLeafPurpose),
            "a cA=TRUE mdoc DS leaf violates Table B.3 basicConstraints (cA=FALSE)"
        );
    }

    #[test]
    fn mdoc_ds_leaf_without_digital_signature_key_usage_is_rejected() {
        // Table B.3 keyUsage row is `mc` = digitalSignature: a DS leaf whose keyUsage is keyEncipherment
        // (no digitalSignature) is rejected even with the correct mdlDS EKU + cA=FALSE.
        let anchors = vec![MT_ROOT.to_vec()];
        assert_eq!(
            verify_chain(&[MT_MDOC_DS_WRONGKU], &anchors, NOW, None, MDOC),
            Err(ChainError::WrongLeafPurpose),
            "an mdoc DS leaf without the digitalSignature keyUsage violates Table B.3"
        );
    }

    // =============================================================================================
    // Unrecognized critical extension reject (RFC 5280 §6.1.4 (o) / §6.1.5 (f)).
    // =============================================================================================

    #[test]
    fn leaf_with_an_unrecognized_critical_extension_is_rejected() {
        // The leaf meets the SD-JWT VC issuer floor and chains to mt-root, but carries an extension
        // marked CRITICAL whose OID the validator does not process → rejected fail-closed, carrying the
        // offending OID.
        let anchors = vec![MT_ROOT.to_vec()];
        match verify_chain(&[MT_CRIT_UNKNOWN_LEAF], &anchors, NOW, None, SDJWT) {
            Err(ChainError::UnsupportedCriticalExtension(oid)) => {
                assert_eq!(oid, "1.3.6.1.4.1.99999.1");
            }
            other => panic!("expected UnsupportedCriticalExtension, got {other:?}"),
        }
    }

    // =============================================================================================
    // Name constraints (RFC 5280 §4.2.1.10 / §6.1.3 (b)(c) / §6.1.4 (g)) — directoryName subtrees.
    // =============================================================================================

    #[test]
    fn leaf_within_an_intermediates_permitted_directory_name_subtree_is_trusted() {
        // `nc-intermediate` permits the directoryName subtree `C=NL,O=Alkemio Test`; `nc-leaf-in`'s
        // subject (C=NL,O=Alkemio Test,CN=…) lies within it → the path validates to mt-root.
        let anchors = vec![MT_ROOT.to_vec()];
        assert!(
            verify_chain(&[NC_LEAF_IN, NC_INTERMEDIATE], &anchors, NOW, None, SDJWT).is_ok(),
            "a leaf within the permitted directoryName subtree must be trusted"
        );
    }

    #[test]
    fn leaf_outside_the_permitted_subtree_is_rejected() {
        // `nc-leaf-out`'s subject (C=DE,O=Other Org,…) is outside the permitted `C=NL,O=Alkemio Test`
        // subtree → NameConstraintViolation, even though it chains by name+signature to mt-root.
        let anchors = vec![MT_ROOT.to_vec()];
        assert_eq!(
            verify_chain(&[NC_LEAF_OUT, NC_INTERMEDIATE], &anchors, NOW, None, SDJWT),
            Err(ChainError::NameConstraintViolation),
            "a leaf outside the permitted subtree must be rejected"
        );
    }

    #[test]
    fn leaf_inside_an_excluded_subtree_is_rejected() {
        // `nc-leaf-excluded`'s subject (C=NL,O=Alkemio Test,OU=Forbidden,…) is within the permitted
        // subtree but ALSO within the EXCLUDED `…,OU=Forbidden` subtree → NameConstraintViolation
        // (excluded wins over permitted).
        let anchors = vec![MT_ROOT.to_vec()];
        assert_eq!(
            verify_chain(
                &[NC_LEAF_EXCLUDED, NC_INTERMEDIATE],
                &anchors,
                NOW,
                None,
                SDJWT
            ),
            Err(ChainError::NameConstraintViolation),
            "a leaf within an excluded subtree must be rejected"
        );
    }

    // =============================================================================================
    // Inner/outer signatureAlgorithm consistency (RFC 5280 §4.1.1.2 / §4.1.2.3).
    // =============================================================================================

    #[test]
    fn inner_outer_signature_algorithm_mismatch_is_rejected() {
        // Swap ONLY the outer `signatureAlgorithm` OID (leave the signed inner `tbsCertificate.signature`
        // as ES256): the outer field is unauthenticated, so a substitution is a malformed/tampered cert
        // → SignatureAlgorithmMismatch (caught before the signature is even checked).
        let mut cert = Certificate::from_der(SDJWT_ISSUER).expect("parse leaf");
        let rsa: der::asn1::ObjectIdentifier = const_oid::db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION;
        cert.signature_algorithm.oid = rsa; // inner tbs.signature stays ecdsa-with-SHA256
        let mangled = cert.to_der().expect("re-encode");
        let anchors = vec![CA_IACA.to_vec()];
        assert_eq!(
            verify_chain(&[mangled.as_slice()], &anchors, NOW, None, SDJWT),
            Err(ChainError::SignatureAlgorithmMismatch),
            "outer signatureAlgorithm ≠ inner tbsCertificate.signature must be rejected"
        );
    }

    // =============================================================================================
    // The DS-validity-at-signing-time seam (ISO/IEC 18013-5 §9.3.1) — `leaf_validity_time`.
    // =============================================================================================

    #[test]
    fn ds_leaf_expired_at_now_but_valid_at_signed_is_trusted_via_the_seam() {
        // ISO 18013-5 §9.3.1: the DS cert window must contain the MSO `signed` time, not "now". `mdoc-ds`
        // is in-window at NOW but expired by 2030; ca-iaca (the anchor) is valid until 2036. At now=2030
        // (leaf expired) with `Some(signed=NOW)` the DS leaf is checked at its signing time → VALID (the
        // false-reject the seam fixes); with `None` the leaf is checked at now=2030 → LeafExpired.
        let anchors = vec![CA_IACA.to_vec()];
        let now_after_leaf = 1_893_456_000; // 2030-01-01: past the DS leaf's notAfter, inside ca-iaca.
        assert!(
            verify_chain(&[MDOC_DS], &anchors, now_after_leaf, Some(NOW), MDOC).is_ok(),
            "a DS cert expired at now but valid at the MSO `signed` time must be trusted (§9.3.1)"
        );
        assert_eq!(
            verify_chain(&[MDOC_DS], &anchors, now_after_leaf, None, MDOC),
            Err(ChainError::LeafExpired),
            "without the seam (None) the expired DS leaf is checked at now and rejected"
        );
    }

    #[test]
    fn ds_leaf_not_valid_at_signed_is_rejected() {
        // The other direction: a DS cert that is NOT within its window at the claimed `signed` time is
        // rejected as LeafExpired even when `now` is inside the leaf's window — the leaf window is judged
        // against `signed`, so a signing time outside it fails closed.
        let anchors = vec![CA_IACA.to_vec()];
        let signed_after_leaf = 1_893_456_000; // 2030-01-01: past the DS leaf's notAfter.
        assert_eq!(
            verify_chain(&[MDOC_DS], &anchors, NOW, Some(signed_after_leaf), MDOC),
            Err(ChainError::LeafExpired),
            "a DS cert not valid at the MSO `signed` time must be rejected"
        );
    }

    // =============================================================================================
    // Fail-closed parsing edges + the directoryName/dNSName subtree-matching helpers (unit-level).
    // =============================================================================================

    #[test]
    fn pub_eaa_issuer_without_qc_psb_is_rejected() {
        // PuB-EAA requires the QcPSB qcStatement (TS 119 412-6 PSB-8.3-01). `sdjwt-issuer` carries only
        // the PID QcType, so presented as a PuB-EAA issuer it is rejected (the QcPSB branch of the guard).
        let anchors = vec![CA_IACA.to_vec()];
        let pub_eaa = LeafPurpose::SdJwtVcIssuer(IssuerRole::PubEaa);
        assert_eq!(
            verify_chain(&[SDJWT_ISSUER], &anchors, NOW, None, pub_eaa),
            Err(ChainError::WrongLeafPurpose)
        );
    }

    #[test]
    fn a_duplicate_qc_statements_extension_fails_closed() {
        // A leaf with TWO qcStatements extensions cannot be unambiguously decoded → fail closed under a
        // role that requires a QcStatement (PID). Duplicate the extension on the genuine PID issuer leaf.
        let qc_oid: der::asn1::ObjectIdentifier =
            der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.3");
        let mut cert = Certificate::from_der(SDJWT_ISSUER).expect("parse sdjwt-issuer");
        let exts = cert
            .tbs_certificate
            .extensions
            .as_mut()
            .expect("sdjwt-issuer carries extensions");
        let qc = exts
            .iter()
            .find(|e| e.extn_id == qc_oid)
            .expect("sdjwt-issuer carries qcStatements")
            .clone();
        exts.push(qc); // a second qcStatements ⇒ Vec::<QcStatement>::from_der on a duplicate ⇒ fail closed.
        let mangled = cert.to_der().expect("re-encode");
        let anchors = vec![CA_IACA.to_vec()];
        assert_eq!(
            verify_chain(&[mangled.as_slice()], &anchors, NOW, None, SDJWT_PID),
            Err(ChainError::WrongLeafPurpose)
        );
    }

    #[test]
    fn an_mdoc_ds_leaf_with_a_duplicate_basic_constraints_fails_closed() {
        // The mdoc DS profile fails closed on an unparsable basicConstraints (duplicate extension): the
        // EKU + keyUsage pass, but the cA=FALSE check cannot decode → WrongLeafPurpose.
        use const_oid::db::rfc5280::ID_CE_BASIC_CONSTRAINTS;
        let mut cert = Certificate::from_der(MDOC_DS).expect("parse mdoc-ds");
        let exts = cert
            .tbs_certificate
            .extensions
            .as_mut()
            .expect("mdoc-ds carries extensions");
        let bc = exts
            .iter()
            .find(|e| e.extn_id == ID_CE_BASIC_CONSTRAINTS)
            .expect("mdoc-ds carries basicConstraints")
            .clone();
        exts.push(bc);
        let mangled = cert.to_der().expect("re-encode");
        let anchors = vec![CA_IACA.to_vec()];
        assert_eq!(
            verify_chain(&[mangled.as_slice()], &anchors, NOW, None, MDOC),
            Err(ChainError::WrongLeafPurpose)
        );
    }

    #[test]
    fn dns_within_subtree_matches_add_labels_on_the_left_case_insensitively() {
        use super::dns_within_subtree;
        // Equal, or one-or-more labels added on the left (RFC 5280 §4.2.1.10), case-insensitive (§7.2).
        assert!(dns_within_subtree("example.com", "example.com"));
        assert!(dns_within_subtree("example.com", "host.example.com"));
        assert!(dns_within_subtree("example.com", "a.b.EXAMPLE.com"));
        assert!(dns_within_subtree(".example.com", "host.example.com")); // leading-dot form tolerated
                                                                         // NOT within: a different domain, or a suffix that is not on a label boundary.
        assert!(!dns_within_subtree("example.com", "example.org"));
        assert!(!dns_within_subtree("example.com", "notexample.com"));
        assert!(!dns_within_subtree("example.com", "com"));
    }

    #[test]
    fn dns_within_subtree_normalizes_a_trailing_fqdn_dot() {
        use super::dns_within_subtree;
        // RFC 5280 §7.2: a trailing absolute-FQDN root dot must NOT let a leaf evade a subtree. An
        // un-normalized `strip_suffix` misses these — a fail-open in the EXCLUDED direction.
        assert!(dns_within_subtree("example.com", "evil.example.com.")); // trailing dot on the name
        assert!(dns_within_subtree("example.com.", "evil.example.com")); // trailing dot on the base
        assert!(dns_within_subtree("example.com", "example.com.")); // equal modulo the root dot
        assert!(!dns_within_subtree("example.com", "example.org.")); // still a different domain
    }

    #[test]
    fn dn_within_subtree_matches_case_and_encoding_variants() {
        use super::dn_within_subtree;
        use core::str::FromStr;
        use x509_cert::name::Name;
        // RFC 5280 §7.1 caseIgnoreMatch: `O=Example Org` and `O=example org` are the SAME DN, so a
        // case-variant subject must be recognized as within an excluded/permitted subtree — a byte-exact
        // compare fails open in the EXCLUDED direction. (Encoding-invariance — PrintableString vs
        // UTF8String — follows from the same value-based rendering.)
        let base = Name::from_str("O=Example Org").expect("parse base DN");
        assert!(dn_within_subtree(
            &base,
            &Name::from_str("O=example org").expect("parse case variant")
        ));
        // A genuinely different organization is NOT within the subtree.
        assert!(!dn_within_subtree(
            &base,
            &Name::from_str("O=Evil Org").expect("parse other")
        ));
    }

    #[test]
    fn name_constraint_dns_helpers_enforce_permitted_and_excluded() {
        use super::{check_dns_within, NameConstraintState};

        // A dNSName state: permitted example.com, excluded bad.example.com. (The directoryName helpers
        // `check_dn_within`/`dn_within_subtree` are exercised end-to-end by the `nc-leaf-*` fixtures,
        // which carry real DER-ordered subject DNs.)
        let nc = NameConstraintState {
            permitted_dns: vec![vec!["example.com".to_owned()]],
            excluded_dns: vec!["bad.example.com".to_owned()],
            ..Default::default()
        };
        assert!(nc.is_constrained());
        assert!(check_dns_within("host.example.com", &nc).is_ok()); // within permitted, not excluded
        assert_eq!(
            check_dns_within("other.org", &nc),
            Err(ChainError::NameConstraintViolation) // outside permitted
        );
        assert_eq!(
            check_dns_within("x.bad.example.com", &nc),
            Err(ChainError::NameConstraintViolation) // within excluded
        );

        // An empty state is unconstrained: any name passes and `is_constrained` is false.
        let empty = NameConstraintState::default();
        assert!(!empty.is_constrained());
        assert!(check_dns_within("anything.test", &empty).is_ok());
    }
}
