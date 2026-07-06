//! ISO/IEC 18013-5 mdoc verification.
//!
//! Verifies a presented mdoc `DeviceResponse` against the always-on bar (contracts/verifier.md),
//! owning the security-critical checks the only Rust mdoc library omits (research D3):
//!
//! 1. **`IssuerAuth` signature** — the `COSE_Sign1` over the Mobile Security Object (MSO) is verified
//!    with the Document Signer (DS) certificate's public key (ES256, via the SDK's `p256`/`ecdsa`),
//!    and the DS certificate is resolved from the `x5chain` COSE header and checked for trust through
//!    the pluggable [`crate::trust::TrustAnchorSource`] (the IACA root).
//! 2. **`valueDigests` integrity (in-house)** — each disclosed `IssuerSignedItem` is hashed (with the
//!    MSO `digestAlgorithm`) over its **on-wire `IssuerSignedItemBytes`** — the `#6.24(bstr)` element
//!    exactly as received (ISO/IEC 18013-5 §9.2.2.5), never a re-encode — and matched against the MSO
//!    `valueDigests`; any mismatch is rejected. This is the selective-disclosure-integrity check.
//! 3. **MSO `validityInfo` (in-house)** — the `signed` / `validFrom` / `validUntil` bounds are
//!    enforced at the verification instant.
//! 4. **`DeviceAuth` holder binding** — the `DeviceSignature` `COSE_Sign1` over the
//!    `DeviceAuthentication` structure (including the session transcript) is verified against the MSO
//!    `DeviceKey`. (The `DeviceMac` / ECDH variant is a documented follow-on — research D8.)
//!
//! Every failure path yields a specific [`crate::types::ReasonCode`] and never a false-accept
//! (SC-002). The module is **sans-IO** — it works from the passed `DeviceResponse` bytes, the
//! configured anchors, and (optionally) the session transcript alone, with no network.
//!
//! All crypto routes through the SDK's vetted RustCrypto stack plus `coset` (a COSE *codec*, not
//! crypto) and `ciborium` (CBOR) — no hand-rolled crypto (Principle IV).

use std::collections::{BTreeMap, BTreeSet};

use ciborium::value::Value;
use ciborium::Value as CborValue;
use coset::{AsCborValue, CoseSign1, Label, RegisteredLabelWithPrivate};
use sha2::{Digest, Sha384, Sha512};

use crate::status::StatusOutcome;
use crate::trust::TrustAnchorSource;
use crate::types::{
    AttributeValue, IssuerRole, ReasonCode, TrustStatus, Validity, VerificationResult,
};

/// The disclosed attributes of an mdoc, GROUPED BY NAMESPACE: `{ namespace → { elementIdentifier →
/// elementValue } }`. ISO/IEC 18013-5 `elementIdentifier`s are unique only WITHIN a namespace, so the
/// disclosure is a nested map keyed first by namespace (so the same `id` in two namespaces is a
/// distinct attribute, never a collision) and then by identifier. The verifier carries this strongly-
/// typed nested shape internally — it cannot be anything but a map by construction — and projects it to
/// the public [`VerificationResult::disclosed_attributes`] shape (`{ namespace → AttributeValue::Map }`)
/// once, at the end of [`verify_inner`], via [`namespace_grouped_attributes`].
type DisclosedByNamespace = BTreeMap<String, BTreeMap<String, AttributeValue>>;

/// The CBOR tag for an "encoded CBOR data item" (`#6.24`) — re-exported from the crate-level
/// [`crate::TAG_ENCODED_CBOR`] (the one authoritative definition; DRY — Principle III) so this
/// module's raw cursor (which recognizes the `#6.24(bstr)` wrapper head directly) and test helpers
/// read it under the local name.
use crate::TAG_ENCODED_CBOR;

/// The COSE header label for an X.509 certificate chain (`x5chain`), RFC 9360 — carried in the
/// `IssuerAuth` unprotected header as the DS certificate (or chain, leaf-first).
const COSE_HEADER_X5CHAIN: i64 = 33;

/// The COSE `crv` value for the NIST P-256 curve (IANA COSE Elliptic Curves registry).
const COSE_CRV_P256: i64 = 1;

/// COSE_Key label for the EC2 curve identifier (`-1`).
const COSE_KEY_CRV: i64 = -1;
/// COSE_Key label for the EC2 x-coordinate (`-2`).
const COSE_KEY_X: i64 = -2;
/// COSE_Key label for the EC2 y-coordinate (`-3`).
const COSE_KEY_Y: i64 = -3;
/// COSE_Key `kty` label (`1`).
const COSE_KEY_KTY: i64 = 1;
/// COSE_Key `kty` value for an EC2 key (`2`).
const COSE_KTY_EC2: i64 = 2;

/// The one ISO/IEC 18013-5 schema version this verifier implements. The standard fixes BOTH the
/// `DeviceResponse.version` (§8.3.2.1.2.2) and the `MobileSecurityObject.version` (§9.1.2.4) to the
/// text string `"1.0"`. An absent or different version is an unrecognized schema this verifier cannot
/// claim to validate, so it is rejected as malformed (never guessed/up-converted) — confirmed against
/// the ISO CDDL (e.g. the auth0-lab/mdl reference parser likewise enforces the MSO version is `"1.0"`).
const MDOC_SCHEMA_VERSION: &str = "1.0";

/// The hash algorithm named by the MSO `digestAlgorithm` field (ISO/IEC 18013-5 §9.1.2.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DigestAlgorithm {
    /// SHA-256 (the EUDI / ARF baseline).
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

impl DigestAlgorithm {
    /// Parse the MSO `digestAlgorithm` text field. ISO/IEC 18013-5 permits `SHA-256` / `SHA-384` /
    /// `SHA-512`; anything else is unrecognized and must be rejected (never guessed).
    fn from_name(name: &str) -> Option<Self> {
        match name {
            "SHA-256" => Some(Self::Sha256),
            "SHA-384" => Some(Self::Sha384),
            "SHA-512" => Some(Self::Sha512),
            _ => None,
        }
    }

    /// Compute the digest of `data` under this algorithm.
    fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            // SHA-256 routes through the crate's single authoritative digest (DRY — `crate::crypto`
            // is the one SHA-256 helper); SHA-384/512 are mdoc-only (no SD-JWT VC use), so they stay
            // on `sha2` here.
            Self::Sha256 => crate::crypto::sha256(data).to_vec(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
            Self::Sha512 => Sha512::digest(data).to_vec(),
        }
    }
}

/// An error encountered while parsing or verifying an mdoc `DeviceResponse`, paired with the specific
/// [`ReasonCode`] it surfaces to the caller.
///
/// Internal to the verifier: the public API returns a [`VerificationResult`] (never this), but
/// carrying the reason on the error lets every early-return map to the correct machine-readable code
/// with no chance of a generic "verification failed".
#[derive(Debug)]
struct VerifyFailure {
    /// The machine-readable reason this verification failed.
    reason: ReasonCode,
}

impl VerifyFailure {
    /// A structurally-malformed-credential failure (could not parse the CBOR/COSE).
    const fn malformed() -> Self {
        Self {
            reason: ReasonCode::MalformedCredential,
        }
    }

    /// A failure carrying a specific reason.
    const fn reason(reason: ReasonCode) -> Self {
        Self { reason }
    }
}

/// The verification instant and the optional session transcript needed to verify an mdoc.
///
/// `now_unix` is the time (Unix seconds) at which the MSO `validityInfo` window is enforced — passed
/// in (sans-IO) rather than read from the system clock so verification is deterministic and testable.
/// `session_transcript` is the CBOR-encoded `SessionTranscript` the holder's `DeviceSignature` is
/// computed over; it is supplied by the transport/OpenID4VP layer. ISO/IEC 18013-5 §9.1.5
/// `DeviceAuthentication` is **always** computed over a real `SessionTranscript` (the device-retrieval
/// transcript, or the OpenID4VP handover), so when a document asserts holder binding (carries a
/// `DeviceSignature`) and `session_transcript` is `None`, the verifier CANNOT confirm that binding and
/// MUST NOT fabricate a transcript to "pass" it. The verifier therefore rejects such a document with
/// [`ReasonCode::MissingRequestBinding`] rather than silently no-op the binding — the caller must
/// supply the explicit `SessionTranscript` (or, for OpenID4VP, the reconstructed handover via
/// [`crate::openid4vp`]).
#[derive(Debug, Clone)]
pub struct MdocVerifyParams<'a> {
    /// The verification instant, in Unix seconds, at which `validityInfo` is enforced.
    pub now_unix: i64,
    /// The CBOR-encoded ISO/IEC 18013-5 `SessionTranscript` the `DeviceSignature` is bound to.
    pub session_transcript: Option<&'a [u8]>,
    /// The issuer role under which DS trust is resolved against the anchors (mdoc anchors to an IACA
    /// root; the role selects the per-role/format anchor set).
    pub role: IssuerRole,
    /// The revocation/status outcomes (the T014 seam) — one canonical [`StatusOutcome`] **per document**,
    /// positional (index `i` is `documents[i]`'s status), resolved by the host through the status source.
    /// A `DeviceResponse` MAY carry MORE THAN ONE document, each with its OWN status-list pointer, so a
    /// single outcome cannot cover them (applying one to all would let a revoked second document ride
    /// inside a VALID verdict — SC-002). A document whose index is not covered by `statuses` fails closed
    /// to [`StatusOutcome::Unavailable`] (never a silent VALID). Mirrors the SD-JWT VC status seam (which
    /// carries a single credential's single outcome).
    pub statuses: &'a [StatusOutcome],
}

impl Default for MdocVerifyParams<'_> {
    /// A default suitable for the offline suite: no session transcript, the PID role (the role under
    /// which the test IACA anchor is configured), and a zero instant the caller is expected to set.
    /// Note: a `DeviceSignature`-bearing document verified with `session_transcript: None` is rejected
    /// as [`ReasonCode::MissingRequestBinding`] (§9.1.5 — the transcript is required); the caller must
    /// set an explicit transcript to verify the holder binding.
    fn default() -> Self {
        Self {
            now_unix: 0,
            session_transcript: None,
            role: IssuerRole::Pid,
            statuses: crate::status::DEFAULT_STATUSES,
        }
    }
}

/// Verify a presented ISO/IEC 18013-5 mdoc `DeviceResponse`.
///
/// Runs the mdoc always-on bar — `IssuerAuth` signature + DS trust, in-house `valueDigests`
/// integrity, MSO `validityInfo` (including the `signed` consistency check), and the `DeviceAuth`
/// holder binding — over **every** document in the response (and enforces the top-level
/// `DeviceResponse.status`). Returns a [`VerificationResult`]: `valid = true` with the disclosed
/// attributes only when every document clears every check, or `valid = false` carrying a single
/// specific [`ReasonCode`] on the first failure (no false-accept — SC-002). Verifying every document
/// is essential: a verdict that covered only `documents[0]` would let a forged second document ride
/// inside a VALID result unverified.
///
/// ## Disclosed-attributes shape (mdoc: namespace-grouped)
///
/// [`VerificationResult::disclosed_attributes`] for an mdoc is GROUPED BY NAMESPACE: each top-level key
/// is an ISO/IEC 18013-5 namespace, and its value is an [`AttributeValue::Map`] of that namespace's
/// `{ elementIdentifier: elementValue }` — i.e. `{ "org.iso.18013.5.1": Map({ "given_name": … }), … }`.
/// `elementIdentifier`s are unique only WITHIN a namespace, so a presentation MAY legitimately carry the
/// SAME id (e.g. `given_name`) in two namespaces with different values; grouping by namespace keeps
/// those distinct (never a false `DisclosureIntegrity` reject) and preserves the namespace provenance a
/// consumer needs. Across multiple documents the namespaces merge, with a same-`(namespace, id)`
/// conflicting value rejected as `DisclosureIntegrity` (an identical re-disclosure merges cleanly).
/// The byproducts the single always-on-bar pass already computed about a `DeviceResponse`, surfaced
/// alongside the [`VerificationResult`] so the callers that would otherwise RE-DECODE the same response
/// (the OpenID4VP replay classifier and the opt-in qualified gate) read these cached results instead.
///
/// Every field is derived from the ONE `ciborium` decode + per-document parse [`verify_with_meta`]
/// already performs; nothing here changes the verdict (it is the same `VerificationResult`
/// [`verify_with_meta`] returns) — it only avoids the duplicate decodes those callers used to trigger
/// (an attacker-multipliable soft-DoS lever: documents × IssuerAuth/MSO size).
#[derive(Debug, Clone, Default)]
pub struct MdocVerifyMeta {
    /// The `documents` array length (`0` when the response is too malformed to read it). The OpenID4VP
    /// replay classifier bounds its `Replay` re-attribution to the single-document case via this count,
    /// read from the bar's own decode (no separate `DeviceResponse` re-decode).
    pub document_count: usize,
    /// Per-document **claimed** issuer `(ds_cert_der, issuance_time_unix)` — the Document Signer leaf
    /// (DER) from `IssuerAuth.x5chain` PAIRED with the MSO `validityInfo.signed` — collected during a
    /// VALID bar pass (and EMPTY on any INVALID verdict). The opt-in [`crate::qualified`] gate folds
    /// these (it runs only on a VALID credential), reading EACH document's already-extracted cert + its
    /// issuance/relevant time rather than re-decoding the response. On a VALID credential `signed` is
    /// mandatory (the bar requires it), so this is the single source the gate folds — the per-document
    /// `(leaf, signed)` already paired by the bar pass.
    pub claimed_issuers: Vec<(Vec<u8>, i64)>,
    /// Per-document verified `docType` (the signed MSO `docType`, one per document), collected during a
    /// VALID bar pass (and EMPTY on any INVALID verdict). The in-core OpenID4VP DCQL gate
    /// ([`crate::dcql`]) matches these against the query's `meta.doctype_value` (mdoc `docType` ==
    /// `doctype_value`), reading the bar's already-decoded `docType` rather than re-decoding the
    /// response. On a VALID document the MSO `docType` equals the document `docType` (the bar enforces
    /// it), so this is the authoritative type view for the "did I get what I requested" check.
    pub doc_types: Vec<String>,
    /// The `DeviceAuth` holder-binding **machinery** soundness across every document — populated ONLY
    /// when the verdict is an INVALID [`ReasonCode::HolderBinding`] (the one case the OpenID4VP replay
    /// classifier consults it); `None` otherwise. Computed from the bar's already-decoded `documents`
    /// (no second `DeviceResponse` decode), and identical to the standalone [`device_binding_machinery`].
    pub binding_machinery: Option<DeviceBindingMachinery>,
}

/// Verify a presented mdoc `DeviceResponse` against the always-on bar (the IACA-rooted issuer chain,
/// the MSO `validityInfo` window, selective-disclosure integrity, and the `DeviceAuth` holder binding)
/// AND surface the [`MdocVerifyMeta`] the single bar pass already computed — the per-document claimed
/// issuer `(cert, issuance_time)`, the document count, and (on a `HolderBinding` failure) the
/// holder-binding-machinery soundness — so the OpenID4VP binding verifier and the qualified gate read
/// these cached results instead of re-decoding the response. This is the canonical mdoc entry point;
/// callers that do not need the meta simply take the [`VerificationResult`] (`.0`).
#[must_use]
pub fn verify_with_meta<A: TrustAnchorSource + ?Sized>(
    device_response: &[u8],
    anchors: &A,
    params: &MdocVerifyParams<'_>,
) -> (VerificationResult, MdocVerifyMeta) {
    match verify_inner(device_response, anchors, params) {
        Ok((result, meta)) => (result, meta),
        Err((failure, meta)) => (VerificationResult::invalid(failure.reason), meta),
    }
}

/// Whether a presented mdoc's `DeviceAuth` holder-binding **machinery** is structurally sound — used
/// to tell a fresh-nonce/transcript mismatch apart from a genuine holder-binding fault when a
/// [`verify_with_meta`] run returns [`ReasonCode::HolderBinding`].
///
/// A nonce/transcript mismatch (a replayed presentation) fails the `DeviceSignature` check **only**
/// because the verifier rebuilds `DeviceAuthentication` over a different transcript than the holder
/// signed — the binding machinery itself is intact: the `DeviceAuth` is a `DeviceSignature`, its alg
/// is ES256, the MSO `DeviceKey` parses, and the signature bytes form a well-formed ES256 signature.
/// A genuine fault (a corrupt/garbled signature, a non-ES256 alg, an unparseable `DeviceKey`, or a
/// `DeviceMac`-only `DeviceAuth`) is **transcript-independent** — it fails for ANY transcript — so it
/// is NOT a freshness mismatch and must keep [`ReasonCode::HolderBinding`].
///
/// [`crate::openid4vp`] uses this to attribute the failure precisely: `Sound` (every document's
/// binding machinery is intact) ⇒ the failure is the fresh-nonce mismatch ⇒ `Replay`; `Faulty` ⇒ a
/// real holder-binding fault ⇒ `HolderBinding` (never masked as `Replay`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceBindingMachinery {
    /// Every document's `DeviceAuth` is a well-formed ES256 `DeviceSignature` over a parseable MSO
    /// `DeviceKey` — so a failed binding is consistent with (only) a transcript/nonce mismatch.
    Sound,
    /// At least one document's binding is structurally broken (corrupt signature, non-ES256 alg,
    /// unparseable `DeviceKey`, or `DeviceMac`-only) — a transcript-INDEPENDENT holder-binding fault.
    Faulty,
}

/// Classify whether the `DeviceAuth` holder-binding **machinery** of every document in a
/// `DeviceResponse` is structurally sound (see [`DeviceBindingMachinery`]). Transcript-INDEPENDENT:
/// it checks the `DeviceAuth` shape, the `DeviceSignature` algorithm, the MSO `DeviceKey`, and that
/// the signature bytes form a well-formed ES256 signature — it deliberately does NOT verify the
/// signature against any payload, so it isolates a genuine binding fault (which fails for every
/// transcript) from a fresh-nonce mismatch (which fails only because the rebuilt transcript differs).
///
/// Used only to refine the failure attribution when [`verify_with_meta`] already returned
/// [`ReasonCode::HolderBinding`]; a malformed/absent structure conservatively reports `Faulty` (a
/// holder-binding fault is never silently downgraded to a replay).
///
/// This is the standalone (bytes-in) entry; [`verify_with_meta`] surfaces the SAME classification from
/// its own already-decoded `documents` (no second decode) via [`MdocVerifyMeta::binding_machinery`], so
/// the OpenID4VP replay classifier reads that cached value instead of calling this. Both route through
/// the shared `classify_binding_machinery` core, so the bytes-in and decoded-in answers are identical.
#[must_use]
pub fn device_binding_machinery(device_response: &[u8]) -> DeviceBindingMachinery {
    let Ok(root) = ciborium::from_reader::<CborValue, _>(device_response) else {
        // Unparseable bytes can't be classified → conservatively `Faulty` (never a silent replay).
        return DeviceBindingMachinery::Faulty;
    };
    // No `documents` array → too malformed to classify → conservatively `Faulty`.
    get_map_entry(&root, "documents")
        .and_then(CborValue::as_array)
        .map_or(DeviceBindingMachinery::Faulty, |documents| {
            classify_binding_machinery(documents)
        })
}

/// Classify the `DeviceAuth` holder-binding machinery soundness across an ALREADY-DECODED `documents`
/// array — the shared core of [`device_binding_machinery`] (bytes-in) and [`verify_with_meta`]'s meta
/// (which feeds its OWN decoded documents in, avoiding a second `DeviceResponse` decode). `Sound` iff
/// EVERY document's binding machinery is intact; an empty array, or any structurally-broken document,
/// is `Faulty` (a holder-binding fault is never silently downgraded to a replay).
fn classify_binding_machinery(documents: &[CborValue]) -> DeviceBindingMachinery {
    // Every document's binding machinery must be sound for the overall failure to be a (freshness)
    // replay; one structurally-broken binding (or an empty array) makes it a genuine binding fault.
    if !documents.is_empty() && documents.iter().all(device_binding_machinery_sound) {
        DeviceBindingMachinery::Sound
    } else {
        DeviceBindingMachinery::Faulty
    }
}

/// Whether a single `Document`'s `DeviceAuth` holder-binding machinery is structurally sound: the
/// `DeviceAuth` carries a `DeviceSignature` (not `DeviceMac`-only), its protected alg is ES256, the
/// MSO `DeviceKey` parses to a P-256 key, and the `DeviceSignature` bytes form a well-formed ES256
/// fixed-width raw `r‖s` signature. No payload is checked (transcript-independent).
///
/// The well-formed test matches the verifier's accepted-signature set exactly (raw `r‖s` only — RFC
/// 9053 §2.1; see [`crate::crypto::p256_verify_es256`]): a DER-encoded COSE signature is NOT well-formed
/// here, so it is classified `Faulty` — a genuine, transcript-INDEPENDENT binding fault that the verifier
/// now rejects for any transcript, never a freshness/replay signal.
fn device_binding_machinery_sound(document: &CborValue) -> bool {
    let check = || -> Option<bool> {
        // The MSO DeviceKey must parse (a malformed key is a binding fault, not a freshness issue).
        let issuer_signed = get_map_entry(document, "issuerSigned")?;
        let issuer_auth = parse_cose_sign1(get_map_entry(issuer_signed, "issuerAuth")?).ok()?;
        let mso_inner = unwrap_bstr_tagged_payload(issuer_auth.payload.as_ref()?).ok()?;
        let mso: CborValue = ciborium::from_reader(mso_inner.as_slice()).ok()?;
        if mso_device_key(&mso).is_err() {
            return Some(false);
        }

        // The DeviceAuth must be a DeviceSignature (a DeviceMac-only binding is a documented
        // follow-on, treated as a binding fault here — never a freshness replay).
        let device_signed = get_map_entry(document, "deviceSigned")?;
        let device_auth = get_map_entry(device_signed, "deviceAuth")?;
        let Some(device_signature_value) = get_map_entry(device_auth, "deviceSignature") else {
            return Some(false);
        };
        let Ok(device_signature) = parse_cose_sign1(device_signature_value) else {
            return Some(false);
        };
        // ES256 alg gate + a well-formed ES256 signature (r‖s or DER). A garbled/short signature is a
        // structural fault; a well-formed signature that simply doesn't match the rebuilt transcript
        // is the freshness signal.
        if !cose_alg_is_es256(&device_signature) {
            return Some(false);
        }
        // Raw fixed-width `r‖s` ONLY (RFC 9053 §2.1) — the same accepted set the verifier enforces,
        // parsed through the SHARED [`parse_es256_sig`] (DRY — Principle III) so "well-formed" here is
        // exactly what the verifier accepts. A DER-encoded signature is `None` (a structural fault that
        // fails for any transcript), not a freshness mismatch.
        let well_formed = parse_es256_sig(&device_signature.signature).is_some();
        Some(well_formed)
    };
    // A document too malformed to inspect is conservatively NOT sound (fault, never a silent replay).
    check().unwrap_or(false)
}

/// The disclosed attributes recovered by the **issuer-side** conformance verification of an mdoc
/// `DeviceResponse`'s first document, GROUPED BY NAMESPACE: keyed by namespace, each value an
/// [`AttributeValue::Map`] of that namespace's `{ elementIdentifier: elementValue }` (the same
/// namespace-grouped shape [`verify_with_meta`] returns — `elementIdentifier`s are unique only within
/// a namespace, ISO/IEC 18013-5).
///
/// Returned by [`verify_issuer_auth_against_vector`] — the external-vector entry that runs the
/// issuer-side bar (IssuerAuth signature + DS trust + MSO validity + `valueDigests` recompute) without
/// the holder `DeviceAuth` binding, for vectors whose `DeviceAuth` is the ISO device-retrieval
/// `DeviceMac` (not the OID4VP `DeviceSignature`).
#[cfg(any(test, feature = "test-vectors"))]
pub type IssuerVerifiedAttributes = BTreeMap<String, AttributeValue>;

/// Run the **issuer-side** always-on bar over a real ISO/IEC 18013-5 `DeviceResponse` vector's first
/// document — the `IssuerAuth` `COSE_Sign1` signature, DS-certificate trust, MSO `digestAlgorithm` /
/// `validityInfo` enforcement, and the in-house `valueDigests` recompute over every disclosed
/// `IssuerSignedItem` — returning the disclosed attributes on success or the specific [`ReasonCode`]
/// on the first failure.
///
/// This is the entry the **external-vector conformance** test drives (the ISO Annex-D worked example),
/// exercising the exact production `verify_issuer_signed` path — NOT a parallel re-implementation
/// (Principle III/VIII). It deliberately omits the holder `DeviceAuth` binding: the Annex-D vector's
/// `DeviceAuth` is the device-retrieval `DeviceMac` (an ECDH-derived HMAC over the ISO
/// `SessionTranscript`), which is a documented follow-on to this SDK's `DeviceSignature` path
/// (research D8) and out of scope for an issuer-signature conformance check. The issuer-signed parts
/// (signature + digests + validity) are what a real vector lets us prove byte-for-byte against an
/// independent, externally-authored credential.
///
/// # Errors
///
/// Returns the specific [`ReasonCode`] of the first issuer-side check that fails.
#[cfg(any(test, feature = "test-vectors"))]
pub fn verify_issuer_auth_against_vector<A: TrustAnchorSource + ?Sized>(
    device_response: &[u8],
    anchors: &A,
    params: &MdocVerifyParams<'_>,
) -> Result<IssuerVerifiedAttributes, ReasonCode> {
    let run = || -> Result<IssuerVerifiedAttributes, VerifyFailure> {
        let root: CborValue =
            ciborium::from_reader(device_response).map_err(|_| VerifyFailure::malformed())?;
        let document = first_document(&root)?;
        let doc_type = get_text(document, "docType").ok_or_else(VerifyFailure::malformed)?;
        let issuer_signed =
            get_map_entry(document, "issuerSigned").ok_or_else(VerifyFailure::malformed)?;
        // Capture the first document's on-wire `IssuerSignedItemBytes` (ISO/IEC 18013-5 §9.2.2.5
        // hashes the received bytes); the issuer-side check below consults these exact spans.
        let raw_items = scan_raw_issuer_items(device_response);
        // The external-vector path verifies the FIRST document only; use its positional status (index 0),
        // failing closed to `Unavailable` if the caller supplied none.
        let status = params
            .statuses
            .first()
            .copied()
            .unwrap_or(StatusOutcome::Unavailable);
        let verified = verify_issuer_signed(
            issuer_signed,
            raw_items.first(),
            anchors,
            &doc_type,
            status,
            params,
        )?;
        // Project the internal nested disclosure to the public namespace-grouped wire shape
        // (`{ ns: AttributeValue::Map({ id: value }) }`) — the same shape `verify` returns.
        Ok(namespace_grouped_attributes(verified.disclosed))
    };
    run().map_err(|failure| failure.reason)
}

/// The fallible verification body; [`verify_with_meta`] maps its error to a specific-reason INVALID
/// verdict. Returns the [`VerificationResult`] PAIRED with the [`MdocVerifyMeta`] the single decode +
/// bar pass produced (on BOTH the `Ok` and `Err` arms, so the cached byproducts are available whatever
/// the verdict): the per-document claimed issuer `(cert, issuance_time)` on success, and the document
/// count + (on a `HolderBinding` failure) the binding-machinery soundness — all from the ONE decode of
/// `root`, never a second `DeviceResponse` decode.
///
/// A `DeviceResponse` MAY carry more than one `Document`. The verdict is VALID only when **every**
/// document clears the full always-on bar — verifying just `documents[0]` would let a forged second
/// document ride inside a VALID verdict, with no signature/trust/validity/status/holder-binding check
/// (a false-accept). The top-level `DeviceResponse.version` (must be `"1.0"`) and `DeviceResponse.status`
/// (a non-zero `status` signals the holder reported an error and the response MUST NOT be treated as a
/// clean success) are enforced. A present `documentErrors` entry does NOT reject the response: ISO/IEC
/// 18013-5 §8.3 makes `documentErrors` informational — it names docType(s) the device could NOT return,
/// not a fault of the document(s) it DID return — so the verdict stands on the documents that ARE
/// present (an empty/absent `documents` array is still rejected: there is nothing to verify).
#[allow(clippy::type_complexity)] // the (result, meta) pair on both arms is the function's whole point
fn verify_inner<A: TrustAnchorSource + ?Sized>(
    device_response: &[u8],
    anchors: &A,
    params: &MdocVerifyParams<'_>,
) -> Result<(VerificationResult, MdocVerifyMeta), (VerifyFailure, MdocVerifyMeta)> {
    // --- Deterministic-CBOR gate: reject indefinite-length encoding BEFORE the permissive decode. ----
    // ISO/IEC 18013-5 §9.1.1 mandates deterministic CBOR for the mdoc structures, and RFC 8949 §4.2.1
    // (Core Deterministic Encoding Requirements) states "Indefinite-length items MUST NOT appear."
    // `ciborium::from_reader` below would otherwise ACCEPT an indefinite-length `DeviceResponse`, so it
    // is rejected up front with a single definite-length structural pre-scan of the whole item (the
    // integrity raw cursor already enforces this on the `IssuerSignedItemBytes`; this extends the same
    // guarantee to the top-level decode). Fail-closed → `MalformedCredential`.
    if reject_indefinite_length_cbor(device_response).is_err() {
        return Err((VerifyFailure::malformed(), MdocVerifyMeta::default()));
    }

    let root: CborValue = match ciborium::from_reader(device_response) {
        Ok(root) => root,
        // Unparseable bytes: nothing decoded, so the meta is empty (the failure is not `HolderBinding`).
        Err(_) => return Err((VerifyFailure::malformed(), MdocVerifyMeta::default())),
    };

    // The early structural gates below are NOT `HolderBinding`, so they need no binding-machinery meta;
    // `documents` may not even be readable yet. A tiny closure pairs each early failure with an empty
    // meta (the document count is filled once `documents` is in hand).
    let early = |failure: VerifyFailure| (failure, MdocVerifyMeta::default());

    // --- DeviceResponse.version: ISO/IEC 18013-5 §8.3.2.1.2.2 fixes the schema version to "1.0"; an
    //     absent/other version is an unrecognized DeviceResponse schema (reject as malformed). --------
    if get_text(&root, "version").as_deref() != Some(MDOC_SCHEMA_VERSION) {
        return Err(early(VerifyFailure::malformed()));
    }

    // --- DeviceResponse.status: a non-zero status (ISO/IEC 18013-5 §8.3.2.1.2.2) means the holder
    //     reported an error; a clean success is `status == 0`. A non-zero status MUST NOT carry a
    //     VALID verdict. -------------------------------------------------------------------------------
    enforce_device_response_status(&root).map_err(early)?;

    // --- documentErrors (ISO/IEC 18013-5 §8.3): INFORMATIONAL — it names docType(s) the device could
    //     NOT return, NOT a fault of the document(s) it DID return. A partially-fulfilled multi-doc
    //     request whose returned documents are all valid must therefore NOT be rejected merely because
    //     `documentErrors` is present; the verdict stands on the documents that ARE present (verified
    //     in full below). An empty/absent `documents` array is still rejected — there is nothing to
    //     verify. (Previously any `documentErrors` entry hard-rejected the response: an over-strict
    //     false-reject, conformance-audit T7.5.) ------------------------------------------------------

    let documents = match get_map_entry(&root, "documents").and_then(CborValue::as_array) {
        Some(documents) => documents,
        None => return Err(early(VerifyFailure::malformed())),
    };
    // An empty `documents` array carries nothing to verify; a VALID verdict over zero credentials is
    // meaningless, so reject it.
    if documents.is_empty() {
        return Err(early(VerifyFailure::malformed()));
    }

    // From here on `documents` is decoded, so every meta carries the document count; the binding
    // machinery is computed (from these SAME decoded documents — no re-decode) only when the bar fails
    // with `HolderBinding` (the one case the OpenID4VP replay classifier consults it).
    let document_count = documents.len();
    let fail = |failure: VerifyFailure| {
        let binding_machinery = (failure.reason == ReasonCode::HolderBinding)
            .then(|| classify_binding_machinery(documents));
        (
            failure,
            MdocVerifyMeta {
                document_count,
                claimed_issuers: Vec::new(),
                doc_types: Vec::new(),
                binding_machinery,
            },
        )
    };

    // Capture the on-wire `IssuerSignedItemBytes` of every document once, up front: ISO/IEC 18013-5
    // §9.2.2.5 hashes the bytes AS RECEIVED, so the `valueDigests` check below feeds on these exact
    // spans (keyed by `(namespace, digestID)`), never a re-encode. Indexed by document position.
    let raw_items = scan_raw_issuer_items(device_response);

    // Verify EVERY document; the verdict is VALID only if all pass. Disclosed attributes are merged
    // across documents into the single namespace-grouped result map (`{ ns: Map({ id: value }) }`)
    // WITHOUT silent shadowing: a second authentic document (same trusted DS, or a holder presenting two
    // credentials) MUST NOT be able to overwrite a claim a consumer reads with a conflicting value. The
    // conflict rule is keyed on the FULL `(namespace, id)` — the SAME `id` in two different namespaces
    // is a DISTINCT attribute and never collides. A same-`(namespace, id)` clash with a different value
    // is rejected (`DisclosureIntegrity`); an identical re-disclosure is harmless and merges cleanly.
    //
    // Each verified document also contributes its claimed-issuer `(cert, issuance_time)` to the meta the
    // qualified gate folds (the gate runs only on the VALID verdict this loop completing produces).
    let mut disclosed: DisclosedByNamespace = BTreeMap::new();
    let mut claimed_issuers: Vec<(Vec<u8>, i64)> = Vec::with_capacity(document_count);
    let mut doc_types: Vec<String> = Vec::with_capacity(document_count);
    // The SessionTranscript is invariant across the whole response; decode it ONCE here rather than
    // once per document (Ef2). `None` here covers BOTH "no transcript supplied" and "supplied but not
    // decodable CBOR": the per-document binding check still distinguishes them (absent →
    // `MissingRequestBinding` via `params.session_transcript`; present-but-`None` here → `malformed`)
    // at the SAME point the former per-document decode raised each.
    let session_transcript = params
        .session_transcript
        .and_then(|bytes| decode_session_transcript_value(bytes).ok());
    for (index, document) in documents.iter().enumerate() {
        // The raw-item capture is positional + best-effort; an out-of-range/absent entry yields an
        // empty map, so `verify_value_digests` fails that document's items closed (never a re-encode).
        let doc_raw_items = raw_items.get(index);
        // Per-document revocation status (positional): `documents[i]` is checked against `statuses[i]`.
        // An index the host supplied no status for fails closed to `Unavailable` — a multi-document
        // response with a single/short `statuses` slice MUST NOT silently reuse one outcome for every
        // document (that let a revoked document ride inside a VALID verdict — SC-002, conformance-audit).
        let doc_status = params
            .statuses
            .get(index)
            .copied()
            .unwrap_or(StatusOutcome::Unavailable);
        let (doc_disclosed, claimed_issuer) = verify_one_document(
            document,
            doc_raw_items,
            anchors,
            doc_status,
            session_transcript.as_ref(),
            params,
        )
        .map_err(fail)?;
        claimed_issuers.push(claimed_issuer);
        // The document's `docType` (verified == the signed MSO `docType` inside `verify_one_document`)
        // is the DCQL `doctype_value` match input the in-core OpenID4VP gate reads from the meta.
        if let Some(doc_type) = get_text(document, "docType") {
            doc_types.push(doc_type);
        }
        // `doc_disclosed` is namespace-grouped (`{ ns: { id: value } }`); merge each `(namespace, id,
        // value)` triple so the cross-document no-shadow rule is keyed per `(namespace, id)`.
        for (namespace, ns_map) in doc_disclosed {
            for (identifier, value) in ns_map {
                insert_no_shadow(&mut disclosed, &namespace, identifier, value).map_err(fail)?;
            }
        }
    }

    let result = VerificationResult {
        valid: true,
        // Project the strongly-typed nested disclosure to the public wire shape (`{ ns:
        // AttributeValue::Map({ id: value }) }`) exactly once, at the boundary.
        disclosed_attributes: namespace_grouped_attributes(disclosed),
        trust_status: TrustStatus::Trusted,
        qualified_status: None,
        reasons: Vec::new(),
    };
    Ok((
        result,
        MdocVerifyMeta {
            document_count,
            claimed_issuers,
            doc_types,
            binding_machinery: None,
        },
    ))
}

/// Project the strongly-typed namespace-grouped disclosure (`{ ns → { id → value } }`) to the public
/// [`VerificationResult::disclosed_attributes`] shape: `{ ns → AttributeValue::Map({ id → value }) }`.
/// The single place the internal nested map becomes the wire `AttributeValue` shape (so the merge logic
/// never has to re-unwrap an `AttributeValue::Map`).
fn namespace_grouped_attributes(
    disclosed: DisclosedByNamespace,
) -> BTreeMap<String, AttributeValue> {
    disclosed
        .into_iter()
        .map(|(namespace, ns_map)| (namespace, AttributeValue::Map(ns_map)))
        .collect()
}

/// Enforce the top-level `DeviceResponse.status` (ISO/IEC 18013-5 §8.3.2.1.2.2): the field is an
/// unsigned integer where `0` is OK; any other value (or a non-integer/absent status) is rejected.
/// A non-zero status (e.g. `10` general error, `11` CBOR decoding, `12` CBOR validation) means the
/// device did not return a clean success, so the response MUST NOT be accepted as VALID.
fn enforce_device_response_status(root: &CborValue) -> Result<(), VerifyFailure> {
    match get_integer(root, "status") {
        Some(0) => Ok(()),
        // A present-but-non-zero status is an explicit device-reported error.
        Some(_) => Err(VerifyFailure::reason(ReasonCode::MalformedCredential)),
        // `status` is a mandatory field of `DeviceResponse`; an absent/non-integer status is a
        // structurally malformed response.
        None => Err(VerifyFailure::malformed()),
    }
}

/// Run the full always-on bar over a single `Document`, returning its disclosed attributes (GROUPED BY
/// NAMESPACE — `{ ns: { id: value } }`; see [`verify_value_digests`]) PAIRED with that document's
/// claimed-issuer `(ds_cert_der, issuance_time)` (the signature/trust-verified Document Signer leaf and
/// the MSO `signed`) on success — the cached input the opt-in qualified gate folds per document.
///
/// `raw_items` is the on-wire `IssuerSignedItemBytes` captured for THIS document (keyed by
/// `(namespace, digestID)`), the digest input ISO/IEC 18013-5 §9.2.2.5 hashes; `None` when the raw
/// pass could not place this document (then the `valueDigests` check fails its items closed).
fn verify_one_document<A: TrustAnchorSource + ?Sized>(
    document: &CborValue,
    raw_items: Option<&RawDocumentItems<'_>>,
    anchors: &A,
    status: StatusOutcome,
    session_transcript: Option<&CborValue>,
    params: &MdocVerifyParams<'_>,
) -> Result<(DisclosedByNamespace, (Vec<u8>, i64)), VerifyFailure> {
    let doc_type = get_text(document, "docType").ok_or_else(VerifyFailure::malformed)?;
    let issuer_signed =
        get_map_entry(document, "issuerSigned").ok_or_else(VerifyFailure::malformed)?;

    // --- Issuer-side bar: IssuerAuth signature + DS trust + MSO validity + valueDigests integrity. --
    let issuer_verified =
        verify_issuer_signed(issuer_signed, raw_items, anchors, &doc_type, status, params)?;

    // --- DeviceAuth holder binding: DeviceSignature over DeviceAuthentication w/ the MSO DeviceKey. --
    verify_device_binding(
        document,
        &issuer_verified.device_key,
        &doc_type,
        session_transcript,
        params,
    )?;

    let claimed_issuer = (issuer_verified.ds_cert_der, issuer_verified.issuance_time);
    Ok((issuer_verified.disclosed, claimed_issuer))
}

/// The result of verifying the **issuer-signed** half of an mdoc document: the disclosed attributes
/// (after the `valueDigests` integrity recompute), the MSO `DeviceKey` the holder binding is checked
/// against, and the claimed-issuer `(ds_cert_der, issuance_time)` the opt-in qualified gate reads.
struct IssuerVerified {
    /// The disclosed attributes (GROUPED BY NAMESPACE — `{ ns: { id: value } }`), after each
    /// `IssuerSignedItem` digest was recomputed and matched. See [`verify_value_digests`].
    disclosed: DisclosedByNamespace,
    /// The holder's `DeviceKey` extracted from the MSO (the input to the `DeviceAuth` binding check).
    device_key: DeviceKey,
    /// The Document Signer leaf certificate (DER) from the `IssuerAuth` `x5chain` — the signature- and
    /// trust-verified leaf, surfaced so the qualified gate need not re-resolve it from the response.
    ds_cert_der: Vec<u8>,
    /// The credential's issuance/relevant time (Unix seconds) — the MSO `validityInfo.signed` (always
    /// present on this VALID path; ISO/IEC 18013-5 §9.1.2.4) the qualified gate reads status AT.
    issuance_time: i64,
}

/// Verify the **issuer-signed** half of an mdoc `Document` (everything the issuer signs, independent
/// of the holder's `DeviceAuth`): parse the `IssuerAuth` `COSE_Sign1` + the MSO it carries, verify the
/// `IssuerAuth` ES256 signature with the DS certificate, resolve DS trust against the configured
/// `anchors`, parse + enforce the MSO `digestAlgorithm` / `validityInfo` / status / `docType`
/// consistency, and recompute every disclosed `IssuerSignedItem` digest against the MSO `valueDigests`.
///
/// This is the single authoritative issuer-side verification path: [`verify_one_document`] runs it and
/// then adds the holder binding, while the external-vector conformance test
/// ([`verify_issuer_auth_against_vector`]) runs exactly this against a real ISO/IEC 18013-5 Annex-D
/// vector whose `DeviceAuth` uses the device-retrieval `DeviceMac` (not the OID4VP `DeviceSignature`),
/// so the two callers share one implementation (no parallel re-verification — Principle III/VIII).
fn verify_issuer_signed<A: TrustAnchorSource + ?Sized>(
    issuer_signed: &CborValue,
    raw_items: Option<&RawDocumentItems<'_>>,
    anchors: &A,
    doc_type: &str,
    status: StatusOutcome,
    params: &MdocVerifyParams<'_>,
) -> Result<IssuerVerified, VerifyFailure> {
    // --- Parse the IssuerAuth COSE_Sign1 and the MSO it carries. -----------------------------------
    let issuer_auth_value =
        get_map_entry(issuer_signed, "issuerAuth").ok_or_else(VerifyFailure::malformed)?;
    let issuer_auth = parse_cose_sign1(issuer_auth_value)?;
    let mso_bytes = issuer_auth
        .payload
        .as_ref()
        .ok_or_else(VerifyFailure::malformed)?;
    // The COSE_Sign1 payload bytes ARE the CBOR of the `#6.24(bstr .cbor MSO)` tagged item.
    let mso_inner = unwrap_bstr_tagged_payload(mso_bytes)?;
    let mso: CborValue =
        ciborium::from_reader(mso_inner.as_slice()).map_err(|_| VerifyFailure::malformed())?;

    // MSO `version`: ISO/IEC 18013-5 §9.1.2.4 fixes the MobileSecurityObject version to "1.0"; an
    // absent/other version is an unrecognized MSO schema (reject as malformed, never guessed).
    if get_text(&mso, "version").as_deref() != Some(MDOC_SCHEMA_VERSION) {
        return Err(VerifyFailure::malformed());
    }

    // --- Resolve the DS chain from the x5chain and verify the IssuerAuth signature under the leaf. ---
    // The full x5chain (leaf-first) is read, not just the leaf: an mdoc DS leaf may chain to the
    // trusted IACA root through an intermediate sub-CA, so the supplied intermediates are needed as
    // path-building material for the trust step (RFC 5280 §6.1 path validation).
    let ds_chain = ds_chain_from_x5chain(&issuer_auth)?;
    let (ds_cert_der, supplied_intermediates) = ds_chain
        .split_first()
        .ok_or_else(VerifyFailure::malformed)?;
    // Verify the IssuerAuth ES256 signature over the MSO with the DS certificate's key.
    verify_cose_sign1_es256(&issuer_auth, ds_cert_der)?;

    // --- Role derivation/validation (conformance-audit T4.3). The signed MSO `docType` (verified above;
    //     its consistency with the document `docType` is checked below) selects/validates the trust-
    //     anchoring role: a EUDI PID `docType` MUST anchor under `IssuerRole::Pid`, so a caller role that
    //     contradicts the credential's claimed type is rejected (`RoleMismatch`) rather than silently
    //     anchoring under the wrong per-role IACA list. A `docType` with no standardized role mapping
    //     keeps the caller's role. The reconciled role is what the trust step below anchors against.
    let effective_role = match get_text(&mso, "docType") {
        Some(doc_type) => {
            crate::dcql::reconcile_role(params.role, crate::types::Format::Mdoc, &doc_type)
                .map_err(|()| VerifyFailure::reason(ReasonCode::RoleMismatch))?
        }
        // No MSO `docType` to derive from → keep the caller role (the missing `docType` is rejected by
        // the MSO-vs-document `docType` consistency check below).
        None => params.role,
    };

    // --- MSO validityInfo: parsed FIRST so its `signed` time is the DS-leaf validity instant. --------
    // ISO/IEC 18013-5 §9.3.1 requires the Document Signer certificate's validity window to contain the
    // MSO `signed` time (DS certs rotate ~monthly while mDLs live for years → checking the DS window at
    // `now` would false-reject a conformant mDL once its DS cert expired). `signed` (== `issuance_time`)
    // is also the credential's relevant time the qualified gate reads status at. (Parsing it here, ahead
    // of the trust step, also runs its `signed`-not-in-future / `signed`-before-`validFrom` tamper
    // checks before trust — both are reject paths, so the order does not change any VALID verdict.)
    let (validity, issuance_time) = parse_validity_info(&mso, params.now_unix)?;

    // --- IssuerAuth trust: the DS leaf's certification path (leaf + supplied x5chain intermediates)
    //     must validate to the configured anchor for the role/format. -------------------------------
    let decision = anchors.resolve(
        effective_role,
        crate::types::Format::Mdoc,
        ds_cert_der,
        supplied_intermediates,
        // ISO 18013-5 §9.3.1: the DS leaf's window is checked against the MSO `signed` time, not `now`
        // (the rest of the chain — intermediates → IACA anchor — stays at `now`). This is the seam that
        // stops a conformant, in-window mDL from being false-rejected after its DS certificate expires.
        Some(issuance_time),
    );
    if !decision.trusted {
        // A chain failure carries a coarse-but-accurate `TrustFailure`: an expired/not-yet-valid cert on
        // the DS path → `Expired` (not a misleading `UntrustedIssuer`), any other no-trust → `UntrustedIssuer`.
        return Err(VerifyFailure::reason(
            decision
                .failure
                .unwrap_or_else(crate::trust::TrustFailure::not_trusted)
                .reason_code(),
        ));
    }

    // --- MSO digestAlgorithm + validity-window enforcement (at the verification instant `now`). -------
    let digest_alg_name = get_text(&mso, "digestAlgorithm").ok_or_else(VerifyFailure::malformed)?;
    let digest_alg =
        DigestAlgorithm::from_name(&digest_alg_name).ok_or_else(VerifyFailure::malformed)?;
    enforce_validity(&validity, params.now_unix)?;

    // --- Revocation / status (the T014 seam): THIS document's own outcome maps onto the bar. --------
    match status {
        StatusOutcome::NoStatus | StatusOutcome::Good => {}
        StatusOutcome::Revoked => return Err(VerifyFailure::reason(ReasonCode::Revoked)),
        StatusOutcome::Unavailable => {
            return Err(VerifyFailure::reason(ReasonCode::StatusUnavailable))
        }
    }

    // The MSO docType MUST match the document's docType (a mismatch is a structural tamper).
    if get_text(&mso, "docType").as_deref() != Some(doc_type) {
        return Err(VerifyFailure::reason(ReasonCode::Tamper));
    }

    // --- valueDigests integrity (in-house): recompute each disclosed item's digest. -----------------
    let disclosed = verify_value_digests(issuer_signed, raw_items, &mso, digest_alg)?;

    // --- Extract the MSO DeviceKey (the input to the DeviceAuth holder binding the caller runs). -----
    let device_key = mso_device_key(&mso)?;

    Ok(IssuerVerified {
        disclosed,
        device_key,
        ds_cert_der: ds_cert_der.clone(),
        issuance_time,
    })
}

// =================================================================================================
// Raw `IssuerSignedItemBytes` capture (ISO/IEC 18013-5 §9.2.2.5 hashes the bytes AS RECEIVED).
//
// The MSO `valueDigests` digest is computed over "the binary data of the IssuerSignedItem"
// (§9.2.2.5), i.e. each `IssuerSignedItemBytes = #6.24(bstr .cbor IssuerSignedItem)` element of
// `IssuerSigned.nameSpaces`, hashed EXACTLY as it appears on the wire. Decoding to a `ciborium`
// `Value` and re-encoding the tagged item is *not* guaranteed to reproduce those bytes: ciborium
// preserves the inner `bstr` content verbatim but re-derives the outer tag + length framing, so a
// valid-but-non-canonical issuer (one whose `#6.24`/length head is not minimal-length) would be
// FALSE-REJECTED. ISO/IEC 18013-5 §9.1.1 requires Canonical-CBOR length encoding, so a conformant
// issuer round-trips — but the digest input MUST still be the received bytes, never a re-encode, so
// the verifier never depends on its own serializer reproducing another implementation's framing.
//
// `ciborium` 0.2 exposes no raw-value capture (no `RawValue`, and `ciborium-ll`'s decoder has no
// byte-offset API), so this is a light, self-contained CBOR pass that walks ONLY the structure it
// needs — `DeviceResponse → documents[i] → issuerSigned → nameSpaces → {ns: [items]}` — and records,
// for EACH on-wire `#6.24(bstr)` element, ONE record that carries together its exact original byte
// span AND the `digestID` / `elementIdentifier` / `elementValue` decoded from THOSE SAME bytes.
//
// SECURITY (SC-002 — selective-disclosure integrity): the bytes that get HASHED and the value that
// gets DISCLOSED MUST be the same on-wire item. A digestID-keyed map decoupled from the disclosed
// value is a FALSE-ACCEPT lever — a forged item reusing a genuine item's `digestID` could hash the
// genuine bytes (digest matches the MSO) while disclosing an attacker-chosen identifier/value the
// issuer never signed. Capturing one self-contained record per item ties bytes↔value inseparably,
// and per-namespace `digestID` uniqueness is enforced ([`verify_value_digests`]) so a reused digestID
// is rejected outright.
// =================================================================================================

/// One captured on-wire `IssuerSignedItem`: its exact `#6.24(bstr .cbor IssuerSignedItem)` byte span
/// (the digest input ISO/IEC 18013-5 §9.2.2.5 hashes) PAIRED with the decoded inner `IssuerSignedItem`
/// map (and the `digestID` / `elementIdentifier` read from it) — ALL from those SAME bytes, so the
/// value disclosed is inseparable from the bytes hashed (no decoupled-lookup false-accept).
///
/// The `elementValue` is NOT materialized into an [`AttributeValue`] here: it stays as the decoded
/// `item` map, and [`verify_value_digests`] projects it via [`Self::element_value`] only AFTER this
/// item's digest matches the MSO — so an item whose digest later mismatches (or a never-disclosed item)
/// never pays the deep `cbor_to_attribute` clone of its (attacker-sized) value. The inner map itself is
/// decoded ONCE (a single `ciborium` pass over the bstr content), not twice.
struct RawIssuerItem<'a> {
    /// The exact on-wire `IssuerSignedItemBytes` span (`#6.24(bstr)`), hashed verbatim.
    raw_bytes: &'a [u8],
    /// The `digestID` decoded from the inner map (the MSO `valueDigests` index for this item).
    digest_id: i64,
    /// The `elementIdentifier` (claim name) decoded from the inner map.
    identifier: String,
    /// The decoded inner `IssuerSignedItem` map (the SAME bytes as `raw_bytes`). The `elementValue`
    /// is projected lazily from here via [`Self::element_value`], only once the digest has matched.
    item: CborValue,
}

impl RawIssuerItem<'_> {
    /// Materialize this item's `elementValue` into the SDK's [`AttributeValue`]. Called by
    /// [`verify_value_digests`] ONLY after the item's digest matches the MSO `valueDigests` entry, so
    /// the deep `cbor_to_attribute` clone of an (attacker-sized) value is paid only for disclosed,
    /// digest-authenticated items — never for an item whose digest mismatches. The decode validated an
    /// `elementValue` is present (a record is only created when it is), so this is total.
    fn element_value(&self) -> AttributeValue {
        get_map_entry(&self.item, "elementValue").map_or(AttributeValue::Null, cbor_to_attribute)
    }
}

/// The captured on-wire `IssuerSignedItem`s of one document, keyed by namespace: each value is the
/// list of [`RawIssuerItem`] records for that namespace, IN WIRE ORDER. Built by
/// [`scan_raw_issuer_items`] from the original `DeviceResponse` bytes (one scan per response), then
/// consumed by [`verify_value_digests`] (which recomputes each record's digest over its OWN bytes and
/// discloses that record's OWN identifier/value). A `Vec` (not a `digestID`-keyed map) so duplicate
/// `digestID`s are visible and rejected rather than silently collapsed.
type RawDocumentItems<'a> = BTreeMap<String, Vec<RawIssuerItem<'a>>>;

/// A minimal forward CBOR cursor over a byte slice, used only to walk the `IssuerSigned.nameSpaces`
/// structure and capture each `IssuerSignedItemBytes` span verbatim. It is NOT a general decoder: it
/// reads item heads, skips items it does not need, and hands back exact sub-slices.
struct CborCursor<'a> {
    /// The full input being walked (slices handed out borrow from this).
    input: &'a [u8],
    /// The current read position (byte offset into `input`).
    pos: usize,
}

/// The major type + argument of one CBOR data-item head (RFC 8949 §3): the 3-bit major type and the
/// decoded unsigned argument (the "additional information" value), with the head already consumed.
struct CborHead {
    /// The CBOR major type (0..=7).
    major: u8,
    /// The decoded argument (length for strings/containers, value for ints, tag number for tags).
    arg: u64,
}

impl<'a> CborCursor<'a> {
    /// Start a cursor at the beginning of `input`.
    const fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }

    /// Read and consume one item head: the initial byte's major type + additional info, plus any
    /// following 1/2/4/8 argument bytes (RFC 8949 §3). Indefinite-length (additional info 31) is
    /// rejected — ISO/IEC 18013-5 §9.1.1 forbids it, and capturing a definite span is the whole point.
    fn read_head(&mut self) -> Option<CborHead> {
        let initial = *self.input.get(self.pos)?;
        self.pos += 1;
        let major = initial >> 5;
        let info = initial & 0x1f;
        let arg = match info {
            0..=23 => u64::from(info),
            24 => self.read_uint(1)?,
            25 => self.read_uint(2)?,
            26 => self.read_uint(4)?,
            27 => self.read_uint(8)?,
            // 28..=30 reserved; 31 indefinite-length — neither is valid Canonical CBOR here.
            _ => return None,
        };
        Some(CborHead { major, arg })
    }

    /// Read `n` big-endian bytes as the head argument, advancing the cursor.
    fn read_uint(&mut self, n: usize) -> Option<u64> {
        // `checked_add` for the end offset: attacker-controlled head bytes must never overflow `usize`
        // into a panic (overflow-checks on) — an out-of-range read fails closed via `get` returning
        // `None`. (Consistent with `skip_pending` / `take_text`.)
        let end = self.pos.checked_add(n)?;
        let bytes = self.input.get(self.pos..end)?;
        self.pos = end;
        let mut value = 0u64;
        for &b in bytes {
            value = (value << 8) | u64::from(b);
        }
        Some(value)
    }

    /// Skip exactly one complete data item (head + all content/children), advancing the cursor past
    /// it. Returns `None` on malformed/indefinite input.
    fn skip_item(&mut self) -> Option<()> {
        self.skip_pending(1)
    }

    /// The number of complete data items that follow this head as its content: arrays contribute
    /// `arg` items, maps `2 * arg` (key/value pairs), tags `1`, and scalars/strings `0` (a string's
    /// bytes are not separate items — they are consumed by the caller). Returns `None` for an
    /// unsupported major type (indefinite/reserved were already rejected by `read_head`). Uses
    /// `checked_mul` so a maliciously-large map length cannot overflow `usize` into a panic.
    fn head_child_count(head: &CborHead) -> Option<usize> {
        match head.major {
            // Integers, simple/float, byte/text string: no child *items* follow.
            0 | 1 | 2 | 3 | 7 => Some(0),
            // Array: `arg` items follow.
            4 => usize::try_from(head.arg).ok(),
            // Map: `arg` key/value PAIRS = `2 * arg` items follow.
            5 => usize::try_from(head.arg).ok()?.checked_mul(2),
            // Tag: exactly one tagged item follows.
            6 => Some(1),
            _ => None,
        }
    }

    /// Iteratively skip `pending` complete data items, advancing the cursor past all of them.
    ///
    /// This is the depth-bound for the raw cursor: ISO/IEC 18013-5 CBOR is walked over a strictly
    /// forward byte stream, so skipping nested containers needs no per-level call frame — each
    /// container head simply ADDS its child-item count to the flat work counter, and the loop consumes
    /// items until the counter drains. An adversarially-nested `DeviceResponse` (hundreds of thousands
    /// of nested arrays) therefore costs O(1) stack and a single `usize` counter instead of recursing
    /// once per level — it can never overflow the stack (a former DoS: an uncatchable SIGABRT). A
    /// malformed/truncated stream drains the input first and fails closed (`read_head`/string-byte read
    /// returns `None`); a length that would overflow the counter likewise fails closed via `checked_add`.
    fn skip_pending(&mut self, mut pending: usize) -> Option<()> {
        while pending > 0 {
            pending -= 1;
            let head = self.read_head()?;
            // A string's content bytes are consumed inline (they are not separate items); a container
            // contributes its children to the remaining work.
            if matches!(head.major, 2 | 3) {
                let len = usize::try_from(head.arg).ok()?;
                self.pos = self.pos.checked_add(len)?;
                if self.pos > self.input.len() {
                    return None;
                }
                continue;
            }
            let children = Self::head_child_count(&head)?;
            pending = pending.checked_add(children)?;
        }
        Some(())
    }

    /// Read the next item expecting it to be a `#6.24(bstr)` ("encoded CBOR data item") and return BOTH
    /// the element's exact full on-wire span (`raw`, tag + bstr head + content — the digest input
    /// ISO/IEC 18013-5 §9.2.2.5 hashes verbatim) AND the inner bstr's content slice (`inner`, the
    /// `.cbor IssuerSignedItem` bytes), in ONE structural pass. The cursor leaves positioned just past
    /// the element.
    ///
    /// This reads only item HEADS (the `#6.24` tag head + the inner byte-string head) and hands back
    /// sub-slices — it never re-decodes the wrapper through `ciborium`. The caller then runs a SINGLE
    /// `ciborium` decode over `inner` to reach the `IssuerSignedItem` map, instead of decoding the
    /// `#6.24(bstr)` wrapper and then decoding the inner bytes a second time (the former double parse —
    /// an attacker-multipliable soft-DoS lever across documents × namespaces × items). Returns `None`
    /// (fails closed) for anything that is not a `#6.24` tag wrapping a definite-length byte string.
    fn take_tagged_bstr_item(&mut self) -> Option<(&'a [u8], &'a [u8])> {
        let start = self.pos;
        // The `#6.24` "encoded CBOR data item" tag head (major 6, arg = the tag number).
        let tag = self.read_head()?;
        if tag.major != 6 || tag.arg != TAG_ENCODED_CBOR {
            return None;
        }
        // The inner byte string: a definite-length bstr (major 2) whose content bytes are the inner
        // `.cbor IssuerSignedItem` serialization, taken verbatim (no copy).
        let bstr = self.read_head()?;
        if bstr.major != 2 {
            return None;
        }
        let len = usize::try_from(bstr.arg).ok()?;
        let content_start = self.pos;
        // `checked_add` so an attacker-declared giant `len` fails closed (`None`), never overflows.
        let content_end = content_start.checked_add(len)?;
        let inner = self.input.get(content_start..content_end)?;
        self.pos = content_end;
        let raw = self.input.get(start..self.pos)?;
        Some((raw, inner))
    }

    /// Read a text-string item, returning its UTF-8 content (used to read map keys / namespace names).
    fn take_text(&mut self) -> Option<&'a str> {
        let head = self.read_head()?;
        if head.major != 3 {
            return None;
        }
        let len = usize::try_from(head.arg).ok()?;
        // `checked_add` for the end offset: a giant declared `len` (attacker-controlled) must fail
        // closed (`None`), never overflow `usize` into a panic. (Matches `skip_pending`'s string
        // arm and `read_uint`.)
        let end = self.pos.checked_add(len)?;
        let bytes = self.input.get(self.pos..end)?;
        self.pos = end;
        core::str::from_utf8(bytes).ok()
    }

    /// Expect a map head, returning its entry count.
    fn read_map_len(&mut self) -> Option<u64> {
        let head = self.read_head()?;
        (head.major == 5).then_some(head.arg)
    }

    /// Expect an array head, returning its element count.
    fn read_array_len(&mut self) -> Option<u64> {
        let head = self.read_head()?;
        (head.major == 4).then_some(head.arg)
    }

    /// Walk a map, invoking `on_entry` with a cursor positioned at each value after reading its text
    /// key; `on_entry` MUST consume exactly its value. Non-text keys are skipped (with their values).
    fn for_each_text_keyed_entry(
        &mut self,
        mut on_entry: impl FnMut(&str, &mut Self) -> Option<()>,
    ) -> Option<()> {
        let len = self.read_map_len()?;
        for _ in 0..len {
            // Peek whether the key is a text string; if not, skip key + value together.
            let key_start = self.pos;
            if let Some(key) = self.take_text() {
                // `take_text` returns `&'a str` (tied to the input lifetime, NOT to `*self`), so the
                // key borrow does not conflict with the `&mut self` re-borrow for the callback.
                on_entry(key, self)?;
            } else {
                // Reset to the key start, skip the key item and its value.
                self.pos = key_start;
                self.skip_item()?;
                self.skip_item()?;
            }
        }
        Some(())
    }
}

/// Reject a `DeviceResponse` that uses indefinite-length (or reserved) CBOR encoding ANYWHERE in its
/// top-level item — ISO/IEC 18013-5 §9.1.1 mandates deterministic CBOR, and RFC 8949 §4.2.1 states
/// "Indefinite-length items MUST NOT appear." `ciborium` (the always-on bar's decoder) would otherwise
/// accept indefinite-length encoding, so this walks the WHOLE response with the definite-length-only
/// [`CborCursor`] — whose [`CborCursor::read_head`] returns `None` for any indefinite-length (additional
/// info 31) or reserved (28..=30) head — and requires it to consume EXACTLY the input. A successful,
/// fully-consuming walk proves definite-length encoding with no trailing bytes (the deterministic
/// "one well-formed item" rule); any deviation fails closed ([`VerifyFailure::malformed`]). The cursor
/// is iterative (O(1) stack), so this is also safe against adversarial nesting.
fn reject_indefinite_length_cbor(device_response: &[u8]) -> Result<(), VerifyFailure> {
    let mut cursor = CborCursor::new(device_response);
    match cursor.skip_item() {
        // Exactly one complete, definite-length top-level item that consumes the whole input.
        Some(()) if cursor.pos == device_response.len() => Ok(()),
        // An indefinite/reserved head (cursor returns `None`), a truncated item, or trailing bytes.
        _ => Err(VerifyFailure::malformed()),
    }
}

/// Decode a [`RawIssuerItem`] record for one on-wire `#6.24(bstr .cbor IssuerSignedItem)` element from
/// its exact full span (`raw_bytes`, the digest input) and the inner bstr content (`inner`, the
/// `.cbor IssuerSignedItem` bytes) — the two slices the cursor's [`CborCursor::take_tagged_bstr_item`]
/// hands back from a single structural pass over the SAME element (so `raw_bytes` and the decoded item
/// are one and the same on-wire item by construction; no decoupled-lookup false-accept).
///
/// The `#6.24(bstr)` wrapper is recognized by the cursor, so this performs ONE `ciborium` decode (of
/// `inner` → the `IssuerSignedItem` map), not the former two (the tag wrapper, then the inner bytes).
/// It reads + retains `digestID` / `elementIdentifier` (needed for the digest match + disclosure key)
/// but DEFERS the `elementValue` materialization to [`RawIssuerItem::element_value`] (run only after a
/// digest match). Returns `None` if `inner` is not a map with an integer `digestID`, a text
/// `elementIdentifier`, and a present `elementValue`.
fn decode_raw_issuer_item<'a>(raw_bytes: &'a [u8], inner: &[u8]) -> Option<RawIssuerItem<'a>> {
    let item: CborValue = ciborium::from_reader(inner).ok()?;
    let digest_id = get_integer(&item, "digestID")?;
    let identifier = get_text(&item, "elementIdentifier")?;
    // Require `elementValue` to be present (a record stands for a disclosable item), but DON'T
    // materialize it yet — the deep `cbor_to_attribute` clone is deferred to `element_value()`, run
    // only after this item's digest matches the MSO (an item that later mismatches never pays it).
    get_map_entry(&item, "elementValue")?;
    Some(RawIssuerItem {
        raw_bytes,
        digest_id,
        identifier,
        item,
    })
}

/// Scan the original `DeviceResponse` bytes once and capture, per document (in document order), one
/// [`RawIssuerItem`] record per on-wire `IssuerSignedItem` (its exact `IssuerSignedItemBytes` span —
/// the digest input ISO/IEC 18013-5 §9.2.2.5 mandates — plus the `digestID` / identifier / value
/// decoded from those same bytes), grouped by namespace in wire order.
///
/// This is a best-effort capture: a document/element this light pass cannot navigate (it never
/// happens for a well-formed response, which the always-on bar parses in full via `ciborium`) simply
/// yields fewer records than the decoded `nameSpaces` carries, and [`verify_value_digests`] then fails
/// that document closed (`DisclosureIntegrity`) rather than silently re-encoding or dropping an item —
/// so a parse the two paths disagree on can never become a FALSE-ACCEPT. The verdict is unchanged for
/// every conformant response.
fn scan_raw_issuer_items(device_response: &[u8]) -> Vec<RawDocumentItems<'_>> {
    let mut per_document = Vec::new();
    let mut cursor = CborCursor::new(device_response);
    let _ = cursor.for_each_text_keyed_entry(|key, c| {
        if key == "documents" {
            let len = c.read_array_len()?;
            for _ in 0..len {
                per_document.push(scan_document_issuer_items(c).unwrap_or_default());
            }
            Some(())
        } else {
            c.skip_item()
        }
    });
    per_document
}

/// Capture one `Document`'s `issuerSigned.nameSpaces` as per-namespace [`RawIssuerItem`] record lists
/// (in wire order). The cursor enters positioned at the `Document` map and leaves positioned just past
/// it (so the caller's array walk stays in step).
fn scan_document_issuer_items<'a>(cursor: &mut CborCursor<'a>) -> Option<RawDocumentItems<'a>> {
    let mut items: RawDocumentItems<'a> = BTreeMap::new();
    cursor.for_each_text_keyed_entry(|doc_key, c| {
        if doc_key == "issuerSigned" {
            c.for_each_text_keyed_entry(|is_key, c2| {
                if is_key == "nameSpaces" {
                    scan_name_spaces(c2, &mut items)
                } else {
                    c2.skip_item()
                }
            })
        } else {
            c.skip_item()
        }
    })?;
    Some(items)
}

/// Capture every `IssuerSignedItem` of a `nameSpaces` map (`{ namespace: [ #6.24(bstr) … ] }`) into
/// `items` as per-namespace [`RawIssuerItem`] record lists (in wire order). The cursor enters at the
/// `nameSpaces` map value and leaves just past it.
fn scan_name_spaces<'a>(
    cursor: &mut CborCursor<'a>,
    items: &mut RawDocumentItems<'a>,
) -> Option<()> {
    cursor.for_each_text_keyed_entry(|namespace, c| {
        let ns_entry = items.entry(namespace.to_owned()).or_default();
        let len = c.read_array_len()?;
        for _ in 0..len {
            // Capture this element's EXACT on-wire `#6.24(bstr)` span AND its inner bstr content in one
            // structural pass, then decode `digestID` / `elementIdentifier` from that SAME inner span
            // into one self-contained record (bytes↔value tied together; the `elementValue` is left
            // unmaterialized until a digest match). An element the raw pass cannot parse produces no
            // record, so the per-namespace record count falls short of the decoded item count and
            // `verify_value_digests` fails the document closed (`DisclosureIntegrity`) — never a silent
            // skip that drops an item.
            let (raw_item, inner) = c.take_tagged_bstr_item()?;
            if let Some(record) = decode_raw_issuer_item(raw_item, inner) {
                ns_entry.push(record);
            }
        }
        Some(())
    })
}

// =================================================================================================
// CBOR map/value helpers (ciborium uses an association-list `Value::Map`; these read it by key).
// =================================================================================================

/// Look up a text-keyed entry in a CBOR map value, returning a reference to the value. The **one**
/// CBOR-map-by-text-key lookup the crate shares (DRY — Principle III): the holder presentation splice
/// ([`crate::issuance::present`]) reads the same `DeviceResponse` shape through this exact helper, so
/// both halves resolve a `Document`/`issuerSigned`/`deviceSigned` key identically.
pub(crate) fn get_map_entry<'a>(value: &'a CborValue, key: &str) -> Option<&'a CborValue> {
    let map = value.as_map()?;
    map.iter().find_map(|(k, v)| match k {
        Value::Text(t) if t == key => Some(v),
        _ => None,
    })
}

/// Look up a text-keyed entry whose value is text, returning the owned string.
fn get_text(value: &CborValue, key: &str) -> Option<String> {
    get_map_entry(value, key).and_then(|v| v.as_text().map(ToOwned::to_owned))
}

/// Extract the first `Document` from a `DeviceResponse`'s `documents` array. Only the
/// external-vector conformance entry [`verify_issuer_auth_against_vector`] (single-document) reads the
/// first document this way; the always-on bar folds across EVERY document, so this is gated to the
/// same `test`/`test-vectors` builds as its sole caller.
#[cfg(any(test, feature = "test-vectors"))]
fn first_document(root: &CborValue) -> Result<&CborValue, VerifyFailure> {
    let documents = get_map_entry(root, "documents")
        .and_then(CborValue::as_array)
        .ok_or_else(VerifyFailure::malformed)?;
    documents.first().ok_or_else(VerifyFailure::malformed)
}

/// Unwrap a CBOR `#6.24(bstr)` ("encoded CBOR data item") to its inner byte string, mapping a non-tag/
/// non-bytes value to a malformed-credential failure. The inner bytes are the exact serialization that
/// was hashed/signed, so they must be used verbatim. Delegates to the crate's single `#6.24(bstr)`
/// unwrap [`crate::unwrap_tagged_cbor_payload`] (DRY — Principle III; the holder presentation splice
/// shares it, so both halves unwrap identically).
fn unwrap_tagged_cbor_payload(value: &CborValue) -> Result<Vec<u8>, VerifyFailure> {
    crate::unwrap_tagged_cbor_payload(value).ok_or_else(VerifyFailure::malformed)
}

/// Unwrap a byte string that is itself a `#6.24`-tagged encoded CBOR item. The `IssuerAuth`/`Device`
/// payloads are stored as plain `bstr` whose content is the tagged item; re-decode the bstr's bytes
/// as CBOR to reach the tag.
fn unwrap_bstr_tagged_payload(bstr: &[u8]) -> Result<Vec<u8>, VerifyFailure> {
    let value: CborValue = ciborium::from_reader(bstr).map_err(|_| VerifyFailure::malformed())?;
    unwrap_tagged_cbor_payload(&value)
}

// =================================================================================================
// COSE_Sign1 parsing + ES256 signature verification.
// =================================================================================================

/// Parse a COSE_Sign1 from a CBOR value. ISO/IEC 18013-5 carries the `IssuerAuth`/`DeviceSignature`
/// as the bare `[protected, unprotected, payload, signature]` array (RFC 8152 §4.2 untagged form),
/// though a `#6.18`-tagged form is also accepted defensively.
///
/// The value is ALREADY decoded (it came from the single `ciborium` decode of the `DeviceResponse`),
/// so this builds the `CoseSign1` straight from it via `coset`'s [`coset::AsCborValue::from_cbor_value`]
/// — the very codec `from_slice` runs after its own decode — rather than re-serializing the whole
/// `[protected, unprotected, payload, signature]` array (its large MSO-bearing payload bstr included)
/// and re-decoding it. The resulting `CoseSign1` (and therefore the `Sig_structure` the signature is
/// verified over) is byte-identical to the former serialize→`from_slice` round-trip; only the redundant
/// re-encode + re-decode of the MSO payload (an attacker-multipliable soft-DoS lever — documents ×
/// IssuerAuth × MSO size) is removed. `from_cbor_value` MOVES the payload bstr out of the array, so the
/// MSO bytes are copied at most once (the borrowed value's clone), never the prior twice.
fn parse_cose_sign1(value: &CborValue) -> Result<CoseSign1, VerifyFailure> {
    // The untagged `[protected, unprotected, payload, signature]` array is the COSE_Sign1 itself; a
    // `#6.18`-tagged form (accepted defensively) carries that array as its single tagged item.
    let array = match value {
        CborValue::Tag(_, inner) => inner.as_ref(),
        other => other,
    };
    let sign1 =
        CoseSign1::from_cbor_value(array.clone()).map_err(|_| VerifyFailure::malformed())?;
    // RFC 9052 §3.1 (`crit`) enforcement, applied at this single COSE_Sign1 construction chokepoint so
    // BOTH the `IssuerAuth` and `DeviceSignature` paths inherit it (DRY — Principle III).
    reject_unprocessed_crit(&sign1)?;
    Ok(sign1)
}

/// Enforce the COSE `crit` (critical headers) protected-header parameter (RFC 9052 §3.1).
///
/// RFC 9052 §3.1 defines `crit` (label 2) as the list that "indicate[s] which protected header
/// parameters an application that is processing a message is required to understand"; if a recipient
/// does not process a header parameter listed there, the spec is explicit that "this is a fatal error
/// in processing the message". This verifier processes exactly ONE protected header parameter — the
/// standard `alg` (label 1) it already pins to ES256 — and implements NO extension headers, so ANY
/// other label appearing in `crit` is one it does not understand and the message MUST be rejected
/// (fail-closed forward-compat: an issuer that marks a header critical is demanding the verifier honor
/// it, so silently ignoring it would be a false-trust — conformance-audit T2.1). A `crit` listing only
/// `alg` is accepted (it IS understood; RFC 9052 §3.1 separately notes such "Integer labels in the
/// range of 0 to 7 SHOULD be omitted", but a redundant listing is not an interop failure here).
/// `coset` already parses `crit` into `protected.header.crit`; this only enforces it. Rejected as
/// [`ReasonCode::MalformedCredential`] (a structurally-unprocessable message).
fn reject_unprocessed_crit(sign1: &CoseSign1) -> Result<(), VerifyFailure> {
    let all_understood = sign1.protected.header.crit.iter().all(|label| {
        // The sole protected header parameter this verifier processes is `alg` (label 1).
        matches!(
            label,
            RegisteredLabelWithPrivate::Assigned(coset::iana::HeaderParameter::Alg)
        )
    });
    if all_understood {
        Ok(())
    } else {
        Err(VerifyFailure::malformed())
    }
}

/// Resolve the full Document Signer certificate chain (DER, leaf-first) from a COSE_Sign1's `x5chain`
/// header (RFC 9360). The leaf is the first certificate; any further entries are the intermediate
/// sub-CAs the leaf chains through. A single-cert chain may be carried as a bare `bstr` rather than an
/// array of `bstr`; an empty array, or any non-`bstr` entry, is malformed.
fn ds_chain_from_x5chain(sign1: &CoseSign1) -> Result<Vec<Vec<u8>>, VerifyFailure> {
    let label = Label::Int(COSE_HEADER_X5CHAIN);
    let value = sign1
        .unprotected
        .rest
        .iter()
        .find_map(|(l, v)| (*l == label).then_some(v))
        .ok_or_else(VerifyFailure::malformed)?;
    match value {
        Value::Bytes(b) => Ok(vec![b.clone()]),
        Value::Array(certs) if !certs.is_empty() => certs
            .iter()
            .map(|c| match c {
                Value::Bytes(b) => Ok(b.clone()),
                _ => Err(VerifyFailure::malformed()),
            })
            .collect(),
        _ => Err(VerifyFailure::malformed()),
    }
}

/// Whether a COSE_Sign1's protected-header `alg` names ES256 — the single authoritative
/// algorithm-gate predicate the EUDI baseline pins. Both the `IssuerAuth` and `DeviceSignature`
/// verifiers gate on this BEFORE any signature math runs, so a non-ES256 header is rejected on the
/// algorithm alone (never via a failed ES256 verification of differently-signed bytes). Factored out
/// (DRY) so the gate has one definition and can be probed in isolation.
fn cose_alg_is_es256(sign1: &CoseSign1) -> bool {
    matches!(
        sign1.protected.header.alg,
        Some(RegisteredLabelWithPrivate::Assigned(
            coset::iana::Algorithm::ES256
        ))
    )
}

/// Verify a COSE_Sign1 ES256 signature against a P-256 public key extracted from `cert_der`.
///
/// Builds the COSE `Sig_structure` (via `coset`, with no external AAD) and verifies the raw `r‖s`
/// signature with the SDK's `p256`/`ecdsa` (no hand-rolled crypto). A non-ES256 algorithm header is
/// rejected as a tamper (the EUDI baseline is ES256).
fn verify_cose_sign1_es256(sign1: &CoseSign1, cert_der: &[u8]) -> Result<(), VerifyFailure> {
    // The protected header MUST name ES256 (the EUDI baseline). Anything else is rejected on the
    // algorithm alone, before any signature math.
    if !cose_alg_is_es256(sign1) {
        return Err(VerifyFailure::reason(ReasonCode::Tamper));
    }

    // The crate's single cert-DER → P-256 key path (DRY — Principle III; the SD-JWT VC JWS verifier
    // shares the same helper). An `x5chain` leaf that does not yield a usable P-256 key means the
    // IssuerAuth signature cannot be verified — a `Tamper`-class reject.
    let verifying_key = crate::crypto::p256_verifying_key_from_cert_der(cert_der)
        .ok_or_else(|| VerifyFailure::reason(ReasonCode::Tamper))?;

    let outcome = sign1.verify_signature(&[], |sig, tbs| {
        crate::crypto::p256_verify_es256(&verifying_key, tbs, sig)
    });
    outcome.map_err(|()| VerifyFailure::reason(ReasonCode::Tamper))
}

/// Parse the bytes of a COSE ES256 signature into a [`p256::ecdsa::Signature`], accepting ONLY the
/// fixed-width raw `r‖s` form (RFC 9053 §2.1 — NEVER an ASN.1/DER `SEQUENCE`), or `None` for any other
/// encoding. Used by the structural binding-machinery probe ([`device_binding_machinery_sound`]) to
/// classify a `DeviceSignature`'s well-formedness independently of any transcript.
///
/// This uses the SAME `p256::ecdsa::Signature::from_slice` raw-only parse the crate's ES256 verify
/// kernel ([`crate::crypto::p256_verify_es256`]) applies, so the probe's notion of "well-formed" is
/// EXACTLY the verifier's accepted set BY CONSTRUCTION: a DER-encoded signature is `None` here
/// (classified a transcript-INDEPENDENT binding fault, never a freshness/replay signal) and is
/// likewise rejected by the verifier — the two can never drift apart.
fn parse_es256_sig(sig_bytes: &[u8]) -> Option<p256::ecdsa::Signature> {
    p256::ecdsa::Signature::from_slice(sig_bytes).ok()
}

// =================================================================================================
// MSO validityInfo.
// =================================================================================================

/// Parse the MSO `validityInfo` into the SDK's [`Validity`] (Unix seconds) PAIRED with the `signed`
/// instant. `signed`/`validFrom`/`validUntil` are RFC 3339 `tdate` strings (often CBOR `#6.0`-tagged);
/// a missing/unparseable bound is malformed.
///
/// `signed` is the instant the issuer asserts it signed the MSO (ISO/IEC 18013-5 §9.1.2.4). It is
/// inside the IssuerAuth-signed MSO, so it is not itself a forgery vector, but it is enforced for
/// internal consistency: a `signed` after `validFrom` is contradictory (the credential claims it was
/// valid from before it was signed), and a `signed` in the future (after `now`) is impossible for a
/// genuinely issued credential — either is a tamper/malformed MSO and is rejected, not ignored.
///
/// `signed` is returned because it is the credential's issuance/relevant time (ISO/IEC 18013-5 §9.1.2.4
/// — what the opt-in qualified gate reads status at). The bar REQUIRES `signed` (this errors when it is
/// absent), so on a VALID credential the returned `signed` is the single issuance time the bar pass
/// surfaces (via [`MdocVerifyMeta::claimed_issuers`]), letting the gate read this cached value instead
/// of re-parsing the MSO.
fn parse_validity_info(mso: &CborValue, now_unix: i64) -> Result<(Validity, i64), VerifyFailure> {
    let info = get_map_entry(mso, "validityInfo").ok_or_else(VerifyFailure::malformed)?;
    let signed = tdate_field(info, "signed")?;
    let valid_from = tdate_field(info, "validFrom")?;
    let valid_until = tdate_field(info, "validUntil")?;
    // `signed` must not be in the future relative to the verification instant — an MSO cannot have
    // been signed after `now`.
    if signed > now_unix {
        return Err(VerifyFailure::reason(ReasonCode::Tamper));
    }
    // `signed` must not be after `validFrom`: the issuer cannot assert the credential was valid before
    // it was signed (an inconsistent window).
    if signed > valid_from {
        return Err(VerifyFailure::reason(ReasonCode::Tamper));
    }
    Ok((
        Validity {
            not_before: Some(valid_from),
            not_after: Some(valid_until),
        },
        signed,
    ))
}

/// Read a `tdate` (RFC 3339) field from `validityInfo`, accepting the bare text or a `#6.0`-tagged
/// text, returning Unix seconds.
fn tdate_field(info: &CborValue, key: &str) -> Result<i64, VerifyFailure> {
    let value = get_map_entry(info, key).ok_or_else(VerifyFailure::malformed)?;
    let text = match value {
        CborValue::Text(t) => t.clone(),
        CborValue::Tag(0, inner) => inner
            .as_text()
            .map(ToOwned::to_owned)
            .ok_or_else(VerifyFailure::malformed)?,
        _ => return Err(VerifyFailure::malformed()),
    };
    crate::datetime::parse_rfc3339_utc(&text).ok_or_else(VerifyFailure::malformed)
}

/// Enforce the validity window at `now_unix`: outside `[validFrom, validUntil]` → `Expired`.
///
/// ## Boundary convention (per-spec, intentionally asymmetric with SD-JWT VC — DO NOT unify blindly)
///
/// The upper bound here is **inclusive**: `now > validUntil` rejects, so the credential is valid up to
/// and **including** the `validUntil` instant (ISO/IEC 18013-5 — the window is the closed interval
/// `[validFrom, validUntil]`). The SD-JWT VC verifier's [`crate::sdjwtvc`] `check_validity` uses an
/// **exclusive** upper bound (`now >= exp`), per RFC 7519 §4.1.4 ("now MUST be *before* `exp`"). This
/// one-second divergence at the boundary is each format's own spec rule, NOT a bug — a future refactor
/// that "unifies" the two windows would silently change one format's accepted range, so the two sites
/// cross-reference each other deliberately.
fn enforce_validity(validity: &Validity, now_unix: i64) -> Result<(), VerifyFailure> {
    if let Some(not_before) = validity.not_before {
        if now_unix < not_before {
            return Err(VerifyFailure::reason(ReasonCode::Expired));
        }
    }
    if let Some(not_after) = validity.not_after {
        // INCLUSIVE upper bound (ISO/IEC 18013-5: valid up to and including `validUntil`).
        // Intentionally differs from SD-JWT VC's EXCLUSIVE `now >= exp` (RFC 7519) — see doc comment.
        if now_unix > not_after {
            return Err(VerifyFailure::reason(ReasonCode::Expired));
        }
    }
    Ok(())
}

// =================================================================================================
// valueDigests integrity (in-house, MANDATORY).
// =================================================================================================

/// Recompute every on-wire `IssuerSignedItem` digest and match it against the MSO `valueDigests`,
/// returning the disclosed attributes (GROUPED BY NAMESPACE) only for items whose digest matches.
///
/// ## Result shape (namespace-grouped)
///
/// ISO/IEC 18013-5 `elementIdentifier`s are unique only WITHIN a namespace — a valid presentation MAY
/// carry the SAME identifier (e.g. `given_name`) in two different namespaces with different values. The
/// returned map ([`DisclosedByNamespace`]) is therefore keyed by **namespace**, each value the nested
/// `{ elementIdentifier: elementValue }` map for that namespace: `{ ns: { id: value } }`. This (i) never
/// false-rejects two distinct `(namespace, id)` pairs that merely share an `id`, and (ii) preserves the
/// namespace provenance a consumer needs to tell the two apart. (It is projected to the public
/// `{ ns: AttributeValue::Map }` shape once in [`verify_inner`] — see [`verify_with_meta`] / contracts/verifier.md.)
///
/// The disclosure works from the [`scan_raw_issuer_items`] **records** (`raw_items`): each record
/// carries the item's exact `IssuerSignedItemBytes` span (`#6.24(bstr .cbor IssuerSignedItem)`)
/// PAIRED with the `digestID` / `elementIdentifier` / `elementValue` decoded from THOSE SAME bytes.
/// For each record the digest is computed over its OWN `raw_bytes` — the bytes as received (ISO/IEC
/// 18013-5 §9.2.2.5: "the input for the digest function is the binary data of the IssuerSignedItem"),
/// never a re-encode — and matched against `valueDigests[ns][digestID]`; ONLY on a match is that
/// record's OWN identifier/value disclosed under its namespace. Because the hashed bytes and the
/// disclosed value are one inseparable record, a forged item cannot hash a genuine item's bytes while
/// disclosing an attacker-chosen claim (SC-002 — the selective-disclosure-integrity false-accept).
///
/// Integrity rules (all → `DisclosureIntegrity`):
/// * `digestID` uniqueness within a namespace — a `digestID` appearing on two on-wire items is
///   rejected (the lever the false-accept rides on: two items competing for one MSO digest slot).
/// * Each item's `digestID` MUST resolve to exactly one MSO digest for its namespace, and the
///   recomputed digest MUST equal it.
/// * The captured record count MUST equal the decoded `issuer_signed.nameSpaces` item count, per
///   namespace and overall — so an item the raw pass could not capture (it produces no record) fails
///   the document closed rather than being silently dropped from the verified set.
///
/// `issuer_signed` is consulted ONLY to cross-check the per-namespace item COUNT (the decoded view);
/// the verified disclosure comes entirely from the records, so the decoded value is never disclosed
/// decoupled from the bytes that were hashed. The expected digests are indexed into a per-namespace
/// `BTreeMap<digestID, &digest>` once, so each item is an `O(log n)` lookup.
fn verify_value_digests(
    issuer_signed: &CborValue,
    raw_items: Option<&RawDocumentItems<'_>>,
    mso: &CborValue,
    digest_alg: DigestAlgorithm,
) -> Result<DisclosedByNamespace, VerifyFailure> {
    let name_spaces = get_map_entry(issuer_signed, "nameSpaces")
        .and_then(CborValue::as_map)
        .ok_or_else(VerifyFailure::malformed)?;
    let value_digests = get_map_entry(mso, "valueDigests")
        .and_then(CborValue::as_map)
        .ok_or_else(VerifyFailure::malformed)?;
    // The records are the authoritative on-wire item set (bytes↔value tied); an absent capture fails
    // every item closed rather than disclosing the decoded view decoupled from the hashed bytes.
    let raw_items =
        raw_items.ok_or_else(|| VerifyFailure::reason(ReasonCode::DisclosureIntegrity))?;

    let mut disclosed: DisclosedByNamespace = BTreeMap::new();
    for (ns_key, items_value) in name_spaces {
        let ns = ns_key.as_text().ok_or_else(VerifyFailure::malformed)?;
        let decoded_items = items_value
            .as_array()
            .ok_or_else(VerifyFailure::malformed)?;
        // The captured records for this namespace (one per on-wire item, in wire order). Their count
        // MUST equal the decoded item count: a shortfall means the raw pass could not capture some
        // item — fail closed (never verify a subset and silently drop the rest).
        let ns_records = raw_items
            .get(ns)
            .ok_or_else(|| VerifyFailure::reason(ReasonCode::DisclosureIntegrity))?;
        if ns_records.len() != decoded_items.len() {
            return Err(VerifyFailure::reason(ReasonCode::DisclosureIntegrity));
        }

        // Build the `digestID → expected digest` index for this namespace ONCE: a missing namespace
        // entry in `valueDigests` is a disclosure-integrity failure.
        let ns_digests_map = value_digests
            .iter()
            .find_map(|(k, v)| (k.as_text() == Some(ns)).then_some(v))
            .and_then(CborValue::as_map)
            .ok_or_else(|| VerifyFailure::reason(ReasonCode::DisclosureIntegrity))?;
        let expected_by_id: BTreeMap<i64, &[u8]> = ns_digests_map
            .iter()
            .filter_map(|(k, v)| Some((integer_label(k)?, v.as_bytes()?.as_slice())))
            .collect();

        // Track the `digestID`s already seen on an on-wire item in THIS namespace: a duplicate is the
        // false-accept lever (two items competing for one MSO digest slot) and is rejected.
        let mut seen_digest_ids: BTreeSet<i64> = BTreeSet::new();
        for record in ns_records {
            if !seen_digest_ids.insert(record.digest_id) {
                return Err(VerifyFailure::reason(ReasonCode::DisclosureIntegrity));
            }

            // Hash THIS record's OWN on-wire bytes (ISO/IEC 18013-5 §9.2.2.5) and match the MSO digest
            // recorded for its `digestID`. The disclosed value below is this SAME record's value, so a
            // matching digest authenticates exactly the claim that is disclosed.
            let computed = digest_alg.digest(record.raw_bytes);
            let expected = expected_by_id
                .get(&record.digest_id)
                .ok_or_else(|| VerifyFailure::reason(ReasonCode::DisclosureIntegrity))?;
            if computed.as_slice() != *expected {
                return Err(VerifyFailure::reason(ReasonCode::DisclosureIntegrity));
            }

            // Disclose this record's `(identifier → value)` UNDER its namespace (the namespace-grouped
            // shape — `elementIdentifier`s are unique only within a namespace, ISO/IEC 18013-5). The
            // `elementValue` is materialized HERE — only now, AFTER the digest matched — so an item
            // whose digest mismatched (rejected above) never pays the deep clone. Insert without ever
            // silently shadowing a CONFLICTING value for the SAME `(namespace, id)` — a same-key clash
            // with a different value is a structurally untrustworthy disclosure set (a consumer cannot
            // know which value is authoritative); an identical re-disclosure is harmless. Two namespaces
            // carrying the same `id` land in distinct sub-maps and never collide.
            insert_no_shadow(
                &mut disclosed,
                ns,
                record.identifier.clone(),
                record.element_value(),
            )?;
        }
    }
    Ok(disclosed)
}

/// Insert a disclosed `(namespace, identifier) → value` into the namespace-grouped `map` without ever
/// silently shadowing an existing entry.
///
/// `map` ([`DisclosedByNamespace`]) is keyed by namespace, each value the nested `{ identifier: value }`
/// map for that namespace. ISO/IEC 18013-5 `elementIdentifier`s are unique only WITHIN a namespace, so
/// the conflict rule is keyed on the FULL `(namespace, identifier)`: two namespaces carrying the same
/// `id` land in distinct sub-maps and NEVER collide (they are different attributes). A clash on the
/// SAME `(namespace, id)` with a DIFFERENT value MUST NOT silently overwrite an earlier one — across
/// documents in a multi-credential response, a consumer reading that attribute could otherwise be
/// served a second, attacker-chosen document's value — so it is rejected as a structurally
/// untrustworthy disclosure set. An identical re-disclosure (same value) is harmless and accepted.
fn insert_no_shadow(
    map: &mut DisclosedByNamespace,
    namespace: &str,
    identifier: String,
    value: AttributeValue,
) -> Result<(), VerifyFailure> {
    // Reach (or create) this namespace's `{ id: value }` sub-map.
    let ns_map = map.entry(namespace.to_owned()).or_default();
    match ns_map.get(&identifier) {
        // A genuine same-(namespace,id) collision with a DIFFERENT value: one would shadow the other.
        Some(existing) if *existing != value => {
            Err(VerifyFailure::reason(ReasonCode::DisclosureIntegrity))
        }
        // Same `(namespace, id)`, same value (or first sighting): no shadowing risk.
        Some(_) => Ok(()),
        None => {
            ns_map.insert(identifier, value);
            Ok(())
        }
    }
}

/// Read an integer-valued, text-keyed field from a CBOR map.
fn get_integer(value: &CborValue, key: &str) -> Option<i64> {
    get_map_entry(value, key).and_then(integer_label)
}

/// Read a CBOR integer value as `i64` (the digest IDs and ints; `ciborium` models all ints as a
/// 128-bit `Integer`).
fn integer_label(value: &CborValue) -> Option<i64> {
    match value {
        CborValue::Integer(i) => i128::from(*i).try_into().ok(),
        _ => None,
    }
}

/// Convert an mdoc `elementValue` CBOR value into the SDK's [`AttributeValue`]. Unsupported shapes
/// (e.g. floats) become [`AttributeValue::Null`] rather than failing — the digest already proved
/// integrity; this is a lossy presentation projection.
fn cbor_to_attribute(value: &CborValue) -> AttributeValue {
    match value {
        CborValue::Text(t) => AttributeValue::Text(t.clone()),
        CborValue::Integer(_) => {
            integer_label(value).map_or(AttributeValue::Null, AttributeValue::Integer)
        }
        CborValue::Bool(b) => AttributeValue::Boolean(*b),
        CborValue::Bytes(b) => AttributeValue::Bytes(b.clone()),
        CborValue::Array(items) => {
            AttributeValue::Array(items.iter().map(cbor_to_attribute).collect())
        }
        CborValue::Map(entries) => {
            let mut map = BTreeMap::new();
            for (k, v) in entries {
                if let Some(key) = k.as_text() {
                    map.insert(key.to_owned(), cbor_to_attribute(v));
                }
            }
            AttributeValue::Map(map)
        }
        // tdate-tagged text / other tagged values: unwrap text if present, else Null.
        CborValue::Tag(_, inner) => cbor_to_attribute(inner),
        _ => AttributeValue::Null,
    }
}

// =================================================================================================
// DeviceAuth holder binding (DeviceSignature path).
// =================================================================================================

/// A P-256 public key extracted from the MSO `DeviceKey` (COSE_Key).
#[derive(Debug)]
struct DeviceKey {
    /// Uncompressed SEC1 point (`0x04 || X || Y`).
    sec1: Vec<u8>,
}

/// Extract the holder's P-256 public key from the MSO `deviceKeyInfo.deviceKey` (a COSE_Key).
fn mso_device_key(mso: &CborValue) -> Result<DeviceKey, VerifyFailure> {
    let key_info = get_map_entry(mso, "deviceKeyInfo").ok_or_else(VerifyFailure::malformed)?;
    let device_key_value =
        get_map_entry(key_info, "deviceKey").ok_or_else(VerifyFailure::malformed)?;
    // Require an EC2 (kty=2) P-256 (crv=1) key; read kty/crv and X (-2)/Y (-3) directly from the
    // COSE_Key CBOR map via the shared `find_key_label` (the same integer-label reader used for the
    // coordinates below — no separate `coset::CoseKey` re-encode/parse just to read `kty`).
    if find_key_label(device_key_value, COSE_KEY_KTY, integer_label) != Some(COSE_KTY_EC2) {
        return Err(VerifyFailure::malformed());
    }
    if find_key_label(device_key_value, COSE_KEY_CRV, integer_label) != Some(COSE_CRV_P256) {
        return Err(VerifyFailure::malformed());
    }
    let x = find_key_label(device_key_value, COSE_KEY_X, |v| v.as_bytes().cloned())
        .ok_or_else(VerifyFailure::malformed)?;
    let y = find_key_label(device_key_value, COSE_KEY_Y, |v| v.as_bytes().cloned())
        .ok_or_else(VerifyFailure::malformed)?;
    // The 32-byte-coordinate check + `0x04 ‖ X ‖ Y` assembly is the shared
    // [`crate::crypto::p256_sec1_from_coords`] (DRY — the same SEC1 assembly the JWK path uses, just
    // fed from COSE labels here rather than a JWK).
    let sec1 = crate::crypto::p256_sec1_from_coords(&x, &y).ok_or_else(VerifyFailure::malformed)?;
    Ok(DeviceKey { sec1 })
}

/// Find the value of an integer-keyed (COSE label) entry in a COSE_Key CBOR map, projected through
/// `extract`. One generic finder for every label kind (integer value, byte-string value, …) so the
/// per-type readers are a single shared lookup rather than copy-pasted scans (DRY — Principle III).
fn find_key_label<T>(
    value: &CborValue,
    label: i64,
    extract: impl Fn(&CborValue) -> Option<T>,
) -> Option<T> {
    let map = value.as_map()?;
    map.iter().find_map(|(k, v)| {
        (integer_label(k) == Some(label))
            .then(|| extract(v))
            .flatten()
    })
}

/// Verify the `DeviceAuth` holder binding via the `DeviceSignature` `COSE_Sign1`.
///
/// The signature is computed over the **detached** `DeviceAuthentication` structure
/// `["DeviceAuthentication", SessionTranscript, docType, DeviceNameSpacesBytes]` wrapped in `#6.24`
/// (ISO/IEC 18013-5 §9.1.3); we rebuild that payload from the document's `deviceSigned.nameSpaces`
/// and the supplied session transcript, then verify the COSE_Sign1 over it with the MSO `DeviceKey`.
fn verify_device_binding(
    document: &CborValue,
    device_key: &DeviceKey,
    doc_type: &str,
    session_transcript: Option<&CborValue>,
    params: &MdocVerifyParams<'_>,
) -> Result<(), VerifyFailure> {
    let device_signed =
        get_map_entry(document, "deviceSigned").ok_or_else(VerifyFailure::malformed)?;
    let device_auth =
        get_map_entry(device_signed, "deviceAuth").ok_or_else(VerifyFailure::malformed)?;
    let device_signature_value = get_map_entry(device_auth, "deviceSignature")
        // A DeviceMac-only DeviceAuth is the ECDH variant — a documented follow-on, not the
        // signature path; treat its absence here as a holder-binding failure (no false-accept).
        .ok_or_else(|| VerifyFailure::reason(ReasonCode::HolderBinding))?;

    // FAIL-CLOSED (ISO/IEC 18013-5 §9.1.5): a `DeviceSignature` is ALWAYS computed over a real
    // `SessionTranscript`. A request-less verify with no transcript cannot confirm holder binding, so
    // the verifier MUST NOT fabricate a `[null, null, null]` transcript and "pass" the binding with
    // zero freshness/transport binding (a silent no-op false-accept). Reject up front: an explicit
    // `SessionTranscript` (or, for OpenID4VP, the reconstructed handover via `crate::openid4vp`) is
    // required to verify the `DeviceAuth`. This is `MissingRequestBinding` condition (2) — the
    // mdoc-no-transcript case (see the `ReasonCode` rustdoc; one of three distinct "binding material
    // absent" conditions the code intentionally covers — distinct from a present-but-invalid binding,
    // which is `HolderBinding`).
    if params.session_transcript.is_none() {
        return Err(VerifyFailure::reason(ReasonCode::MissingRequestBinding));
    }
    let device_signature = parse_cose_sign1(device_signature_value)?;

    // `deviceSigned.nameSpaces` is a `#6.24(bstr .cbor DeviceNameSpaces)`; carry its exact bytes.
    let device_name_spaces_value =
        get_map_entry(device_signed, "nameSpaces").ok_or_else(VerifyFailure::malformed)?;
    let device_name_spaces_bytes = reencode_tagged(device_name_spaces_value)?;

    // The `SessionTranscript` was decoded ONCE up front (Ef2, in `verify_inner`). It was confirmed
    // present above, so a `None` here means the supplied bytes were malformed CBOR → `malformed` (the
    // same reason the former per-document decode raised, at this same point).
    let session_transcript = session_transcript.ok_or_else(VerifyFailure::malformed)?;
    let device_auth_payload =
        build_device_authentication(session_transcript, doc_type, &device_name_spaces_bytes)
            .ok_or_else(VerifyFailure::malformed)?;

    verify_cose_sign1_detached_es256(&device_signature, &device_auth_payload, &device_key.sec1)
        .map_err(|()| VerifyFailure::reason(ReasonCode::HolderBinding))
}

/// Re-encode a `#6.24(bstr)` CBOR value to its canonical bytes (the `DeviceNameSpacesBytes` form).
fn reencode_tagged(value: &CborValue) -> Result<Vec<u8>, VerifyFailure> {
    let inner = unwrap_tagged_cbor_payload(value)?;
    Ok(crate::encode_tagged_cbor(&inner))
}

/// Decode the supplied `SessionTranscript` bytes to a CBOR value. The transcript is REQUIRED to verify
/// a `DeviceSignature` (ISO/IEC 18013-5 §9.1.5); [`verify_inner`] decodes it ONCE for the whole response
/// (Ef2) and threads the value into each document's [`verify_device_binding`], which rejects an absent
/// transcript ([`ReasonCode::MissingRequestBinding`]). This never fabricates one — it only re-hydrates
/// the explicit, caller-supplied bytes.
fn decode_session_transcript_value(session_transcript: &[u8]) -> Result<CborValue, VerifyFailure> {
    ciborium::from_reader(session_transcript).map_err(|_| VerifyFailure::malformed())
}

/// Build the `DeviceAuthentication` detached payload bytes: the `#6.24(bstr .cbor [...])` wrapping of
/// `["DeviceAuthentication", SessionTranscript, docType, DeviceNameSpacesBytes]` (ISO/IEC 18013-5
/// §9.1.3). Returns `None` only when `device_name_spaces_bytes` is not decodable CBOR.
///
/// The **one** authoritative `DeviceAuthentication` builder (DRY — Principle III): the holder signer
/// ([`crate::issuance::device::build_device_signature`]) signs over these bytes and this verifier
/// rebuilds them to check the signature, so the two MUST produce byte-identical output — a
/// signed↔verified symmetry that must never drift. Both call this one `pub(crate)` fn (mirroring the
/// shared [`crate::openid4vp::oid4vp_handover_transcript`]). Each caller maps the `None` into its own
/// error variant.
pub(crate) fn build_device_authentication(
    session_transcript: &CborValue,
    doc_type: &str,
    device_name_spaces_bytes: &[u8],
) -> Option<Vec<u8>> {
    // DeviceNameSpacesBytes is itself a #6.24(bstr) item; embed it as the already-encoded CBOR value.
    let device_ns_value: CborValue = ciborium::from_reader(device_name_spaces_bytes).ok()?;
    let device_auth = CborValue::Array(vec![
        CborValue::Text("DeviceAuthentication".to_owned()),
        session_transcript.clone(),
        CborValue::Text(doc_type.to_owned()),
        device_ns_value,
    ]);
    Some(crate::encode_tagged_cbor(&crate::cbor_to_vec(&device_auth)))
}

/// Verify a COSE_Sign1 ES256 signature over a **detached** payload against a SEC1 P-256 public key.
fn verify_cose_sign1_detached_es256(
    sign1: &CoseSign1,
    payload: &[u8],
    public_key_sec1: &[u8],
) -> Result<(), ()> {
    // The DeviceSignature MUST be a DETACHED COSE_Sign1: a nil payload (third array element `null`),
    // with the signed `DeviceAuthentication` supplied externally (ISO/IEC 18013-5 §9.1.3). A
    // COSE_Sign1 carrying an ATTACHED payload (a `bstr` third element) is a malformed holder binding
    // AND a panic vector: `coset`'s `tbs_detached_data` asserts `self.payload.is_none()` (an `assert!`
    // that fires in release too), so calling `verify_detached_signature` on attacker-controlled input
    // whose payload is present would PANIC/ABORT (a remote DoS). Reject it here, BEFORE any coset
    // detached-verify call, so the assert is never reachable from `verify()`.
    if sign1.payload.is_some() {
        return Err(());
    }

    // Gate on the algorithm BEFORE any signature math (the same single predicate the IssuerAuth path
    // uses): a non-ES256 DeviceSignature is rejected on its header alone.
    if !cose_alg_is_es256(sign1) {
        return Err(());
    }
    let verifying_key =
        p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key_sec1).map_err(|_| ())?;
    // The detached coset call (`verify_detached_signature`) stays distinct from the attached path's
    // `verify_signature`; only the inner raw-`r‖s` ES256 check is shared — the single
    // [`crate::crypto::p256_verify_es256`] kernel (DRY).
    sign1.verify_detached_signature(payload, &[], |sig, tbs| {
        crate::crypto::p256_verify_es256(&verifying_key, tbs, sig)
    })
}

#[cfg(any(test, feature = "test-vectors"))]
pub(crate) mod test_issuer;
#[cfg(test)]
mod tests;

#[cfg(test)]
mod unit {
    //! Direct unit tests of the pure helpers whose error branches are awkward to reach end-to-end.

    use super::{
        cbor_to_attribute, cose_alg_is_es256, ds_chain_from_x5chain, find_key_label,
        insert_no_shadow, integer_label, scan_raw_issuer_items, tdate_field,
        unwrap_tagged_cbor_payload, CborCursor, DigestAlgorithm, COSE_HEADER_X5CHAIN,
        TAG_ENCODED_CBOR,
    };
    use crate::types::AttributeValue;
    use ciborium::Value as CborValue;
    use coset::{iana::Algorithm, CoseSign1Builder, HeaderBuilder};
    use sha2::{Digest as _, Sha256};
    use std::collections::BTreeMap;

    #[test]
    fn cose_alg_gate_accepts_only_es256() {
        // Isolated probe of the algorithm gate (the single predicate both the IssuerAuth and
        // DeviceSignature paths gate on BEFORE any signature math): ES256 passes, ES384 / absent fail.
        // This proves the non-ES256 rejection in `issuer_auth_non_es256_alg_is_rejected_as_tamper` and
        // `device_signature_with_non_es256_alg_fails_holder_binding` is the ALGORITHM gate, distinct
        // from the signature-math failures that share the same ReasonCode.
        let es256 = CoseSign1Builder::new()
            .protected(HeaderBuilder::new().algorithm(Algorithm::ES256).build())
            .signature(vec![0; 64])
            .build();
        assert!(cose_alg_is_es256(&es256), "ES256 header passes the gate");

        let es384 = CoseSign1Builder::new()
            .protected(HeaderBuilder::new().algorithm(Algorithm::ES384).build())
            .signature(vec![0; 64])
            .build();
        assert!(
            !cose_alg_is_es256(&es384),
            "ES384 header is rejected by the gate, not by failed ES256 math"
        );

        // An absent `alg` header (no protected algorithm) also fails the gate.
        let no_alg = CoseSign1Builder::new().signature(vec![0; 64]).build();
        assert!(
            !cose_alg_is_es256(&no_alg),
            "an absent alg header fails the gate (never guessed as ES256)"
        );
    }

    /// Read a disclosed `(namespace, id)` out of the namespace-grouped nested map (`{ ns: { id: value }
    /// }`, [`super::DisclosedByNamespace`]) — the shape `insert_no_shadow` / `verify_value_digests` build.
    fn ns_attr<'a>(
        map: &'a super::DisclosedByNamespace,
        namespace: &str,
        id: &str,
    ) -> Option<&'a AttributeValue> {
        map.get(namespace).and_then(|ns_map| ns_map.get(id))
    }

    #[test]
    fn insert_no_shadow_inserts_accepts_idempotent_rejects_conflict() {
        const NS: &str = "org.iso.18013.5.1";
        let mut map = BTreeMap::new();
        // First sighting inserts under the namespace.
        assert!(insert_no_shadow(
            &mut map,
            NS,
            "given_name".to_owned(),
            AttributeValue::Text("Ada".to_owned())
        )
        .is_ok());
        assert_eq!(
            ns_attr(&map, NS, "given_name"),
            Some(&AttributeValue::Text("Ada".to_owned()))
        );
        // Identical re-disclosure is accepted (no shadowing of a different value) and does not change
        // the stored value.
        assert!(insert_no_shadow(
            &mut map,
            NS,
            "given_name".to_owned(),
            AttributeValue::Text("Ada".to_owned())
        )
        .is_ok());
        assert_eq!(
            ns_attr(&map, NS, "given_name"),
            Some(&AttributeValue::Text("Ada".to_owned()))
        );
        // A conflicting value for the SAME (namespace, id) is rejected (DisclosureIntegrity) and the
        // original is preserved.
        let err = insert_no_shadow(
            &mut map,
            NS,
            "given_name".to_owned(),
            AttributeValue::Text("EVIL".to_owned()),
        )
        .unwrap_err();
        assert_eq!(err.reason, crate::types::ReasonCode::DisclosureIntegrity);
        assert_eq!(
            ns_attr(&map, NS, "given_name"),
            Some(&AttributeValue::Text("Ada".to_owned())),
            "a rejected conflict never overwrites the existing value"
        );
        // A distinct identifier in the same namespace still inserts cleanly.
        assert!(insert_no_shadow(
            &mut map,
            NS,
            "nationality".to_owned(),
            AttributeValue::Text("NL".to_owned())
        )
        .is_ok());
        // The SAME id in a DIFFERENT namespace is a DISTINCT attribute: it never collides with the
        // first namespace's `given_name`, and BOTH values are kept under their own namespaces.
        const OTHER_NS: &str = "org.example.other";
        assert!(insert_no_shadow(
            &mut map,
            OTHER_NS,
            "given_name".to_owned(),
            AttributeValue::Text("Grace".to_owned())
        )
        .is_ok());
        assert_eq!(
            ns_attr(&map, NS, "given_name"),
            Some(&AttributeValue::Text("Ada".to_owned())),
            "the first namespace's given_name is untouched by a same-id different-namespace insert"
        );
        assert_eq!(
            ns_attr(&map, OTHER_NS, "given_name"),
            Some(&AttributeValue::Text("Grace".to_owned())),
            "the same id in another namespace is a distinct attribute, kept under that namespace"
        );
        // Two namespaces present: `org.iso.18013.5.1` (given_name + nationality) and `org.example.other`.
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn digest_algorithm_parses_the_iso_names() {
        assert_eq!(
            DigestAlgorithm::from_name("SHA-256"),
            Some(DigestAlgorithm::Sha256)
        );
        assert_eq!(
            DigestAlgorithm::from_name("SHA-384"),
            Some(DigestAlgorithm::Sha384)
        );
        assert_eq!(
            DigestAlgorithm::from_name("SHA-512"),
            Some(DigestAlgorithm::Sha512)
        );
        assert_eq!(DigestAlgorithm::from_name("SHA-1"), None);
        assert_eq!(DigestAlgorithm::from_name(""), None);
    }

    #[test]
    fn digest_algorithm_lengths_match_the_hash() {
        assert_eq!(DigestAlgorithm::Sha256.digest(b"x").len(), 32);
        assert_eq!(DigestAlgorithm::Sha384.digest(b"x").len(), 48);
        assert_eq!(DigestAlgorithm::Sha512.digest(b"x").len(), 64);
    }

    /// Build a `validityInfo`-shaped CBOR map carrying a single `key → tdate(text)` entry, so the
    /// `tdate_field` reader (and the shared RFC 3339 parser it delegates to) can be exercised.
    fn validity_info_with(key: &str, value: &str) -> CborValue {
        CborValue::Map(vec![(
            CborValue::Text(key.to_owned()),
            CborValue::Text(value.to_owned()),
        )])
    }

    #[test]
    fn tdate_field_parses_a_well_formed_utc_instant() {
        // The mdoc `tdate` reader delegates to the shared RFC 3339 parser (`crate::datetime`).
        assert_eq!(
            tdate_field(
                &validity_info_with("validFrom", "1970-01-01T00:00:00Z"),
                "validFrom"
            )
            .ok(),
            Some(0)
        );
        assert_eq!(
            tdate_field(
                &validity_info_with("validUntil", "2023-01-01T00:00:00Z"),
                "validUntil"
            )
            .ok(),
            Some(1_672_531_200)
        );
        // Fractional seconds are tolerated (still ends in Z); they are truncated.
        assert_eq!(
            tdate_field(
                &validity_info_with("signed", "2023-01-01T00:00:00.123Z"),
                "signed"
            )
            .ok(),
            Some(1_672_531_200)
        );
    }

    #[test]
    fn tdate_field_accepts_a_tag0_wrapped_text() {
        // A `#6.0`-tagged text (a CBOR `tdate`) is read the same as a bare text.
        let info = CborValue::Map(vec![(
            CborValue::Text("validFrom".to_owned()),
            CborValue::Tag(
                0,
                Box::new(CborValue::Text("2023-01-01T00:00:00Z".to_owned())),
            ),
        )]);
        assert_eq!(tdate_field(&info, "validFrom").ok(), Some(1_672_531_200));
    }

    #[test]
    fn tdate_field_rejects_a_malformed_or_invalid_instant() {
        // A malformed timestamp fails closed (Err), never a wrong instant.
        assert!(tdate_field(&validity_info_with("validFrom", "2023-01-01"), "validFrom").is_err());
        assert!(tdate_field(
            &validity_info_with("validFrom", "2023-01-01T00:00:00+01:00"),
            "validFrom"
        )
        .is_err());
        // An out-of-range day-of-month (the old `1..=31` bug) is now rejected, not rolled forward.
        assert!(tdate_field(
            &validity_info_with("validFrom", "2023-02-31T00:00:00Z"),
            "validFrom"
        )
        .is_err());
        // A missing field is malformed.
        assert!(tdate_field(
            &validity_info_with("other", "2023-01-01T00:00:00Z"),
            "validFrom"
        )
        .is_err());
        // A non-text value is malformed.
        let numeric = CborValue::Map(vec![(
            CborValue::Text("validFrom".to_owned()),
            CborValue::Integer(0.into()),
        )]);
        assert!(tdate_field(&numeric, "validFrom").is_err());
    }

    #[test]
    fn integer_label_rejects_non_integers() {
        assert_eq!(integer_label(&CborValue::Text("x".to_owned())), None);
        assert_eq!(integer_label(&CborValue::Integer(7.into())), Some(7));
    }

    #[test]
    fn cbor_to_attribute_maps_floats_and_tags() {
        // A float has no AttributeValue projection → Null (lossy presentation, integrity already
        // proven by the digest).
        assert_eq!(
            cbor_to_attribute(&CborValue::Float(1.5)),
            AttributeValue::Null
        );
        // A tagged value unwraps to its inner projection.
        assert_eq!(
            cbor_to_attribute(&CborValue::Tag(
                0,
                Box::new(CborValue::Text("t".to_owned()))
            )),
            AttributeValue::Text("t".to_owned())
        );
    }

    #[test]
    fn unwrap_tagged_cbor_payload_rejects_non_tag_and_non_bytes() {
        // A #6.24 tag wrapping a non-bytes value is malformed.
        let tag_over_text = CborValue::Tag(TAG_ENCODED_CBOR, Box::new(CborValue::Text("x".into())));
        assert!(unwrap_tagged_cbor_payload(&tag_over_text).is_err());
        // A value that is not a #6.24 tag at all is malformed.
        assert!(unwrap_tagged_cbor_payload(&CborValue::Text("x".into())).is_err());
        // The well-formed case succeeds.
        let ok = CborValue::Tag(TAG_ENCODED_CBOR, Box::new(CborValue::Bytes(vec![1, 2, 3])));
        assert_eq!(unwrap_tagged_cbor_payload(&ok).unwrap(), vec![1, 2, 3]);
    }

    /// Build a COSE_Sign1 carrying the given x5chain header value (test helper).
    fn sign1_with_x5chain(x5chain: CborValue) -> coset::CoseSign1 {
        let unprotected = HeaderBuilder::new()
            .value(COSE_HEADER_X5CHAIN, x5chain)
            .build();
        CoseSign1Builder::new()
            .unprotected(unprotected)
            .payload(vec![0])
            .signature(vec![0; 64])
            .build()
    }

    #[test]
    fn ds_chain_from_x5chain_rejects_malformed_chains() {
        // An array whose first element is not a bstr is malformed.
        let bad_array = sign1_with_x5chain(CborValue::Array(vec![CborValue::Integer(1.into())]));
        assert!(ds_chain_from_x5chain(&bad_array).is_err());
        // A scalar that is neither bstr nor array is malformed.
        let scalar = sign1_with_x5chain(CborValue::Integer(1.into()));
        assert!(ds_chain_from_x5chain(&scalar).is_err());
        // A bare-bstr chain resolves to a single-cert chain whose leaf is the bytes.
        let good = sign1_with_x5chain(CborValue::Bytes(vec![9, 9]));
        assert_eq!(ds_chain_from_x5chain(&good).unwrap(), vec![vec![9, 9]]);
    }

    #[test]
    fn tdate_field_rejects_non_text_non_tag_values() {
        // validityInfo with a `signed` that is an integer (not text / not #6.0) is malformed.
        let info = CborValue::Map(vec![(
            CborValue::Text("signed".to_owned()),
            CborValue::Integer(7.into()),
        )]);
        assert!(tdate_field(&info, "signed").is_err());
        // A #6.0-tagged non-text value is also malformed.
        let info_bad_tag = CborValue::Map(vec![(
            CborValue::Text("signed".to_owned()),
            CborValue::Tag(0, Box::new(CborValue::Integer(7.into()))),
        )]);
        assert!(tdate_field(&info_bad_tag, "signed").is_err());
    }

    #[test]
    fn find_key_label_reads_int_and_bytes_via_one_generic() {
        // The generic `find_key_label` replaces the old copy-pasted int/bytes finders (DRY): the same
        // lookup serves an integer projection and a byte-string projection, and a wrong-type
        // projection returns None (the entry exists but is not the requested kind).
        let key = CborValue::Map(vec![
            (CborValue::Integer(1.into()), CborValue::Integer(2.into())), // label 1 → int 2
            (
                CborValue::Integer((-2).into()),
                CborValue::Bytes(vec![9, 9, 9]),
            ), // label -2 → bytes
        ]);
        assert_eq!(find_key_label(&key, 1, integer_label), Some(2));
        assert_eq!(
            find_key_label(&key, -2, |v| v.as_bytes().cloned()),
            Some(vec![9, 9, 9])
        );
        // Label 1 holds an int, not bytes → the bytes projection finds nothing.
        assert_eq!(find_key_label(&key, 1, |v| v.as_bytes().cloned()), None);
        // An absent label → None. A non-map value → None.
        assert_eq!(find_key_label(&key, 7, integer_label), None);
        assert_eq!(
            find_key_label(&CborValue::Integer(0.into()), 1, integer_label),
            None
        );
    }

    #[test]
    fn cbor_cursor_skips_every_major_type_and_rejects_indefinite_length() {
        // The raw cursor must skip exactly one complete item of each major type so the namespaces
        // walk steps correctly over fields it does not capture.
        let nested = CborValue::Array(vec![
            CborValue::Integer(1.into()),        // major 0
            CborValue::Integer((-1).into()),     // major 1
            CborValue::Bytes(vec![1, 2, 3]),     // major 2
            CborValue::Text("hello".to_owned()), // major 3
            CborValue::Array(vec![CborValue::Bool(true), CborValue::Null]), // major 4 (nested)
            CborValue::Map(vec![(
                CborValue::Text("k".to_owned()),
                CborValue::Integer(9.into()),
            )]), // major 5
            CborValue::Tag(0, Box::new(CborValue::Text("t".to_owned()))), // major 6
            CborValue::Bool(false),              // major 7
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&nested, &mut buf).unwrap();
        // A trailing sentinel byte after the encoded array proves `skip_item` consumed EXACTLY the
        // array's bytes (the cursor lands precisely on the sentinel).
        buf.push(0xAB);
        let mut cursor = CborCursor::new(&buf);
        assert!(cursor.skip_item().is_some(), "skips the whole nested array");
        assert_eq!(cursor.pos, buf.len() - 1, "lands exactly on the sentinel");

        // Indefinite-length (additional info 31) is rejected — ISO/IEC 18013-5 §9.1.1 forbids it and a
        // definite span is required to capture exact bytes. 0x9f = array(*) indefinite.
        let mut indefinite = CborCursor::new(&[0x9f, 0xff]);
        assert!(indefinite.skip_item().is_none());
        // Reserved additional-info 28..=30 (0x1c here) is also rejected.
        let mut reserved = CborCursor::new(&[0x1c]);
        assert!(reserved.read_head().is_none());

        // A byte/text string whose declared length OVERRUNS the remaining input fails closed in the
        // iterative skip (the `pos > input.len()` guard), never reading past the buffer. `0x43` =
        // bstr(3) but only 1 content byte follows.
        let mut truncated = CborCursor::new(&[0x43, 0x01]);
        assert!(
            truncated.skip_item().is_none(),
            "a string length overrunning the input is rejected (no out-of-bounds read)"
        );

        // A 4-byte length head (additional info 26) is decoded like the 1/2/8-byte forms. `0x5a` =
        // bstr with a u32 length; here a length-2 string with two content bytes round-trips.
        let mut len4 = CborCursor::new(&[0x5a, 0x00, 0x00, 0x00, 0x02, 0xAA, 0xBB]);
        assert!(
            len4.skip_item().is_some(),
            "a 4-byte (u32) length head skips its content correctly"
        );
        assert_eq!(len4.pos, 7, "the whole 4-byte-length string was consumed");
    }

    #[test]
    fn cbor_cursor_bounds_recursion_depth_no_stack_overflow() {
        // DoS PROBE (fix #2): the raw cursor's skip walk recurses once per nested array/map/tag level
        // over ATTACKER-controlled CBOR. With no bound, a deeply-nested item overflows the stack and
        // aborts the process (uncatchable SIGABRT). Build a chain of `DEPTH` nested 1-element arrays
        // (each `0x81` = array(1)) far deeper than the cursor's bound; `skip_item` must return `None`
        // (MalformedCredential upstream), NEVER overflow the stack.
        const DEPTH: usize = 500_000;
        let deep = vec![0x81u8; DEPTH]; // DEPTH nested array(1) heads, no terminal element
        let mut cursor = CborCursor::new(&deep);
        assert!(
            cursor.skip_item().is_none(),
            "over-deep nesting yields None (bounded), never a stack overflow"
        );

        // A nesting depth WITHIN the bound still walks correctly: a modest nested array round-trips.
        let nested = CborValue::Array(vec![CborValue::Array(vec![CborValue::Array(vec![
            CborValue::Integer(7.into()),
        ])])]);
        let mut buf = Vec::new();
        ciborium::into_writer(&nested, &mut buf).unwrap();
        let mut ok_cursor = CborCursor::new(&buf);
        assert!(
            ok_cursor.skip_item().is_some(),
            "a legitimately-nested item within the bound still skips cleanly"
        );
    }

    #[test]
    fn verify_rejects_deeply_nested_response_without_abort() {
        // End-to-end: a deeply-nested `DeviceResponse` must yield a clean `MalformedCredential`
        // verdict, never a process abort — neither the always-on `ciborium` parse nor the raw cursor
        // may overflow the stack on adversarial nesting.
        use super::{verify_with_meta, MdocVerifyParams};
        use crate::trust::StaticTestAnchors;
        // 400 nested arrays (deeper than ciborium's 256 recursion limit) wrapped so the bytes parse as
        // far as the nesting bound, then bottom out — the verifier must reject, not abort.
        let mut deep = vec![0x81u8; 400];
        deep.push(0x00); // a terminal 0 so the innermost array has its one element
        let result = verify_with_meta(
            &deep,
            &StaticTestAnchors::new(),
            &MdocVerifyParams::default(),
        )
        .0;
        assert!(!result.valid, "a deeply-nested response must not be VALID");
        assert_eq!(
            result.reasons,
            vec![crate::types::ReasonCode::MalformedCredential],
            "adversarial nesting is MalformedCredential, never an abort"
        );
    }

    #[test]
    fn cbor_cursor_take_text_rejects_giant_declared_length_no_panic() {
        // OVERFLOW PROBE (fix #3): a text head declaring length 0xFFFF_FFFF_FFFF_FFFF (`0x7b` + 8
        // length bytes) must NOT compute `pos + len` with an unchecked add (which panics under the
        // overflow-checks the dev/test profile enables). `take_text` must return `None` on the
        // overflow, never panic.
        let giant_text = [0x7b, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let mut cursor = CborCursor::new(&giant_text);
        assert!(
            cursor.take_text().is_none(),
            "a giant declared text length yields None (checked add), never an overflow panic"
        );
        // The sibling skip path over the same giant byte/text length head is likewise overflow-safe.
        let giant_bytes = [0x5b, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let mut skip_cursor = CborCursor::new(&giant_bytes);
        assert!(
            skip_cursor.skip_item().is_none(),
            "skipping a giant declared byte-string length is overflow-safe too"
        );
    }

    #[test]
    fn scan_raw_issuer_items_captures_the_exact_on_wire_bytes_not_a_reencode() {
        // The load-bearing property of fix #1: the digest input is the `IssuerSignedItemBytes` AS
        // RECEIVED. Build a `DeviceResponse` skeleton whose single `#6.24(bstr)` item carries a
        // DELIBERATELY NON-MINIMAL outer byte-string length header (`0x59 00 LL` — a 2-byte length
        // where 1 byte suffices), which a re-encode (ciborium, canonical) would NEVER reproduce. The
        // scanner must hand back those exact non-canonical bytes, so hashing them differs from hashing
        // a canonical re-encode — proving the verifier hashes the wire bytes.
        let inner = {
            // A minimal IssuerSignedItem map with digestID = 5.
            let item = CborValue::Map(vec![
                (
                    CborValue::Text("digestID".to_owned()),
                    CborValue::Integer(5.into()),
                ),
                (
                    CborValue::Text("elementIdentifier".to_owned()),
                    CborValue::Text("x".to_owned()),
                ),
                (
                    CborValue::Text("elementValue".to_owned()),
                    CborValue::Integer(1.into()),
                ),
            ]);
            let mut b = Vec::new();
            ciborium::into_writer(&item, &mut b).unwrap();
            b
        };
        // Hand-encode `#6.24(bstr)` with a NON-minimal 2-byte length head: tag 24 = `0xD8 0x18`,
        // then `0x59 <len:u16>` for the byte string (canonical would be `0x58 <len:u8>` for len<256).
        assert!(
            inner.len() < 256,
            "test item fits a 1-byte canonical length"
        );
        let mut non_canonical_item = vec![0xD8, 0x18, 0x59];
        non_canonical_item.extend_from_slice(&u16::try_from(inner.len()).unwrap().to_be_bytes());
        non_canonical_item.extend_from_slice(&inner);

        // A canonical re-encode of the SAME inner bytes uses the shorter `0x58` length head, so the two
        // framings differ — the precondition that makes this test meaningful.
        let canonical_item = {
            let tagged =
                CborValue::Tag(TAG_ENCODED_CBOR, Box::new(CborValue::Bytes(inner.clone())));
            let mut b = Vec::new();
            ciborium::into_writer(&tagged, &mut b).unwrap();
            b
        };
        assert_ne!(
            non_canonical_item, canonical_item,
            "the non-minimal framing must differ from the canonical re-encode"
        );

        // Build the minimal `DeviceResponse → documents[0] → issuerSigned → nameSpaces → {ns:[item]}`
        // wrapper around the non-canonical item bytes, splicing the raw item in verbatim. (We encode
        // the surrounding maps/arrays canonically, then replace the canonical item with the
        // non-canonical one, which has the same inner content + a longer length head.)
        let wire = build_device_response_with_raw_item("ns", &non_canonical_item, &canonical_item);

        let per_doc = scan_raw_issuer_items(&wire);
        assert_eq!(per_doc.len(), 1, "one document scanned");
        let ns_records = per_doc[0]
            .get("ns")
            .expect("the `ns` namespace was captured");
        assert_eq!(ns_records.len(), 1, "one item captured for the namespace");
        let record = &ns_records[0];
        assert_eq!(
            record.digest_id, 5,
            "the digestID was decoded from the item"
        );
        assert_eq!(
            record.raw_bytes,
            non_canonical_item.as_slice(),
            "the scanner captures the EXACT on-wire bytes (non-minimal framing preserved)"
        );
        // The bytes captured and the value decoded are ONE record (the integrity tie): the identifier
        // and value were decoded from the SAME bytes the digest is computed over. `element_value()`
        // materializes the (deferred) value lazily from the record's stored inner map.
        assert_eq!(record.identifier, "x");
        assert_eq!(record.element_value(), AttributeValue::Integer(1));
        // The digest of the captured wire bytes differs from the digest of a canonical re-encode — so a
        // verifier hashing the wire bytes (this fix) and one re-encoding would disagree.
        assert_ne!(
            Sha256::digest(record.raw_bytes).to_vec(),
            Sha256::digest(&canonical_item).to_vec(),
            "hashing the wire bytes is NOT the same as hashing a canonical re-encode"
        );
    }

    /// Build a `DeviceResponse` whose `documents[0].issuerSigned.nameSpaces[namespace]` array holds a
    /// single element, splicing `raw_item` (the exact bytes to land on the wire) in place of the
    /// canonical encoding `canonical_item`. The rest of the structure is canonical CBOR.
    fn build_device_response_with_raw_item(
        namespace: &str,
        raw_item: &[u8],
        canonical_item: &[u8],
    ) -> Vec<u8> {
        // First encode the structure with the CANONICAL item as a placeholder, then byte-replace it
        // with the raw (non-canonical) item — both share the identical inner content, so the only
        // change is the spliced element's framing.
        let canonical_value: CborValue =
            ciborium::from_reader(canonical_item).expect("canonical item decodes");
        let response = CborValue::Map(vec![(
            CborValue::Text("documents".to_owned()),
            CborValue::Array(vec![CborValue::Map(vec![(
                CborValue::Text("issuerSigned".to_owned()),
                CborValue::Map(vec![(
                    CborValue::Text("nameSpaces".to_owned()),
                    CborValue::Map(vec![(
                        CborValue::Text(namespace.to_owned()),
                        CborValue::Array(vec![canonical_value]),
                    )]),
                )]),
            )])]),
        )]);
        let mut encoded = Vec::new();
        ciborium::into_writer(&response, &mut encoded).unwrap();
        // Splice: find the canonical item bytes and replace with the raw (non-canonical) bytes.
        let at = encoded
            .windows(canonical_item.len())
            .position(|w| w == canonical_item)
            .expect("canonical item present in the encoded response");
        let mut spliced = encoded[..at].to_vec();
        spliced.extend_from_slice(raw_item);
        spliced.extend_from_slice(&encoded[at + canonical_item.len()..]);
        spliced
    }
}
