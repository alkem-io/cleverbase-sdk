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
use coset::{CborSerializable, CoseKey, CoseSign1, Label, RegisteredLabelWithPrivate};
use sha2::{Digest, Sha384, Sha512};
use x509_cert::der::{Decode as _, Encode as _};
use x509_cert::Certificate;

use crate::status::StatusOutcome;
use crate::trust::TrustAnchorSource;
use crate::types::{
    AttributeValue, IssuerRole, ReasonCode, TrustStatus, Validity, VerificationResult,
};

/// The CBOR tag for an "encoded CBOR data item" (`#6.24`) — a byte string whose content is itself
/// CBOR. ISO/IEC 18013-5 wraps each `IssuerSignedItem`, the MSO, the `DeviceNameSpaces`, and the
/// `SessionTranscript`/`DeviceAuthentication` payloads in this tag so the *exact bytes* are what gets
/// hashed/signed (a re-serialization with different map ordering must not change the digest).
const TAG_ENCODED_CBOR: u64 = 24;

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
/// computed over; it is supplied by the transport/OpenID4VP layer. When `None`, the verifier treats
/// the holder binding as bound to an empty transcript (the value the test issuer and a transport-less
/// presentation agree on).
#[derive(Debug, Clone)]
pub struct MdocVerifyParams<'a> {
    /// The verification instant, in Unix seconds, at which `validityInfo` is enforced.
    pub now_unix: i64,
    /// The CBOR-encoded ISO/IEC 18013-5 `SessionTranscript` the `DeviceSignature` is bound to.
    pub session_transcript: Option<&'a [u8]>,
    /// The issuer role under which DS trust is resolved against the anchors (mdoc anchors to an IACA
    /// root; the role selects the per-role/format anchor set).
    pub role: IssuerRole,
    /// The revocation/status outcome (the T014 seam) — the canonical [`StatusOutcome`] the
    /// [`verify()`](crate::verify()) entry point resolves through the host status source. Mirrors the SD-JWT VC
    /// status seam so the always-on bar's revocation check covers both formats.
    pub status: StatusOutcome,
}

impl Default for MdocVerifyParams<'_> {
    /// A default suitable for the offline suite: no session transcript, the PID role (the role under
    /// which the test IACA anchor is configured), and a zero instant the caller is expected to set.
    fn default() -> Self {
        Self {
            now_unix: 0,
            session_transcript: None,
            role: IssuerRole::Pid,
            status: StatusOutcome::NoStatus,
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
/// `anchors` is the configured trust-anchor source (the IACA root for mdoc); `params` carries the
/// verification instant, the session transcript for the holder binding, and the issuer role.
#[must_use]
pub fn verify<A: TrustAnchorSource + ?Sized>(
    device_response: &[u8],
    anchors: &A,
    params: &MdocVerifyParams<'_>,
) -> VerificationResult {
    match verify_inner(device_response, anchors, params) {
        Ok(result) => result,
        Err(failure) => VerificationResult::invalid(failure.reason),
    }
}

/// Whether a presented mdoc's `DeviceAuth` holder-binding **machinery** is structurally sound — used
/// to tell a fresh-nonce/transcript mismatch apart from a genuine holder-binding fault when a
/// [`verify`] run returns [`ReasonCode::HolderBinding`].
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
/// Used only to refine the failure attribution when [`verify`] already returned
/// [`ReasonCode::HolderBinding`]; a malformed/absent structure conservatively reports `Faulty` (a
/// holder-binding fault is never silently downgraded to a replay).
#[must_use]
pub fn device_binding_machinery(device_response: &[u8]) -> DeviceBindingMachinery {
    let sound = classify_device_binding(device_response).unwrap_or(false);
    if sound {
        DeviceBindingMachinery::Sound
    } else {
        DeviceBindingMachinery::Faulty
    }
}

/// The fallible body of [`device_binding_machinery`]: `Some(true)` iff EVERY document's binding
/// machinery is sound, `Some(false)` iff at least one is structurally broken, `None` if the response
/// is too malformed to classify (the caller treats `None`/`false` alike as `Faulty`).
fn classify_device_binding(device_response: &[u8]) -> Option<bool> {
    let root: CborValue = ciborium::from_reader(device_response).ok()?;
    let documents = get_map_entry(&root, "documents").and_then(CborValue::as_array)?;
    if documents.is_empty() {
        return Some(false);
    }
    // Every document's binding machinery must be sound for the overall failure to be a (freshness)
    // replay; one structurally-broken binding makes it a genuine holder-binding fault.
    Some(documents.iter().all(device_binding_machinery_sound))
}

/// Whether a single `Document`'s `DeviceAuth` holder-binding machinery is structurally sound: the
/// `DeviceAuth` carries a `DeviceSignature` (not `DeviceMac`-only), its protected alg is ES256, the
/// MSO `DeviceKey` parses to a P-256 key, and the `DeviceSignature` bytes form a well-formed ES256
/// (`r‖s` or DER) signature. No payload is checked (transcript-independent).
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
        let sig = &device_signature.signature;
        let well_formed = p256::ecdsa::Signature::from_slice(sig).is_ok()
            || p256::ecdsa::Signature::from_der(sig).is_ok();
        Some(well_formed)
    };
    // A document too malformed to inspect is conservatively NOT sound (fault, never a silent replay).
    check().unwrap_or(false)
}

/// The disclosed attributes recovered by the **issuer-side** conformance verification of an mdoc
/// `DeviceResponse`'s first document, keyed by `elementIdentifier`.
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
        let verified =
            verify_issuer_signed(issuer_signed, raw_items.first(), anchors, &doc_type, params)?;
        Ok(verified.disclosed)
    };
    run().map_err(|failure| failure.reason)
}

/// The fallible verification body; `verify` maps its error to a specific-reason INVALID verdict.
///
/// A `DeviceResponse` MAY carry more than one `Document`. The verdict is VALID only when **every**
/// document clears the full always-on bar — verifying just `documents[0]` would let a forged second
/// document ride inside a VALID verdict, with no signature/trust/validity/status/holder-binding check
/// (a false-accept). The top-level `DeviceResponse.status` is also enforced (a non-zero `status`
/// signals the holder reported an error and the response MUST NOT be treated as a clean success), and
/// a present `documentErrors` entry rejects the response (the device could not return a requested
/// document, so the response is not a complete success).
fn verify_inner<A: TrustAnchorSource + ?Sized>(
    device_response: &[u8],
    anchors: &A,
    params: &MdocVerifyParams<'_>,
) -> Result<VerificationResult, VerifyFailure> {
    let root: CborValue =
        ciborium::from_reader(device_response).map_err(|_| VerifyFailure::malformed())?;

    // --- DeviceResponse.status: a non-zero status (ISO/IEC 18013-5 §8.3.2.1.2.2) means the holder
    //     reported an error; a clean success is `status == 0`. A non-zero status MUST NOT carry a
    //     VALID verdict. -------------------------------------------------------------------------------
    enforce_device_response_status(&root)?;

    // --- documentErrors: if the device could not return a requested document, the response is not a
    //     complete success — reject rather than silently accept a partial response. ------------------
    if get_map_entry(&root, "documentErrors").is_some() {
        return Err(VerifyFailure::reason(ReasonCode::MalformedCredential));
    }

    let documents = get_map_entry(&root, "documents")
        .and_then(CborValue::as_array)
        .ok_or_else(VerifyFailure::malformed)?;
    // An empty `documents` array carries nothing to verify; a VALID verdict over zero credentials is
    // meaningless, so reject it.
    if documents.is_empty() {
        return Err(VerifyFailure::malformed());
    }

    // Capture the on-wire `IssuerSignedItemBytes` of every document once, up front: ISO/IEC 18013-5
    // §9.2.2.5 hashes the bytes AS RECEIVED, so the `valueDigests` check below feeds on these exact
    // spans (keyed by `(namespace, digestID)`), never a re-encode. Indexed by document position.
    let raw_items = scan_raw_issuer_items(device_response);

    // Verify EVERY document; the verdict is VALID only if all pass. Disclosed attributes are merged
    // across documents into the single result map WITHOUT silent shadowing: a second authentic
    // document (same trusted DS, or a holder presenting two credentials) MUST NOT be able to overwrite
    // a claim a consumer reads with a conflicting value. A same-identifier clash with a different value
    // is rejected (`DisclosureIntegrity`); an identical re-disclosure is harmless and merges cleanly.
    let mut disclosed = BTreeMap::new();
    for (index, document) in documents.iter().enumerate() {
        // The raw-item capture is positional + best-effort; an out-of-range/absent entry yields an
        // empty map, so `verify_value_digests` fails that document's items closed (never a re-encode).
        let doc_raw_items = raw_items.get(index);
        let doc_disclosed = verify_one_document(document, doc_raw_items, anchors, params)?;
        for (identifier, value) in doc_disclosed {
            insert_no_shadow(&mut disclosed, identifier, value)?;
        }
    }

    Ok(VerificationResult {
        valid: true,
        disclosed_attributes: disclosed,
        trust_status: TrustStatus::Trusted,
        qualified_status: None,
        reasons: Vec::new(),
    })
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

/// Run the full always-on bar over a single `Document`, returning its disclosed attributes on success.
///
/// `raw_items` is the on-wire `IssuerSignedItemBytes` captured for THIS document (keyed by
/// `(namespace, digestID)`), the digest input ISO/IEC 18013-5 §9.2.2.5 hashes; `None` when the raw
/// pass could not place this document (then the `valueDigests` check fails its items closed).
fn verify_one_document<A: TrustAnchorSource + ?Sized>(
    document: &CborValue,
    raw_items: Option<&RawDocumentItems<'_>>,
    anchors: &A,
    params: &MdocVerifyParams<'_>,
) -> Result<BTreeMap<String, AttributeValue>, VerifyFailure> {
    let doc_type = get_text(document, "docType").ok_or_else(VerifyFailure::malformed)?;
    let issuer_signed =
        get_map_entry(document, "issuerSigned").ok_or_else(VerifyFailure::malformed)?;

    // --- Issuer-side bar: IssuerAuth signature + DS trust + MSO validity + valueDigests integrity. --
    let issuer_verified =
        verify_issuer_signed(issuer_signed, raw_items, anchors, &doc_type, params)?;

    // --- DeviceAuth holder binding: DeviceSignature over DeviceAuthentication w/ the MSO DeviceKey. --
    verify_device_binding(document, &issuer_verified.device_key, &doc_type, params)?;

    Ok(issuer_verified.disclosed)
}

/// The result of verifying the **issuer-signed** half of an mdoc document: the disclosed attributes
/// (after the `valueDigests` integrity recompute) and the MSO `DeviceKey` the holder binding is
/// checked against.
struct IssuerVerified {
    /// The disclosed attributes, after each `IssuerSignedItem` digest was recomputed and matched.
    disclosed: BTreeMap<String, AttributeValue>,
    /// The holder's `DeviceKey` extracted from the MSO (the input to the `DeviceAuth` binding check).
    device_key: DeviceKey,
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

    // --- Resolve the DS certificate from the x5chain and verify the IssuerAuth signature. ----------
    let ds_cert_der = ds_cert_from_x5chain(&issuer_auth)?;
    verify_issuer_auth_signature(&issuer_auth, &ds_cert_der)?;

    // --- IssuerAuth trust: the DS cert must be on the configured anchor for the role/format. --------
    let decision = anchors.resolve(params.role, crate::types::Format::Mdoc, &ds_cert_der);
    if !decision.trusted {
        return Err(VerifyFailure::reason(ReasonCode::UntrustedIssuer));
    }

    // --- MSO digestAlgorithm + validityInfo. -------------------------------------------------------
    let digest_alg_name = get_text(&mso, "digestAlgorithm").ok_or_else(VerifyFailure::malformed)?;
    let digest_alg =
        DigestAlgorithm::from_name(&digest_alg_name).ok_or_else(VerifyFailure::malformed)?;
    let validity = parse_validity_info(&mso, params.now_unix)?;
    enforce_validity(&validity, params.now_unix)?;

    // --- Revocation / status (the T014 seam): the canonical outcome maps onto the bar. -------------
    match params.status {
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
/// (the digest input ISO/IEC 18013-5 §9.2.2.5 hashes) PAIRED with the `digestID` /
/// `elementIdentifier` / `elementValue` decoded from those SAME bytes — so the value disclosed is
/// inseparable from the bytes hashed (no decoupled-lookup false-accept).
struct RawIssuerItem<'a> {
    /// The exact on-wire `IssuerSignedItemBytes` span (`#6.24(bstr)`), hashed verbatim.
    raw_bytes: &'a [u8],
    /// The `digestID` decoded from `raw_bytes` (the MSO `valueDigests` index for this item).
    digest_id: i64,
    /// The `elementIdentifier` (claim name) decoded from `raw_bytes`.
    identifier: String,
    /// The `elementValue` (claim value) decoded from `raw_bytes`.
    element_value: AttributeValue,
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

    /// Capture the exact byte slice of the next complete data item without interpreting it, advancing
    /// the cursor past it.
    fn take_item_slice(&mut self) -> Option<&'a [u8]> {
        let start = self.pos;
        self.skip_item()?;
        self.input.get(start..self.pos)
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
                // `take_text` borrowed `self.input`; re-borrow the key for the callback by slicing the
                // same range (avoids holding an immutable borrow across the &mut self call).
                let key_range = key_start..self.pos;
                let key_owned = self.input.get(key_range)?;
                // Re-decode the (already-validated) key text from the captured bytes.
                let mut key_cursor = Self {
                    input: key_owned,
                    pos: 0,
                };
                let key_text = key_cursor.take_text()?;
                debug_assert_eq!(key_text, key);
                on_entry(key_text, self)?;
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

/// Decode a [`RawIssuerItem`] record from one on-wire `#6.24(bstr .cbor IssuerSignedItem)` element's
/// exact bytes (`item_bytes`): unwrap the tag, decode the inner `IssuerSignedItem` map, and read its
/// `digestID` / `elementIdentifier` / `elementValue` — ALL from those same bytes. `raw_bytes` (the
/// hash input) and the decoded `(identifier, value)` (the disclosure) are therefore one and the same
/// item by construction. Returns `None` if the element is not a `#6.24(bstr)` wrapping a map with an
/// integer `digestID`, a text `elementIdentifier`, and an `elementValue`.
fn decode_raw_issuer_item(item_bytes: &[u8]) -> Option<RawIssuerItem<'_>> {
    let value: CborValue = ciborium::from_reader(item_bytes).ok()?;
    let inner = unwrap_tagged_cbor_payload(&value).ok()?;
    let item: CborValue = ciborium::from_reader(inner.as_slice()).ok()?;
    let digest_id = get_integer(&item, "digestID")?;
    let identifier = get_text(&item, "elementIdentifier")?;
    let element_value = cbor_to_attribute(get_map_entry(&item, "elementValue")?);
    Some(RawIssuerItem {
        raw_bytes: item_bytes,
        digest_id,
        identifier,
        element_value,
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
            // Capture this element's EXACT on-wire span, then decode its `digestID` / identifier /
            // value from that SAME span into one self-contained record (bytes↔value tied together).
            // An element the raw decode cannot parse simply produces no record, so the per-namespace
            // record count falls short of the decoded item count and `verify_value_digests` fails the
            // document closed (`DisclosureIntegrity`) — never a silent skip that drops an item.
            let item_slice = c.take_item_slice()?;
            if let Some(record) = decode_raw_issuer_item(item_slice) {
                ns_entry.push(record);
            }
        }
        Some(())
    })
}

// =================================================================================================
// CBOR map/value helpers (ciborium uses an association-list `Value::Map`; these read it by key).
// =================================================================================================

/// Look up a text-keyed entry in a CBOR map value, returning a reference to the value.
fn get_map_entry<'a>(value: &'a CborValue, key: &str) -> Option<&'a CborValue> {
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

/// Extract the first `Document` from a `DeviceResponse`'s `documents` array.
fn first_document(root: &CborValue) -> Result<&CborValue, VerifyFailure> {
    let documents = get_map_entry(root, "documents")
        .and_then(CborValue::as_array)
        .ok_or_else(VerifyFailure::malformed)?;
    documents.first().ok_or_else(VerifyFailure::malformed)
}

/// Unwrap a CBOR `#6.24(bstr)` ("encoded CBOR data item") to its inner byte string. The inner bytes
/// are the exact serialization that was hashed/signed, so they must be used verbatim.
fn unwrap_tagged_cbor_payload(value: &CborValue) -> Result<Vec<u8>, VerifyFailure> {
    match value {
        CborValue::Tag(TAG_ENCODED_CBOR, inner) => match inner.as_ref() {
            CborValue::Bytes(b) => Ok(b.clone()),
            _ => Err(VerifyFailure::malformed()),
        },
        _ => Err(VerifyFailure::malformed()),
    }
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
fn parse_cose_sign1(value: &CborValue) -> Result<CoseSign1, VerifyFailure> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).map_err(|_| VerifyFailure::malformed())?;
    // `from_slice` accepts the untagged array; if the value is the tagged form, strip the tag first.
    if let CborValue::Tag(_, inner) = value {
        let mut inner_buf = Vec::new();
        ciborium::into_writer(inner.as_ref(), &mut inner_buf)
            .map_err(|_| VerifyFailure::malformed())?;
        return CoseSign1::from_slice(&inner_buf).map_err(|_| VerifyFailure::malformed());
    }
    CoseSign1::from_slice(&buf).map_err(|_| VerifyFailure::malformed())
}

/// Extract the Document Signer signing certificate (DER) a presented mdoc claims in its `IssuerAuth`
/// `x5chain`, without verifying anything (the opt-in [`crate::qualified`] gate matches this leaf
/// against the national Trusted List's `EAA/Q` service entries).
///
/// Returns `None` when the `DeviceResponse` does not parse or carries no `x5chain` leaf. The value is
/// *claimed* (its trust + signature are decided by the always-on bar in [`verify`]); this read is
/// only the gate's cert-matching input, never an acceptance.
#[must_use]
pub fn issuer_signing_cert_der(device_response: &[u8]) -> Option<Vec<u8>> {
    let root: CborValue = ciborium::from_reader(device_response).ok()?;
    let document = first_document(&root).ok()?;
    issuer_signing_cert_of_document(document)
}

/// Extract the claimed Document Signer leaf certificate (DER) from a single `Document`'s `IssuerAuth`
/// `x5chain` (read-only, no verification — the shared body of [`issuer_signing_cert_der`] and
/// [`issuer_signing_certs_der`]). Returns `None` when the document carries no resolvable leaf.
fn issuer_signing_cert_of_document(document: &CborValue) -> Option<Vec<u8>> {
    let issuer_signed = get_map_entry(document, "issuerSigned")?;
    let issuer_auth_value = get_map_entry(issuer_signed, "issuerAuth")?;
    let issuer_auth = parse_cose_sign1(issuer_auth_value).ok()?;
    ds_cert_from_x5chain(&issuer_auth).ok()
}

/// Extract the claimed issuance/relevant time (Unix seconds) of a single `Document` from its MSO
/// `validityInfo`: `signed` (the instant the issuer asserts it signed the MSO — ISO/IEC 18013-5
/// §9.1.2.4, the credential's issuance time), falling back to `validFrom` when `signed` is absent
/// (the start of the validity window, `validFrom >= signed`). Read-only, no verification.
///
/// Returns `None` when the document carries no parseable MSO or neither `signed` nor `validFrom` can
/// be read — the opt-in [`crate::qualified`] gate then fails closed for this document rather than
/// reading the issuer's status at "now" (contracts/qualified-status-gate.md: status is read at the
/// credential's issuance/relevant time, NOT "now").
fn issuance_time_of_document(document: &CborValue) -> Option<i64> {
    let issuer_signed = get_map_entry(document, "issuerSigned")?;
    let issuer_auth_value = get_map_entry(issuer_signed, "issuerAuth")?;
    let issuer_auth = parse_cose_sign1(issuer_auth_value).ok()?;
    let mso_bytes = issuer_auth.payload.as_ref()?;
    let mso_inner = unwrap_bstr_tagged_payload(mso_bytes).ok()?;
    let mso: CborValue = ciborium::from_reader(mso_inner.as_slice()).ok()?;
    let info = get_map_entry(&mso, "validityInfo")?;
    // `signed` is the issuance instant; `validFrom` is the fallback relevant time. `tdate_field`
    // returns the RFC 3339 instant as Unix seconds; map its `Result` to `Option` (a read, not a gate).
    tdate_field(info, "signed")
        .ok()
        .or_else(|| tdate_field(info, "validFrom").ok())
}

/// Extract the claimed Document Signer leaf certificate (DER) of **every** document in a
/// `DeviceResponse`, in document order — the per-document input the opt-in [`crate::qualified`] gate
/// needs so a multi-document response is decided over ALL its issuers, not just `documents[0]`.
///
/// The always-on bar verifies + merges attributes from every document (possibly different issuers), so
/// a qualified-status determination that read only `documents[0]` could report `Qualified` over a
/// result that also carries a non-qualified second document's attributes. This returns one entry per
/// document (`None` for a document whose leaf cannot be read), so the gate can fold a status across
/// all of them and never report a single `Qualified` that under-covers.
///
/// Returns `None` when the `DeviceResponse` does not parse or carries no `documents` array. Like
/// [`issuer_signing_cert_der`], the certs are *claimed* (trust + signature are decided by the
/// always-on bar in [`verify`]); this read is only the gate's cert-matching input, never an acceptance.
#[must_use]
pub fn issuer_signing_certs_der(device_response: &[u8]) -> Option<Vec<Option<Vec<u8>>>> {
    let root: CborValue = ciborium::from_reader(device_response).ok()?;
    let documents = get_map_entry(&root, "documents").and_then(CborValue::as_array)?;
    Some(
        documents
            .iter()
            .map(issuer_signing_cert_of_document)
            .collect(),
    )
}

/// One document's *claimed* qualified-gate input: its Document Signer leaf certificate (DER) and its
/// issuance/relevant time (Unix seconds), each `None` when that field cannot be read. The values are
/// claimed (read-only, unverified); trust + signature are decided by the always-on bar.
pub type ClaimedIssuer = (Option<Vec<u8>>, Option<i64>);

/// Extract, per document in a `DeviceResponse`, the claimed Document Signer leaf certificate (DER)
/// **paired with** that document's claimed issuance/relevant time (Unix seconds) — the input the
/// opt-in [`crate::qualified`] gate folds across every document so the determination uses EACH
/// issuer's own issuance time (the credential's relevant time, NOT "now").
///
/// Each [`ClaimedIssuer`] entry is `(claimed_cert, claimed_issuance_time)`: the leaf from the
/// document's `IssuerAuth` `x5chain` and the MSO `validityInfo.signed` (fallback `validFrom`). Either
/// element is `None` when that field cannot be read; a per-document `None` issuance time fails the
/// gate closed for that document ([`crate::types::QualifiedStatus::Indeterminate`]) rather than
/// substituting "now".
///
/// Returns `None` when the `DeviceResponse` does not parse or carries no `documents` array. Like
/// [`issuer_signing_cert_der`], the certs/times are *claimed* (trust + signature are decided by the
/// always-on bar in [`verify`]); this read is only the gate's input, never an acceptance.
#[must_use]
pub fn issuer_signing_certs_with_issuance_der(
    device_response: &[u8],
) -> Option<Vec<ClaimedIssuer>> {
    let root: CborValue = ciborium::from_reader(device_response).ok()?;
    let documents = get_map_entry(&root, "documents").and_then(CborValue::as_array)?;
    Some(
        documents
            .iter()
            .map(|doc| {
                (
                    issuer_signing_cert_of_document(doc),
                    issuance_time_of_document(doc),
                )
            })
            .collect(),
    )
}

/// Resolve the Document Signer certificate (DER) from a COSE_Sign1's `x5chain` header. The leaf is
/// the first certificate (RFC 9360); a single-cert chain may be carried as a bare `bstr` rather than
/// an array of `bstr`.
fn ds_cert_from_x5chain(sign1: &CoseSign1) -> Result<Vec<u8>, VerifyFailure> {
    let label = Label::Int(COSE_HEADER_X5CHAIN);
    let value = sign1
        .unprotected
        .rest
        .iter()
        .find_map(|(l, v)| (*l == label).then_some(v))
        .ok_or_else(VerifyFailure::malformed)?;
    match value {
        Value::Bytes(b) => Ok(b.clone()),
        Value::Array(certs) => match certs.first() {
            Some(Value::Bytes(b)) => Ok(b.clone()),
            _ => Err(VerifyFailure::malformed()),
        },
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
    use p256::ecdsa::signature::Verifier as _;
    use x509_cert::spki::DecodePublicKey as _;

    // The protected header MUST name ES256 (the EUDI baseline). Anything else is rejected on the
    // algorithm alone, before any signature math.
    if !cose_alg_is_es256(sign1) {
        return Err(VerifyFailure::reason(ReasonCode::Tamper));
    }

    let cert = Certificate::from_der(cert_der).map_err(|_| VerifyFailure::malformed())?;
    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| VerifyFailure::malformed())?;
    let verifying_key = p256::ecdsa::VerifyingKey::from_public_key_der(&spki_der)
        .map_err(|_| VerifyFailure::reason(ReasonCode::Tamper))?;

    let outcome = sign1.verify_signature(&[], |sig, tbs| {
        let signature = p256::ecdsa::Signature::from_slice(sig)
            .map_err(|_| ())
            .or_else(|()| p256::ecdsa::Signature::from_der(sig).map_err(|_| ()))?;
        verifying_key.verify(tbs, &signature).map_err(|_| ())
    });
    outcome.map_err(|()| VerifyFailure::reason(ReasonCode::Tamper))
}

/// Verify the `IssuerAuth` signature over the MSO with the DS certificate's key.
fn verify_issuer_auth_signature(
    issuer_auth: &CoseSign1,
    ds_cert_der: &[u8],
) -> Result<(), VerifyFailure> {
    verify_cose_sign1_es256(issuer_auth, ds_cert_der)
}

// =================================================================================================
// MSO validityInfo.
// =================================================================================================

/// Parse the MSO `validityInfo` into the SDK's [`Validity`] (Unix seconds). `signed`/`validFrom`/
/// `validUntil` are RFC 3339 `tdate` strings (often CBOR `#6.0`-tagged); a missing/unparseable bound
/// is malformed.
///
/// `signed` is the instant the issuer asserts it signed the MSO (ISO/IEC 18013-5 §9.1.2.4). It is
/// inside the IssuerAuth-signed MSO, so it is not itself a forgery vector, but it is enforced for
/// internal consistency: a `signed` after `validFrom` is contradictory (the credential claims it was
/// valid from before it was signed), and a `signed` in the future (after `now`) is impossible for a
/// genuinely issued credential — either is a tamper/malformed MSO and is rejected, not ignored.
fn parse_validity_info(mso: &CborValue, now_unix: i64) -> Result<Validity, VerifyFailure> {
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
    Ok(Validity {
        not_before: Some(valid_from),
        not_after: Some(valid_until),
    })
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
/// returning the disclosed attributes only for items whose digest matches.
///
/// The disclosure works from the [`scan_raw_issuer_items`] **records** (`raw_items`): each record
/// carries the item's exact `IssuerSignedItemBytes` span (`#6.24(bstr .cbor IssuerSignedItem)`)
/// PAIRED with the `digestID` / `elementIdentifier` / `elementValue` decoded from THOSE SAME bytes.
/// For each record the digest is computed over its OWN `raw_bytes` — the bytes as received (ISO/IEC
/// 18013-5 §9.2.2.5: "the input for the digest function is the binary data of the IssuerSignedItem"),
/// never a re-encode — and matched against `valueDigests[ns][digestID]`; ONLY on a match is that
/// record's OWN identifier/value disclosed. Because the hashed bytes and the disclosed value are one
/// inseparable record, a forged item cannot hash a genuine item's bytes while disclosing an
/// attacker-chosen claim (SC-002 — the selective-disclosure-integrity false-accept).
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
) -> Result<BTreeMap<String, AttributeValue>, VerifyFailure> {
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

    let mut disclosed = BTreeMap::new();
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

            // The disclosed map is keyed by `elementIdentifier` alone (the format's flat claim view),
            // but a credential MAY carry the same identifier in more than one namespace. Merging
            // last-writer-wins would let one namespace silently SHADOW another's value, so insert
            // without overwriting a conflicting value — a clash is a structurally untrustworthy
            // disclosure set (a consumer cannot know which value is authoritative).
            insert_no_shadow(
                &mut disclosed,
                record.identifier.clone(),
                record.element_value.clone(),
            )?;
        }
    }
    Ok(disclosed)
}

/// Insert a disclosed attribute into `map` without ever silently shadowing an existing entry.
///
/// The disclosed map is keyed by `elementIdentifier` alone (the flat claim view consumers read). If
/// the same identifier is disclosed more than once — across namespaces within a document, or across
/// documents in a multi-credential response — a *conflicting* value MUST NOT silently overwrite an
/// earlier one (a consumer reading `given_name` could otherwise be served a second, attacker-chosen
/// document's value). An identical re-disclosure is harmless (no shadowing of a different value) and
/// is accepted; a conflicting one is rejected as a structurally untrustworthy disclosure set.
fn insert_no_shadow(
    map: &mut BTreeMap<String, AttributeValue>,
    identifier: String,
    value: AttributeValue,
) -> Result<(), VerifyFailure> {
    match map.get(&identifier) {
        // A genuine collision with a DIFFERENT value: one disclosure would shadow the other — reject.
        Some(existing) if *existing != value => {
            Err(VerifyFailure::reason(ReasonCode::DisclosureIntegrity))
        }
        // Same identifier, same value (or first sighting): no shadowing risk.
        Some(_) => Ok(()),
        None => {
            map.insert(identifier, value);
            Ok(())
        }
    }
}

/// Re-encode a byte string as a CBOR `#6.24(bstr)` tagged item — the `DeviceNameSpacesBytes` wire form
/// the `DeviceAuthentication` payload embeds (see [`reencode_tagged`] / [`build_device_authentication`]).
///
/// This is used only for the holder-binding payload (which the verifier rebuilds and re-signs over);
/// the `valueDigests` integrity check hashes the ORIGINAL on-wire `IssuerSignedItemBytes` instead
/// (ISO/IEC 18013-5 §9.2.2.5), so it never re-encodes — see [`verify_value_digests`].
fn encode_tagged_cbor(inner: &[u8]) -> Result<Vec<u8>, VerifyFailure> {
    let tagged = CborValue::Tag(TAG_ENCODED_CBOR, Box::new(CborValue::Bytes(inner.to_vec())));
    let mut buf = Vec::new();
    ciborium::into_writer(&tagged, &mut buf).map_err(|_| VerifyFailure::malformed())?;
    Ok(buf)
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
    // Re-encode the COSE_Key value and parse it via `coset` for label handling.
    let mut buf = Vec::new();
    ciborium::into_writer(device_key_value, &mut buf).map_err(|_| VerifyFailure::malformed())?;
    let cose_key = CoseKey::from_slice(&buf).map_err(|_| VerifyFailure::malformed())?;

    // Require an EC2 (kty=2) P-256 (crv=1) key; read X (-2) and Y (-3) coordinates.
    let kty_ok = matches!(
        cose_key.kty,
        coset::RegisteredLabel::Assigned(coset::iana::KeyType::EC2)
    );
    if !kty_ok {
        // Defensive: also accept a raw kty=2 carried in `params` if `coset` did not assign it.
        if find_key_label(device_key_value, COSE_KEY_KTY, integer_label) != Some(COSE_KTY_EC2) {
            return Err(VerifyFailure::malformed());
        }
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
    let device_signature = parse_cose_sign1(device_signature_value)?;

    // `deviceSigned.nameSpaces` is a `#6.24(bstr .cbor DeviceNameSpaces)`; carry its exact bytes.
    let device_name_spaces_value =
        get_map_entry(device_signed, "nameSpaces").ok_or_else(VerifyFailure::malformed)?;
    let device_name_spaces_bytes = reencode_tagged(device_name_spaces_value)?;

    let session_transcript = build_session_transcript_value(params.session_transcript)?;
    let device_auth_payload =
        build_device_authentication(&session_transcript, doc_type, &device_name_spaces_bytes)?;

    verify_cose_sign1_detached_es256(&device_signature, &device_auth_payload, &device_key.sec1)
        .map_err(|()| VerifyFailure::reason(ReasonCode::HolderBinding))
}

/// Re-encode a `#6.24(bstr)` CBOR value to its canonical bytes (the `DeviceNameSpacesBytes` form).
fn reencode_tagged(value: &CborValue) -> Result<Vec<u8>, VerifyFailure> {
    let inner = unwrap_tagged_cbor_payload(value)?;
    encode_tagged_cbor(&inner)
}

/// Decode the supplied `SessionTranscript` bytes to a CBOR value, defaulting to a 3-element null
/// transcript `[null, null, null]` (DeviceEngagementBytes, EReaderKeyBytes, Handover) when none is
/// supplied — the value a transport-less presentation and the test issuer agree on.
fn build_session_transcript_value(
    session_transcript: Option<&[u8]>,
) -> Result<CborValue, VerifyFailure> {
    session_transcript.map_or_else(
        || {
            Ok(CborValue::Array(vec![
                CborValue::Null,
                CborValue::Null,
                CborValue::Null,
            ]))
        },
        |bytes| ciborium::from_reader(bytes).map_err(|_| VerifyFailure::malformed()),
    )
}

/// Build the `DeviceAuthentication` detached payload bytes: the `#6.24(bstr .cbor [...])` wrapping of
/// `["DeviceAuthentication", SessionTranscript, docType, DeviceNameSpacesBytes]`.
fn build_device_authentication(
    session_transcript: &CborValue,
    doc_type: &str,
    device_name_spaces_bytes: &[u8],
) -> Result<Vec<u8>, VerifyFailure> {
    // DeviceNameSpacesBytes is itself a #6.24(bstr) item; embed it as the already-encoded CBOR value.
    let device_ns_value: CborValue =
        ciborium::from_reader(device_name_spaces_bytes).map_err(|_| VerifyFailure::malformed())?;
    let device_auth = CborValue::Array(vec![
        CborValue::Text("DeviceAuthentication".to_owned()),
        session_transcript.clone(),
        CborValue::Text(doc_type.to_owned()),
        device_ns_value,
    ]);
    let mut inner = Vec::new();
    ciborium::into_writer(&device_auth, &mut inner).map_err(|_| VerifyFailure::malformed())?;
    encode_tagged_cbor(&inner)
}

/// Verify a COSE_Sign1 ES256 signature over a **detached** payload against a SEC1 P-256 public key.
fn verify_cose_sign1_detached_es256(
    sign1: &CoseSign1,
    payload: &[u8],
    public_key_sec1: &[u8],
) -> Result<(), ()> {
    use p256::ecdsa::signature::Verifier as _;

    // Gate on the algorithm BEFORE any signature math (the same single predicate the IssuerAuth path
    // uses): a non-ES256 DeviceSignature is rejected on its header alone.
    if !cose_alg_is_es256(sign1) {
        return Err(());
    }
    let verifying_key =
        p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key_sec1).map_err(|_| ())?;
    sign1.verify_detached_signature(payload, &[], |sig, tbs| {
        let signature = p256::ecdsa::Signature::from_slice(sig)
            .map_err(|_| ())
            .or_else(|()| p256::ecdsa::Signature::from_der(sig).map_err(|_| ()))?;
        verifying_key.verify(tbs, &signature).map_err(|_| ())
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
        cbor_to_attribute, cose_alg_is_es256, ds_cert_from_x5chain, find_key_label,
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

    #[test]
    fn insert_no_shadow_inserts_accepts_idempotent_rejects_conflict() {
        let mut map = BTreeMap::new();
        // First sighting inserts.
        assert!(insert_no_shadow(
            &mut map,
            "given_name".to_owned(),
            AttributeValue::Text("Ada".to_owned())
        )
        .is_ok());
        assert_eq!(
            map.get("given_name"),
            Some(&AttributeValue::Text("Ada".to_owned()))
        );
        // Identical re-disclosure is accepted (no shadowing of a different value) and does not change
        // the stored value.
        assert!(insert_no_shadow(
            &mut map,
            "given_name".to_owned(),
            AttributeValue::Text("Ada".to_owned())
        )
        .is_ok());
        assert_eq!(
            map.get("given_name"),
            Some(&AttributeValue::Text("Ada".to_owned()))
        );
        // A conflicting value is rejected (DisclosureIntegrity) and the original is preserved.
        let err = insert_no_shadow(
            &mut map,
            "given_name".to_owned(),
            AttributeValue::Text("EVIL".to_owned()),
        )
        .unwrap_err();
        assert_eq!(err.reason, crate::types::ReasonCode::DisclosureIntegrity);
        assert_eq!(
            map.get("given_name"),
            Some(&AttributeValue::Text("Ada".to_owned())),
            "a rejected conflict never overwrites the existing value"
        );
        // A distinct identifier still inserts cleanly.
        assert!(insert_no_shadow(
            &mut map,
            "nationality".to_owned(),
            AttributeValue::Text("NL".to_owned())
        )
        .is_ok());
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
    fn ds_cert_from_x5chain_rejects_malformed_chains() {
        // An array whose first element is not a bstr is malformed.
        let bad_array = sign1_with_x5chain(CborValue::Array(vec![CborValue::Integer(1.into())]));
        assert!(ds_cert_from_x5chain(&bad_array).is_err());
        // A scalar that is neither bstr nor array is malformed.
        let scalar = sign1_with_x5chain(CborValue::Integer(1.into()));
        assert!(ds_cert_from_x5chain(&scalar).is_err());
        // A bare-bstr chain resolves to the leaf bytes.
        let good = sign1_with_x5chain(CborValue::Bytes(vec![9, 9]));
        assert_eq!(ds_cert_from_x5chain(&good).unwrap(), vec![9, 9]);
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
        use super::{verify, MdocVerifyParams};
        use crate::trust::StaticTestAnchors;
        // 400 nested arrays (deeper than ciborium's 256 recursion limit) wrapped so the bytes parse as
        // far as the nesting bound, then bottom out — the verifier must reject, not abort.
        let mut deep = vec![0x81u8; 400];
        deep.push(0x00); // a terminal 0 so the innermost array has its one element
        let result = verify(
            &deep,
            &StaticTestAnchors::new(),
            &MdocVerifyParams::default(),
        );
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
        // and value were decoded from the SAME bytes the digest is computed over.
        assert_eq!(record.identifier, "x");
        assert_eq!(record.element_value, AttributeValue::Integer(1));
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
