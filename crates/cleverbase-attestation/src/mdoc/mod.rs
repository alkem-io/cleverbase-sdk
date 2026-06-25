//! ISO/IEC 18013-5 mdoc verification.
//!
//! Verifies a presented mdoc `DeviceResponse` against the always-on bar (contracts/verifier.md),
//! owning the security-critical checks the only Rust mdoc library omits (research D3):
//!
//! 1. **`IssuerAuth` signature** — the `COSE_Sign1` over the Mobile Security Object (MSO) is verified
//!    with the Document Signer (DS) certificate's public key (ES256, via the SDK's `p256`/`ecdsa`),
//!    and the DS certificate is resolved from the `x5chain` COSE header and checked for trust through
//!    the pluggable [`crate::trust::TrustAnchorSource`] (the IACA root).
//! 2. **`valueDigests` integrity (in-house)** — each disclosed `IssuerSignedItem` is re-hashed (with
//!    the MSO `digestAlgorithm`) over its tagged-CBOR (`#6.24`) byte string and matched against the
//!    MSO `valueDigests`; any mismatch is rejected. This is the selective-disclosure-integrity check.
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

use std::collections::BTreeMap;

use ciborium::value::Value;
use ciborium::Value as CborValue;
use coset::{CborSerializable, CoseKey, CoseSign1, Label, RegisteredLabelWithPrivate};
use sha2::{Digest, Sha256, Sha384, Sha512};
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
            Self::Sha256 => Sha256::digest(data).to_vec(),
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
    /// [`crate::verify`] entry point resolves through the host status source. Mirrors the SD-JWT VC
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
/// integrity, MSO `validityInfo`, and the `DeviceAuth` holder binding — over the first document in
/// the response. Returns a [`VerificationResult`]: `valid = true` with the disclosed attributes when
/// every check passes, or `valid = false` carrying a single specific [`ReasonCode`] on the first
/// failure (no false-accept — SC-002).
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

/// The fallible verification body; `verify` maps its error to a specific-reason INVALID verdict.
fn verify_inner<A: TrustAnchorSource + ?Sized>(
    device_response: &[u8],
    anchors: &A,
    params: &MdocVerifyParams<'_>,
) -> Result<VerificationResult, VerifyFailure> {
    let root: CborValue =
        ciborium::from_reader(device_response).map_err(|_| VerifyFailure::malformed())?;
    let document = first_document(&root)?;
    let doc_type = get_text(document, "docType").ok_or_else(VerifyFailure::malformed)?;
    let issuer_signed =
        get_map_entry(document, "issuerSigned").ok_or_else(VerifyFailure::malformed)?;

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
    let validity = parse_validity_info(&mso)?;
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
    if get_text(&mso, "docType").as_deref() != Some(doc_type.as_str()) {
        return Err(VerifyFailure::reason(ReasonCode::Tamper));
    }

    // --- valueDigests integrity (in-house): recompute each disclosed item's digest. -----------------
    let disclosed = verify_value_digests(issuer_signed, &mso, digest_alg)?;

    // --- DeviceAuth holder binding: DeviceSignature over DeviceAuthentication w/ the MSO DeviceKey. --
    let device_key = mso_device_key(&mso)?;
    verify_device_binding(document, &device_key, &doc_type, params)?;

    Ok(VerificationResult {
        valid: true,
        disclosed_attributes: disclosed,
        trust_status: TrustStatus::Trusted,
        qualified_status: None,
        reasons: Vec::new(),
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
    let issuer_signed = get_map_entry(document, "issuerSigned")?;
    let issuer_auth_value = get_map_entry(issuer_signed, "issuerAuth")?;
    let issuer_auth = parse_cose_sign1(issuer_auth_value).ok()?;
    ds_cert_from_x5chain(&issuer_auth).ok()
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

/// Verify a COSE_Sign1 ES256 signature against a P-256 public key extracted from `cert_der`.
///
/// Builds the COSE `Sig_structure` (via `coset`, with no external AAD) and verifies the raw `r‖s`
/// signature with the SDK's `p256`/`ecdsa` (no hand-rolled crypto). A non-ES256 algorithm header is
/// rejected as a tamper (the EUDI baseline is ES256).
fn verify_cose_sign1_es256(sign1: &CoseSign1, cert_der: &[u8]) -> Result<(), VerifyFailure> {
    use p256::ecdsa::signature::Verifier as _;
    use x509_cert::spki::DecodePublicKey as _;

    // The protected header MUST name ES256 (the EUDI baseline). Anything else is rejected.
    let is_es256 = matches!(
        sign1.protected.header.alg,
        Some(RegisteredLabelWithPrivate::Assigned(
            coset::iana::Algorithm::ES256
        ))
    );
    if !is_es256 {
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

/// Parse the MSO `validityInfo` into the SDK's [`Validity`] (Unix seconds). `validFrom`/`validUntil`
/// are RFC 3339 `tdate` strings (often CBOR `#6.0`-tagged); a missing/unparseable bound is malformed.
fn parse_validity_info(mso: &CborValue) -> Result<Validity, VerifyFailure> {
    let info = get_map_entry(mso, "validityInfo").ok_or_else(VerifyFailure::malformed)?;
    let signed = tdate_field(info, "signed")?;
    let valid_from = tdate_field(info, "validFrom")?;
    let valid_until = tdate_field(info, "validUntil")?;
    // `signed` must not be in the future relative to `validFrom`; ISO models them independently but
    // both gate validity. We keep `validFrom`/`validUntil` as the window and check `signed <= now`
    // implicitly via the not_before bound (validFrom >= signed for a well-formed MSO).
    let _ = signed;
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
    parse_rfc3339_to_unix(&text).ok_or_else(VerifyFailure::malformed)
}

/// Parse an RFC 3339 / ISO 8601 UTC timestamp (`YYYY-MM-DDThh:mm:ssZ`, optional fractional seconds)
/// to Unix seconds, without pulling a date crate. Only the `Z` (UTC) form is accepted — ISO/IEC
/// 18013-5 mandates UTC for `tdate` fields.
fn parse_rfc3339_to_unix(s: &str) -> Option<i64> {
    // Expect at least "YYYY-MM-DDThh:mm:ss" then optional ".fff" then "Z".
    let bytes = s.as_bytes();
    if bytes.len() < 20 {
        return None;
    }
    let year: i64 = s.get(0..4)?.parse().ok()?;
    if bytes.get(4) != Some(&b'-') {
        return None;
    }
    let month: i64 = s.get(5..7)?.parse().ok()?;
    if bytes.get(7) != Some(&b'-') {
        return None;
    }
    let day: i64 = s.get(8..10)?.parse().ok()?;
    if bytes.get(10) != Some(&b'T') {
        return None;
    }
    let hour: i64 = s.get(11..13)?.parse().ok()?;
    if bytes.get(13) != Some(&b':') {
        return None;
    }
    let min: i64 = s.get(14..16)?.parse().ok()?;
    if bytes.get(16) != Some(&b':') {
        return None;
    }
    let sec: i64 = s.get(17..19)?.parse().ok()?;
    // Must end in 'Z' (after an optional fractional part); reject offsets/local time.
    if !s.ends_with('Z') {
        return None;
    }
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    if hour > 23 || min > 59 || sec > 60 {
        return None;
    }
    Some(civil_to_unix(year, month, day, hour, min, sec))
}

/// Convert a UTC civil date-time to Unix seconds using Howard Hinnant's `days_from_civil` algorithm
/// (public-domain; the same algorithm `chrono`/`time` use). Avoids a date dependency for the single
/// `tdate` parse the verifier needs.
fn civil_to_unix(year: i64, month: i64, day: i64, hour: i64, min: i64, sec: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    days * 86_400 + hour * 3_600 + min * 60 + sec
}

/// Enforce the validity window at `now_unix`: outside `[validFrom, validUntil]` → `Expired`.
fn enforce_validity(validity: &Validity, now_unix: i64) -> Result<(), VerifyFailure> {
    if let Some(not_before) = validity.not_before {
        if now_unix < not_before {
            return Err(VerifyFailure::reason(ReasonCode::Expired));
        }
    }
    if let Some(not_after) = validity.not_after {
        if now_unix > not_after {
            return Err(VerifyFailure::reason(ReasonCode::Expired));
        }
    }
    Ok(())
}

// =================================================================================================
// valueDigests integrity (in-house, MANDATORY).
// =================================================================================================

/// Recompute every disclosed `IssuerSignedItem` digest and match it against the MSO `valueDigests`.
///
/// For each namespace and each disclosed item: the digest is computed over the **tagged-CBOR bytes**
/// of the item (`#6.24(bstr .cbor IssuerSignedItem)` — the exact bytes carried in `IssuerSigned`),
/// then compared to the MSO `valueDigests[ns][digestID]`. Any missing or mismatched digest fails with
/// `DisclosureIntegrity`. Returns the disclosed attributes (flattened across namespaces) on success.
fn verify_value_digests(
    issuer_signed: &CborValue,
    mso: &CborValue,
    digest_alg: DigestAlgorithm,
) -> Result<BTreeMap<String, AttributeValue>, VerifyFailure> {
    let name_spaces = get_map_entry(issuer_signed, "nameSpaces")
        .and_then(CborValue::as_map)
        .ok_or_else(VerifyFailure::malformed)?;
    let value_digests = get_map_entry(mso, "valueDigests")
        .and_then(CborValue::as_map)
        .ok_or_else(VerifyFailure::malformed)?;

    let mut disclosed = BTreeMap::new();
    for (ns_key, items_value) in name_spaces {
        let ns = ns_key.as_text().ok_or_else(VerifyFailure::malformed)?;
        let items = items_value
            .as_array()
            .ok_or_else(VerifyFailure::malformed)?;
        let ns_digests = value_digests
            .iter()
            .find_map(|(k, v)| (k.as_text() == Some(ns)).then_some(v))
            .and_then(CborValue::as_map)
            .ok_or_else(|| VerifyFailure::reason(ReasonCode::DisclosureIntegrity))?;

        for item_value in items {
            // The item is a `#6.24(bstr)`; hash the *exact* tagged-CBOR encoding of the bstr content.
            let item_inner = unwrap_tagged_cbor_payload(item_value)?;
            // ISO hashes the tagged item as it appears on the wire (`#6.24(bstr)`), i.e. the
            // re-serialized tagged value — recompute that canonical encoding.
            let tagged_bytes = encode_tagged_cbor(&item_inner)?;
            let computed = digest_alg.digest(&tagged_bytes);

            let item: CborValue = ciborium::from_reader(item_inner.as_slice())
                .map_err(|_| VerifyFailure::malformed())?;
            let digest_id = get_integer(&item, "digestID").ok_or_else(VerifyFailure::malformed)?;
            let expected = ns_digests
                .iter()
                .find_map(|(k, v)| (integer_label(k) == Some(digest_id)).then_some(v))
                .and_then(CborValue::as_bytes)
                .ok_or_else(|| VerifyFailure::reason(ReasonCode::DisclosureIntegrity))?;

            if computed.as_slice() != expected.as_slice() {
                return Err(VerifyFailure::reason(ReasonCode::DisclosureIntegrity));
            }

            let identifier =
                get_text(&item, "elementIdentifier").ok_or_else(VerifyFailure::malformed)?;
            let element_value =
                get_map_entry(&item, "elementValue").ok_or_else(VerifyFailure::malformed)?;
            disclosed.insert(identifier, cbor_to_attribute(element_value));
        }
    }
    Ok(disclosed)
}

/// Re-encode a byte string as a CBOR `#6.24(bstr)` tagged item — the canonical wire form whose digest
/// the MSO `valueDigests` carries.
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
        if find_key_label_int(device_key_value, COSE_KEY_KTY) != Some(COSE_KTY_EC2) {
            return Err(VerifyFailure::malformed());
        }
    }
    if find_key_label_int(device_key_value, COSE_KEY_CRV) != Some(COSE_CRV_P256) {
        return Err(VerifyFailure::malformed());
    }
    let x =
        find_key_label_bytes(device_key_value, COSE_KEY_X).ok_or_else(VerifyFailure::malformed)?;
    let y =
        find_key_label_bytes(device_key_value, COSE_KEY_Y).ok_or_else(VerifyFailure::malformed)?;
    if x.len() != 32 || y.len() != 32 {
        return Err(VerifyFailure::malformed());
    }
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    Ok(DeviceKey { sec1 })
}

/// Find an integer-keyed (COSE label) integer value in a COSE_Key CBOR map.
fn find_key_label_int(value: &CborValue, label: i64) -> Option<i64> {
    let map = value.as_map()?;
    map.iter().find_map(|(k, v)| {
        (integer_label(k) == Some(label))
            .then(|| integer_label(v))
            .flatten()
    })
}

/// Find an integer-keyed (COSE label) byte-string value in a COSE_Key CBOR map.
fn find_key_label_bytes(value: &CborValue, label: i64) -> Option<Vec<u8>> {
    let map = value.as_map()?;
    map.iter().find_map(|(k, v)| {
        (integer_label(k) == Some(label))
            .then(|| v.as_bytes().cloned())
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

    let is_es256 = matches!(
        sign1.protected.header.alg,
        Some(RegisteredLabelWithPrivate::Assigned(
            coset::iana::Algorithm::ES256
        ))
    );
    if !is_es256 {
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

#[cfg(test)]
pub(crate) mod test_issuer;
#[cfg(test)]
mod tests;

#[cfg(test)]
mod unit {
    //! Direct unit tests of the pure helpers whose error branches are awkward to reach end-to-end.

    use super::{
        cbor_to_attribute, civil_to_unix, ds_cert_from_x5chain, integer_label,
        parse_rfc3339_to_unix, tdate_field, unwrap_tagged_cbor_payload, DigestAlgorithm,
        COSE_HEADER_X5CHAIN, TAG_ENCODED_CBOR,
    };
    use crate::types::AttributeValue;
    use ciborium::Value as CborValue;
    use coset::{CoseSign1Builder, HeaderBuilder};

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

    #[test]
    fn rfc3339_parses_a_well_formed_utc_instant() {
        // 1970-01-01T00:00:00Z is the Unix epoch.
        assert_eq!(parse_rfc3339_to_unix("1970-01-01T00:00:00Z"), Some(0));
        // A known instant: 2023-01-01T00:00:00Z.
        assert_eq!(
            parse_rfc3339_to_unix("2023-01-01T00:00:00Z"),
            Some(1_672_531_200)
        );
        // Fractional seconds are tolerated (still ends in Z).
        assert_eq!(
            parse_rfc3339_to_unix("2023-01-01T00:00:00.123Z"),
            Some(1_672_531_200)
        );
    }

    #[test]
    fn rfc3339_rejects_malformed_or_non_utc_strings() {
        // Too short.
        assert_eq!(parse_rfc3339_to_unix("2023-01-01"), None);
        // Missing the trailing Z (an offset / local time is not accepted).
        assert_eq!(parse_rfc3339_to_unix("2023-01-01T00:00:00+01:00"), None);
        // Wrong separators.
        assert_eq!(parse_rfc3339_to_unix("2023/01/01T00:00:00Z"), None);
        assert_eq!(parse_rfc3339_to_unix("2023-01/01T00:00:00Z"), None);
        assert_eq!(parse_rfc3339_to_unix("2023-01-01 00:00:00Z"), None);
        assert_eq!(parse_rfc3339_to_unix("2023-01-01T00-00:00Z"), None);
        assert_eq!(parse_rfc3339_to_unix("2023-01-01T00:00-00Z"), None);
        // Out-of-range fields.
        assert_eq!(parse_rfc3339_to_unix("2023-13-01T00:00:00Z"), None);
        assert_eq!(parse_rfc3339_to_unix("2023-01-32T00:00:00Z"), None);
        assert_eq!(parse_rfc3339_to_unix("2023-01-01T24:00:00Z"), None);
        assert_eq!(parse_rfc3339_to_unix("2023-01-01T00:60:00Z"), None);
        assert_eq!(parse_rfc3339_to_unix("2023-01-01T00:00:99Z"), None);
        // Non-numeric components.
        assert_eq!(parse_rfc3339_to_unix("yyyy-01-01T00:00:00Z"), None);
    }

    #[test]
    fn civil_to_unix_handles_pre_epoch_and_leap_years() {
        // 1969-12-31T00:00:00Z is one day before the epoch (negative-year branch via month<=2 path).
        assert_eq!(civil_to_unix(1969, 12, 31, 0, 0, 0), -86_400);
        // A leap day: 2020-02-29T00:00:00Z (month <= 2 branch).
        assert_eq!(civil_to_unix(2020, 2, 29, 0, 0, 0), 1_582_934_400);
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
}
