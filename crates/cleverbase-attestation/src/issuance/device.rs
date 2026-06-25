//! mdoc `DeviceAuth` `DeviceSignature` ceremony for the holder signer-hook (US2 — task T024).
//!
//! The mdoc holder-binding signature is a **detached** COSE_Sign1 over the ISO/IEC 18013-5 §9.1.3
//! `DeviceAuthentication` structure (`["DeviceAuthentication", SessionTranscript, docType,
//! DeviceNameSpacesBytes]`, wrapped `#6.24`). Unlike the JOSE ceremonies, the to-be-signed bytes are
//! a COSE `Sig_structure`, built here with `coset::sig_structure_data` (a pure encoder — no key), and
//! the spliced result is a reconstructed `CoseSign1` whose detached signature the verifier checks
//! with [`crate::mdoc`].
//!
//! The `aud`/`nonce` the holder binds are folded into the session-transcript handover (the same
//! [`crate::openid4vp::oid4vp_handover_transcript`] the verifier reconstructs), so the
//! [`crate::issuance::signer::SigningInput`] surfaces them for host policy inspection even though the
//! signed COSE payload carries them only as a hash.

use ciborium::value::Value as CborValue;
use coset::{
    iana, CborSerializable as _, CoseSign1Builder, HeaderBuilder, ProtectedHeader, SignatureContext,
};

use super::signer::{SignatureAlgorithm, SignerError, SigningInput};

/// The CBOR `#6.24` "encoded CBOR data item" tag (RFC 8949 §3.4.5.1) — the wrapper ISO 18013-5 puts
/// the `DeviceAuthentication` (and `DeviceNameSpaces`) payloads in, so the *exact bytes* are signed.
const TAG_ENCODED_CBOR: u64 = 24;

/// A built mdoc `DeviceSignature` input, plus the splice context (the protected header + payload) to
/// reconstruct the detached COSE_Sign1 once the host has signed the `Sig_structure`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DeviceSignatureBuild {
    /// The signing input the host must sign (exposes the verifier `aud`/`nonce`).
    pub input: SigningInput,
    /// The `#6.24(bstr .cbor DeviceAuthentication)` detached payload (kept so the verifier-side and a
    /// caller assembling the `DeviceResponse` use the identical bytes).
    #[serde(with = "serde_bytes")]
    pub device_auth_payload: Vec<u8>,
    #[serde(with = "serde_bytes")]
    protected_header_value: Vec<u8>,
}

impl DeviceSignatureBuild {
    /// Splice the host-returned `r‖s` ES256 signature into a detached `DeviceSignature` COSE_Sign1,
    /// returning its CBOR encoding (the `deviceAuth.deviceSignature` value).
    ///
    /// # Errors
    ///
    /// [`SignerError::BadSignatureLength`] if the signature is not the algorithm's expected length;
    /// [`SignerError::Serialize`] on a (here impossible) COSE re-encode failure.
    pub fn assemble(&self, signature: &[u8]) -> Result<Vec<u8>, SignerError> {
        match self.input.algorithm() {
            SignatureAlgorithm::Es256 => {
                if signature.len() != 64 {
                    return Err(SignerError::BadSignatureLength(
                        SignatureAlgorithm::Es256,
                        signature.len(),
                    ));
                }
            }
        }
        // Rebuild the protected header the Sig_structure was built over, attach the host signature,
        // and emit a DETACHED COSE_Sign1 (no payload) — exactly what the verifier reconstructs and
        // checks against the DeviceAuthentication payload.
        let protected = ProtectedHeader::from_cbor_bstr(coset::cbor::value::Value::Bytes(
            self.protected_header_value.clone(),
        ))
        .map_err(|e| SignerError::Serialize(e.to_string()))?;
        let sign1 = CoseSign1Builder::new()
            .protected(protected.header)
            .signature(signature.to_vec())
            .build();
        sign1
            .to_vec()
            .map_err(|e| SignerError::Serialize(e.to_string()))
    }
}

/// Build the mdoc `DeviceSignature` signing input over the `DeviceAuthentication` for `doc_type`,
/// bound to a session-transcript handover that folds in `audience`/`nonce`.
///
/// `session_transcript` is the CBOR `SessionTranscript` the holder signs over (for OpenID4VP, the
/// [`crate::openid4vp::oid4vp_handover_transcript`] of `audience`+`nonce`). `device_name_spaces_bytes`
/// is the **exact** `DeviceNameSpacesBytes` (`#6.24(bstr .cbor DeviceNameSpaces)`) of the
/// `deviceSigned.nameSpaces` being presented — the verifier rebuilds `DeviceAuthentication` from the
/// document's *actual* `deviceSigned.nameSpaces` ([`crate::mdoc`]), so the signature MUST cover the
/// same bytes or a device-disclosed (non-empty) namespace map would be rejected. Use
/// [`empty_device_name_spaces_bytes`] for the empty-disclosure case.
/// The host signs [`DeviceSignatureBuild::input`]; [`DeviceSignatureBuild::assemble`] splices the
/// result.
///
/// # Errors
///
/// [`SignerError::Serialize`] on a (here impossible) CBOR-encode failure of an in-memory value, or a
/// malformed `session_transcript` / `device_name_spaces_bytes` (not decodable CBOR).
pub fn build_device_signature(
    doc_type: &str,
    session_transcript: &[u8],
    device_name_spaces_bytes: &[u8],
    audience: &str,
    nonce: &str,
) -> Result<DeviceSignatureBuild, SignerError> {
    // Carry the presented DeviceNameSpacesBytes verbatim: the verifier rebuilds DeviceAuthentication
    // from the document's actual deviceSigned.nameSpaces, so the signed payload must match it exactly.
    let device_ns_value = decode(device_name_spaces_bytes)?;

    let transcript_value = decode(session_transcript)?;
    let device_auth_inner = encode(&CborValue::Array(vec![
        CborValue::Text("DeviceAuthentication".to_owned()),
        transcript_value,
        CborValue::Text(doc_type.to_owned()),
        device_ns_value,
    ]))?;
    let device_auth_payload = encode(&tagged_cbor(device_auth_inner))?;

    // The ES256 protected header is what the verifier reads the alg from; build the Sig_structure
    // (Signature1 context) over the detached DeviceAuthentication payload with no external aad.
    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES256)
        .build();
    let protected_header = ProtectedHeader {
        original_data: None,
        header: protected,
    };
    let protected_header_value = protected_header
        .clone()
        .cbor_bstr()
        .ok()
        .and_then(|v| v.into_bytes().ok())
        .ok_or_else(|| SignerError::Serialize("encode COSE protected header".to_owned()))?;

    let to_be_signed = coset::sig_structure_data(
        SignatureContext::CoseSign1,
        protected_header,
        None,
        &[],
        &device_auth_payload,
    );

    Ok(DeviceSignatureBuild {
        input: SigningInput::for_device_signature(
            to_be_signed,
            audience.to_owned(),
            nonce.to_owned(),
        ),
        device_auth_payload,
        protected_header_value,
    })
}

/// The `DeviceNameSpacesBytes` for an empty device-disclosed namespace map (`#6.24(bstr .cbor {})`)
/// — the bytes to sign over when the device discloses no extra namespaces.
///
/// # Errors
///
/// [`SignerError::Serialize`] on a (here impossible) CBOR-encode failure of an in-memory value.
pub fn empty_device_name_spaces_bytes() -> Result<Vec<u8>, SignerError> {
    let device_ns_inner = encode(&CborValue::Map(vec![]))?;
    encode(&tagged_cbor(device_ns_inner))
}

/// Wrap inner CBOR bytes in a `#6.24` tag (the encoded-CBOR-data-item form).
fn tagged_cbor(inner: Vec<u8>) -> CborValue {
    CborValue::Tag(TAG_ENCODED_CBOR, Box::new(CborValue::Bytes(inner)))
}

/// Encode a `ciborium` value to CBOR bytes, surfacing the (impossible) failure as [`SignerError`].
fn encode(value: &CborValue) -> Result<Vec<u8>, SignerError> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).map_err(|e| SignerError::Serialize(e.to_string()))?;
    Ok(buf)
}

/// Decode CBOR bytes to a `ciborium` value, surfacing a malformed input as [`SignerError`].
fn decode(bytes: &[u8]) -> Result<CborValue, SignerError> {
    ciborium::from_reader(bytes).map_err(|e| SignerError::Serialize(e.to_string()))
}

#[cfg(test)]
mod tests;
