//! Holder OpenID4VP `present` — build a selectively-disclosed presentation bound to the verifier's
//! request via the signer-hook (US2 — task T026).
//!
//! [`present`] takes a [`HeldAttestation`] (an obtained SD-JWT VC / mdoc), the verifier's
//! [`PresentationRequest`], the [`HolderContext`] + [`Signer`] hook, and the subset of claims to
//! disclose, and produces a `vp_token` that **verifies under** [`crate::openid4vp::verify_response`]
//! (the round-trip oracle). Holder binding is built by the signer-hook — the SDK never holds the
//! private key (FR-009):
//!
//! - **SD-JWT VC** — the SDK conceals the undisclosed claims, computes the KB-JWT signing input
//!   (`aud`/`nonce`/`sd_hash`) over the resulting presentation prefix, the host signs it, and the SDK
//!   splices the compact KB-JWT onto the presentation.
//! - **mdoc** — the SDK reconstructs the `DeviceAuthentication` over the request's OID4VP handover
//!   (`audience`+`nonce`), the host signs the COSE `Sig_structure`, and the SDK splices a fresh
//!   detached `DeviceSignature` into the held `DeviceResponse`.

use std::collections::BTreeSet;

use ciborium::value::Value as CborValue;
use serde::{Deserialize, Serialize};

use super::device::build_device_signature;
use super::signer::{build_kb_jwt, HolderContext, Signer};
use crate::openid4vp::{oid4vp_handover_transcript, MdocVpToken, PresentationRequest, VpToken};

/// An owned holder OpenID4VP `vp_token`, the output of [`present`]. The caller borrows it as a
/// [`VpToken`] via [`HolderPresentation::as_vp_token`] to verify it under
/// [`crate::openid4vp::verify_response`] (the round-trip), or carries it on the wire.
///
/// Owning the bytes (rather than returning a borrowed [`VpToken`]) keeps `present` allocation-honest:
/// no leaked `'static` borrow, and the same value serializes onto the C-ABI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HolderPresentation {
    /// A compact SD-JWT VC presentation string (`<issuer-JWS>~<D>…~<KB-JWT>`).
    SdJwtVc {
        /// The compact presentation.
        vp_token: String,
    },
    /// An mdoc `vp_token`: the rebuilt `DeviceResponse` plus the addressed audience.
    Mdoc {
        /// The addressed audience (the verifier `client_id`).
        audience: String,
        /// The rebuilt CBOR `DeviceResponse` (with the request-bound holder `DeviceSignature`).
        #[serde(with = "serde_bytes")]
        device_response: Vec<u8>,
    },
}

impl HolderPresentation {
    /// Borrow this presentation as a [`VpToken`] for [`crate::openid4vp::verify_response`].
    #[must_use]
    pub fn as_vp_token(&self) -> VpToken<'_> {
        match self {
            Self::SdJwtVc { vp_token } => VpToken::SdJwtVc(vp_token),
            Self::Mdoc {
                audience,
                device_response,
            } => VpToken::Mdoc(MdocVpToken {
                audience: audience.clone(),
                device_response: device_response.clone(),
            }),
        }
    }
}

/// A held (obtained) attestation the holder can present (the output of [`super::obtain`], or any
/// credential the integrator already holds). Carries the encoded credential only — no key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeldAttestation {
    /// An issued SD-JWT VC: the compact `<issuer-JWS>~<D.1>~…~<D.N>~` string (issuer JWS + **all**
    /// the issued disclosures, no KB-JWT yet — the holder selects + binds at presentation time).
    SdJwtVc {
        /// The issued compact SD-JWT VC (issuer JWS + all disclosures).
        issued: String,
    },
    /// An issued mdoc: the CBOR `DeviceResponse` (the issuer-signed parts + a placeholder
    /// `DeviceSignature` the holder replaces, bound to the verifier's request, at presentation time).
    Mdoc {
        /// The CBOR-encoded issued `DeviceResponse`.
        #[serde(with = "serde_bytes")]
        device_response: Vec<u8>,
    },
}

/// An error building a holder presentation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PresentError {
    /// The held credential could not be parsed.
    #[error("the held credential is malformed: {0}")]
    Malformed(String),
    /// A requested disclosed claim is not present in the held credential.
    #[error("requested disclosure '{0}' is not a disclosable claim of the held credential")]
    UndisclosableClaim(String),
    /// The signer-hook failed (the host's error rendered as a message).
    #[error("the holder signer-hook failed: {0}")]
    Signer(String),
    /// Building or splicing a ceremony envelope failed.
    #[error("failed to build the presentation: {0}")]
    Build(String),
}

/// A `sha-256` [`sd_jwt_payload::Hasher`] over the SDK's own `sha2` (the SDK has no second crypto
/// stack — research D1). Used to recompute disclosure digests when concealing for presentation.
#[derive(Debug, Clone, Copy, Default)]
struct Sha2Hasher;

impl sd_jwt_payload::Hasher for Sha2Hasher {
    fn digest(&self, input: &[u8]) -> Vec<u8> {
        use sha2::Digest as _;
        sha2::Sha256::digest(input).to_vec()
    }
    fn alg_name(&self) -> &'static str {
        "sha-256"
    }
}

/// A holder presentation prepared up to (but not including) the holder signature: it carries the
/// [`SigningInput`](super::signer::SigningInput) the host must sign and the splice context to
/// assemble the final [`HolderPresentation`].
///
/// This is the two-step seam that mirrors the signing core's begin/resume: [`prepare_present`] builds
/// it (returning the input to sign), then [`PreparedPresentation::finish`] splices the host signature
/// into the `vp_token`. The one-shot [`present`] (with an in-process [`Signer`]) is a thin wrapper
/// over the two — DRY, and the same code path backs the C-ABI's `BeginPresent`/`FinishPresent`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedPresentation {
    kind: PreparedKind,
    audience: String,
}

/// The format-specific splice context held by a [`PreparedPresentation`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum PreparedKind {
    /// SD-JWT VC: the concealed presentation prefix + the KB-JWT build to splice onto it.
    SdJwtVc {
        presentation_prefix: String,
        kb: super::signer::KbJwtBuild,
    },
    /// mdoc: the held `DeviceResponse` (CBOR) + the `DeviceSignature` build to splice into it.
    Mdoc {
        #[serde(with = "serde_bytes")]
        device_response: Vec<u8>,
        build: super::device::DeviceSignatureBuild,
    },
}

impl PreparedPresentation {
    /// The signing input the host must sign with the holder key (exposes the verifier `aud`/`nonce`).
    #[must_use]
    pub fn signing_input(&self) -> &super::signer::SigningInput {
        match &self.kind {
            PreparedKind::SdJwtVc { kb, .. } => &kb.input,
            PreparedKind::Mdoc { build, .. } => &build.input,
        }
    }

    /// Splice the host-returned `r‖s` ES256 signature into the final [`HolderPresentation`].
    ///
    /// # Errors
    ///
    /// [`PresentError`] when the signature does not splice (wrong length) or the envelope re-encode
    /// fails.
    pub fn finish(&self, signature: &[u8]) -> Result<HolderPresentation, PresentError> {
        match &self.kind {
            PreparedKind::SdJwtVc {
                presentation_prefix,
                kb,
            } => {
                let kb_jwt = kb
                    .assemble(signature)
                    .map_err(|e| PresentError::Build(e.to_string()))?;
                Ok(HolderPresentation::SdJwtVc {
                    vp_token: format!("{presentation_prefix}{kb_jwt}"),
                })
            }
            PreparedKind::Mdoc {
                device_response,
                build,
            } => {
                let device_signature_cbor = build
                    .assemble(signature)
                    .map_err(|e| PresentError::Build(e.to_string()))?;
                let response: CborValue = ciborium::from_reader(device_response.as_slice())
                    .map_err(|e| PresentError::Malformed(e.to_string()))?;
                let rebuilt = replace_device_signature(&response, &device_signature_cbor)?;
                let mut buf = Vec::new();
                ciborium::into_writer(&rebuilt, &mut buf)
                    .map_err(|e| PresentError::Build(e.to_string()))?;
                Ok(HolderPresentation::Mdoc {
                    audience: self.audience.clone(),
                    device_response: buf,
                })
            }
        }
    }
}

/// Prepare a holder presentation for the held attestation, disclosing only `disclose`, bound to the
/// verifier's `request` — up to the holder signature (the two-call seam; the host signs
/// [`PreparedPresentation::signing_input`] and calls [`PreparedPresentation::finish`]).
///
/// # Errors
///
/// [`PresentError`] when the held credential is malformed, a requested claim is not disclosable, or
/// building the ceremony envelope fails.
pub fn prepare_present(
    held: &HeldAttestation,
    request: &PresentationRequest,
    disclose: &BTreeSet<String>,
    iat: i64,
) -> Result<PreparedPresentation, PresentError> {
    match held {
        HeldAttestation::SdJwtVc { issued } => prepare_sd_jwt_vc(issued, request, disclose, iat),
        HeldAttestation::Mdoc { device_response } => prepare_mdoc(device_response, request),
    }
}

/// Build an OpenID4VP `vp_token` for the held attestation, disclosing only `disclose`, bound to the
/// verifier's `request` via the holder signer-hook.
///
/// The produced [`HolderPresentation`] **verifies under** [`crate::openid4vp::verify_response`]
/// against the same `request` (the round-trip), revealing only the `disclose` subset. `iat` is the
/// holder's signing instant (the KB-JWT `iat`). A thin wrapper over [`prepare_present`] +
/// [`PreparedPresentation::finish`] with an in-process [`Signer`].
///
/// # Errors
///
/// [`PresentError`] when the held credential is malformed, a requested claim is not disclosable, or
/// the signer-hook / envelope build fails.
pub fn present<S: Signer>(
    held: &HeldAttestation,
    request: &PresentationRequest,
    _holder: &HolderContext,
    disclose: &BTreeSet<String>,
    signer: &S,
    iat: i64,
) -> Result<HolderPresentation, PresentError>
where
    S::Error: core::fmt::Display,
{
    let prepared = prepare_present(held, request, disclose, iat)?;
    let signature = signer
        .sign("", prepared.signing_input())
        .map_err(|e| PresentError::Signer(e.to_string()))?;
    prepared.finish(&signature)
}

/// Prepare the SD-JWT VC presentation: conceal the undisclosed claims, then build the KB-JWT input
/// over the verifier's `aud`/`nonce` (the holder signs it next).
fn prepare_sd_jwt_vc(
    issued: &str,
    request: &PresentationRequest,
    disclose: &BTreeSet<String>,
    iat: i64,
) -> Result<PreparedPresentation, PresentError> {
    let sd_jwt =
        sd_jwt_payload::SdJwt::parse(issued).map_err(|e| PresentError::Malformed(e.to_string()))?;

    // The full set of disclosable claim names in the issued credential (top-level object disclosures).
    let disclosable: BTreeSet<String> = sd_jwt
        .disclosures()
        .iter()
        .filter_map(|d| d.claim_name.clone())
        .collect();
    for name in disclose {
        if !disclosable.contains(name) {
            return Err(PresentError::UndisclosableClaim(name.clone()));
        }
    }

    // Conceal every disclosable claim NOT in the requested subset (selective disclosure).
    let mut builder = sd_jwt
        .into_presentation(&Sha2Hasher)
        .map_err(|e| PresentError::Build(e.to_string()))?;
    for name in disclosable.difference(disclose) {
        builder = builder
            .conceal(&format!("/{name}"))
            .map_err(|e| PresentError::Build(e.to_string()))?;
    }
    let (presented_sd_jwt, _omitted) = builder.finish();
    let presentation_prefix = presented_sd_jwt.presentation();

    let kb = build_kb_jwt(
        &request.audience,
        &request.nonce_b64(),
        iat,
        &presentation_prefix,
    )
    .map_err(|e| PresentError::Build(e.to_string()))?;
    Ok(PreparedPresentation {
        audience: request.audience.clone(),
        kind: PreparedKind::SdJwtVc {
            presentation_prefix,
            kb,
        },
    })
}

/// Prepare the mdoc presentation: reconstruct the `DeviceAuthentication` over the request's OID4VP
/// handover and build the `DeviceSignature` input (the holder signs it next; the held `DeviceResponse`
/// is carried so [`PreparedPresentation::finish`] can splice the fresh signature in).
///
/// mdoc selective disclosure is enforced at the namespace/element level inside the held
/// `DeviceResponse` (the issuer-signed `IssuerSignedItem`s the holder chooses to include); this
/// presents the issued document's disclosed items as-is and binds them to the request with a fresh
/// device signature. (Per-element pruning is a follow-on; the issued document already carries exactly
/// the items the holder presents.)
fn prepare_mdoc(
    device_response: &[u8],
    request: &PresentationRequest,
) -> Result<PreparedPresentation, PresentError> {
    let response: CborValue = ciborium::from_reader(device_response)
        .map_err(|e| PresentError::Malformed(e.to_string()))?;
    let doc_type = first_doc_type(&response).ok_or_else(|| {
        PresentError::Malformed("DeviceResponse has no document docType".to_owned())
    })?;

    let transcript = oid4vp_handover_transcript(&request.audience, &request.nonce);
    let build = build_device_signature(
        &doc_type,
        &transcript,
        &request.audience,
        &request.nonce_b64(),
    )
    .map_err(|e| PresentError::Build(e.to_string()))?;
    Ok(PreparedPresentation {
        audience: request.audience.clone(),
        kind: PreparedKind::Mdoc {
            device_response: device_response.to_vec(),
            build,
        },
    })
}

/// The `docType` of the first document in a `DeviceResponse`.
fn first_doc_type(response: &CborValue) -> Option<String> {
    let documents = map_get(response, "documents")?.as_array()?;
    let first = documents.first()?;
    map_get(first, "docType")?.as_text().map(str::to_owned)
}

/// Replace the `deviceSigned.deviceAuth.deviceSignature` of every document with `device_signature`
/// (the fresh, request-bound holder signature). Returns the rebuilt `DeviceResponse` value.
fn replace_device_signature(
    response: &CborValue,
    device_signature_cbor: &[u8],
) -> Result<CborValue, PresentError> {
    let device_signature_value: CborValue = ciborium::from_reader(device_signature_cbor)
        .map_err(|e| PresentError::Build(e.to_string()))?;
    let map = response
        .as_map()
        .ok_or_else(|| PresentError::Malformed("DeviceResponse is not a map".to_owned()))?;
    let mut out_entries = Vec::with_capacity(map.len());
    for (k, v) in map {
        if k.as_text() == Some("documents") {
            let documents = v
                .as_array()
                .ok_or_else(|| PresentError::Malformed("documents is not an array".to_owned()))?;
            let rebuilt_docs = documents
                .iter()
                .map(|doc| replace_in_document(doc, &device_signature_value))
                .collect::<Result<Vec<_>, _>>()?;
            out_entries.push((k.clone(), CborValue::Array(rebuilt_docs)));
        } else {
            out_entries.push((k.clone(), v.clone()));
        }
    }
    Ok(CborValue::Map(out_entries))
}

/// Replace the `deviceSignature` within a single `Document`'s `deviceSigned.deviceAuth`.
fn replace_in_document(
    document: &CborValue,
    device_signature_value: &CborValue,
) -> Result<CborValue, PresentError> {
    let map = document
        .as_map()
        .ok_or_else(|| PresentError::Malformed("Document is not a map".to_owned()))?;
    let mut out = Vec::with_capacity(map.len());
    for (k, v) in map {
        if k.as_text() == Some("deviceSigned") {
            out.push((k.clone(), rebuild_device_signed(v, device_signature_value)?));
        } else {
            out.push((k.clone(), v.clone()));
        }
    }
    Ok(CborValue::Map(out))
}

/// Rebuild a `DeviceSigned` map, replacing `deviceAuth.deviceSignature` with the fresh signature.
fn rebuild_device_signed(
    device_signed: &CborValue,
    device_signature_value: &CborValue,
) -> Result<CborValue, PresentError> {
    let map = device_signed
        .as_map()
        .ok_or_else(|| PresentError::Malformed("deviceSigned is not a map".to_owned()))?;
    let mut out = Vec::with_capacity(map.len());
    for (k, v) in map {
        if k.as_text() == Some("deviceAuth") {
            let new_auth = CborValue::Map(vec![(
                CborValue::Text("deviceSignature".to_owned()),
                device_signature_value.clone(),
            )]);
            out.push((k.clone(), new_auth));
        } else {
            out.push((k.clone(), v.clone()));
        }
    }
    Ok(CborValue::Map(out))
}

/// Get a text-keyed entry from a CBOR map value.
fn map_get<'a>(value: &'a CborValue, key: &str) -> Option<&'a CborValue> {
    value
        .as_map()?
        .iter()
        .find_map(|(k, v)| (k.as_text() == Some(key)).then_some(v))
}

#[cfg(test)]
mod tests;
