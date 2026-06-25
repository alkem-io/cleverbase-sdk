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

use super::device::{build_device_signature, empty_device_name_spaces_bytes};
use super::signer::{build_kb_jwt, HolderContext, Signer};
use crate::mdoc::get_map_entry;
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
    /// The held mdoc `DeviceResponse` carries more than one `Document`. The holder `present` seam
    /// signs ONE `DeviceSignature` (one [`PreparedPresentation::signing_input`], one host signature),
    /// so it can bind exactly one document; a multi-document held credential is rejected rather than
    /// producing a token whose extra documents carry a signature over the FIRST document's data (which
    /// the verifier — checking each document against its OWN docType + `deviceSigned.nameSpaces` —
    /// would reject). A holder presents individual credentials; multi-document binding is a separate,
    /// multi-signature seam (a documented follow-on), never a silently-invalid token.
    #[error(
        "the held mdoc carries {0} documents; the holder present seam binds a single document \
         (present each credential separately)"
    )]
    MultiDocumentMdoc(usize),
}

/// A `sha-256` [`sd_jwt_payload::Hasher`] over the SDK's own `sha2` (the SDK has no second crypto
/// stack — research D1). Used to recompute disclosure digests when concealing for presentation.
#[derive(Debug, Clone, Copy, Default)]
struct Sha2Hasher;

impl sd_jwt_payload::Hasher for Sha2Hasher {
    fn digest(&self, input: &[u8]) -> Vec<u8> {
        // Route through the crate's single authoritative SHA-256 (DRY — `crate::crypto` is the one
        // digest helper), adapting its fixed `[u8; 32]` to the `Vec<u8>` the `Hasher` trait returns.
        crate::crypto::sha256(input).to_vec()
    }
    fn alg_name(&self) -> &'static str {
        crate::crypto::SHA_256
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
                    // The addressed audience is the verifier `aud` the prepared signing input already
                    // carries (the `DeviceSignature` ceremony binds it) — derive it there rather than
                    // duplicate it as a struct field (DRY).
                    audience: build.input.audience().to_owned(),
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
    holder: &HolderContext,
    disclose: &BTreeSet<String>,
    signer: &S,
    iat: i64,
) -> Result<HolderPresentation, PresentError>
where
    S::Error: core::fmt::Display,
{
    let prepared = prepare_present(held, request, disclose, iat)?;
    // Pass the holder's key handle so the signer selects the correct holder key in its HSM/KMS — the
    // handle is the host's opaque selector ([`HolderContext::key_handle`], threaded verbatim to
    // [`Signer::sign`]). Signing with an empty handle would let an in-process wrapper sign with the
    // wrong/default key (a holder-binding fault). The two-call C-ABI seam threads the handle on the
    // host side instead (the host owns the key + calls `finish`); this one-shot wrapper owns the in-
    // process `Signer`, so it must supply the handle here.
    let signature = signer
        .sign(&holder.key_handle, prepared.signing_input())
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

    // The named (object-property) disclosable claims — those that carry a `claim_name` (RFC 9901).
    let named_disclosable: BTreeSet<String> = sd_jwt
        .disclosures()
        .iter()
        .filter_map(|d| d.claim_name.clone())
        .collect();

    // Array-element disclosures carry NO `claim_name` (RFC 9901), so the named set never covers them —
    // left untouched they would ALWAYS ride on the wire regardless of `disclose`, an over-disclosure
    // leak. Map each array-element disclosure to its JSON-pointer path + the top-level claim that
    // contains it, so it can be concealed/disclosed in step with that claim.
    let array_element_paths = array_element_disclosure_paths(&sd_jwt)?;

    // A claim is selectable if it is a named disclosure OR a (possibly always-visible) claim that
    // holds array-element disclosures — so `disclose` can reference the parent of an array.
    let disclosable: BTreeSet<&str> = named_disclosable
        .iter()
        .map(String::as_str)
        .chain(
            array_element_paths
                .iter()
                .map(|p| p.top_level_claim.as_str()),
        )
        .collect();
    for name in disclose {
        if !disclosable.contains(name.as_str()) {
            return Err(PresentError::UndisclosableClaim(name.clone()));
        }
    }

    let mut builder = sd_jwt
        .into_presentation(&Sha2Hasher)
        .map_err(|e| PresentError::Build(e.to_string()))?;

    // Conceal every named claim NOT in the requested subset (selective disclosure). Concealing a
    // claim also drops its concealable sub-values, so an explicitly-concealed parent takes its
    // array-element disclosures with it.
    for name in &named_disclosable {
        if !disclose.contains(name) {
            builder = builder
                .conceal(&format!("/{name}"))
                .map_err(|e| PresentError::Build(e.to_string()))?;
        }
    }
    // Conceal every array-element disclosure whose top-level parent claim is NOT disclosed (a narrow
    // `disclose` subset must keep array elements off the wire too — no over-disclosure). Elements
    // under a concealed parent were already removed above; concealing them again is idempotent.
    for path in &array_element_paths {
        if !disclose.contains(&path.top_level_claim) {
            builder = builder
                .conceal(&path.pointer)
                .map_err(|e| PresentError::Build(e.to_string()))?;
        }
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
        kind: PreparedKind::SdJwtVc {
            presentation_prefix,
            kb,
        },
    })
}

/// An array-element disclosure located in the issued credential: the JSON-pointer `pointer` the
/// presentation builder conceals it at, and the `top_level_claim` that contains it (so it is
/// concealed/disclosed in step with that claim).
struct ArrayElementPath {
    pointer: String,
    top_level_claim: String,
}

/// Locate every array-element disclosure in the issued SD-JWT and resolve its conceal path.
///
/// Array-element disclosures (RFC 9901) appear in the issuer-signed claims as `{ "...": "<digest>" }`
/// redaction entries inside an array; the matching disclosure has no `claim_name`. We walk the claims
/// structure, and for each redaction whose digest matches a presented array-element disclosure we
/// record its JSON-pointer (`/<claim>/…/<index>`) and its top-level claim.
fn array_element_disclosure_paths(
    sd_jwt: &sd_jwt_payload::SdJwt,
) -> Result<Vec<ArrayElementPath>, PresentError> {
    use sd_jwt_payload::Hasher as _;

    // The base64url digest of every array-element disclosure (those without a claim name).
    let hasher = Sha2Hasher;
    let array_element_digests: BTreeSet<String> = sd_jwt
        .disclosures()
        .iter()
        .filter(|d| d.claim_name.is_none())
        .map(|d| hasher.encoded_digest(d.as_str()))
        .collect();
    if array_element_digests.is_empty() {
        return Ok(Vec::new());
    }

    let claims =
        serde_json::to_value(sd_jwt.claims()).map_err(|e| PresentError::Build(e.to_string()))?;
    let mut paths = Vec::new();
    collect_array_element_paths(&claims, "", None, &array_element_digests, &mut paths);
    Ok(paths)
}

/// Recursively walk `value`, recording the conceal path of every `{ "...": digest }` array redaction
/// whose digest is in `targets`. `pointer` is the JSON pointer to `value`; `top_level` is the first
/// path segment (the top-level claim the redaction belongs to).
fn collect_array_element_paths(
    value: &serde_json::Value,
    pointer: &str,
    top_level: Option<&str>,
    targets: &BTreeSet<String>,
    out: &mut Vec<ArrayElementPath>,
) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                // `_sd` holds object-property digests (handled by named conceal); never an array path.
                if key == "_sd" {
                    continue;
                }
                let child_pointer = format!("{pointer}/{}", escape_json_pointer(key));
                let child_top_level = top_level.or(Some(key.as_str()));
                collect_array_element_paths(child, &child_pointer, child_top_level, targets, out);
            }
        }
        serde_json::Value::Array(items) => {
            for (idx, item) in items.iter().enumerate() {
                let item_pointer = format!("{pointer}/{idx}");
                if let serde_json::Value::Object(obj) = item {
                    if let Some(serde_json::Value::String(digest)) = obj.get("...") {
                        if targets.contains(digest) {
                            if let Some(claim) = top_level {
                                out.push(ArrayElementPath {
                                    pointer: item_pointer.clone(),
                                    top_level_claim: claim.to_owned(),
                                });
                            }
                            continue;
                        }
                    }
                }
                collect_array_element_paths(item, &item_pointer, top_level, targets, out);
            }
        }
        _ => {}
    }
}

/// Escape a JSON object key for use as a single JSON-pointer reference token (RFC 6901 §3: `~` → `~0`,
/// `/` → `~1`).
fn escape_json_pointer(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
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
    // The present seam signs ONE DeviceSignature and `finish` splices it into every document; a
    // multi-document held response would therefore give documents[1..] a signature over documents[0]'s
    // docType + deviceSigned.nameSpaces, which the per-document verifier rejects. Reject up front with
    // a clear error rather than emit a silently-invalid token (no false token — multi-document binding
    // is a separate multi-signature seam).
    let document_count = get_map_entry(&response, "documents")
        .and_then(CborValue::as_array)
        .map_or(0, Vec::len);
    if document_count > 1 {
        return Err(PresentError::MultiDocumentMdoc(document_count));
    }
    let doc_type = first_doc_type(&response).ok_or_else(|| {
        PresentError::Malformed("DeviceResponse has no document docType".to_owned())
    })?;
    // The verifier rebuilds DeviceAuthentication from the document's ACTUAL deviceSigned.nameSpaces,
    // so the DeviceSignature must be computed over the SAME bytes (`finish` keeps these namespaces
    // unchanged and only replaces deviceAuth.deviceSignature). Carry the first document's exact
    // `DeviceNameSpacesBytes` (`#6.24(bstr .cbor DeviceNameSpaces)`), defaulting to the empty map when
    // the document discloses no device namespaces.
    let device_name_spaces_bytes = first_device_name_spaces_bytes(&response)?;

    let transcript =
        oid4vp_handover_transcript(&request.audience, &request.nonce, &request.response_uri);
    let build = build_device_signature(
        &doc_type,
        &transcript,
        &device_name_spaces_bytes,
        &request.audience,
        &request.nonce_b64(),
    )
    .map_err(|e| PresentError::Build(e.to_string()))?;
    Ok(PreparedPresentation {
        kind: PreparedKind::Mdoc {
            device_response: device_response.to_vec(),
            build,
        },
    })
}

/// The `docType` of the first document in a `DeviceResponse`.
fn first_doc_type(response: &CborValue) -> Option<String> {
    let documents = get_map_entry(response, "documents")?.as_array()?;
    let first = documents.first()?;
    get_map_entry(first, "docType")?
        .as_text()
        .map(str::to_owned)
}

/// The first document's `deviceSigned.nameSpaces` re-encoded to its canonical `DeviceNameSpacesBytes`
/// (`#6.24(bstr .cbor DeviceNameSpaces)`) — the exact bytes the verifier rebuilds `DeviceAuthentication`
/// from. Defaults to the empty namespace map (`#6.24(bstr .cbor {})`) when the document carries no
/// `deviceSigned.nameSpaces` (the empty-disclosure case), so a placeholder document still round-trips.
fn first_device_name_spaces_bytes(response: &CborValue) -> Result<Vec<u8>, PresentError> {
    let device_name_spaces = get_map_entry(response, "documents")
        .and_then(CborValue::as_array)
        .and_then(|docs| docs.first())
        .and_then(|doc| get_map_entry(doc, "deviceSigned"))
        .and_then(|ds| get_map_entry(ds, "nameSpaces"));
    device_name_spaces.map_or_else(
        || empty_device_name_spaces_bytes().map_err(|e| PresentError::Build(e.to_string())),
        reencode_device_name_spaces,
    )
}

/// Re-encode a `deviceSigned.nameSpaces` value (`#6.24(bstr .cbor DeviceNameSpaces)`) to its canonical
/// `DeviceNameSpacesBytes` — extracting the tagged byte string's inner CBOR and re-wrapping it in a
/// `#6.24(bstr)` tag, matching the verifier's reconstruction byte-for-byte.
///
/// The unwrap+re-wrap goes through the crate's single `#6.24(bstr)` pair
/// ([`crate::unwrap_tagged_cbor_payload`] then [`crate::encode_tagged_cbor`]) (DRY — Principle III), the
/// SAME pair the mdoc verifier's `reencode_tagged` uses: the verifier rebuilds `DeviceAuthentication`
/// from these exact bytes, so this holder half and the verifier half MUST produce byte-identical output
/// (correctness-critical). A value that is not a `#6.24(bstr)` is malformed.
fn reencode_device_name_spaces(value: &CborValue) -> Result<Vec<u8>, PresentError> {
    let inner = crate::unwrap_tagged_cbor_payload(value).ok_or_else(|| {
        PresentError::Malformed("deviceSigned.nameSpaces is not a #6.24(bstr)".to_owned())
    })?;
    Ok(crate::encode_tagged_cbor(&inner))
}

/// Replace the `deviceSigned.deviceAuth.deviceSignature` with `device_signature` (the fresh,
/// request-bound holder signature), returning the rebuilt `DeviceResponse` value.
///
/// [`prepare_mdoc`] rejects a multi-document held response (the present seam signs ONE signature), so
/// the `documents` array carries exactly one document here; the per-document map below is kept simply
/// to mirror the `DeviceResponse` shape (it would splice the single signature wherever a document
/// appears, never a same-signature-over-different-documents token, which the guard makes unreachable).
fn replace_device_signature(
    response: &CborValue,
    device_signature_cbor: &[u8],
) -> Result<CborValue, PresentError> {
    let device_signature_value: CborValue = ciborium::from_reader(device_signature_cbor)
        .map_err(|e| PresentError::Build(e.to_string()))?;
    // Walk DeviceResponse → documents[] → deviceSigned → deviceAuth, replacing each level's target key
    // via the single map-key-replace helper (DRY — Principle III; three near-identical
    // clone-or-transform walks collapse to one-line transforms).
    replace_map_entry(response, "DeviceResponse", "documents", |documents| {
        let documents = documents
            .as_array()
            .ok_or_else(|| PresentError::Malformed("documents is not an array".to_owned()))?;
        let rebuilt_docs = documents
            .iter()
            .map(|doc| {
                replace_map_entry(doc, "Document", "deviceSigned", |device_signed| {
                    replace_map_entry(device_signed, "deviceSigned", "deviceAuth", |_| {
                        Ok(CborValue::Map(vec![(
                            CborValue::Text("deviceSignature".to_owned()),
                            device_signature_value.clone(),
                        )]))
                    })
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(CborValue::Array(rebuilt_docs))
    })
}

/// Rebuild a CBOR map `value`, replacing the entry under `key` with `transform(old_value)` and leaving
/// every other entry untouched (a clone-or-transform walk). The **one** map-key-replace primitive the
/// holder-presentation splice uses at each `DeviceResponse` → `documents` → `deviceSigned` →
/// `deviceAuth` level (DRY — Principle III). `map_label` names the map in the malformed-shape error.
/// Pure CBOR re-serialization — no security logic (the signature it splices is validated elsewhere).
///
/// `transform` is applied to **every** entry whose key matches (matching the prior per-level walks,
/// which carried no single-use guard); a well-formed `DeviceResponse` carries each key exactly once.
///
/// # Errors
///
/// [`PresentError::Malformed`] if `value` is not a CBOR map; propagates any error from `transform`.
fn replace_map_entry(
    value: &CborValue,
    map_label: &str,
    key: &str,
    transform: impl Fn(&CborValue) -> Result<CborValue, PresentError>,
) -> Result<CborValue, PresentError> {
    let map = value
        .as_map()
        .ok_or_else(|| PresentError::Malformed(format!("{map_label} is not a map")))?;
    let mut out = Vec::with_capacity(map.len());
    for (k, v) in map {
        if k.as_text() == Some(key) {
            out.push((k.clone(), transform(v)?));
        } else {
            out.push((k.clone(), v.clone()));
        }
    }
    Ok(CborValue::Map(out))
}

#[cfg(test)]
mod tests;
