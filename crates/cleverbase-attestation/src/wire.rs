//! Versioned CBOR wire envelope for the attestation C-ABI (and WASM) boundary.
//!
//! Mirrors `cleverbase-core::wire`: the C-ABI and non-native bindings exchange these CBOR-encoded
//! envelopes; native bindings can call the typed Rust API ([`verify()`](crate::verify())) directly. The envelope
//! carries an [`ATTESTATION_SCHEMA_VERSION`] so a binding can refuse a payload it cannot read
//! (Principle VII).
//!
//! Protocol logic lives **here, in the core** — the `cleverbase-ffi` C-ABI only wraps
//! [`process_verify_bytes`] in the pointer/length/free dance (Principle III: no protocol logic in
//! bindings). The `verify` operation is the always-on bar (contracts/verifier.md); this envelope
//! carries everything the sans-IO [`verify()`](crate::verify()) entry point needs: the presented credential, the
//! verifier policy, the configured **trust anchors** (resolved by the host-driven trust step and
//! passed in as `(role, format, cert)` entries — data-model.md `TrustAnchorSource`), the verification
//! **context** (instant, role, resolved revocation/status outcome, mdoc transcript, qualified-gate
//! seam), and the optional OpenID4VP **request** the presentation must be bound to.
//!
//! ## Schema version 3
//!
//! Version 2 replaced the version-1 foundation seam (which carried only `presentation` + `policy` and
//! returned `NotImplemented`) with the full always-on verifier wiring. Version 3 (this) additively
//! carries the opt-in qualified-status gate's national Trusted List
//! ([`WireContext::qualified_trust_list`]) alongside the existing `qualified_gate` flag (T020), so
//! the C-ABI gate has data. The CBOR shape changed (an additive field), so the schema version was
//! bumped (Principle VII); a binding speaking an older version is refused with a clear message rather
//! than mis-parsed.

use serde::{Deserialize, Serialize};

use crate::openid4vp::PresentationRequest;
use crate::status::StatusOutcome;
use crate::trust::StaticTestAnchors;
use crate::types::{Format, IssuerRole, VerificationPolicy, VerificationResult};
use crate::verify::{verify, Presentation, VerifyContext};

/// Wire schema version of the attestation envelope. Bumped on a breaking CBOR-shape change within a
/// SemVer major (independent of the signing core's `SCHEMA_VERSION`). Version 2 carries the full
/// verifier inputs (the always-on bar + OpenID4VP binding); version 1 was the foundation seam.
pub const ATTESTATION_SCHEMA_VERSION: u32 = 3;

/// A single configured trust anchor passed across the wire: a trusted issuer/anchor certificate for
/// a `(role, format)` (the host resolved these from the EU LOTL / national TLs / IACA roots in its
/// trust-refresh step and passes them in — the core stays sans-IO).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireTrustAnchor {
    /// The issuer role this anchor covers.
    pub role: IssuerRole,
    /// The credential format this anchor covers.
    pub format: Format,
    /// The DER-encoded trusted issuer/anchor certificate.
    #[serde(with = "serde_bytes")]
    pub cert_der: Vec<u8>,
}

/// The presented credential as carried on the wire (the CBOR mirror of [`Presentation`]).
///
/// SD-JWT VC is the compact presentation string; mdoc is the `DeviceResponse` bytes plus the
/// OpenID4VP addressed audience (present only when verifying against a request).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WirePresentation {
    /// A compact SD-JWT VC presentation string.
    SdJwtVc {
        /// The compact `<issuer-JWS>~<D>…~<KB-JWT>` presentation.
        presentation: String,
    },
    /// An mdoc `DeviceResponse` plus its OpenID4VP addressed audience (when bound to a request).
    Mdoc {
        /// The CBOR-encoded `DeviceResponse`.
        #[serde(with = "serde_bytes")]
        device_response: Vec<u8>,
        /// The audience the response was addressed to (the verifier `client_id`), when applicable.
        #[serde(default)]
        audience: Option<String>,
    },
}

/// The verification context carried on the wire (the CBOR mirror of [`VerifyContext`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireContext {
    /// The verification instant (Unix seconds).
    pub now_unix: i64,
    /// The issuer role under which trust is anchored.
    pub role: IssuerRole,
    /// The host-resolved revocation/status outcome.
    pub status: StatusOutcome,
    /// The mdoc `SessionTranscript` for a non-OpenID4VP presentation (else `None`).
    #[serde(default, with = "serde_bytes")]
    pub session_transcript: Option<Vec<u8>>,
    /// The off-by-default opt-in qualified-status gate flag (T019/T020). When `true`, the gate runs
    /// over [`Self::qualified_trust_list`] and populates `VerificationResult.qualified_status`; when
    /// `false` (the default) the always-on verdict is byte-identical and `qualified_status` is absent
    /// (SC-007).
    #[serde(default)]
    pub qualified_gate: bool,
    /// The raw national Trusted List JSON the opt-in gate reads (the offline
    /// `qualified-trust-list.json` form / a host-supplied national TL), carried additively on the
    /// wire so the C-ABI gate has data. `None` (the default) with the gate enabled yields an honest
    /// `Indeterminate` (unreachable data — never a false "qualified").
    #[serde(default, with = "serde_bytes")]
    pub qualified_trust_list: Option<Vec<u8>>,
}

/// A `verify` request: the presented credential, the policy, the configured anchors, the
/// verification context, and (optionally) the OpenID4VP request the presentation must be bound to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyRequest {
    /// Wire schema version of this envelope.
    pub schema_version: u32,
    /// The presented credential.
    pub presentation: WirePresentation,
    /// The verifier policy.
    pub policy: VerificationPolicy,
    /// The configured trust anchors (resolved + passed in by the host's trust-refresh step).
    pub anchors: Vec<WireTrustAnchor>,
    /// The verification context (instant, role, status, transcript, gate seam).
    pub context: WireContext,
    /// The OpenID4VP request the presentation must be bound to, when present.
    #[serde(default)]
    pub request: Option<PresentationRequest>,
}

/// The outcome of a `verify` operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyOutcome {
    /// The verdict (the always-on bar — contracts/verifier.md).
    Ok {
        /// The verification result.
        result: VerificationResult,
    },
    /// A decode/usage error rendered as a message (e.g. an unsupported schema version).
    Err {
        /// Human-readable error message.
        message: String,
    },
}

/// A versioned `verify` response envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyResponse {
    /// Wire schema version of this envelope.
    pub schema_version: u32,
    /// The operation outcome.
    pub outcome: VerifyOutcome,
}

/// Decode a `verify` request envelope, rejecting unknown schema versions.
///
/// # Errors
///
/// Returns the decode error (or a schema-version mismatch message) as a `String`.
pub fn decode_verify_request(bytes: &[u8]) -> Result<VerifyRequest, String> {
    let req: VerifyRequest = ciborium::from_reader(bytes).map_err(|e| e.to_string())?;
    if req.schema_version != ATTESTATION_SCHEMA_VERSION {
        return Err(format!(
            "unsupported attestation schema_version {} (this core speaks {ATTESTATION_SCHEMA_VERSION})",
            req.schema_version
        ));
    }
    Ok(req)
}

/// Encode a `verify` response envelope at the current schema version.
#[must_use]
pub fn encode_verify_response(outcome: VerifyOutcome) -> Vec<u8> {
    let resp = VerifyResponse {
        schema_version: ATTESTATION_SCHEMA_VERSION,
        outcome,
    };
    let mut buf = Vec::new();
    // Infallible: writing CBOR into an in-memory Vec cannot fail, and VerifyResponse is a plain serde
    // type. There is no error channel on this helper, so an impossible failure should surface.
    #[allow(clippy::expect_used)] // infallible: CBOR into a Vec writer
    {
        ciborium::into_writer(&resp, &mut buf)
            .expect("CBOR serialization of VerifyResponse is infallible");
    }
    buf
}

/// Build a [`StaticTestAnchors`] trust source from the wire anchor entries (the host's resolved,
/// passed-in anchor set — the core never fetches a trust list itself).
fn anchors_from_wire(entries: &[WireTrustAnchor]) -> StaticTestAnchors {
    let mut anchors = StaticTestAnchors::new();
    for e in entries {
        anchors = anchors.trust(e.role, e.format, &e.cert_der);
    }
    anchors
}

/// Decode → verify → encode. Pure; shared by the C-ABI, language bindings, and tests (single source
/// of truth — Principle III). A well-formed request runs the always-on [`verify`] entry point and
/// returns the [`VerificationResult`]; a malformed one yields [`VerifyOutcome::Err`].
#[must_use]
pub fn process_verify_bytes(input: &[u8]) -> Vec<u8> {
    let outcome = match decode_verify_request(input) {
        Ok(req) => {
            let anchors = anchors_from_wire(&req.anchors);
            // Parse the optional national Trusted List the opt-in gate reads. A malformed list (or
            // none) is treated as absent data → the gate yields `Indeterminate` (fail-closed, never a
            // false "qualified"); it never fails the always-on verdict.
            let qualified_trust_list = req
                .context
                .qualified_trust_list
                .as_deref()
                .and_then(|bytes| crate::qualified::QualifiedTrustList::parse(bytes).ok());
            let ctx = VerifyContext {
                now_unix: req.context.now_unix,
                role: req.context.role,
                status: req.context.status,
                session_transcript: req.context.session_transcript.as_deref(),
                qualified_gate: req.context.qualified_gate,
                qualified_trust_list: qualified_trust_list.as_ref(),
            };
            let presentation = match &req.presentation {
                WirePresentation::SdJwtVc { presentation } => Presentation::SdJwtVc(presentation),
                WirePresentation::Mdoc {
                    device_response,
                    audience,
                } => Presentation::Mdoc {
                    device_response,
                    audience: audience.as_deref(),
                },
            };
            let result = verify(
                &presentation,
                &req.policy,
                &anchors,
                &ctx,
                req.request.as_ref(),
            );
            VerifyOutcome::Ok { result }
        }
        Err(message) => VerifyOutcome::Err { message },
    };
    encode_verify_response(outcome)
}

#[cfg(test)]
mod tests;
