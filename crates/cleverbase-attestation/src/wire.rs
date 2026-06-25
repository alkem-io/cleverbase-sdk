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
//! ## Trust semantics over the C-ABI
//!
//! The wire anchors are treated as **trusted anchors/roots** and the credential's signing leaf is
//! **chain-validated** against them (per role/format) via [`ChainValidatingAnchors`], reusing the
//! production [`crate::trust::chain::verify_chain`] primitive (DRY). This is the EUDI chain-to-root
//! model (contracts/verifier.md step 3): a host passing an issuing **CA / IACA root** trusts every
//! credential whose leaf chains to it, and the leaf's **validity window** is enforced at the
//! verification instant — an expired/withdrawn pinned issuer leaf is rejected
//! ([`crate::trust::chain::ChainError::LeafExpired`]), never silently accepted. The core stays
//! **sans-IO**: the host fetches/refreshes the trust list and passes the resolved anchors in; the
//! core only chain-validates against them (it does not fetch).
//!
//! ## Schema version 5
//!
//! Version 2 replaced the version-1 foundation seam (which carried only `presentation` + `policy` and
//! returned `NotImplemented`) with the full always-on verifier wiring. Version 3 additively carried
//! the opt-in qualified-status gate's national Trusted List ([`WireContext::qualified_trust_list`])
//! alongside the existing `qualified_gate` flag (T020). Version 4 additively carried the
//! gate's **scheme-operator trust anchors** ([`WireContext::qualified_scheme_anchors`]) — the X.509
//! anchor(s) the gate chain-authenticates the national TL's signer against before reading any status,
//! so a forged / unsigned / unchained / stale TL can never report `Qualified` (fail-closed, SC-007);
//! with the gate enabled but no scheme anchor the determination is `Indeterminate`. Version 5 (this)
//! adds the OpenID4VP request's first-class **`response_uri`**
//! ([`crate::openid4vp::PresentationRequest::response_uri`]) — the 4th element of the mdoc
//! `OpenID4VPHandoverInfo` (OpenID4VP 1.0 §B.2.6), previously stubbed to the `client_id`. A
//! `PresentationRequest` carried in [`VerifyRequest::request`] now requires this field, so the CBOR
//! shape changed and the schema version was bumped (Principle VII); a binding speaking an older
//! version is refused with a clear message rather than mis-parsed.

use serde::{Deserialize, Serialize};

use crate::openid4vp::PresentationRequest;
use crate::status::StatusOutcome;
use crate::trust::ChainValidatingAnchors;
use crate::types::{Format, IssuerRole, VerificationPolicy, VerificationResult};
use crate::verify::{verify, Presentation, VerifyContext};

/// Wire schema version of the attestation envelope. Bumped on a breaking CBOR-shape change within a
/// SemVer major (independent of the signing core's `SCHEMA_VERSION`). Version 2 carries the full
/// verifier inputs (the always-on bar + OpenID4VP binding); version 1 was the foundation seam.
pub const ATTESTATION_SCHEMA_VERSION: u32 = 5;

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
    /// The scheme-operator trust anchor certificate(s) (DER) the opt-in gate chain-authenticates the
    /// national TL's signer against **before** reading any status, carried additively on the wire.
    /// Empty (the default) with the gate enabled means the TL cannot be authenticated → an honest
    /// `Indeterminate` (can't authenticate ⇒ can't assert qualified — never a false "qualified").
    #[serde(default)]
    pub qualified_scheme_anchors: Vec<WireSchemeAnchor>,
}

/// One scheme-operator (national-TL-operator) trust anchor carried across the wire: the DER-encoded
/// anchor certificate the opt-in qualified gate authenticates the national Trusted List's signer
/// against. Distinct from [`WireTrustAnchor`] (which is role/format-scoped issuer trust for the
/// always-on bar); a scheme anchor is only the TL-signing root, so it carries no role/format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireSchemeAnchor {
    /// The DER-encoded scheme-operator anchor certificate.
    #[serde(with = "serde_bytes")]
    pub cert_der: Vec<u8>,
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

/// Build a [`ChainValidatingAnchors`] trust source from the wire anchor entries (the host's resolved,
/// passed-in anchor set — the core never fetches a trust list itself).
///
/// Each wire anchor is treated as a **trusted anchor/root**: at verify time the credential's signing
/// leaf is **chain-validated** against the anchors for its role/format (reusing the production
/// [`crate::trust::chain::verify_chain`] primitive — DRY), enforcing the leaf's validity window at
/// `now_unix`. This is the production C-ABI trust semantics (chain-to-root + leaf-validity), NOT the
/// exact-DER-equality test seam: a host passing an issuing CA / IACA root trusts every credential
/// whose leaf chains to it, and an expired pinned issuer leaf is rejected rather than accepted.
fn anchors_from_wire(entries: &[WireTrustAnchor], now_unix: i64) -> ChainValidatingAnchors {
    let mut anchors = ChainValidatingAnchors::new(now_unix);
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
            // Chain-validate the credential's leaf against the host-supplied anchors at the
            // verification instant (the leaf-validity window is enforced at `now_unix`).
            let anchors = anchors_from_wire(&req.anchors, req.context.now_unix);
            // Parse the optional national Trusted List the opt-in gate reads. A malformed list (or
            // none) is treated as absent data → the gate yields `Indeterminate` (fail-closed, never a
            // false "qualified"); it never fails the always-on verdict.
            let qualified_trust_list = req
                .context
                .qualified_trust_list
                .as_deref()
                .and_then(|bytes| crate::qualified::QualifiedTrustList::parse(bytes).ok());
            // The scheme-operator anchor(s) the gate authenticates the national TL against. Empty
            // (the default) with the gate enabled → the TL can't be authenticated → Indeterminate.
            let qualified_scheme_anchors: Vec<Vec<u8>> = req
                .context
                .qualified_scheme_anchors
                .iter()
                .map(|a| a.cert_der.clone())
                .collect();
            let ctx = VerifyContext {
                now_unix: req.context.now_unix,
                role: req.context.role,
                status: req.context.status,
                session_transcript: req.context.session_transcript.as_deref(),
                qualified_gate: req.context.qualified_gate,
                qualified_trust_list: qualified_trust_list.as_ref(),
                qualified_scheme_anchors: &qualified_scheme_anchors,
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
