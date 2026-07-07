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
//!
//! Version 5 ALSO carries (additively, no further bump) the host-fetched **signed** Token Status List
//! tokens ([`WireContext::status_tokens`], uri → raw token bytes) that drive the in-core Token Status
//! List authentication: when a presented credential declares a Token Status List reference and a
//! matching token is supplied, the core verifies the token's signature (against a key authorized by the
//! credential's own trust anchor) and reads the revocation bit itself, rather than trusting a
//! host-supplied outcome. The field is `#[serde(default)]` (empty), so an older v5 payload without it
//! decodes to "no signed tokens ⇒ the positional `statuses` seam alone" — a decode-compatible addition.
//! Because this crate is pre-release (0.1.0, unmerged), the addition consolidates into v5 rather than
//! minting a v6 for an unreleased shape.
//!
//! Version 5 further carries the revocation/status seam as the **plural, per-document** positional
//! `statuses` ([`WireContext::statuses`], one [`StatusOutcome`] per presented document — a
//! multi-document mdoc `DeviceResponse` checks `documents[i]` against `statuses[i]`, never a silent
//! reuse of one outcome across documents, SC-002) and hardens both wire structs with
//! `#[serde(deny_unknown_fields)]`, so a typo'd/unrecognized key is a hard decode error rather than a
//! silently-defaulted field (e.g. a misspelled `qualified_gate` can no longer leave the gate off).
//!
//! Version 5 ALSO adds a NEW, SEPARATE **set-level** OpenID4VP envelope
//! ([`WireVpTokenRequest`]/[`WireVpTokenResponse`], decoded by [`process_vp_token_bytes`]) that carries
//! the full multi-credential `vp_token` (`{credential_id: [presentations]}`) so the set-level DCQL
//! semantics ([`crate::openid4vp::verify_vp_token`] — `credential_sets` required option-sets +
//! `multiple` cardinality) AND in-core Token Status List authentication are reachable over the C-ABI
//! (previously native-Rust-only). It is a distinct entry point on the SAME schema version — the
//! single-presentation [`VerifyRequest`]/[`process_verify_bytes`] envelope is untouched — so this is an
//! additive addition, not a shape change to an existing envelope (no bump; this crate is pre-release).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::openid4vp::{
    verify_vp_token_slots, MdocVpToken, PresentationRequest, VpToken, VpTokenSlot,
    VpTokenVerification,
};
use crate::status::StatusOutcome;
use crate::trust::ChainValidatingAnchors;
use crate::types::{Format, IssuerRole, VerificationPolicy, VerificationResult};
use crate::verify::{verify, Presentation, VerifyContext};

/// Wire schema version of the attestation envelope. Bumped on a breaking CBOR-shape change within a
/// SemVer major (independent of the signing core's `SCHEMA_VERSION`). The current version (5) carries
/// the full verifier inputs — the always-on bar + the OpenID4VP binding + the opt-in qualified-status
/// gate's national Trusted List / scheme anchors + the mdoc handover `response_uri`. See the
/// `## Schema version 5` module section for the per-version history (v1 was the foundation seam).
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
///
/// `deny_unknown_fields`: a typo'd optional key (`statuses`, `status_tokens`, `session_transcript`,
/// `qualified_gate`, `qualified_trust_list`, `qualified_scheme_anchors`) is a hard decode error rather than a silent
/// default — a misspelled `qualified_gate` must not silently leave the gate off, nor a misspelled
/// `session_transcript` silently skip the mdoc binding. Same rationale as [`VerifyRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireContext {
    /// The verification instant (Unix seconds).
    pub now_unix: i64,
    /// The issuer role under which trust is anchored.
    pub role: IssuerRole,
    /// The host-resolved revocation/status outcomes, one **per presented document**, positional (SD-JWT
    /// VC uses index `0`; a multi-document mdoc `DeviceResponse` needs one per document). A document with
    /// no covering entry fails closed to [`StatusOutcome::Unavailable`] — never a silent reuse of one
    /// outcome across documents (SC-002).
    pub statuses: Vec<StatusOutcome>,
    /// The host-fetched **signed** Token Status List tokens, keyed by list URI → raw token bytes (a
    /// `statuslist+jwt` compact JWS, or an `application/statuslist+cwt` tagged `COSE_Sign1`). When a
    /// presented credential declares a Token Status List reference AND a token is supplied here for its
    /// URI, the core AUTHENTICATES that token in-core (signature against a key authorized by the
    /// credential's own trust anchor + `sub` binding + freshness + bit read) and that outcome OVERRIDES
    /// the positional [`Self::statuses`] entry. Absent (the default `#[serde(default)]` empty map) ⇒ the
    /// positional `statuses` seam alone (host pre-resolved), preserving the pre-existing behavior. The
    /// values are CBOR byte strings ([`serde_bytes::ByteBuf`]) so the raw token round-trips through
    /// ciborium without a lossy text re-encode. Carried additively within schema version 5 (this crate
    /// is pre-release / unmerged, so the field consolidates into v5 rather than forcing a bump; an older
    /// v5 payload lacking it decodes to the empty default — a decode-compatible addition).
    #[serde(default)]
    pub status_tokens: BTreeMap<String, serde_bytes::ByteBuf>,
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
///
/// `deny_unknown_fields`: an unrecognized key is a hard decode error, NOT silently ignored. This closes
/// the request-binding footgun — a **misspelled** `request` key (e.g. `"reqeust"`) would otherwise be
/// dropped to the `#[serde(default)] None` and silently downgrade to the request-LESS path (no
/// replay/audience protection) while still reporting `valid = true`. Within a schema version the field
/// set is fixed; forward compatibility is the `schema_version` bump, not unknown-field tolerance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

/// A versioned CBOR wire envelope carrying its own `schema_version`, so the shared
/// [`decode_versioned`] guard can read the version generically. Implemented by [`VerifyRequest`] and
/// the issuance [`IssuanceRequest`](crate::issuance::wire::IssuanceRequest) (DRY — Principle III: one
/// CBOR-decode + version-guard body for both envelopes).
pub(crate) trait HasSchemaVersion {
    /// The envelope's declared wire schema version.
    fn schema_version(&self) -> u32;
}

impl HasSchemaVersion for VerifyRequest {
    fn schema_version(&self) -> u32 {
        self.schema_version
    }
}

/// Decode a versioned CBOR wire envelope, rejecting an unrecognized schema version.
///
/// Shared by [`decode_verify_request`] and the issuance
/// [`decode_issuance_request`](crate::issuance::wire::decode_issuance_request) (DRY — Principle III):
/// the CBOR-decode + `schema_version` guard body is identical bar the envelope type, the expected
/// version, and the `domain` word in the mismatch message.
///
/// # Errors
///
/// Returns the CBOR decode error (or a schema-version mismatch message) as a `String`.
pub(crate) fn decode_versioned<T: serde::de::DeserializeOwned + HasSchemaVersion>(
    bytes: &[u8],
    expected: u32,
    domain: &str,
) -> Result<T, String> {
    let req: T = ciborium::from_reader(bytes).map_err(|e| e.to_string())?;
    if req.schema_version() != expected {
        return Err(format!(
            "unsupported {domain} schema_version {} (this core speaks {expected})",
            req.schema_version()
        ));
    }
    Ok(req)
}

/// Decode a `verify` request envelope, rejecting unknown schema versions.
///
/// # Errors
///
/// Returns the decode error (or a schema-version mismatch message) as a `String`.
pub fn decode_verify_request(bytes: &[u8]) -> Result<VerifyRequest, String> {
    decode_versioned(bytes, ATTESTATION_SCHEMA_VERSION, "attestation")
}

/// Encode a `verify` response envelope at the current schema version.
#[must_use]
pub fn encode_verify_response(outcome: VerifyOutcome) -> Vec<u8> {
    let resp = VerifyResponse {
        schema_version: ATTESTATION_SCHEMA_VERSION,
        outcome,
    };
    // Infallible (no error channel on this helper): the shared `cbor_to_vec` encodes a plain serde
    // value into an in-memory Vec, which cannot fail (DRY — one authoritative CBOR-into-Vec helper).
    crate::cbor_to_vec(&resp)
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

/// MOVE the wire `status_tokens` map (list URI → CBOR [`serde_bytes::ByteBuf`]) into the typed
/// `uri → Vec<u8>` map the sans-IO verify context borrows, WITHOUT cloning the (attacker-sized) raw
/// token buffers: `mem::take` empties the source map and each `ByteBuf` is `into_vec`'d in place.
///
/// One authoritative take-and-convert body shared by [`process_verify_bytes`]
/// ([`WireContext::status_tokens`]) and [`process_vp_token_bytes`] ([`WireVpTokenRequest::status_tokens`])
/// — DRY (Principle III), replacing the copy-pasted `mem::take + into_iter + into_vec + collect` block.
fn take_status_tokens(
    map: &mut BTreeMap<String, serde_bytes::ByteBuf>,
) -> BTreeMap<String, Vec<u8>> {
    std::mem::take(map)
        .into_iter()
        .map(|(uri, token)| (uri, token.into_vec()))
        .collect()
}

/// Decode → verify → encode. Pure; shared by the C-ABI, language bindings, and tests (single source
/// of truth — Principle III). A well-formed request runs the always-on [`verify`] entry point and
/// returns the [`VerificationResult`]; a malformed one yields [`VerifyOutcome::Err`].
#[must_use]
pub fn process_verify_bytes(input: &[u8]) -> Vec<u8> {
    let outcome = match decode_verify_request(input) {
        Ok(mut req) => {
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
            // Convert the wire `BTreeMap<String, ByteBuf>` to the typed `BTreeMap<String, Vec<u8>>` the
            // sans-IO `VerifyContext` borrows (the raw signed Token Status List token bytes, keyed by
            // list URI). Empty (the `#[serde(default)]`) ⇒ the positional `statuses` seam alone. The
            // shared `take_status_tokens` MOVES the map out (never cloning the attacker-sized buffers).
            let status_tokens = take_status_tokens(&mut req.context.status_tokens);
            let ctx = VerifyContext {
                now_unix: req.context.now_unix,
                role: req.context.role,
                statuses: &req.context.statuses,
                status_tokens: &status_tokens,
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

// =================================================================================================
// Set-level OpenID4VP envelope (schema v5, additive) — the multi-credential `vp_token` surface.
//
// The single-presentation `VerifyRequest` above enforces only the per-presentation single-query match.
// This SEPARATE envelope carries the whole `vp_token` map so the C-ABI reaches the ONLY entry that folds
// the **set-level** DCQL semantics ([`verify_vp_token`] — `credential_sets` required option-sets +
// `multiple` cardinality) AND performs in-core Token Status List authentication across the set. Its
// discipline mirrors `VerifyRequest`/`process_verify_bytes` exactly (versioned + `deny_unknown_fields`
// + fail-closed decode); it reuses `WirePresentation`/`WireTrustAnchor`/`decode_versioned`/
// `anchors_from_wire` (DRY — Principle III).
// =================================================================================================

/// A **set-level** `verify_vp_token` request: the OpenID4VP request the presentations must be bound to,
/// the whole multi-credential `vp_token` (`{credential_id: [presentations]}`), the policy, the
/// configured anchors, the verification instant/role, the host-resolved per-credential/-token/-document
/// positional `statuses`, and (additively) the host-fetched signed Token Status List `status_tokens`.
///
/// `deny_unknown_fields` for the same reason as [`VerifyRequest`]: a misspelled key is a hard decode
/// error, never a silent default (a typo'd `status_tokens` must not silently drop in-core status
/// authentication). Reuses [`WirePresentation`] per presentation and [`WireTrustAnchor`] per anchor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireVpTokenRequest {
    /// Wire schema version of this envelope.
    pub schema_version: u32,
    /// The OpenID4VP request (DCQL query + fresh nonce + audience + `response_uri`) the presentations
    /// must be bound to — the SAME [`PresentationRequest`] carried by [`VerifyRequest::request`].
    pub request: PresentationRequest,
    /// The returned `vp_token`: each Credential Query `id` → the Presentations returned under it
    /// (OpenID4VP 1.0 §"Response Parameters"). Reuses [`WirePresentation`] per presentation.
    pub vp_token: BTreeMap<String, Vec<WirePresentation>>,
    /// The verifier policy.
    pub policy: VerificationPolicy,
    /// The configured trust anchors (resolved + passed in by the host's trust-refresh step).
    pub anchors: Vec<WireTrustAnchor>,
    /// The verification instant (Unix seconds), shared across every presentation.
    pub now_unix: i64,
    /// The default issuer role trust is anchored under (per-credential a query's expected PID type may
    /// override it — see [`crate::openid4vp::verify_vp_token`]).
    pub role: IssuerRole,
    /// The host-resolved revocation/status outcomes, keyed by credential id → per **token**
    /// (presentation) → per **document** (positional). A credential id / token / document with no
    /// covering entry fails closed to [`StatusOutcome::Unavailable`] — never a silent reuse (SC-002).
    pub statuses: BTreeMap<String, Vec<Vec<StatusOutcome>>>,
    /// The host-fetched **signed** Token Status List tokens, keyed by list URI → raw token bytes,
    /// shared across every presentation. When a presented credential declares a Token Status List
    /// reference AND a token is supplied for its URI, the core AUTHENTICATES that token in-core and its
    /// outcome OVERRIDES the positional [`Self::statuses`] entry (identically to the single-presentation
    /// [`WireContext::status_tokens`]). Absent (the `#[serde(default)]` empty map) ⇒ the positional
    /// `statuses` seam alone. `ByteBuf` so the raw token round-trips through ciborium without a lossy
    /// text re-encode.
    #[serde(default)]
    pub status_tokens: BTreeMap<String, serde_bytes::ByteBuf>,
}

impl HasSchemaVersion for WireVpTokenRequest {
    fn schema_version(&self) -> u32 {
        self.schema_version
    }
}

/// The outcome of a set-level `verify_vp_token` operation (mirrors [`VerifyOutcome`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireVpTokenOutcome {
    /// The set-level verdict: the overall `satisfied` decision + the per-credential outcomes (each
    /// carrying its per-Presentation [`VerificationResult`]s + its own `satisfied` flag).
    Ok {
        /// The set-level verification result (carries the full [`VpTokenVerification`] as-is — DRY).
        result: VpTokenVerification,
    },
    /// A decode/usage error rendered as a message (e.g. an unsupported schema version).
    Err {
        /// Human-readable error message.
        message: String,
    },
}

/// A versioned set-level `verify_vp_token` response envelope (mirrors [`VerifyResponse`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireVpTokenResponse {
    /// Wire schema version of this envelope.
    pub schema_version: u32,
    /// The operation outcome.
    pub outcome: WireVpTokenOutcome,
}

/// Decode a set-level `verify_vp_token` request envelope, rejecting unknown schema versions.
///
/// # Errors
///
/// Returns the decode error (or a schema-version mismatch message) as a `String`.
pub fn decode_vp_token_request(bytes: &[u8]) -> Result<WireVpTokenRequest, String> {
    decode_versioned(bytes, ATTESTATION_SCHEMA_VERSION, "attestation")
}

/// Encode a set-level `verify_vp_token` response envelope at the current schema version.
#[must_use]
pub fn encode_vp_token_response(outcome: WireVpTokenOutcome) -> Vec<u8> {
    let resp = WireVpTokenResponse {
        schema_version: ATTESTATION_SCHEMA_VERSION,
        outcome,
    };
    // Infallible: the shared `cbor_to_vec` encodes a plain serde value into an in-memory Vec (DRY).
    crate::cbor_to_vec(&resp)
}

/// Decode → [`crate::openid4vp::verify_vp_token`] → encode for the set-level `vp_token` surface (the
/// wire delegates to the shared slot-level evaluator, which may carry a no-audience-mdoc slot). Pure; shared by the
/// C-ABI, language bindings, and tests (single source of truth — Principle III). A well-formed request
/// folds the complete OpenID4VP set-level DCQL semantics (`credential_sets` + `multiple`) AND
/// authenticates any supplied signed Token Status List token in-core; a malformed one yields
/// [`WireVpTokenOutcome::Err`] (fail-closed, same discipline as [`process_verify_bytes`]).
///
/// **The set-level surface does NOT run the opt-in eIDAS qualified-status gate** (it carries no national
/// Trusted List / scheme anchors): a request with `policy.qualified_gate == true` is REJECTED with a
/// clear [`WireVpTokenOutcome::Err`] rather than silently running no determination — the gate is
/// available only on the single-presentation [`process_verify_bytes`] surface.
#[must_use]
pub fn process_vp_token_bytes(input: &[u8]) -> Vec<u8> {
    let outcome = match decode_vp_token_request(input) {
        Ok(req) if req.policy.qualified_gate => {
            // FAIL LOUD (no silent downgrade): the set-level surface carries no national Trusted List /
            // scheme anchors, so the opt-in eIDAS qualified-status gate CANNOT run here — running it
            // would be a silent no-op (`qualified_status` stays `None`) while still returning `satisfied`.
            // Reject the request rather than let the flag be a silent no-op. The gate runs ONLY on the
            // single-presentation `verify` surface, which carries those inputs.
            WireVpTokenOutcome::Err {
                message: "the opt-in qualified-status gate is not supported on the set-level vp_token \
                          surface; verify each presentation via the single-presentation surface, or \
                          unset qualified_gate"
                    .to_owned(),
            }
        }
        Ok(mut req) => {
            // Chain-validate every credential's leaf against the host-supplied anchors at the
            // verification instant (reuses `anchors_from_wire` — DRY).
            let anchors = anchors_from_wire(&req.anchors, req.now_unix);
            // MOVE the signed Token Status List tokens out (never cloning the attacker-sized buffers) via
            // the shared `take_status_tokens` — exactly as `process_verify_bytes` does for
            // `WireContext::status_tokens`.
            let status_tokens = take_status_tokens(&mut req.status_tokens);
            // Build the BORROWED `{credential_id: [VpTokenSlot]}` map referencing the owned `req.vp_token`
            // (a slot borrows the presentation string / device-response bytes — held live in `req`
            // through the `verify_vp_token_slots` call). The `WirePresentation`→slot mapping mirrors the
            // single-presentation `WirePresentation`→`Presentation` mapping in `process_verify_bytes`,
            // INCLUDING its treatment of an mdoc with NO addressed audience: the single-presentation
            // `verify()` path hard-rejects that as `MissingRequestBinding`, so here it maps to
            // [`VpTokenSlot::MissingAudienceMdoc`] (fail-closed to `MissingRequestBinding`, counted for
            // cardinality but never bar-run) rather than a spoofable empty-string audience that would
            // misreport `WrongAudience` and bypass an empty-`client_id` audience gate.
            let vp_token: BTreeMap<String, Vec<VpTokenSlot<'_>>> = req
                .vp_token
                .iter()
                .map(|(id, presentations)| {
                    let slots = presentations
                        .iter()
                        .map(|presentation| match presentation {
                            WirePresentation::SdJwtVc { presentation } => {
                                VpTokenSlot::Present(VpToken::SdJwtVc(presentation))
                            }
                            WirePresentation::Mdoc {
                                device_response,
                                audience,
                            } => audience.as_deref().map_or(
                                VpTokenSlot::MissingAudienceMdoc,
                                |audience| {
                                    VpTokenSlot::Present(VpToken::Mdoc(MdocVpToken {
                                        audience,
                                        device_response,
                                    }))
                                },
                            ),
                        })
                        .collect();
                    (id.clone(), slots)
                })
                .collect();
            let result = verify_vp_token_slots(
                &req.request,
                &vp_token,
                &req.policy,
                &anchors,
                req.now_unix,
                req.role,
                &req.statuses,
                &status_tokens,
            );
            WireVpTokenOutcome::Ok { result }
        }
        Err(message) => WireVpTokenOutcome::Err { message },
    };
    encode_vp_token_response(outcome)
}

#[cfg(test)]
mod tests;
