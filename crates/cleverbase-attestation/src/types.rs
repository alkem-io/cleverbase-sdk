//! Shared domain types for EUDI attestation verification (data-model.md).
//!
//! These are the conceptual domain entities of the attestation core. They are **sans-IO** — the core
//! holds no persistence and no key custody — and are carried across the `cleverbase-ffi` C-ABI as
//! CBOR (hence the `serde` derives), so they form a versioned wire contract, not just an in-process
//! API. None of these types carries a private key or other sole-control secret (those stay in the
//! integrator's HSM via the signer-hook), so deriving `Debug` here exposes only issuer-public and
//! verifier-side data. `disclosedAttributes` does carry the holder-disclosed subject claims (PII by
//! nature); a host that logs a [`VerificationResult`] is logging exactly the data it asked the
//! subject to disclose — no *undisclosed* attribute is ever present.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The credential format of an attestation. The format determines the encoding (JOSE vs CBOR/COSE)
/// and the selective-disclosure / holder-binding mechanism (data-model.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    /// SD-JWT VC (IETF RFC 9901 / draft-16) — compact JWS with selective-disclosure salts and a
    /// holder Key-Binding JWT.
    SdJwtVc,
    /// ISO/IEC 18013-5 mdoc — a CBOR `DeviceResponse` with a COSE_Sign1 `IssuerAuth` and `DeviceAuth`
    /// holder binding.
    Mdoc,
}

/// The issuer role, which selects the trust anchor for verification (research D5).
///
/// EUDI anchors trust **per role** — a qualified-EAA issuer is found on a different list than a PID
/// provider — so the role is an explicit input to [`crate::trust::TrustAnchorSource::resolve`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssuerRole {
    /// Qualified Electronic Attestation of Attributes issuer (EU LOTL + national Trusted Lists,
    /// ETSI TS 119 612).
    Qeaa,
    /// Person Identification Data provider (Commission list under eIDAS Art. 5a(18)).
    Pid,
    /// Public-body EAA provider (Commission list under eIDAS Art. 45f(3)).
    PubEaa,
    /// Non-qualified EAA issuer (trusted via a configured anchor, but not on a qualified list).
    NonQualifiedEaa,
}

/// The issuer's trust status under the always-on bar: present on the configured trust anchor for its
/// role/format, or not (data-model.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustStatus {
    /// The issuer is present (and its trust-list entry is currently in-force) on the configured
    /// anchor.
    Trusted,
    /// The issuer is absent, or its entry is expired/withdrawn/revoked, on the configured anchor.
    Untrusted,
}

/// The eIDAS qualified status of the issuer, populated **only** by the opt-in TS 119 615 cl. 4.12
/// gate (otherwise absent — never assumed). See [`crate::qualified`].
///
/// Outcome conditions are pinned (tasks T018/T019): `Qualified` iff the issuer's `EAA/Q` service
/// entry was `granted` at the relevant time; `NotQualified` iff the entry is found but not granted
/// (withdrawn/suspended) at that time; `Indeterminate` iff the trust-list data is
/// absent/ambiguous/unreachable. There is no false "qualified" (SC-007).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualifiedStatus {
    /// The issuer's qualified-EAA service was `granted` at the relevant time.
    Qualified,
    /// The issuer's entry was found but not granted (withdrawn/suspended) at the relevant time.
    NotQualified,
    /// The trust-list data needed to decide was absent, ambiguous, or unreachable.
    Indeterminate,
}

/// The validity window of an attestation (SD-JWT VC `nbf`/`exp`; mdoc MSO `validityInfo`), as Unix
/// seconds. Either bound may be absent if the format/credential omits it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Validity {
    /// Not-valid-before (Unix seconds), if present.
    pub not_before: Option<i64>,
    /// Not-valid-after (Unix seconds), if present.
    pub not_after: Option<i64>,
}

/// A disclosed attribute value.
///
/// Credential claims are heterogeneous (strings, numbers, booleans, nested maps, byte strings — e.g.
/// an mdoc `portrait`). A closed, self-describing value type keeps the CBOR wire contract explicit
/// rather than leaning on an untyped `serde_json::Value`/`ciborium::Value` (which would also drag a
/// `Debug`-via-untyped-value foot-gun into the public API).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributeValue {
    /// A UTF-8 text claim.
    Text(String),
    /// An integer claim.
    Integer(i64),
    /// A boolean claim.
    Boolean(bool),
    /// A byte-string claim (e.g. an mdoc portrait or a raw value).
    Bytes(#[serde(with = "serde_bytes")] Vec<u8>),
    /// A nested object claim.
    Map(BTreeMap<String, Self>),
    /// An array claim.
    Array(Vec<Self>),
    /// An explicitly null claim.
    Null,
}

/// The fail-closed-vs-best-effort policy for an unreachable revocation/status endpoint
/// (data-model.md `VerificationPolicy.statusReachability`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatusReachability {
    /// An unreachable status endpoint yields INVALID `status_unavailable` (the secure default).
    #[default]
    FailClosed,
    /// An unreachable status endpoint is tolerated (the credential is not failed on reachability
    /// alone) — opt-in, for environments that accept the weaker guarantee.
    BestEffort,
}

/// The verifier's policy input (data-model.md `VerificationPolicy`).
///
/// Defaults are the secure baseline: both formats accepted, the qualified gate **off**, and status
/// reachability **fail-closed**.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationPolicy {
    /// Which formats to accept. An empty set is treated as "both" (the default).
    pub formats: Vec<Format>,
    /// Enable the opt-in TS 119 615 qualified-status determination (default off).
    pub qualified_gate: bool,
    /// The fail-closed-vs-best-effort status-reachability policy (default fail-closed).
    pub status_reachability: StatusReachability,
}

impl Default for VerificationPolicy {
    /// The secure baseline: accept both formats, qualified gate off, status reachability
    /// fail-closed.
    fn default() -> Self {
        Self {
            formats: vec![Format::SdJwtVc, Format::Mdoc],
            qualified_gate: false,
            status_reachability: StatusReachability::FailClosed,
        }
    }
}

/// A machine-readable reason for a verification outcome (FR-005 / SC-002).
///
/// This is a **closed** enum: every failed always-on check maps to exactly one specific variant, so
/// an INVALID verdict always carries an actionable, stable reason (no opaque "verification failed").
/// New reasons are added by SemVer-minor as the verifier grows; consumers MUST treat an unknown
/// reason conservatively.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ReasonCode {
    /// The issuer signature did not verify, or the credential was otherwise tampered with.
    Tamper,
    /// The credential is outside its validity window at the relevant time (SD-JWT VC `nbf`/`exp`;
    /// mdoc MSO `validityInfo`).
    Expired,
    /// The credential is revoked per its status mechanism (status list / CRL).
    Revoked,
    /// The issuer is not on the configured trust anchor for its role/format (absent, or an
    /// expired/withdrawn trust-list entry).
    UntrustedIssuer,
    /// The revocation/status endpoint (or trust list) was unreachable or stale and the policy is
    /// fail-closed (never a silent VALID).
    StatusUnavailable,
    /// The holder binding did not verify (SD-JWT VC KB-JWT; mdoc DeviceAuth).
    HolderBinding,
    /// A disclosed attribute did not match an issuer-signed digest (SD-JWT disclosure digest; mdoc
    /// `valueDigests`).
    DisclosureIntegrity,
    /// The presentation was replayed — it did not echo the issued request's fresh `nonce`.
    Replay,
    /// The presentation was addressed to a different audience than the verifier's `client_id`.
    WrongAudience,
    /// The credential format is unrecognized or not enabled by the policy (never a guess).
    UnsupportedFormat,
    /// The credential or presentation was structurally malformed and could not be parsed.
    MalformedCredential,
    /// The request binding was required (an OpenID4VP request was supplied) but is missing from the
    /// presentation.
    MissingRequestBinding,
}

/// The verdict of a verification (data-model.md `VerificationResult`).
///
/// No **false-accept** (SC-002): any failed always-on check yields `valid = false` with at least one
/// specific [`ReasonCode`]. `qualified_status` is `Some` only when the opt-in gate ran.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationResult {
    /// The always-on bar: signature + trust-list membership + validity + status + holder binding +
    /// disclosure integrity + (when a request was supplied) request binding all passed.
    pub valid: bool,
    /// Only the disclosed subset of attributes; undisclosed attributes are neither revealed nor
    /// required.
    pub disclosed_attributes: BTreeMap<String, AttributeValue>,
    /// The issuer trust status.
    pub trust_status: TrustStatus,
    /// The eIDAS qualified status, present only when the opt-in gate ran.
    pub qualified_status: Option<QualifiedStatus>,
    /// The machine-readable reasons for the verdict (especially for INVALID — FR-005); empty for a
    /// clean VALID.
    pub reasons: Vec<ReasonCode>,
}

impl VerificationResult {
    /// Construct an INVALID verdict carrying a single specific reason, with no disclosed attributes
    /// and an `Untrusted` issuer — the safe default for an early reject (e.g. an unsupported format
    /// or a malformed credential), before the issuer or its disclosures are even established.
    #[must_use]
    pub fn invalid(reason: ReasonCode) -> Self {
        Self {
            valid: false,
            disclosed_attributes: BTreeMap::new(),
            trust_status: TrustStatus::Untrusted,
            qualified_status: None,
            reasons: vec![reason],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AttributeValue, Format, ReasonCode, StatusReachability, TrustStatus, VerificationPolicy,
        VerificationResult,
    };
    use std::collections::BTreeMap;

    /// Round-trip a value through the CBOR codec the C-ABI uses, asserting it survives unchanged.
    fn cbor_roundtrip<T>(value: &T) -> T
    where
        T: serde::Serialize + serde::de::DeserializeOwned,
    {
        let mut buf = Vec::new();
        ciborium::into_writer(value, &mut buf).expect("CBOR encode");
        ciborium::from_reader(&buf[..]).expect("CBOR decode")
    }

    #[test]
    fn verification_policy_default_is_the_secure_baseline() {
        let policy = VerificationPolicy::default();
        assert_eq!(policy.formats, vec![Format::SdJwtVc, Format::Mdoc]);
        assert!(!policy.qualified_gate);
        assert_eq!(policy.status_reachability, StatusReachability::FailClosed);
    }

    #[test]
    fn verification_result_round_trips_through_cbor() {
        let mut disclosed = BTreeMap::new();
        disclosed.insert("given_name".to_string(), AttributeValue::Text("Ada".into()));
        let result = VerificationResult {
            valid: true,
            disclosed_attributes: disclosed,
            trust_status: TrustStatus::Trusted,
            qualified_status: None,
            reasons: Vec::new(),
        };
        assert_eq!(cbor_roundtrip(&result), result);
    }

    #[test]
    fn reason_codes_round_trip_through_cbor() {
        for reason in [
            ReasonCode::Tamper,
            ReasonCode::Expired,
            ReasonCode::Revoked,
            ReasonCode::UntrustedIssuer,
            ReasonCode::StatusUnavailable,
            ReasonCode::HolderBinding,
            ReasonCode::DisclosureIntegrity,
            ReasonCode::Replay,
            ReasonCode::WrongAudience,
            ReasonCode::UnsupportedFormat,
            ReasonCode::MalformedCredential,
            ReasonCode::MissingRequestBinding,
        ] {
            assert_eq!(cbor_roundtrip(&reason), reason);
        }
    }

    #[test]
    fn invalid_helper_carries_the_specific_reason_and_no_disclosures() {
        let result = VerificationResult::invalid(ReasonCode::UnsupportedFormat);
        assert!(!result.valid);
        assert_eq!(result.reasons, vec![ReasonCode::UnsupportedFormat]);
        assert!(result.disclosed_attributes.is_empty());
        assert_eq!(result.trust_status, TrustStatus::Untrusted);
        assert!(result.qualified_status.is_none());
    }
}
