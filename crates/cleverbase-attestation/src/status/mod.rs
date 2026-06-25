//! Revocation / status check (status list / CRL) with a fail-closed reachability policy (T014).
//!
//! The always-on bar (FR-003) includes revocation: a credential whose status mechanism says it is
//! revoked → INVALID `revoked`; one whose status cannot be reached → fail-closed by default →
//! INVALID `status_unavailable` (never a silent VALID). This module evaluates that check.
//!
//! ## Sans-IO (host seam — like the trust engine)
//!
//! The core performs no network I/O. A credential references its status mechanism (a Token Status
//! List pointer `uri`+`idx`, or a CRL the integrator names); the **host** fetches the referenced
//! status document and supplies its bytes through the [`StatusSource`] seam, exactly as the trust
//! engine takes fetched trust-list bytes through `TrustListFetcher`. The fetch (network, caching,
//! freshness of the *transport*) is the host's; the *evaluation* and the **fail-closed policy** are
//! the core's.
//!
//! ## Status mechanisms
//!
//! - **Token Status List** (IETF `draft-ietf-oauth-status-list` — the EUDI/HAIP baseline): a
//!   credential carries a `status.status_list = { idx, uri }`; the referenced list is a packed
//!   bit-array (1 or 2 bits per entry). A non-zero status value at `idx` is revoked/suspended.
//! - **CRL** (X.509 Certificate Revocation List): a credential is identified by an issuer-assigned
//!   serial; the referenced CRL enumerates revoked serials. Modelled abstractly here (the integrator
//!   supplies the parsed revoked-serial set) so the same fail-closed policy covers both.
//!
//! The decision maps to a single canonical [`StatusOutcome`] that the per-format verifiers consume
//! through their status seam (one authoritative status type — DRY).

use serde::{Deserialize, Serialize};

use crate::types::StatusReachability;

/// The canonical outcome of the revocation/status check, consumed by both per-format verifiers'
/// status seam (the single authoritative status type — DRY, Principle III).
///
/// The per-format `verify` paths translate this into their reject reason: [`Self::Revoked`] →
/// [`ReasonCode::Revoked`], [`Self::Unavailable`] → [`ReasonCode::StatusUnavailable`], and
/// [`Self::NoStatus`]/[`Self::Good`] continue the bar. Carried across the C-ABI as CBOR (the host
/// resolves it through [`check_status`] and passes the outcome in), hence the `serde` derives.
///
/// [`ReasonCode::Revoked`]: crate::types::ReasonCode::Revoked
/// [`ReasonCode::StatusUnavailable`]: crate::types::ReasonCode::StatusUnavailable
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatusOutcome {
    /// The credential declares no status mechanism — nothing to check (continue the bar).
    NoStatus,
    /// The status mechanism was reachable and says the credential is current.
    Good,
    /// The status mechanism says the credential is revoked or suspended.
    Revoked,
    /// The status document was unreachable (or unparseable) and the policy is fail-closed — never a
    /// silent VALID.
    Unavailable,
}

/// What a credential declares about its status mechanism (parsed from the credential), or the
/// absence of one.
///
/// This is the *reference* the host resolves: a Token Status List pointer (`uri`+`idx`), or a CRL
/// entry (a CRL location plus the credential's serial). The host fetches the referenced document and
/// supplies it via the [`StatusSource`] seam; the core then evaluates `idx`/serial against it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusReference {
    /// The credential declares no status mechanism.
    None,
    /// A Token Status List reference: the index of this credential's entry and the list URI the host
    /// fetches.
    StatusList {
        /// The credential's entry index in the referenced status list.
        index: u64,
        /// The status-list URI the host resolves to the packed status document.
        uri: String,
    },
    /// A CRL reference: the credential's serial and the CRL location the host fetches.
    Crl {
        /// The credential's issuer-assigned serial (as bytes — X.509 serials are big integers).
        serial: Vec<u8>,
        /// The CRL distribution-point URI the host resolves to the revoked-serial set.
        uri: String,
    },
}

/// A host-driven source of fetched status documents (keeps the core sans-IO — Principle III).
///
/// Mirrors `crate::trust::engine::TrustListFetcher`: the core never performs network I/O; the host
/// fetches the referenced status document (network, transport caching) and returns its parsed form,
/// or `None` when it is unreachable. A `None` under [`StatusReachability::FailClosed`] is the
/// fail-closed reject; under [`StatusReachability::BestEffort`] it is tolerated.
pub trait StatusSource {
    /// Fetch the packed Token Status List bytes for `uri`, or `None` if unreachable.
    ///
    /// The bytes are the **unpacked** status array: one byte per entry holding that entry's status
    /// value (`0` = valid; non-zero = revoked/suspended). The host is responsible for decompressing /
    /// bit-unpacking the wire form (the CBOR/JWT-wrapped, optionally DEFLATE-compressed bitstring)
    /// into this byte-per-entry view; the core does not pull a compression dependency into its
    /// sans-IO surface.
    fn fetch_status_list(&self, uri: &str) -> Option<Vec<u8>>;

    /// Fetch the set of revoked serials for the CRL at `uri`, or `None` if unreachable.
    ///
    /// Each entry is a revoked credential serial (big-endian bytes). The host parses the DER CRL (or
    /// its cached form) into this set; the core checks membership.
    fn fetch_crl_revoked_serials(&self, uri: &str) -> Option<Vec<Vec<u8>>>;
}

/// Evaluate a credential's status against the host-supplied status documents, applying the
/// fail-closed reachability policy.
///
/// - [`StatusReference::None`] → [`StatusOutcome::NoStatus`].
/// - A reachable status list / CRL → [`StatusOutcome::Revoked`] if the entry is revoked, else
///   [`StatusOutcome::Good`].
/// - An **unreachable** status document → [`StatusOutcome::Unavailable`] under
///   [`StatusReachability::FailClosed`] (the secure default), or [`StatusOutcome::Good`] under
///   [`StatusReachability::BestEffort`] (the credential is not failed on reachability alone).
///
/// Sans-IO: the status documents are supplied through `source`; this performs no network I/O.
#[must_use]
pub fn check_status<S: StatusSource + ?Sized>(
    reference: &StatusReference,
    source: &S,
    reachability: StatusReachability,
) -> StatusOutcome {
    match reference {
        StatusReference::None => StatusOutcome::NoStatus,
        StatusReference::StatusList { index, uri } => source.fetch_status_list(uri).map_or_else(
            || unreachable_outcome(reachability),
            |list| evaluate_status_list(&list, *index),
        ),
        StatusReference::Crl { serial, uri } => source.fetch_crl_revoked_serials(uri).map_or_else(
            || unreachable_outcome(reachability),
            |revoked| {
                if revoked.iter().any(|s| s == serial) {
                    StatusOutcome::Revoked
                } else {
                    StatusOutcome::Good
                }
            },
        ),
    }
}

/// Map an unreachable status document to the policy outcome: fail-closed → `Unavailable` (the secure
/// default, never a silent VALID); best-effort → `Good` (tolerate, do not fail on reachability).
const fn unreachable_outcome(reachability: StatusReachability) -> StatusOutcome {
    match reachability {
        StatusReachability::FailClosed => StatusOutcome::Unavailable,
        StatusReachability::BestEffort => StatusOutcome::Good,
    }
}

/// Read the status value at `index` in an unpacked status array (one byte per entry). A `0` value is
/// valid; any non-zero value (revoked / suspended / application-defined) is treated as revoked. An
/// out-of-range index is a malformed/short list → fail-closed `Unavailable` (the core cannot prove
/// the credential is current).
fn evaluate_status_list(list: &[u8], index: u64) -> StatusOutcome {
    match usize::try_from(index).ok().and_then(|i| list.get(i)) {
        Some(0) => StatusOutcome::Good,
        Some(_) => StatusOutcome::Revoked,
        None => StatusOutcome::Unavailable,
    }
}

#[cfg(test)]
mod tests;
