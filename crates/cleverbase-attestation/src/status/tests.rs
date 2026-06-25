//! Tests for the revocation/status check (T014 — written test-first against the implementation).
//!
//! The status check is sans-IO: a credential references its status mechanism, the host supplies the
//! fetched status document through the [`StatusSource`] seam, and the core evaluates it under the
//! fail-closed reachability policy. These assert: no-status → NoStatus; a reachable list/CRL →
//! Good/Revoked per the entry; and an **unreachable** document → Unavailable (fail-closed) or Good
//! (best-effort) per the policy — never a silent VALID under the default.

use std::collections::BTreeMap;

use super::{check_status, StatusOutcome, StatusReference, StatusSource};
use crate::types::StatusReachability;

/// A configurable in-memory status source for the tests (the host seam): maps URIs to either a
/// status-list byte array or a CRL revoked-serial set, and can be made to report a URI as
/// unreachable (returning `None`).
#[derive(Default)]
struct TestStatusSource {
    status_lists: BTreeMap<String, Vec<u8>>,
    crls: BTreeMap<String, Vec<Vec<u8>>>,
}

impl TestStatusSource {
    fn with_status_list(mut self, uri: &str, entries: Vec<u8>) -> Self {
        self.status_lists.insert(uri.to_owned(), entries);
        self
    }

    fn with_crl(mut self, uri: &str, revoked: Vec<Vec<u8>>) -> Self {
        self.crls.insert(uri.to_owned(), revoked);
        self
    }
}

impl StatusSource for TestStatusSource {
    fn fetch_status_list(&self, uri: &str) -> Option<Vec<u8>> {
        self.status_lists.get(uri).cloned()
    }
    fn fetch_crl_revoked_serials(&self, uri: &str) -> Option<Vec<Vec<u8>>> {
        self.crls.get(uri).cloned()
    }
}

const URI: &str = "https://issuer.example/status/1";

#[test]
fn no_status_reference_is_no_status() {
    let source = TestStatusSource::default();
    let outcome = check_status(
        &StatusReference::None,
        &source,
        StatusReachability::FailClosed,
    );
    assert_eq!(outcome, StatusOutcome::NoStatus);
}

#[test]
fn current_entry_in_a_reachable_status_list_is_good() {
    // Entry 2 holds 0 (valid).
    let source = TestStatusSource::default().with_status_list(URI, vec![1, 0, 0, 1]);
    let outcome = check_status(
        &StatusReference::StatusList {
            index: 2,
            uri: URI.to_owned(),
        },
        &source,
        StatusReachability::FailClosed,
    );
    assert_eq!(outcome, StatusOutcome::Good);
}

#[test]
fn revoked_entry_in_a_reachable_status_list_is_revoked() {
    // Entry 0 holds 1 (revoked); any non-zero value is revoked/suspended.
    let source = TestStatusSource::default().with_status_list(URI, vec![1, 0, 0]);
    let outcome = check_status(
        &StatusReference::StatusList {
            index: 0,
            uri: URI.to_owned(),
        },
        &source,
        StatusReachability::FailClosed,
    );
    assert_eq!(outcome, StatusOutcome::Revoked);
}

#[test]
fn suspended_nonzero_status_value_is_treated_as_revoked() {
    // A 2-bit status list can carry value 2 (suspended); the always-on bar fails it like revoked.
    let source = TestStatusSource::default().with_status_list(URI, vec![0, 2]);
    let outcome = check_status(
        &StatusReference::StatusList {
            index: 1,
            uri: URI.to_owned(),
        },
        &source,
        StatusReachability::FailClosed,
    );
    assert_eq!(outcome, StatusOutcome::Revoked);
}

#[test]
fn unreachable_status_list_fails_closed_by_default() {
    // The URI is not in the source → unreachable. Fail-closed (default) → Unavailable.
    let source = TestStatusSource::default();
    let outcome = check_status(
        &StatusReference::StatusList {
            index: 0,
            uri: URI.to_owned(),
        },
        &source,
        StatusReachability::FailClosed,
    );
    assert_eq!(outcome, StatusOutcome::Unavailable);
}

#[test]
fn unreachable_status_list_is_tolerated_under_best_effort() {
    let source = TestStatusSource::default();
    let outcome = check_status(
        &StatusReference::StatusList {
            index: 0,
            uri: URI.to_owned(),
        },
        &source,
        StatusReachability::BestEffort,
    );
    assert_eq!(outcome, StatusOutcome::Good);
}

#[test]
fn out_of_range_index_fails_closed() {
    // A short/malformed list that does not cover the credential's index cannot prove it current.
    let source = TestStatusSource::default().with_status_list(URI, vec![0, 0]);
    let outcome = check_status(
        &StatusReference::StatusList {
            index: 99,
            uri: URI.to_owned(),
        },
        &source,
        StatusReachability::FailClosed,
    );
    assert_eq!(outcome, StatusOutcome::Unavailable);
}

#[test]
fn crl_with_the_serial_is_revoked() {
    let serial = vec![0x01, 0x02, 0x03];
    let source = TestStatusSource::default().with_crl(URI, vec![vec![0xAA], serial.clone()]);
    let outcome = check_status(
        &StatusReference::Crl {
            serial,
            uri: URI.to_owned(),
        },
        &source,
        StatusReachability::FailClosed,
    );
    assert_eq!(outcome, StatusOutcome::Revoked);
}

#[test]
fn crl_without_the_serial_is_good() {
    let source = TestStatusSource::default().with_crl(URI, vec![vec![0xAA], vec![0xBB]]);
    let outcome = check_status(
        &StatusReference::Crl {
            serial: vec![0x01],
            uri: URI.to_owned(),
        },
        &source,
        StatusReachability::FailClosed,
    );
    assert_eq!(outcome, StatusOutcome::Good);
}

#[test]
fn unreachable_crl_fails_closed_by_default() {
    let source = TestStatusSource::default();
    let outcome = check_status(
        &StatusReference::Crl {
            serial: vec![0x01],
            uri: URI.to_owned(),
        },
        &source,
        StatusReachability::FailClosed,
    );
    assert_eq!(outcome, StatusOutcome::Unavailable);
}

#[test]
fn unreachable_crl_is_tolerated_under_best_effort() {
    let source = TestStatusSource::default();
    let outcome = check_status(
        &StatusReference::Crl {
            serial: vec![0x01],
            uri: URI.to_owned(),
        },
        &source,
        StatusReachability::BestEffort,
    );
    assert_eq!(outcome, StatusOutcome::Good);
}
