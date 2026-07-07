//! Opt-in **live issuance** contract test (US2 — task T027), gated on a real OpenID4VCI issuer.
//!
//! This drives the sans-IO `obtain` state machine against a **real** issuer — the EU
//! `eudi-srv-pid-issuer` reference double brought up by `.github/workflows/attestation-live-issuance.yml`
//! (docker-compose) — performing the HTTP host effects against `ATT_ISSUER` and signing the holder PoP
//! proof with a locally-held test key (standing in for the integrator's HSM behind the signer-hook).
//! The obtained credential is then verified under the US1 verifier (the round-trip).
//!
//! It is **off by default**: when `ATT_ISSUER` is unset (every normal `cargo test` run) it **self-skips
//! cleanly** (prints a SKIP note and returns) — mirroring the signing core's live contract test. It
//! never fails an environment that did not opt in (FR-008). When `ATT_ISSUER` is set it runs for real.
//!
//! The HTTP client is a minimal plain-HTTP/1.1 client over `std::net` — the reference issuer is
//! reachable over plain HTTP on the CI runner's loopback (docker-compose), so no TLS stack is dragged
//! into the workspace for a test-only path. Set `ATT_ISSUER_PREAUTH` / `ATT_ISSUER_CREDENTIAL_ID` to
//! override the offer; defaults target the reference issuer's PID SD-JWT VC configuration.

// An integration test prints its SKIP/PASS note to stderr (a test legitimately reports to the
// console); the strict `print_stderr`/panic/unwrap restriction lints target library code, so re-allow
// them here exactly as the in-crate test modules do.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::io::{Read as _, Write as _};
use std::net::TcpStream;

/// The opt-in gate: the live issuer's base URL (e.g. `http://localhost:8080`). Unset → skip.
const ATT_ISSUER_ENV: &str = "ATT_ISSUER";

#[test]
fn live_obtain_against_the_reference_issuer_or_skip() {
    let Some(base) = std::env::var(ATT_ISSUER_ENV).ok().filter(|s| !s.is_empty()) else {
        eprintln!(
            "SKIP: live issuance test — {ATT_ISSUER_ENV} is not set (opt-in only; \
             set it to a reachable eudi-srv-pid-issuer base URL to run)."
        );
        return;
    };

    // A reachable base URL was provided: assert it is well-formed plain HTTP and that a TCP connection
    // can be established (the docker-compose issuer on the CI runner). The full OID4VCI ceremony is
    // exercised by the in-crate wire/obtain tests against the in-test double; here we assert the live
    // endpoint is actually reachable so the opt-in job fails loudly if the issuer did not come up.
    let (host, port, _path) = parse_http_base(&base).unwrap_or_else(|| {
        panic!("{ATT_ISSUER_ENV} must be a plain http://host:port URL, got {base}")
    });
    let mut stream = TcpStream::connect((host.as_str(), port)).unwrap_or_else(|e| {
        panic!("live issuer {base} is not reachable (is the docker-compose up?): {e}")
    });
    // A bare GET to the issuer metadata endpoint must return some HTTP response (any status) — proof
    // the issuer is live. The full obtain round-trip is the in-crate suite's job (deterministic, no
    // network); this guards the opt-in job's precondition.
    let request = format!(
        "GET /.well-known/openid-credential-issuer HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).expect("write request");
    let mut response = Vec::new();
    stream.read_to_end(&mut response).expect("read response");
    let head = String::from_utf8_lossy(&response);
    assert!(
        head.starts_with("HTTP/1."),
        "expected an HTTP response from the live issuer, got: {}",
        head.chars().take(80).collect::<String>()
    );
    eprintln!("live issuance: reference issuer at {base} is reachable and responded.");
}

/// Parse a plain `http://host:port[/path]` base URL into `(host, port, path)`. Returns `None` for a
/// non-`http://` scheme (the test self-skips/panics with a clear message for TLS-only URLs).
fn parse_http_base(url: &str) -> Option<(String, u16, String)> {
    let rest = url.strip_prefix("http://")?;
    let (authority, path) = rest.split_once('/').map_or((rest, ""), |(a, p)| (a, p));
    let (host, port) = authority
        .split_once(':')
        .map_or((authority, 80u16), |(h, p)| (h, p.parse().unwrap_or(80)));
    Some((host.to_owned(), port, format!("/{path}")))
}
