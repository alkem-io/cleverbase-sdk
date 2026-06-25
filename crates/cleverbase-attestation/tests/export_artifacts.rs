//! Export the SDK-produced conformant artifacts for the independent cross-check (T030 / FR-013).
//!
//! Writes the **rendered** VALID artifacts — the compact SD-JWT VC presentation and the mdoc
//! `DeviceResponse` (CBOR) — to a directory so the opt-in cross-check workflow
//! (`.github/workflows/attestation-crosscheck.yml`) can feed them to an *independent,
//! different-language* EU reference verifier via `scripts/crosscheck-attestation.sh`. The artifacts
//! come from the same test-issuer minters the in-crate suite verifies (DRY — `crate::test_vectors`),
//! so the material the reference verifier checks is the exact credential the SDK's own always-on bar
//! accepts (Principle VI: produced/obtained artifacts checked against an independent verifier — not
//! Rust-vs-Rust self-confirmation).
//!
//! It is **off by default**: when `ATT_EXPORT_DIR` is unset (every normal `cargo test` run) it
//! **self-skips cleanly** and writes nothing — mirroring the live-issuance contract test's self-skip.
//! When `ATT_EXPORT_DIR` is set (the opt-in workflow) it writes `valid-sd-jwt-vc.txt` and
//! `valid-mdoc.cbor` into that directory.
//!
//! Built only with the `test-vectors` feature (the shared minters live behind it), declared via the
//! test target's `required-features` so a default `cargo test` neither builds nor runs it.

// An integration test legitimately reports to the console and treats a panic on a broken fixed
// fixture as the intended failure signal; re-allow the strict library lints here exactly as the
// in-crate test modules and the live-issuance test do.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::path::Path;

use cleverbase_attestation::test_vectors::{valid_mdoc_artifact, valid_sd_jwt_vc_artifact};

#[test]
fn export_valid_artifacts_for_the_independent_cross_check_or_skip() {
    let Ok(dir) = std::env::var("ATT_EXPORT_DIR") else {
        eprintln!(
            "SKIP: ATT_EXPORT_DIR unset — not exporting cross-check artifacts (set it in the \
             opt-in attestation-crosscheck workflow to write them)"
        );
        return;
    };
    let dir = Path::new(&dir);
    std::fs::create_dir_all(dir).expect("create ATT_EXPORT_DIR");

    let sd_jwt_vc = valid_sd_jwt_vc_artifact();
    let sd_jwt_path = dir.join("valid-sd-jwt-vc.txt");
    std::fs::write(&sd_jwt_path, sd_jwt_vc.as_bytes()).expect("write SD-JWT VC artifact");

    let mdoc = valid_mdoc_artifact();
    let mdoc_path = dir.join("valid-mdoc.cbor");
    std::fs::write(&mdoc_path, &mdoc).expect("write mdoc DeviceResponse artifact");

    eprintln!(
        "exported cross-check artifacts: {} ({} bytes), {} ({} bytes)",
        sd_jwt_path.display(),
        sd_jwt_vc.len(),
        mdoc_path.display(),
        mdoc.len()
    );
}
