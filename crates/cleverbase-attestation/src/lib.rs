//! # cleverbase-attestation
//!
//! The sans-IO EUDI **attestation** core of the Cleverbase SDK. It verifies presented EUDI
//! credentials in both mandated formats — **SD-JWT VC** (RFC 9901 / draft-16) and **ISO/IEC 18013-5
//! mdoc** — against EU trust anchors, and (forward-looking, gated) drives OpenID4VCI issuance and
//! OpenID4VP holder presentation via the integrator's signer-hook. Like `cleverbase-core` it is
//! **sans-IO** (no network in the core; trust lists are fetched/cached by a host-driven step and
//! passed in as anchors) and **pure-Rust / WASM-able** (no JVM, no OpenSSL-FFI).
//!
//! See `specs/004-attestation-and-verification/` for the spec, plan, data-model, and contracts.
//!
//! ## Design constraints (from the plan)
//!
//! - **No hand-rolled crypto** (Principle IV): signatures and digests go through the SDK's existing
//!   RustCrypto stack (`p256`/`ecdsa`/`rsa`/`sha2`/`x509-cert`/`cms`) plus `coset` for COSE.
//! - **One Rust core** (Principle III): all attestation logic lives here, surfaced over the existing
//!   `cleverbase-ffi` C-ABI; the bindings stay thin.
//! - **Not a wallet** (Principle IV): holder keys are the integrator's, exercised via the spec-001
//!   signer-hook; the SDK never holds a private key.
//!
//! ## Status
//!
//! User Story 1 (feature 004 — the MVP) is implemented: the global [`verify`] entry point assembles
//! the always-on bar over both format verifiers ([`sdjwtvc`], [`mdoc`]), the native EU trust-list
//! engine ([`trust`]), the revocation/[`status`] check (fail-closed by default), and the
//! [`openid4vp`] request binding (nonce + audience), surfaced over the `cleverbase-ffi` C-ABI via
//! [`wire`]. The opt-in [`qualified`]-status gate (T019) and the gated [`issuance`] path (US2)
//! remain stubs filled in by later tasks; [`verify::VerifyContext::qualified_gate`] is the off-by-
//! default seam for the former.

// The workspace pins a strict `restriction` lint set (unwrap/expect/panic/indexing/…) that targets
// library code. Test modules use those same constructs as assertions, where a panic IS the intended
// failure signal, so re-allow them under `cfg(test)` only — `src` stays held to the strict bar.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::unwrap_in_result,
        clippy::string_slice
    )
)]

pub mod issuance;
pub mod mdoc;
pub mod openid4vp;
pub mod qualified;
pub mod sdjwtvc;
pub mod status;
#[cfg(feature = "test-vectors")]
pub mod test_vectors;
pub mod trust;
pub mod types;
pub mod verify;
pub mod wire;

pub use verify::{detect_format, verify, Presentation, VerifyContext};
