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
//! Foundation (feature 004, phases 1–2): the shared domain [`types`] and the pluggable [`trust`]
//! anchor seam (trait + offline test anchor) are implemented. The format verifiers
//! ([`sdjwtvc`], [`mdoc`]), the [`openid4vp`] binding layer, the EU trust-list engine, the opt-in
//! [`qualified`]-status gate, and the gated [`issuance`] path are stubs filled in by later tasks.

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
pub mod trust;
pub mod types;
pub mod wire;
