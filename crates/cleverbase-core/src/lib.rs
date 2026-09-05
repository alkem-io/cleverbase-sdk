//! # cleverbase-core
//!
//! The sans-IO core of the Cleverbase SDK: a pure, serializable state machine for obtaining a
//! Qualified Electronic Signature (QES) on a PDF (PAdES B-B / B-T). It performs all cryptography
//! and PDF work in-process and **emits effects** (HTTP requests, browser redirects) that the host
//! executes — it never performs I/O itself. This keeps the core deterministic, WASM-able, and
//! contract-testable by replaying recorded HTTP fixtures.
//!
//! See `specs/001-remote-qes-signing/` for the spec, plan, and contracts.
//!
//! ## Status
//!
//! Phase 1 (signing) is implemented and tested: the full CSC/OIDC flow (service auth → credential
//! discovery → identity check → PDF prepare → hash-bound credential auth → `signHash` → CMS
//! assembly → embed), PAdES **B-B** and **B-T** (RFC 3161), **RSA** and **ECDSA P-256**, optional
//! visible appearance, the stateless session handle, and integrity-only verification of a
//! singly-signed PDF. See `docs/limitations.md` for the later-phase roadmap (B-LT/B-LTA, full
//! PDF/A, EUDI attestation).

#![forbid(unsafe_code)]
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

pub mod crypto;
pub mod effects;
pub mod evidence;
pub mod pades;
pub mod session;
pub mod signing;
pub mod timestamp;
pub mod types;
pub mod util;
pub mod verification;
pub mod wire;

pub use effects::{HttpEffect, HttpMethod, RedirectEffect, Step};
pub use evidence::{SignerIdentity, SigningEvidenceRecord, SigningOutcome, TimestampInfo};
pub use session::{SigningPhase, SigningSessionHandle};
pub use signing::{begin, resume, CoreError, HostContext, ResumeInput};
pub use types::{
    AppearanceShow, ConformanceLevel, CscApi, Environment, ExpectedSignerIdentity, MatchOn, Rect,
    RequestOptions, Secret, SignatureAppearance, SignatureMeta, SignedDocument, SigningRequest,
    TrustServiceConfiguration, TsaConfiguration,
};
pub use verification::{verify_pdf, PdfSigner, PdfVerification, VerificationReason};

/// Wire schema version for the CBOR FFI/WASM boundary and the session handle.
pub const SCHEMA_VERSION: u32 = 1;
