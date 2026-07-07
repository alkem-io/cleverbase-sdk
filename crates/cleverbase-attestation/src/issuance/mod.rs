//! Forward-looking, **gated** issuance + holder presentation (OpenID4VCI / OpenID4VP) — US2.
//!
//! Drives OpenID4VCI `obtain` and holder OpenID4VP `present` through the spec-001 **signer-hook**
//! (research D8): the integrator's HSM/KMS signs out-of-process; the SDK never holds the holder
//! private key (not a wallet — FR-009). The issuer is a configurable backend ([`IssuerBackend`]); the
//! live path is **skipped** when no issuer API is configured (`kind = None`), so a future Cleverbase
//! issuer drops in by configuration.
//!
//! ## Sans-IO, mirroring the signing core
//!
//! Like `cleverbase_core::signing`, issuance is a **sans-IO state machine driven by host effects**.
//! [`begin_obtain`]/[`resume_obtain`] mirror the signing core's `begin`/`resume`: each call returns
//! an [`ObtainStep`] describing the next host effect (an HTTP request, or a holder **sign** via the
//! [`Signer`] hook) and the core advances only when the host feeds the result back. The holder key
//! never enters the core — the **sign** step is the exact analogue of the CSC `signHash` HTTP effect
//! (the host signs off-box and returns the bytes; the SDK splices them in).
//!
//! ## Modules
//!
//! - [`signer`] — the [`HolderContext`] + [`Signer`] hook and the deterministic [`SigningInput`]
//!   builders for the PoP-JWT / KB-JWT ceremonies (the splice helpers live with each builder).
//! - [`device`] — the mdoc `DeviceAuth` `DeviceSignature` ceremony (a detached COSE_Sign1).
//! - [`obtain`] — the configurable-backend OpenID4VCI flow + the **skip-when-`None`** gating.
//! - [`present`](mod@present) — the holder OpenID4VP present (selective disclosure, bound to the
//!   request).

pub mod device;
pub mod obtain;
pub mod present;
pub mod signer;
pub mod wire;

pub use obtain::{
    begin_obtain, resume_obtain, CredentialOffer, HttpEffect, HttpMethod, IssuerBackend,
    IssuerBackendKind, ObtainError, ObtainSession, ObtainStep, ResumeObtain,
};
pub use present::{
    prepare_present, present, HeldAttestation, HolderPresentation, PreparedPresentation,
    PresentError,
};
pub use signer::{
    build_kb_jwt, build_pop_jwt, Ceremony, HolderContext, KbJwtBuild, PopJwtBuild,
    SignatureAlgorithm, Signer, SignerError, SigningInput,
};
