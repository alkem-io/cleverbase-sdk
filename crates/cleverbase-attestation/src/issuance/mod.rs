//! Forward-looking, **gated** issuance + holder presentation (OpenID4VCI / OpenID4VP).
//!
//! Drives OpenID4VCI `obtain` and holder OpenID4VP `present` through the spec-001 **signer-hook**
//! (the integrator's HSM/KMS signs; the SDK never holds the private key — not a wallet, FR-009). The
//! issuer is a configurable backend; the live path is **skipped** when no issuer API is configured
//! (`kind = None`), so a future Cleverbase issuer drops in by configuration.
//!
//! Filled in by tasks **T024–T028** (preceded by the failing/gated tests in **T021–T023**). This is
//! currently a scaffold module; no public items yet.
