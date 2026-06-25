//! Opt-in eIDAS qualified-status determination (ETSI TS 119 615 v1.4.1 cl. 4.12).
//!
//! Over the always-on bar, an **opt-in**, version-pinned determination of whether an issuer's
//! `EAA/Q` trust-service entry was `granted` at the relevant time — reusing the [`crate::trust`]
//! primitives. Off by default; never assumes "qualified" (honest `Indeterminate` when trust-list
//! data is absent/ambiguous/unreachable).
//!
//! Filled in by task **T019** (preceded by the failing tests in **T018**). This is currently a
//! scaffold module; no public items yet.
