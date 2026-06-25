//! ISO/IEC 18013-5 mdoc verification.
//!
//! Verifies a presented mdoc `DeviceResponse`: the `IssuerAuth` `COSE_Sign1` (via `ciborium` +
//! `coset` + the SDK's RustCrypto), the in-house recompute-and-match of `valueDigests`
//! (selective-disclosure integrity), the MSO `validityInfo` window, and the `DeviceAuth` holder
//! binding — the security-critical checks `isomdl` omits.
//!
//! Filled in by task **T012** (preceded by the failing tests in **T008**). This is currently a
//! scaffold module; no public items yet.
