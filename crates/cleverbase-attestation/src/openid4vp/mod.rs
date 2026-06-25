//! OpenID4VP 1.0 verifier binding (DCQL request build + `vp_token` binding verify).
//!
//! Builds the presentation request (DCQL query + a fresh `nonce` + the verifier `audience`) and
//! verifies that a returned `vp_token` is cryptographically **bound** to it (nonce echo + audience),
//! for both credential formats — the replay / wrong-audience protection (FR-015).
//!
//! Filled in by task **T015** (preceded by the failing tests in **T010**). This is currently a
//! scaffold module; no public items yet.
