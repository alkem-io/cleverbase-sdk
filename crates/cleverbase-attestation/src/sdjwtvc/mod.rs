//! SD-JWT VC (RFC 9901 / draft-16) verification.
//!
//! Verifies a presented SD-JWT VC: the issuer-signed compact JWS (in-house verify over the SDK's
//! RustCrypto), the selective-disclosure digests via `sd-jwt-payload` (hashing delegated to the
//! SDK's `sha2`), the `vct` type metadata, and the holder Key-Binding JWT (`aud`/`nonce`/`sd_hash`).
//!
//! Filled in by task **T011** (preceded by the failing tests in **T007**). This is currently a
//! scaffold module; no public items yet.
