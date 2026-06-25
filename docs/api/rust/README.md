# Rust API

Generated from the in-source rustdoc comments of the Rust workspace (rustdoc JSON → Markdown).

- [`cleverbase_core`](cleverbase_core.md) — the sans-IO protocol/crypto core (the state machine,
  PAdES/CMS assembly, RFC 3161 timestamping, the session handle).
- [`cleverbase_attestation`](cleverbase_attestation.md) — the sans-IO EUDI attestation core (SD-JWT VC
  + ISO 18013-5 mdoc verification, the native EU trust-list engine, OpenID4VP binding, and the gated
  OpenID4VCI/OpenID4VP issuance/presentation path).
- [`cleverbase_ffi`](cleverbase_ffi.md) — the stable C ABI over the core.
