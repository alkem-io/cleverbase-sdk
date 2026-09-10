# PAdES conformance regression fixture

`cleverbase-acceptance-dev-2026-09-10.pdf` is the first PDF produced by the complete Alkemio DEV
journey against Cleverbase acceptance on 2026-09-10. Its signer is Cleverbase's public test persona;
the PDF contains no client credentials, OAuth tokens, or signing-session state.

- SHA-256: `70fd4bb9cbf53bb9ba61ebce734756f8f135b86e2d95e11f28a7938a7e6d3f65`
- Signature and RFC 3161 timestamp token: cryptographically sound.
- Regression purpose: its `/ByteRange` excludes only the raw `/Contents` hex digits, its signature
  dictionary omits `/M` and `/Name`, and its CMS carries the PAdES-forbidden `signing-time`
  attribute. It must not be accepted as conformant output by the SDK verifier.

The synthetic fixture flow continues to generate all positive SDK output. This real-provider file
is retained only as the negative regression vector for the production defects it exposed.

## v0.3.1 in-flight session compatibility

`v0.3.1-timestamp-pending.cbor.b64` is a base64-encoded `TimestampPending` handle captured with the
released `bindings/go/v0.3.1` source (annotated tag object
`185fb7dd2f07d1740004197308bd20fbc8088dcd`, peeled commit
`372bf25fd6692776fb623acdd83140522124a4aa`). It was serialized from that tag's existing
`drive_bt_to_timestamp_pending()` fixture flow. It therefore contains only the repository's synthetic
test PDF, certificates, and fixture token strings; it contains no live credentials or user data.

- Decoded CBOR SHA-256: `2d829216a91e147fbfa2e0f2d97230ebff56b3d9dfc6257542ef8cf2c93d76f5`
- Matching tag-era `rsa.tsr` SHA-256:
  `31d085c27fcdf9e568db1230a872d0492c1e3ee756bcdd5a0a866d5e479c2699`
- Regression purpose: the released handle has no `timestamp_nonce`. Resuming it under v0.3.2 must
  fail closed with `BadHandle` and never emit `Done`; the user restarts the signing flow after upgrade.
