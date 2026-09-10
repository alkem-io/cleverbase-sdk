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
