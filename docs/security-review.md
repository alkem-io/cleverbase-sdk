# Security review — Phase 1 (signing)

Review of the Cleverbase SDK against Constitution Principle IV (Security & Cryptographic Rigor) and
the spec's security requirements. Status: **pass with documented follow-ups**.

## Secret handling

- Secrets (`client_secret`, SAD, access tokens) are modeled by a `Secret` newtype whose `Debug`
  redacts to `Secret(***)` (unit-tested) — they never appear in logs/diagnostics by default.
- Failure reasons and the evidence record never embed secret material.
- The session handle may carry short-lived authorization material (service Bearer, request/config);
  the API contract and README require it to be **stored encrypted, server-side only**.

## No crypto / no secrets in the frontend

- The TS frontend helper performs no cryptography and transmits only redirect URLs, an opaque
  correlation id, and the OAuth `code`/`state`. A test asserts no `client_secret`/`SAD`/handle/
  private-key material appears in any request it makes (US3 / SC-005).
- **No embedded wallet / no PIN handling in the core**: the user authorizes in Cleverbase's own
  wallet app; the SDK never sees or reconstructs PINs or wallet credentials.

## Cryptographic rigor

- Memory-safe core (`#![forbid(unsafe_code)]` in `cleverbase-core`; the only `unsafe` is the small,
  documented C-ABI boundary in `cleverbase-ffi`).
- No hand-rolled crypto: SHA-256/RSA/ECDSA/CMS/X.509/ASN.1 all use vetted RustCrypto crates.
- WYSIWYS: the document hash is bound into the credential authorization and is exactly the hash sent
  to `signHash` (unit-tested), so the signer authorizes precisely what is signed.
- Detached, external-signature CMS: the private key never exists in the SDK — Cleverbase signs the
  hash; the SDK assembles the container.

## Independent validation

- Produced PAdES B-B and B-T signatures (**RSA**) are verified by **OpenSSL** (independent of our
  code): signature validity, message-digest binding over the ByteRange, and chain to the (test) CA.
  The ECDSA P-256 path is verified at the CMS layer (assembly + in-crate `verify_signed_data`); a
  full ECDSA OpenSSL/DSS end-to-end pass is outstanding (see docs/limitations.md).

## Follow-ups (see docs/limitations.md)

- Deeper eIDAS validation via EU DSS; PDF/A preservation + veraPDF; incremental-update multi-sig;
  transport-layer hardening guidance for the host performing the emitted HTTP effects (TLS pinning,
  timeouts, retry/idempotency policy); secret-at-rest encryption guidance for the session handle.
- Live validation against the Cleverbase acceptance/production environments is pending client
  registration (external onboarding).
