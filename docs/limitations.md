# Known limitations & remaining work

Honest status of the Cleverbase SDK Phase-1 signing slice. The core signing capability (PAdES
B-B/B-T, RSA + ECDSA, all three bindings, frontend helper) is implemented and tested, with
independent OpenSSL validation. The items below are deliberately deferred, blocked, or partial.

## Blocked on external input

- **Live acceptance / production signing** (tasks T061/T064/T065 and any real-signer flow) requires a
  **Cleverbase client registration** (`client_id`/`client_secret` + registered redirect URI),
  which is obtained through a sales-led onboarding. Until then, the flow is validated offline with
  recorded-shape fixtures and a synthetic test PKI. This is the one genuine external dependency.
- **B-T against a real qualified TSA**: tested against a local OpenSSL TSA. Production B-T needs a
  contracted qualified Time-Stamping Authority endpoint (Cleverbase provides none).

## Partial / approximate

- **Independent validation** uses **OpenSSL `cms -verify`** (signature, message-digest binding,
  chain to CA) and the OpenSSL TSA for B-T. A deeper **EU DSS** PAdES-conformance/qualification
  gate (and **veraPDF** for PDF/A) is the intended next validation layer.
- **PDF/A**: input PDF/A is *detected* and the output `pdf_a` flag is set conservatively
  (invisible signatures only). Full PDF/A-preserving signing (embedded fonts for visible
  appearances, OutputIntent/XMP fidelity) + veraPDF validation is not yet implemented (FR-017 /
  T040 partial).
- **Multiple signatures / FR-010**: the container currently re-serializes the PDF (full save),
  which is correct for a first signature but does **not** preserve prior signatures. True
  incremental-update signing is required to add a signature without invalidating existing ones
  (T030). Until then, an **already-signed input PDF is rejected** at `begin` with a clear
  `InvalidDocument` outcome (it is never silently corrupted by signing into the existing slot).
- **Dual-algorithm independent validation**: RSA is OpenSSL-validated end-to-end; ECDSA P-256 is
  validated at the CMS layer (assemble + verify) and the state machine is algorithm-agnostic. A
  full ECDSA flow + OpenSSL/DSS validation pass is outstanding (T031).

## Mechanical / not yet done

- CI matrix across Linux (glibc/musl) / macOS / Windows; packaging & publishing of prebuilt
  artifacts (wheels, napi prebuilds, cdylib releases) — a starter CI workflow exists.
- ≥95% coverage gate enforcement in CI (coverage tooling configured conceptually; gate not wired).
- Per-binding full-signature tests + cross-language parity harness (bindings are tested at the
  begin/resume protocol level today); language demos; API reference docs.
- WASM surface (T020): **not required** — the frontend helper performs no crypto, so no in-browser
  core is needed.

## Roadmap (later phases, architected-for)

PAdES B-LT / B-LTA + LTV; the pluggable eIDAS **ValidationBackend** (self-hosted DSS/pyHanko
sidecar); non-PDF formats (CAdES/XAdES/JAdES); identification, authentication, and EUDI attestation
(OpenID4VCI/VP, SD-JWT VC, mdoc); **multi-tenant `account_token`** (HS256) routing and OIDC `sub`
identity matching — both need Cleverbase's exact multi-tenant contract and are not wired in Phase 1;
a **logo/image in the visible appearance** (Phase 1 renders text only — the image XObject embedding
+ input-format contract are deferred).
