# Contract: External Dependencies (upstream services the core drives)

Informative — documents the upstream contracts the sans-IO core targets via `HttpEffect`/
`RedirectEffect`. Verified against Cleverbase's live services (see project memory
`cleverbase-signing-surface`).

## Cleverbase CSC signing API

- **v1 (production, RSA)** — base `https://connect.cleverbase.com` (acceptance:
  `https://connect.acc.cleverbase.com`). Operations the core uses:
  - `GET /oauth2/authorize` — `scope=service` then `scope=credential` (the latter carries the
    base64url **document hash** + `numSignatures`); OAuth Authorization Code; HTTP Basic client auth
    at the token endpoint.
  - `POST /oauth2/token` — exchanges `code` → Bearer (service) / SAD (credential).
  - `POST /csc/v1/credentials/list`, `POST /csc/v1/credentials/info` — discover credential + X.509
    chain + key algo + SCAL.
  - `POST /csc/v1/signatures/signHash` — returns the **raw signature value** only (no container).
- **v2 (beta, ECDSA-P256)** — `…/csc/v2/*`, `oauth2code` auth only; `signHash` only. Same shape; the
  core selects RSA vs ECDSA-P256 signature encoding per `config.csc_api`.
- **Completion** is the OAuth **redirect** back to `redirect_uri`. **No webhook exists.**
- **Not available** (verified): `signatures/signDoc`, `signatures/timestamp`, any AdES
  conformance level, validation info. SHA-256 is the only advertised hash.

## External Qualified Time-Stamping Authority (B-T)

- **RFC 3161** TSA, **external and qualified** (Cleverbase provides none). Configured via
  `TsaConfiguration.url` (+ optional auth, policy OID). The core emits a `TimeStampReq` over the
  signature value as an `HttpEffect`; the response `TimeStampToken` is embedded as the
  `signature-time-stamp` attribute. Procurement of a qualified TSA is a delivery dependency.

## Independent validators (test/CI only — not a runtime dependency)

- **OpenSSL** — the implemented independent validator: verifies the produced detached CMS (signature
  over the signed attributes, `message-digest` vs ByteRange content, cert chain) and plays the
  RFC 3161 TSA in tests (`crates/cleverbase-core/tests/independent_validation.rs`).
- **EU DSS** (PAdES B-B/B-T conformance) and **veraPDF** (PDF/A) are the intended next validation
  layer — not yet wired into code/CI (see docs/limitations.md).

## Out of scope this phase (architected-for)

Revocation sources (OCSP/CRL) for B-LT, archive timestamps for B-LTA, and the runtime eIDAS
**ValidationBackend** sidecar (EU DSS / pyHanko) are later phases; their seams exist in the core but
are not wired here.
