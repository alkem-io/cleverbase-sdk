# Security Model — Reference Integration

This reference integration is structured so that the browser tier handles **no cryptography and holds no secrets**. This document summarizes its threat surface and the guarantees the design provides.

## Trust boundary

The trust boundary sits at the signing-service. Everything sensitive lives behind it; the frontend is an untrusted, no-crypto helper.

- **API authentication.** The REST API is gated by a bearer API key (`REFSVC_API_KEY`). Auth is **on by default**; a missing or invalid key is rejected with `401` before any work is done. `REFSVC_AUTH_DISABLED=true` exists only for local fixtures runs.
- **Secrets stay server-side.** The OAuth client secret, OAuth tokens, the signature activation data (SAD), and the SDK session handle never leave the signing-service. They are not serialized into any REST response and are never sent to the frontend.
- **The frontend carries only opaque material.** Across the browser tier flow only correlation ids, redirect URLs, and the OAuth `code`/`state` — none of which is a secret on its own.
- **Only the hash goes upstream.** Cleverbase signs hashes only; the SDK sends just the document hash to the upstream. The PDF itself never leaves the backend.

## Data handling in the session store

The default in-memory `SessionStore` holds session state — including the SDK handle and the retained PDF — only while the session is in flight. State is held until the session reaches a terminal status (`completed` / `declined` / `failed`) or its `REFSVC_SESSION_TTL` elapses, and is scrubbed from the store on completion. Because the store is in-memory and single-instance, a backend restart discards in-flight session state rather than persisting secrets.

## Supply chain

- Published images are **cosign-signed** (keyless) and carry **SBOM attestations**; verify both before deploying (see the README's "Verify image provenance").
- All images run as a non-root user. The signing-service and web images are distroless (`gcr.io/distroless/cc-debian12:nonroot` and `gcr.io/distroless/static-debian12:nonroot`). The mock-upstream image is a slim Debian non-root image (`debian:bookworm-slim`) that bundles `openssl`, which it needs at runtime to run the test RFC 3161 TSA; it is therefore not distroless.

## Fixtures PKI

The PKI under `tests/fixtures/pki/` (CA, signer, and TSA keys and certificates) is **synthetic and test-only**. It makes fixtures mode runnable offline and must never be used as a production key or trust anchor.
