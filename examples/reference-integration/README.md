# Cleverbase Remote-QES Reference Integration

A runnable, deployable three-tier example of signing a PDF with the Cleverbase remote-QES signing SDK. Cleverbase signs **hashes only** — the SDK (Rust core plus a Go cgo binding) owns the entire AdES/PAdES stack — and this integration runs the full signing journey **without Cleverbase credentials** by swapping the upstream for a bundled mock; switching fixtures → live is a configuration change only.

## Architecture

```
                          opaque correlation ids,
                          redirect URLs, code/state
                          (no secrets, no crypto)
  ┌─────────────────┐    ◄──────────────────────►    ┌──────────────────────────────┐
  │  browser / web  │                                 │       signing-service        │
  │   (no crypto)   │  ─── POST /v1/sign/start ─────► │  Go + cgo  (:8080)           │
  │   static :8080  │  ─── POST /v1/sign/complete ──► │  holds ALL secrets +         │
  │                 │  ─── GET  /v1/sign/status ────► │  the SDK session handle;     │
  │                 │  ◄── redirectUrl / status ───── │  drives SDK begin / resume   │
  └─────────────────┘                                 └───────────────┬──────────────┘
                                                                      │ cgo
                                                                      ▼
                                                       ┌──────────────────────────────┐
                                                       │       Rust core (SDK)        │
                                                       │  AdES/PAdES, emits HTTP       │
                                                       │  effects (hash only upstream) │
                                                       └───────────────┬──────────────┘
                                                                       │ HTTP effects
                                                                       │ performed by
                                                                       │ signing-service
              ┌────────────────────────────────────────────────────────┤
              ▼                                                          ▼
  ┌────────────────────────────┐                          ┌────────────────────────────┐
  │  upstream CSC / OIDC        │                          │  TSA  (RFC 3161)            │
  │  mock-upstream  (:9000)     │                          │  mock: openssl-backed /tsr  │
  │  in fixtures /  Cleverbase  │                          │  (B-T conformance only)     │
  │  in live                    │                          │  live: REFSVC_TSA_URL       │
  └────────────────────────────┘                          └────────────────────────────┘

  Only the document HASH crosses to the upstream. The PDF never leaves the backend.
```

## Components

| Component | Path | Listen | Role |
|-----------|------|--------|------|
| signing-service | `signing-service/` (`cmd/refsvc`) | `:8080` | Go backend; embeds the SDK via cgo, holds all secrets and the SDK session handle, performs the SDK's HTTP effects, exposes the REST API. |
| web | `web/` (static bundle) | `:8080` | Thin no-crypto TypeScript frontend on `frontend/helper-ts`; carries only correlation ids, redirect URLs, and OAuth `code`/`state`. |
| mock-upstream | `mock-upstream/` (`cmd/mockupstream`) | `:9000` | Credential-free stand-in for Cleverbase's CSC/OIDC surface, serving the SDK's recorded fixtures; shells `openssl` for an RFC 3161 TSA at `/tsr`. |

## REST API

Base path `/v1`. All `/v1/sign/*` endpoints require `Authorization: Bearer <REFSVC_API_KEY>` when auth is enabled (the default). A missing or invalid key returns `401 { "error": "unauthorized" }` before any work. `correlationId` is an opaque, server-issued id; no secrets, tokens, or SDK handles appear in any response — only the signed PDF bytes on `result`.

### `POST /v1/sign/start`

Begin a signing session. Calls the SDK `begin`, retains the PDF server-side, and returns the service-scope authorization redirect.

Request:

```json
{
  "document": "<base64 PDF>",
  "conformanceLevel": "B-B",
  "expectedSigner": { "matchOn": "certificate_serial_number", "value": "PNONL-…" }
}
```

- `document` — optional; omit to use the bundled sample PDF.
- `conformanceLevel` — optional `B-B` | `B-T`; omit to use `REFSVC_DEFAULT_CONFORMANCE` (else `B-B`).
- `expectedSigner` — optional identity pin (`matchOn` + `value`).

Response `200`:

```json
{ "redirectUrl": "https://…/oauth2/authorize?…", "correlationId": "…" }
```

### `POST /v1/sign/complete`

Advance the flow after a browser redirect returns to the registered `redirect_uri`. This flow has **two** authorization redirects (service-scope login, then credential-scope / SCAL2 hash authorization), so the first `complete` returns `status: "authorizing"` together with a second `redirectUrl` to follow; the second `complete` carries the session to a terminal status.

Request (success):

```json
{ "code": "<oauth code>", "state": "<oauth state>" }
```

Request (decline or OAuth error):

```json
{ "error": "access_denied", "state": "<oauth state>" }
```

Response `200`:

```json
{ "status": "authorizing", "redirectUrl": "https://…/oauth2/authorize?scope=credential…" }
```

`redirectUrl` is present only when a further redirect is required; it is absent once the session is terminal. `reason` is present when `status` is `failed`.

### `GET /v1/sign/status?correlationId=…`

Response `200`:

```json
{ "status": "pending", "reason": "<code>" }
```

`reason` is present and required only when `status` is `failed`.

### `GET /v1/sign/result?correlationId=…`

Returns the signed PDF (`Content-Type: application/pdf`) once the session is `completed`, with the evidence record in a base64 `X-Signature-Evidence` header. Returns `409` if the session is not yet completed.

### `GET /healthz` · `GET /readyz`

Unauthenticated. `200 { "status": "ok" }` when healthy/ready (ready = config valid + SDK loaded). Used for orchestration liveness/readiness probes.

### Status and failure codes

| `status` | Meaning |
|----------|---------|
| `pending` | Session created, awaiting the first authorization redirect to return. |
| `authorizing` | A further authorization redirect (credential scope / SCAL2) is required. |
| `completed` | Signed PDF available at `result`. |
| `declined` | The signer declined or an OAuth error ended the flow. |
| `failed` | Terminal error; `reason` is set. |

When `status` is `failed`, `reason` is a snake_case code from the authoritative `failed` reason set
defined in [`specs/002-reference-integration/contracts/reference-service-api.md`](../../specs/002-reference-integration/contracts/reference-service-api.md):
the seven SDK `SigningOutcome` failure codes — `authorization_expired` · `credential_unavailable` ·
`identity_mismatch` · `invalid_document` · `timestamp_failed` · `appearance_placement_error` ·
`signature_invalid` — plus the service-operational codes `upstream_error`, `resume_error`,
`session_expired`, and the defensive catch-all `unknown`.

## Configuration

### signing-service (`REFSVC_*`)

| Variable | Default | Notes |
|----------|---------|-------|
| `REFSVC_MODE` | `fixtures` | `fixtures` (mock upstream) or `live` (Cleverbase). |
| `REFSVC_BASE_URL` | — | Mock upstream base URL; **required in fixtures mode**. |
| `REFSVC_ENV` | `acceptance` | `acceptance` or `production`. |
| `REFSVC_CSC_API` | `v1_rsa` | `v1_rsa` or `v2_ecdsa`. |
| `REFSVC_CLIENT_ID` | — | OAuth client id (**required in live**). |
| `REFSVC_CLIENT_SECRET` | — | OAuth client secret (**required in live**). |
| `REFSVC_REDIRECT_URI` | — | Registered redirect URI (**required in live**). |
| `REFSVC_TSA_URL` | — | RFC 3161 TSA endpoint (required in live for B-T). |
| `REFSVC_TSA_AUTH` | — | Optional TSA authorization header value. |
| `REFSVC_TSA_POLICY` | — | Optional TSA policy OID (live B-T). |
| `REFSVC_API_KEY` | — | Bearer key for the service's REST API; auth is on by default. |
| `REFSVC_AUTH_DISABLED` | `false` | Set `true` to run without a key in local fixtures only. |
| `REFSVC_DEFAULT_CONFORMANCE` | `B-B` | `B-B` or `B-T` when a request omits `conformanceLevel`. |
| `REFSVC_SESSION_TTL` | `15m` | In-flight session lifetime before eviction. |
| `REFSVC_LISTEN` | `:8080` | Listen address. |

In fixtures mode the service supplies harmless default credentials (the mock ignores them) and defaults `REFSVC_TSA_URL` to `<REFSVC_BASE_URL>/tsr`, so a fixtures run needs no Cleverbase credentials.

### mock-upstream (`REFMOCK_*`)

| Variable | Default | Notes |
|----------|---------|-------|
| `REFMOCK_FIXTURES_DIR` | `/fixtures` | Directory of recorded SDK fixtures + synthetic PKI. |
| `REFMOCK_LISTEN` | `:9000` | Listen address. |

## Run credential-free locally

Bring up the mock, the signing-service, and the web frontend in fixtures mode:

```bash
docker compose -f deploy/compose.yml up --build
```

Then drive the flow. The examples below assume the API key is exported as `REFSVC_API_KEY`:

```bash
export REFSVC_API_KEY=local-dev-key   # the same value the service was started with

# 1. Start a session (omit "document" to use the bundled sample PDF).
curl -s -X POST http://localhost:8080/v1/sign/start \
  -H "Authorization: Bearer $REFSVC_API_KEY" \
  -H 'content-type: application/json' \
  -d '{ "conformanceLevel": "B-B" }'
# → { "redirectUrl": "http://localhost:9000/oauth2/authorize?…", "correlationId": "…" }

# 2. Follow redirectUrl in a browser (or, headless against the mock, GET it and read the
#    code+state from the redirect back to the return route). Then complete the first redirect.
curl -s -X POST http://localhost:8080/v1/sign/complete \
  -H "Authorization: Bearer $REFSVC_API_KEY" \
  -H 'content-type: application/json' \
  -d '{ "code": "<code-1>", "state": "<state-1>" }'
# → { "status": "authorizing", "redirectUrl": "http://localhost:9000/oauth2/authorize?scope=credential…" }

# 3. Follow the second (credential-scope) redirectUrl, then complete again.
curl -s -X POST http://localhost:8080/v1/sign/complete \
  -H "Authorization: Bearer $REFSVC_API_KEY" \
  -H 'content-type: application/json' \
  -d '{ "code": "<code-2>", "state": "<state-2>" }'
# → { "status": "completed" }

# 4. Poll status.
curl -s "http://localhost:8080/v1/sign/status?correlationId=<id>" \
  -H "Authorization: Bearer $REFSVC_API_KEY"
# → { "status": "completed" }

# 5. Fetch the signed PDF (and capture the evidence header).
curl -s -D - "http://localhost:8080/v1/sign/result?correlationId=<id>" \
  -H "Authorization: Bearer $REFSVC_API_KEY" \
  -o signed.pdf
# response headers include: X-Signature-Evidence: <base64 json>
```

For a no-key local run, start the service with `REFSVC_AUTH_DISABLED=true` and drop the `Authorization` header.

## Go live

Switching to live Cleverbase acceptance is **configuration only** — no code or image change:

1. Set `REFSVC_MODE=live`.
2. Provide `REFSVC_CLIENT_ID`, `REFSVC_CLIENT_SECRET`, and `REFSVC_REDIRECT_URI`.
3. Register that redirect URI with Cleverbase.
4. For B-T, set `REFSVC_TSA_URL` (plus `REFSVC_TSA_AUTH` / `REFSVC_TSA_POLICY` if your TSA requires them).

`REFSVC_BASE_URL` and the mock-upstream are dropped in live; everything else is unchanged.

## Deploy to Kubernetes

Kustomize overlays select the mode:

```bash
kubectl apply -k deploy/k8s/overlays/fixtures   # credential-free, with the mock
kubectl apply -k deploy/k8s/overlays/live       # live Cleverbase (supply secrets)
```

## Verify image provenance

Published images are cosign-signed (keyless) and SBOM-attested:

```bash
cosign verify ghcr.io/<owner>/cleverbase-refsvc:<tag>
cosign verify-attestation --type spdxjson ghcr.io/<owner>/cleverbase-refsvc:<tag>
```

## Session store

The default `SessionStore` is **in-memory and single-instance**. It holds in-flight session state (including the SDK handle) until the session reaches a terminal status or its `REFSVC_SESSION_TTL` expires. A shared, persistent store (for example Redis) is the documented extension point behind the `SessionStore` interface for multi-replica or durable deployments. With the default store, a backend restart loses in-flight sessions — an acceptable trade-off for this reference, since each session is human-paced and can simply be restarted.

## Synthetic PKI notice

The synthetic CA, signer, and TSA keys/certificates under `tests/fixtures/pki/` exist **only** to make fixtures mode runnable offline. They are test material — never use them as production keys or trust anchors.
