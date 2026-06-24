# Contract: Reference Signing Service REST API

The backend the web frontend (and any host app) calls. It implements the contract the SDK's
`frontend/helper-ts` expects (`startUrl`/`completeUrl`/`statusUrl`) plus result retrieval and health.
All bodies are JSON unless noted. The **upstream** Cleverbase CSC/OIDC + TSA contract the service
drives is NOT re-specified here — see `specs/001-remote-qes-signing/contracts/external-dependencies.md`
(single source); the mock upstream implements that subset.

## Conventions

- Base path: `/v1`. Auth: `Authorization: Bearer <REFSVC_API_KEY>` required on `/v1/sign/*` when auth
  is enabled (default). Missing/invalid → `401` with `{ "error": "unauthorized" }`, before any work.
- `correlationId` is an opaque server-issued id. No secrets, tokens, or handles ever appear in any
  response except the signed PDF bytes on `result`.
- Errors: `{ "error": "<code>", "message": "<human text>" }` with an appropriate 4xx/5xx status.

## `POST /v1/sign/start`

Begin a signing session.

- **Request**:
  ```json
  {
    "document": "<base64 PDF>",            // or omitted to use the bundled sample
    "conformanceLevel": "B-B",              // "B-B" | "B-T"; omit to use REFSVC_DEFAULT_CONFORMANCE (else "B-B")
    "expectedSigner": { "matchOn": "certificate_serial_number", "value": "PNONL-…" }, // optional
    "appearance": { "page": 1, "rect": { "x": 50, "y": 50, "w": 200, "h": 80 }, "show": { "signerName": true } } // optional
  }
  ```
- **Response 200** (matches the helper's `StartResult`):
  ```json
  { "redirectUrl": "https://…/oauth2/authorize?…", "correlationId": "…" }
  ```
- **Behavior**: calls the SDK `begin`; stores the session; returns the service-scope authorization
  redirect URL. The PDF is retained server-side; only its hash is ever sent upstream.
- **Errors**: `400` invalid document/options; `401` auth; `500` internal.

## `POST /v1/sign/complete`

Advance the flow after a browser redirect returns to the registered `redirect_uri`.

- **Request** (one of):
  ```json
  { "code": "<oauth code>", "state": "<oauth state>" }
  ```
  ```json
  { "error": "access_denied", "state": "<oauth state>" }
  ```
- **Response 200**:
  ```json
  { "status": "authorizing", "redirectUrl": "https://…/oauth2/authorize?scope=credential…" }
  ```
  `redirectUrl` is present when a further authorization redirect is required (the credential-scope /
  SCAL2 step); absent once the session is terminal.
- **Behavior**: resolves the pending session by `state`, calls `resume` with the redirect result,
  performs the resulting HTTP effects against the upstream, and returns the next `status`
  (+ `redirectUrl` if another redirect is needed).
- **Errors**: `400` unknown/expired/already-consumed `state` or malformed body; `401` auth; `500`
  internal resume failure. (The pending `state` is one-shot: it is de-indexed when the session
  becomes terminal, so a replay of a consumed `state` resolves as `400` unknown — there is no
  separate `409`.)

## `GET /v1/sign/status?correlationId=…`

- **Response 200**: `{ "status": "pending" | "authorizing" | "completed" | "declined" | "failed", "reason": "<code>" }`
- `reason` is present (and required) **only** when `status == "failed"`. This is the **authoritative**
  `failed` reason set: all codes are **snake_case** (matching the Rust core's `SigningOutcome`
  serialization), and the service emits exactly one of these eleven:
  - the seven SDK `SigningOutcome` failure codes — `authorization_expired` · `credential_unavailable`
    · `identity_mismatch` · `invalid_document` · `timestamp_failed` · `appearance_placement_error` ·
    `signature_invalid` (passed through verbatim from the evidence `outcome`); or
  - a service-operational failure code — `upstream_error` (an upstream call failed),
    `resume_error` (the SDK could not advance), or `session_expired` (the session TTL elapsed); or
  - `unknown` — a defensive catch-all the flow engine emits for an unmapped/future SDK outcome.

  `completed` and `declined` are their own statuses and carry **no** `reason`; `reason` is absent for
  every non-failed status. All nine SDK terminal outcomes thus stay distinguishable.
- **Errors**: `404` unknown/expired correlation id; `401` auth.

## `GET /v1/sign/result?correlationId=…`

- **Response 200**: the signed PDF.
  - `Content-Type: application/pdf`; body = signed PDF bytes. Header `X-Signature-Evidence: <base64 json>`
    carries the evidence record.
- **Errors**: `404` unknown id; `409` not `completed`; `401` auth.

## `GET /healthz` · `GET /readyz`

- Unauthenticated. `200` with `{ "status": "ok" }` when healthy/ready (ready = config valid + SDK
  loaded). Used by container orchestration liveness/readiness probes.

## Notes for consumers

- The frontend wires `startUrl=/v1/sign/start`, `completeUrl=/v1/sign/complete`, `statusUrl=/v1/sign/status`
  into the helper; the registered `redirect_uri` is a frontend route that forwards `code`/`state` to
  `complete`.
- **Multi-redirect (SCAL2)**: this flow has **two** authorization redirects (service-scope login,
  then credential-scope hash authorization). `complete` returns a `redirectUrl` when a further
  redirect is required, so the helper's `complete()`/`reportRedirectError()` return a
  `CompleteResult` (`{ status, redirectUrl? }`) and the page MUST navigate to `redirectUrl` when
  present (looping back to the return route). `frontend/helper-ts` implements this: both methods
  resolve to `CompleteResult`, with `redirectUrl` set only while a further redirect is pending and
  omitted once the session is terminal.
- A host application can drive the same API directly (the credential-free CI E2E does exactly this,
  with no browser — it follows the `redirectUrl` against the mock to obtain the next `code`/`state`).
