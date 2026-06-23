# Contract: SDK Public API (signing operations)

The single logical contract every binding exposes. The core is **sans-IO**: callers drive a loop —
call an operation, perform whatever effect it returns, feed the result back — until `Done`/`Failed`.
Types reference [data-model.md](../data-model.md).

## Core operations (logical)

```text
begin(request: SigningRequest, config: TrustServiceConfiguration)
    -> (handle: SigningSessionHandle, step: Step)

resume(handle: SigningSessionHandle, input: ResumeInput)
    -> (handle: SigningSessionHandle, step: Step)
```

`SigningRequest` carries `document`, `conformance_level`, and the optional `expected_signer`
(FR-014), `appearance` (FR-016), and `signature_meta`. These optional parts are fully reachable
from every binding: Python/Node `begin_signing` takes an `options_json` argument (a JSON object with
`expected_signer` / `appearance` / `signature_meta`), and Go `BeginSigning` takes a
`*RequestOptions` struct.

`ResumeInput` is one of:
- `HttpResult { status, headers, body }` — the response to a prior `Step.PerformHttp`.
- `RedirectReturn { code, state }` — the OAuth `code`+`state` received at the integrator's
  `redirect_uri` after a prior `Step.Redirect`.
- `RedirectError { error, state }` — an OAuth error received at the `redirect_uri` instead of a
  code (e.g. `access_denied` when the signer declines in the wallet). The core validates `state`
  and resolves to a terminal `Declined` (for `access_denied`) or `AuthorizationExpired` outcome.
  Exposed by the bindings as `resume_redirect_error` / `resumeRedirectError` / `ResumeRedirectError`.

Host-injected clock and randomness are NOT `ResumeInput` variants: they are passed as a
`HostContext { now_unix, entropy }` argument on every `begin`/`resume` call, which keeps the core
deterministic (entropy MUST be ≥ 16 bytes).

`Step` (returned union) is exactly one of:
- `PerformHttp(HttpEffect)` — host performs the request (idempotent; retry on transport failure),
  then calls `resume` with `HttpResult`.
- `Redirect(RedirectEffect)` — host sends the signer's browser to `url`; on return, calls `resume`
  with `RedirectReturn`.
- `Done(SignedDocument, SigningEvidenceRecord)` — terminal success.
- `Failed(SigningEvidenceRecord)` — terminal failure; `evidence.outcome` ≠ `Signed`.

**Invariants**: the handle returned by each call supersedes the previous one and is the only state
to persist. `begin`/`resume` never block on I/O and never mutate shared state (thread-safe;
unbounded concurrency). `Failed` always carries an evidence record (FR-015).

## Idiomatic binding shapes (illustrative, same semantics)

The native bindings return a CBOR `{ handle, step }`; the host loops on `step.kind`
(`redirect` | `perform_http` | `done` | `failed`) and calls the matching resume function.

TypeScript / Node:
```ts
const { handle, step } = decode(cleverbase.beginSigning(
  document, env, cscApi, clientId, clientSecret, redirectUri, conformance, now, entropy, tsaUrl, optionsJson));
// on step.kind:
//   "redirect"     → resumeRedirect(handle, code, state, now, entropy)
//                    (or resumeRedirectError(handle, error, state, now, entropy) on decline)
//   "perform_http" → resumeHttp(handle, status, body, now, entropy)
```

Python:
```python
out = cleverbase.begin_signing(
    document, env, csc_api, client_id, client_secret, redirect_uri, conformance, now, entropy, tsa_url, options_json)
# loop: resume_redirect(...) | resume_redirect_error(...) | resume_http(...)
```

Go (over the C-ABI; CBOR under the hood, typed wrapper on top):
```go
sess, err := cleverbase.BeginSigning(document, cfg, conformance, opts, now, entropy)
// loop: cleverbase.ResumeRedirect(...) | ResumeRedirectError(...) | ResumeHTTP(...)
```

Bindings MAY add a convenience driver that runs the loop given host-provided `doHttp` and
`onRedirect` callbacks — but it MUST be a thin wrapper over `begin`/`resume` (no protocol logic).

## C-ABI surface (Go / WASM)

Coarse, stable, CBOR-in/result-out (mirrors `scal3`):
```c
int  cleverbase_process(const uint8_t* in, size_t in_len, uint8_t** out, size_t* out_len);
void cleverbase_free(uint8_t* out, size_t out_len);
```
`in` = CBOR `{ op: "begin"|"resume", ... }`; `out` = CBOR `{ handle, step }` or `{ error }`. The
CBOR schema is **versioned** (`schema_version`); compatible within a SemVer major (Principle VII).

## Error model

- **Protocol/terminal failures** are NOT exceptions — they are `Step.Failed` with a typed
  `SigningOutcome` (`Declined`, `AuthorizationExpired`, `CredentialUnavailable`, `IdentityMismatch`,
  `TimestampFailed`, `InvalidDocument`, `AppearancePlacementError`, `SignatureInvalid`).
- **Programmer/usage errors** (malformed handle, schema mismatch, missing required config) surface
  as the binding's native error type / exception.
- No secret material (client_secret, SAD, tokens) appears in any error message or evidence record
  (Principle IV).

## Versioning

SemVer. The C-ABI symbol set and the CBOR `schema_version` are stable within a major version;
bindings expose `cleverbase.coreVersion()` and refuse a handle whose `schema_version` they cannot
read.
