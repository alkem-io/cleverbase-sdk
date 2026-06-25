# Contract: Authorizer (E2E live harness)

The pluggable seam for the Cleverbase user-authorization (OIDC/SCAL2) step. It lives in the **E2E test
harness** (`examples/reference-integration/signing-service/e2e/`), not in the SDK or the signing service —
the driving loop only needs `(code, state)` to call `/v1/sign/complete`, so swapping authorizers changes
nothing in the core/flow (FR-013, research D5).

## Interface

```go
// Authorizer completes one Cleverbase redirect (service-scope, then credential-scope/SCAL2) and returns
// the OIDC callback parameters. It is the only thing that differs between credential-free and live runs
// and between human-in-the-loop and headless live runs.
type Authorizer interface {
    // Authorize is given the authorize URL the flow produced and the CSRF state it expects back. It
    // returns the (code, state) to feed into POST /v1/sign/complete, or an error.
    Authorize(ctx context.Context, authorizeURL string, expectState string) (code string, state string, err error)
}
```

## Implementations

| Impl | Selected by | Behaviour |
|------|-------------|-----------|
| `mockAutoApprove` | credential-free runs | GETs the mock's auto-approving authorize endpoint (today's `followRedirect`); refactored to satisfy the interface. |
| `Interactive` | `REFSVC_LIVE_AUTHORIZER=interactive` (default, live) | Prints/surfaces the authorize URL; captures the redirect callback (stdin paste or a local redirect-capture listener at `REFSVC_REDIRECT_URI`); returns the captured `code,state`. Works the day real credentials arrive. |
| `Headless` | `REFSVC_LIVE_AUTHORIZER=headless` (opt-in, live) | Drives an automatable Cleverbase test-credential approval to obtain `code,state`. Added when such a test approval exists; **must drop in without reworking the loop**. |

## Behavioural contract

- MUST be called **once per redirect** — twice per signing flow (service-scope authorize, then
  credential-scope/SCAL2 authorize that binds the document hash).
- MUST return the `state` it received from Cleverbase; the service re-checks it (CSRF) — a mismatch MUST
  surface as a clear error, not a silent pass.
- On signer decline / `access_denied`, MUST return an error that the live path maps to a clear
  "authorization declined" outcome (distinct from an SDK defect — FR-011).
- On timeout (human did not approve within the window), MUST fail fast with "authorization not completed",
  never hang (Edge Cases).
- MUST NOT log secrets (codes, tokens) — FR-010.

## Test (must fail first)

- A harness test with a stub `Authorizer` asserts `runFlow` calls `Authorize` exactly twice and feeds the
  returned `code,state` into `/v1/sign/complete` unchanged. (Proves the seam is loop-agnostic.)
</content>
