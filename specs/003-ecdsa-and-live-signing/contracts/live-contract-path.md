# Contract: live contract path (`e2e/live_test.go`)

A **gated** test that drives a full signing journey against the **real Cleverbase** service and
independently verifies the result against the **real** trust chain (US2). Replaces today's smoke stub.

## Gating (FR-009)

- Runs only when the required real-credential env is present (`REFSVC_CLIENT_ID`, `REFSVC_CLIENT_SECRET`,
  `REFSVC_REDIRECT_URI`, and a credential on the account). Absent → `t.Skip` (reported skipped, **never
  failed**); the credential-free suite runs and passes unchanged.
- Secrets are CI-secret-only; never committed, never logged (FR-010).
- Not part of the default credential-free pipeline; lives in an opt-in `live.yml` job.

## Flow (driven via the existing service API)

```
POST /v1/sign/start            -> { redirectUrl (service-scope authorize), correlationId }
Authorizer.Authorize(url, st)  -> (code, state)        # interactive human / headless
POST /v1/sign/complete {code,state}                    # -> next redirect (credential-scope / SCAL2)
Authorizer.Authorize(url2, st2)-> (code2, state2)      # SCAL2 approval binds the document hash
POST /v1/sign/complete {code2,state2}                  # -> signing completes
GET  /v1/sign/result           -> signed PDF (+ evidence header)
verify(pdf, REFSVC_LIVE_CA_BUNDLE)                     # always-on OpenSSL bar, real chain
```

## Config knobs (see data-model `LiveRunConfig`)

Existing: `REFSVC_MODE` (`fixtures` default | `live` — the master mode switch the live knobs depend on),
`REFSVC_CLIENT_ID/SECRET`, `REFSVC_REDIRECT_URI`, `REFSVC_ENV` (default `acceptance`),
`REFSVC_CSC_API`, `REFSVC_TSA_URL`. **New**: `REFSVC_LIVE_AUTHORIZER` (`interactive` default | `headless`),
`REFSVC_LIVE_CA_BUNDLE` (real Cleverbase issuer chain PEM for verification).

## Coverage rules (clarified in spec)

- **Algorithms** (FR-007): exercise both RSA (v1) and ECDSA (v2) when credentials for both exist; **pass on
  at least one** verified. A single available credential is sufficient.
- **Conformance** (FR-015): **B-B required**; additionally **B-T when `REFSVC_TSA_URL` is set**; a missing
  TSA MUST NOT block the live run.
- **Verification** (FR-008): the produced signature MUST verify against the **real** Cleverbase-issued
  signer cert + issuer chain (`REFSVC_LIVE_CA_BUNDLE`), reusing the algorithm-agnostic `validateCMS`.

## Failure semantics (FR-011)

- Service/credential/authorization failures (expired/invalid credential, declined approval, network) MUST
  produce a clear, actionable error that distinguishes a **dependency problem** from an **SDK defect**.
- A verification failure against the real chain is a hard failure (the contract test caught a real-surface
  regression) — never a silent pass.

## Test (must fail first)

- With a stub real-service double (or recorded acceptance responses), assert the full
  start→complete×2→result→verify path and the skip-when-absent gate. The live job itself runs the real
  flow when secrets are present.
</content>
