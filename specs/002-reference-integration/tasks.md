# Tasks: Reference Integration Services & Container Delivery

**Input**: Design documents from `/specs/002-reference-integration/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/reference-service-api.md, quickstart.md

**Tests**: REQUIRED (Constitution Principle VI — test-first; the signing service is held to ≥95% unit coverage). Test tasks are authored before the implementation they cover and MUST fail first.

**Organization**: by user story (US1 P1 = MVP, US2 P2, US3 P3). All paths are under `examples/reference-integration/` unless noted.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: parallelizable (different files, no incomplete-task dependency)
- **[Story]**: US1/US2/US3 (Setup/Foundational/Polish carry no story label)

---

## Phase 1: Setup (Shared Infrastructure)

- [x] T001 Create the `examples/reference-integration/` tree (`signing-service/`, `mock-upstream/`, `web/`, `deploy/`, `README.md`) per plan.md.
- [x] T002 [P] Initialize the Go module for the backend in `examples/reference-integration/signing-service/go.mod`, requiring the repo's `bindings/go` and `github.com/fxamacker/cbor/v2`.
- [x] T003 [P] Initialize the Go module for the mock in `examples/reference-integration/mock-upstream/go.mod`.
- [x] T004 [P] Initialize the web package in `examples/reference-integration/web/package.json` (depends on `frontend/helper-ts`; bundle with esbuild) + strict `tsconfig.json`.
- [x] T005 Add `examples/reference-integration/Makefile` that builds the `cleverbase-ffi` **staticlib** and exports the `CGO_LDFLAGS`/`CGO_ENABLED=1` needed to link it into the Go modules.
- [x] T006 [P] Add `golangci-lint` config covering the two Go modules (reuse the repo `.golangci.yml`) and confirm `gofmt`/`go vet` wiring.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: the mode-agnostic backend service + web frontend (incl. the helper extension) that every story builds on. **⚠️ No user story can complete until this phase is done.**

### Tests (write first; must fail)

- [x] T007 [P] REST API contract tests (start/complete/status/result/health, API-key 401; `complete` returns `redirectUrl` for the second-redirect case; `status` returns the enumerated `reason` codes) in `signing-service/internal/httpapi/handlers_test.go` per `contracts/reference-service-api.md`.
- [x] T008 [P] `RunProfile` env-load + fail-fast validation tests in `signing-service/internal/config/config_test.go`.
- [x] T009 [P] `SessionStore` tests — TTL eviction, `oauth_state`→`correlation_id` index updated across **both** sequential OAuth states, secret scrub on terminal — in `signing-service/internal/session/store_test.go`.
- [x] T010 [P] Flow mapping tests asserting **all nine** FR-009 terminal outcomes map to **distinct** `{status, reason}` (`completed`/`declined` + the **seven** `failed` reason codes: authorization_expired, credential_unavailable, identity_mismatch, invalid_document, timestamp_failed, appearance_placement_error, signature_invalid) in `signing-service/internal/flow/flow_test.go`.
- [x] T011 [P] Effect-loop **structured-logging** test: each upstream request/result and each state transition is logged with secrets **redacted** (FR-008) in `signing-service/internal/flow/logging_test.go`.
- [x] T012 [P] Frontend-helper test: `complete()`/`reportRedirectError()` return `{ status, redirectUrl? }` and the helper can navigate the **second** authorization redirect, in `frontend/helper-ts/test/helper.test.mjs`.

### Implementation

- [x] T013 Implement `RunProfile` config (env load + validation; fixtures vs live; `REFSVC_DEFAULT_CONFORMANCE` default `B-B`, overridden per-request; `REFSVC_SESSION_TTL` default 15m) in `signing-service/internal/config/config.go`.
- [x] T014 Implement `SessionStore` (in-memory map + TTL, `oauth_state`→`correlation_id` index re-indexed on the second redirect, drop sensitive fields on terminal) in `signing-service/internal/session/store.go`.
- [x] T015 Implement the upstream HTTP client that performs the SDK's `PerformHttp` effects in `signing-service/internal/upstream/client.go`.
- [x] T016 Implement the flow engine — drive `begin`/`resume` via `bindings/go`, perform effects, map outcomes → `{status, reason}`, and emit **structured, secret-redacted** logs of each effect + transition (FR-008/FR-009) — in `signing-service/internal/flow/flow.go` (depends on T013–T015).
- [x] T017 Extend `frontend/helper-ts`: `complete()`/`reportRedirectError()` return `{ status, redirectUrl? }` and add navigation of the second redirect; bump `0.1.0` → `0.2.0` with a CHANGELOG note (pre-1.0 breaking return-type change, documented per Constitution VII), in `frontend/helper-ts/src/index.ts` + `package.json` (so the web page can drive the second authorization redirect).
- [x] T018 Implement REST handlers `start`/`complete`/`status`/`result` + `healthz`/`readyz` (status surfaces the `reason` codes) in `signing-service/internal/httpapi/handlers.go` (depends on T016).
- [x] T019 Implement the API-key auth middleware (enabled by default; 401 before any work) in `signing-service/internal/httpapi/auth.go`.
- [x] T020 Implement `main` wiring + HTTP server (graceful shutdown) in `signing-service/cmd/refsvc/main.go`.
- [x] T021 [P] Implement the web frontend (start page + return page driving **both** redirects via the extended helper) in `web/src/` (depends on T017).
- [x] T022 [P] Add a multi-stage `signing-service/Dockerfile` (rust staticlib → cgo build → `distroless/cc`, non-root).
- [x] T023 [P] Add `web/Dockerfile` (static bundle served by a minimal non-root image that also answers a health route).
- [x] T024 Extend `.github/workflows/test.yml` with a Go job: `go test` + a **≥95% line-coverage gate** scoped to the `signing-service` packages only (`signing-service/internal/...` + `cmd`); `mock-upstream`, `web`, and `deploy` are excluded from the measurement per FR-024.
- [x] T025 Extend `.github/workflows/lint.yml` with `golangci-lint` for the two Go modules.

**Checkpoint**: backend + frontend build, lint, and pass unit tests; the helper supports the two-redirect flow.

---

## Phase 3: User Story 1 — Credential-free signing (Priority: P1) 🎯 MVP

**Goal**: complete the full signing journey against a mock upstream with no Cleverbase credentials, producing an OpenSSL-validated signed PDF, gated in CI.

**Independent Test**: with the fixtures stack up, drive the backend HTTP API (no browser) start→complete (twice, following `redirectUrl`)→result; the PDF passes `openssl` CMS validation and no document bytes/secrets were sent to the mock.

### Shared fixtures (prerequisite — single source, FR-015)

- [x] T026 [US1] Extract the upstream response **shapes** (OAuth `token`, `credentials/list`, `credentials/info`, SAD/`signHash` envelope) from `crates/cleverbase-core/tests/independent_validation.rs` (+ relevant signing unit-test literals) into language-neutral `tests/fixtures/upstream/*.json`, and **refactor the Rust test(s) to read them**, so the SDK tests and the Go mock share ONE source (FR-015 / Constitution VIII). Re-run the SDK test suite to confirm no behavior change.

### Tests (write first; must fail)

- [x] T027 [P] [US1] Credential-free **backend-API E2E** test in `examples/reference-integration/e2e/credfree_test.go`: start → complete ×2 (following `redirectUrl`) → result, sending a configured `REFSVC_API_KEY` so **auth stays enabled** (exercises FR-025, not bypassed). `openssl`-validate the CMS for **both B-B and B-T** (the B-T case asserts a valid mock-TSA timestamp bound to the signature). Assert the `X-Signature-Evidence` header is present and parseable; assert hash-only; assert an already-signed PDF is rejected with `invalid_document`; and assert a negative case where an `expectedSigner` not matching the fixture signer yields `failed` + `reason: identity_mismatch` (FR-014 end-to-end).
- [x] T028 [P] [US1] Mock-upstream unit tests reading `tests/fixtures/upstream/*.json` (authorize redirect, token, list, info, `signHash` signature validity, TSA token) in `mock-upstream/internal/server_test.go`.
- [x] T029 [P] [US1] Session-lifecycle edge test: an abandoned/expired session reports a terminal/expired `status` (never hangs) and a stale correlation id resolves cleanly in `signing-service/internal/session/lifecycle_test.go`.

### Implementation

- [x] T030 [US1] Implement the mock upstream — `/oauth2/authorize` (auto-302 with `code`+`state`), `/oauth2/token`, `/csc/v{1,2}/credentials/list` + `/credentials/info`, `/signatures/signHash` (sign with the synthetic fixture key), `/tsr` RFC 3161 TSA — sourcing the shared `tests/fixtures/upstream/*.json` + `tests/fixtures/pki/`, in `mock-upstream/internal/` + `mock-upstream/cmd/mockupstream/main.go`.
- [x] T031 [P] [US1] Add `mock-upstream/Dockerfile` (distroless, non-root).
- [x] T032 [US1] Add fixtures-mode `RunProfile` defaults + a bundled sample PDF in `signing-service/internal/config/` and `examples/reference-integration/testdata/sample.pdf`.
- [x] T033 [US1] Author `deploy/compose.yml` running `mock-upstream` + `signing-service` (fixtures) + `web`.
- [x] T034 [US1] Extend `.github/workflows/test.yml` with the **credential-free E2E job** (compose up the mock+service with a test `REFSVC_API_KEY` so auth stays enabled, run T027, `openssl`-validate **B-B and B-T**) as a merge gate (no Cleverbase credentials/secrets).
- [x] T035 [US1] README: run the credential-free stack locally (quickstart S1/S2/S3) and **document the in-memory backend-restart behavior** (in-flight sessions are lost; acceptable default).

**Checkpoint**: MVP — the stack signs end to end with zero credentials and is CI-gated.

---

## Phase 4: User Story 2 — Live acceptance via configuration (Priority: P2)

**Goal**: the same services drive a real Cleverbase signer when credentials are supplied; switching is config-only.

**Independent Test**: with acceptance credentials + a registered redirect URI, a real test signer completes a signing; the service/frontend artifacts are byte-identical to fixtures mode.

### Tests (write first; must fail)

- [x] T036 [P] [US2] Tests for live-mode config validation/fail-fast (missing client creds / redirect / TSA-when-B-T) in `signing-service/internal/config/live_test.go`.

### Implementation

- [x] T037 [US2] Implement live-mode validation + B-T TSA wiring (reuse the same flow path; `REFSVC_TSA_URL` → TSA endpoint, `REFSVC_TSA_AUTH` → the TSA request `Authorization` header, `REFSVC_TSA_POLICY` → policy OID) in `signing-service/internal/config/` and `internal/flow/`.
- [x] T038 [US2] Add an env-gated live smoke test (skipped without `REFSVC_CLIENT_ID`/`SECRET`) in `examples/reference-integration/e2e/live_test.go`.
- [x] T039 [US2] README: registering the `redirect_uri`, live env config, and the only-config-differs (artifact-identity) guarantee (SC-003).

**Checkpoint**: live signing reachable by configuration; sole remaining blocker is the externally-provided Cleverbase credentials/test-signer (+ a qualified TSA for live B-T).

---

## Phase 5: User Story 3 — Multi-arch image delivery & deploy (Priority: P3)

**Goal**: publish signed, SBOM-attested, multi-arch images to GHCR on native runners, deployable to Docker/k8s.

**Independent Test**: the `images` workflow publishes amd64 + arm64 images for both services to GHCR; each starts and reports healthy on its native arch; signatures + SBOM verify.

### Tests (write first; must fail)

- [x] T040 [P] [US3] Add an image **smoke** script in `examples/reference-integration/scripts/smoke.sh`: for the Go services assert `GET /healthz` 200; for the static **web** image assert `GET /` 200 (its health probe — a static server has no `/healthz`).

### Implementation

- [x] T041 [US3] Finalize/harden all three Dockerfiles (distroless/cc, non-root, minimal layers, pinned bases).
- [x] T042 [US3] Create `.github/workflows/images.yml`: matrix on **native** `ubuntu-24.04` (amd64) + `ubuntu-24.04-arm` (arm64); build + push per-arch **by digest** to GHCR as `ghcr.io/<org>/cleverbase-refsvc` and `…/cleverbase-refweb` (+ the mock as `…/cleverbase-refmock`); tags (`sha-…`+branch on default branch, semver+`latest` on tags); least-privilege `packages: write`.
- [x] T043 [US3] Add the manifest-list assembly job (`docker buildx imagetools create`) to `images.yml`.
- [x] T044 [US3] Add **cosign keyless** signing + **Syft SBOM** attestation + build provenance steps to `images.yml`.
- [x] T045 [US3] Add a per-arch image smoke job (run T040: Go `/healthz`, web `GET /`) to `images.yml`.
- [x] T046 [P] [US3] k8s base manifests (Deployments + Services for the three components; liveness/readiness probes — Go `/healthz`, web `/`; non-root `securityContext`) in `deploy/k8s/base/`.
- [x] T047 [P] [US3] Kustomize overlays `deploy/k8s/overlays/{fixtures,live}/` (mode selection + secrets via `Secret`).
- [x] T048 [US3] README: deploy via compose and via `kubectl apply -k`; verify images with `cosign verify` / `verify-attestation`.

**Checkpoint**: all stories independently functional; images published and deployable.

---

## Phase 6: Polish & Cross-Cutting Concerns

- [x] T049 [P] Verify `signing-service` sustains **≥95%** line coverage (measured over the `signing-service` packages only; mock/web/deploy exempt); add tests to close gaps (SC-008).
- [x] T050 [P] **Frontend-bound** no-leak assertion: scan every backend **client-bound** response (`start`/`status`/`result`) for any secret/token/SDK-handle (SC-004) in `signing-service/internal/httpapi/leak_test.go`.
- [x] T051 [P] **Upstream** hash-only assertion: scan every outbound-to-upstream request (URL + headers + body) for document bytes or secrets, in the E2E (`examples/reference-integration/e2e/credfree_test.go`).
- [x] T052 Run the full `quickstart.md` (S1–S5) and reconcile any documentation drift; confirm the SC-001 budget by **pre-building the staticlib and building/pulling all images first (cold baseline excluded), then timing only the warm run** (< 10 min).
- [x] T053 [P] Top-level `examples/reference-integration/README.md` (architecture diagram, components, full config/env table); document the pluggable `SessionStore` extension point — the default is in-memory; a shared/persistent store (e.g. Redis) is the documented swap-in (FR-005).
- [x] T054 Add `examples/reference-integration/SECURITY.md` (threat surface: API key, server-side secrets, hash-only upstream, image signing).

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (P1)** → no deps.
- **Foundational (P2)** → depends on Setup; **blocks all user stories**. Note: **T017 (helper extension) blocks T021 (web frontend)**; T012 (helper test) precedes T017.
- **US1** → depends on Foundational. **T026 (shared-fixtures extraction) blocks T028/T030 (mock tests + impl).** **MVP.**
- **US2** → depends on Foundational (reuses the service); independent of US1's mock.
- **US3** → depends on Foundational + the per-service Dockerfiles (T022/T023/T031).
- **Polish (P6)** → after the desired stories.

### Within Each Story

- Tests authored first and FAIL before implementation (Constitution VI).
- config/session/upstream → flow → handlers → wiring → web; helper (T017) before web (T021); shared fixtures (T026) before the mock; service before Dockerfile; Dockerfiles before CI image publish.

### Parallel Opportunities

- Setup: T002/T003/T004/T006.
- Foundational tests: T007–T012 in parallel; impl T013–T015 in parallel, then T016; T017 + T022/T023 parallel with the Go impl.
- US1: after T026, tests T027/T028/T029 in parallel; T031 parallel with T030.
- US3: T046/T047 (k8s) parallel with the `images.yml` tasks.
- After Foundational, US1/US2/US3 can be staffed in parallel.

### Parallel Example: Foundational tests

```bash
Task: "REST API contract tests in signing-service/internal/httpapi/handlers_test.go"
Task: "config tests in signing-service/internal/config/config_test.go"
Task: "session store tests in signing-service/internal/session/store_test.go"
Task: "flow outcome→{status,reason} tests in signing-service/internal/flow/flow_test.go"
Task: "effect-loop redacted-logging test in signing-service/internal/flow/logging_test.go"
Task: "helper second-redirect test in frontend/helper-ts/test/helper.test.mjs"
```

---

## Implementation Strategy

### MVP First (US1)

1. Phase 1 Setup → 2. Phase 2 Foundational → 3. Phase 3 US1 (extract shared fixtures T026 first) → **STOP & VALIDATE** the credential-free signed PDF (OpenSSL) → demo. This alone is a runnable, CI-gated reference (T001–T035).

### Incremental Delivery

Foundational → US1 (credential-free MVP, CI-gated) → US2 (live-by-config) → US3 (signed multi-arch images + k8s) → Polish.

---

## Requirement & criterion coverage

All 25 FRs and 9 SCs have ≥1 task. Notable mappings: FR-008 (structured redacted logging) → T011/T016;
FR-015 (single fixtures source) → **T026** (extract once; Rust + Go mock share it); SC-004 (frontend-bound
leak check) → T050, kept distinct from the upstream hash-only check T051; two-redirect helper handling →
T012/T017; FR-009's nine distinct outcomes → T010 + the enumerated `reason` codes; abandoned/expired +
restart behavior → T029/T035; session TTL → T013 (`REFSVC_SESSION_TTL`). FR-006 (env config, no baked
secrets) is covered by T013 and FR-007 (`healthz`/`readyz`) by T018 — folded into those tasks rather
than carrying their own IDs. The B-T-in-fixtures path is exercised by the T027/T034 CI gate (mock TSA),
not deferred.

---

## Notes

- `[P]` = different files, no incomplete-task dependency.
- The Go service re-implements **no** protocol/crypto — it drives the SDK via `bindings/go` (Constitution III); all signing logic stays in the Rust core.
- Fixtures have **one** source: the synthetic PKI under `tests/fixtures/pki/` and the upstream shapes extracted to `tests/fixtures/upstream/` (T026). The Go mock and the SDK's Rust tests both read these — never a forked copy (Constitution VIII / FR-015).
- Secrets (client secret, tokens, SDK handle) stay server-side; the frontend is the no-crypto helper (Constitution IV).
- T017 and T026 change shipped SDK artifacts (`frontend/helper-ts`, the Rust test fixtures); keep them minimal, additive where possible, and note the helper version bump.
- Commit after each task or logical group; verify each test fails before implementing it.
