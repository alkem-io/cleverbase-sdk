# Quickstart: Reference Integration Services

Validation/run guide for the reference integration. Implementation details live in `tasks.md` and the
code under `examples/reference-integration/`.

## Prerequisites

- Docker + Docker Compose (local bring-up), or a Kubernetes cluster + `kubectl`/`kustomize`.
- For from-source builds: Rust (per the workspace `rust-toolchain.toml`), Go ≥ 1.22, Node ≥ 18.
- `openssl` for independent validation of the produced signature.
- **No Cleverbase credentials** are needed for the credential-free scenarios (S1–S3).

## Components

- `signing-service` (Go) — embeds the SDK (Go binding/cgo), runs `begin`/`resume`, performs upstream
  I/O, serves the REST API (`contracts/reference-service-api.md`).
- `web` (TypeScript) — thin no-crypto UI on `frontend/helper-ts`; hosts the redirect-return route.
- `mock-upstream` (Go) — serves the credential-free CSC/OIDC + TSA fixtures.

## Validation scenarios

### S1 — Credential-free end-to-end via the browser (US1)

1. `docker compose -f examples/reference-integration/deploy/compose.yml up` (starts `mock-upstream`,
   `signing-service` in `fixtures` mode, and `web`).
2. Open the web UI, choose the bundled sample PDF (or upload one), click **Sign**, and follow the
   (auto-completing) authorization redirects.
3. **Expected**: status reaches `completed`; download the signed PDF.
4. **Validate**: `openssl` verifies the embedded CMS (signature, `message-digest` vs ByteRange, chain
   to the synthetic CA) — identical to the SDK's `independent_validation` check.

### S2 — Credential-free end-to-end via the backend API (US1, the CI gate)

1. With the stack up (S1), drive the **backend API directly** (no browser): `POST /v1/sign/start`
   → follow `redirectUrl` against the mock to obtain `code`+`state` → `POST /v1/sign/complete`
   (repeat for the credential-auth step) → `GET /v1/sign/result`.
2. **Expected**: a signed PDF that passes the same `openssl` validation; assert no document bytes or
   secrets appear in any request the service made to the mock (hash-only upstream).
3. This is the automated, deterministic flow CI runs to gate merges (FR-021).

### S3 — Credential-free B-T (timestamped)

1. Either set the deployment default `REFSVC_DEFAULT_CONFORMANCE=B-T`, or pass `"conformanceLevel": "B-T"`
   in the `start` request (the per-request field overrides the default); the mock TSA issues the timestamp.
2. **Expected**: the signed PDF carries a valid signature timestamp bound to the signature.

### S4 — Live acceptance signing (US2, requires external credentials)

1. Configure `REFSVC_MODE=live` with `REFSVC_CLIENT_ID`/`SECRET`, `REFSVC_REDIRECT_URI` (registered
   with Cleverbase), `REFSVC_ENV`/`CSC_API`, and (for B-T) `REFSVC_TSA_*`.
2. A real test signer completes login + authorizes the hash in Cleverbase's wallet.
3. **Expected**: a real signed PDF + evidence; **only configuration/secrets differ from S1** — the
   service and frontend artifacts are byte-identical (SC-003).

### S5 — Deploy to Kubernetes

1. `kubectl apply -k examples/reference-integration/deploy/k8s/overlays/fixtures` (or `live`).
2. **Expected**: both services become Ready (health/readiness probes pass) on the cluster's
   architecture; the flow works as in S1.

## Image build & delivery (US3)

- Local: `docker buildx build` each service for the host arch; run and hit `/healthz`.
- CI (`images` workflow): on default-branch push and tags, native amd64 + arm64 runners build & push
  per-arch images to **GHCR**, a manifest list is assembled, each digest is **cosign-signed**
  (keyless) and gets an **SBOM** attestation. Verify with `cosign verify` and
  `cosign verify-attestation`.

## Definition of done

- S1–S3 (credential-free) pass locally and **in CI with zero credentials**; the produced signature
  passes `openssl` validation.
- The `signing-service` sustains **≥95%** unit-test coverage in CI.
- `images` publishes signed, SBOM-attested amd64 + arm64 images to GHCR that start and report healthy
  on each architecture.
- S4 (live) is reachable by configuration alone — the only remaining blocker is the external
  Cleverbase credentials / test signer (and a qualified TSA for live B-T).
