# Quickstart & Validation Guide: Remote Qualified Signing (PAdES B-B / B-T)

How to prove this feature works end-to-end. Implementation details live in `tasks.md` and the code;
this is a run/validation guide. See [contracts/](./contracts/) and [data-model.md](./data-model.md).

## Prerequisites

- Rust toolchain (stable, ≥ MSRV), native target. (No WASM target needed — the frontend helper is
  pure TypeScript and performs no crypto.)
- Binding toolchains: `maturin` (Python), Node ≥ 18 + `napi` (Node), Go ≥ 1.22 (cgo).
- Independent validators: **EU DSS** validator and **veraPDF** (CI containers).
- Cleverbase **acceptance** access: public stub `client_id` + `redirect_uri` registered (sales-led
  onboarding is out of scope — see spec Assumptions).
- A configured **qualified RFC 3161 TSA** endpoint (required only for the B-T scenarios).
- Test PDFs are generated programmatically by the tests (`minimal_pdf()`); only PKI material
  (certs/keys for the synthetic CA, signer, and TSA) lives under `tests/fixtures/pki/`.

## Build

```bash
cargo build --workspace                       # core + ffi
maturin develop -m bindings/python/Cargo.toml # Python ext
(cd bindings/node && npm install && npm run build)
(cd bindings/go && go build ./...)            # cgo against cleverbase-ffi
```

## Validation scenarios

Each scenario is the acceptance test for a user story / success criterion. Run offline with the
recorded HTTP-shape fixtures inlined in the Rust tests and/or live against the acceptance environment.

### S1 — Sign a PDF, PAdES B-B (US1, SC-001/002/005)
1. Drive `begin → resume…` with `conformance_level=B_B` and a plain PDF (loop over the returned
   `Step`s, completing the two authorization redirects via the wallet — or replaying fixtures).
2. **Expected**: `Step.Done` with a signed PDF + evidence record; only a **hash** was sent upstream
   (assert no document bytes in any `HttpEffect`).
3. **Validate**: EU DSS reports a valid **qualified** signature at PAdES **B-B**.

### S2 — Timestamped signature, PAdES B-T (US2, SC-003)
1. Repeat S1 with `conformance_level=B_T` and a configured TSA.
2. **Expected**: signed PDF embeds a `signature-time-stamp`; if the TSA fails, `Step.Failed`
   (`TimestampFailed`) with **no downgrade** to B-B.
3. **Validate**: EU DSS reports a valid signature timestamp at PAdES **B-T**.

### S3 — Signer-identity binding (FR-014, SC-008)
1. Run S1 with `expected_signer` set to the correct signer → succeeds.
2. Run with a deliberately wrong `expected_signer` → `Step.Failed` (`IdentityMismatch`), no
   signature produced.

### S4 — Visible appearance + PDF/A (FR-016/017, SC-011/012)
1. Sign with an `appearance` (page/rect + reason/location/name); **expected**: the block renders at
   the requested position and DSS still validates the signature.
2. Sign a **PDF/A** input; **expected**: **veraPDF** reports the output is still PDF/A-conformant.

### S5 — Stateless resumability (FR-013, SC-009)
1. After the credential authorization returns, **persist the handle, discard the in-memory state,
   reload the handle**, then finalize.
2. **Expected**: signature completes from the handle alone, no re-prompt, while the authorization is
   unexpired.

### S6 — Cross-language parity (FR-012, SC-004)
1. Run S1/S2 from Python, Node, and Go against the same fixtures.
2. **Expected**: all three produce signed output that DSS validates equivalently.

### S7 — Frontend helper carries no secrets (US3, SC-005)
1. Drive a sample web demo through the helper; capture browser traffic.
2. **Expected**: no `client_secret`/SAD/token/handle/private key present; no crypto in the browser.

## Definition of done (feature)

All of S1–S7 pass in CI, coverage ≥ 95% across core + bindings, and every produced signature passes
the EU DSS / veraPDF validators. Demos for each language run S1 against the acceptance environment
within the 30-minute first-signature target (SC-007).
