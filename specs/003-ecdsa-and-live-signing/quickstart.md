# Quickstart: validate ECDSA parity + live signing

Runnable scenarios that prove this feature works. Credential-free scenarios need **no Cleverbase
credentials**; the live scenario is opt-in. Commands are run from the repo root.

## Prerequisites

- Rust 1.94.1 (`rust-toolchain.toml`), Go 1.22+, `openssl` on PATH (always-on validator).
- For the opt-in profile gate only: Python 3.11+ (pyHanko) and Docker (EU DSS).
- cgo env for the Go reference integration:
  ```bash
  cargo build -p cleverbase-ffi
  export LIB="$PWD/target/debug" CGO_LDFLAGS="-L$PWD/target/debug" \
         LD_LIBRARY_PATH="$PWD/target/debug" DYLD_LIBRARY_PATH="$PWD/target/debug"
  ```

## Scenario 1 — ECDSA P-256 credential-free, independently verified (US1, P1)

Proves the headline gap closure: a full B-B and B-T flow signed with ECDSA P-256, verified by OpenSSL.

```bash
# Core: the new ECDSA arms of the independent OpenSSL validation (B-B + B-T)
cargo test -p cleverbase-core --test independent_validation

# Reference E2E: the algorithm table {v1_rsa, v2_ecdsa} × {B-B, B-T}
( cd examples/reference-integration/signing-service && go test ./e2e/ -run CredentialFree -v )
```

**Expected**: the ECDSA cases produce a PDF whose CMS `signatureAlgorithm` is `ecdsa-with-SHA256` and which
`openssl cms -verify` accepts against the synthetic EC chain; the B-T case additionally carries a valid RFC
3161 timestamp. RSA cases still pass unchanged (no regression — FR-005/SC-002).

## Scenario 2 — DRY check (FR-004 / SC-003)

Confirms there is one algorithm-parametrized path, not RSA/ECDSA twins.

```bash
# The mock holds per-route signers, not a hardcoded rsaKey:
grep -n "rsaKey" examples/reference-integration/mock-upstream/mock/server.go   # -> no single hardcoded signer
# The E2E is a table, not duplicated test bodies:
grep -n "v2_ecdsa\|v1_rsa" examples/reference-integration/signing-service/e2e/credfree_test.go
# Fixtures regenerate reproducibly:
bash tests/fixtures/pki/gen.sh --check     # regenerates to identical material / verifies chains
```

**Expected**: a reviewer can confirm no copy-pasted RSA/ECDSA logic; `gen.sh` reproduces the committed PKI.

## Scenario 3 — coverage + no-external-deps gate (Principle VI)

```bash
cargo test -p cleverbase-core              # incl. the new ECDSA arms
# per-package coverage stays >=95% (run the repo's coverage recipe / make target)
( cd examples/reference-integration/signing-service && go test -coverprofile=/tmp/c.out ./internal/... && go tool cover -func=/tmp/c.out | tail -1 )
```

**Expected**: all green with **zero** external dependencies; coverage ≥95% per package (SC-004).

## Scenario 4 — opt-in PAdES/eIDAS profile-conformance gate (FR-014)

```bash
# produce a credential-free B-B and B-T PDF (helper from the E2E), then:
scripts/validate-pades.sh --expect-level B-B --trust tests/fixtures/pki/ca.cert.pem out-bb.pdf
scripts/validate-pades.sh --expect-level B-T --trust tests/fixtures/pki/ca.cert.pem out-bt.pdf
```

**Expected**: pyHanko reports AdES-valid (RSA + ECDSA); EU DSS reports `PAdES-BASELINE-B` / `-T` matching
`--expect-level`. Asserting the B-B PDF as `--expect-level B-T` fails loudly (no timestamp). The always-on
OpenSSL bar (Scenario 1) is unaffected by whether this gate runs (SC-007).

## Scenario 5 — live contract path against real Cleverbase (US2, P2) — opt-in

```bash
export REFSVC_MODE=live REFSVC_ENV=acceptance
export REFSVC_CLIENT_ID=… REFSVC_CLIENT_SECRET=… REFSVC_REDIRECT_URI=…
export REFSVC_CSC_API=v2_ecdsa            # or v1_rsa; run both if both credentials exist
export REFSVC_TSA_URL=…                    # set -> B-T covered too; unset -> B-B only
export REFSVC_LIVE_AUTHORIZER=interactive  # default: a human approves in the browser
export REFSVC_LIVE_CA_BUNDLE=/path/to/real-cleverbase-chain.pem

( cd examples/reference-integration/signing-service && go test ./e2e/ -run Live -v )
```

**Expected (creds present)**: the flow reaches the Cleverbase authorize URL; the interactive authorizer
lets a human approve; the produced PDF verifies against the **real** issuer chain (B-B; B-T when a TSA is
set). **Expected (creds absent)**: the test is **skipped**, and Scenarios 1–3 still pass (FR-009).

## Success mapping

| Scenario | Validates |
|----------|-----------|
| 1 | US1, FR-001/002/003, SC-001/002 |
| 2 | FR-004, SC-003; PKI reproducibility (research D4) |
| 3 | FR-005/006, SC-004 |
| 4 | FR-014, SC-007 |
| 5 | US2, FR-007/008/009/011/013/015, SC-005 |
</content>
