# Quickstart: validate EUDI attestation verification + (gated) issuance

Runnable scenarios proving the feature. Verification scenarios need **no Cleverbase API and no live
issuance** (offline conformant vectors + a configured test trust anchor). The issuance scenario is opt-in.
Run from the repo root.

## Prerequisites

- Rust 1.94.1; the `cleverbase-attestation` crate + its test vectors (`tests/fixtures/attestation/`).
- Always-on suite: **no external dependency**.
- Cross-check (Principle VI): an independent **different-language** EU reference verifier (Kotlin/TS) —
  opt-in CI.
- Gated issuance: the EU `eudi-srv-pid-issuer` reference issuer (docker-compose) — opt-in.

## Scenario 1 — Verify a presented attestation, both formats (US1, P1) 🎯 MVP

```bash
cargo test -p cleverbase-attestation --test verify     # SD-JWT VC + mdoc, VALID + all negative paths
```

**Expected**: conformant SD-JWT VC and mdoc presentations verify VALID and return the disclosed attributes;
tampered / expired / revoked / wrong-issuer / untrusted / broken-holder-binding / status-unreachable
(fail-closed) / unsupported-format each return INVALID with a **specific reason** (SC-002). Zero Cleverbase
API, zero live issuance (SC-001/SC-003).

## Scenario 2 — Full verifier: replay / audience binding (FR-015 / SC-008)

```bash
cargo test -p cleverbase-attestation --test openid4vp_binding
```

**Expected**: the SDK builds an OpenID4VP request (DCQL + fresh nonce + audience); a presentation bound to
it verifies; the **same presentation replayed**, or one built for a **different audience**, is rejected
(`replay` / `wrong_audience`). Both formats.

## Scenario 3 — Opt-in qualified-status gate (FR-014 / SC-007)

```bash
cargo test -p cleverbase-attestation --test qualified_gate   # self-skips if TL fixtures absent
```

**Expected**: with the gate enabled, a qualified-issuer fixture (granted at the relevant time) →
`Qualified`; a trusted-but-non-qualified issuer → VALID-but-`NotQualified` (no false "qualified"); missing
trust-list data → `Indeterminate`. With the gate disabled, the always-on verdict is identical (SC-007).

## Scenario 4 — Independent reference cross-check (Principle VI)

```bash
# opt-in CI: verify the SAME credentials with an independent Kotlin/TS EU reference verifier; assert agreement
scripts/crosscheck-attestation.sh   # self-skips if the reference verifier isn't available
```

**Expected**: the Rust verifier's VALID/INVALID verdicts agree with the independent reference verifier on
the shared vectors (no Rust-vs-Rust self-confirmation).

## Scenario 5 — Coverage + no-external-deps gate (Principle VI)

```bash
cargo test -p cleverbase-attestation
# per-crate coverage stays >=95% (repo coverage recipe)
```

**Expected**: all green with **zero** external dependencies; coverage ≥95% (SC-003).

## Scenario 6 — Gated issuance/holding/presentation (US2, P2) — opt-in

```bash
# bring up the EU reference issuer, then:
export ATT_ISSUER=reference ATT_ISSUER_URL=http://localhost:8080   # eudi-srv-pid-issuer
cargo test -p cleverbase-attestation --test issuance -- --include-ignored
```

**Expected (issuer configured)**: `obtain` (OpenID4VCI, holder-binding via the signer-hook — the SDK never
holds the key) yields a conformant attestation that verifies under Scenario 1; `present` (OpenID4VP) yields
a vp_token the verifier accepts. **Expected (no issuer / `ATT_ISSUER` unset)**: the issuance test is
**skipped**, and Scenarios 1–3 still pass (FR-008). A future Cleverbase issuer is enabled by config alone
(SC-005).

## Success mapping

| Scenario | Validates |
|----------|-----------|
| 1 | US1, FR-001/002/003/005, SC-001/002 |
| 2 | FR-015, SC-008 |
| 3 | FR-014, SC-007 |
| 4 | FR-013 (independent reference verifier), Principle VI |
| 5 | FR-013, SC-003 |
| 6 | US2, FR-006/007/008/009, SC-004/005 |
</content>
