# Contract: opt-in PAdES/eIDAS profile-conformance gate

An **opt-in, additional** validation over produced signatures (credential-free + live) asserting ETSI
EN 319 142 PAdES **B-B/B-T** profile conformance (FR-014). It runs **in addition to — never instead of** —
the always-on OpenSSL cryptographic+structural bar (FR-003/FR-012), and is **never linked into the shipped
SDK** (Principle V — pluggable, self-hosted validation backend).

## Entry point: `scripts/validate-pades.sh <pdf>... `

```
scripts/validate-pades.sh \
  --expect-level {B-B|B-T} \
  --trust <ca-or-trust-bundle.pem> \
  <signed.pdf> [<signed.pdf> ...]
```

Exit non-zero (fail the gate) if any input fails AdES validation or the detected baseline level does not
match `--expect-level`.

## Backends (research D7)

| Backend | Role | Why |
|---------|------|-----|
| **pyHanko** (`pyhanko adesverify`, MIT, pip) | primary AdES validation: signature + chain + timestamp, RSA & ECDSA P-256 | constitution's named lighter default; CI-trivial; superset of the openssl check |
| **EU DSS** (containerized, LGPL-2.1) | the **structural baseline-level** assertion: report `SignatureFormat == PAdES-BASELINE-B / -T` | pyHanko's CLI does **not** assert profile *level*; DSS does — FR-014's literal wording |

The script pip-installs `pyhanko-cli` into a throwaway venv and invokes the DSS container only for the
level assertion. Neither tool is a build/runtime dependency of the SDK. **Both versions MUST be pinned** —
an exact `pyhanko-cli` version and a **digest-pinned EU DSS container image (or a fixed DSS release tag)**,
declared once in `scripts/validate-pades.sh` (single source — Constitution III) — so the opt-in gate is
reproducible across CI and dev.

## CI wiring

- New workflow `profile-conformance.yml`, **off by default** (manual `workflow_dispatch` and/or a label
  gate) — distinct from the always-on credential-free job.
- Runs the gate over the credential-free B-B/B-T PDFs for **both** algorithms; for live runs, over the
  real-signed PDFs using the real trust bundle.

## Contract rules

- Enabling/disabling the gate MUST NOT affect the always-on OpenSSL bar (it runs unconditionally — SC-007).
- A cryptographically-valid but profile-non-conformant signature MUST fail the gate loudly, naming the
  non-conformant element (Edge Cases).
- No private document or trust material leaves the operator's infrastructure (Principle IV) — both backends
  run locally/in-container.

## Test (must fail first)

- A known-good B-B PDF passes with `--expect-level B-B`; the same asserted as `--expect-level B-T` fails
  (no timestamp). A tampered PDF fails AdES validation. (Run only when the opt-in toolchain is present;
  otherwise the test self-skips, mirroring the credential-free `openssl`-absent skip.)
</content>
