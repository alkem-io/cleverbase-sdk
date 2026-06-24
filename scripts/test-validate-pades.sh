#!/usr/bin/env bash
# Test harness for the opt-in PAdES/eIDAS profile-conformance gate (feature 003, task T015).
#
# Asserts the contract of scripts/validate-pades.sh (contracts/profile-conformance-gate.md, "Test"):
#
#   1. a known-good B-B PDF PASSES  `validate-pades.sh --expect-level B-B`
#   2. the same B-B PDF FAILS       `validate-pades.sh --expect-level B-T`   (no timestamp → wrong level)
#   3. a tampered PDF FAILS         AdES validation                          (no false-accept)
#
# Like the always-on `openssl`-absent skip in the Go/Rust tests, this harness SELF-SKIPS (prints a
# `SKIP:` line and exits 0) when the opt-in toolchain (pyHanko venv + the EU DSS container) is not
# installed — which is the normal state of a dev machine. The real assertions run in CI
# (.github/workflows/profile-conformance.yml, task T017), which installs the pinned toolchain and
# generates the credential-free B-B/B-T PDFs for both algorithms before invoking the gate.
#
# Obtaining test PDFs without the opt-in toolchain present:
#   * If $PADES_TEST_PDF_DIR is set, this harness uses the PDFs CI already produced there
#     (B-B-<algo>.pdf, B-T-<algo>.pdf — emitted by the producer the workflow runs).
#   * Otherwise it cannot produce signed PDFs on its own (that requires the cleverbase-ffi build + the
#     mock upstream), so it SELF-SKIPS early. This is the documented, preferred behaviour in a dev env
#     (the task brief: "prefer self-skip cleanly when the toolchain is absent").
#
# Exit status: 0 on all-pass OR on a clean self-skip; non-zero only if the gate behaves incorrectly
# (a B-B PDF rejected at B-B, accepted at B-T, or a tampered PDF accepted).
set -euo pipefail

PROG="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATE="$SCRIPT_DIR/validate-pades.sh"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

skip() { printf 'SKIP: %s\n' "$*" >&2; }
note() { printf '==> %s\n' "$*" >&2; }
fail() { printf '%s: FAIL: %s\n' "$PROG" "$*" >&2; exit 1; }

if [ ! -x "$GATE" ]; then
  fail "gate script not found or not executable: $GATE"
fi

# ---------------------------------------------------------------------------------------------------
# Self-skip when the opt-in toolchain is absent. pyHanko is the IRREDUCIBLE requirement: the contract's
# central assertions — a tampered PDF fails AdES validation, and the AdES half of "PASS at B-B" — can
# only be exercised by pyHanko (EU DSS alone asserts the structural level, not AdES). So if pyHanko is
# absent we self-skip the whole harness even if a container engine happens to be present (there is no
# meaningful assertion left to make). This is the normal dev-machine state; the full matrix runs in CI
# (profile-conformance.yml).
#
# We do NOT separately detect the EU DSS container engine here: whether the level half actually ran is
# the gate's own determination (it depends on the pinned DSS image being pullable, not merely on docker
# being installed), so assertion 2 reads the gate's "baseline level confirmed" report (single source of
# truth) rather than re-implementing DSS detection — see gate_level_was_asserted below.
# ---------------------------------------------------------------------------------------------------
have_pyhanko() {
  { [ -n "${PYHANKO_VENV:-}" ] && [ -x "$PYHANKO_VENV/bin/pyhanko" ]; } || command -v pyhanko >/dev/null 2>&1
}

if ! have_pyhanko; then
  skip "profile-gate toolchain not installed (pyHanko absent — the primary AdES backend) — nothing to assert; the real run is in CI (profile-conformance.yml)"
  exit 0
fi

# ---------------------------------------------------------------------------------------------------
# Locate the test PDFs. CI's producer writes them to $PADES_TEST_PDF_DIR. We need at least one B-B PDF
# (any algorithm) and a tampered copy. We prefer the RSA leg for determinism but accept either.
# ---------------------------------------------------------------------------------------------------
if [ -z "${PADES_TEST_PDF_DIR:-}" ] || [ ! -d "${PADES_TEST_PDF_DIR:-/nonexistent}" ]; then
  skip "PADES_TEST_PDF_DIR not set / not a directory — cannot obtain signed test PDFs without the producer; self-skipping (CI sets it after running the credential-free producer)"
  exit 0
fi

find_pdf() {
  # $1 = level prefix (B-B / B-T). Return the first matching PDF in PADES_TEST_PDF_DIR.
  local level="$1" f
  for f in "$PADES_TEST_PDF_DIR/${level}"*.pdf; do
    [ -r "$f" ] && { printf '%s\n' "$f"; return 0; }
  done
  return 1
}

BB_PDF="$(find_pdf "B-B")" || {
  skip "no B-B*.pdf in $PADES_TEST_PDF_DIR — producer did not emit one; self-skipping"
  exit 0
}

# Trust anchor: the synthetic CA the credential-free fixtures chain to, materialized as PEM. The gate
# needs PEM; the committed CA is DER. (For live PDFs CI passes the real bundle via TRUST_PEM_OVERRIDE.)
TRUST_PEM="${TRUST_PEM_OVERRIDE:-}"
if [ -z "$TRUST_PEM" ]; then
  CA_DER="$REPO_ROOT/tests/fixtures/pki/ca.cert.der"
  if [ ! -r "$CA_DER" ]; then
    skip "synthetic CA fixture not found ($CA_DER) and no TRUST_PEM_OVERRIDE — self-skipping"
    exit 0
  fi
  if ! command -v openssl >/dev/null 2>&1; then
    skip "openssl needed to materialize the CA PEM from DER and is absent — self-skipping"
    exit 0
  fi
  TRUST_PEM="$(mktemp)"
  openssl x509 -inform DER -in "$CA_DER" -out "$TRUST_PEM"
  trap 'rm -f "$TRUST_PEM"' EXIT
fi

# ---------------------------------------------------------------------------------------------------
# Assertion helpers. run_gate succeeds (returns 0) iff the gate exits 0. It captures the gate's
# combined stdout+stderr into GATE_OUTPUT so callers can distinguish WHAT the gate asserted (the gate
# prints "baseline level confirmed = X" only when the EU DSS level half actually ran, and
# "level NOT asserted" when DSS was unavailable). run_gate must keep its own exit status under `set -e`,
# so we capture into a variable without a pipeline that would mask it.
# ---------------------------------------------------------------------------------------------------
GATE_OUTPUT=""
run_gate() {
  # $1 = expect-level, $2 = pdf
  local rc=0
  GATE_OUTPUT="$("$GATE" --expect-level "$1" --trust "$TRUST_PEM" "$2" 2>&1)" || rc=$?
  printf '%s\n' "$GATE_OUTPUT" >&2
  return "$rc"
}

# gate_level_was_asserted: true iff the LAST run_gate call's output shows the EU DSS level half
# actually ran and confirmed a level. The gate prints "baseline level confirmed" on a real level
# assertion and "level NOT asserted" when DSS was unavailable (image unpullable / no engine). This is
# the single source of truth for "did the level half run" — we read the gate's own report rather than
# re-detecting DSS reachability here (which would duplicate validate-pades.sh and could drift).
gate_level_was_asserted() {
  printf '%s' "$GATE_OUTPUT" | grep -q 'baseline level confirmed'
}

PASS=0

# Assertion 1: a known-good B-B PDF passes --expect-level B-B.
note "assert 1: $BB_PDF passes --expect-level B-B"
if run_gate "B-B" "$BB_PDF"; then
  note "  ok: B-B PDF accepted at B-B"
  PASS=$((PASS + 1))
else
  fail "a known-good B-B PDF was REJECTED at --expect-level B-B"
fi

# Assertion 2: the same B-B PDF asserted as B-T fails (it has no timestamp → not BASELINE-T). This
# assertion is ONLY meaningful when the EU DSS level half actually runs — that is what distinguishes
# B-B from B-T (pyHanko's adesverify is level-agnostic). A present container engine does NOT guarantee
# the pinned DSS image is pullable: if the engine exists but DSS is unreachable, the gate correctly
# self-skips the level half, the level-agnostic AdES half PASSES the valid B-B PDF, and run_gate exits
# 0 — which is the gate behaving CORRECTLY ("level NOT asserted"), not a wrong-accept. So we gate this
# assertion on the gate's OWN report that the level was confirmed (gate_level_was_asserted), never on
# the exit code alone, to avoid a false CI failure when DSS is merely unavailable.
note "assert 2: $BB_PDF FAILS --expect-level B-T"
if run_gate "B-T" "$BB_PDF"; then
  # Exit 0. Only a wrong-accept IF the DSS level half actually asserted the level; otherwise this is
  # the correct level-agnostic AdES pass with the level explicitly NOT asserted — skip, don't fail.
  if gate_level_was_asserted; then
    fail "a B-B PDF (no timestamp) was wrongly ACCEPTED at --expect-level B-T (DSS confirmed the level)"
  else
    skip "EU DSS level half did not run (engine present but DSS unavailable) — the B-B-as-B-T mismatch was NOT asserted here (CI asserts it)"
  fi
else
  # Non-zero exit: the gate rejected the B-B PDF at B-T. This is the level mismatch being caught — it
  # can only happen when the DSS level half ran (the AdES half alone is level-agnostic and would pass).
  note "  ok: B-B PDF correctly rejected at B-T"
  PASS=$((PASS + 1))
fi

# Assertion 3: a tampered PDF fails AdES validation. Flip a byte deep in the /Contents CMS region so
# the document still parses but the signature no longer verifies. This leg needs pyHanko (the AdES
# half); skip it cleanly if only the DSS engine is present.
note "assert 3: a tampered copy of $BB_PDF FAILS AdES validation"
if have_pyhanko; then
  TAMPERED="$(mktemp --suffix=.pdf 2>/dev/null || mktemp)"
  # Copy, then corrupt a byte near the end of the file (inside the signature /Contents blob for a
  # PAdES signature, which is appended last) without truncating it.
  cp "$BB_PDF" "$TAMPERED"
  python3 - "$TAMPERED" <<'PY'
import sys
p = sys.argv[1]
with open(p, "rb") as fh:
    data = bytearray(fh.read())
# Flip a byte ~200 bytes from the end — inside the signature container for an appended PAdES sig,
# leaving the PDF structurally parseable so the failure is the signature check, not a parse error.
i = max(0, len(data) - 200)
data[i] ^= 0x01
with open(p, "wb") as fh:
    fh.write(data)
PY
  if run_gate "B-B" "$TAMPERED"; then
    rm -f "$TAMPERED"
    fail "a tampered PDF was wrongly ACCEPTED (no false-accept guarantee violated)"
  else
    note "  ok: tampered PDF rejected"
    PASS=$((PASS + 1))
  fi
  rm -f "$TAMPERED"
else
  skip "pyHanko not available — AdES half not running, so the tamper-rejection cannot be asserted here (CI asserts it)"
fi

if [ "$PASS" -eq 0 ]; then
  skip "no assertion legs ran (partial toolchain) — nothing asserted; CI covers the full matrix"
  exit 0
fi

note "test-validate-pades: $PASS assertion(s) passed"
exit 0
