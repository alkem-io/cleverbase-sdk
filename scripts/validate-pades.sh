#!/usr/bin/env bash
# Opt-in PAdES/eIDAS profile-conformance gate (feature 003, task T016, FR-014).
#
# This is an ADDITIONAL validation over already-produced signed PDFs (credential-free or live).
# It runs IN ADDITION TO — never instead of — the always-on OpenSSL cryptographic+structural bar
# (`openssl cms -verify`, asserted in the Go E2E and the Rust independent_validation tests). It is
# OPT-IN, off by default, and is NEVER linked into or required by the shipped SDK
# (Constitution Principle V — pluggable, self-hosted validation backend).
#
# It asserts ETSI EN 319 142 PAdES BASELINE-B / BASELINE-T conformance with two backends, because no
# single CLI does both halves (research D7, contracts/profile-conformance-gate.md):
#
#   * pyHanko (`pyhanko sign adesverify`, MIT, pip)  — primary AdES validation: signature value +
#     certificate chain + (for B-T) the embedded RFC 3161 timestamp, for BOTH RSA and ECDSA P-256.
#     pyHanko's CLI does the full AdES check but does NOT emit the structural PAdES *profile level*.
#   * EU DSS (esig/dss, LGPL-2.1, containerized) — the structural baseline-LEVEL assertion: its
#     validation report's `SignatureFormat` is exactly `PAdES-BASELINE-B` / `PAdES-BASELINE-T`,
#     which is FR-014's literal wording. Used ONLY for the level assertion.
#
# Neither tool is a build/runtime dependency of the SDK; both run locally / in a local container so
# no private document or trust material leaves the operator's infrastructure (Principle IV).
#
# Exit status:
#   0  — every input PDF passed AdES validation AND its detected baseline level matched --expect-level
#   1+ — at least one PDF failed AdES validation OR its level did not match (the gate FAILS loudly,
#        naming the non-conformant element)
#   0  — with a "SKIP:" message, when the opt-in toolchain (pyHanko venv / the DSS container image) is
#        not available — so the gate self-skips in environments that did not opt in, mirroring the
#        `openssl`-absent skip in the always-on tests. The real run happens in CI (profile-conformance.yml).
#
# Usage:
#   scripts/validate-pades.sh --expect-level {B-B|B-T} --trust <ca-or-trust-bundle.pem> <signed.pdf> [<signed.pdf> ...]
#
# shellcheck disable=SC2310  # functions used in `if` conditions intentionally disable -e locally.
set -euo pipefail

# ---------------------------------------------------------------------------------------------------
# Pinned toolchain — SINGLE SOURCE OF TRUTH (Constitution Principle III).
#
# `.github/workflows/profile-conformance.yml` MUST install/pull these exact versions (it reads them
# from this script via `--print-pins`, so the workflow and the local gate can never drift). Bump them
# here and only here.
#
#   * PYHANKO_CLI_VERSION / PYHANKO_VERSION — exact pip pins. pyhanko-cli 0.4.0 requires
#     pyHanko >=0.35.0,<0.36; we pin pyHanko to 0.35.1 (the highest in that range) so the pair is
#     fully reproducible.
#   * DSS_RELEASE — the fixed EU DSS release the level assertion is pinned to (esig/dss 6.4).
#   * DSS_IMAGE — the EU DSS validation web app container reference. The contract allows "a
#     digest-pinned image OR a fixed DSS release tag"; the DEFAULT here is a FIXED RELEASE TAG
#     (esignaturedss/dss-demo-webapp:${DSS_RELEASE}), which is a mutable registry tag, NOT a content
#     digest. For a true, byte-for-byte reproducible pin, override DSS_IMAGE with a digest reference
#     (DSS_IMAGE=registry/...@sha256:...); the contract is satisfied either way. It is overridable via
#     the DSS_IMAGE env var for operators running a self-hosted mirror or a digest pin. If the image
#     cannot be pulled/run, the DSS half self-skips with a clear SKIP (the AdES half still runs); if
#     pyHanko is also absent the whole gate self-skips.
# ---------------------------------------------------------------------------------------------------
PYHANKO_CLI_VERSION="0.4.0"
PYHANKO_VERSION="0.35.1"
DSS_RELEASE="6.4"
# Default DSS validation-webapp image: a FIXED RELEASE TAG carrying DSS_RELEASE (a mutable registry
# tag, not a content digest). Override DSS_IMAGE for a self-hosted mirror or a TRUE digest pin
# (e.g. DSS_IMAGE=registry.example/dss-webapp@sha256:...). The gate self-skips the DSS half cleanly if
# this reference is not pullable in the current environment.
DSS_IMAGE="${DSS_IMAGE:-esignaturedss/dss-demo-webapp:${DSS_RELEASE}}"
# Host port the throwaway DSS container is published on (overridable to avoid clashes in CI).
DSS_PORT="${DSS_PORT:-8089}"
# Container engine: docker by default, podman if that is what is installed.
CONTAINER_ENGINE="${CONTAINER_ENGINE:-}"

PROG="$(basename "$0")"

err()  { printf '%s: error: %s\n' "$PROG" "$*" >&2; }
skip() { printf 'SKIP: %s\n' "$*" >&2; }
note() { printf '==> %s\n' "$*" >&2; }

usage() {
  cat >&2 <<EOF
Usage: $PROG --expect-level {B-B|B-T} --trust <pem> <signed.pdf> [<signed.pdf> ...]

  --expect-level B-B|B-T   the ETSI EN 319 142 baseline level every input must structurally match
  --trust <pem>            PEM trust anchor (CA / issuer chain) the signer must chain to
  --print-pins             print the pinned tool versions (for CI to read) and exit 0
  -h, --help               show this help

Drives pyHanko (AdES validation) + EU DSS (PAdES baseline-level assertion). Self-skips (exit 0 with a
SKIP message) when the opt-in toolchain is unavailable.

Pinned: pyhanko-cli==${PYHANKO_CLI_VERSION}, pyHanko==${PYHANKO_VERSION}, EU DSS ${DSS_RELEASE} (${DSS_IMAGE}).
EOF
}

# ---------------------------------------------------------------------------------------------------
# Argument parsing.
# ---------------------------------------------------------------------------------------------------
EXPECT_LEVEL=""
TRUST_PEM=""
PDFS=()

while [ "$#" -gt 0 ]; do
  case "$1" in
    --expect-level) EXPECT_LEVEL="${2:-}"; shift 2 ;;
    --trust)        TRUST_PEM="${2:-}";    shift 2 ;;
    --print-pins)
      printf 'PYHANKO_CLI_VERSION=%s\nPYHANKO_VERSION=%s\nDSS_RELEASE=%s\nDSS_IMAGE=%s\n' \
        "$PYHANKO_CLI_VERSION" "$PYHANKO_VERSION" "$DSS_RELEASE" "$DSS_IMAGE"
      exit 0
      ;;
    -h|--help)      usage; exit 0 ;;
    --)             shift; while [ "$#" -gt 0 ]; do PDFS+=("$1"); shift; done ;;
    -*)             err "unknown flag: $1"; usage; exit 2 ;;
    *)              PDFS+=("$1"); shift ;;
  esac
done

case "$EXPECT_LEVEL" in
  B-B|B-T) ;;
  "")  err "--expect-level is required (B-B or B-T)"; usage; exit 2 ;;
  *)   err "--expect-level must be B-B or B-T, got: $EXPECT_LEVEL"; exit 2 ;;
esac
if [ -z "$TRUST_PEM" ]; then err "--trust <pem> is required"; usage; exit 2; fi
if [ ! -r "$TRUST_PEM" ]; then err "trust bundle not readable: $TRUST_PEM"; exit 2; fi
if [ "${#PDFS[@]}" -eq 0 ]; then err "at least one <signed.pdf> is required"; usage; exit 2; fi
for pdf in "${PDFS[@]}"; do
  if [ ! -r "$pdf" ]; then err "PDF not readable: $pdf"; exit 2; fi
done

# Map our CLI level (B-B/B-T) to the DSS SignatureFormat token it asserts.
case "$EXPECT_LEVEL" in
  B-B) DSS_EXPECT_FORMAT="PAdES-BASELINE-B" ;;
  B-T) DSS_EXPECT_FORMAT="PAdES-BASELINE-T" ;;
esac

# ---------------------------------------------------------------------------------------------------
# Toolchain discovery. If NEITHER backend is available we self-skip the whole gate (exit 0): this is
# the opt-in env without the toolchain. If only one is available we run that half and SKIP the other
# (still a meaningful partial check); a self-skip never fails the gate.
# ---------------------------------------------------------------------------------------------------

# pyHanko: prefer an already-installed `pyhanko` on PATH; else a venv at $PYHANKO_VENV (CI creates one).
PYHANKO_BIN=""
detect_pyhanko() {
  if [ -n "${PYHANKO_VENV:-}" ] && [ -x "$PYHANKO_VENV/bin/pyhanko" ]; then
    PYHANKO_BIN="$PYHANKO_VENV/bin/pyhanko"; return 0
  fi
  if command -v pyhanko >/dev/null 2>&1; then
    PYHANKO_BIN="$(command -v pyhanko)"; return 0
  fi
  return 1
}

# Container engine for the DSS half.
detect_engine() {
  if [ -n "$CONTAINER_ENGINE" ]; then
    command -v "$CONTAINER_ENGINE" >/dev/null 2>&1 && return 0
    return 1
  fi
  for e in docker podman; do
    if command -v "$e" >/dev/null 2>&1; then CONTAINER_ENGINE="$e"; return 0; fi
  done
  return 1
}

HAVE_PYHANKO=0
HAVE_DSS=0
detect_pyhanko && HAVE_PYHANKO=1 || true
detect_engine  && HAVE_DSS=1     || true

if [ "$HAVE_PYHANKO" -eq 0 ] && [ "$HAVE_DSS" -eq 0 ]; then
  skip "profile-gate toolchain not installed (need pyHanko==${PYHANKO_VERSION} via pip and a container engine for EU DSS ${DSS_RELEASE}); see .github/workflows/profile-conformance.yml"
  exit 0
fi

# ---------------------------------------------------------------------------------------------------
# pyHanko AdES validation. `pyhanko sign adesverify` performs signature + chain (+ timestamp for B-T)
# validation for RSA and ECDSA P-256, exiting non-zero on any failure. We pass the operator's trust
# anchor with --trust and --trust-replace (use ONLY the supplied bundle — these are non-EUTL synthetic
# or real issuer chains, not the EU trusted list). --no-revocation-check because the synthetic /
# acceptance fixtures have no CRL/OCSP responder; the always-on OpenSSL bar already covers crypto, and
# this gate's job is AdES structure + profile level, not live revocation.
# ---------------------------------------------------------------------------------------------------
pyhanko_validate() {
  local pdf="$1"
  "$PYHANKO_BIN" sign adesverify \
    --trust "$TRUST_PEM" \
    --trust-replace \
    --no-revocation-check \
    --pretty-print \
    "$pdf"
}

# ---------------------------------------------------------------------------------------------------
# EU DSS structural baseline-LEVEL assertion. We run the DSS validation web app as a throwaway
# container, POST each PDF to its REST validation endpoint, and assert the SimpleReport's
# `SignatureFormat` equals the expected PAdES-BASELINE-B/-T. This is the ONE thing pyHanko's CLI does
# not assert (research D7).
# ---------------------------------------------------------------------------------------------------
DSS_CONTAINER=""
DSS_BASE_URL=""

dss_cleanup() {
  if [ -n "$DSS_CONTAINER" ]; then
    "$CONTAINER_ENGINE" rm -f "$DSS_CONTAINER" >/dev/null 2>&1 || true
    DSS_CONTAINER=""
  fi
}
trap dss_cleanup EXIT INT TERM

# Start the DSS container and wait for its REST endpoint to come up. Returns non-zero (so the caller
# self-skips the DSS half) if the image cannot be pulled or the service never becomes ready.
dss_start() {
  note "pulling EU DSS image (pinned ${DSS_IMAGE})"
  if ! "$CONTAINER_ENGINE" pull "$DSS_IMAGE" >/dev/null 2>&1; then
    return 1
  fi
  note "starting EU DSS validation web app on :${DSS_PORT}"
  DSS_CONTAINER="$("$CONTAINER_ENGINE" run -d -p "${DSS_PORT}:8080" "$DSS_IMAGE" 2>/dev/null)" || return 1
  DSS_BASE_URL="http://127.0.0.1:${DSS_PORT}"
  # The DSS demo webapp deploys at the ROOT context; the REST validation endpoint is
  # /services/rest/validation/validateSignature (DSS cookbook). Poll until it answers.
  local url="${DSS_BASE_URL}/services/rest/validation/validateSignature"
  local _
  for _ in $(seq 1 60); do
    # A bare GET/HEAD returns 4xx/405 (it wants a POST) but proves the service is up.
    if curl -fsS -o /dev/null "${DSS_BASE_URL}/" 2>/dev/null \
       || curl -s -o /dev/null -w '%{http_code}' "$url" 2>/dev/null | grep -qE '^[2345]'; then
      return 0
    fi
    sleep 2
  done
  return 1
}

# Assert one PDF's DSS-reported SignatureFormat matches DSS_EXPECT_FORMAT. Returns non-zero on
# mismatch or transport error (naming the offending value), so the gate fails loudly.
dss_assert_level() {
  local pdf="$1" b64 fmt
  b64="$(base64 < "$pdf" | tr -d '\n')"
  # Minimal DSS validateSignature request: just the signed document (PAdES is self-contained, no
  # detached original). python3 builds the JSON to avoid shell-quoting the large base64 payload.
  local reqfile respfile
  reqfile="$(mktemp)"; respfile="$(mktemp)"
  PDF_B64="$b64" PDF_NAME="$(basename "$pdf")" python3 - "$reqfile" <<'PY'
import json, os, sys
req = {
    "signedDocument": {
        "bytes": os.environ["PDF_B64"],
        "name": os.environ["PDF_NAME"],
    }
}
with open(sys.argv[1], "w", encoding="utf-8") as fh:
    json.dump(req, fh)
PY
  if ! curl -fsS -X POST \
        -H 'Content-Type: application/json' -H 'Accept: application/json' \
        --data @"$reqfile" \
        "${DSS_BASE_URL}/services/rest/validation/validateSignature" >"$respfile" 2>/dev/null; then
    rm -f "$reqfile" "$respfile"
    err "EU DSS validation request failed for $pdf"
    return 1
  fi
  # Extract every SignatureFormat the SimpleReport reports (there may be several signatures); the
  # report JSON nests them under simpleReport.signatureOrTimestampOrEvidenceRecord[].Signature.
  fmt="$(python3 - "$respfile" <<'PY'
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
fmts = []
def walk(node):
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "SignatureFormat" and isinstance(v, str):
                fmts.append(v)
            else:
                walk(v)
    elif isinstance(node, list):
        for v in node:
            walk(v)
walk(data)
print("\n".join(fmts))
PY
)"
  rm -f "$reqfile" "$respfile"
  if [ -z "$fmt" ]; then
    err "EU DSS report contained no SignatureFormat for $pdf (no signature detected?)"
    return 1
  fi
  # Every signature in the document must be at the expected baseline level.
  local line ok=1
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    if [ "$line" != "$DSS_EXPECT_FORMAT" ]; then
      err "PAdES level mismatch in $pdf: DSS reports '$line', expected '$DSS_EXPECT_FORMAT' (--expect-level $EXPECT_LEVEL)"
      ok=0
    fi
  done <<EOF
$fmt
EOF
  [ "$ok" -eq 1 ]
}

# ---------------------------------------------------------------------------------------------------
# Drive the gate over every input PDF.
# ---------------------------------------------------------------------------------------------------
FAILED=0
RAN=0            # set to 1 once at least one backend actually validated a PDF (vs. self-skipped)
ADES_RAN=0       # set to 1 once pyHanko actually ran AdES validation
LEVEL_ASSERTED=0 # set to 1 ONLY when EU DSS actually confirmed the baseline level (--expect-level)

# --- AdES half (pyHanko) ---
if [ "$HAVE_PYHANKO" -eq 1 ]; then
  note "pyHanko AdES validation ($("$PYHANKO_BIN" --version 2>/dev/null || echo "$PYHANKO_BIN"))"
  for pdf in "${PDFS[@]}"; do
    note "adesverify: $pdf"
    RAN=1
    ADES_RAN=1
    if pyhanko_validate "$pdf"; then
      printf 'PASS (AdES): %s\n' "$pdf" >&2
    else
      err "AdES validation FAILED: $pdf"
      FAILED=1
    fi
  done
else
  skip "pyHanko not available — AdES validation half skipped (install pyhanko-cli==${PYHANKO_CLI_VERSION} pyHanko==${PYHANKO_VERSION})"
fi

# --- Profile-LEVEL half (EU DSS) ---
if [ "$HAVE_DSS" -eq 1 ]; then
  if dss_start; then
    note "EU DSS baseline-level assertion (expect ${DSS_EXPECT_FORMAT})"
    for pdf in "${PDFS[@]}"; do
      note "dss level: $pdf"
      RAN=1
      LEVEL_ASSERTED=1
      if dss_assert_level "$pdf"; then
        printf 'PASS (level %s): %s\n' "$DSS_EXPECT_FORMAT" "$pdf" >&2
      else
        FAILED=1
      fi
    done
  else
    # The image was not pullable / the service never came up — self-skip the DSS half (do NOT fail).
    skip "EU DSS image '${DSS_IMAGE}' unavailable — baseline-level assertion skipped"
  fi
else
  skip "no container engine — EU DSS baseline-level assertion skipped"
fi

dss_cleanup
trap - EXIT INT TERM

if [ "$FAILED" -ne 0 ]; then
  err "profile-conformance gate FAILED"
  exit 1
fi
# If neither backend was actually available, every PDF was self-skipped — report a clean SKIP rather
# than a misleading PASS (exit 0 either way: a self-skip never fails the gate). This only happens when
# the opt-in toolchain is absent; the real validation runs in CI (profile-conformance.yml).
if [ "$RAN" -eq 0 ]; then
  skip "profile-gate toolchain not installed — every PDF was self-skipped (no AdES/level assertion made)"
  exit 0
fi
# Report EXACTLY which checks ran. The baseline-LEVEL (--expect-level B-B/-T) is asserted ONLY by the
# EU DSS half; the pyHanko half runs a level-agnostic adesverify. So we MUST NOT claim conformance "at
# level X" unless DSS actually confirmed level X — otherwise a B-B PDF would falsely "pass" an explicit
# --expect-level B-T assertion whenever DSS was unavailable. The level was REQUESTED on every run
# (--expect-level is required), so the only honest outcomes are:
#   * LEVEL_ASSERTED=1 — DSS confirmed the level: report PASS at the level (AdES too, if it ran).
#   * LEVEL_ASSERTED=0 — DSS did not run (no container engine / image unpullable): the level was NOT
#     checked. We do NOT print "PASSED ... at level X". The AdES half (if it ran) still passed; the
#     level assertion is reported as SKIPPED and is left explicitly NOT PERFORMED.
if [ "$LEVEL_ASSERTED" -eq 1 ]; then
  if [ "$ADES_RAN" -eq 1 ]; then
    note "profile-conformance gate PASSED for ${#PDFS[@]} PDF(s): AdES validated AND baseline level confirmed = ${EXPECT_LEVEL}"
  else
    note "profile-conformance gate PASSED for ${#PDFS[@]} PDF(s): baseline level confirmed = ${EXPECT_LEVEL} (AdES half SKIPPED — pyHanko unavailable)"
  fi
  exit 0
fi
# DSS did not run: the baseline level was NOT asserted. Only the AdES half ran here (RAN=1 with
# LEVEL_ASSERTED=0 implies ADES_RAN=1). Report the AdES PASS and the level as explicitly SKIPPED — never
# claim "at level ${EXPECT_LEVEL}".
note "profile-conformance gate: AdES PASSED for ${#PDFS[@]} PDF(s); baseline-level (${EXPECT_LEVEL}) assertion SKIPPED (EU DSS unavailable — level NOT asserted)"
exit 0
