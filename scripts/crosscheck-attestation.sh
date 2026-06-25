#!/usr/bin/env bash
# Independent cross-check harness (feature 004, task T017, FR-013 / Constitution Principle VI).
#
# Verifies EUDI attestation artifacts with an INDEPENDENT, DIFFERENT-LANGUAGE EU reference verifier
# and asserts the reference verdict AGREES with the expected/known verdict. This is the cross-check
# that backs FR-013's "produced/obtained artifacts are checked against an independent reference
# verifier" — it runs IN ADDITION TO, never instead of, the SDK's own always-on Rust verifier
# (`cargo test -p cleverbase-attestation`).
#
# It accepts an ARBITRARY artifact path (C1), so it cross-checks BOTH:
#   * the shared Tier-A conformance vectors and SDK-produced US1 material, AND
#   * US2-produced artifacts (an obtained credential + a holder `vp_token`) — the same harness, so
#     the independent-verifier agreement spans the whole produce/obtain/verify story.
#
# Two reference verifiers, one per format (no single different-language tool covers both):
#   * SD-JWT VC  — eudi-lib-jvm-sdjwt-kt (EUDI Wallet reference, Kotlin/JVM, Apache-2.0). A different
#                  language (JVM) and a different implementation than the SDK's Rust verifier.
#   * ISO mdoc   — mdoc-ts (TypeScript/Node, the OWF/EUDI mdoc reference). Again a different language
#                  and implementation.
# Neither is a build/runtime dependency of the SDK; both run locally so no artifact leaves the
# operator's machine (Principle IV). The real run happens in the opt-in CI job
# (.github/workflows, T030); locally it self-skips cleanly when the reference toolchain is absent.
#
# Exit status:
#   0  — every artifact's reference verdict matched the expected verdict (cross-check PASSED), OR
#   0  — with a "SKIP:" message, when the reference verifier for a needed format is not installed
#        (the harness self-skips so it never fails an environment that did not opt in — mirroring the
#        openssl/DSS-absent skips in the other gates), OR
#   1+ — at least one artifact's reference verdict DISAGREED with the expected verdict (FAILS loudly,
#        naming the artifact and the disagreement).
#
# Usage:
#   scripts/crosscheck-attestation.sh --expect {valid|invalid} [--format {sd-jwt-vc|mdoc|auto}] \
#       <artifact> [<artifact> ...]
#
# shellcheck disable=SC2310  # functions are used in `if` conditions, intentionally disabling -e there.
set -euo pipefail

# ---------------------------------------------------------------------------------------------------
# Pinned reference verifiers — SINGLE SOURCE OF TRUTH (Constitution Principle III).
#
# The opt-in CI job MUST install/pull these exact versions (it reads them via `--print-pins`, so the
# workflow and this local harness can never drift). Bump them here and only here. These are mutable
# upstream coordinates today; override the *_CMD env vars to point at a self-hosted/pinned build.
# ---------------------------------------------------------------------------------------------------
SDJWT_REF_VERSION="0.13.0"   # eudi-lib-jvm-sdjwt-kt (Kotlin/JVM) reference SD-JWT VC verifier
MDOC_REF_VERSION="0.6.0"     # mdoc-ts (TypeScript) reference ISO 18013-5 mdoc verifier

# The reference-verifier entry points. Each MUST: read the artifact path as $1, exit 0 when the
# artifact verifies and non-zero when it does not (the universal "valid/invalid" contract this
# harness compares against). Override via env to wire a self-hosted/pinned build; otherwise the
# harness looks for these on PATH and self-skips when absent.
SDJWT_REF_CMD="${SDJWT_REF_CMD:-eudi-sdjwt-verify}"
MDOC_REF_CMD="${MDOC_REF_CMD:-mdoc-ts-verify}"

PROG="$(basename "$0")"

err()  { printf '%s: error: %s\n' "$PROG" "$*" >&2; }
skip() { printf 'SKIP: %s\n' "$*" >&2; }
note() { printf '==> %s\n' "$*" >&2; }

usage() {
  cat >&2 <<EOF
Usage: $PROG --expect {valid|invalid} [--format {sd-jwt-vc|mdoc|auto}] <artifact> [<artifact> ...]

  --expect valid|invalid   the known verdict every artifact must reproduce under the reference verifier
  --format sd-jwt-vc|mdoc|auto
                           force the artifact format, or auto-detect (default: auto)
  --print-pins             print the pinned reference-verifier versions (for CI to read) and exit 0
  -h, --help               show this help

Cross-checks artifacts against an INDEPENDENT, different-language EU reference verifier
(eudi-lib-jvm-sdjwt-kt for SD-JWT VC; mdoc-ts for mdoc) and asserts the reference verdict matches
--expect. Self-skips (exit 0 with a SKIP message) when the needed reference verifier is unavailable.

Pinned: eudi-lib-jvm-sdjwt-kt==${SDJWT_REF_VERSION} (\$SDJWT_REF_CMD), mdoc-ts==${MDOC_REF_VERSION} (\$MDOC_REF_CMD).
EOF
}

# ---------------------------------------------------------------------------------------------------
# Argument parsing.
# ---------------------------------------------------------------------------------------------------
EXPECT=""
FORMAT="auto"
ARTIFACTS=()

while [ "$#" -gt 0 ]; do
  case "$1" in
    --expect) EXPECT="${2:-}"; shift 2 ;;
    --format) FORMAT="${2:-}"; shift 2 ;;
    --print-pins)
      printf 'SDJWT_REF_VERSION=%s\nMDOC_REF_VERSION=%s\nSDJWT_REF_CMD=%s\nMDOC_REF_CMD=%s\n' \
        "$SDJWT_REF_VERSION" "$MDOC_REF_VERSION" "$SDJWT_REF_CMD" "$MDOC_REF_CMD"
      exit 0
      ;;
    -h|--help) usage; exit 0 ;;
    --)        shift; while [ "$#" -gt 0 ]; do ARTIFACTS+=("$1"); shift; done ;;
    -*)        err "unknown flag: $1"; usage; exit 2 ;;
    *)         ARTIFACTS+=("$1"); shift ;;
  esac
done

case "$EXPECT" in
  valid|invalid) ;;
  "") err "--expect is required (valid or invalid)"; usage; exit 2 ;;
  *)  err "--expect must be valid or invalid, got: $EXPECT"; exit 2 ;;
esac
case "$FORMAT" in
  sd-jwt-vc|mdoc|auto) ;;
  *) err "--format must be sd-jwt-vc, mdoc, or auto, got: $FORMAT"; exit 2 ;;
esac
if [ "${#ARTIFACTS[@]}" -eq 0 ]; then err "at least one <artifact> is required"; usage; exit 2; fi
for a in "${ARTIFACTS[@]}"; do
  if [ ! -r "$a" ]; then err "artifact not readable: $a"; exit 2; fi
done

# ---------------------------------------------------------------------------------------------------
# Format detection (auto): an SD-JWT VC artifact is UTF-8 text whose first `~`-segment is a 3-part
# compact JWS; anything else is treated as a binary mdoc DeviceResponse. Mirrors the core's
# `detect_format` heuristic so the harness routes an arbitrary artifact to the right reference tool.
# ---------------------------------------------------------------------------------------------------
detect_format() {
  # $1 = artifact path. Echoes "sd-jwt-vc" or "mdoc".
  local path="$1" first
  # An SD-JWT VC is printable ASCII with a `~`; read the first line and look for the compact-JWS shape.
  if LC_ALL=C grep -qU '~' "$path" 2>/dev/null && file "$path" 2>/dev/null | grep -qiE 'text|ascii'; then
    first="$(head -c 4096 "$path" | tr -d '\n')"
    # The issuer JWS is the segment before the first `~`; require exactly two dots (header.payload.sig).
    local jws="${first%%~*}"
    if [ "$(printf '%s' "$jws" | tr -cd '.' | wc -c | tr -d ' ')" = "2" ]; then
      printf 'sd-jwt-vc'
      return 0
    fi
  fi
  printf 'mdoc'
}

# ---------------------------------------------------------------------------------------------------
# Reference-verifier discovery. If the verifier needed for ANY artifact's format is unavailable, the
# whole harness self-skips (exit 0): this is the common case locally (the EU reference toolchain is
# not installed). A self-skip never fails the cross-check.
# ---------------------------------------------------------------------------------------------------
detect_ref() {
  # $1 = format. Returns 0 when the matching reference verifier is on PATH, 1 otherwise.
  local fmt="$1"
  case "$fmt" in
    sd-jwt-vc) command -v "$SDJWT_REF_CMD" >/dev/null 2>&1 && return 0 ;;
    mdoc)      command -v "$MDOC_REF_CMD"  >/dev/null 2>&1 && return 0 ;;
  esac
  return 1
}

# Resolve each artifact's format first, so we can self-skip up front if a needed verifier is missing.
declare -a FORMATS=()
NEED_SDJWT=0
NEED_MDOC=0
for a in "${ARTIFACTS[@]}"; do
  if [ "$FORMAT" = "auto" ]; then fmt="$(detect_format "$a")"; else fmt="$FORMAT"; fi
  FORMATS+=("$fmt")
  case "$fmt" in
    sd-jwt-vc) NEED_SDJWT=1 ;;
    mdoc)      NEED_MDOC=1 ;;
  esac
done

if [ "$NEED_SDJWT" = "1" ] && ! detect_ref sd-jwt-vc; then
  skip "SD-JWT VC reference verifier '$SDJWT_REF_CMD' (eudi-lib-jvm-sdjwt-kt ${SDJWT_REF_VERSION}) not found on PATH; not opting in to the independent cross-check."
  exit 0
fi
if [ "$NEED_MDOC" = "1" ] && ! detect_ref mdoc; then
  skip "mdoc reference verifier '$MDOC_REF_CMD' (mdoc-ts ${MDOC_REF_VERSION}) not found on PATH; not opting in to the independent cross-check."
  exit 0
fi

# ---------------------------------------------------------------------------------------------------
# Run the reference verifier per artifact and assert its verdict matches --expect.
# ---------------------------------------------------------------------------------------------------
run_ref() {
  # $1 = format, $2 = artifact path. Echoes "valid" or "invalid" from the reference verifier's exit
  # code (0 = valid, non-zero = invalid — the universal contract documented above).
  local fmt="$1" path="$2" bin
  case "$fmt" in
    sd-jwt-vc) bin="$SDJWT_REF_CMD" ;;
    mdoc)      bin="$MDOC_REF_CMD" ;;
  esac
  if "$bin" "$path" >/dev/null 2>&1; then printf 'valid'; else printf 'invalid'; fi
}

FAILURES=0
for i in "${!ARTIFACTS[@]}"; do
  artifact="${ARTIFACTS[$i]}"
  fmt="${FORMATS[$i]}"
  note "cross-checking ($fmt) $artifact against the independent reference verifier"
  verdict="$(run_ref "$fmt" "$artifact")"
  if [ "$verdict" = "$EXPECT" ]; then
    note "  reference verdict '$verdict' AGREES with expected '$EXPECT'"
  else
    err "reference verdict '$verdict' DISAGREES with expected '$EXPECT' for: $artifact"
    FAILURES=$((FAILURES + 1))
  fi
done

if [ "$FAILURES" -gt 0 ]; then
  err "$FAILURES artifact(s) disagreed with the independent reference verifier"
  exit 1
fi
note "all ${#ARTIFACTS[@]} artifact(s) agreed with the independent reference verifier"
exit 0
