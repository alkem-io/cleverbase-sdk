#!/usr/bin/env bash
#
# smoke.sh — post-build smoke test for a reference-integration container image.
#
# Starts the given image, waits for it to become ready, and asserts a basic liveness
# endpoint responds. Always cleans up the container it started.
#
# Usage:
#   smoke.sh <image-ref> <go|web> [port]
#
# Arguments:
#   <image-ref>   Fully-qualified image reference to run (e.g. ghcr.io/owner/cleverbase-refsvc:sha-abc1234).
#   <go|web>      Probe type:
#                   go  — HTTP service exposing /healthz (signing-service, mock-upstream).
#                   web — static file server; probe the root path "/" (no /healthz).
#   [port]        Container port to publish AND probe. Defaults to 8080.
#                 For the mock-upstream image pass 9000.
#
# Examples:
#   smoke.sh ghcr.io/owner/cleverbase-refsvc:latest  go          # probes :8080/healthz
#   smoke.sh ghcr.io/owner/cleverbase-refmock:latest go 9000     # probes :9000/healthz
#   smoke.sh ghcr.io/owner/cleverbase-refweb:latest  web         # probes :8080/
#
# Exit status: 0 on PASS, non-zero on FAIL.

set -euo pipefail

# --- argument parsing ------------------------------------------------------------------

usage() {
  echo "Usage: $(basename "$0") <image-ref> <go|web> [port]" >&2
}

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
  usage
  exit 2
fi

IMAGE_REF="$1"
PROBE_TYPE="$2"
PORT="${3:-8080}"

case "$PROBE_TYPE" in
  go | web) ;;
  *)
    echo "error: probe type must be 'go' or 'web', got '${PROBE_TYPE}'" >&2
    usage
    exit 2
    ;;
esac

if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
  echo "error: port must be an integer in 1..65535, got '${PORT}'" >&2
  exit 2
fi

# The probe path depends on the component type. The static web server has no /healthz, so
# the root path is the readiness signal there.
case "$PROBE_TYPE" in
  go) PROBE_PATH="/healthz" ;;
  web) PROBE_PATH="/" ;;
esac

PROBE_URL="http://localhost:${PORT}${PROBE_PATH}"
READINESS_TIMEOUT_SECS=30
CONTAINER_ID=""

# --- cleanup ---------------------------------------------------------------------------

cleanup() {
  # Best-effort teardown; never let cleanup mask the real exit status.
  if [ -n "$CONTAINER_ID" ]; then
    docker rm -f "$CONTAINER_ID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  # Surface a few log lines to aid debugging when the probe never succeeds.
  if [ -n "$CONTAINER_ID" ]; then
    echo "----- last container logs -----" >&2
    docker logs --tail 50 "$CONTAINER_ID" 2>&1 | sed 's/^/  /' >&2 || true
    echo "-------------------------------" >&2
  fi
  exit 1
}

# --- run -------------------------------------------------------------------------------

echo "Starting ${IMAGE_REF} (probe ${PROBE_TYPE} at ${PROBE_URL}) ..."

# Publish and probe the same port number inside and outside the container. Extra `docker run` flags
# (e.g. the env the signing service needs to pass config) come from SMOKE_RUN_ARGS.
# shellcheck disable=SC2086
CONTAINER_ID="$(docker run -d -p "${PORT}:${PORT}" ${SMOKE_RUN_ARGS:-} "$IMAGE_REF")" \
  || fail "could not start container from ${IMAGE_REF}"

echo "Container ${CONTAINER_ID} started; waiting up to ${READINESS_TIMEOUT_SECS}s for readiness ..."

deadline=$(( SECONDS + READINESS_TIMEOUT_SECS ))
while true; do
  # If the container died, fail fast rather than waiting out the full timeout.
  if [ -z "$(docker ps -q --no-trunc --filter "id=${CONTAINER_ID}")" ]; then
    fail "container exited before becoming ready"
  fi

  if curl -fsS -o /dev/null "$PROBE_URL"; then
    break
  fi

  if [ "$SECONDS" -ge "$deadline" ]; then
    fail "timed out after ${READINESS_TIMEOUT_SECS}s waiting for ${PROBE_URL}"
  fi

  sleep 1
done

echo "PASS: ${IMAGE_REF} responded at ${PROBE_URL}"
exit 0
