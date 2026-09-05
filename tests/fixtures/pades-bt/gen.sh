#!/usr/bin/env bash
# Human-run recipe for the checked-in PAdES B-T verifier fixtures. Not part of the test run.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

version="$(openssl version)"
case "${version}" in
  "OpenSSL 3."*) ;;
  *)
    echo "error: fixture generation requires OpenSSL 3; found: ${version}" >&2
    exit 1
    ;;
esac

cd "${REPO_ROOT}"
cargo test -p cleverbase-core --test independent_validation \
  regenerate_pades_bt_fixtures -- --ignored --exact
