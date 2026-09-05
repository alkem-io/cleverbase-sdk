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
test_name="regenerate_pades_bt_fixtures"
listed_tests="$(cargo test -p cleverbase-core --test independent_validation \
  "${test_name}" -- --ignored --exact --list)"
match_count="$(printf '%s\n' "${listed_tests}" | awk -v name="${test_name}: test" \
  '$0 == name { count++ } END { print count + 0 }')"
if [[ "${match_count}" != "1" ]]; then
  echo "error: expected exactly one ${test_name} test; found ${match_count}" >&2
  exit 1
fi
cargo test -p cleverbase-core --test independent_validation \
  "${test_name}" -- --ignored --exact
