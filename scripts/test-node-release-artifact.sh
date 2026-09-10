#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <npm-tarball>" >&2
  exit 2
}

if [ "$#" -ne 1 ]; then
  usage
fi

package="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
if [ ! -f "$package" ]; then
  echo "npm tarball not found: $package" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT
work_dir="$(cd "$work_dir" && pwd -P)"

cd "$work_dir"
npm init --yes >/dev/null
npm install --ignore-scripts "$package" cbor@9.0.2 >/dev/null

resolved="$(node -e 'process.stdout.write(require.resolve("@alkemio/cleverbase-sdk"))')"
case "$resolved" in
  "$work_dir"/*) ;;
  *) echo "installed package resolved outside the clean consumer: $resolved" >&2; exit 1 ;;
esac

NODE_PATH="$work_dir/node_modules" \
CLEVERBASE_NODE_MODULE="@alkemio/cleverbase-sdk" \
  node --test "$repo_root"/bindings/node/test/*.test.cjs
