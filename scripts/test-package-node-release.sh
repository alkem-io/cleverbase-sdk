#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

native_dir="$work_dir/native"
output_dir="$work_dir/out"
mkdir -p "$native_dir"

for target in \
  darwin-arm64 \
  darwin-x64 \
  linux-arm64-gnu \
  linux-x64-gnu; do
  printf 'cleverbase node fixture: %s\n' "$target" > "$native_dir/cleverbase.$target.node"
done

SOURCE_DATE_EPOCH=946684800 "$repo_root/scripts/package-node-release.sh" \
  "0.3.3" "$native_dir" "$output_dir"

package="$output_dir/alkemio-cleverbase-sdk-0.3.3.tgz"
test -f "$package"
python3 "$repo_root/scripts/check_sdk_artifact.py" node "$package" 0.3.3

first_package="$work_dir/first.tgz"
cp "$package" "$first_package"
touch -t 202001010000 "$native_dir"/*.node
SOURCE_DATE_EPOCH=946684800 "$repo_root/scripts/package-node-release.sh" \
  "0.3.3" "$native_dir" "$output_dir" >/dev/null
cmp "$first_package" "$package"

missing_dir="$work_dir/missing"
mkdir -p "$missing_dir"
cp "$native_dir"/cleverbase.darwin-arm64.node "$missing_dir"
if "$repo_root/scripts/package-node-release.sh" \
  "0.3.3" "$missing_dir" "$work_dir/missing-out" >/dev/null 2>&1; then
  echo "expected a missing native binary to fail" >&2
  exit 1
fi

if "$repo_root/scripts/package-node-release.sh" \
  "release-0.3.3" "$native_dir" "$work_dir/invalid" >/dev/null 2>&1; then
  echo "expected an invalid version to fail" >&2
  exit 1
fi

echo "package-node-release contract: ok"
