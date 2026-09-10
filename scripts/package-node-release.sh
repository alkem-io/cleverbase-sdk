#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <version> <native-directory> <output-directory>" >&2
  exit 2
}

if [ "$#" -ne 3 ]; then
  usage
fi

version="$1"
native_dir="$2"
output_dir="$3"

if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "invalid semantic version: $version" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
node_source="$repo_root/bindings/node"
package_dir="$(mktemp -d)"
trap 'rm -rf "$package_dir"' EXIT

for source_file in package.json index.js index.d.ts; do
  cp "$node_source/$source_file" "$package_dir/$source_file"
done
cp "$repo_root/README.md" "$package_dir/README.md"
cp "$repo_root/LICENSE" "$package_dir/LICENSE"

for target in \
  darwin-arm64 \
  darwin-x64 \
  linux-arm64-gnu \
  linux-x64-gnu; do
  native_file="cleverbase.$target.node"
  if [ ! -s "$native_dir/$native_file" ]; then
    echo "native Node binding not found or empty: $native_dir/$native_file" >&2
    exit 2
  fi
  cp "$native_dir/$native_file" "$package_dir/$native_file"
done

mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"
(
  cd "$package_dir"
  npm pack --ignore-scripts --pack-destination "$output_dir" >/dev/null
)

package="$output_dir/alkemio-cleverbase-sdk-$version.tgz"
python3 "$repo_root/scripts/check_sdk_artifact.py" node "$package" "$version" >/dev/null
printf '%s\n' "$package"
