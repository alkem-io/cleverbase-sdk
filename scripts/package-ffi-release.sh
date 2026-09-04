#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <version> <linux|darwin> <amd64|arm64> <static-library> <output-directory>" >&2
  exit 2
}

if [ "$#" -ne 5 ]; then
  usage
fi

version="$1"
release_os="$2"
release_arch="$3"
library="$4"
output_dir="$5"
source_date_epoch="${SOURCE_DATE_EPOCH:-0}"

if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "invalid semantic version: $version" >&2
  exit 2
fi
case "$release_os" in
  linux|darwin) ;;
  *) echo "unsupported release OS: $release_os" >&2; exit 2 ;;
esac
case "$release_arch" in
  amd64|arm64) ;;
  *) echo "unsupported release architecture: $release_arch" >&2; exit 2 ;;
esac
if [ ! -f "$library" ]; then
  echo "static library not found: $library" >&2
  exit 2
fi
if [[ ! "$source_date_epoch" =~ ^[0-9]+$ ]]; then
  echo "SOURCE_DATE_EPOCH must be a non-negative integer" >&2
  exit 2
fi

tar_command="${TAR:-tar}"
if ! "$tar_command" --version 2>/dev/null | head -n 1 | grep -q 'GNU tar'; then
  if [ -n "${TAR:-}" ]; then
    echo "TAR must name a GNU tar executable" >&2
    exit 2
  elif command -v gtar >/dev/null 2>&1; then
    tar_command="gtar"
  else
    echo "GNU tar is required (install gtar on Darwin or set TAR)" >&2
    exit 2
  fi
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"
archive_name="cleverbase-ffi-v${version}-${release_os}-${release_arch}.tar.gz"
archive="$output_dir/$archive_name"

package_dir="$(mktemp -d)"
trap 'rm -rf "$package_dir"' EXIT
mkdir -p "$package_dir/lib"
cp "$library" "$package_dir/lib/libcleverbase_ffi.a"
cp "$repo_root/LICENSE" "$package_dir/LICENSE"

"$tar_command" \
  --sort=name \
  --format=ustar \
  --mtime="@$source_date_epoch" \
  --owner=0 \
  --group=0 \
  --numeric-owner \
  -C "$package_dir" \
  -cf - LICENSE lib/libcleverbase_ffi.a | gzip -n > "$archive"

if command -v sha256sum >/dev/null 2>&1; then
  digest="$(sha256sum "$archive" | awk '{print $1}')"
else
  digest="$(shasum -a 256 "$archive" | awk '{print $1}')"
fi
printf '%s  %s\n' "$digest" "$archive_name" > "$archive.sha256"

printf '%s\n' "$archive"
