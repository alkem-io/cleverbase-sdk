#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

fake_lib="$work_dir/libcleverbase_ffi.a"
output_dir="$work_dir/out"
printf 'cleverbase ffi archive fixture\n' > "$fake_lib"

"$repo_root/scripts/package-ffi-release.sh" \
  "0.1.0" "linux" "amd64" "$fake_lib" "$output_dir"

archive="$output_dir/cleverbase-ffi-v0.1.0-linux-amd64.tar.gz"
checksum="$archive.sha256"
test -f "$archive"
test -f "$checksum"

tar -tzf "$archive" | diff -u - <(printf '%s\n' LICENSE lib/libcleverbase_ffi.a)
(
  cd "$output_dir"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c "$(basename "$checksum")"
  else
    shasum -a 256 -c "$(basename "$checksum")"
  fi
)

extract_dir="$work_dir/extract"
mkdir -p "$extract_dir"
tar -xzf "$archive" -C "$extract_dir"
cmp "$fake_lib" "$extract_dir/lib/libcleverbase_ffi.a"
cmp "$repo_root/LICENSE" "$extract_dir/LICENSE"

for invalid in \
  "release-0.1.0 linux amd64" \
  "0.1.0 windows amd64" \
  "0.1.0 linux ppc64"; do
  read -r version os arch <<< "$invalid"
  if "$repo_root/scripts/package-ffi-release.sh" \
    "$version" "$os" "$arch" "$fake_lib" "$work_dir/invalid" >/dev/null 2>&1; then
    echo "expected invalid release coordinates to fail: $invalid" >&2
    exit 1
  fi
done

echo "package-ffi-release contract: ok"
