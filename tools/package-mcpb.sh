#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: tools/package-mcpb.sh --binary PATH --output-dir DIR" >&2
}

binary=""
output_dir=""
while (($#)); do
  case "$1" in
    --binary)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      binary=$2
      shift 2
      ;;
    --output-dir)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      output_dir=$2
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

[[ -n "$binary" && -n "$output_dir" ]] || { usage; exit 2; }
[[ -x "$binary" ]] || { echo "binary is not executable: $binary" >&2; exit 1; }
command -v zip >/dev/null || { echo "zip is required to build an MCPB" >&2; exit 1; }

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
manifest="$repo_root/distribution/mcpb/manifest.json"
version=$("$binary" version | sed -n 's/^stallhunt //p')
manifest_version=$(sed -n 's/^[[:space:]]*"version": "\([^"]*\)",/\1/p' "$manifest" | head -n 1)

[[ -n "$version" ]] || { echo "could not read Stallhunt version from $binary" >&2; exit 1; }
[[ "$version" == "$manifest_version" ]] || {
  echo "binary version $version does not match MCPB manifest $manifest_version" >&2
  exit 1
}

mkdir -p "$output_dir"
output_dir=$(cd "$output_dir" && pwd)
staging=$(mktemp -d)
trap 'rm -rf -- "$staging"' EXIT
mkdir -p "$staging/server"

cp "$manifest" "$staging/manifest.json"
cp "$repo_root/assets/stallhunt-icon-512.png" "$staging/icon.png"
cp "$binary" "$staging/server/stallhunt"
cp "$repo_root/README.md" "$repo_root/PRIVACY.md" "$repo_root/TERMS.md" \
  "$repo_root/LICENSE-MIT" "$repo_root/LICENSE-APACHE" "$staging/"
chmod 0755 "$staging/server/stallhunt"

artifact="$output_dir/stallhunt-$version-x86_64-unknown-linux-gnu.mcpb"
(cd "$staging" && zip -X -q -r "$artifact" .)
(cd "$output_dir" && sha256sum "$(basename "$artifact")" > "$(basename "$artifact").sha256")
echo "$artifact"
