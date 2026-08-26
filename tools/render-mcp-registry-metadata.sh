#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: tools/render-mcp-registry-metadata.sh --artifact PATH --output PATH" >&2
}

artifact=""
output=""
while (($#)); do
  case "$1" in
    --artifact)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      artifact=$2
      shift 2
      ;;
    --output)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      output=$2
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

[[ -n "$artifact" && -n "$output" ]] || { usage; exit 2; }
[[ -f "$artifact" ]] || { echo "artifact does not exist: $artifact" >&2; exit 1; }

filename=$(basename "$artifact")
version=${filename#stallhunt-}
version=${version%-x86_64-unknown-linux-gnu.mcpb}
[[ "$version" != "$filename" && -n "$version" ]] || {
  echo "unexpected MCPB filename: $filename" >&2
  exit 1
}

sha256=$(sha256sum "$artifact" | awk '{print $1}')
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
template="$repo_root/distribution/mcp-registry/server.json.in"
mkdir -p "$(dirname "$output")"
sed -e "s/@VERSION@/$version/g" -e "s/@SHA256@/$sha256/g" "$template" > "$output"
echo "$output"
