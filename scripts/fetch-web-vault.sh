#!/usr/bin/env bash
# Fetches the prebuilt Bitwarden web vault (Vaultwarden's patched build, bw_web_builds)
# into public/web-vault so wrangler bundles it as static assets,
# then applies Vaultur branding overrides.
#
# Usage: scripts/fetch-web-vault.sh [version]
#   version: bw_web_builds release tag (default: latest release)
#
# Set GITHUB_TOKEN to authenticate GitHub requests. Shared CI/build fleets
# (e.g. Cloudflare Workers Builds) commonly exhaust GitHub's 60/hr
# unauthenticated rate limit or trip its IP-based abuse detection, surfacing
# as a bare `curl: (22) ... 403`.

set -euo pipefail

REPO="dani-garcia/bw_web_builds"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$ROOT_DIR/public/web-vault"
OVERRIDES="$ROOT_DIR/public/overrides"

curl_gh() {
  if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    curl -fsSL -H "Authorization: Bearer $GITHUB_TOKEN" "$@"
  else
    curl -fsSL "$@"
  fi
}

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
  VERSION=$(curl_gh "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p')
fi
if [[ -z "$VERSION" ]]; then
  echo "Could not determine bw_web_builds version" >&2
  exit 1
fi

echo "Fetching bw_web_builds $VERSION ..."
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

curl_gh -o "$TMP/web-vault.tar.gz" \
  "https://github.com/$REPO/releases/download/$VERSION/bw_web_$VERSION.tar.gz"

rm -rf "$DEST"
mkdir -p "$DEST"
tar -xzf "$TMP/web-vault.tar.gz" -C "$DEST" --strip-components=1

# Rename vaultwarden.css reference to vaultur.css so our override is picked up
for htmlfile in "$DEST"/*.html; do
	[[ -f "$htmlfile" ]] || continue
	sed -i.bak -e 's/vaultwarden\.css/vaultur.css/g' "$htmlfile"
	rm -f "$htmlfile.bak"
done

# Apply Vaultur overrides (branding css, etc.) if present
if [[ -d "$OVERRIDES" ]]; then
  echo "Applying Vaultur overrides ..."
  cp -R "$OVERRIDES/." "$DEST/"
fi

echo "Web vault $VERSION installed at public/web-vault"
