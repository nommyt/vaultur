#!/usr/bin/env bash
# Ensures public/web-vault exists so `wrangler deploy` has an assets directory.
# If the real Bitwarden web vault hasn't been fetched yet (see
# scripts/fetch-web-vault.sh), drop in a minimal placeholder page. The Worker
# API serves fine without the UI; only the browser web vault is missing.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$ROOT_DIR/public/web-vault"

if [[ -f "$DEST/index.html" ]]; then
  exit 0
fi

echo "public/web-vault not found — writing a placeholder. Run 'pnpm web-vault:fetch' for the real web vault." >&2
mkdir -p "$DEST"

cat > "$DEST/index.html" <<'HTML'
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Vaultur</title>
    <style>
      body { font-family: system-ui, sans-serif; background: #f6f7fb; color: #333; display: grid; place-items: center; min-height: 100vh; margin: 0; }
      .card { background: #fff; padding: 2.5rem 3rem; border-radius: 12px; box-shadow: 0 6px 24px rgba(0,0,0,.08); max-width: 32rem; }
      h1 { color: #635bff; margin-top: 0; }
      code { background: #eef; padding: .1rem .35rem; border-radius: 4px; }
      a { color: #635bff; }
    </style>
  </head>
  <body>
    <div class="card">
      <h1>Vaultur</h1>
      <p>The Vaultur API is running. This is a placeholder page — the Bitwarden web vault UI has not been installed.</p>
      <p>To install it, run <code>pnpm web-vault:fetch</code> and redeploy, or point any Bitwarden client (mobile, browser extension, desktop, CLI) at this server URL.</p>
    </div>
  </body>
</html>
HTML

cp "$DEST/index.html" "$DEST/404.html"
