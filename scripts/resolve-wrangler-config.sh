#!/usr/bin/env bash
# Prints which wrangler config file deploy/migration commands should use: an
# explicit WRANGLER_CONFIG override, else the gitignored wrangler.deploy.jsonc
# (real resource IDs) if present, else the committed wrangler.jsonc template.
# Single source of truth for the `deploy` and `db:migrate:remote` package.json
# scripts, so both always resolve to the same config within one invocation.
set -euo pipefail

if [[ -n "${WRANGLER_CONFIG:-}" ]]; then
	echo "$WRANGLER_CONFIG"
elif [[ -f wrangler.deploy.jsonc ]]; then
	echo "wrangler.deploy.jsonc"
else
	echo "wrangler.jsonc"
fi
