# Deploying Vaultur

Vaultur runs entirely on Cloudflare: Workers (Hono API), D1 (vault database),
R2 (attachments + file Sends), KV (icon cache, rate limiting, ephemeral codes),
Durable Objects (live-sync WebSocket hub), and the Email Sending binding
(transactional mail).

## Prerequisites

- A Cloudflare account (free tier works; R2 requires a card on file)
- `pnpm install` at the repo root
- Wrangler authenticated: `pnpm dlx wrangler login`

## 1. Create resources

```bash
cd apps/server

# D1 database — copy the printed database_id into wrangler.jsonc
pnpm dlx wrangler d1 create vaultur

# KV namespace — copy the id into wrangler.jsonc
pnpm dlx wrangler kv namespace create KV

# R2 bucket (name must match wrangler.jsonc)
pnpm dlx wrangler r2 bucket create vaultur-files
```

Edit `apps/server/wrangler.jsonc` and replace `REPLACE_WITH_D1_DATABASE_ID`
and `REPLACE_WITH_KV_NAMESPACE_ID`.

## 2. Email Sending (recommended)

Transactional email (verification, invites, 2FA codes, alerts) uses the
[Email Sending binding](https://developers.cloudflare.com/email-service/).

```bash
# One-time: onboard your domain for sending
pnpm dlx wrangler email sending enable yourdomain.com
```

Then set the sender in `wrangler.jsonc` vars:

```jsonc
"EMAIL_FROM": "vault@yourdomain.com",
"EMAIL_FROM_NAME": "Vaultur"
```

Without `EMAIL_FROM`, Vaultur runs in no-mail mode (like vaultwarden without
SMTP): signups don't require verification, org invites auto-accept, password
hints are shown inline if `SHOW_PASSWORD_HINT=true`.

## 3. Secrets

```bash
cd apps/server
openssl rand -base64 64 | tr -d '\n' | pnpm dlx wrangler secret put JWT_SECRET
# Optional — enables the /admin API:
openssl rand -base64 48 | tr -d '\n' | pnpm dlx wrangler secret put ADMIN_TOKEN
```

Rotating `JWT_SECRET` invalidates all sessions (clients just log in again);
vault data is never touched by it.

## 4. Migrations

```bash
pnpm --filter @vaultur/server db:migrate:remote
```

## 5. Web vault (official client)

Vaultur serves the prebuilt Bitwarden web vault (Vaultwarden's
[bw_web_builds](https://github.com/dani-garcia/bw_web_builds) patch set) as
Workers static assets:

```bash
bash scripts/fetch-web-vault.sh          # latest release
bash scripts/fetch-web-vault.sh v2026.4.1 # pinned
```

## 6. Deploy

```bash
pnpm --filter @vaultur/server deploy
```

Point any Bitwarden client (mobile / extension / desktop / CLI) at
`https://<your-worker-domain>` as a self-hosted server URL.

## Configuration reference

All vars live in `wrangler.jsonc` (`vars`) — see comments there. Highlights:

| Var | Default | Meaning |
| --- | --- | --- |
| `DOMAIN` | request origin | Public origin used in links/JWT issuer |
| `SIGNUPS_ALLOWED` | `true` | Open registration |
| `SIGNUPS_DOMAINS_WHITELIST` | — | CSV of email domains allowed to sign up |
| `SIGNUPS_VERIFY` | `false` | Require email verification before login |
| `ORG_CREATION_USERS` | `all` | `all`, `none`, or CSV of emails |
| `PASSWORD_ITERATIONS` | `600000` | Server-side PBKDF2 rounds |
| `TRASH_AUTO_DELETE_DAYS` | `30` | Purge window for soft-deleted items |
| `PUSH_ENABLED` + installation id/key | `false` | Mobile push relay (get credentials at bitwarden.com/host) |
| `ICON_CACHE_TTL_SECONDS` | 30 days | KV icon cache TTL |

## Local development

```bash
cd apps/server
cp .dev.vars.example .dev.vars   # set JWT_SECRET
pnpm db:migrate:local
pnpm dev                          # wrangler dev on http://localhost:8787
```

Tests run against an in-memory Workers runtime (no deploy needed):

```bash
pnpm --filter @vaultur/server test
```

## Migrating from vaultwarden

The D1 schema is a 1:1 port of vaultwarden's SQLite schema (same tables and
columns). A migration script that converts a vaultwarden `db.sqlite3` dump to
D1-importable SQL (base64-encoding the two binary password columns) is planned
in `scripts/`; until then the schema parity makes hand-migration mechanical.
