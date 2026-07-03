# Deploying Vaultur

Vaultur is a single Cloudflare Worker. One `wrangler.jsonc` deploys the API,
the web vault, and the scheduled jobs — everything it needs runs on
Cloudflare:

| Concern                                          | Cloudflare product    | Binding                 |
| ------------------------------------------------ | --------------------- | ----------------------- |
| API + web-vault host                             | Workers               | —                       |
| Vault database                                   | D1 (SQLite)           | `VAULTUR_DB`            |
| Attachments & file Sends                         | R2                    | `VAULTUR_FILES`         |
| Icon cache, 2FA email codes, rate-limit counters | KV                    | `VAULTUR_KV`            |
| Live-sync WebSocket hub                          | Durable Objects       | `VAULTUR_NOTIFICATIONS` |
| Transactional email                              | Email Sending         | `VAULTUR_EMAIL`         |
| Web vault UI                                     | Workers Static Assets | `VAULTUR_ASSETS`        |

The whole thing fits inside Cloudflare's free tier (R2 needs a card on file but
has a free allowance).

---

## 0. Prerequisites

- A Cloudflare account.
- Node.js 22+ and pnpm 10+.
- Clone the repo and install: `pnpm install`
- Authenticate Wrangler once: `pnpm wrangler login`

All commands below are run from the **repository root**.

---

## 1. Create the storage resources

```bash
# D1 database — copy the printed "database_id"
pnpm wrangler d1 create vaultur

# KV namespace — copy the printed "id"
pnpm wrangler kv namespace create VAULTUR_KV

# R2 bucket (name must match wrangler.jsonc)
pnpm wrangler r2 bucket create vaultur-files
```

Open **`wrangler.jsonc`** and paste the two IDs:

```jsonc
"d1_databases": [{ "binding": "VAULTUR_DB", "database_name": "vaultur",
                   "database_id": "PASTE_D1_ID", "migrations_dir": "migrations" }],
"kv_namespaces": [{ "binding": "VAULTUR_KV", "id": "PASTE_KV_ID" }],
```

(The R2 bucket and the Durable Object are referenced by name/class and need no ID.)

---

## 2. Email Sending (recommended)

Transactional email — email verification, org/emergency invites, 2FA email
codes, new-device alerts, password hints — uses the
[Email Sending binding](https://developers.cloudflare.com/email-service/).

This requires a domain whose DNS is on Cloudflare — either registered
through Cloudflare, or registered with any other registrar and pointed at
Cloudflare's nameservers. The registrar doesn't matter; what matters is that
Cloudflare is authoritative for the zone, since Email Sending provisions and
validates DKIM/SPF records on it directly.

No domain on Cloudflare DNS? Skip this section entirely: remove the
`send_email` binding block and `VAULTUR_EMAIL` reference from
`wrangler.jsonc`, leave `EMAIL_FROM` unset, and Vaultur runs in **no-mail
mode** (see the note at the end of this section). There's no SMTP fallback —
Vaultur is built around Cloudflare Email Sending as its one mail transport by
design, not because Workers are technically incapable of speaking SMTP.

1. Onboard your domain for sending (one-time; requires the domain to be on
   Cloudflare with Email Routing):

   ```bash
   pnpm wrangler email sending enable yourdomain.com
   ```

2. Set the sender in `wrangler.jsonc` `vars`:

   ```jsonc
   "EMAIL_FROM": "vault@yourdomain.com",
   "EMAIL_FROM_NAME": "Vaultur"
   ```

3. (Optional, recommended) lock the sender address on the binding:

   ```jsonc
   "send_email": [{ "name": "VAULTUR_EMAIL", "allowed_sender_addresses": ["vault@yourdomain.com"] }]
   ```

> **Testing tip:** until your domain's DKIM/SPF is fully propagated, Email
> Sending will only deliver to **verified destination addresses**. Add your own
> address as a destination in the Cloudflare dashboard (Email → Email Routing →
> Destination addresses) to receive test mail.

**No-mail mode** (no `EMAIL_FROM` set), which mirrors vaultwarden without SMTP:

- signups don't require email verification;
- org and emergency-access invites are auto-accepted when the invitee already
  has an account;
- password hints are shown inline only if `SHOW_PASSWORD_HINT=true`.

---

## 3. Secrets

```bash
# HS256 signing secret for all JWTs (access/refresh/invite/etc.)
openssl rand -base64 64 | tr -d '\n' | pnpm wrangler secret put JWT_SECRET

# Optional — enables the admin panel (HTML UI + JSON API) at /admin/*. Omit to disable admin entirely.
openssl rand -base64 48 | tr -d '\n' | pnpm wrangler secret put ADMIN_TOKEN
```

Rotating `JWT_SECRET` invalidates all existing sessions (clients simply log in
again). It never touches vault data.

---

## 4. Apply database migrations

```bash
pnpm db:migrate:remote      # wrangler d1 migrations apply vaultur --remote
```

Schema changes: edit `src/db/schema.ts`, run `pnpm db:generate` (drizzle-kit
writes a new file under `migrations/`), then apply. Never hand-edit generated SQL.

---

## 5. Install the web vault UI

Vaultur serves the official Bitwarden web vault — Vaultwarden's
[bw_web_builds](https://github.com/dani-garcia/bw_web_builds) patch set — as
Workers static assets:

```bash
pnpm web-vault:fetch            # latest bw_web_builds release
pnpm web-vault:fetch v2026.4.1  # or pin a version
```

This populates `public/web-vault/` (gitignored). If you deploy **without**
running this, a placeholder landing page is used instead — the API and all
Bitwarden clients (mobile/extension/desktop/CLI) still work; only the browser
web vault is missing.

---

## 6. Deploy

```bash
pnpm deploy                     # bootstraps the assets dir, then wrangler deploy
```

> **Deploy config override:** The committed `wrangler.jsonc` is an open-source
> template with placeholder resource IDs. To deploy your own, either edit it in
> place, or (preferred for maintainers) keep a local `wrangler.deploy.jsonc`
> (gitignored) with your real IDs/domains — `pnpm deploy` and
> `pnpm db:migrate:remote` auto-use it when present, falling back to
> `wrangler.jsonc` otherwise. Override explicitly with
> `WRANGLER_CONFIG=path`.

Then point any Bitwarden client at `https://<your-worker-domain>` as the
self-hosted server URL. The default `*.workers.dev` domain works for testing;
for production use a custom domain (next section).

Verify it's live:

```bash
curl https://<your-worker-domain>/alive           # -> an ISO timestamp
curl https://<your-worker-domain>/api/config       # -> server metadata JSON
```

---

## 7. Custom domain (recommended for production)

The official mobile apps dislike `*.workers.dev`. Add a custom domain:

1. In the Cloudflare dashboard: **Workers & Pages → vaultur → Settings →
   Domains & Routes → Add → Custom domain**, e.g. `vault.example.com`.
2. Set the public origin so links and JWT issuers are correct:

   ```jsonc
   "routes": [{ "pattern": "vaultur.example.com", "custom_domain": true }],
   // wrangler.jsonc vars
   "DOMAIN": "https://vault.example.com"
   ```

3. Redeploy.

---

## 8. Mobile push notifications (optional)

To relay push to the official Bitwarden mobile apps, register for a push
installation id/key at <https://bitwarden.com/host> and set:

```jsonc
"PUSH_ENABLED": "true",
"PUSH_INSTALLATION_ID": "…",
"PUSH_INSTALLATION_KEY": "…"
```

Live sync over WebSockets (the `VAULTUR_NOTIFICATIONS` Durable Object) works without
this; push only affects background notifications on the mobile apps.

---

## 9. Scheduled jobs

Two cron triggers are configured in `wrangler.jsonc` and deploy automatically:

- `12 7 * * 0` (every Sunday 07:12) — purge soft-deleted ciphers older than
  `TRASH_AUTO_DELETE_DAYS`.
- `*/15 * * * *` — purge expired Sends (and their R2 objects), expired
  auth-requests, and stale incomplete-2FA records. Early-outs when there is
  nothing to purge, to avoid unnecessary R2/DB writes.

---

## Configuration reference

All non-secret settings live in `wrangler.jsonc` under `vars`. Highlights:

| Var                                  | Default        | Meaning                                                                                       |
| ------------------------------------ | -------------- | --------------------------------------------------------------------------------------------- |
| `DOMAIN`                             | request origin | Public origin used in links and JWT issuers                                                   |
| `SIGNUPS_ALLOWED`                    | `true`         | Open registration                                                                             |
| `SIGNUPS_DOMAINS_WHITELIST`          | —              | CSV of email domains allowed to sign up                                                       |
| `SIGNUPS_VERIFY`                     | `false`        | Require email verification before first login                                                 |
| `INVITATIONS_ALLOWED`                | `true`         | Allow inviting users who have no account yet                                                  |
| `EMERGENCY_ACCESS_ALLOWED`           | `true`         | Enable emergency access                                                                       |
| `SENDS_ALLOWED`                      | `true`         | Enable Bitwarden Send                                                                         |
| `ORG_CREATION_USERS`                 | `all`          | `all`, `none`, or CSV of emails allowed to create orgs                                        |
| `PASSWORD_HINTS_ALLOW`               | `true`         | Allow storing/serving password hints                                                          |
| `SHOW_PASSWORD_HINT`                 | `false`        | In no-mail mode, reveal hints inline                                                          |
| `PASSWORD_ITERATIONS`                | `100000`       | Server-side PBKDF2 rounds over the client hash (hard-capped at 100000 by Workers' Web Crypto) |
| `EMAIL_FROM` / `EMAIL_FROM_NAME`     | — / `Vaultur`  | Sender; empty `EMAIL_FROM` = no-mail mode                                                     |
| `PUSH_ENABLED` + installation id/key | `false`        | Mobile push relay                                                                             |
| `TRASH_AUTO_DELETE_DAYS`             | `30`           | Soft-delete purge window (0 disables)                                                         |
| `ICON_SERVICE`                       | `internal`     | `internal` (proxy+cache) or a redirect service                                                |
| `ICON_CACHE_TTL_SECONDS`             | `2592000`      | KV icon cache TTL (30 days)                                                                   |
| `LOGIN_RATELIMIT_MAX_BURST`          | `10`           | Login attempts per IP per minute (soft, KV-based)                                             |
| `ADMIN_SESSION_LIFETIME_MINUTES`     | `20`           | Admin cookie lifetime                                                                         |

Secrets (set with `wrangler secret put`, never in `wrangler.jsonc`):

| Secret        | Required | Meaning                                             |
| ------------- | -------- | --------------------------------------------------- |
| `JWT_SECRET`  | **yes**  | HS256 signing key for all tokens                    |
| `ADMIN_TOKEN` | no       | Enables `/admin/*`; omit to disable the admin panel |

### Admin panel overrides take precedence

Most of the table above is also editable at runtime from the admin panel's
Settings page (`/admin`, requires `ADMIN_TOKEN`). Saved edits are persisted as
a single JSON row in the D1 `server_config` table and layered on top of the
`wrangler.jsonc` vars on every request — so once a setting has been changed
in the panel, redeploying with a different value in `wrangler.jsonc` **will
not** take effect until that override is cleared. Use "Reset defaults" in the
panel (or `POST /admin/config/delete`) to fall back to the env value again.

---

## Local development

```bash
cp .dev.vars.example .dev.vars     # set JWT_SECRET (and ADMIN_TOKEN if wanted)
pnpm db:migrate:local              # apply migrations to the local D1
pnpm dev                           # wrangler dev on http://localhost:8787
```

`wrangler dev` uses a local simulation of D1/KV/R2/DO. The Email binding is a
no-op locally unless you configure `"remote": true` on the `send_email` binding.

Tests run against a real in-memory `workerd` (no deploy, no account needed):

```bash
pnpm typecheck
pnpm test
```

---

## Local checks (lefthook)

Checks run locally via [lefthook](https://lefthook.dev) git hooks
(`lefthook.yml`). Activate them once per clone:

```bash
pnpm exec lefthook install
```

- **pre-commit** — `pnpm format:check` + `pnpm typecheck` on staged files
- **pre-push** — `pnpm build` (deploy dry-run) + `pnpm test`

## Continuous deployment (optional)

To wire up your own CD (GitHub Actions or otherwise), create a Cloudflare API
token (Workers Scripts: Edit) and run:

```yaml
- run: pnpm install
- run: pnpm web-vault:fetch
- run: pnpm deploy
  env:
    CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}
    CLOUDFLARE_ACCOUNT_ID: ${{ secrets.CLOUDFLARE_ACCOUNT_ID }}
```

`JWT_SECRET` (and `ADMIN_TOKEN`) are set once via `wrangler secret put`; they
persist across deploys and don't need to be passed through CI.

---

## Migrating from vaultwarden

Vaultur's D1 schema is a 1:1 port of vaultwarden's SQLite schema — same table and
column names — so a `db.sqlite3` dump is a near-mechanical import. The only
transform needed is base64-encoding the two binary columns
(`users.password_hash`/`salt`, and the `sends` password columns), which Vaultur
stores as text. A dump-conversion script is planned under `scripts/`; until then
the schema parity keeps hand-migration straightforward.

---

## Troubleshooting

| Symptom                                                                                                            | Cause / fix                                                                                                                                                                                                                            |
| ------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `assets.directory ... does not exist` on deploy                                                                    | Run `pnpm web-vault:fetch` (or let `pnpm deploy` write the placeholder).                                                                                                                                                               |
| Mobile app can't connect on `*.workers.dev`                                                                        | Use a custom domain (section 7); some clients reject `workers.dev`.                                                                                                                                                                    |
| No emails arriving                                                                                                 | Check `EMAIL_FROM` is set, the domain is onboarded (`wrangler email sending list`), and the recipient is a verified destination during DKIM propagation.                                                                               |
| `Invalid claim` / logged out after deploy                                                                          | `JWT_SECRET` changed or isn't set. Set it once as a secret.                                                                                                                                                                            |
| `/admin` returns 404                                                                                               | `ADMIN_TOKEN` is not set — the admin panel is disabled by design.                                                                                                                                                                      |
| Live sync not updating                                                                                             | Confirm the `VAULTUR_NOTIFICATIONS` Durable Object migration (`tag: v1`) deployed; check the client reaches `/notifications/hub`.                                                                                                      |
| Extension/mobile "create account" fails (`masterPasswordHash cannot be blank`, `invalid email verification token`) | Official Bitwarden clients change their registration wire format over time (wrapped `masterPasswordAuthentication`/`masterPasswordUnlock` payloads, iOS's raw-text token response). Redeploy the latest `main` — Vaultur tracks these. |
