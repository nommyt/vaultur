# Vaultur

A Bitwarden-compatible server that runs entirely on Cloudflare — Workers,
D1, R2, KV, Durable Objects, and Email Sending — written in TypeScript with
[Hono](https://hono.dev). Works with the official Bitwarden clients
(browser extensions, mobile apps, desktop, CLI) as a self-hosted server.

Inspired by [vaultwarden](https://github.com/dani-garcia/vaultwarden) (the
API surface and semantics are ported from it) and
[warden-worker](https://github.com/qaz741wsd856/warden-worker) (the
deploy-and-forget Cloudflare architecture), rebuilt from scratch in
TypeScript with full organization support.

## Features

- **Identity**: register, prelogin, OAuth2 password grant, refresh tokens,
  API-key login, login-with-device (auth requests), new-device alerts
- **Vault**: sync, ciphers (all 5 types incl. SSH keys), folders, favorites,
  archives, soft-delete/restore, import, purge, per-cipher keys
- **Attachments** on R2 (v2 signed upload flow + legacy)
- **Bitwarden Send** (text + file, passwords, access limits)
- **Two-factor**: authenticator TOTP, email codes, recovery codes,
  remember-device tokens
- **Organizations**: collections, member lifecycle (invite → accept →
  confirm), roles incl. custom/manager, groups, policies (2FA, master
  password, single-org, personal-ownership, disable-send)
- **Emergency access** (view + takeover)
- **Live sync** via SignalR-compatible WebSockets on Durable Objects,
  plus mobile push relay
- **Email** via the Cloudflare Email Sending binding (no SMTP server)
- **Admin API**, icon proxy with KV cache, event logs, scheduled cleanup jobs
- **Web vault**: serves the official client (bw_web_builds) as static assets

## Repo layout

```
apps/server     Workers API (Hono) — the Bitwarden-compatible server
packages/db     Drizzle ORM schema for D1 (1:1 port of vaultwarden's schema)
packages/shared Protocol enums/constants shared across packages
```

The web vault UI is the official Bitwarden client (Vaultwarden's
[bw_web_builds](https://github.com/dani-garcia/bw_web_builds) patch set),
served by the Worker as static assets — no custom client is maintained here.

## Quick start

```bash
pnpm install
cd apps/server && cp .dev.vars.example .dev.vars  # set JWT_SECRET
pnpm db:migrate:local && pnpm dev                  # http://localhost:8787
```

Deploying to Cloudflare: see [docs/deployment.md](docs/deployment.md).

## Testing

Integration tests run the real Worker in workerd via
`@cloudflare/vitest-pool-workers` — D1, KV, R2 and Durable Objects included:

```bash
pnpm test
```

## License

AGPL-3.0 (same as vaultwarden, whose behavior this project ports).
Bitwarden is a trademark of Bitwarden, Inc. This project is not affiliated
with Bitwarden, Inc.
