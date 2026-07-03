# Vaultur — agent notes

Bitwarden-compatible server on Cloudflare Workers, built as a single Hono
worker project. `src/` holds the worker; `src/db/` is the Drizzle schema,
`src/shared/` the protocol enums/constants.

## Ground rules

- **vaultwarden is the behavioral reference.** The Rust source lives at
  `../vaultwarden` (sibling checkout). When response shapes or permission
  semantics are unclear, read the corresponding `json!({...})` /
  `to_json` in vaultwarden and port it exactly — camelCase keys, `object`
  discriminators, list envelopes `{data, object: "list", continuationToken: null}`.
- **...but vaultwarden can lag the official clients.** If a request fails
  validation in a way that doesn't make sense (a field is "blank" when it's
  clearly filled, a token is "invalid" when it was just issued), don't assume
  vaultwarden's shape is still current — check the actual client source
  (`gh api`/`gh search code` against `bitwarden/ios`, `bitwarden/android`,
  `bitwarden/clients`, `bitwarden/server`) for what that specific client
  version actually sends. Example: 2026.5+ clients wrap registration's
  `masterPasswordHash`/`key` in `masterPasswordAuthentication`/
  `masterPasswordUnlock` objects; vaultwarden's `RegisterData` still only
  accepts the flat legacy fields.
- Errors only via `src/error.ts` helpers (`err`, `errCode`, `errJson`,
  `notFound`) — clients parse that envelope.
- Read request bodies with `ci<T>(body, 'camelCaseKey')` (`src/util.ts`) —
  clients send both camelCase and PascalCase. Newer clients also increasingly
  wrap several flat fields into one nested object instead of a breaking
  rename (e.g. `accountUnlockData`/`accountKeys`/`accountData` in key
  rotation, `masterPasswordAuthentication`/`masterPasswordUnlock` in
  registration) — read the flat shape first and fall back to the nested one
  via `ci()`, see `rotateKey` (`src/api/accounts.ts`) and `registerHandler`
  (`src/api/identity.ts`).
- A few endpoints return a bare token as the whole response body (e.g.
  `register/send-verification-email`). The official iOS client parses that
  response as raw bytes, not JSON, so `c.json(token)` corrupts it with
  literal quote characters — check `Device-Type` (`DeviceType.Ios`) and use
  `c.text(token)` for iOS; other clients expect the JSON-quoted form.
- Public `/api/*` routes (no bearer token) must be added to the
  `PUBLIC_API_ROUTES` allowlist in `src/auth/middleware.ts` — otherwise the
  first mounted `/api/*` `requireAuth` guard (Hono flattens sub-app
  middleware) will 401 them.
- Membership privilege does NOT follow numeric order (Owner=0, Admin=1,
  User=2, Manager=3). Always compare via `src/services/memberships.ts`.
- Hono matches in registration order: register static paths before `:param`
  paths of the same shape (e.g. `/ciphers/organization-details` before
  `/ciphers/:id`).
- Timestamps stored in vaultwarden's NaiveDateTime format via
  `src/db/datetime.ts` (`nowDb`/`toDb`), serialized with `toApi`.
- Formatting is enforced by oxfmt: tabs, double quotes, no semicolons,
  100-col — see `.oxfmtrc.json`. Run `pnpm format` before committing, or let
  the `lefthook` pre-commit hook catch it.

## Admin panel

`src/api/admin.ts` (routes) + `src/api/admin-views.tsx` (Hono JSX pages,
ported from vaultwarden's `templates/admin/*.hbs`) + `src/api/admin-assets.ts`
(inline CSS/JS, ported from `admin.js`/`admin_settings.js`). The whole surface
404s unless `ADMIN_TOKEN` is set; auth is a bearer token or a JWT session
cookie (`VAULTUR_ADMIN`, kind `"admin"`).

Editable settings (the admin Settings page) are declared in
`src/config-schema.ts` (`SETTINGS_GROUPS` — label, type, `get`/`apply` against
`Config`), not just added to `Config`/`env.ts`. Saved values are diffed
against the env baseline and persisted as a single JSON row in the D1
`server_config` table (`src/services/server-config.ts`), then layered back
onto the env-derived config on every request via `applyOverrides`. Adding a
new admin-editable setting means touching both `config.ts` (env default) and
`config-schema.ts` (form field); it's still just an env var if you skip the
latter.

## Commands (run at repo root)

- `pnpm typecheck` — strict tsc
- `pnpm test` / `pnpm vitest run test/<file>.spec.ts` — integration tests in
  real workerd (D1/KV/R2/DO bindings via `@cloudflare/vitest-pool-workers`)
- `pnpm format` / `pnpm format:check` — oxfmt write / check
- `pnpm dev` — wrangler dev (needs `.dev.vars`, see `.dev.vars.example`)
- `pnpm deploy` — wrangler deploy

Local git hooks (`lefthook`) enforce checks: pre-commit runs
`format:check`+`typecheck`, pre-push runs `build`+`test`. Run
`pnpm exec lefthook install` once per clone to activate the git hooks; they
don't run on their own otherwise.

## Schema changes

Edit `src/db/schema.ts`, then `pnpm db:generate` (drizzle-kit). Never edit the
generated SQL under `migrations/` by hand.
