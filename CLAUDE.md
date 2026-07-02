# Vaultur — agent notes

Bitwarden-compatible server on Cloudflare Workers. Single Hono worker project
(not a monorepo). `src/` holds the worker; `src/db/` is the Drizzle schema,
`src/shared/` the protocol enums/constants.

## Ground rules

- **vaultwarden is the behavioral reference.** The Rust source lives at
  `../vaultwarden` (sibling checkout). When response shapes or permission
  semantics are unclear, read the corresponding `json!({...})` /
  `to_json` in vaultwarden and port it exactly — camelCase keys, `object`
  discriminators, list envelopes `{data, object: "list", continuationToken: null}`.
- Errors only via `src/error.ts` helpers (`err`, `errCode`, `errJson`,
  `notFound`) — clients parse that envelope.
- Read request bodies with `ci<T>(body, 'camelCaseKey')` (`src/util.ts`) —
  clients send both camelCase and PascalCase.
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

## Commands (run at repo root)

- `pnpm typecheck` — strict tsc
- `pnpm test` / `pnpm vitest run test/<file>.spec.ts` — integration tests in
  real workerd (D1/KV/R2/DO bindings via `@cloudflare/vitest-pool-workers`)
- `pnpm dev` — wrangler dev (needs `.dev.vars`, see `.dev.vars.example`)
- `pnpm deploy` — wrangler deploy

## Schema changes

Edit `src/db/schema.ts`, then `pnpm db:generate` (drizzle-kit). Never edit the
generated SQL under `migrations/` by hand.
