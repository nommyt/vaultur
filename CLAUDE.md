# Vaultur — agent notes

Bitwarden-compatible server on Cloudflare Workers. pnpm monorepo.

## Ground rules

- **vaultwarden is the behavioral reference.** The Rust source lives at
  `../vaultwarden` (sibling checkout). When response shapes or permission
  semantics are unclear, read the corresponding `json!({...})` /
  `to_json` in vaultwarden and port it exactly — camelCase keys, `object`
  discriminators, list envelopes `{data, object: "list", continuationToken: null}`.
- Errors only via `apps/server/src/error.ts` helpers (`err`, `errCode`,
  `errJson`, `notFound`) — clients parse that envelope.
- Read request bodies with `ci<T>(body, 'camelCaseKey')` (`src/util.ts`) —
  clients send both camelCase and PascalCase.
- Membership privilege does NOT follow numeric order (Owner=0, Admin=1,
  User=2, Manager=3). Always compare via `src/services/memberships.ts`.
- Hono matches in registration order: public routes before
  `.use('*', requireAuth)`; static paths before `:param` paths.
- Timestamps stored in vaultwarden's NaiveDateTime format via
  `packages/db/src/datetime.ts` (`nowDb`/`toDb`), serialized with `toApi`.

## Commands (run in apps/server)

- `pnpm typecheck` — strict tsc
- `pnpm test` / `pnpm vitest run test/<file>.spec.ts` — integration tests in
  real workerd (D1/KV/R2/DO bindings via `@cloudflare/vitest-pool-workers`)
- `pnpm dev` — wrangler dev (needs `.dev.vars`, see `.dev.vars.example`)

## Schema changes

Edit `packages/db/src/schema.ts`, then `pnpm --filter @vaultur/db generate`.
Never edit generated SQL in `packages/db/migrations` by hand.
