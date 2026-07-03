## What does this change?

<!-- Summary of the change and why it's needed -->

## Checklist

- [ ] Read [CLAUDE.md](../CLAUDE.md) for this repo's conventions
- [ ] Added/updated tests in `test/*.spec.ts` (real workerd, not mocks)
- [ ] `pnpm format` and `pnpm typecheck` pass locally
- [ ] `pnpm test` passes locally (`pnpm test:heavy` too, if this touches `VAULTUR_HEAVY`)
- [ ] Schema changes went through `pnpm db:generate` (migrations under `migrations/` are generated, not hand-edited)
