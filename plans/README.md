# Implementation Plans

Three audit runs are recorded here. Open plan files are self-contained: read
them fully before starting, honor their STOP conditions, and update the status
row when done. Completed plan files are deleted; their DONE rows remain below
as implementation history.

1. **2026-07-06 — security focus** (standard depth), against commit `7eb3a33`:
   plans 001–002.
2. **2026-07-08 — drift focus** (deep; vaultwarden + Bitwarden-client drift),
   also against commit `7eb3a33`: plan 003, plus a recorded backlog of vetted
   drift findings below.
3. **2026-07-08 — public-deployment security focus** (standard depth; scoped
   to "server is public on workers.dev — restrict it to specific
   users/emails while keeping Bitwarden clients working"), also against
   commit `7eb3a33`: plans 004–006.

## Execution order & status

| Plan | Title                                                                                 | Priority | Effort | Depends on | Status |
| ---- | ------------------------------------------------------------------------------------- | -------- | ------ | ---------- | ------ |
| 001  | Block an org Admin from resetting a higher-ranked (Owner's) master password           | P1       | S      | —          | DONE   |
| 002  | Replace the full-table Send scan on the public access endpoint with an indexed lookup | P2       | S      | —          | DONE   |
| 003  | Add an automated upstream-drift tracker (Vaultwarden + Bitwarden release signals)     | P1       | M      | —          | TODO   |
| 004  | Enforce a login-time email allowlist across every authentication path                 | P1       | M      | —          | DONE   |
| 005  | Document and template the edge-hardening runbook (custom domain, Access, WAF, config) | P1       | S–M    | —          | DONE   |
| 006  | Add a per-account failed-login limiter alongside the per-IP one                       | P3       | S      | —          | DONE   |

Status values: TODO | IN PROGRESS | DONE | BLOCKED (one-line reason) |
REJECTED (one-line rationale).

Only plan **003** remains open.

## Maintenance notes

- Completed plan 004's maintenance rule still binds future work: the
  drift-backlog `send_access` grant (D3) must consciously decide its allowlist
  stance when implemented.

---

# 2026-07-06 security audit

## Findings → plans

- **001** fixes a broken-access-control bug: the org account-recovery
  reset-password endpoints (`src/api/org-members.ts:1339`, `:1365`) enforce only
  `requireMember(Admin)` and are missing vaultwarden's rank rule, so an org
  Admin can reset an **Owner's** master password and take over the account.
- **002** fixes an unauthenticated resource-exhaustion / DoS vector: the public
  `POST /api/sends/access/:accessId` endpoint (`src/api/sends.ts:217`) loads the
  entire `sends` table and linearly scans it per request, instead of decoding
  the access id to a UUID and doing an indexed lookup (vaultwarden
  `Send::find_by_access_id`).

## Findings reported but NOT selected for a plan

- **YubiKey OTP response signature check is conditional** (`src/services/yubikey.ts:69`)
  — `if (response.h) { …verify… }` skips integrity verification when the
  YubiCloud response omits the `h` field. Real but only exploitable via a TLS
  MITM of `api.yubico.com`; LOW severity, defense-in-depth. Left unplanned by
  the maintainer's selection; revisit if desired (fix: require a valid `h` on any
  `status=OK` response).

## Findings considered and rejected (so they aren't re-audited)

- **`access_token` accepted as a URL query parameter** (`src/auth/middleware.ts:65`):
  tokens in URLs can leak via logs/referrer, but this is required by the SignalR
  notifications WebSocket client and matches vaultwarden. By-design; note only.
- **Refresh token survives a master-password change** (`refreshLogin`,
  `src/api/identity.ts`): the refreshed access token re-embeds the _current_
  security stamp, so a stale refresh token keeps minting valid tokens after
  "log out everywhere." This is vaultwarden's exact security-stamp model —
  by-design parity, not a Vaultur regression.
- **Soft per-IP KV login rate limiting** (`src/services/ratelimit.ts`): documented
  best-effort fixed-window limiter; matches vaultwarden's approach. Real hardening
  belongs at the Cloudflare WAF layer, not here.
- **Admin panel XSS / CSRF**: checked and safe — Hono JSX auto-escapes all
  user-controlled fields, `dangerouslySetInnerHTML` is used only for the static
  bundled CSS/JS, the session cookie is `HttpOnly`+`Secure`+`SameSite=Strict`,
  and the admin client JS uses `confirm()`/`alert()` + same-origin fetch (no
  `innerHTML`, no `eval`).
- **SSRF (icon proxy, SSO discovery)**: the outbound-fetch guard
  (`src/services/ssrf.ts`) rejects non-global IPs across decimal/hex/octal/IPv6/
  IPv4-mapped encodings plus internal hostnames, and the Workers platform can't
  reach the private network. Solid; no action.
- **Dependencies**: `pnpm audit --prod` → "No known vulnerabilities found."

## Not deeply audited (scope honesty, 2026-07-06)

This pass concentrated on the highest-risk security surfaces: authentication,
crypto/PBKDF2, JWT issuance/verification, SSO/OIDC, 2FA (TOTP/WebAuthn/Duo/
YubiKey), the admin panel, IDOR/ownership on ciphers/attachments/sends,
organization-member privilege enforcement, account operations (password/KDF/key
rotation/email change), and emergency access. Not read line-by-line (their shared
access-control helpers were, however): `src/api/ciphers.ts`,
`src/api/organizations.ts`, the `src/api/twofactor.ts` route layer,
`src/api/devices.ts`, `src/api/auth-requests.ts`, `src/api/notifications.ts` /
`src/durable/`, `src/api/events.ts`, `src/api/domains.ts`, `src/services/mail.ts`,
`src/api/sync.ts`.

---

# 2026-07-08 drift audit (deep)

Reference: vaultwarden pinned at `d6a3d539` (v1.36.0+10, 2026-06-05), sibling
checkout `../vaultwarden`. Upstream `dani-garcia/vaultwarden@main` confirmed
**9 commits ahead** of the pin at audit time (`gh api …/compare`, ahead 9,
behind 0). Every finding below was verified by direct reads of both codebases;
upstream-main claims were verified against the GitHub compare API and commit
diffs.

## Findings → plans

- **003** builds the upstream-drift tracker the maintainer requested: a
  committed `.vaultwarden-pin`, a weekly GitHub Actions job diffing the pin
  against upstream `main` (commit list, protocol-file filter, route-attribute
  diff), vaultwarden/bw_web_builds/Bitwarden-client release watching, and a
  rolling `drift`-labeled issue. Detection only — porting stays human-driven.

## Findings reported but NOT selected for a plan (drift backlog)

Vetted and real; recorded so they can be planned directly (e.g.
`improve plan <Dn>`) without re-auditing. Ordered by leverage.

**Tier 1 — current clients broken or silent data/security failure:**

- **D1 — Org-policy PUT parses the flat body only** (`src/api/org-members.ts:1245-1246`;
  both `/policies/:type` and `/policies/:type/vnext` share it, `:1326-1327`).
  2026.5+ web clients send `{policy:{enabled,data,type}}` (upstream `7320a1db4`),
  so `enabled` parses as `false` — **policies silently save disabled**, including
  require-2FA. Fix: unwrap `ci(body,"policy") ?? body`. Effort S.
- **D2 — `/accounts/kdf` ignores the nested `authenticationData`/`unlockData`**
  the current clients send (`src/api/accounts.ts:326-341` reads flat only; vw
  `accounts.rs:595-648` requires nested, flat fields are dead-code; client
  `kdf.request.ts` sends no flat KDF fields). Stored KDF defaults to
  PBKDF2/600k while the client re-wrapped keys with the chosen KDF → **account
  lockout on next login**. Port the dual-read pattern from `registerHandler`
  (`src/api/identity.ts:795-807`) + vw's kdf-equality/salt==email guards +
  `validateKdf`; also add the same fallback to `/accounts/set-password`
  (`accounts.ts:361-372`) and return the `{object:"set-password",…}` envelope
  (vw `accounts.rs:405-408`). Effort S.
- **D3 — `send_access` OAuth grant + bearer Send-access routes missing**
  (upstream `5c5e8e1a6`, "2026.6.0 send support"): no `send_access` case in the
  connect/token switch (`src/api/identity.ts:120-156`), only legacy path-param
  access routes exist (`src/api/sends.ts:211`, `:237`). 2026.6+ clients cannot
  open Sends. Also reject the unsupported `emails` field like upstream. Effort L.
- **D4 — `PUT /organizations/:orgId/users/:memberId/recover-account` missing**
  (upstream `ec7fa137b`; renamed from `reset-password` in web 2026.4.2, with new
  `resetMasterPassword`/`resetTwoFactor` bools — reject `resetTwoFactor:true`).
  Vaultur has only the old route (`src/api/org-members.ts:1366`) → admin account
  recovery 404s on current web. NOTE: coordinate with plan 001, which hardens the
  same handler. Effort S–M.
- **D5 — Trash auto-delete defaults ON (30d) and the admin setting is a no-op
  for the purge**: vw `trash_auto_delete_days` is unset-by-default (`config.rs:603`,
  `cipher.rs:508-516` — never purges unless opted in); vaultur defaults 30
  (`src/config.ts:104`) and the weekly cron reads raw `env.TRASH_AUTO_DELETE_DAYS`
  (`src/jobs/scheduled.ts:26`), bypassing admin-panel overrides
  (`src/config-schema.ts:136-146`). Silent permanent data loss on fresh installs.
  Effort S.
- **D6 — `collections_v2` returns a bare cipher** instead of
  `{object:"optionalCipherDetails",unavailable:false,cipher}` (`src/api/ciphers.ts:622,627-628`
  vs vw `ciphers.rs:769-782`); web vault can corrupt its local cipher cache after
  "assign to collections". Secondary: `collections-admin` should return an empty
  200, not a cipher. Effort S.

**Tier 2 — real behavioral drift:**

- **D7 — Disabling the last 2FA method never enforces the org 2FA policy**:
  `disableTwofactor` (`src/api/twofactor.ts:255-282`) doesn't call the existing
  `enforce2faPolicy` helper (`src/services/twofactor.ts:214`, already called at
  login `:303,:401`); vw revokes memberships immediately on disable
  (`two_factor/mod.rs:158-160`) and from the admin panel (`admin.rs:511`). A live
  refresh token defers vaultur's login-time enforcement indefinitely. Effort S.
- **D8 — Archive/unarchive require write access** (`src/api/ciphers.ts:797`,
  `loadAccessibleCipher(...,true)`); vw needs only read (`ciphers.rs:1991`,
  archive is per-user state) → read-only org members get 400. Effort S.
- **D9 — Bulk archive/unarchive return an empty body** instead of the
  `{data,object:"list"}` envelope (`src/api/ciphers.ts:826-833`; contrast
  vaultur's own `bulkRestore` `:773-788`), and archiving bumps the cipher's
  `updatedAt` (`:808`) where vw leaves `revisionDate` untouched. Effort S.
- **D10 — Passwordless Sends emit `authType: 0`** (=email OTP) instead of `2`
  (=none) (`src/services/vault.ts:489` vs vw `send.rs:57-65`), and `hideEmail`
  serializes `null` where clients expect boolean (`vault.ts:491`; upstream fix
  `fddc16d2b` → `?? false`). Effort S.
- **D11 — v2 attachment upload size tolerance is ±1 byte** — the code comment
  misreads upstream's ±1 MiB `LEEWAY` (`src/api/attachments.ts:150-155` vs vw
  `ciphers.rs:1277-1295`, which also persists the actual size). Effort S.
- **D12 — Emergency access trio**: `GET /emergency-access/:id` returns the
  minimal shape instead of `emergencyAccessGranteeDetails` with grantee
  id/email/name (`src/api/emergency-access.ts:190-194` vs vw
  `emergency_access.rs:88-101`); invite lacks the duplicate-pair check (vw
  `:248-257` "Grantee user already invited"); update drops `keyEncrypted`
  (`updateEa` reads only type/waitTimeDays vs vw `:107-156`). Effort S.
- **D13 — `auto-enroll-status` hardcodes `resetPasswordEnabled: false`**
  (`src/api/org-members.ts:1330-1336`) although account recovery is implemented;
  vw computes it from the ResetPassword policy's autoEnroll data and handles the
  `FAKE_SSO_IDENTIFIER` (`organizations.rs:359+`) → recovery auto-enroll never
  happens. Effort S–M.
- **D14 — Email change requires the emailed token even when mail is disabled**
  → impossible on no-mail servers (vw skips the token check and clears
  `verified_at`, `accounts.rs:1005-1055`); also missing the
  `email_change_allowed` gate (`accounts.rs:945,1007`) and the new-email domain
  allowlist check (`:975`). Effort S.
- **D15 — `/api/config` `disableUserRegistration` is `!signupsAllowed`**
  (`src/api/meta.ts:23`); vw's `is_signup_disabled()` (`config.rs:1521-1526`)
  also covers whitelist / mail-off+invitations / SSO-only → wrong signup-link
  visibility in three configurations. Effort S.
- **D16 — Enum/const sync**: `OrgPolicyType` missing `RestrictedItemTypes=15`,
  `UriMatchDefaults=16` (`src/shared/constants.ts:97-113` vs `org_policy.rs:46-48`);
  `DeviceType` missing `DuckDuckGoBrowser=26` (`device.rs:330`); `EventType`
  missing 1010/1513/1514/1515/1516 (`event.rs:60,107-110`); dead `COMPAT` const
  with contradictory version string (`constants.ts:236-241` — unused; actual
  served version is `src/api/meta.ts:5`). Effort S.

**Tier 3 — niche/hardening parity (all verified):**

- `require_device_email` unsupported — new-device mail is fire-and-forget
  (`src/api/identity.ts:304-316` `waitUntil`) vs vw's reject-login-on-send-failure
  (`identity.rs:483,631`).
- No verify-email resend/throttle on login of unverified users
  (`src/api/identity.ts:272-274` vs vw `identity.rs:429-459`,
  `signups_verify_resend_time/_limit`).
- No randomized delay on the `register/send-verification-email` existing-account
  path (`identity.ts:751-757` vs vw `identity.rs:1070`) — timing-based account
  enumeration; LOW.
- JWT `email_verified` claim misses the mail-disabled short-circuit
  (`src/auth/tokens.ts:44` vs `auth.rs:250`; profile path is already correct in
  `src/services/vault.ts`).
- Cipher write gate drops vw's `manage` override (`src/services/vault.ts:216-219`
  vs `cipher.rs:719-724`, `!read_only || manage`) — edge multi-collection config.
- Org-invitation lifecycle on mail-disabled servers (upstream `a16b5afaa`):
  invitation row for existing password-less users + cleanup on member delete;
  MED confidence, verify the delete path first.
- Registration 422 cross-checks for the nested format (upstream `a058a35cc`):
  kdf-equality + salt==email guards; the format itself is already handled.
- SSO token exchange always uses `client_secret_post`
  (`src/services/sso.ts:267-273`); upstream `5447ee6af` honors
  `token_endpoint_auth_methods_supported` and falls back to Basic.
- Absent-but-default-matching config knobs: `HIBP_API_KEY` (breach report
  permanently stubbed, `src/api/misc.ts:16-34` vs `config.rs:591` +
  `mod.rs:148-180`), `org_attachment_limit` (`config.rs:596`),
  `increase_note_size_limit` (`src/services/ciphers.ts:92` hardcodes 10k),
  `experimental_client_feature_flags` (`src/api/meta.ts:37-39` hardcodes one
  flag), `sso_master_password_policy`.
- `/accounts/set-password` returns empty 200 vs vw's
  `{object:"set-password",captchaBypassToken:""}` — LOW; folded into D2's scope.

## Findings considered and rejected (drift audit)

- **Upstream `b25f71536` (DNS `enforce_block` refactor)**: reqwest/Hickory
  SSRF plumbing — does not port to workerd's `fetch()`; vaultur's SSRF guard
  (`src/services/ssrf.ts`) is the platform-appropriate equivalent.
- **Upstream `4720cdbe8` (new feature-flag string)**: only meaningful if the
  `experimental_client_feature_flags` mechanism (tier-3 backlog) is adopted.
- **Opaque device refresh tokens** (vs vw's signed refresh JWTs): vaultur issues
  and accepts them consistently and vw retains a legacy-opaque fallback — not
  client-breaking; noted that vaultur's refresh tokens carry no 30/90-day expiry.
- **Duo legacy iframe & U2F absent**: documented deliberate deviations (README
  "Implementation notes"); not drift.
- **`get /api/webauthn` empty list, HIBP fallback shape, `/sync` envelope,
  Cipher/Send/folder `to_json`, token-response field set, 2FA challenge
  payloads, prelogin defaults, DB schema (all 28 tables), global-domains
  dataset, `featureStates` default output, KDF validation bounds, config
  defaults other than trash**: checked in both trees — in parity; don't
  re-audit.
- Prior run's rejections (2026-07-06 section above) all stand.

## Not deeply audited (scope honesty, 2026-07-08)

Two audit slices were cut short by a session limit and only their
highest-signal targets were hand-verified afterwards (org-policy PUT,
auto-enroll-status, 2FA-disable enforcement, archive/EA routes, provider
selection payloads): a full field-level sweep of **organization/member/group/
collection JSON shapes** (`src/api/organizations.ts` ↔ vw `organizations.rs`),
**events & public directory-connector APIs**, **device/push relay payloads**,
and the **notifications-hub WebSocket frames** was not completed. A focused
follow-up pass on those surfaces is the natural next audit.

---

# 2026-07-08 public-deployment security audit (focused)

Maintainer's question: the server is live on `nommyt.workers.dev` — what
else hardens a _personal_ deployment while keeping Bitwarden clients working,
restricted to specific users/emails? This pass audited the exposure/identity
boundary (who can reach what, who can authenticate) and deliberately did not
re-audit anything the two runs above already covered or rejected. Read
end-to-end for this pass: `src/auth/middleware.ts` (incl. the
`PUBLIC_API_ROUTES` allowlist), all four grant handlers + registration in
`src/api/identity.ts`, `src/services/ratelimit.ts` and every call site,
`src/api/admin.ts` auth, `src/config.ts` / `src/config-schema.ts` /
`src/services/server-config.ts`, the public endpoints in
`src/api/{accounts,twofactor,auth-requests,sends,meta}.ts`, and both wrangler
configs + `docs/deployment.md`.

## Findings → plans

Selection note: run was non-interactive (the confirm step could not be
answered), so per the improve skill's default the top findings by leverage
were planned: S1 → **004**, S3+S4 (+S2's WAF half) → **005**, S2's app-level
half → **006**.

- **S1 — No login-time identity restriction** (→ plan 004). All grant types
  gate only on credentials + `user.enabled` (`src/api/identity.ts:193` ff.,
  `:339` ff., `:565` ff., `:161` ff.); `SIGNUPS_DOMAINS_WHITELIST` gates
  registration only. Any existing account (invite flows, SSO
  auto-provisioning at `identity.ts:404-424`) authenticates. HIGH/M/HIGH-conf.
- **S3 — Deployment rides on `workers_dev: true` with no custom domain**
  (→ plan 005; `wrangler.deploy.jsonc:17,19`). Blocks every zone-level
  control (Access, WAF, rate rules) and leaves the guessable shared hostname
  serving the vault. MED/S/HIGH-conf.
- **S4 — Nothing network-level restricts browser-only surfaces** (→ plan
  005). `/admin` is internet-reachable (app-auth only); Cloudflare Access
  can gate it (and optionally the web-vault shell) with zero client impact,
  but must never cover `/api|/identity|/notifications|/icons|/events`
  (native clients can't traverse Access). HIGH-for-goal/M/HIGH-conf.
- **S2 — Login rate limiting is per-IP only and KV-non-atomic**
  (`src/services/ratelimit.ts:15-21`; IP from `CF-Connecting-IP`,
  `src/app.ts:106`). IP rotation bypasses it entirely; each guess burns a
  HeavyCompute 600k-iteration PBKDF2. WAF half → plan 005 §11.3; per-account
  failure dimension → plan 006. The 2026-07-06 rejection of hardening the KV
  limiter _internals_ stands. MED/S–M/HIGH-conf.

## Findings considered and rejected (public-deployment audit)

- **S5 — login timing oracle for account existence** (`src/api/identity.ts:200-261`:
  unknown users skip the PBKDF2 round-trip, existing users pay it).
  Superseded by plan 004: with an allowlist, password login rejects
  non-allowlisted emails before any user lookup with the same generic error,
  so the oracle only distinguishes among the operator's own allowlisted
  emails. A constant-work dummy verify would also hand attackers a free
  PBKDF2-cost amplifier on unknown-email spray. Not worth doing after 004.
- **prelogin KDF oracle** (`/identity/accounts/prelogin` + `/api/accounts/prelogin`
  return real KDF params for existing users): Bitwarden protocol requirement,
  matches vaultwarden; by-design.
- **Unauthenticated email-trigger endpoints** (`password-hint`,
  `delete-recover`, `register/send-verification-email`): with
  `SIGNUPS_ALLOWED=false` they only send for already-existing accounts, and
  all include anti-enumeration same-response paths. Residual risk is quota
  burn against known emails; mitigation is config (`PASSWORD_HINTS_ALLOW=false`,
  plan 005 §11.4), not code.
- **Icon proxy as unauthenticated fetch/cache-fill** (`src/api/icons.ts:37`):
  gating `/icons` behind auth breaks the web vault; SSRF guard already vetted
  2026-07-06; KV cache-fill abuse is bounded by the icon TTL. Note only.
- **`/api/config`, `/alive`, `/api/version` fingerprinting** (`src/api/meta.ts`):
  protocol-required public metadata; can't remove without breaking clients.
- **Admin panel app-layer auth**: re-checked, not a finding — constant-time
  token compare, JWT session cookie (`Strict`/`HttpOnly`/`Secure`, 20-min
  TTL), rate-limited login and failed-auth paths, whole surface 404s without
  `ADMIN_TOKEN`, weak-token warning (`src/api/admin.ts:56-161`). Remaining
  exposure is _reachability_, addressed by plan 005's Access step.
- **`POST /api/auth-requests` unauthenticated creation** (login-with-device,
  `src/api/auth-requests.ts:82`): can only notify an existing user's own
  devices; completing the flow runs through `passwordLogin` (gated by 004
  once it lands) and requires same-IP + access-code match. Volumetrics fall
  under the plan-005 WAF note. Not worth its own plan.

## Not deeply audited (scope honesty, 2026-07-08 focused pass)

This pass did not re-read the protocol/ownership surfaces covered on
2026-07-06, and did not read line-by-line: `src/durable/notifications-hub.ts`
internals (hub _auth_ uses the standard login JWT via `requireAuth`-equivalent
token checks — only its route layer was reviewed), `src/services/storage.ts`,
`src/services/mail.ts` content, `src/jobs/scheduled.ts`, or the icon fetch
pipeline beyond its auth posture and the existing SSRF guard. The
2026-07-08 drift audit's "not audited" list also still stands.
