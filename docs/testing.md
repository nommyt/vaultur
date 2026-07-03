# Testing & vaultwarden parity

## How Vaultur is tested

Integration tests run the **real Worker** inside `workerd` via
`@cloudflare/vitest-pool-workers`, with live D1, KV, R2 and Durable Object
bindings — so every test exercises the actual request path, database, and
storage, not mocks.

```bash
pnpm test                       # all suites
pnpm vitest run test/vault.spec.ts   # one suite
```

Current coverage — **67 tests across 12 suites**:

| Suite              | What it covers                                                                                                                                                                                                         |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `identity`         | register (both flat and wrapped `masterPasswordAuthentication`/`masterPasswordUnlock` payloads), iOS-vs-JSON verification-token content negotiation, prelogin, password/refresh/api-key grants, `invalid_grant` shapes |
| `vault`            | cipher CRUD, folders, sync payload, import, purge, stale-revision guard, account password change → token invalidation, equivalent domains                                                                              |
| `twofactor`        | authenticator TOTP enroll → login challenge → complete → disable, recovery-code reset                                                                                                                                  |
| `organizations`    | org create (profile shape), collections CRUD, cipher sharing, org keys, owner/leave guards                                                                                                                             |
| `org-members`      | invite → confirm → edit → revoke → restore, groups, 2FA-policy revocation, cross-org isolation                                                                                                                         |
| `emergency-access` | invite → confirm → initiate → approve → takeover → grantor password reset                                                                                                                                              |
| `sends`            | text send + public access + access-count/password/max-access limits, file send v2 upload/download                                                                                                                      |
| `attachments`      | R2 v2 upload/download via signed URL, size-mismatch rejection, delete                                                                                                                                                  |
| `devices`          | knowndevice probe, list, push-token set/clear, deauthorize → token invalidation                                                                                                                                        |
| `admin`            | bearer + session-cookie auth, HTML login/settings/users/organizations/diagnostics pages, user disable/enable/remove-2fa/invite, D1-persisted config overrides                                                          |
| `api-surface`      | plans, prelogin aliases, device-verification-settings, org API-key login → LDAP directory import, bulk collections                                                                                                     |
| `ssrf`             | icon-proxy host validation (SSRF) + 2FA email obscuring                                                                                                                                                                |

## Parity with vaultwarden's test suite

vaultwarden ships two kinds of tests. Here's how Vaultur maps to each.

### 1. Rust unit tests (34 functions, 6 files)

| vaultwarden test area                                                                                                                                      | Vaultur status                                                                           |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `http_client.rs` — SSRF host validation (~24 tests: loopback/private/metadata/CGNAT IPs across decimal/hex/octal/IPv6/IPv4-mapped encodings, IDN/punycode) | **Ported** to `src/services/ssrf.ts` + `test/ssrf.spec.ts`. Wired into the icon proxy.   |
| `two_factor/email.rs` — `obscure_email`                                                                                                                    | **Ported** — `obscureEmail` matches vaultwarden exactly; covered in `test/ssrf.spec.ts`. |
| `storage.rs` — S3/opendal path joining (4 tests)                                                                                                           | **N/A** — Vaultur uses the R2 binding directly, not opendal.                             |
| `admin.rs` — `validate_web_vault_compare` (web-vault version check)                                                                                        | **N/A** — vaultwarden-specific admin panel feature.                                      |
| `db/models/organization.rs`, `util.rs` — test helpers                                                                                                      | No standalone assertions to port.                                                        |

### 2. Playwright end-to-end suite (9 specs)

vaultwarden's e2e specs (`login`, `organization`, `collection`, plus SMTP and
SSO variants) drive the **web-vault UI in a browser** against a running server.
They validate the _client_, using the server as a backend.

Vaultur serves the **same official web vault** (bw_web_builds), so those flows
run against the same UI. What Vaultur must get right is the **server side** of
each flow — and that is exactly what the Vitest integration suite covers, at
the protocol level and more granularly than a browser click-through:

| Playwright spec                                             | Equivalent Vaultur coverage                                                                                                      |
| ----------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `login.spec.ts` (register, login, 2FA)                      | `identity.spec.ts`, `twofactor.spec.ts`                                                                                          |
| `organization.spec.ts` (create org, invite/confirm members) | `organizations.spec.ts`, `org-members.spec.ts`                                                                                   |
| `collection.spec.ts` (create/manage collections)            | `organizations.spec.ts` (collections), `api-surface.spec.ts` (bulk)                                                              |
| `*.smtp.spec.ts` (email delivery via a mail catcher)        | Mail paths run in no-mail mode in tests; the Email binding is exercised structurally. A live SMTP/MailHog e2e is **not** ported. |
| `sso_*.spec.ts` (SSO login)                                 | `sso.spec.ts` — full OIDC flow against a fetch-mocked IdP with a real RS256 JWKS.                                                |

## Route parity

`route-parity.spec.ts` embeds vaultwarden's entire route table (~245 routes,
extracted from its `#[get/post/put/delete]` attributes) and fires a request at
each one, asserting the router actually has it — a missing route or method
answers 404, a registered one answers 401/400/200/redirect. Regenerate the
fixture from the sibling checkout with:

```
grep -rEoh '#\[(get|post|put|delete)\("[^"]+"' ../vaultwarden/src/api --include='*.rs'
```

External-2FA/SSO specs mock at the fetch layer with `fetchMock` from
`cloudflare:test`, with real signatures (HMAC-SHA1 YubiCloud, HS512 Duo
id_tokens, RS256 IdP JWKS), so the verification code runs for real:
`webauthn.spec.ts`, `yubikey-duo.spec.ts`, `sso.spec.ts`.

## Deliberately out of scope

- **Admin-panel DB backup/restore.** The rest of vaultwarden's admin panel —
  login, settings editor (D1-persisted overrides), users, organizations,
  diagnostics — is ported to `/admin/*` (`admin.spec.ts`, `admin-extras.spec.ts`).
  D1 doesn't support the SQLite-file-copy backup vaultwarden's admin panel
  offers; use Cloudflare's D1
  [time travel](https://developers.cloudflare.com/d1/reference/time-travel/)
  or `wrangler d1 export` instead.
- **bitwarden/server-only Enterprise machinery** vaultwarden doesn't implement
  either (Secrets Manager, native SCIM, passkey login, Key Connector). See the
  Non-goals section in the README.

## Can Vaultur pass vaultwarden's tests?

- **Unit tests**: the security-relevant ones (SSRF, email obscuring) are ported
  and pass. The rest are implementation-specific (opendal, admin panel) and
  don't apply to a Workers/R2 build.
- **Playwright e2e**: the specs exercise flows Vaultur fully implements
  (including SSO); pointing that suite at a deployed Vaultur + the bundled web
  vault is the intended way to run them. Standing up the browser harness is a
  deployment-time activity rather than part of `pnpm test`.
