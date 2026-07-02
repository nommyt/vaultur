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

Current coverage — **60 tests across 12 suites**:

| Suite              | What it covers                                                                                                                            |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `identity`         | register, prelogin, password/refresh/api-key grants, `invalid_grant` shapes                                                               |
| `vault`            | cipher CRUD, folders, sync payload, import, purge, stale-revision guard, account password change → token invalidation, equivalent domains |
| `twofactor`        | authenticator TOTP enroll → login challenge → complete → disable, recovery-code reset                                                     |
| `organizations`    | org create (profile shape), collections CRUD, cipher sharing, org keys, owner/leave guards                                                |
| `org-members`      | invite → confirm → edit → revoke → restore, groups, 2FA-policy revocation, cross-org isolation                                            |
| `emergency-access` | invite → confirm → initiate → approve → takeover → grantor password reset                                                                 |
| `sends`            | text send + public access + access-count/password/max-access limits, file send v2 upload/download                                         |
| `attachments`      | R2 v2 upload/download via signed URL, size-mismatch rejection, delete                                                                     |
| `devices`          | knowndevice probe, list, push-token set/clear, deauthorize → token invalidation                                                           |
| `admin`            | token auth, user disable/enable/remove-2fa, invite, diagnostics                                                                           |
| `api-surface`      | plans, prelogin aliases, device-verification-settings, org API-key login → LDAP directory import, bulk collections                        |
| `ssrf`             | icon-proxy host validation (SSRF) + 2FA email obscuring                                                                                   |

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
| `sso_*.spec.ts` (SSO login)                                 | **Out of scope** — see below.                                                                                                    |

## Deliberately out of scope

These vaultwarden features are intentionally not implemented (and so not
tested). The web vault surfaces some of their UI, but the endpoints return a
clear "not available" rather than silently misbehaving:

- **SSO / OpenID Connect** (`/identity/connect/authorize`, `oidc-signin`, prevalidate)
- **Hardware / advanced 2FA**: WebAuthn/FIDO2, Duo, YubiKey OTP. Supported 2FA:
  authenticator TOTP, email codes, recovery codes.
- **vaultwarden admin HTML panel** and its config editor / DB backup. Vaultur
  exposes an equivalent **JSON admin API** (`/admin/*`) instead.

## Can Vaultur pass vaultwarden's tests?

- **Unit tests**: the security-relevant ones (SSRF, email obscuring) are ported
  and pass. The rest are implementation-specific (opendal, admin panel) and
  don't apply to a Workers/R2 build.
- **Playwright e2e**: the non-SSO specs exercise flows Vaultur fully implements;
  pointing that suite at a deployed Vaultur + the bundled web vault is the
  intended way to run them. Standing up the browser harness is a deployment-time
  activity rather than part of `pnpm test`. The SSO specs are out of scope.
