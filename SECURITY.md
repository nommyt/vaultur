# Security Policy

Vaultur stores and serves encrypted vault data, so security reports get priority
attention.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report privately via GitHub's
[private vulnerability reporting](https://github.com/nommyt/vaultur/security/advisories/new)
(Security tab → "Report a vulnerability"). This opens a draft security advisory
visible only to the maintainer until it's resolved.

Include:

- The affected endpoint(s)/component(s) and a reproduction (request/response
  shapes are fine; please don't include real vault data, tokens, or master
  passwords)
- Impact — what an attacker could do with it
- Whether it's Vaultur-specific or inherited from vaultwarden's behavior (if
  the latter, consider also reporting upstream)

## Scope

In scope: the Worker code in `src/`, auth/session/crypto handling, the admin
panel, and anything that diverges from vaultwarden's security model.

Out of scope: your own Cloudflare account configuration (API tokens, WAF
rules, DNS), and vulnerabilities that require an already-compromised master
password or device.

## Supported versions

Vaultur is pre-1.0 and tracks `main` as the only supported line — fixes land
there and you pick them up on your next deploy. There's no LTS branch.

## Response

This is a single-maintainer project run outside of full-time hours — expect
an initial response within a few days, not hours. Confirmed vulnerabilities
get a fix and a coordinated disclosure timeline; there's no bug bounty.
