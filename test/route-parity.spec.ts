import { SELF } from "cloudflare:test"
import { describe, expect, it } from "vitest"

/**
 * Exhaustive route-parity check against vaultwarden's full surface.
 *
 * The fixture below is vaultwarden's complete route table (extracted from its
 * `#[get/post/put/delete("…")]` attributes, sibling checkout at `../vaultwarden`),
 * grouped by mount prefix. For every route we fire an (unauthenticated) request
 * with placeholder params and assert the router actually has it — a registered
 * route answers 401/400/200/redirect, only a *missing* one answers 404. Method
 * mismatches also surface as 404 in Hono, so this checks method parity too.
 *
 * Regenerate the fixture from vaultwarden with:
 *   grep -rEoh '#\[(get|post|put|delete)\("[^"]+"' src/api --include='*.rs'
 *
 * Keep EXCLUSIONS in sync with the Non-goals section in README.md.
 */

// method + path, one per line, `<param>`/`?<query>` as in vaultwarden.
const API = `
get /accounts/profile
put /accounts/profile
post /accounts/profile
put /accounts/avatar
get /users/<id>/public-key
post /accounts/set-password
post /accounts/keys
post /accounts/password
post /accounts/kdf
post /accounts/key-management/rotate-user-account-keys
post /accounts/security-stamp
post /accounts/email-token
post /accounts/email
post /accounts/verify-email
post /accounts/verify-email-token
post /accounts/delete-recover
post /accounts/delete-recover-token
post /accounts/delete
delete /accounts
get /accounts/revision-date
post /accounts/password-hint
post /accounts/prelogin
post /accounts/verify-password
post /accounts/api-key
post /accounts/rotate-api-key
get /devices/knowndevice
get /devices
get /devices/identifier/<id>
post /devices/identifier/<id>/token
put /devices/identifier/<id>/token
put /devices/identifier/<id>/clear-token
post /devices/identifier/<id>/clear-token
get /tasks
post /auth-requests
get /auth-requests/<id>
put /auth-requests/<id>
get /auth-requests/<id>/response
get /auth-requests
get /auth-requests/pending
get /sync
get /ciphers
get /ciphers/<id>
get /ciphers/<id>/admin
get /ciphers/<id>/details
post /ciphers/admin
post /ciphers/create
post /ciphers
post /ciphers/import
put /ciphers/<id>/admin
post /ciphers/<id>/admin
post /ciphers/<id>
put /ciphers/<id>
post /ciphers/<id>/partial
put /ciphers/<id>/partial
put /ciphers/<id>/collections_v2
post /ciphers/<id>/collections_v2
put /ciphers/<id>/collections
post /ciphers/<id>/collections
put /ciphers/<id>/collections-admin
post /ciphers/<id>/collections-admin
post /ciphers/<id>/share
put /ciphers/<id>/share
put /ciphers/share
get /ciphers/<id>/attachment/<aid>
post /ciphers/<id>/attachment/v2
post /ciphers/<id>/attachment/<aid>
post /ciphers/<id>/attachment
post /ciphers/<id>/attachment-admin
post /ciphers/<id>/attachment/<aid>/share
post /ciphers/<id>/attachment/<aid>/delete-admin
post /ciphers/<id>/attachment/<aid>/delete
delete /ciphers/<id>/attachment/<aid>
delete /ciphers/<id>/attachment/<aid>/admin
post /ciphers/<id>/delete
post /ciphers/<id>/delete-admin
put /ciphers/<id>/delete
put /ciphers/<id>/delete-admin
delete /ciphers/<id>
delete /ciphers/<id>/admin
delete /ciphers
post /ciphers/delete
put /ciphers/delete
delete /ciphers/admin
post /ciphers/delete-admin
put /ciphers/delete-admin
put /ciphers/<id>/restore
put /ciphers/<id>/restore-admin
put /ciphers/restore-admin
put /ciphers/restore
post /ciphers/move
put /ciphers/move
post /ciphers/purge
put /ciphers/<id>/archive
put /ciphers/archive
put /ciphers/<id>/unarchive
put /ciphers/unarchive
get /ciphers/organization-details
post /organizations
delete /organizations/<id>
post /organizations/<id>/delete
post /organizations/<id>/leave
get /organizations/<id>
put /organizations/<id>
post /organizations/<id>
get /collections
get /organizations/<id>/auto-enroll-status
get /organizations/<id>/collections
get /organizations/<id>/collections/details
post /organizations/<id>/collections
post /organizations/<id>/collections/bulk-access
put /organizations/<id>/collections/<cid>
post /organizations/<id>/collections/<cid>
delete /organizations/<id>/collections/<cid>
post /organizations/<id>/collections/<cid>/delete
delete /organizations/<id>/collections
post /organizations/<id>/collections/bulk-delete
get /organizations/<id>/collections/<cid>/details
get /organizations/<id>/collections/<cid>/users
put /organizations/<id>/collections/<cid>/users
post /organizations/domain/sso/verified
get /organizations/<id>/users
post /organizations/<id>/keys
post /organizations/<id>/users/invite
post /organizations/<id>/users/reinvite
post /organizations/<id>/users/<mid>/reinvite
post /organizations/<id>/users/<mid>/accept
post /organizations/<id>/users/confirm
post /organizations/<id>/users/<mid>/confirm
get /organizations/<id>/users/mini-details
get /organizations/<id>/users/<mid>
put /organizations/<id>/users/<mid>
post /organizations/<id>/users/<mid>
delete /organizations/<id>/users
delete /organizations/<id>/users/<mid>
post /organizations/<id>/users/<mid>/delete
post /organizations/<id>/users/public-keys
post /ciphers/import-organization
post /ciphers/bulk-collections
get /organizations/<id>/policies
get /organizations/<id>/policies/token
get /organizations/<id>/policies/master-password
get /organizations/<id>/policies/<pt>
put /organizations/<id>/policies/<pt>
put /organizations/<id>/policies/<pt>/vnext
get /plans
get /organizations/<id>/billing/metadata
get /organizations/<id>/billing/vnext/warnings
get /organizations/<id>/billing/vnext/self-host/metadata
put /organizations/<id>/users/<mid>/revoke
put /organizations/<id>/users/revoke
put /organizations/<id>/users/<mid>/restore/vnext
put /organizations/<id>/users/<mid>/restore
put /organizations/<id>/users/restore
get /organizations/<id>/groups
get /organizations/<id>/groups/details
post /organizations/<id>/groups/<gid>
post /organizations/<id>/groups
put /organizations/<id>/groups/<gid>
get /organizations/<id>/groups/<gid>/details
post /organizations/<id>/groups/<gid>/delete
delete /organizations/<id>/groups/<gid>
delete /organizations/<id>/groups
get /organizations/<id>/groups/<gid>
get /organizations/<id>/groups/<gid>/users
put /organizations/<id>/groups/<gid>/users
post /organizations/<id>/groups/<gid>/delete-user/<mid>
get /organizations/<id>/public-key
get /organizations/<id>/keys
put /organizations/<id>/users/<mid>/reset-password
get /organizations/<id>/users/<mid>/reset-password-details
put /organizations/<id>/users/<mid>/reset-password-enrollment
get /organizations/<id>/export
post /organizations/<id>/api-key
post /organizations/<id>/rotate-api-key
get /sends
get /sends/<id>
post /sends
post /sends/file
post /sends/file/v2
post /sends/<id>/file/<fid>
post /sends/access/<aid>
post /sends/<id>/access/file/<fid>
get /sends/<id>/<fid>
put /sends/<id>
delete /sends/<id>
put /sends/<id>/remove-password
get /folders
get /folders/<id>
post /folders
post /folders/<id>
put /folders/<id>
post /folders/<id>/delete
delete /folders/<id>
get /emergency-access/trusted
get /emergency-access/granted
get /emergency-access/<id>
put /emergency-access/<id>
post /emergency-access/<id>
delete /emergency-access/<id>
post /emergency-access/<id>/delete
post /emergency-access/invite
post /emergency-access/<id>/reinvite
post /emergency-access/<id>/accept
post /emergency-access/<id>/confirm
post /emergency-access/<id>/initiate
post /emergency-access/<id>/approve
post /emergency-access/<id>/reject
post /emergency-access/<id>/view
post /emergency-access/<id>/takeover
post /emergency-access/<id>/password
get /emergency-access/<id>/policies
get /two-factor
post /two-factor/get-recover
post /two-factor/recover
post /two-factor/disable
put /two-factor/disable
get /two-factor/get-device-verification-settings
post /two-factor/get-authenticator
post /two-factor/authenticator
put /two-factor/authenticator
delete /two-factor/authenticator
post /two-factor/send-email-login
post /two-factor/get-email
post /two-factor/send-email
put /two-factor/email
post /two-factor/get-webauthn
post /two-factor/get-webauthn-challenge
post /two-factor/webauthn
put /two-factor/webauthn
delete /two-factor/webauthn
post /two-factor/get-yubikey
post /two-factor/yubikey
put /two-factor/yubikey
post /two-factor/get-duo
post /two-factor/duo
put /two-factor/duo
post /public/organization/import
get /organizations/<id>/users/<mid>/events
get /ciphers/<id>/events
get /organizations/<id>/events
post /collect
`

const IDENTITY = `
post /connect/token
post /accounts/prelogin
post /accounts/prelogin/password
post /accounts/register
post /accounts/register/send-verification-email
post /accounts/register/finish
get /sso/prevalidate
get /account/prevalidate
get /connect/oidc-signin
get /connect/authorize
`

const ADMIN = `
post /invite
post /test/smtp
get /logout
get /users
get /users/overview
get /users/by-mail/<mail>
get /users/<id>
post /users/<id>/delete
delete /users/<id>/sso
post /users/<id>/deauth
post /users/<id>/disable
post /users/<id>/enable
post /users/<id>/remove-2fa
post /users/<id>/invite/resend
post /users/org_type
post /users/update_revision
get /organizations/overview
post /organizations/<id>/delete
get /diagnostics
get /diagnostics/config
get /diagnostics/http
post /config
post /config/delete
`

const EVENTS = `
post /collect
`

// vaultwarden routes intentionally not ported. Keep in sync with README.md Non-goals.
const EXCLUSIONS = new Set([
	"POST /admin/config/backup_db" // SQLite file copy — meaningless on D1 (use wrangler d1 export)
])

// Public routes whose handler returns the generic 404 ("Not found") when the
// referenced resource is absent — indistinguishable from a routing miss by
// status+body alone. Their existence is proven by dedicated round-trip tests
// (test/sends.spec.ts), so we assert they're in the fixture but accept a 404.
const PUBLIC_404_OK = new Set([
	"GET /api/sends/parity/parity" // token-authenticated Send file download
])

function parse(block: string, prefix: string): [string, string][] {
	return block
		.trim()
		.split("\n")
		.map((line) => line.trim())
		.filter(Boolean)
		.map((line) => {
			const [method, rawPath] = line.split(/\s+/, 2) as [string, string]
			const path = rawPath
				.replace(/\?.*$/, "") // strip query fragment
				.replace(/<[^>]+>/g, "parity") // params → placeholder
			return [method.toUpperCase(), `${prefix}${path}`] as [string, string]
		})
}

const ROUTES: [string, string][] = [
	...parse(API, "/api"),
	...parse(IDENTITY, "/identity"),
	...parse(ADMIN, "/admin"),
	...parse(EVENTS, "/events")
].filter(([m, p]) => !EXCLUSIONS.has(`${m} ${p}`))

describe("route parity with vaultwarden", () => {
	it("registers every vaultwarden route (method + path)", async () => {
		// De-dupe (some vaultwarden routes collapse to one path after normalization).
		const seen = new Set<string>()
		const unique = ROUTES.filter(([m, p]) => {
			const k = `${m} ${p}`
			if (seen.has(k)) return false
			seen.add(k)
			return true
		})

		const missing: string[] = []
		await Promise.all(
			unique.map(async ([method, path]) => {
				const key = `${method} ${path}`
				const res = await SELF.fetch(`https://vault.test${path}`, {
					method,
					headers: { "Content-Type": "application/json" },
					body: method === "GET" || method === "DELETE" ? undefined : "{}"
				})
				if (res.status !== 404) return // 401/400/200/redirect ⇒ route exists
				if (PUBLIC_404_OK.has(key)) return // public route, generic-404 by design

				// A routing miss uses the app-level notFound envelope ("Not found");
				// a handler that found the route but not the resource uses a specific
				// message (e.g. "AuthRequest doesn't exist", the Send-inaccessible text).
				const body = (await res.json().catch(() => ({}))) as { message?: string }
				if (!body.message || body.message === "Not found") missing.push(key)
			})
		)

		expect(missing, `Missing/unmatched routes:\n${missing.join("\n")}`).toEqual([])
	})

	it("covers the whole surface (sanity: fixture size)", () => {
		// Guards against an accidentally-truncated fixture.
		expect(ROUTES.length).toBeGreaterThan(240)
	})
})
