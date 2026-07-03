import { SELF } from "cloudflare:test"
import { describe, expect, it } from "vitest"

import { registerUser, login, api } from "./helpers"

// Test env sets ADMIN_TOKEN = 'vaultur-test-admin-token'
const ADMIN_TOKEN = "vaultur-test-admin-token"

function adminGet(path: string, method = "GET", body?: unknown) {
	return SELF.fetch(`https://vault.test/admin${path}`, {
		method,
		headers: { Authorization: `Bearer ${ADMIN_TOKEN}`, "Content-Type": "application/json" },
		body: body === undefined ? undefined : JSON.stringify(body)
	})
}

describe("admin API", () => {
	it("rejects an invalid admin token", async () => {
		const res = await SELF.fetch("https://vault.test/admin", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ token: "wrong" })
		})
		expect(res.status).toBe(401)
	})

	it("accepts a valid admin token and issues a session cookie", async () => {
		const res = await SELF.fetch("https://vault.test/admin", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ token: ADMIN_TOKEN })
		})
		expect(res.status).toBe(200)
		expect(res.headers.get("Set-Cookie")).toContain("VAULTUR_ADMIN=")
	})

	it("accepts the admin token and lists users", async () => {
		await registerUser()
		const res = await adminGet("/users")
		expect(res.status).toBe(200)
		const users = (await res.json()) as Record<string, any>[]
		expect(users.length).toBeGreaterThanOrEqual(1)
		expect(users[0]!.object).toBe("adminUser")
		expect(users[0]!.email).toBeTruthy()
	})

	it("disables and re-enables a user", async () => {
		await registerUser()
		const users = (await (await adminGet("/users")).json()) as Record<string, any>[]
		const id = users[0]!.id

		expect((await adminGet(`/users/${id}/disable`, "POST")).status).toBe(200)
		// Disabled user cannot log in
		const disabledLogin = await login()
		expect(disabledLogin.status).toBe(400)
		expect(((await disabledLogin.json()) as Record<string, any>).errorModel.message).toContain(
			"disabled"
		)

		expect((await adminGet(`/users/${id}/enable`, "POST")).status).toBe(200)
		expect((await login()).status).toBe(200)
	})

	it("removes 2FA for a user", async () => {
		await registerUser()
		const users = (await (await adminGet("/users")).json()) as Record<string, any>[]
		const id = users[0]!.id
		expect((await adminGet(`/users/${id}/remove-2fa`, "POST")).status).toBe(200)
	})

	it("invites a new email and reports diagnostics", async () => {
		const invite = await adminGet("/invite", "POST", { email: "invited@vaultur.dev" })
		expect(invite.status).toBe(200)
		expect(((await invite.json()) as Record<string, any>).email).toBe("invited@vaultur.dev")

		const diag = (await (await adminGet("/diagnostics/config")).json()) as Record<string, any>
		expect(diag.dbType).toBe("d1")
		expect(diag.running).toBe(true)
	})

	it("requires authentication for admin data routes", async () => {
		const res = await SELF.fetch("https://vault.test/admin/users")
		expect(res.status).toBe(401)
	})

	it("serves the login page unauthenticated at GET /admin", async () => {
		const res = await SELF.fetch("https://vault.test/admin")
		expect(res.status).toBe(200)
		expect(res.headers.get("Content-Type")).toContain("text/html")
		const html = await res.text()
		expect(html).toContain("Vaultur Admin")
		expect(html).toContain("Authentication key needed")
		expect(html).toContain('action="/admin"')
		// Not authenticated: nav should not expose Settings/Users links
		expect(html).not.toContain("/admin/users/overview")
	})

	it("renders the settings page with editable groups when authenticated", async () => {
		const res = await SELF.fetch("https://vault.test/admin", {
			headers: { Authorization: `Bearer ${ADMIN_TOKEN}` }
		})
		expect(res.status).toBe(200)
		const html = await res.text()
		expect(html).toContain('id="config-form"')
		expect(html).toContain("General Settings")
		expect(html).toContain("Email (Cloudflare Email Sending)")
		expect(html).toContain("Cloudflare Email Sending") // SMTP redesign
		expect(html).toContain("/admin/users/overview") // nav shown when logged in
		// Email provider is view-only (locked to Cloudflare Email Sending), not a
		// misleading disabled <select> that implies other options exist.
		expect(html).toContain('id="email_provider"')
		expect(html).toMatch(/<input(?=[^>]*id="email_provider")(?=[^>]*readonly)[^>]*>/)
		expect(html).not.toContain("Custom SMTP")
	})

	it("renders the users and organizations overview pages as HTML", async () => {
		await registerUser()
		const usersPage = await (await adminGet("/users/overview")).text()
		expect(usersPage).toContain("Registered Users")
		expect(usersPage).toContain('id="users-table"')

		const orgsPage = await (await adminGet("/organizations/overview")).text()
		expect(orgsPage).toContain('id="orgs-table"')
	})

	it("saves config overrides and applies them to the effective config", async () => {
		// Default SIGNUPS_ALLOWED is true in the test env; override it to false.
		const save = await adminGet("/config", "POST", { signups_allowed: false })
		expect(save.status).toBe(200)

		// The override should now be reflected in diagnostics-adjacent behaviour:
		// registration should be rejected once signups are disabled.
		const reg = await SELF.fetch("https://vault.test/identity/accounts/register", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				email: "blocked@vaultur.dev",
				masterPasswordHash: "x",
				key: "2.a|b|c",
				kdf: 0,
				kdfIterations: 100000
			})
		})
		expect(reg.status).toBeGreaterThanOrEqual(400)

		// Reset overrides restores env defaults.
		const reset = await adminGet("/config/delete", "POST")
		expect(reset.status).toBe(200)
	})
})
