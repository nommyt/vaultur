import { SELF } from "cloudflare:test"
import { afterEach, describe, expect, it } from "vitest"

import { api, login, registerUser, TEST_USER } from "./helpers"

const ADMIN = {
	Authorization: "Bearer vaultur-test-admin-token",
	"Content-Type": "application/json"
}

const admin = (method: string, path: string, body?: unknown) =>
	SELF.fetch(`https://vault.test/admin${path}`, {
		method,
		headers: ADMIN,
		body: body === undefined ? undefined : JSON.stringify(body)
	})

const OTHER_EMAIL = "other@vaultur.dev"

afterEach(async () => {
	await admin("POST", "/config/delete")
})

describe("login email allowlist", () => {
	it("blocks password login for a non-allowlisted account", async () => {
		expect((await registerUser({ email: OTHER_EMAIL })).status).toBe(200)
		expect((await admin("POST", "/config", { login_allowed_emails: TEST_USER.email })).status).toBe(
			200
		)

		const res = await login(OTHER_EMAIL)
		expect(res.status).toBe(400)
		const body = (await res.json()) as Record<string, any>
		expect(body.errorModel.message).toContain("Username or password is incorrect")
	})

	it("allows password login and registration for an allowlisted account", async () => {
		expect((await admin("POST", "/config", { login_allowed_emails: TEST_USER.email })).status).toBe(
			200
		)
		expect((await registerUser()).status).toBe(200)

		const res = await login()
		expect(res.status).toBe(200)
		expect(((await res.json()) as Record<string, any>).access_token).toBeTruthy()
	})

	it("revokes refresh-token use after an account is delisted", async () => {
		expect((await registerUser({ email: OTHER_EMAIL })).status).toBe(200)
		const first = await login(OTHER_EMAIL)
		expect(first.status).toBe(200)
		const { refresh_token: refreshToken } = (await first.json()) as { refresh_token: string }

		await admin("POST", "/config", { login_allowed_emails: TEST_USER.email })
		const form = new URLSearchParams({
			grant_type: "refresh_token",
			refresh_token: refreshToken,
			client_id: "web"
		})
		const res = await SELF.fetch("https://vault.test/identity/connect/token", {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: form.toString()
		})
		expect(res.status).toBe(400)
		expect(((await res.json()) as Record<string, any>).error).toBe("invalid_grant")
	})

	it("blocks registration for a non-allowlisted account", async () => {
		await admin("POST", "/config", { login_allowed_emails: TEST_USER.email })

		const res = await registerUser({ email: OTHER_EMAIL })
		expect(res.status).toBe(400)
		const body = (await res.json()) as Record<string, any>
		expect(body.errorModel.message).toContain("Registration not allowed")
	})

	it("allows every account when the allowlist is empty", async () => {
		await admin("POST", "/config/delete")
		expect((await registerUser({ email: OTHER_EMAIL })).status).toBe(200)
		expect((await login(OTHER_EMAIL)).status).toBe(200)
	})

	it("blocks personal API-key login for a delisted account", async () => {
		expect((await registerUser({ email: OTHER_EMAIL })).status).toBe(200)
		const loginRes = await login(OTHER_EMAIL)
		expect(loginRes.status).toBe(200)
		const { access_token: token } = (await loginRes.json()) as { access_token: string }
		const profile = (await (await api(token, "GET", "/api/accounts/profile")).json()) as Record<
			string,
			any
		>
		const keyRes = await api(token, "POST", "/api/accounts/api-key", {
			masterPasswordHash: TEST_USER.masterPasswordHash
		})
		expect(keyRes.status).toBe(200)
		const { apiKey } = (await keyRes.json()) as { apiKey: string }

		await admin("POST", "/config", { login_allowed_emails: TEST_USER.email })
		const form = new URLSearchParams({
			grant_type: "client_credentials",
			scope: "api",
			client_id: `user.${profile.id}`,
			client_secret: apiKey,
			deviceType: "9",
			deviceIdentifier: "allowlist-cli-device",
			deviceName: "cli"
		})
		const res = await SELF.fetch("https://vault.test/identity/connect/token", {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: form.toString()
		})
		expect(res.status).toBe(400)
		const body = (await res.json()) as Record<string, any>
		expect(body.errorModel.message).toContain("Login not allowed")
	})
})
