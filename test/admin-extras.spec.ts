import { SELF } from "cloudflare:test"
import { describe, expect, it } from "vitest"

import { api, registerAndLogin, TEST_USER } from "./helpers"

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

describe("admin extras", () => {
	it("update_revision bumps every user's revision date", async () => {
		const session = await registerAndLogin()
		const before = await api(session.access_token, "GET", "/api/accounts/revision-date")
		const beforeMs = Number(await before.text())

		await new Promise((r) => setTimeout(r, 1100))
		const res = await admin("POST", "/users/update_revision")
		expect(res.status).toBe(200)

		const after = await api(session.access_token, "GET", "/api/accounts/revision-date")
		expect(Number(await after.text())).toBeGreaterThan(beforeMs)
	})

	it("org_type changes a member's role but protects the last owner", async () => {
		const session = await registerAndLogin()
		// Create an org (registering user becomes Owner)
		const orgRes = await api(session.access_token, "POST", "/api/organizations", {
			name: "Acme",
			billingEmail: TEST_USER.email,
			key: "org-key",
			keys: { publicKey: "pub", encryptedPrivateKey: "priv" },
			collectionName: "Default"
		})
		expect(orgRes.status).toBe(200)
		const org = (await orgRes.json()) as { id: string }

		const users = await admin("GET", "/users")
		const [me] = (await users.json()) as { id: string }[]

		// Demoting the only owner is refused
		const demote = await admin("POST", "/users/org_type", {
			userType: 2,
			userUuid: me!.id,
			orgUuid: org.id
		})
		expect(demote.status).toBe(400)
		expect(((await demote.json()) as { message: string }).message).toContain("last owner")
	})

	it("invite/resend 400s once the user has accepted", async () => {
		await registerAndLogin()
		const users = await admin("GET", "/users")
		const [me] = (await users.json()) as { id: string }[]
		const res = await admin("POST", `/users/${me!.id}/invite/resend`)
		expect(res.status).toBe(400)
	})

	it("diagnostics/http echoes the requested status", async () => {
		const res = await admin("GET", "/diagnostics/http?code=503")
		expect(res.status).toBe(503)
	})
})

describe("well-known statics", () => {
	it("serves app-id.json with the FIDO content type", async () => {
		const res = await SELF.fetch("https://vault.test/app-id.json")
		expect(res.status).toBe(200)
		expect(res.headers.get("Content-Type")).toBe("application/fido.trusted-apps+json")
		const body = (await res.json()) as { trustedFacets: { ids: string[] }[] }
		expect(body.trustedFacets[0]!.ids).toContain("https://vault.test")
	})

	it("serves the apple-app-site-association", async () => {
		const res = await SELF.fetch("https://vault.test/.well-known/apple-app-site-association")
		expect(res.status).toBe(200)
		const body = (await res.json()) as { webcredentials: { apps: string[] } }
		expect(body.webcredentials.apps).toContain("LTZ2PFU5D6.com.8bit.bitwarden")
	})
})
