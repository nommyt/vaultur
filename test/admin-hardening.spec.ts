import { SELF } from "cloudflare:test"
import { describe, expect, it } from "vitest"

const ADMIN_TOKEN = "vaultur-test-admin-token" // matches vitest.config.ts

function adminLoginPost(token: string) {
	return SELF.fetch("https://vault.test/admin", {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({ token })
	})
}

describe("admin auth hardening", () => {
	it("rate-limits repeated admin login attempts from one IP", async () => {
		// Default burst is 10/min; the 11th attempt in the same window is throttled.
		let sawRateLimit = false
		for (let i = 0; i < 11; i++) {
			const res = await adminLoginPost("wrong-token")
			if (res.status === 429) sawRateLimit = true
		}
		expect(sawRateLimit).toBe(true)
	})

	it("does not warn about a weak token when the configured token is strong", async () => {
		// Test env ADMIN_TOKEN is 24 chars → not weak → banner must be absent.
		const res = await SELF.fetch("https://vault.test/admin", {
			headers: { Authorization: `Bearer ${ADMIN_TOKEN}` }
		})
		expect(res.status).toBe(200)
		const html = await res.text()
		expect(html).not.toContain("Weak admin token")
	})
})
