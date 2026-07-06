import { SELF } from "cloudflare:test"
import { describe, expect, it } from "vitest"

import { registerAndLogin } from "./helpers"

describe("security headers", () => {
	it("sets safe hardening headers on API responses", async () => {
		const res = await SELF.fetch("https://vault.test/alive")
		expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff")
		expect(res.headers.get("X-Frame-Options")).toBe("SAMEORIGIN")
		expect(res.headers.get("Referrer-Policy")).toBe("no-referrer")
		expect(res.headers.get("Strict-Transport-Security")).toContain("max-age=")
	})

	it("does NOT set cross-origin isolation headers (would break clients)", async () => {
		const res = await SELF.fetch("https://vault.test/alive")
		expect(res.headers.get("Cross-Origin-Resource-Policy")).toBeNull()
		expect(res.headers.get("Cross-Origin-Opener-Policy")).toBeNull()
		expect(res.headers.get("Cross-Origin-Embedder-Policy")).toBeNull()
	})

	it("denies framing on the admin panel", async () => {
		const res = await SELF.fetch("https://vault.test/admin")
		expect(res.status).toBe(200)
		expect(res.headers.get("X-Frame-Options")).toBe("DENY")
		expect(res.headers.get("Content-Security-Policy")).toContain("frame-ancestors 'none'")
	})

	// Regression: the notifications hub proxies to a Durable Object that upgrades
	// to a WebSocket (`new Response(null, { status: 101, webSocket })`); such a
	// response has immutable headers, so any header middleware that unconditionally
	// calls `.headers.set(...)` on it throws `TypeError: Can't modify immutable
	// headers` — this previously crashed every live-sync connection in production.
	it("does not crash the WebSocket upgrade on /notifications/hub", async () => {
		const { access_token } = await registerAndLogin()
		const res = await SELF.fetch(
			`https://vault.test/notifications/hub?access_token=${access_token}`,
			{ headers: { Upgrade: "websocket", Connection: "Upgrade" } }
		)
		expect(res.status).toBe(101)
		expect(res.webSocket).not.toBeNull()
	})

	it("does not crash the WebSocket upgrade on /notifications/anonymous-hub", async () => {
		const res = await SELF.fetch(
			"https://vault.test/notifications/anonymous-hub?token=any-auth-request-id",
			{ headers: { Upgrade: "websocket", Connection: "Upgrade" } }
		)
		expect(res.status).toBe(101)
		expect(res.webSocket).not.toBeNull()
	})
})
