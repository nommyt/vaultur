import { SELF } from "cloudflare:test"
import { describe, expect, it } from "vitest"

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
})
