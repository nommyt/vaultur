import { env } from "cloudflare:test"
import { describe, expect, it } from "vitest"

import { hashPassword, pbkdf2, pbkdf2Als, verifyPassword } from "../src/crypto"
import { heavyRunner } from "../src/services/pbkdf2-offload"

/**
 * Server-side PBKDF2 runs exclusively in the HeavyCompute Durable Object. These
 * tests exercise the real path by installing the DO runner via AsyncLocalStorage
 * (exactly what the app middleware does per-request in src/app.ts).
 *
 * PBKDF2-HMAC-SHA256 test vector (RFC-style; also used by test/heavy-compute.spec.ts):
 *   password = "password", salt = "salt", c = 4096, dkLen = 32
 */
const TEST_VECTOR = {
	password: "password",
	salt: "salt",
	iterations: 4096,
	dkLen: 32,
	expectedHex: "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"
}

function withHeavy<T>(fn: () => Promise<T>): Promise<T> {
	const ns = env.VAULTUR_HEAVY
	if (!ns) throw new Error("VAULTUR_HEAVY binding not configured in test")
	return pbkdf2Als.run(heavyRunner(ns), fn)
}

describe("pbkdf2 (via HeavyCompute DO)", () => {
	it("produces the correct output for a known test vector", async () => {
		const digest = await withHeavy(() =>
			pbkdf2(
				new TextEncoder().encode(TEST_VECTOR.password),
				new TextEncoder().encode(TEST_VECTOR.salt),
				TEST_VECTOR.iterations,
				TEST_VECTOR.dkLen
			)
		)
		const hex = Array.from(digest)
			.map((b) => b.toString(16).padStart(2, "0"))
			.join("")
		expect(hex).toBe(TEST_VECTOR.expectedHex)
	})

	it("round-trips via hashPassword + verifyPassword", async () => {
		const clientHash = "some-client-hash"
		const record = await withHeavy(() => hashPassword(clientHash, 100_000))
		expect(record.iterations).toBe(100_000)
		expect(record.hash).toBeTruthy()
		expect(record.salt).toBeTruthy()

		const valid = await withHeavy(() => verifyPassword(clientHash, record))
		expect(valid).toBe(true)

		const wrong = await withHeavy(() => verifyPassword("wrong-hash", record))
		expect(wrong).toBe(false)
	})

	it("handles 600k iterations (vaultwarden default)", async () => {
		const clientHash = "test-hash-for-600k"
		const record = await withHeavy(() => hashPassword(clientHash, 600_000))
		expect(record.iterations).toBe(600_000)
		const valid = await withHeavy(() => verifyPassword(clientHash, record))
		expect(valid).toBe(true)
	})
})
