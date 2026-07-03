import { describe, expect, it } from "vitest"

import { pbkdf2, hashPassword, verifyPassword } from "../src/crypto"

/**
 * PBKDF2-HMAC-SHA256 test vector (RFC 8018 / Node.js crypto test suite):
 *   password = "password", salt = "salt", c = 4096, dkLen = 32
 */
const TEST_VECTOR = {
	password: "password",
	salt: "salt",
	iterations: 4096,
	dkLen: 32,
	expectedHex: "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"
}

describe("pbkdf2", () => {
	it("produces the correct output for a known test vector", async () => {
		const digest = await pbkdf2(
			new TextEncoder().encode(TEST_VECTOR.password),
			new TextEncoder().encode(TEST_VECTOR.salt),
			TEST_VECTOR.iterations,
			TEST_VECTOR.dkLen
		)
		const hex = Array.from(digest)
			.map((b) => b.toString(16).padStart(2, "0"))
			.join("")
		expect(hex).toBe(TEST_VECTOR.expectedHex)
	})

	it("round-trips via hashPassword + verifyPassword", async () => {
		const clientHash = "some-client-hash"
		const record = await hashPassword(clientHash, 100_000)
		expect(record.iterations).toBe(100_000)
		expect(record.hash).toBeTruthy()
		expect(record.salt).toBeTruthy()

		const valid = await verifyPassword(clientHash, record)
		expect(valid).toBe(true)

		const wrong = await verifyPassword("wrong-hash", record)
		expect(wrong).toBe(false)
	})

	it("handles 600k iterations (vaultwarden default)", async () => {
		const clientHash = "test-hash-for-600k"
		const record = await hashPassword(clientHash, 600_000)
		expect(record.iterations).toBe(600_000)
		const valid = await verifyPassword(clientHash, record)
		expect(valid).toBe(true)
	})
})
