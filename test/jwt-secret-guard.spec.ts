import { describe, expect, it } from "vitest"

import { jwtSecretProblem } from "../src/auth/secret"

describe("jwtSecretProblem", () => {
	it("rejects an unset secret", () => {
		expect(jwtSecretProblem(undefined)).toBeTruthy()
		expect(jwtSecretProblem("")).toBeTruthy()
	})

	it("rejects a too-short secret", () => {
		expect(jwtSecretProblem("short-secret")).toBeTruthy()
	})

	it("rejects the shipped placeholder even though it is long enough", () => {
		// .env.example value — 35 chars, so length alone would not catch it.
		expect(jwtSecretProblem("change-me-to-64-random-bytes-base64")).toBeTruthy()
	})

	it("accepts the test env secret and a strong random secret", () => {
		expect(jwtSecretProblem("vaultur-test-jwt-secret-vaultur-test-jwt-secret")).toBeNull()
		expect(jwtSecretProblem("Zm9vYmFyYmF6".repeat(4))).toBeNull()
	})
})
