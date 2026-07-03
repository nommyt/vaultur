import { env } from "cloudflare:test"
import { describe, expect, it } from "vitest"

import { pbkdf2 } from "../src/crypto"
import type { Bindings } from "../src/env"
import type { Pbkdf2OffloadRequest, Pbkdf2OffloadResponse } from "../src/services/pbkdf2-offload"
import { b64Encode } from "../src/util"

const TEST_PASSWORD = "password"
const TEST_SALT = "salt"
const TEST_ITERATIONS = 4096
const TEST_DKLEN = 32

describe("HeavyCompute Durable Object", () => {
	it("produces the correct digest via the DO endpoint", async () => {
		const bindings = env as unknown as Bindings
		const ns = bindings.VAULTUR_HEAVY
		if (!ns) throw new Error("VAULTUR_HEAVY binding not configured in test")

		const id = ns.idFromName("vaultur:heavy")
		const stub = ns.get(id)

		const body: Pbkdf2OffloadRequest = {
			password: b64Encode(new TextEncoder().encode(TEST_PASSWORD)),
			salt: b64Encode(new TextEncoder().encode(TEST_SALT)),
			iterations: TEST_ITERATIONS,
			dkLen: TEST_DKLEN
		}

		const res = await stub.fetch("https://heavy/pbkdf2", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify(body)
		})

		expect(res.status).toBe(200)
		const data = (await res.json()) as Pbkdf2OffloadResponse
		expect(data.digest).toBeTruthy()

		const inlineDigest = await pbkdf2(
			new TextEncoder().encode(TEST_PASSWORD),
			new TextEncoder().encode(TEST_SALT),
			TEST_ITERATIONS,
			TEST_DKLEN
		)
		const inlineB64 = b64Encode(inlineDigest)
		expect(data.digest).toBe(inlineB64)
	})

	it("rejects non-POST requests", async () => {
		const bindings = env as unknown as Bindings
		const ns = bindings.VAULTUR_HEAVY
		if (!ns) throw new Error("VAULTUR_HEAVY binding not configured in test")

		const id = ns.idFromName("vaultur:heavy")
		const stub = ns.get(id)

		const res = await stub.fetch("https://heavy/pbkdf2", { method: "GET" })
		expect(res.status).toBe(405)
	})

	it("rejects unknown paths", async () => {
		const bindings = env as unknown as Bindings
		const ns = bindings.VAULTUR_HEAVY
		if (!ns) throw new Error("VAULTUR_HEAVY binding not configured in test")

		const id = ns.idFromName("vaultur:heavy")
		const stub = ns.get(id)

		const res = await stub.fetch("https://heavy/unknown", { method: "POST" })
		expect(res.status).toBe(404)
	})
}, 30_000 /* DO tests may be slow in simulated miniflare */)
