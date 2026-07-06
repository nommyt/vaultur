import { env } from "cloudflare:test"
import { describe, expect, it } from "vitest"

import type { Bindings } from "../src/env"
import type { Pbkdf2OffloadRequest, Pbkdf2OffloadResponse } from "../src/services/pbkdf2-offload"
import { b64Decode, b64Encode } from "../src/util"

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

		// PBKDF2-HMAC-SHA256("password", "salt", 4096, 32) — canonical vector.
		const digestHex = Array.from(b64Decode(data.digest))
			.map((b) => b.toString(16).padStart(2, "0"))
			.join("")
		expect(digestHex).toBe("c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a")
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
