import { describe, expect, it } from "vitest"

import { api, registerAndLogin, login, TEST_USER } from "./helpers"

/**
 * WebAuthn 2FA round-trip using a software authenticator: registration options
 * → attestation (fmt "none") → login challenge → assertion, all with real
 * P-256 keys so the server-side signature verification is exercised.
 */

// --- Minimal CBOR encoder (ints, negatives, byte/text strings, maps) ---

function cborEncode(value: unknown): Uint8Array {
	const out: number[] = []
	encodeValue(value, out)
	return Uint8Array.from(out)
}

function encodeHead(major: number, length: number, out: number[]) {
	if (length < 24) out.push((major << 5) | length)
	else if (length < 256) out.push((major << 5) | 24, length)
	else out.push((major << 5) | 25, length >> 8, length & 0xff)
}

function encodeValue(value: unknown, out: number[]) {
	if (typeof value === "number" && Number.isInteger(value)) {
		if (value >= 0) encodeHead(0, value, out)
		else encodeHead(1, -1 - value, out)
	} else if (value instanceof Uint8Array) {
		encodeHead(2, value.length, out)
		out.push(...value)
	} else if (typeof value === "string") {
		const bytes = new TextEncoder().encode(value)
		encodeHead(3, bytes.length, out)
		out.push(...bytes)
	} else if (value instanceof Map) {
		encodeHead(5, value.size, out)
		for (const [k, v] of value) {
			encodeValue(k, out)
			encodeValue(v, out)
		}
	} else if (value && typeof value === "object") {
		const entries = Object.entries(value)
		encodeHead(5, entries.length, out)
		for (const [k, v] of entries) {
			encodeValue(k, out)
			encodeValue(v, out)
		}
	} else {
		throw new Error(`Unsupported CBOR value: ${String(value)}`)
	}
}

// --- Software authenticator ---

const b64url = (data: Uint8Array | ArrayBuffer): string =>
	Buffer.from(data as Uint8Array).toString("base64url")
const fromB64url = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "base64url"))

async function sha256(data: Uint8Array | string): Promise<Uint8Array> {
	const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data
	return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as BufferSource))
}

/** WebCrypto raw (r||s) ECDSA signature → DER, as WebAuthn requires. */
function rawSigToDer(raw: Uint8Array): Uint8Array {
	const trim = (b: Uint8Array): Uint8Array => {
		let i = 0
		while (i < b.length - 1 && b[i] === 0) i++
		let v = b.slice(i)
		if (v[0]! & 0x80) v = Uint8Array.from([0, ...v])
		return v
	}
	const r = trim(raw.slice(0, 32))
	const s = trim(raw.slice(32))
	return Uint8Array.from([
		0x30,
		4 + r.length + s.length,
		0x02,
		r.length,
		...r,
		0x02,
		s.length,
		...s
	])
}

interface SoftKey {
	credId: Uint8Array
	keyPair: CryptoKeyPair
	counter: number
}

async function createSoftKey(): Promise<SoftKey> {
	const keyPair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
		"sign",
		"verify"
	])) as CryptoKeyPair
	const credId = crypto.getRandomValues(new Uint8Array(32))
	return { credId, keyPair, counter: 0 }
}

async function coseKey(key: SoftKey): Promise<Uint8Array> {
	const jwk = (await crypto.subtle.exportKey("jwk", key.keyPair.publicKey)) as {
		x?: string
		y?: string
	}
	return cborEncode(
		new Map<number, unknown>([
			[1, 2], // kty: EC2
			[3, -7], // alg: ES256
			[-1, 1], // crv: P-256
			[-2, fromB64url(jwk.x!)],
			[-3, fromB64url(jwk.y!)]
		])
	)
}

async function makeAttestation(key: SoftKey, rpId: string, challenge: string, origin: string) {
	const rpIdHash = await sha256(rpId)
	const flags = 0x41 // UP | AT
	const counter = Uint8Array.from([0, 0, 0, 0])
	const aaguid = new Uint8Array(16)
	const credIdLen = Uint8Array.from([key.credId.length >> 8, key.credId.length & 0xff])
	const cose = await coseKey(key)
	const authData = Uint8Array.from([
		...rpIdHash,
		flags,
		...counter,
		...aaguid,
		...credIdLen,
		...key.credId,
		...cose
	])
	const attestationObject = cborEncode({ fmt: "none", attStmt: {}, authData })
	const clientDataJSON = JSON.stringify({
		type: "webauthn.create",
		challenge,
		origin,
		crossOrigin: false
	})
	return {
		id: b64url(key.credId),
		rawId: b64url(key.credId),
		type: "public-key",
		// Bitwarden clients send `clientDataJson` (lowercase "son") — keep that casing
		response: {
			attestationObject: b64url(attestationObject),
			clientDataJson: b64url(new TextEncoder().encode(clientDataJSON))
		},
		extensions: {}
	}
}

async function makeAssertion(key: SoftKey, rpId: string, challenge: string, origin: string) {
	key.counter += 1
	const rpIdHash = await sha256(rpId)
	const counterBytes = Uint8Array.from([
		(key.counter >> 24) & 0xff,
		(key.counter >> 16) & 0xff,
		(key.counter >> 8) & 0xff,
		key.counter & 0xff
	])
	const authData = Uint8Array.from([...rpIdHash, 0x01 /* UP */, ...counterBytes])
	const clientDataJSON = JSON.stringify({
		type: "webauthn.get",
		challenge,
		origin,
		crossOrigin: false
	})
	const clientDataHash = await sha256(clientDataJSON)
	const toSign = Uint8Array.from([...authData, ...clientDataHash])
	const rawSig = await crypto.subtle.sign(
		{ name: "ECDSA", hash: "SHA-256" },
		key.keyPair.privateKey,
		toSign as BufferSource
	)
	return JSON.stringify({
		id: b64url(key.credId),
		rawId: b64url(key.credId),
		type: "public-key",
		response: {
			authenticatorData: b64url(authData),
			clientDataJson: b64url(new TextEncoder().encode(clientDataJSON)),
			signature: b64url(rawSigToDer(new Uint8Array(rawSig))),
			userHandle: null
		},
		extensions: {}
	})
}

const ORIGIN = "https://vault.test"
const RP_ID = "vault.test"

describe("two-factor (webauthn)", () => {
	it("registers a key, requires it on login, asserts, and deletes it", async () => {
		const session = await registerAndLogin()
		const token = session.access_token

		// 1. Registration challenge
		const challengeRes = await api(token, "POST", "/api/two-factor/get-webauthn-challenge", {
			masterPasswordHash: TEST_USER.masterPasswordHash
		})
		expect(challengeRes.status).toBe(200)
		const options = (await challengeRes.json()) as {
			challenge: string
			rp: { id: string }
			user: { name: string }
			status: string
			authenticatorSelection: { userVerification: string }
		}
		expect(options.status).toBe("ok")
		expect(options.rp.id).toBe(RP_ID)
		expect(options.user.name).toBe(TEST_USER.email)
		expect(options.authenticatorSelection.userVerification).toBe("discouraged")

		// 2. Attestation
		const key = await createSoftKey()
		const deviceResponse = await makeAttestation(key, RP_ID, options.challenge, ORIGIN)
		const activateRes = await api(token, "POST", "/api/two-factor/webauthn", {
			id: 1,
			name: "Test Key",
			masterPasswordHash: TEST_USER.masterPasswordHash,
			deviceResponse
		})
		expect(activateRes.status).toBe(200)
		const activated = (await activateRes.json()) as {
			enabled: boolean
			keys: { id: number; name: string }[]
		}
		expect(activated.enabled).toBe(true)
		expect(activated.keys).toEqual([{ id: 1, name: "Test Key", migrated: false }])

		// 3. Provider listed
		const listRes = await api(token, "GET", "/api/two-factor")
		const list = (await listRes.json()) as { data: { type: number }[] }
		expect(list.data.map((p) => p.type)).toContain(7)

		// 4. Login now requires 2FA and returns a WebAuthn challenge
		const relogin = await login()
		expect(relogin.status).toBe(400)
		const twoFactorRequired = (await relogin.json()) as {
			TwoFactorProviders2: Record<string, { challenge: string; allowCredentials: { id: string }[] }>
		}
		const provider = twoFactorRequired.TwoFactorProviders2["7"]
		expect(provider).toBeTruthy()
		expect(provider!.allowCredentials[0]!.id).toBe(b64url(key.credId))

		// 5. Assert and log in
		const assertion = await makeAssertion(key, RP_ID, provider!.challenge, ORIGIN)
		const okRes = await login(TEST_USER.email, TEST_USER.masterPasswordHash, {
			twoFactorProvider: "7",
			twoFactorToken: assertion
		})
		expect(okRes.status).toBe(200)

		// 6. A stale assertion is rejected (challenge is single-use)
		const staleRes = await login(TEST_USER.email, TEST_USER.masterPasswordHash, {
			twoFactorProvider: "7",
			twoFactorToken: assertion
		})
		expect(staleRes.status).toBe(400)

		// 7. Wrong-key assertion is rejected
		const relogin2 = await login()
		const challenge2 = ((await relogin2.json()) as typeof twoFactorRequired).TwoFactorProviders2[
			"7"
		]!.challenge
		const rogueKey = await createSoftKey()
		rogueKey.credId = key.credId // right id, wrong private key
		const forged = await makeAssertion(rogueKey, RP_ID, challenge2, ORIGIN)
		const forgedRes = await login(TEST_USER.email, TEST_USER.masterPasswordHash, {
			twoFactorProvider: "7",
			twoFactorToken: forged
		})
		expect(forgedRes.status).toBe(400)

		// 8. Delete the key (webauthn 2FA row stays, empty key list)
		const delRes = await api(token, "DELETE", "/api/two-factor/webauthn", {
			id: 1,
			masterPasswordHash: TEST_USER.masterPasswordHash
		})
		expect(delRes.status).toBe(200)
		expect(((await delRes.json()) as { keys: unknown[] }).keys).toEqual([])
	})

	it("rejects registration with a tampered challenge", async () => {
		const session = await registerAndLogin()
		const token = session.access_token

		const challengeRes = await api(token, "POST", "/api/two-factor/get-webauthn-challenge", {
			masterPasswordHash: TEST_USER.masterPasswordHash
		})
		expect(challengeRes.status).toBe(200)

		const key = await createSoftKey()
		// Attestation over a challenge the server never issued
		const forgedChallenge = b64url(crypto.getRandomValues(new Uint8Array(32)))
		const deviceResponse = await makeAttestation(key, RP_ID, forgedChallenge, ORIGIN)
		const res = await api(token, "POST", "/api/two-factor/webauthn", {
			id: 1,
			name: "Bad Key",
			masterPasswordHash: TEST_USER.masterPasswordHash,
			deviceResponse
		})
		expect(res.status).toBe(400)
	})
})
