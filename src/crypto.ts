import { AsyncLocalStorage } from "node:async_hooks"
import { createHash, createHmac } from "node:crypto"

import { b64Decode, b64Encode, constantTimeEqual, randomBytes } from "./util"

/**
 * Server-side password verification, matching vaultwarden's model:
 * clients derive a master-password hash (PBKDF2/Argon2id client-side) and send
 * it as `password`; the server stores PBKDF2-HMAC-SHA256(clientHash, salt, N).
 *
 * The PBKDF2 derivation runs EXCLUSIVELY in the HeavyCompute Durable Object
 * (src/durable/heavy-compute.ts), reached through a Pbkdf2Runner that middleware
 * (src/app.ts) installs via AsyncLocalStorage. The request Worker never derives
 * inline: workerd caps native PBKDF2 at 100k iterations in production
 * (cloudflare/workerd#1346), and the pure-JS alternative (@noble/hashes) is
 * CPU-heavy, so all heavy compute is offloaded to the DO. @noble/hashes
 * therefore lives only inside the DO, not in this request path.
 *
 * SHA256 and HMAC-SHA256 still use node:crypto (no cap there).
 */

export interface Pbkdf2Runner {
	derive(
		password: Uint8Array,
		salt: Uint8Array,
		iterations: number,
		lengthBytes: number
	): Promise<Uint8Array>
}

export const pbkdf2Als = new AsyncLocalStorage<Pbkdf2Runner | undefined>()

export async function pbkdf2(
	password: Uint8Array,
	salt: Uint8Array,
	iterations: number,
	lengthBytes = 32
): Promise<Uint8Array> {
	const runner = pbkdf2Als.getStore()
	if (!runner) {
		throw new Error(
			"No PBKDF2 runner in context: server-side PBKDF2 runs exclusively in the " +
				"HeavyCompute Durable Object. Ensure VAULTUR_HEAVY is bound and the call " +
				"runs inside the app middleware (src/app.ts), or wrap it in " +
				"pbkdf2Als.run(heavyRunner(ns), ...) as the tests do."
		)
	}
	return runner.derive(password, salt, iterations, lengthBytes)
}

export interface PasswordRecord {
	/** base64 */
	hash: string
	/** base64 */
	salt: string
	iterations: number
}

export async function hashPassword(
	clientHash: string,
	iterations: number,
	salt: Uint8Array = randomBytes(64)
): Promise<PasswordRecord> {
	const digest = await pbkdf2(new TextEncoder().encode(clientHash), salt, iterations)
	return { hash: b64Encode(digest), salt: b64Encode(salt), iterations }
}

export async function verifyPassword(clientHash: string, record: PasswordRecord): Promise<boolean> {
	const digest = await pbkdf2(
		new TextEncoder().encode(clientHash),
		b64Decode(record.salt),
		record.iterations
	)
	return constantTimeEqual(digest, b64Decode(record.hash))
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
	return new Uint8Array(createHash("sha256").update(data).digest())
}

export async function hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
	return new Uint8Array(createHmac("sha256", key).update(data).digest())
}
