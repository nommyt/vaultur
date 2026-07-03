import { AsyncLocalStorage } from "node:async_hooks"
import { createHash, createHmac } from "node:crypto"

import { pbkdf2Async } from "@noble/hashes/pbkdf2.js"
import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js"

import { b64Decode, b64Encode, constantTimeEqual, randomBytes } from "./util"

/**
 * Server-side password verification, matching vaultwarden's model:
 * clients derive a master-password hash (PBKDF2/Argon2id client-side) and send
 * it as `password`; the server stores PBKDF2-HMAC-SHA256(clientHash, salt, N).
 *
 * Uses @noble/hashes (pure JS) instead of native crypto — both WebCrypto and
 * node:crypto pbkdf2 in workerd cap iterations at 100_000 in production
 * (cloudflare/workerd#1346), while @noble/hashes runs as V8 compute with no
 * such limit, so vaultwarden's 600k default is achievable.
 *
 * When the VAULTUR_HEAVY Durable Object binding is active, the derivation is
 * offloaded to a DO for a higher CPU budget (free-tier friendly), set via
 * AsyncLocalStorage by middleware — callers are oblivious.
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
	if (runner) return runner.derive(password, salt, iterations, lengthBytes)
	return pbkdf2Async(nobleSha256, password, salt, { c: iterations, dkLen: lengthBytes })
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
