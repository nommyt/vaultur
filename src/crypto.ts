import { createHash, createHmac, pbkdf2Sync } from "node:crypto"

import { b64Decode, b64Encode, constantTimeEqual, randomBytes } from "./util"

/**
 * Server-side password verification, matching vaultwarden's model:
 * clients derive a master-password hash (PBKDF2/Argon2id client-side) and send
 * it as `password`; the server stores PBKDF2-HMAC-SHA256(clientHash, salt, N).
 *
 * Uses node:crypto (nodejs_compat) rather than Web Crypto — Web Crypto's
 * PBKDF2 is hard-capped at 100k iterations on Workers, while node:crypto has
 * no such limit, so vaultwarden's 600k default is achievable.
 */

export async function pbkdf2(
	password: Uint8Array,
	salt: Uint8Array,
	iterations: number,
	lengthBytes = 32
): Promise<Uint8Array> {
	return new Uint8Array(pbkdf2Sync(password, salt, iterations, lengthBytes, "sha256"))
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
