import { b64Decode, b64Encode, constantTimeEqual, randomBytes } from "./util"

/**
 * Server-side password verification, matching vaultwarden's model:
 * clients derive a master-password hash (PBKDF2/Argon2id client-side) and send
 * it as `password`; the server stores PBKDF2-HMAC-SHA256(clientHash, salt, N).
 */

export async function pbkdf2(
	password: Uint8Array,
	salt: Uint8Array,
	iterations: number,
	lengthBytes = 32
): Promise<Uint8Array> {
	const key = await crypto.subtle.importKey("raw", password as BufferSource, "PBKDF2", false, [
		"deriveBits"
	])
	const bits = await crypto.subtle.deriveBits(
		{ name: "PBKDF2", hash: "SHA-256", salt: salt as BufferSource, iterations },
		key,
		lengthBytes * 8
	)
	return new Uint8Array(bits)
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
	return new Uint8Array(await crypto.subtle.digest("SHA-256", data as BufferSource))
}

export async function hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
	const k = await crypto.subtle.importKey(
		"raw",
		key as BufferSource,
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"]
	)
	return new Uint8Array(await crypto.subtle.sign("HMAC", k, data as BufferSource))
}
