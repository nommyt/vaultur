import type { Pbkdf2Runner } from "../crypto"
import { b64Decode, b64Encode } from "../util"

export interface Pbkdf2OffloadRequest {
	password: string // base64
	salt: string // base64
	iterations: number
	dkLen: number
}

export interface Pbkdf2OffloadResponse {
	digest: string // base64
}

export function heavyRunner(ns: DurableObjectNamespace): Pbkdf2Runner {
	const id = ns.idFromName("vaultur:heavy")
	return {
		async derive(password, salt, iterations, lengthBytes) {
			const stub = ns.get(id)
			const res = await stub.fetch("https://heavy/pbkdf2", {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({
					password: b64Encode(password),
					salt: b64Encode(salt),
					iterations,
					dkLen: lengthBytes
				} satisfies Pbkdf2OffloadRequest)
			})
			if (!res.ok) {
				const text = await res.text()
				throw new Error(`heavy compute failed (${res.status}): ${text}`)
			}
			const { digest } = (await res.json()) as Pbkdf2OffloadResponse
			return b64Decode(digest)
		}
	}
}
