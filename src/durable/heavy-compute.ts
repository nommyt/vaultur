import { pbkdf2Async } from "@noble/hashes/pbkdf2.js"
import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js"
import { DurableObject } from "cloudflare:workers"

import type { Pbkdf2OffloadRequest, Pbkdf2OffloadResponse } from "../services/pbkdf2-offload"
import { b64Decode, b64Encode } from "../util"

/**
 * Stateless Durable Object that runs server-side PBKDF2-HMAC-SHA256 via
 * @noble/hashes (pure JS). The workerd native PBKDF2 cap (100k iterations)
 * doesn't apply here because noble runs as V8 compute, not through BoringSSL.
 *
 * A single DO instance ("vaultur:heavy") accepts POST /pbkdf2 with
 * { password, salt, iterations, dkLen } in base64 and returns { digest }.
 *
 * Configure by adding the VAULTUR_HEAVY binding in wrangler.jsonc. When the
 * binding is absent the main Worker runs noble inline.
 */
export class HeavyCompute extends DurableObject {
	override async fetch(request: Request): Promise<Response> {
		if (request.method !== "POST") {
			return new Response("Method not allowed", { status: 405 })
		}
		const url = new URL(request.url)
		if (!url.pathname.endsWith("/pbkdf2")) {
			return new Response("Not found", { status: 404 })
		}

		const body = (await request.json()) as Pbkdf2OffloadRequest
		const digest = await pbkdf2Async(nobleSha256, b64Decode(body.password), b64Decode(body.salt), {
			c: body.iterations,
			dkLen: body.dkLen
		})
		return Response.json({ digest: b64Encode(digest) } satisfies Pbkdf2OffloadResponse)
	}
}
