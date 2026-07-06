import type { Bindings } from "../env"

/**
 * Blob storage abstraction for cipher attachments and file Sends.
 *
 * R2 requires a paid Cloudflare plan, so `VAULTUR_FILES` is optional: when the
 * binding is absent (free tier), files fall back to KV. Backend selection is
 * driven purely by binding presence — see `getBlobStore`.
 */

export interface StoredBlob {
	body: ReadableStream
	size: number
}

export interface BlobStore {
	/** Hard per-file byte ceiling for this backend. */
	readonly maxBytes: number
	get(key: string): Promise<StoredBlob | null>
	put(key: string, body: ReadableStream, size: number): Promise<void>
	delete(key: string): Promise<void>
	deletePrefix(prefix: string): Promise<void>
}

const R2_MAX_BYTES = 500 * 1024 * 1024
// KV's hard per-value size limit (not merely a free-tier quota).
const KV_MAX_BYTES = 25 * 1024 * 1024

export class R2BlobStore implements BlobStore {
	readonly maxBytes = R2_MAX_BYTES

	constructor(private bucket: R2Bucket) {}

	async get(key: string): Promise<StoredBlob | null> {
		const object = await this.bucket.get(key)
		if (!object) return null
		return { body: object.body, size: object.size }
	}

	async put(key: string, body: ReadableStream): Promise<void> {
		await this.bucket.put(key, body, { httpMetadata: { contentType: "application/octet-stream" } })
	}

	async delete(key: string): Promise<void> {
		await this.bucket.delete(key)
	}

	async deletePrefix(prefix: string): Promise<void> {
		const list = await this.bucket.list({ prefix })
		await Promise.all(list.objects.map((o) => this.bucket.delete(o.key)))
	}
}

interface KvBlobMetadata {
	size: number
}

export class KvBlobStore implements BlobStore {
	readonly maxBytes = KV_MAX_BYTES

	constructor(private kv: KVNamespace) {}

	async get(key: string): Promise<StoredBlob | null> {
		const { value, metadata } = await this.kv.getWithMetadata<KvBlobMetadata>(key, "stream")
		if (!value) return null
		return { body: value, size: metadata?.size ?? 0 }
	}

	async put(key: string, body: ReadableStream, size: number): Promise<void> {
		await this.kv.put(key, body, { metadata: { size } satisfies KvBlobMetadata })
	}

	async delete(key: string): Promise<void> {
		await this.kv.delete(key)
	}

	async deletePrefix(prefix: string): Promise<void> {
		let cursor: string | undefined
		for (;;) {
			const list = await this.kv.list({ prefix, cursor })
			await Promise.all(list.keys.map((k) => this.kv.delete(k.name)))
			if (list.list_complete) break
			cursor = list.cursor
		}
	}
}

export function getBlobStore(env: Pick<Bindings, "VAULTUR_FILES" | "VAULTUR_KV">): BlobStore {
	return env.VAULTUR_FILES ? new R2BlobStore(env.VAULTUR_FILES) : new KvBlobStore(env.VAULTUR_KV)
}
