import { env } from "cloudflare:test"
import { describe, expect, it } from "vitest"

import type { Bindings } from "../src/env"
import { KvBlobStore, listKeys, R2BlobStore } from "../src/services/storage"

function streamOf(bytes: Uint8Array): ReadableStream {
	return new Blob([bytes]).stream()
}

async function readAll(stream: ReadableStream): Promise<Uint8Array> {
	return new Uint8Array(await new Response(stream).arrayBuffer())
}

describe("KvBlobStore", () => {
	const kv = (env as unknown as Bindings).VAULTUR_KV
	const store = new KvBlobStore(kv)

	it("round-trips a put through get, preserving size via metadata", async () => {
		const bytes = new Uint8Array([1, 2, 3, 4, 5])
		await store.put("test/roundtrip", streamOf(bytes), bytes.length)

		const got = await store.get("test/roundtrip")
		expect(got).not.toBeNull()
		expect(got?.size).toBe(bytes.length)
		expect(await readAll(got!.body)).toEqual(bytes)
	})

	it("returns null for a missing key", async () => {
		expect(await store.get("test/does-not-exist")).toBeNull()
	})

	it("deletes a key", async () => {
		const bytes = new Uint8Array([9, 9, 9])
		await store.put("test/to-delete", streamOf(bytes), bytes.length)
		expect(await store.get("test/to-delete")).not.toBeNull()

		await store.delete("test/to-delete")
		expect(await store.get("test/to-delete")).toBeNull()
	})

	it("deletePrefix clears every key under a prefix and leaves others intact", async () => {
		const prefix = "test/sends/some-uuid/"
		await store.put(`${prefix}file-a`, streamOf(new Uint8Array([1])), 1)
		await store.put(`${prefix}file-b`, streamOf(new Uint8Array([2])), 1)
		await store.put("test/sends/other-uuid/file-c", streamOf(new Uint8Array([3])), 1)

		await store.deletePrefix(prefix)

		expect(await store.get(`${prefix}file-a`)).toBeNull()
		expect(await store.get(`${prefix}file-b`)).toBeNull()
		expect(await store.get("test/sends/other-uuid/file-c")).not.toBeNull()
	})

	it("exposes a 25 MiB max size", () => {
		expect(store.maxBytes).toBe(25 * 1024 * 1024)
	})
})

async function listAll(bucket: R2Bucket, prefix: string): Promise<string[]> {
	const keys: string[] = []
	for await (const page of listKeys(bucket, prefix)) keys.push(...page)
	return keys
}

async function seed(bucket: R2Bucket, prefix: string, count: number): Promise<void> {
	for (let start = 0; start < count; start += 100) {
		const batch = Array.from({ length: Math.min(100, count - start) }, (_, i) =>
			bucket.put(`${prefix}${String(start + i).padStart(5, "0")}`, "x")
		)
		await Promise.all(batch)
	}
}

describe("R2BlobStore.deletePrefix", () => {
	const bucket = (env as unknown as Bindings).VAULTUR_FILES!
	const store = new R2BlobStore(bucket)

	it("removes a prefix that spans more than one listing page", async () => {
		const prefix = "r2-paged/big/"
		const sibling = "r2-paged/other/"
		await seed(bucket, prefix, 1005)
		await seed(bucket, sibling, 3)
		// Guard: the binding really paginates, so this test exercises the cursor.
		expect((await bucket.list({ prefix })).truncated).toBe(true)

		await store.deletePrefix(prefix)

		expect(await listAll(bucket, prefix)).toEqual([])
		expect(await listAll(bucket, sibling)).toHaveLength(3)
	})

	it("sends each listing page to one bucket.delete call", async () => {
		const prefix = "r2-calls/big/"
		await seed(bucket, prefix, 1005)
		let deleteCalls = 0
		const counting = {
			list: (o?: R2ListOptions) => bucket.list(o),
			delete: (keys: string | string[]) => {
				deleteCalls++
				return bucket.delete(keys)
			}
		} as unknown as R2Bucket

		await new R2BlobStore(counting).deletePrefix(prefix)

		expect(deleteCalls).toBe(2)
		expect(await listAll(bucket, prefix)).toEqual([])
	})

	it("succeeds on an empty prefix without a delete call", async () => {
		let deleteCalls = 0
		const counting = {
			list: (o?: R2ListOptions) => bucket.list(o),
			delete: () => {
				deleteCalls++
			}
		} as unknown as R2Bucket
		await expect(
			new R2BlobStore(counting).deletePrefix("r2-paged/nothing-here/")
		).resolves.toBeUndefined()
		expect(deleteCalls).toBe(0)
	})

	it("surfaces a listing failure", async () => {
		const failing = {
			list: async () => {
				throw new Error("list failed")
			},
			delete: async () => {}
		} as unknown as R2Bucket
		await expect(new R2BlobStore(failing).deletePrefix("p/")).rejects.toThrow("list failed")
	})

	it("surfaces a delete failure", async () => {
		const failing = {
			list: async () => ({ objects: [{ key: "p/a" }], truncated: false }),
			delete: async () => {
				throw new Error("delete failed")
			}
		} as unknown as R2Bucket
		await expect(new R2BlobStore(failing).deletePrefix("p/")).rejects.toThrow("delete failed")
	})
})
