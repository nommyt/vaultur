import { env } from "cloudflare:test"
import { describe, expect, it } from "vitest"

import type { Bindings } from "../src/env"
import { KvBlobStore } from "../src/services/storage"

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
