import { SELF } from "cloudflare:test"
import { describe, expect, it } from "vitest"

import { api, registerAndLogin } from "./helpers"

const LOGIN_CIPHER = {
	type: 1,
	name: "2.name|iv==",
	login: { username: "2.u|iv==", password: "2.p|iv==", uris: [] }
}

async function createCipher(token: string): Promise<string> {
	const res = await api(token, "POST", "/api/ciphers", LOGIN_CIPHER)
	return ((await res.json()) as Record<string, any>).id
}

describe("attachments (R2)", () => {
	it("runs the v2 upload/download flow", async () => {
		const { access_token: token } = await registerAndLogin()
		const cipherId = await createCipher(token)
		const bytes = new Uint8Array([10, 20, 30, 40, 50])

		// Reserve the attachment
		const reserve = await api(token, "POST", `/api/ciphers/${cipherId}/attachment/v2`, {
			key: "2.attachmentKey|iv==",
			fileName: "2.secret.txt|iv==",
			fileSize: bytes.length
		})
		expect(reserve.status).toBe(200)
		const meta = (await reserve.json()) as Record<string, any>
		expect(meta.object).toBe("attachment-fileUpload")
		expect(meta.attachmentId).toBeTruthy()
		expect(meta.cipherResponse.object).toBe("cipherDetails")

		// Upload the bytes
		const form = new FormData()
		form.append("data", new File([bytes], "secret.bin"))
		const upload = await SELF.fetch(`https://vault.test/api${meta.url}`, {
			method: "POST",
			headers: { Authorization: `Bearer ${token}` },
			body: form
		})
		expect(upload.status).toBe(200)

		// Cipher now reports the attachment with a tokenized URL
		const cipher = (await (await api(token, "GET", `/api/ciphers/${cipherId}`)).json()) as Record<
			string,
			any
		>
		expect(cipher.attachments).toHaveLength(1)
		const attachment = cipher.attachments[0]
		expect(attachment.fileName).toBe("2.secret.txt|iv==")
		expect(attachment.url).toContain("token=")

		// Download via the tokenized (unauthenticated) URL
		const downloadPath = new URL(attachment.url).pathname + new URL(attachment.url).search
		const download = await SELF.fetch(`https://vault.test${downloadPath}`)
		expect(download.status).toBe(200)
		expect(new Uint8Array(await download.arrayBuffer())).toEqual(bytes)
	})

	it("rejects an upload whose size does not match the reservation", async () => {
		const { access_token: token } = await registerAndLogin()
		const cipherId = await createCipher(token)

		const meta = (await (
			await api(token, "POST", `/api/ciphers/${cipherId}/attachment/v2`, {
				key: "2.k|iv==",
				fileName: "2.f|iv==",
				fileSize: 100
			})
		).json()) as Record<string, any>

		const form = new FormData()
		form.append("data", new File([new Uint8Array([1, 2, 3])], "f.bin"))
		const upload = await SELF.fetch(`https://vault.test/api${meta.url}`, {
			method: "POST",
			headers: { Authorization: `Bearer ${token}` },
			body: form
		})
		expect(upload.status).toBe(400)
	})

	it("deletes an attachment", async () => {
		const { access_token: token } = await registerAndLogin()
		const cipherId = await createCipher(token)
		const bytes = new Uint8Array([1, 2, 3, 4])

		const meta = (await (
			await api(token, "POST", `/api/ciphers/${cipherId}/attachment/v2`, {
				key: "2.k|iv==",
				fileName: "2.f|iv==",
				fileSize: bytes.length
			})
		).json()) as Record<string, any>
		const form = new FormData()
		form.append("data", new File([bytes], "f.bin"))
		await SELF.fetch(`https://vault.test/api${meta.url}`, {
			method: "POST",
			headers: { Authorization: `Bearer ${token}` },
			body: form
		})

		const del = await api(
			token,
			"DELETE",
			`/api/ciphers/${cipherId}/attachment/${meta.attachmentId}`
		)
		expect(del.status).toBe(200)

		const cipher = (await (await api(token, "GET", `/api/ciphers/${cipherId}`)).json()) as Record<
			string,
			any
		>
		expect(cipher.attachments).toBeNull()
	})
})
