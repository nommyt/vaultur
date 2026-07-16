import { SELF } from "cloudflare:test"
import { describe, expect, it } from "vitest"

import { api, registerAndLogin } from "./helpers"

function textSend(overrides: Record<string, unknown> = {}) {
	return {
		type: 0,
		name: "2.sendName|iv==",
		notes: null,
		key: "2.sendKey|iv==",
		text: { text: "2.secret|iv==", hidden: false },
		deletionDate: new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString(),
		...overrides
	}
}

describe("sends", () => {
	it("creates a text send with the expected shape", async () => {
		const { access_token: token } = await registerAndLogin()
		const res = await api(token, "POST", "/api/sends", textSend())
		expect(res.status).toBe(200)
		const send = (await res.json()) as Record<string, any>
		expect(send.object).toBe("send")
		expect(send.type).toBe(0)
		expect(send.accessId).toBeTruthy()
		expect(send.authType).toBe(0)
		expect(send.text.text).toBe("2.secret|iv==")
		expect(send.accessCount).toBe(0)
	})

	it("allows public access and increments the access count", async () => {
		const { access_token: token } = await registerAndLogin()
		const send = (await (await api(token, "POST", "/api/sends", textSend())).json()) as Record<
			string,
			any
		>

		const access = await SELF.fetch(`https://vault.test/api/sends/access/${send.accessId}`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({})
		})
		expect(access.status).toBe(200)
		const accessed = (await access.json()) as Record<string, any>
		expect(accessed.object).toBe("send-access")
		expect(accessed.text.text).toBe("2.secret|iv==")

		// Owner view now shows accessCount incremented
		const view = (await (await api(token, "GET", `/api/sends/${send.id}`)).json()) as Record<
			string,
			any
		>
		expect(view.accessCount).toBe(1)
	})

	it("enforces send passwords", async () => {
		const { access_token: token } = await registerAndLogin()
		const send = (await (
			await api(token, "POST", "/api/sends", textSend({ password: "hunter2" }))
		).json()) as Record<string, any>
		expect(send.authType).toBe(1)
		expect(send.password).toBeTruthy()

		const noPass = await SELF.fetch(`https://vault.test/api/sends/access/${send.accessId}`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({})
		})
		expect(noPass.status).toBe(401)

		const wrongPass = await SELF.fetch(`https://vault.test/api/sends/access/${send.accessId}`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ password: "nope" })
		})
		expect(wrongPass.status).toBe(400)

		const rightPass = await SELF.fetch(`https://vault.test/api/sends/access/${send.accessId}`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ password: "hunter2" })
		})
		expect(rightPass.status).toBe(200)
	})

	it("enforces the max access count", async () => {
		const { access_token: token } = await registerAndLogin()
		const send = (await (
			await api(token, "POST", "/api/sends", textSend({ maxAccessCount: 1 }))
		).json()) as Record<string, any>

		const first = await SELF.fetch(`https://vault.test/api/sends/access/${send.accessId}`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({})
		})
		expect(first.status).toBe(200)

		const second = await SELF.fetch(`https://vault.test/api/sends/access/${send.accessId}`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({})
		})
		expect(second.status).toBe(404)
	})

	it("runs the file send v2 flow (create → upload → access → download)", async () => {
		const { access_token: token } = await registerAndLogin()
		const fileBytes = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])

		const create = await api(token, "POST", "/api/sends/file/v2", {
			type: 1,
			name: "2.fileSend|iv==",
			key: "2.fileKey|iv==",
			file: { fileName: "2.file.txt|iv==" },
			fileLength: fileBytes.length,
			deletionDate: new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString()
		})
		expect(create.status).toBe(200)
		const created = (await create.json()) as Record<string, any>
		expect(created.object).toBe("send-fileUpload")
		const sendId = created.sendResponse.id
		const uploadUrl = created.url as string

		const form = new FormData()
		form.append("data", new File([fileBytes], "file.bin"))
		const upload = await SELF.fetch(`https://vault.test/api${uploadUrl}`, {
			method: "POST",
			headers: { Authorization: `Bearer ${token}` },
			body: form
		})
		expect(upload.status).toBe(200)

		// Public access to get the download URL
		const fileId = created.sendResponse.file.id
		const access = await SELF.fetch(
			`https://vault.test/api/sends/${sendId}/access/file/${fileId}`,
			{
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({})
			}
		)
		expect(access.status).toBe(200)
		const dl = (await access.json()) as Record<string, any>
		expect(dl.object).toBe("send-fileDownload")

		const downloadPath = new URL(dl.url).pathname + new URL(dl.url).search
		const download = await SELF.fetch(`https://vault.test${downloadPath}`)
		expect(download.status).toBe(200)
		expect(new Uint8Array(await download.arrayBuffer())).toEqual(fileBytes)
	})

	it("updates, removes password, and deletes a send", async () => {
		const { access_token: token } = await registerAndLogin()
		const send = (await (
			await api(token, "POST", "/api/sends", textSend({ password: "p" }))
		).json()) as Record<string, any>

		const updated = await api(
			token,
			"PUT",
			`/api/sends/${send.id}`,
			textSend({ name: "2.renamed|iv==" })
		)
		expect(((await updated.json()) as Record<string, any>).name).toBe("2.renamed|iv==")

		const noPass = await api(token, "PUT", `/api/sends/${send.id}/remove-password`)
		expect(((await noPass.json()) as Record<string, any>).authType).toBe(0)

		expect((await api(token, "DELETE", `/api/sends/${send.id}`)).status).toBe(200)
		const gone = (await (await api(token, "GET", "/api/sends")).json()) as Record<string, any>
		expect(gone.data).toHaveLength(0)
	})

	it("returns 404 for an unknown or malformed access id", async () => {
		for (const bad of ["not-a-real-access-id", "AAAA", "%%%"]) {
			const res = await SELF.fetch(`https://vault.test/api/sends/access/${bad}`, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({})
			})
			expect(res.status).toBe(404)
		}
	})

	it("resolves each send by its own access id", async () => {
		const { access_token: token } = await registerAndLogin()
		const a = (await (
			await api(token, "POST", "/api/sends", textSend({ name: "2.A|iv==" }))
		).json()) as Record<string, any>
		const b = (await (
			await api(token, "POST", "/api/sends", textSend({ name: "2.B|iv==" }))
		).json()) as Record<string, any>

		const accessOf = async (accessId: string) =>
			(await (
				await SELF.fetch(`https://vault.test/api/sends/access/${accessId}`, {
					method: "POST",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify({})
				})
			).json()) as Record<string, any>

		expect((await accessOf(a.accessId)).id).toBe(a.id)
		expect((await accessOf(b.accessId)).id).toBe(b.id)
	})
})
