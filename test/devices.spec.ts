import { SELF } from "cloudflare:test"
import { describe, expect, it } from "vitest"

import { api, login, registerUser, TEST_USER } from "./helpers"

function b64url(input: string, pad: boolean): string {
	const b64 = btoa(input).replace(/\+/g, "-").replace(/\//g, "_")
	return pad ? b64 : b64.replace(/=+$/, "")
}

describe("devices", () => {
	it("knowndevice reflects login state (padded and unpadded email)", async () => {
		await registerUser()

		const deviceId = "test-device-id-1" // matches helpers login()
		const knownBefore = await SELF.fetch("https://vault.test/api/devices/knowndevice", {
			headers: {
				"X-Device-Identifier": deviceId,
				"X-Request-Email": b64url(TEST_USER.email, false)
			}
		})
		expect(await knownBefore.json()).toBe(false)

		// Log in to register the device
		await login()

		const knownUnpadded = await SELF.fetch("https://vault.test/api/devices/knowndevice", {
			headers: {
				"X-Device-Identifier": deviceId,
				"X-Request-Email": b64url(TEST_USER.email, false)
			}
		})
		expect(await knownUnpadded.json()).toBe(true)

		const knownPadded = await SELF.fetch("https://vault.test/api/devices/knowndevice", {
			headers: {
				"X-Device-Identifier": deviceId,
				"X-Request-Email": b64url(TEST_USER.email, true)
			}
		})
		expect(await knownPadded.json()).toBe(true)
	})

	it("lists devices and deauthorizes one", async () => {
		await registerUser()
		const session = (await (await login()).json()) as Record<string, any>
		const token = session.access_token

		const list = (await (await api(token, "GET", "/api/devices")).json()) as Record<string, any>
		expect(list.object).toBe("list")
		expect(list.data).toHaveLength(1)
		expect(list.data[0].identifier).toBe("test-device-id-1")

		// Store a push token (no push configured → still succeeds)
		const setToken = await api(token, "PUT", "/api/devices/identifier/test-device-id-1/token", {
			pushToken: "apns-token-123"
		})
		expect(setToken.status).toBe(200)

		// Clear it
		expect(
			(await api(token, "PUT", "/api/devices/identifier/test-device-id-1/clear-token")).status
		).toBe(200)

		// Deauthorize the device → the token's device lookup now fails
		expect((await api(token, "DELETE", "/api/devices/test-device-id-1")).status).toBe(200)
		const afterDeauth = await api(token, "GET", "/api/sync")
		expect(afterDeauth.status).toBe(401)
	})
})
