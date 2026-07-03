import { createHmac } from "node:crypto"

import { fetchMock } from "cloudflare:test"
import { sign } from "hono/jwt"
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest"

import { api, login, registerAndLogin, TEST_USER } from "./helpers"

/**
 * YubiKey OTP and Duo Universal Prompt 2FA, with the YubiCloud / Duo APIs
 * mocked at the fetch layer (responses are signed exactly like the real
 * services so the verification paths run for real).
 */

const YUBICO_SECRET_B64 = Buffer.from("yubico-test-secret").toString("base64")
const DUO_HOST = "api-test.duosecurity.com"
const DUO_IKEY = "DI_TEST_CLIENT_ID_XX"
const DUO_SKEY = "duo-test-client-secret-duo-test-client-secret"

beforeAll(() => {
	fetchMock.activate()
	fetchMock.disableNetConnect()
})
afterEach(() => fetchMock.assertNoPendingInterceptors())
afterAll(() => fetchMock.deactivate())

// --- YubiCloud response signing (same algorithm as the server verifies) ---

function yubicoSign(params: Record<string, string>): string {
	const payload = Object.keys(params)
		.filter((k) => k !== "h")
		.sort()
		.map((k) => `${k}=${params[k]}`)
		.join("&")
	return createHmac("sha1", Buffer.from(YUBICO_SECRET_B64, "base64"))
		.update(payload)
		.digest("base64")
}

function mockYubicoVerify(status = "OK") {
	fetchMock
		.get("https://api.yubico.com")
		.intercept({ method: "GET", path: (p) => p.startsWith("/wsapi/2.0/verify") })
		.reply(200, (req) => {
			const url = new URL(req.path, "https://api.yubico.com")
			const fields: Record<string, string> = {
				otp: url.searchParams.get("otp") ?? "",
				nonce: url.searchParams.get("nonce") ?? "",
				t: "2026-07-03T00:00:00Z0000",
				status
			}
			fields.h = yubicoSign(fields)
			return Object.entries(fields)
				.map(([k, v]) => `${k}=${v}`)
				.join("\r\n")
		})
}

const YUBI_PUBLIC_ID = "ccccccfedcbb"
const otpFor = (publicId: string) => publicId + "c".repeat(32) // 44-char modhex

describe("two-factor (yubikey)", () => {
	it("activates a yubikey and requires a valid OTP on login", async () => {
		const session = await registerAndLogin()
		const token = session.access_token

		// Activation verifies the OTP against YubiCloud
		mockYubicoVerify()
		const activateRes = await api(token, "POST", "/api/two-factor/yubikey", {
			key1: otpFor(YUBI_PUBLIC_ID),
			nfc: true,
			masterPasswordHash: TEST_USER.masterPasswordHash
		})
		expect(activateRes.status).toBe(200)
		const activated = (await activateRes.json()) as Record<string, unknown>
		expect(activated.enabled).toBe(true)
		expect(activated.Key1).toBe(YUBI_PUBLIC_ID)
		expect(activated.nfc).toBe(true)

		// Login without a token advertises provider 3 with the Nfc flag
		const need2fa = await login()
		expect(need2fa.status).toBe(400)
		const body = (await need2fa.json()) as {
			TwoFactorProviders: string[]
			TwoFactorProviders2: Record<string, { Nfc: boolean }>
		}
		expect(body.TwoFactorProviders).toContain("3")
		expect(body.TwoFactorProviders2["3"]).toEqual({ Nfc: true })

		// An OTP from an unregistered key is rejected without calling YubiCloud
		const wrongKey = await login(TEST_USER.email, TEST_USER.masterPasswordHash, {
			twoFactorProvider: "3",
			twoFactorToken: otpFor("ccccccnnnnnn")
		})
		expect(wrongKey.status).toBe(400)

		// A valid OTP for the registered key logs in
		mockYubicoVerify()
		const okRes = await login(TEST_USER.email, TEST_USER.masterPasswordHash, {
			twoFactorProvider: "3",
			twoFactorToken: otpFor(YUBI_PUBLIC_ID)
		})
		expect(okRes.status).toBe(200)

		// A REPLAYED status from YubiCloud fails the login
		mockYubicoVerify("REPLAYED_OTP")
		const replayRes = await login(TEST_USER.email, TEST_USER.masterPasswordHash, {
			twoFactorProvider: "3",
			twoFactorToken: otpFor(YUBI_PUBLIC_ID)
		})
		expect(replayRes.status).toBe(400)

		// get-yubikey returns the stored key ids
		const getRes = await api(token, "POST", "/api/two-factor/get-yubikey", {
			masterPasswordHash: TEST_USER.masterPasswordHash
		})
		const got = (await getRes.json()) as Record<string, unknown>
		expect(got.Key1).toBe(YUBI_PUBLIC_ID)
	})
})

// --- Duo Universal Prompt ---

function mockDuoHealthCheck() {
	fetchMock
		.get(`https://${DUO_HOST}`)
		.intercept({ method: "POST", path: "/oauth/v1/health_check" })
		.reply(200, { stat: "OK" })
}

describe("two-factor (duo)", () => {
	it("activates Duo with global keys and completes the universal-prompt flow", async () => {
		const session = await registerAndLogin()
		const token = session.access_token

		// Empty fields → use the globally configured keys (no /auth/v2/check call)
		const activateRes = await api(token, "POST", "/api/two-factor/duo", {
			host: "",
			clientId: "",
			clientSecret: "",
			masterPasswordHash: TEST_USER.masterPasswordHash
		})
		expect(activateRes.status).toBe(200)
		const activated = (await activateRes.json()) as Record<string, unknown>
		expect(activated.enabled).toBe(true)
		expect(activated.host).toBe("<global_secret>")

		// Login advertises provider 2 with an AuthUrl (server health-checks Duo first)
		mockDuoHealthCheck()
		const need2fa = await login()
		expect(need2fa.status).toBe(400)
		const body = (await need2fa.json()) as {
			TwoFactorProviders2: Record<string, { AuthUrl: string }>
		}
		const authUrl = new URL(body.TwoFactorProviders2["2"]!.AuthUrl)
		expect(authUrl.hostname).toBe(DUO_HOST)
		expect(authUrl.pathname).toBe("/oauth/v1/authorize")
		expect(authUrl.searchParams.get("client_id")).toBe(DUO_IKEY)

		// The signed request JWT carries our state + device-bound nonce
		const request = authUrl.searchParams.get("request")!
		const payload = JSON.parse(Buffer.from(request.split(".")[1]!, "base64url").toString()) as {
			state: string
			nonce: string
			duo_uname: string
		}
		expect(payload.duo_uname).toBe(TEST_USER.email)

		// Duo would redirect back to the client with code+state; the client then
		// submits "<code>|<state>". The server re-health-checks and exchanges the code.
		mockDuoHealthCheck()
		const tokenUrl = `https://${DUO_HOST}/oauth/v1/token`
		const idToken = await sign(
			{
				iss: tokenUrl,
				aud: DUO_IKEY,
				exp: Math.floor(Date.now() / 1000) + 300,
				iat: Math.floor(Date.now() / 1000),
				nonce: payload.nonce,
				preferred_username: TEST_USER.email
			},
			DUO_SKEY,
			"HS512"
		)
		fetchMock
			.get(`https://${DUO_HOST}`)
			.intercept({ method: "POST", path: "/oauth/v1/token" })
			.reply(200, {
				id_token: idToken,
				access_token: "x",
				expires_in: 300,
				token_type: "Bearer"
			})

		const okRes = await login(TEST_USER.email, TEST_USER.masterPasswordHash, {
			twoFactorProvider: "2",
			twoFactorToken: `FAKE_DUO_CODE|${payload.state}`
		})
		expect(okRes.status).toBe(200)

		// The state is single-use: replaying the same token fails before any Duo call
		const replayRes = await login(TEST_USER.email, TEST_USER.masterPasswordHash, {
			twoFactorProvider: "2",
			twoFactorToken: `FAKE_DUO_CODE|${payload.state}`
		})
		expect(replayRes.status).toBe(400)
	})

	it("rejects an id_token whose username does not match", async () => {
		const session = await registerAndLogin()
		await api(session.access_token, "POST", "/api/two-factor/duo", {
			host: "",
			clientId: "",
			clientSecret: "",
			masterPasswordHash: TEST_USER.masterPasswordHash
		})

		mockDuoHealthCheck()
		const need2fa = await login()
		const body = (await need2fa.json()) as {
			TwoFactorProviders2: Record<string, { AuthUrl: string }>
		}
		const request = new URL(body.TwoFactorProviders2["2"]!.AuthUrl).searchParams.get("request")!
		const payload = JSON.parse(Buffer.from(request.split(".")[1]!, "base64url").toString()) as {
			state: string
			nonce: string
		}

		mockDuoHealthCheck()
		const tokenUrl = `https://${DUO_HOST}/oauth/v1/token`
		const idToken = await sign(
			{
				iss: tokenUrl,
				aud: DUO_IKEY,
				exp: Math.floor(Date.now() / 1000) + 300,
				nonce: payload.nonce,
				preferred_username: "attacker@vaultur.dev"
			},
			DUO_SKEY,
			"HS512"
		)
		fetchMock
			.get(`https://${DUO_HOST}`)
			.intercept({ method: "POST", path: "/oauth/v1/token" })
			.reply(200, { id_token: idToken, access_token: "x", expires_in: 300, token_type: "Bearer" })

		const res = await login(TEST_USER.email, TEST_USER.masterPasswordHash, {
			twoFactorProvider: "2",
			twoFactorToken: `FAKE_DUO_CODE|${payload.state}`
		})
		expect(res.status).toBe(400)
	})
})
