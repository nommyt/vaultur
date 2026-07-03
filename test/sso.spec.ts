import { createHash } from "node:crypto"

import { SELF, fetchMock } from "cloudflare:test"
import { SignJWT, exportJWK, generateKeyPair } from "jose"
import { afterAll, beforeAll, describe, expect, it } from "vitest"

import { login, registerAndLogin, registerUser, TEST_USER } from "./helpers"

/**
 * OIDC SSO end-to-end against a fetch-mocked identity provider:
 * authorize redirect → IdP callback → authorization_code grant, with a real
 * RS256 id_token verified through the provider's (mocked) JWKS.
 */

const IDP = "https://idp.test"
const CLIENT_ID = "vaultur-client"

// One RS256 keypair for the whole file — the worker caches the remote JWKS.
let idpKeys: Awaited<ReturnType<typeof generateKeyPair>>

beforeAll(async () => {
	idpKeys = await generateKeyPair("RS256", { extractable: true })
	fetchMock.activate()
	fetchMock.disableNetConnect()

	fetchMock
		.get(IDP)
		.intercept({ method: "GET", path: "/.well-known/openid-configuration" })
		.reply(200, {
			issuer: IDP,
			authorization_endpoint: `${IDP}/authorize`,
			token_endpoint: `${IDP}/token`,
			userinfo_endpoint: `${IDP}/userinfo`,
			jwks_uri: `${IDP}/jwks`
		})
		.persist()

	fetchMock
		.get(IDP)
		.intercept({ method: "GET", path: "/jwks" })
		.reply(200, async () => ({
			keys: [{ ...(await exportJWK(idpKeys.publicKey)), kid: "idp-test-key", alg: "RS256" }]
		}))
		.persist()
})
afterAll(() => fetchMock.deactivate())

const b64 = (s: string) => Buffer.from(s).toString("base64")
const s256 = (v: string) => createHash("sha256").update(v).digest("base64url")

interface IdpUser {
	sub: string
	email: string
	emailVerified?: boolean
	name?: string
}

async function idpIdToken(user: IdpUser, nonce: string): Promise<string> {
	return new SignJWT({
		nonce,
		email: user.email,
		email_verified: user.emailVerified ?? true,
		preferred_username: user.name ?? "SSO User"
	})
		.setProtectedHeader({ alg: "RS256", kid: "idp-test-key" })
		.setIssuer(IDP)
		.setAudience(CLIENT_ID)
		.setSubject(user.sub)
		.setIssuedAt()
		.setExpirationTime("5m")
		.sign(idpKeys.privateKey)
}

function mockTokenEndpoint(user: IdpUser, nonce: string, expectedVerifier: string) {
	fetchMock
		.get(IDP)
		.intercept({ method: "POST", path: "/token" })
		.reply(200, async (req) => {
			const body = new URLSearchParams(String(req.body))
			if (body.get("code_verifier") !== expectedVerifier) {
				return { error: "invalid_grant", error_description: "bad verifier" }
			}
			return {
				id_token: await idpIdToken(user, nonce),
				access_token: "idp-access-token",
				token_type: "Bearer",
				expires_in: 3600
			}
		})
	fetchMock
		.get(IDP)
		.intercept({ method: "GET", path: "/userinfo" })
		.reply(200, { email: user.email, email_verified: user.emailVerified ?? true })
}

/** Drives authorize → callback and returns what the client would receive. */
async function ssoHandshake(state: string, verifier: string) {
	const authorize = await SELF.fetch(
		`https://vault.test/identity/connect/authorize?client_id=web&redirect_uri=${encodeURIComponent(
			"https://vault.test/sso-connector.html"
		)}&response_type=code&scope=api%20offline_access%20openid&state=${state}&code_challenge=${s256(
			verifier
		)}&code_challenge_method=S256`,
		{ redirect: "manual" }
	)
	expect(authorize.status).toBe(307)
	const idpUrl = new URL(authorize.headers.get("Location")!)
	expect(idpUrl.origin).toBe(IDP)
	expect(idpUrl.searchParams.get("state")).toBe(b64(state))
	expect(idpUrl.searchParams.get("code_challenge")).toBe(s256(verifier))
	const nonce = idpUrl.searchParams.get("nonce")!
	const bindingCookie = authorize.headers.get("Set-Cookie")!.split(";")[0]!

	// IdP redirects the browser back with its authorization code
	const idpCode = `idp-code-${state}`
	const callback = await SELF.fetch(
		`https://vault.test/identity/connect/oidc-signin?code=${idpCode}&state=${encodeURIComponent(
			idpUrl.searchParams.get("state")!
		)}`,
		{ redirect: "manual", headers: { Cookie: bindingCookie } }
	)
	expect(callback.status).toBe(307)
	const clientUrl = new URL(callback.headers.get("Location")!)
	expect(clientUrl.pathname).toBe("/sso-connector.html")
	expect(clientUrl.searchParams.get("code")).toBe(idpCode)
	expect(clientUrl.searchParams.get("state")).toBe(state)

	return { nonce, code: idpCode }
}

async function ssoTokenGrant(code: string, verifier: string) {
	return SELF.fetch("https://vault.test/identity/connect/token", {
		method: "POST",
		headers: { "Content-Type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams({
			grant_type: "authorization_code",
			code,
			code_verifier: verifier,
			client_id: "web",
			scope: "api offline_access",
			deviceType: "9",
			deviceIdentifier: "sso-test-device",
			deviceName: "firefox"
		}).toString()
	})
}

describe("sso (oidc)", () => {
	it("prevalidate returns a token when SSO is configured", async () => {
		for (const path of ["/identity/sso/prevalidate", "/identity/account/prevalidate"]) {
			const res = await SELF.fetch(`https://vault.test${path}`)
			expect(res.status).toBe(200)
			expect(((await res.json()) as { token: string }).token).toBeTruthy()
		}
	})

	it("provisions a brand-new user from a verified OIDC identity", async () => {
		const state = "state-new-user"
		const verifier = "verifier-new-user-verifier-new-user"
		const { nonce, code } = await ssoHandshake(state, verifier)

		mockTokenEndpoint(
			{ sub: "oidc-sub-1", email: "fresh@corp.test", name: "Fresh" },
			nonce,
			verifier
		)
		const res = await ssoTokenGrant(code, verifier)
		expect(res.status).toBe(200)
		const body = (await res.json()) as {
			access_token: string
			UserDecryptionOptions: { HasMasterPassword: boolean }
		}
		expect(body.access_token).toBeTruthy()
		// Fresh SSO users have no master password yet — client routes to set-password
		expect(body.UserDecryptionOptions.HasMasterPassword).toBe(false)

		// The code is burned after redemption
		const replay = await ssoTokenGrant(code, verifier)
		expect(replay.status).toBe(400)
	})

	it("links an existing password account by verified email and keeps password login working", async () => {
		await registerAndLogin()

		const state = "state-link-user"
		const verifier = "verifier-link-user-verifier-link-user"
		const { nonce, code } = await ssoHandshake(state, verifier)
		mockTokenEndpoint({ sub: "oidc-sub-2", email: TEST_USER.email }, nonce, verifier)

		const res = await ssoTokenGrant(code, verifier)
		expect(res.status).toBe(200)
		const body = (await res.json()) as {
			Key?: string
			UserDecryptionOptions: { HasMasterPassword: boolean }
		}
		// Linked account keeps its master password and vault key
		expect(body.UserDecryptionOptions.HasMasterPassword).toBe(true)
		expect(body.Key).toBe(TEST_USER.key)

		const pw = await login()
		expect(pw.status).toBe(200)
	})

	it("refuses to link when the provider does not verify the email", async () => {
		await registerUser()

		const state = "state-unverified"
		const verifier = "verifier-unverified-verifier-unverified"
		const { nonce, code } = await ssoHandshake(state, verifier)
		mockTokenEndpoint(
			{ sub: "oidc-sub-3", email: TEST_USER.email, emailVerified: false },
			nonce,
			verifier
		)

		const res = await ssoTokenGrant(code, verifier)
		expect(res.status).toBe(400)
		expect(((await res.json()) as { message: string }).message).toContain("not verified")
	})

	it("rejects a wrong PKCE verifier", async () => {
		const state = "state-bad-pkce"
		const verifier = "verifier-bad-pkce-verifier-bad-pkce-1"
		const { nonce, code } = await ssoHandshake(state, verifier)
		mockTokenEndpoint({ sub: "oidc-sub-4", email: "pkce@corp.test" }, nonce, verifier)

		// The IdP (mock) rejects the mismatched verifier → login fails
		const res = await ssoTokenGrant(code, "a-completely-different-verifier-value")
		expect(res.status).toBe(400)
	})

	it("rejects the callback from a browser without the binding cookie", async () => {
		const state = "state-no-cookie"
		const verifier = "verifier-no-cookie-verifier-no-cookie"
		const authorize = await SELF.fetch(
			`https://vault.test/identity/connect/authorize?client_id=web&redirect_uri=${encodeURIComponent(
				"https://vault.test/sso-connector.html"
			)}&state=${state}&code_challenge=${s256(verifier)}&code_challenge_method=S256`,
			{ redirect: "manual" }
		)
		expect(authorize.status).toBe(307)
		const idpState = new URL(authorize.headers.get("Location")!).searchParams.get("state")!

		const callback = await SELF.fetch(
			`https://vault.test/identity/connect/oidc-signin?code=stolen&state=${encodeURIComponent(idpState)}`,
			{ redirect: "manual" }
		)
		expect(callback.status).toBe(400)
	})
})
