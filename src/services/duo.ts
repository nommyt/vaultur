import { createHash, createHmac } from "node:crypto"

import { and, eq, lt } from "drizzle-orm"
import { sign, verify } from "hono/jwt"

import type { Config } from "../config"
import { duoGlobalConfigured } from "../config"
import { twofactor, twofactorDuoCtx, type Db } from "../db"
import { err } from "../error"
import { TwoFactorType } from "../shared"
import { constantTimeEqualStr, randomAlphanum } from "../util"

/**
 * Duo Security 2FA via the Universal Prompt (OIDC) flow, ported from
 * vaultwarden src/api/core/two_factor/{duo,duo_oidc}.rs.
 *
 * The deprecated iframe ("traditional prompt") flow is intentionally not
 * ported — Duo shut it down in March 2024; vaultwarden only keeps it behind
 * the off-by-default DUO_USE_IFRAME flag.
 */

// Bridge page built into the Bitwarden clients that Duo redirects back to.
const DUO_REDIRECT_LOCATION = "duo-redirect-connector.html"
const JWT_VALIDITY_SECS = 300
const CTX_VALIDITY_SECS = 300
const STATE_LENGTH = 64

export interface DuoData {
	host: string // Duo API hostname
	ik: string // client id
	sk: string // client secret
}

export function globalDuoData(config: Config): DuoData | null {
	return duoGlobalConfigured(config)
		? { host: config.duoHost, ik: config.duoIkey, sk: config.duoSkey }
		: null
}

export type DuoStatus =
	| { kind: "global"; data: DuoData }
	| { kind: "user"; data: DuoData }
	| { kind: "disabled"; hasGlobal: boolean }

export async function getUserDuoData(db: Db, config: Config, userUuid: string): Promise<DuoStatus> {
	const row = await db.query.twofactor.findFirst({
		where: and(eq(twofactor.userUuid, userUuid), eq(twofactor.atype, TwoFactorType.Duo))
	})
	if (!row) return { kind: "disabled", hasGlobal: duoGlobalConfigured(config) }
	if (row.data) {
		try {
			const data = JSON.parse(row.data) as DuoData
			if (data.host && data.ik && data.sk) return { kind: "user", data }
		} catch {
			// fall through to globals
		}
	}
	const global = globalDuoData(config)
	if (global) return { kind: "global", data: global }
	return { kind: "disabled", hasGlobal: false }
}

export async function duoKeysForUser(
	db: Db,
	config: Config,
	userUuid: string | null
): Promise<DuoData> {
	let data: DuoData | null = null
	if (userUuid) {
		const status = await getUserDuoData(db, config, userUuid)
		data = status.kind === "disabled" ? null : status.data
	} else {
		data = globalDuoData(config)
	}
	if (!data) err("Can't fetch Duo Keys")
	return data
}

/** Duo Auth API v2 request signing (used to validate credentials on activation). */
export async function duoApiRequest(
	method: string,
	path: string,
	params: string,
	data: DuoData
): Promise<void> {
	const date = new Date().toUTCString().replace("GMT", "+0000")
	const canon = [date, method, data.host, path, params].join("\n")
	const password = createHmac("sha1", data.sk).update(canon).digest("hex")
	const basic = Buffer.from(`${data.ik}:${password}`).toString("base64")

	let res: Response
	try {
		res = await fetch(`https://${data.host}${path}`, {
			method,
			headers: {
				Authorization: `Basic ${basic}`,
				Date: date,
				"User-Agent": "vaultur:Duo/1.0"
			}
		})
	} catch (e) {
		err(`Failed to validate Duo credentials: ${e instanceof Error ? e.message : e}`)
	}
	if (!res.ok) err("Failed to validate Duo credentials")
}

// ---------------------------------------------------------------------------
// Universal Prompt (OIDC) client — https://duo.com/docs/oauthapi
// ---------------------------------------------------------------------------

function callbackUrl(config: Config, clientName: string): string {
	const url = new URL(`${config.domain}/${DUO_REDIRECT_LOCATION}`)
	url.searchParams.set("client", clientName)
	return url.toString()
}

async function clientAssertion(data: DuoData, url: string): Promise<string> {
	const now = Math.floor(Date.now() / 1000)
	return sign(
		{
			iss: data.ik,
			sub: data.ik,
			aud: url,
			exp: now + JWT_VALIDITY_SECS,
			jti: randomAlphanum(STATE_LENGTH),
			iat: now
		},
		data.sk,
		"HS512"
	)
}

/** Duo "required" health check — verifies the integration before redirecting users. */
async function healthCheck(data: DuoData): Promise<void> {
	const url = `https://${data.host}/oauth/v1/health_check`
	const body = new URLSearchParams({
		client_assertion: await clientAssertion(data, url),
		client_id: data.ik
	})

	let json: { stat?: string; message?: string; message_detail?: string }
	try {
		const res = await fetch(url, {
			method: "POST",
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
				"User-Agent": "vaultur:Duo/2.0"
			},
			body
		})
		json = (await res.json()) as typeof json
	} catch (e) {
		err(`Error requesting Duo health check: ${e instanceof Error ? e.message : e}`)
	}
	if (json.stat !== "OK") {
		err(
			`Duo health check FAIL response, msg: ${json.message ?? "unknown"}, detail: ${json.message_detail ?? ""}`
		)
	}
}

/** The OIDC nonce is bound to the authing device: hex(SHA512-256(nonce + deviceIdentifier)). */
function bindNonce(nonce: string, deviceIdentifier: string): string {
	return createHash("sha512-256").update(`${nonce}${deviceIdentifier}`).digest("hex")
}

/**
 * First stage: returns the AuthUrl clients open for MFA
 * (vaultwarden get_duo_auth_url).
 */
export async function getDuoAuthUrl(
	db: Db,
	config: Config,
	userUuid: string,
	email: string,
	clientId: string,
	deviceIdentifier: string
): Promise<string> {
	const data = await duoKeysForUser(db, config, userUuid)
	const redirectUri = callbackUrl(config, clientId)
	await healthCheck(data)

	const state = randomAlphanum(STATE_LENGTH)
	const nonce = randomAlphanum(STATE_LENGTH)

	await db.delete(twofactorDuoCtx).where(eq(twofactorDuoCtx.state, state))
	await db.insert(twofactorDuoCtx).values({
		state,
		userEmail: email,
		nonce,
		exp: Math.floor(Date.now() / 1000) + CTX_VALIDITY_SECS
	})

	const now = Math.floor(Date.now() / 1000)
	const request = await sign(
		{
			response_type: "code",
			scope: "openid",
			exp: now + JWT_VALIDITY_SECS,
			client_id: data.ik,
			redirect_uri: redirectUri,
			state,
			duo_uname: email,
			iss: data.ik,
			aud: `https://${data.host}`,
			nonce: bindNonce(nonce, deviceIdentifier)
		},
		data.sk,
		"HS512"
	)

	const authUrl = new URL(`https://${data.host}/oauth/v1/authorize`)
	authUrl.searchParams.set("response_type", "code")
	authUrl.searchParams.set("client_id", data.ik)
	authUrl.searchParams.set("request", request)
	return authUrl.toString()
}

/**
 * Second stage: exchanges the `<code>|<state>` token supplied by the client
 * for the MFA result (vaultwarden duo_oidc::validate_duo_login).
 */
export async function validateDuoLogin(
	db: Db,
	config: Config,
	userUuid: string,
	email: string,
	twoFactorToken: string,
	clientId: string,
	deviceIdentifier: string
): Promise<void> {
	const split = twoFactorToken.split("|")
	if (split.length !== 2) err("Invalid response length")
	const [code, state] = split as [string, string]

	const data = await duoKeysForUser(db, config, userUuid)

	const ctx = await db.query.twofactorDuoCtx.findFirst({
		where: eq(twofactorDuoCtx.state, state)
	})
	if (ctx) await db.delete(twofactorDuoCtx).where(eq(twofactorDuoCtx.state, ctx.state))
	const now = Math.floor(Date.now() / 1000)
	if (
		!ctx ||
		ctx.exp < now ||
		!constantTimeEqualStr(email, ctx.userEmail) ||
		!constantTimeEqualStr(state, ctx.state)
	) {
		err("Error validating duo authentication")
	}

	const redirectUri = callbackUrl(config, clientId)
	await healthCheck(data)

	if (!code) err("Empty Duo authorization code")
	const tokenUrl = `https://${data.host}/oauth/v1/token`
	const body = new URLSearchParams({
		grant_type: "authorization_code",
		code,
		redirect_uri: redirectUri,
		client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		client_assertion: await clientAssertion(data, tokenUrl)
	})

	let response: { id_token?: string }
	try {
		const res = await fetch(tokenUrl, {
			method: "POST",
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
				"User-Agent": "vaultur:Duo/2.0"
			},
			body
		})
		if (!res.ok) err(`Failure response from Duo: ${res.status}`)
		response = (await res.json()) as typeof response
	} catch (e) {
		if (e instanceof Error && e.message.startsWith("Failure response")) throw e
		err("Error validating duo authentication")
	}
	if (!response.id_token) err("Error validating duo authentication")

	let claims: { iss?: string; aud?: string; nonce?: string; preferred_username?: string }
	try {
		claims = (await verify(response.id_token, data.sk, "HS512")) as typeof claims
	} catch {
		err("Error validating duo authentication")
	}
	const expectedNonce = bindNonce(ctx.nonce, deviceIdentifier)
	if (
		claims.iss !== tokenUrl ||
		claims.aud !== data.ik ||
		!claims.nonce ||
		!constantTimeEqualStr(expectedNonce, claims.nonce) ||
		!claims.preferred_username ||
		!constantTimeEqualStr(email, claims.preferred_username)
	) {
		err("Error validating duo authentication, nonce or username mismatch.")
	}
}

/** Scheduled-job helper: drop expired Duo auth contexts. */
export async function purgeExpiredDuoContexts(db: Db): Promise<void> {
	await db.delete(twofactorDuoCtx).where(lt(twofactorDuoCtx.exp, Math.floor(Date.now() / 1000)))
}
