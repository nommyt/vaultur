import { createHash } from "node:crypto"

import { eq, lt } from "drizzle-orm"
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose"

import type { Config } from "../config"
import { nowDb, ssoAuth, ssoUsers, toDb, type Db, type SsoAuthRow } from "../db"
import { err } from "../error"
import { randomAlphanum } from "../util"

/**
 * OIDC single sign-on, ported from vaultwarden src/{sso,sso_client}.rs.
 *
 * vaultwarden delegates OIDC to the openidconnect crate; here discovery and
 * the code exchange are plain fetch, with id_token signatures verified via
 * jose's remote JWKS (WebCrypto). The Bitwarden-client-facing contract is
 * identical: the client's PKCE pair is forwarded to the IdP (SSO_PKCE=true),
 * the IdP authorization code is relayed to the client, and the client hands
 * it back through `grant_type=authorization_code` on /identity/connect/token.
 *
 * Session lifetimes: vaultwarden can tie Bitwarden session validity to the
 * IdP's tokens (SSO_AUTH_ONLY_NOT_SESSION=false). Vaultur always behaves like
 * SSO_AUTH_ONLY_NOT_SESSION=true — the IdP authenticates the login, then
 * vaultur issues its own standard access/refresh tokens.
 */

export const SSO_AUTH_EXPIRATION_MS = 10 * 60 * 1000
const DISCOVERY_CACHE_TTL_SECONDS = 3600
const STATE_MAX_LENGTH = 512

export interface OidcMetadata {
	issuer: string
	authorization_endpoint: string
	token_endpoint: string
	userinfo_endpoint?: string
	jwks_uri: string
}

export interface SsoAuthenticatedUser {
	identifier: string // `${issuer}/${subject}`
	email: string
	emailVerified: boolean | null
	userName: string | null
}

export function ssoRedirectUri(config: Config): string {
	return `${config.domain}/identity/connect/oidc-signin`
}

export function sha256Hex(value: string): string {
	return createHash("sha256").update(value).digest("hex")
}

// ---------------------------------------------------------------------------
// Provider discovery (KV-cached) and JWKS
// ---------------------------------------------------------------------------

export async function discoverOidc(config: Config, kv: KVNamespace): Promise<OidcMetadata> {
	const cacheKey = `sso:discovery:${config.ssoAuthority}`
	const cached = await kv.get<OidcMetadata>(cacheKey, "json")
	if (cached) return cached

	let metadata: OidcMetadata
	try {
		const res = await fetch(`${config.ssoAuthority}/.well-known/openid-configuration`, {
			headers: { Accept: "application/json" }
		})
		if (!res.ok) err(`Failed to discover OpenID provider: HTTP ${res.status}`)
		metadata = (await res.json()) as OidcMetadata
	} catch (e) {
		if (e instanceof Error && e.message.startsWith("Failed to discover")) throw e
		err(`Failed to discover OpenID provider: ${e instanceof Error ? e.message : e}`)
	}
	if (!metadata.authorization_endpoint || !metadata.token_endpoint || !metadata.jwks_uri) {
		err("OpenID provider metadata is missing required endpoints")
	}

	await kv.put(cacheKey, JSON.stringify(metadata), { expirationTtl: DISCOVERY_CACHE_TTL_SECONDS })
	return metadata
}

// Remote JWKS handles are cached per isolate (jose caches fetched keys internally).
const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>()

function jwksFor(jwksUri: string): ReturnType<typeof createRemoteJWKSet> {
	let jwks = jwksCache.get(jwksUri)
	if (!jwks) {
		jwks = createRemoteJWKSet(new URL(jwksUri))
		jwksCache.set(jwksUri, jwks)
	}
	return jwks
}

// ---------------------------------------------------------------------------
// Authorize redirect (client → vaultur → IdP)
// ---------------------------------------------------------------------------

/** Maps the Bitwarden client id to its fixed SSO callback (bitwarden/server ApiClient.cs). */
export function clientRedirectUri(
	config: Config,
	clientId: string,
	rawRedirectUri: string
): string {
	switch (clientId) {
		case "web":
		case "browser":
			return `${config.domain}/sso-connector.html`
		case "desktop":
		case "mobile":
			return "bitwarden://sso-callback"
		case "cli": {
			const match = /^http:\/\/localhost:(\d{4})$/.exec(rawRedirectUri)
			if (!match) err("Failed to extract port number")
			return `http://localhost:${match[1]}`
		}
		default:
			err(`Unsupported client ${clientId}`)
	}
}

export interface AuthorizeInput {
	state: string
	codeChallenge: string
	clientId: string
	rawRedirectUri: string
	bindingHash: string | null
}

/** Saves the in-flight auth row and returns the IdP authorization URL. */
export async function buildAuthorizeUrl(
	db: Db,
	config: Config,
	kv: KVNamespace,
	input: AuthorizeInput
): Promise<string> {
	if (!input.state || input.state.length > STATE_MAX_LENGTH) err("Invalid state")
	const metadata = await discoverOidc(config, kv)
	const redirectUri = clientRedirectUri(config, input.clientId, input.rawRedirectUri)
	const nonce = randomAlphanum(64)

	await db.delete(ssoAuth).where(eq(ssoAuth.state, input.state))
	await db.insert(ssoAuth).values({
		state: input.state,
		clientChallenge: input.codeChallenge,
		nonce,
		redirectUri,
		bindingHash: input.bindingHash,
		createdAt: nowDb(),
		updatedAt: nowDb()
	})

	const scopes = new Set(["openid", ...config.ssoScopes.split(/\s+/).filter(Boolean)])
	const url = new URL(metadata.authorization_endpoint)
	url.searchParams.set("response_type", "code")
	url.searchParams.set("client_id", config.ssoClientId)
	url.searchParams.set("redirect_uri", ssoRedirectUri(config))
	url.searchParams.set("scope", [...scopes].join(" "))
	// base64 so org identifiers and other client payloads survive every IdP
	url.searchParams.set("state", Buffer.from(input.state).toString("base64"))
	url.searchParams.set("nonce", nonce)
	if (config.ssoPkce) {
		url.searchParams.set("code_challenge", input.codeChallenge)
		url.searchParams.set("code_challenge_method", "S256")
	}
	return url.toString()
}

// ---------------------------------------------------------------------------
// IdP callback (IdP → vaultur → client)
// ---------------------------------------------------------------------------

export function decodeState(base64State: string): string {
	try {
		const state = Buffer.from(base64State, "base64").toString("utf8")
		if (!state) err(`Failed to decode ${base64State} using base64`)
		return state
	} catch {
		err(`Failed to decode ${base64State} using base64`)
	}
}

export interface CallbackInput {
	base64State: string
	code: string | null
	error: string | null
	errorDescription: string | null
	bindingCookie: string | null
}

/** Stores the IdP response on the auth row and returns the client redirect URL. */
export async function handleOidcCallback(
	db: Db,
	config: Config,
	input: CallbackInput
): Promise<string> {
	const state = decodeState(input.base64State)
	const row = await db.query.ssoAuth.findFirst({ where: eq(ssoAuth.state, state) })
	if (!row) err(`Cannot retrieve sso_auth for ${state}`)

	// The binding cookie was set on /connect/authorize and must come from the
	// same browser that initiated the flow.
	const providedHash = input.bindingCookie ? sha256Hex(input.bindingCookie) : null
	if (row.bindingHash && (!providedHash || providedHash !== row.bindingHash)) {
		err(`SSO session binding mismatch for ${state}`)
	}

	await db
		.update(ssoAuth)
		.set({
			codeResponse: input.code,
			codeResponseError: input.error
				? JSON.stringify({ error: input.error, error_description: input.errorDescription })
				: null,
			updatedAt: nowDb()
		})
		.where(eq(ssoAuth.state, state))

	const url = new URL(row.redirectUri)
	url.searchParams.append("code", input.code ?? "")
	url.searchParams.append("state", state)
	// iss and scope are needed for the redirect to work on iOS
	url.searchParams.append("scope", "api offline_access")
	url.searchParams.append("iss", config.domain)
	return url.toString()
}

// ---------------------------------------------------------------------------
// Code exchange (client → vaultur → IdP token endpoint)
// ---------------------------------------------------------------------------

function s256Challenge(verifier: string): string {
	return createHash("sha256").update(verifier).digest("base64url")
}

export async function exchangeCode(
	db: Db,
	config: Config,
	kv: KVNamespace,
	code: string,
	codeVerifier: string
): Promise<{ row: SsoAuthRow; authUser: SsoAuthenticatedUser }> {
	const oldest = toDb(new Date(Date.now() - SSO_AUTH_EXPIRATION_MS))
	const row = await db.query.ssoAuth.findFirst({ where: eq(ssoAuth.codeResponse, code) })
	if (!row || row.createdAt < oldest) err("Invalid code cannot retrieve sso auth")

	// Second call for the same login (e.g. after the 2FA prompt): the code has
	// already been exchanged, reuse the authenticated result.
	if (row.authResponse) {
		return { row, authUser: JSON.parse(row.authResponse) as SsoAuthenticatedUser }
	}

	if (row.codeResponseError) {
		const detail = JSON.parse(row.codeResponseError) as {
			error: string
			error_description?: string
		}
		await db.delete(ssoAuth).where(eq(ssoAuth.state, row.state))
		err(`SSO authorization failed: ${detail.error}, ${detail.error_description ?? ""}`)
	}

	const metadata = await discoverOidc(config, kv)

	if (!config.ssoPkce && s256Challenge(codeVerifier) !== row.clientChallenge) {
		err("PKCE client challenge failed")
	}

	const body = new URLSearchParams({
		grant_type: "authorization_code",
		code,
		redirect_uri: ssoRedirectUri(config),
		client_id: config.ssoClientId,
		client_secret: config.ssoClientSecret
	})
	if (config.ssoPkce) body.set("code_verifier", codeVerifier)

	let tokenResponse: {
		id_token?: string
		access_token?: string
		refresh_token?: string
		expires_in?: number
	}
	try {
		const res = await fetch(metadata.token_endpoint, {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
			body
		})
		if (!res.ok) err(`Failed to contact token endpoint: HTTP ${res.status}`)
		tokenResponse = (await res.json()) as typeof tokenResponse
	} catch (e) {
		if (e instanceof Error && e.message.startsWith("Failed to contact")) throw e
		err(`Failed to contact token endpoint: ${e instanceof Error ? e.message : e}`)
	}
	if (!tokenResponse.id_token || !tokenResponse.access_token) {
		err("Token response did not contain an id_token")
	}

	let claims: JWTPayload & {
		nonce?: string
		email?: string
		email_verified?: boolean
		preferred_username?: string
	}
	try {
		const verified = await jwtVerify(tokenResponse.id_token, jwksFor(metadata.jwks_uri), {
			issuer: metadata.issuer,
			audience: config.ssoClientId
		})
		claims = verified.payload
	} catch (e) {
		jwksCache.delete(metadata.jwks_uri)
		err(`Could not read id_token claims, ${e instanceof Error ? e.message : e}`)
	}
	if (claims.nonce !== row.nonce) err("Could not read id_token claims, nonce mismatch")

	// userinfo fills in anything the id_token omits (vaultwarden always calls it)
	let userInfo: { email?: string; email_verified?: boolean; preferred_username?: string } = {}
	if (metadata.userinfo_endpoint) {
		try {
			const res = await fetch(metadata.userinfo_endpoint, {
				headers: {
					Authorization: `Bearer ${tokenResponse.access_token}`,
					Accept: "application/json"
				}
			})
			if (!res.ok) err(`Request to user_info endpoint failed: HTTP ${res.status}`)
			userInfo = (await res.json()) as typeof userInfo
		} catch (e) {
			if (e instanceof Error && e.message.startsWith("Request to user_info")) throw e
			err(`Request to user_info endpoint failed: ${e instanceof Error ? e.message : e}`)
		}
	}

	const email = (claims.email ?? userInfo.email)?.toLowerCase()
	if (!email) err("Neither id token nor userinfo contained an email")
	const emailVerified = claims.email_verified ?? userInfo.email_verified ?? null
	const userName = claims.preferred_username ?? userInfo.preferred_username ?? null

	const authUser: SsoAuthenticatedUser = {
		identifier: `${claims.iss}/${claims.sub}`,
		email,
		emailVerified,
		userName
	}

	await db
		.update(ssoAuth)
		.set({ authResponse: JSON.stringify(authUser), updatedAt: nowDb() })
		.where(eq(ssoAuth.state, row.state))

	return { row, authUser }
}

/** After the login fully succeeds: burn the auth row and persist the SSO link. */
export async function redeemSsoAuth(
	db: Db,
	row: SsoAuthRow,
	userUuid: string,
	identifier: string,
	alreadyLinked: boolean
): Promise<void> {
	await db.delete(ssoAuth).where(eq(ssoAuth.state, row.state))
	if (!alreadyLinked) {
		await db.insert(ssoUsers).values({ userUuid, identifier }).onConflictDoNothing()
	}
}

/** Scheduled-job helper: drop abandoned in-flight SSO authentications. */
export async function purgeExpiredSsoAuth(db: Db): Promise<void> {
	const oldest = toDb(new Date(Date.now() - SSO_AUTH_EXPIRATION_MS))
	await db.delete(ssoAuth).where(lt(ssoAuth.createdAt, oldest))
}
