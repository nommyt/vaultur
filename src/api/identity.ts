import { and, eq } from "drizzle-orm"
import { Hono } from "hono"
import type { Context } from "hono"
import { deleteCookie, getCookie, setCookie } from "hono/cookie"

import { basicClaims, decodeJwt, encodeJwt, issuer } from "../auth/jwt"
import { createAuthTokens, type AuthMethod } from "../auth/tokens"
import { loginAllowed, ssoConfigured, type Config } from "../config"
import { verifyPassword } from "../crypto"
import {
	authRequests,
	devices,
	emergencyAccess,
	invitations,
	nowDb,
	fromDb,
	organizationApiKey,
	ssoUsers,
	users,
	usersOrganizations,
	type Db,
	type User
} from "../db"
import type { AppEnv } from "../env"
import { err, errJson } from "../error"
import { findDeviceByRefreshToken, getOrCreateDevice, touchDevice } from "../services/devices"
import { logUserEvent } from "../services/events"
import { createMailer, mail, type Mailer } from "../services/mail"
import { masterPasswordPolicy } from "../services/policies"
import {
	checkLoginRateLimit,
	checkUserLoginFailureLimit,
	recordUserLoginFailure
} from "../services/ratelimit"
import {
	buildAuthorizeUrl,
	exchangeCode,
	handleOidcCallback,
	redeemSsoAuth,
	sha256Hex
} from "../services/sso"
import { twofactorAuth } from "../services/twofactor"
import { findUserByEmail, newUserShell, passwordFields, touchUser } from "../services/users"
import { DeviceType, EventType, KdfType, MembershipStatus } from "../shared"
import { ci, constantTimeEqualStr, normalizeEmail, randomBytes, uuid } from "../util"

export const identityRoutes = new Hono<AppEnv>()

// ---------------------------------------------------------------------------
// POST /identity/connect/token
// ---------------------------------------------------------------------------

interface ConnectData {
	grantType: string
	refreshToken?: string
	clientId?: string
	clientSecret?: string
	password?: string
	scope?: string
	username?: string
	deviceIdentifier?: string
	deviceName?: string
	deviceType?: string
	devicePushToken?: string
	twoFactorToken?: string
	twoFactorProvider?: number
	twoFactorRemember?: number
	authRequest?: string
	code?: string
	codeVerifier?: string
}

function parseConnectData(form: Record<string, string>): ConnectData {
	const get = (...names: string[]) => {
		for (const n of names) {
			const v = form[n]
			if (v != null && v !== "") return v
		}
		return undefined
	}
	const num = (v: string | undefined) => {
		if (v == null) return undefined
		const n = Number.parseInt(v, 10)
		return Number.isFinite(n) ? n : undefined
	}
	return {
		grantType: get("grant_type", "grantType") ?? "",
		refreshToken: get("refresh_token", "refreshToken"),
		clientId: get("client_id", "clientId"),
		clientSecret: get("client_secret", "clientSecret"),
		password: get("password"),
		scope: get("scope"),
		username: get("username"),
		deviceIdentifier: get("device_identifier", "deviceIdentifier"),
		deviceName: get("device_name", "deviceName"),
		deviceType: get("device_type", "deviceType"),
		devicePushToken: get("device_push_token", "devicePushToken"),
		twoFactorToken: get("two_factor_token", "twoFactorToken"),
		twoFactorProvider: num(get("two_factor_provider", "twoFactorProvider")),
		twoFactorRemember: num(get("two_factor_remember", "twoFactorRemember")),
		authRequest: get("auth_request", "authRequest"),
		code: get("code"),
		codeVerifier: get("code_verifier", "codeVerifier")
	}
}

function checkPresent(data: ConnectData, fields: (keyof ConnectData)[]): void {
	for (const f of fields) {
		if (data[f] == null || data[f] === "") err(`${String(f)} cannot be blank`)
	}
}

identityRoutes.post("/connect/token", async (c) => {
	const body = await c.req.parseBody()
	const form: Record<string, string> = {}
	for (const [k, v] of Object.entries(body)) if (typeof v === "string") form[k] = v
	const data = parseConnectData(form)

	const db = c.get("db")
	const config = c.get("config")
	const ip = c.get("ip")

	switch (data.grantType) {
		case "refresh_token": {
			if (!data.refreshToken) errJson({ error: "invalid_grant" }, "Missing refresh_token")
			return refreshLogin(c, db, config, data)
		}
		case "password": {
			if (ssoConfigured(config) && config.ssoOnly) err("SSO sign-in is required")
			checkPresent(data, [
				"clientId",
				"password",
				"scope",
				"username",
				"deviceIdentifier",
				"deviceName",
				"deviceType"
			])
			return passwordLogin(c, db, config, data, ip)
		}
		case "client_credentials": {
			checkPresent(data, [
				"clientId",
				"clientSecret",
				"scope",
				"deviceIdentifier",
				"deviceName",
				"deviceType"
			])
			return apiKeyLogin(c, db, config, data, ip)
		}
		case "authorization_code": {
			if (!ssoConfigured(config)) err("SSO sign-in is not available")
			checkPresent(data, ["clientId", "code", "deviceIdentifier", "deviceName", "deviceType"])
			return ssoLogin(c, db, config, data, ip)
		}
		default:
			err("Invalid type")
	}
})

type Ctx = Context<AppEnv>

async function refreshLogin(c: Ctx, db: Db, config: Config, data: ConnectData) {
	const device = await findDeviceByRefreshToken(db, data.refreshToken!)
	if (!device) {
		errJson(
			{ error: "invalid_grant" },
			"Unable to refresh login credentials: Invalid refresh token"
		)
	}
	const user = await db.query.users.findFirst({ where: eq(users.uuid, device.userUuid) })
	if (!user || !user.enabled) {
		errJson({ error: "invalid_grant" }, "Unable to refresh login credentials: Invalid user")
	}
	if (!loginAllowed(config, user.email)) {
		errJson({ error: "invalid_grant" }, "Unable to refresh login credentials: Login not allowed")
	}

	const tokens = await createAuthTokens(
		config,
		c.env.JWT_SECRET,
		device,
		user,
		"Password",
		data.clientId
	)
	await touchDevice(db, device)

	return c.json({
		refresh_token: tokens.refreshToken,
		access_token: tokens.accessToken,
		expires_in: tokens.expiresIn,
		token_type: "Bearer",
		scope: tokens.scope
	})
}

async function passwordLogin(c: Ctx, db: Db, config: Config, data: ConnectData, ip: string) {
	if (data.scope !== "api offline_access") err("Scope not supported")

	await checkLoginRateLimit(c.env.VAULTUR_KV, config, ip)

	const username = normalizeEmail(data.username!)
	if (!loginAllowed(config, username)) {
		err(`Username or password is incorrect. Try again`)
	}
	await checkUserLoginFailureLimit(c.env.VAULTUR_KV, config, username)
	const user = await findUserByEmail(db, username)
	if (!user) {
		await recordUserLoginFailure(c.env.VAULTUR_KV, username)
		err(`Username or password is incorrect. Try again`)
	}

	if (!user.enabled) {
		await logUserEvent(
			db,
			c.get("config"),
			EventType.UserFailedLogIn,
			user.uuid,
			Number(data.deviceType ?? 14),
			ip
		)
		err("This user has been disabled")
	}

	if (data.authRequest) {
		// Login with device: password field carries the auth-request access code
		const authRequest = await db.query.authRequests.findFirst({
			where: and(eq(authRequests.uuid, data.authRequest), eq(authRequests.userUuid, user.uuid))
		})
		if (!authRequest) {
			await logUserEvent(
				db,
				c.get("config"),
				EventType.UserFailedLogIn,
				user.uuid,
				Number(data.deviceType ?? 14),
				ip
			)
			err("Auth request not found. Try again.")
		}
		const expired = Date.now() >= fromDb(authRequest.creationDate).getTime() + 5 * 60 * 1000
		const codeOk = constantTimeEqualStr(authRequest.accessCode, data.password!)
		if (!authRequest.approved || expired || authRequest.requestIp !== ip || !codeOk) {
			await logUserEvent(
				db,
				c.get("config"),
				EventType.UserFailedLogIn,
				user.uuid,
				Number(data.deviceType ?? 14),
				ip
			)
			await recordUserLoginFailure(c.env.VAULTUR_KV, username)
			err("Username or access code is incorrect. Try again")
		}
	} else {
		const valid = await verifyPassword(data.password!, {
			hash: user.passwordHash,
			salt: user.salt,
			iterations: user.passwordIterations
		})
		if (!valid) {
			await logUserEvent(
				db,
				c.get("config"),
				EventType.UserFailedLogIn,
				user.uuid,
				Number(data.deviceType ?? 14),
				ip
			)
			await recordUserLoginFailure(c.env.VAULTUR_KV, username)
			err(`Username or password is incorrect. Try again`)
		}
		// Server-side iteration upgrade (vaultwarden kdf_upgrade)
		if (user.passwordIterations < config.passwordIterations) {
			const fields = await passwordFields(data.password!, config.passwordIterations)
			await db.update(users).set(fields).where(eq(users.uuid, user.uuid))
		}
	}

	const mailer = createMailer(c.env.VAULTUR_EMAIL, config)

	// Email-verification enforcement on login
	if (!user.verifiedAt && mailer.enabled && config.signupsVerify) {
		err("Please verify your email before trying again.")
	}

	const { device, isNew } = await getOrCreateDevice(
		db,
		{
			deviceIdentifier: data.deviceIdentifier!,
			deviceName: data.deviceName!,
			deviceType: Number.parseInt(data.deviceType ?? "14", 10) || 14
		},
		user.uuid
	)

	const twofactorToken = await twofactorAuth(
		db,
		mailer,
		config,
		c.env.JWT_SECRET,
		user,
		device,
		{
			twoFactorProvider: data.twoFactorProvider,
			twoFactorToken: data.twoFactorToken,
			twoFactorRemember: data.twoFactorRemember,
			clientVersion: c.req.header("Bitwarden-Client-Version"),
			clientId: data.clientId,
			deviceIdentifier: data.deviceIdentifier
		},
		ip
	)

	if (mailer.enabled && isNew) {
		c.executionCtx.waitUntil(
			mail.newDeviceLoggedIn(
				mailer,
				config,
				user.email,
				device.name,
				String(device.atype),
				ip,
				new Date().toUTCString()
			)
		)
	}

	await touchDevice(db, device)

	const tokens = await createAuthTokens(
		config,
		c.env.JWT_SECRET,
		device,
		user,
		"Password",
		data.clientId
	)
	await logUserEvent(db, c.get("config"), EventType.UserLoggedIn, user.uuid, device.atype, ip)

	return c.json(await authenticatedResponse(db, user, tokens, twofactorToken))
}

/**
 * grant_type=authorization_code — OIDC SSO login (vaultwarden sso_login).
 * The code was minted by the IdP and relayed to the client via
 * /connect/oidc-signin; here it is exchanged (once) and the user is
 * provisioned/linked per the SSO_SIGNUPS_MATCH_EMAIL rules.
 */
async function ssoLogin(c: Ctx, db: Db, config: Config, data: ConnectData, ip: string) {
	if (data.scope !== "api offline_access") err("Scope not supported")
	await checkLoginRateLimit(c.env.VAULTUR_KV, config, ip)
	if (!data.codeVerifier) err("Got no code verifier in OIDC data")

	const { row, authUser } = await exchangeCode(
		db,
		config,
		c.env.VAULTUR_KV,
		data.code!,
		data.codeVerifier
	)
	if (!loginAllowed(config, authUser.email)) err("Login not allowed for this account")

	const deviceType = Number(data.deviceType ?? 14)
	const mailer = createMailer(c.env.VAULTUR_EMAIL, config)

	// Resolve the OIDC identity to a local user
	const link = await db.query.ssoUsers.findFirst({
		where: eq(ssoUsers.identifier, authUser.identifier)
	})
	let user: User | undefined
	let alreadyLinked = false

	if (link) {
		alreadyLinked = true
		user = await db.query.users.findFirst({ where: eq(users.uuid, link.userUuid) })
		if (!user) err("Invalid SSO association")
	} else {
		const byEmail = await findUserByEmail(db, authUser.email)
		if (byEmail) {
			const otherLink = await db.query.ssoUsers.findFirst({
				where: eq(ssoUsers.userUuid, byEmail.uuid)
			})
			if (otherLink) {
				await logUserEvent(
					db,
					c.get("config"),
					EventType.UserFailedLogIn,
					byEmail.uuid,
					deviceType,
					ip
				)
				err("Existing SSO user with same email")
			}
			if (byEmail.privateKey != null && !config.ssoSignupsMatchEmail) {
				await logUserEvent(
					db,
					c.get("config"),
					EventType.UserFailedLogIn,
					byEmail.uuid,
					deviceType,
					ip
				)
				err("Existing non SSO user with same email and association is disabled")
			}
			if (authUser.emailVerified == null && !config.ssoAllowUnknownEmailVerification) {
				err("Email verification status is unknown from the SSO provider")
			}
			if (authUser.emailVerified === false) {
				err("Email is not verified by the SSO provider")
			}
			user = byEmail
		}
	}

	if (!user) {
		// First login of an unknown identity — provision a new account
		if (
			config.signupsDomainsWhitelist.length > 0 &&
			!config.signupsDomainsWhitelist.includes(authUser.email.split("@")[1] ?? "")
		) {
			err("Email domain not allowed")
		}
		if (authUser.emailVerified == null && !config.ssoAllowUnknownEmailVerification) {
			err(
				"Your provider does not send email verification status. You will need to change the server configuration (check `SSO_ALLOW_UNKNOWN_EMAIL_VERIFICATION`) to log in."
			)
		}
		if (authUser.emailVerified === false) {
			err("You need to verify your email with your provider before you can log in")
		}
		const shell = newUserShell(authUser.email, authUser.userName)
		shell.verifiedAt = nowDb()
		await db.insert(users).values(shell)
		user = (await db.query.users.findFirst({ where: eq(users.uuid, shell.uuid!) }))!
	}

	if (!user.enabled) err("This user has been disabled")

	const { device, isNew } = await getOrCreateDevice(
		db,
		{
			deviceIdentifier: data.deviceIdentifier!,
			deviceName: data.deviceName!,
			deviceType: Number.parseInt(data.deviceType ?? "14", 10) || 14
		},
		user.uuid
	)

	// Will 400 with the TwoFactorProviders payload when a second factor is needed;
	// the client then re-submits the same code+verifier with the 2FA token.
	const twofactorToken = await twofactorAuth(
		db,
		mailer,
		config,
		c.env.JWT_SECRET,
		user,
		device,
		{
			twoFactorProvider: data.twoFactorProvider,
			twoFactorToken: data.twoFactorToken,
			twoFactorRemember: data.twoFactorRemember,
			clientVersion: c.req.header("Bitwarden-Client-Version"),
			clientId: data.clientId,
			deviceIdentifier: data.deviceIdentifier
		},
		ip
	)

	// Invited users get a stub account — complete it on first SSO login
	if (user.privateKey == null) {
		const patch: Partial<User> = { verifiedAt: user.verifiedAt ?? nowDb(), updatedAt: nowDb() }
		if (authUser.userName) patch.name = authUser.userName
		await db.update(users).set(patch).where(eq(users.uuid, user.uuid))
	}

	if (user.email !== authUser.email && mailer.enabled) {
		c.executionCtx.waitUntil(mail.ssoEmailDrift(mailer, config, authUser.email))
	}

	if (mailer.enabled && isNew) {
		c.executionCtx.waitUntil(
			mail.newDeviceLoggedIn(
				mailer,
				config,
				user.email,
				device.name,
				String(device.atype),
				ip,
				new Date().toUTCString()
			)
		)
	}

	await redeemSsoAuth(db, row, user.uuid, authUser.identifier, alreadyLinked)
	await touchDevice(db, device)

	const tokens = await createAuthTokens(
		config,
		c.env.JWT_SECRET,
		device,
		user,
		"Sso",
		data.clientId
	)
	await logUserEvent(db, c.get("config"), EventType.UserLoggedIn, user.uuid, device.atype, ip)

	return c.json(await authenticatedResponse(db, user, tokens, twofactorToken))
}

function buildAccountKeys(user: User) {
	return user.privateKey
		? {
				publicKeyEncryptionKeyPair: {
					wrappedPrivateKey: user.privateKey,
					publicKey: user.publicKey,
					Object: "publicKeyEncryptionKeyPair"
				},
				Object: "privateKeys"
			}
		: null
}

function buildUserDecryptionOptions(user: User) {
	const hasMasterPassword = user.passwordHash !== ""
	const masterPasswordUnlock = hasMasterPassword
		? {
				Kdf: {
					KdfType: user.clientKdfType,
					Iterations: user.clientKdfIter,
					Memory: user.clientKdfMemory,
					Parallelism: user.clientKdfParallelism
				},
				MasterKeyEncryptedUserKey: user.akey,
				MasterKeyWrappedUserKey: user.akey,
				Salt: user.email
			}
		: null

	return {
		HasMasterPassword: hasMasterPassword,
		MasterPasswordUnlock: masterPasswordUnlock,
		Object: "userDecryptionOptions"
	}
}

async function authenticatedResponse(
	db: Db,
	user: User,
	tokens: { accessToken: string; refreshToken: string; expiresIn: number; scope: string },
	twofactorToken: string | null
) {
	const policy = await masterPasswordPolicy(db, user.uuid)

	const result: Record<string, unknown> = {
		access_token: tokens.accessToken,
		expires_in: tokens.expiresIn,
		token_type: "Bearer",
		refresh_token: tokens.refreshToken,
		PrivateKey: user.privateKey,
		Kdf: user.clientKdfType,
		KdfIterations: user.clientKdfIter,
		KdfMemory: user.clientKdfMemory,
		KdfParallelism: user.clientKdfParallelism,
		ResetMasterPassword: false,
		ForcePasswordReset: false,
		MasterPasswordPolicy: policy,
		scope: tokens.scope,
		AccountKeys: buildAccountKeys(user),
		UserDecryptionOptions: buildUserDecryptionOptions(user)
	}
	if (user.akey !== "") result.Key = user.akey
	if (twofactorToken) result.TwoFactorToken = twofactorToken
	return result
}

async function apiKeyLogin(c: Ctx, db: Db, config: Config, data: ConnectData, ip: string) {
	await checkLoginRateLimit(c.env.VAULTUR_KV, config, ip)

	if (data.scope === "api.organization") return organizationApiKeyLogin(c, db, config, data, ip)
	if (data.scope !== "api") err("Scope not supported")

	const clientId = data.clientId!
	if (!clientId.startsWith("user.")) err("Malformed client_id")
	const userUuid = clientId.slice("user.".length)
	const user = await db.query.users.findFirst({ where: eq(users.uuid, userUuid) })
	if (!user) err("Invalid client_id")
	if (!user.enabled) err("This user has been disabled (API key login)")
	if (!loginAllowed(config, user.email)) err("Login not allowed for this account (API key login)")
	if (!user.apiKey || !constantTimeEqualStr(user.apiKey, data.clientSecret!)) {
		await logUserEvent(
			db,
			c.get("config"),
			EventType.UserFailedLogIn,
			user.uuid,
			Number(data.deviceType ?? 14),
			ip
		)
		err("Incorrect client_secret")
	}

	const { device, isNew } = await getOrCreateDevice(
		db,
		{
			deviceIdentifier: data.deviceIdentifier!,
			deviceName: data.deviceName!,
			deviceType: Number.parseInt(data.deviceType ?? "14", 10) || 14
		},
		user.uuid
	)

	const mailer = createMailer(c.env.VAULTUR_EMAIL, config)
	if (mailer.enabled && isNew) {
		c.executionCtx.waitUntil(
			mail.newDeviceLoggedIn(
				mailer,
				config,
				user.email,
				device.name,
				String(device.atype),
				ip,
				new Date().toUTCString()
			)
		)
	}

	await touchDevice(db, device)
	const tokens = await createAuthTokens(
		config,
		c.env.JWT_SECRET,
		device,
		user,
		"UserApiKey",
		data.clientId
	)
	await logUserEvent(db, c.get("config"), EventType.UserLoggedIn, user.uuid, device.atype, ip)

	return c.json({
		access_token: tokens.accessToken,
		expires_in: tokens.expiresIn,
		token_type: "Bearer",
		Key: user.akey,
		PrivateKey: user.privateKey,
		Kdf: user.clientKdfType,
		KdfIterations: user.clientKdfIter,
		KdfMemory: user.clientKdfMemory,
		KdfParallelism: user.clientKdfParallelism,
		ResetMasterPassword: false,
		ForcePasswordReset: false,
		scope: tokens.scope,
		AccountKeys: buildAccountKeys(user),
		UserDecryptionOptions: buildUserDecryptionOptions(user)
	})
}

// Organization API-key login (scope api.organization) — used by the directory
// connector to obtain a short-lived token for /public/organization/import.
async function organizationApiKeyLogin(
	c: Ctx,
	db: Db,
	config: Config,
	data: ConnectData,
	ip: string
) {
	const clientId = data.clientId ?? ""
	if (!clientId.startsWith("organization.")) err("Malformed client_id")
	const orgId = clientId.slice("organization.".length)

	const row = await db.query.organizationApiKey.findFirst({
		where: eq(organizationApiKey.orgUuid, orgId)
	})
	if (!row) err("Invalid client_id")
	if (!constantTimeEqualStr(row.apiKey, data.clientSecret ?? "")) err("Incorrect client_secret")

	const accessToken = await encodeJwt(
		c.env.JWT_SECRET,
		basicClaims({
			domain: config.domain,
			kind: "api.organization",
			sub: row.uuid,
			ttlSeconds: 3600,
			extra: { client_id: `organization.${orgId}`, client_sub: orgId, scope: ["api.organization"] }
		})
	)

	return c.json({
		access_token: accessToken,
		expires_in: 3600,
		token_type: "Bearer",
		scope: "api.organization"
	})
}

// ---------------------------------------------------------------------------
// Prelogin & registration
// ---------------------------------------------------------------------------

async function prelogin(c: Context<AppEnv>) {
	const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>
	const email = String(ci(body, "email") ?? "")
	const db = c.get("db")
	const user = email ? await findUserByEmail(db, email) : undefined

	return c.json({
		kdf: user?.clientKdfType ?? KdfType.Pbkdf2,
		kdfIterations: user?.clientKdfIter ?? 600_000,
		kdfMemory: user?.clientKdfMemory ?? null,
		kdfParallelism: user?.clientKdfParallelism ?? null
	})
}
identityRoutes.post("/accounts/prelogin", prelogin)
identityRoutes.post("/accounts/prelogin/password", prelogin)

interface RegisterVerifyClaims {
	sub: string
	name?: string | null
	verified?: boolean
	iss: string
	[k: string]: unknown
}

interface InviteClaims {
	sub: string
	email: string
	member_id?: string
	org_id?: string
	iss: string
	[k: string]: unknown
}

interface EmergencyInviteClaims {
	sub: string
	email: string
	emer_id: string
	iss: string
	[k: string]: unknown
}

identityRoutes.post("/accounts/register/send-verification-email", async (c) => {
	const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>
	const email = normalizeEmail(String(ci(body, "email") ?? ""))
	const name = (ci<string>(body, "name") ?? null) as string | null
	const db = c.get("db")
	const config = c.get("config")
	const mailer = createMailer(c.env.VAULTUR_EMAIL, config)

	const invited = await db.query.invitations.findFirst({ where: eq(invitations.email, email) })
	if (!(isSignupAllowed(config, email) || (!mailer.enabled && invited))) {
		err("Registration not allowed or user already exists")
	}
	if (!loginAllowed(config, email)) err("Registration not allowed or user already exists")

	const shouldSendMail = mailer.enabled && config.signupsVerify
	const token = await encodeJwt(
		c.env.JWT_SECRET,
		basicClaims({
			domain: config.domain,
			kind: "register_verify",
			sub: email,
			ttlSeconds: 30 * 60,
			extra: { name, verified: shouldSendMail }
		})
	)

	if (shouldSendMail) {
		const existing = await findUserByEmail(db, email)
		if (!existing?.privateKey) {
			await mail.registerVerifyEmail(mailer, config, email, token)
		}
		return c.body(null, 204)
	}
	// The iOS app reads this response as raw bytes rather than JSON (see
	// StartRegistrationResponseModel in the official client), so a JSON-quoted
	// string corrupts the token with literal quote characters. Android/browser/web
	// parse it as JSON, so only iOS gets the unquoted form.
	const deviceType = Number.parseInt(c.req.header("Device-Type") ?? "", 10)
	if (deviceType === DeviceType.Ios) return c.text(token)
	return c.json(token)
})

identityRoutes.post("/accounts/register", async (c) => registerHandler(c, false))
identityRoutes.post("/accounts/register/finish", async (c) => registerHandler(c, true))

function isSignupAllowed(config: Config, email: string): boolean {
	if (config.signupsDomainsWhitelist.length > 0) {
		const domain = email.split("@")[1] ?? ""
		return config.signupsDomainsWhitelist.includes(domain.toLowerCase())
	}
	return config.signupsAllowed
}

async function registerHandler(c: Ctx, emailVerification: boolean) {
	const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>
	const db = c.get("db")
	const config = c.get("config")
	const mailer = createMailer(c.env.VAULTUR_EMAIL, config)

	const email = normalizeEmail(String(ci(body, "email") ?? ""))
	if (!email) err("Invalid email address")
	if (!loginAllowed(config, email)) err("Registration not allowed or user already exists")

	let name = (ci<string>(body, "name") ?? null) as string | null
	const keysRaw = (ci<Record<string, unknown>>(body, "keys") ??
		ci<Record<string, unknown>>(body, "userAsymmetricKeys")) as Record<string, unknown> | undefined

	// Newer clients (2026.5+ web/browser) wrap the master-password fields in
	// masterPasswordAuthentication/masterPasswordUnlock instead of sending flat
	// masterPasswordHash/key. Same dual-format pattern as accountUnlockData in
	// accounts.ts's rotateKey.
	const masterPasswordAuthentication = ci<Record<string, unknown>>(
		body,
		"masterPasswordAuthentication"
	)
	const masterPasswordUnlock = ci<Record<string, unknown>>(body, "masterPasswordUnlock")

	const key =
		ci<string>(body, "key") ??
		ci<string>(body, "userSymmetricKey") ??
		ci<string>(masterPasswordUnlock, "masterKeyWrappedUserKey")
	const masterPasswordHash =
		ci<string>(body, "masterPasswordHash") ??
		ci<string>(masterPasswordAuthentication, "masterPasswordAuthenticationHash")
	const masterPasswordHint = (ci<string>(body, "masterPasswordHint") ?? null) as string | null
	const organizationUserId = ci<string>(body, "organizationUserId")
	const emailVerificationToken = ci<string>(body, "emailVerificationToken")
	const orgInviteToken = ci<string>(body, "orgInviteToken") ?? ci<string>(body, "token")
	const acceptEmergencyAccessId = ci<string>(body, "acceptEmergencyAccessId")
	const acceptEmergencyAccessInviteToken = ci<string>(body, "acceptEmergencyAccessInviteToken")

	const kdfNested =
		ci<Record<string, unknown>>(masterPasswordAuthentication, "kdf") ??
		ci<Record<string, unknown>>(masterPasswordUnlock, "kdf")
	const kdfRaw = {
		kdf:
			ci<number>(body, "kdf") ??
			ci<number>(body, "kdfType") ??
			ci<number>(kdfNested, "kdfType") ??
			KdfType.Pbkdf2,
		kdfIterations:
			ci<number>(body, "kdfIterations") ??
			ci<number>(body, "iterations") ??
			ci<number>(kdfNested, "iterations") ??
			600_000,
		kdfMemory:
			ci<number>(body, "kdfMemory") ??
			ci<number>(body, "memory") ??
			ci<number>(kdfNested, "memory") ??
			null,
		kdfParallelism:
			ci<number>(body, "kdfParallelism") ??
			ci<number>(body, "parallelism") ??
			ci<number>(kdfNested, "parallelism") ??
			null
	}

	if (!masterPasswordHash) err("masterPasswordHash cannot be blank")
	if (!key) err("key cannot be blank")

	let emailVerified = false

	if (emailVerification) {
		if (emailVerificationToken && !acceptEmergencyAccessId && !organizationUserId) {
			let claims: RegisterVerifyClaims
			try {
				claims = await decodeJwt<RegisterVerifyClaims>(
					c.env.JWT_SECRET,
					emailVerificationToken,
					issuer(config.domain, "register_verify")
				)
			} catch {
				err("Invalid email verification token")
			}
			if (claims.sub !== email) err("Email verification token does not match email")
			if (claims.name != null) name = claims.name
			emailVerified = Boolean(claims.verified)
		} else if (acceptEmergencyAccessId && acceptEmergencyAccessInviteToken) {
			if (!config.emergencyAccessAllowed) err("Emergency access is not enabled.")
			let claims: EmergencyInviteClaims
			try {
				claims = await decodeJwt<EmergencyInviteClaims>(
					c.env.JWT_SECRET,
					acceptEmergencyAccessInviteToken,
					issuer(config.domain, "emergencyaccessinvite")
				)
			} catch {
				err("Invalid emergency access invite token")
			}
			if (claims.email !== email) err("Claim email does not match email")
			if (claims.emer_id !== acceptEmergencyAccessId) {
				err("Claim emer_id does not match accept_emergency_access_id")
			}
			emailVerified = true
		} else if (organizationUserId && orgInviteToken) {
			let claims: InviteClaims
			try {
				claims = await decodeJwt<InviteClaims>(
					c.env.JWT_SECRET,
					orgInviteToken,
					issuer(config.domain, "invite")
				)
			} catch {
				err("Invalid invite token")
			}
			if (claims.email !== email) err("Claim email does not match email")
			if (claims.member_id !== organizationUserId) {
				err("Claim org_user_id does not match organization_user_id")
			}
			emailVerified = true
		} else {
			err("Registration is missing required parameters")
		}
	}

	if (name && name.length > 50) err("The field Name must be a string with a maximum length of 50.")

	const passwordHint = cleanPasswordHint(masterPasswordHint)
	if (passwordHint && !config.passwordHintsAllow) {
		err("Password hints have been disabled by the administrator. Remove the hint and try again.")
	}

	const existing = await findUserByEmail(db, email)
	let user
	if (existing) {
		if (existing.passwordHash !== "") err("Registration not allowed or user already exists")
		if (orgInviteToken) {
			let claims: InviteClaims
			try {
				claims = await decodeJwt<InviteClaims>(
					c.env.JWT_SECRET,
					orgInviteToken,
					issuer(config.domain, "invite")
				)
			} catch {
				err("Invalid invite token")
			}
			if (claims.email !== email) err("Registration email does not match invite email")
			emailVerified = true
		} else {
			const invited = await takeInvitation(db, email)
			if (invited) {
				await db
					.update(usersOrganizations)
					.set({ status: MembershipStatus.Accepted })
					.where(
						and(
							eq(usersOrganizations.userUuid, existing.uuid),
							eq(usersOrganizations.status, MembershipStatus.Invited)
						)
					)
			} else if (
				!isSignupAllowed(config, email) &&
				!(await hasEmergencyInvite(db, config, email))
			) {
				err("Registration not allowed or user already exists")
			}
		}
		user = existing
	} else {
		const invited = await takeInvitation(db, email)
		if (
			!invited &&
			!isSignupAllowed(config, email) &&
			!(acceptEmergencyAccessId && acceptEmergencyAccessInviteToken)
		) {
			err("Registration not allowed or user already exists")
		}
		const shell = newUserShell(email, name)
		await db.insert(users).values(shell)
		user = (await findUserByEmail(db, email))!
	}

	await takeInvitation(db, email)

	validateKdf(kdfRaw)

	const pw = await passwordFields(masterPasswordHash, config.passwordIterations)
	const update: Record<string, unknown> = {
		...pw,
		akey: key,
		passwordHint,
		securityStamp: uuid(),
		clientKdfType: kdfRaw.kdf,
		clientKdfIter: kdfRaw.kdfIterations,
		clientKdfMemory: kdfRaw.kdfMemory,
		clientKdfParallelism: kdfRaw.kdfParallelism,
		updatedAt: nowDb()
	}
	if (name) update.name = name
	if (keysRaw) {
		update.privateKey = ci<string>(keysRaw, "encryptedPrivateKey")
		update.publicKey = ci<string>(keysRaw, "publicKey")
	}
	if (emailVerified) update.verifiedAt = nowDb()

	await db.update(users).set(update).where(eq(users.uuid, user.uuid))

	if (mailer.enabled) {
		if (config.signupsVerify && !emailVerified) {
			const token = await encodeJwt(
				c.env.JWT_SECRET,
				basicClaims({
					domain: config.domain,
					kind: "verifyemail",
					sub: user.uuid,
					ttlSeconds: 3600 * 24 * 5
				})
			)
			c.executionCtx.waitUntil(mail.welcomeMustVerify(mailer, config, email, user.uuid, token))
			await db.update(users).set({ lastVerifyingAt: nowDb() }).where(eq(users.uuid, user.uuid))
		} else {
			c.executionCtx.waitUntil(mail.welcome(mailer, config, email))
		}
	} else if (config.emergencyAccessAllowed) {
		// Accept any open emergency access invitations addressed to this email
		await db
			.update(emergencyAccess)
			.set({ granteeUuid: user.uuid, email: null, status: 1, updatedAt: nowDb() })
			.where(eq(emergencyAccess.email, email))
	}

	return c.json({ object: "register", captchaBypassToken: "" })
}

function cleanPasswordHint(hint: string | null | undefined): string | null {
	if (hint == null) return null
	const trimmed = hint.trim()
	return trimmed === "" ? null : trimmed
}

function validateKdf(kdf: {
	kdf: number
	kdfIterations: number
	kdfMemory: number | null
	kdfParallelism: number | null
}): void {
	if (kdf.kdf === KdfType.Pbkdf2) {
		if (kdf.kdfIterations < 100_000 || kdf.kdfIterations > 2_000_000) {
			err("PBKDF2 KDF iterations must be between 100000 and 2000000.")
		}
	} else if (kdf.kdf === KdfType.Argon2id) {
		if (kdf.kdfIterations < 1 || kdf.kdfIterations > 10)
			err("Argon2 KDF iterations must be between 1 and 10.")
		if (kdf.kdfMemory == null || kdf.kdfMemory < 15 || kdf.kdfMemory > 1024) {
			err("Argon2 memory must be between 15 MB and 1024 MB.")
		}
		if (kdf.kdfParallelism == null || kdf.kdfParallelism < 1 || kdf.kdfParallelism > 16) {
			err("Argon2 parallelism must be between 1 and 16.")
		}
	} else {
		err("Invalid KDF type.")
	}
}

async function takeInvitation(db: Db, email: string): Promise<boolean> {
	const row = await db.query.invitations.findFirst({ where: eq(invitations.email, email) })
	if (!row) return false
	await db.delete(invitations).where(eq(invitations.email, email))
	return true
}

async function hasEmergencyInvite(db: Db, config: Config, email: string): Promise<boolean> {
	if (!config.emergencyAccessAllowed) return false
	const row = await db.query.emergencyAccess.findFirst({ where: eq(emergencyAccess.email, email) })
	return Boolean(row)
}

// ---------------------------------------------------------------------------
// OIDC SSO (vaultwarden src/api/identity.rs authorize/oidcsignin/prevalidate)
// ---------------------------------------------------------------------------

const SSO_BINDING_COOKIE = "VAULTUR_SSO_BINDING"
const SSO_AUTH_TTL_SECONDS = 10 * 60

// Clients probe this before showing the SSO flow; the token is echoed back on
// /connect/authorize (ssoToken) but not otherwise consumed.
function prevalidateHandler(c: Ctx) {
	const config = c.get("config")
	if (!ssoConfigured(config)) {
		return c.json({ message: "SSO sign-in is not available", object: "error" }, 400)
	}
	return encodeJwt(
		c.env.JWT_SECRET,
		basicClaims({ domain: config.domain, kind: "sso", sub: "vaultur", ttlSeconds: 2 * 60 })
	).then((token) => c.json({ token }))
}
identityRoutes.get("/account/prevalidate", prevalidateHandler)
identityRoutes.get("/sso/prevalidate", prevalidateHandler)

// Client → IdP hop. Persists the in-flight state and PKCE challenge, binds the
// flow to this browser via a hashed cookie, then redirects to the IdP.
identityRoutes.get("/connect/authorize", async (c) => {
	const config = c.get("config")
	if (!ssoConfigured(config)) {
		return c.json({ message: "SSO sign-in is not available", object: "error" }, 400)
	}

	const q = (name: string, alt?: string) =>
		c.req.query(name) ?? (alt ? c.req.query(alt) : undefined)
	const state = q("state")
	const codeChallenge = q("code_challenge", "codeChallenge")
	const method = q("code_challenge_method", "codeChallengeMethod")
	const clientId = q("client_id", "clientId")
	const redirectUri = q("redirect_uri", "redirectUri")
	if (!state || !codeChallenge || !clientId || !redirectUri) err("Missing SSO parameters")
	if (method !== "S256") err("Unsupported code challenge method")

	// Browser-binding token: raw value in a cookie, hash in the DB, checked on the callback
	const bindingToken = Buffer.from(randomBytes(32)).toString("base64url")
	const authUrl = await buildAuthorizeUrl(c.get("db"), config, c.env.VAULTUR_KV, {
		state,
		codeChallenge,
		clientId,
		rawRedirectUri: redirectUri,
		bindingHash: sha256Hex(bindingToken)
	})

	setCookie(c, SSO_BINDING_COOKIE, bindingToken, {
		path: "/identity/connect/",
		maxAge: SSO_AUTH_TTL_SECONDS,
		sameSite: "Lax", // the IdP redirect arrives from a different FQDN
		httpOnly: true,
		secure: new URL(config.domain).protocol === "https:"
	})
	return c.redirect(authUrl, 307)
})

// IdP → client hop. Records the IdP response (code or error) and bounces the
// browser back to the Bitwarden client's own callback.
identityRoutes.get("/connect/oidc-signin", async (c) => {
	const config = c.get("config")
	if (!ssoConfigured(config)) {
		return c.json({ message: "SSO sign-in is not available", object: "error" }, 400)
	}
	const base64State = c.req.query("state")
	if (!base64State) err("state cannot be blank")

	const redirect = await handleOidcCallback(c.get("db"), config, {
		base64State,
		code: c.req.query("code") ?? null,
		error: c.req.query("error") ?? null,
		errorDescription: c.req.query("error_description") ?? null,
		bindingCookie: getCookie(c, SSO_BINDING_COOKIE) ?? null
	})
	deleteCookie(c, SSO_BINDING_COOKIE, { path: "/identity/connect/" })
	return c.redirect(redirect, 307)
})
