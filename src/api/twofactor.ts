import { and, eq } from "drizzle-orm"
import { Hono } from "hono"
import type { Context } from "hono"

import { requireAuth, auth } from "../auth/middleware"
import { webauthnSupported, yubicoConfigured } from "../config"
import { verifyPassword } from "../crypto"
import { devices, nowDb, twofactor, users, type Db, type User } from "../db"
import type { AppEnv } from "../env"
import { err } from "../error"
import { duoApiRequest, getUserDuoData, type DuoData } from "../services/duo"
import { logUserEvent } from "../services/events"
import { createMailer, mail } from "../services/mail"
import {
	findTwoFactors,
	sendEmailLoginToken,
	validateTotpCode,
	type EmailTokenData
} from "../services/twofactor"
import { findUserByEmail } from "../services/users"
import {
	finishWebauthnRegistration,
	getWebauthnRegistrations,
	startWebauthnRegistration,
	type WebauthnRegistration
} from "../services/webauthn"
import { verifyYubikeyOtp, type YubikeyMetadata } from "../services/yubikey"
import { EventType, TwoFactorType } from "../shared"
import { ci, normalizeEmail, randomBytes, randomNumericCode, uuid } from "../util"

/**
 * Two-factor management (/api/two-factor/*), ported from vaultwarden
 * src/api/core/two_factor/{mod,authenticator,email}.rs.
 */
export const twofactorRoutes = new Hono<AppEnv>()

type Ctx = Context<AppEnv>

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

function randomBase32(bytes: number): string {
	const raw = randomBytes(bytes)
	let out = ""
	for (const b of raw) out += BASE32_ALPHABET[b % 32]
	return out
}

async function verifyUserPassword(user: User, passwordHash: string): Promise<boolean> {
	return verifyPassword(passwordHash, {
		hash: user.passwordHash,
		salt: user.salt,
		iterations: user.passwordIterations
	})
}

/** PasswordOrOtp guard (vaultwarden PasswordOrOtpData::validate). */
async function validatePasswordOrOtp(
	c: Ctx,
	user: User,
	body: Record<string, unknown>
): Promise<void> {
	const passwordHash = ci<string>(body, "masterPasswordHash")
	const otp = ci<string>(body, "otp")
	if (passwordHash) {
		if (!(await verifyUserPassword(user, passwordHash))) err("Invalid password")
		return
	}
	if (otp) {
		const stored = await c.env.VAULTUR_KV.get(`protected-action:${user.uuid}`)
		if (!stored || stored !== otp) err("Invalid token")
		await c.env.VAULTUR_KV.delete(`protected-action:${user.uuid}`)
		return
	}
	err("No validation provided")
}

/** Clear remembered-2FA tokens on all the user's devices (vaultwarden TwoFactor save/delete side effect). */
async function clearTwofactorRemember(db: Db, userUuid: string): Promise<void> {
	await db.update(devices).set({ twofactorRemember: null }).where(eq(devices.userUuid, userUuid))
}

/** Ensure the user has a 2FA recovery code once any provider is enabled. */
async function ensureRecoveryCode(db: Db, user: User): Promise<void> {
	if (user.totpRecover) return
	const code = randomBase32(20).toLowerCase()
	await db.update(users).set({ totpRecover: code }).where(eq(users.uuid, user.uuid))
}

// ---------------------------------------------------------------------------
// Public endpoints (credentials in body, no bearer token)
// ---------------------------------------------------------------------------

twofactorRoutes.post("/two-factor/send-email-login", async (c) => {
	const body = (await c.req.json()) as Record<string, unknown>
	const email = normalizeEmail(String(ci(body, "email") ?? ""))
	const passwordHash = ci<string>(body, "masterPasswordHash")
	if (!email || !passwordHash) err("Email and masterPasswordHash are required")

	const db = c.get("db")
	const user = await findUserByEmail(db, email)
	if (!user) err("Username or password is incorrect. Try again.")
	if (!(await verifyUserPassword(user, passwordHash))) {
		err("Username or password is incorrect. Try again.")
	}
	if (!user.enabled) err("This user has been disabled")

	const config = c.get("config")
	const mailer = createMailer(c.env.VAULTUR_EMAIL, config)
	await sendEmailLoginToken(db, mailer, config, user.uuid, c.get("ip"))
	return c.body(null, 200)
})

twofactorRoutes.post("/two-factor/recover", async (c) => {
	const body = (await c.req.json()) as Record<string, unknown>
	const email = normalizeEmail(String(ci(body, "email") ?? ""))
	const passwordHash = ci<string>(body, "masterPasswordHash")
	const recoveryCode = String(ci(body, "recoveryCode") ?? "")
		.replace(/\s/g, "")
		.toLowerCase()
	if (!email || !passwordHash || !recoveryCode) err("Missing required fields")

	const db = c.get("db")
	const user = await findUserByEmail(db, email)
	if (!user || !(await verifyUserPassword(user, passwordHash))) {
		err("Username or password is incorrect. Try again.")
	}
	if (!user.totpRecover || user.totpRecover.toLowerCase() !== recoveryCode) {
		err("Recovery code is incorrect. Try again.")
	}

	await db.delete(twofactor).where(eq(twofactor.userUuid, user.uuid))
	await db
		.update(users)
		.set({ totpRecover: null, updatedAt: nowDb() })
		.where(eq(users.uuid, user.uuid))
	await clearTwofactorRemember(db, user.uuid)
	await logUserEvent(db, c.get("config"), EventType.UserRecovered2fa, user.uuid, 14, c.get("ip"))
	return c.json({})
})

// ---------------------------------------------------------------------------
// Authenticated endpoints
// ---------------------------------------------------------------------------

twofactorRoutes.use("*", requireAuth)

twofactorRoutes.get("/two-factor", async (c) => {
	const { user } = auth(c)
	const rows = await findTwoFactors(c.get("db"), user.uuid)
	const data = rows
		.filter((tf) => tf.enabled)
		.map((tf) => ({ enabled: tf.enabled, type: tf.atype, object: "twoFactorProvider" }))
	return c.json({ data, object: "list", continuationToken: null })
})

// Clients poll this at login; device verification is not supported.
twofactorRoutes.get("/two-factor/get-device-verification-settings", (c) =>
	c.json({
		isDeviceVerificationSectionEnabled: false,
		unknownDeviceVerificationEnabled: false,
		object: "deviceVerificationSettings"
	})
)

twofactorRoutes.post("/two-factor/get-recover", async (c) => {
	const { user } = auth(c)
	const body = (await c.req.json()) as Record<string, unknown>
	await validatePasswordOrOtp(c, user, body)
	return c.json({ code: user.totpRecover, object: "twoFactorRecover" })
})

// --- Authenticator (TOTP) ---

twofactorRoutes.post("/two-factor/get-authenticator", async (c) => {
	const { user } = auth(c)
	const body = (await c.req.json()) as Record<string, unknown>
	await validatePasswordOrOtp(c, user, body)

	const row = await c.get("db").query.twofactor.findFirst({
		where: and(eq(twofactor.userUuid, user.uuid), eq(twofactor.atype, TwoFactorType.Authenticator))
	})
	const enabled = Boolean(row?.enabled)
	return c.json({
		enabled,
		key: enabled && row ? row.data : randomBase32(20),
		object: "twoFactorAuthenticator"
	})
})

async function activateAuthenticator(c: Ctx) {
	const { user } = auth(c)
	const db = c.get("db")
	const body = (await c.req.json()) as Record<string, unknown>
	await validatePasswordOrOtp(c, user, body)

	const key = String(ci(body, "key") ?? "")
	const token = String(ci(body, "token") ?? "")
	if (!/^[a-z0-9]{10,}$/i.test(key.replace(/=+$/, ""))) err("Invalid key length")

	// Validate the code first (no row yet, so replay protection is a no-op),
	// then persist the new secret — vaultwarden only saves on success.
	await validateTotpCode(db, user.uuid, token, key.toUpperCase(), c.get("ip"))

	await db
		.delete(twofactor)
		.where(and(eq(twofactor.userUuid, user.uuid), eq(twofactor.atype, TwoFactorType.Authenticator)))
	await db.insert(twofactor).values({
		uuid: uuid(),
		userUuid: user.uuid,
		atype: TwoFactorType.Authenticator,
		enabled: true,
		data: key.toUpperCase(),
		lastUsed: Math.floor(Date.now() / 1000 / 30)
	})

	await ensureRecoveryCode(db, user)
	await clearTwofactorRemember(db, user.uuid)
	const { device } = auth(c)
	await logUserEvent(
		db,
		c.get("config"),
		EventType.UserUpdated2fa,
		user.uuid,
		device.atype,
		c.get("ip")
	)

	return c.json({ enabled: true, key: key.toUpperCase(), object: "twoFactorAuthenticator" })
}
twofactorRoutes.post("/two-factor/authenticator", activateAuthenticator)
twofactorRoutes.put("/two-factor/authenticator", activateAuthenticator)

twofactorRoutes.delete("/two-factor/authenticator", async (c) => {
	const { user, device } = auth(c)
	const db = c.get("db")
	const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>
	await validatePasswordOrOtp(c, user, body)
	await db
		.delete(twofactor)
		.where(and(eq(twofactor.userUuid, user.uuid), eq(twofactor.atype, TwoFactorType.Authenticator)))
	await clearTwofactorRemember(db, user.uuid)
	await logUserEvent(
		db,
		c.get("config"),
		EventType.UserDisabled2fa,
		user.uuid,
		device.atype,
		c.get("ip")
	)
	return c.json({ enabled: false, type: TwoFactorType.Authenticator, object: "twoFactorProvider" })
})

// --- Generic disable ---

async function disableTwofactor(c: Ctx) {
	const { user, device } = auth(c)
	const db = c.get("db")
	const body = (await c.req.json()) as Record<string, unknown>
	await validatePasswordOrOtp(c, user, body)
	const type = Number(ci(body, "type") ?? -1)

	await db
		.delete(twofactor)
		.where(and(eq(twofactor.userUuid, user.uuid), eq(twofactor.atype, type)))
	await clearTwofactorRemember(db, user.uuid)
	await logUserEvent(
		db,
		c.get("config"),
		EventType.UserDisabled2fa,
		user.uuid,
		device.atype,
		c.get("ip")
	)

	// When the last provider is removed, drop the recovery code (vaultwarden behavior)
	const remaining = await findTwoFactors(db, user.uuid)
	if (remaining.filter((tf) => tf.atype < 1000).length === 0) {
		await db.update(users).set({ totpRecover: null }).where(eq(users.uuid, user.uuid))
	}

	return c.json({ enabled: false, type, object: "twoFactorProvider" })
}
twofactorRoutes.post("/two-factor/disable", disableTwofactor)
twofactorRoutes.put("/two-factor/disable", disableTwofactor)

// --- Email 2FA ---

twofactorRoutes.post("/two-factor/get-email", async (c) => {
	const { user } = auth(c)
	const body = (await c.req.json()) as Record<string, unknown>
	await validatePasswordOrOtp(c, user, body)

	const row = await c.get("db").query.twofactor.findFirst({
		where: and(eq(twofactor.userUuid, user.uuid), eq(twofactor.atype, TwoFactorType.Email))
	})
	let email: string | null = null
	if (row) {
		email = (JSON.parse(row.data) as EmailTokenData).email
	}
	return c.json({
		email: email ?? user.email,
		enabled: Boolean(row?.enabled),
		object: "twoFactorEmail"
	})
})

// Setup: store a pending (disabled) email 2FA row and send the code
twofactorRoutes.post("/two-factor/send-email", async (c) => {
	const { user } = auth(c)
	const db = c.get("db")
	const config = c.get("config")
	const body = (await c.req.json()) as Record<string, unknown>
	await validatePasswordOrOtp(c, user, body)

	const email = normalizeEmail(String(ci(body, "email") ?? ""))
	if (!email) err("Email is required")

	const mailer = createMailer(c.env.VAULTUR_EMAIL, config)
	if (!mailer.enabled) err("Email is disabled for this server. Two-factor email cannot be enabled.")

	const token = randomNumericCode(6)
	const data: EmailTokenData = { email, last_token: token, token_sent: nowDb(), attempts: 0 }

	await db
		.delete(twofactor)
		.where(and(eq(twofactor.userUuid, user.uuid), eq(twofactor.atype, TwoFactorType.Email)))
	await db.insert(twofactor).values({
		uuid: uuid(),
		userUuid: user.uuid,
		atype: TwoFactorType.Email,
		enabled: false,
		data: JSON.stringify(data),
		lastUsed: 0
	})

	await mail.twofactorEmail(mailer, config, email, token, c.get("ip"))
	return c.body(null, 200)
})

// Verify the emailed code → enable
twofactorRoutes.put("/two-factor/email", async (c) => {
	const { user, device } = auth(c)
	const db = c.get("db")
	const body = (await c.req.json()) as Record<string, unknown>
	await validatePasswordOrOtp(c, user, body)

	const email = normalizeEmail(String(ci(body, "email") ?? ""))
	const token = String(ci(body, "token") ?? "")

	const row = await db.query.twofactor.findFirst({
		where: and(eq(twofactor.userUuid, user.uuid), eq(twofactor.atype, TwoFactorType.Email))
	})
	if (!row) err("Two factor email is not registered")

	const data = JSON.parse(row.data) as EmailTokenData
	if (!data.last_token || data.last_token !== token || data.email !== email) {
		err("Token is invalid")
	}

	data.last_token = null
	data.attempts = 0
	await db
		.update(twofactor)
		.set({ enabled: true, data: JSON.stringify(data) })
		.where(eq(twofactor.uuid, row.uuid))

	await ensureRecoveryCode(db, user)
	await clearTwofactorRemember(db, user.uuid)
	await logUserEvent(
		db,
		c.get("config"),
		EventType.UserUpdated2fa,
		user.uuid,
		device.atype,
		c.get("ip")
	)

	return c.json({ email: data.email, enabled: true, object: "twoFactorEmail" })
})

// --- WebAuthn (vaultwarden two_factor/webauthn.rs) ---

function webauthnRegistrationJson(r: WebauthnRegistration) {
	return { id: r.id, name: r.name, migrated: r.migrated }
}

twofactorRoutes.post("/two-factor/get-webauthn", async (c) => {
	if (!webauthnSupported(c.get("config"))) {
		err("Configured `DOMAIN` is not compatible with Webauthn")
	}
	const { user } = auth(c)
	const body = (await c.req.json()) as Record<string, unknown>
	await validatePasswordOrOtp(c, user, body)

	const { enabled, registrations } = await getWebauthnRegistrations(c.get("db"), user.uuid)
	return c.json({
		enabled,
		keys: registrations.map(webauthnRegistrationJson),
		object: "twoFactorWebAuthn"
	})
})

twofactorRoutes.post("/two-factor/get-webauthn-challenge", async (c) => {
	if (!webauthnSupported(c.get("config"))) {
		err("Configured `DOMAIN` is not compatible with Webauthn")
	}
	const { user } = auth(c)
	const body = (await c.req.json()) as Record<string, unknown>
	await validatePasswordOrOtp(c, user, body)

	const options = await startWebauthnRegistration(c.get("db"), c.get("config"), user)
	return c.json(options)
})

async function activateWebauthn(c: Ctx) {
	const { user, device } = auth(c)
	const db = c.get("db")
	const body = (await c.req.json()) as Record<string, unknown>
	await validatePasswordOrOtp(c, user, body)

	const entryId = Number(ci(body, "id") ?? 0)
	const name = String(ci(body, "name") ?? "")
	const deviceResponse = ci<Record<string, unknown>>(body, "deviceResponse")
	if (!deviceResponse) err("deviceResponse cannot be blank")

	const registrations = await finishWebauthnRegistration(
		db,
		c.get("config"),
		user.uuid,
		entryId,
		name,
		deviceResponse
	)

	await ensureRecoveryCode(db, user)
	await clearTwofactorRemember(db, user.uuid)
	await logUserEvent(
		db,
		c.get("config"),
		EventType.UserUpdated2fa,
		user.uuid,
		device.atype,
		c.get("ip")
	)

	return c.json({
		enabled: true,
		keys: registrations.map(webauthnRegistrationJson),
		object: "twoFactorU2f"
	})
}
twofactorRoutes.post("/two-factor/webauthn", activateWebauthn)
twofactorRoutes.put("/two-factor/webauthn", activateWebauthn)

twofactorRoutes.delete("/two-factor/webauthn", async (c) => {
	const { user, device } = auth(c)
	const db = c.get("db")
	const body = (await c.req.json()) as Record<string, unknown>
	const passwordHash = String(ci(body, "masterPasswordHash") ?? "")
	if (!(await verifyUserPassword(user, passwordHash))) err("Invalid password")

	const entryId = Number(ci(body, "id") ?? 0)
	const row = await db.query.twofactor.findFirst({
		where: and(eq(twofactor.userUuid, user.uuid), eq(twofactor.atype, TwoFactorType.Webauthn))
	})
	if (!row) err("Webauthn data not found!")

	const registrations = JSON.parse(row.data) as WebauthnRegistration[]
	const idx = registrations.findIndex((r) => r.id === entryId)
	if (idx < 0) err("Webauthn entry not found")
	registrations.splice(idx, 1)

	await db
		.update(twofactor)
		.set({ data: JSON.stringify(registrations) })
		.where(eq(twofactor.uuid, row.uuid))
	await logUserEvent(
		db,
		c.get("config"),
		EventType.UserDisabled2fa,
		user.uuid,
		device.atype,
		c.get("ip")
	)

	return c.json({
		enabled: true,
		keys: registrations.map(webauthnRegistrationJson),
		object: "twoFactorU2f"
	})
})

// --- YubiKey OTP (vaultwarden two_factor/yubikey.rs) ---

function yubikeyResponseJson(metadata: YubikeyMetadata) {
	const out: Record<string, unknown> = {
		enabled: true,
		nfc: metadata.nfc,
		object: "twoFactorU2f"
	}
	metadata.keys.forEach((key, i) => {
		out[`Key${i + 1}`] = key
	})
	return out
}

twofactorRoutes.post("/two-factor/get-yubikey", async (c) => {
	const config = c.get("config")
	if (!yubicoConfigured(config)) {
		err(
			"`YUBICO_CLIENT_ID` or `YUBICO_SECRET_KEY` environment variable is not set. Yubikey OTP Disabled"
		)
	}
	const { user } = auth(c)
	const body = (await c.req.json()) as Record<string, unknown>
	await validatePasswordOrOtp(c, user, body)

	const row = await c.get("db").query.twofactor.findFirst({
		where: and(eq(twofactor.userUuid, user.uuid), eq(twofactor.atype, TwoFactorType.YubiKey))
	})
	if (!row) return c.json({ enabled: false, object: "twoFactorU2f" })
	return c.json(yubikeyResponseJson(JSON.parse(row.data) as YubikeyMetadata))
})

async function activateYubikey(c: Ctx) {
	const { user, device } = auth(c)
	const db = c.get("db")
	const config = c.get("config")
	const body = (await c.req.json()) as Record<string, unknown>
	await validatePasswordOrOtp(c, user, body)

	const keys = [1, 2, 3, 4, 5]
		.map((i) => ci<string>(body, `key${i}`))
		.filter((k): k is string => Boolean(k))

	if (keys.length === 0) {
		await db
			.delete(twofactor)
			.where(and(eq(twofactor.userUuid, user.uuid), eq(twofactor.atype, TwoFactorType.YubiKey)))
		return c.json({ enabled: false, object: "twoFactorU2f" })
	}

	// Full-length values are fresh OTPs — verify them against YubiCloud.
	// 12-char values are already-registered key ids being re-submitted.
	for (const key of keys) {
		if (key.length === 12) continue
		await verifyYubikeyOtp(config, key)
	}

	const metadata: YubikeyMetadata = {
		keys: keys.map((k) => k.slice(0, 12)),
		nfc: Boolean(ci(body, "nfc"))
	}

	await db
		.delete(twofactor)
		.where(and(eq(twofactor.userUuid, user.uuid), eq(twofactor.atype, TwoFactorType.YubiKey)))
	await db.insert(twofactor).values({
		uuid: uuid(),
		userUuid: user.uuid,
		atype: TwoFactorType.YubiKey,
		enabled: true,
		data: JSON.stringify(metadata),
		lastUsed: 0
	})

	await ensureRecoveryCode(db, user)
	await clearTwofactorRemember(db, user.uuid)
	await logUserEvent(
		db,
		c.get("config"),
		EventType.UserUpdated2fa,
		user.uuid,
		device.atype,
		c.get("ip")
	)

	return c.json(yubikeyResponseJson(metadata))
}
twofactorRoutes.post("/two-factor/yubikey", activateYubikey)
twofactorRoutes.put("/two-factor/yubikey", activateYubikey)

// --- Duo (vaultwarden two_factor/duo.rs — Universal Prompt only) ---

const DUO_SECRET_PLACEHOLDER = "<global_secret>"
const DUO_DISABLED_PLACEHOLDER = "<To use the global Duo keys, please leave these fields untouched>"

function obscureDuo(data: DuoData): DuoData {
	const mask = (s: string) => s.slice(0, 4) + "************"
	return { host: mask(data.host), ik: mask(data.ik), sk: mask(data.sk) }
}

twofactorRoutes.post("/two-factor/get-duo", async (c) => {
	const { user } = auth(c)
	const body = (await c.req.json()) as Record<string, unknown>
	await validatePasswordOrOtp(c, user, body)

	const status = await getUserDuoData(c.get("db"), c.get("config"), user.uuid)
	let enabled: boolean
	let data: DuoData | null
	if (status.kind === "global") {
		enabled = true
		data = { host: DUO_SECRET_PLACEHOLDER, ik: DUO_SECRET_PLACEHOLDER, sk: DUO_SECRET_PLACEHOLDER }
	} else if (status.kind === "user") {
		enabled = true
		data = obscureDuo(status.data)
	} else {
		enabled = false
		data = status.hasGlobal
			? {
					host: DUO_DISABLED_PLACEHOLDER,
					ik: DUO_DISABLED_PLACEHOLDER,
					sk: DUO_DISABLED_PLACEHOLDER
				}
			: null
	}

	return c.json({
		enabled,
		host: data?.host ?? null,
		clientSecret: data?.sk ?? null,
		clientId: data?.ik ?? null,
		object: "twoFactorDuo"
	})
})

async function activateDuo(c: Ctx) {
	const { user, device } = auth(c)
	const db = c.get("db")
	const body = (await c.req.json()) as Record<string, unknown>
	await validatePasswordOrOtp(c, user, body)

	const emptyOrDefault = (s: string) => s.trim() === "" || s === DUO_DISABLED_PLACEHOLDER
	const host = String(ci(body, "host") ?? "")
	const clientId = String(ci(body, "clientId") ?? "")
	const clientSecret = String(ci(body, "clientSecret") ?? "")
	const useCustom =
		!emptyOrDefault(host) && !emptyOrDefault(clientId) && !emptyOrDefault(clientSecret)

	let responseData: DuoData
	let dataStr: string
	if (useCustom) {
		const data: DuoData = { host, ik: clientId, sk: clientSecret }
		await duoApiRequest("GET", "/auth/v2/check", "", data)
		responseData = obscureDuo(data)
		dataStr = JSON.stringify(data)
	} else {
		responseData = {
			host: DUO_SECRET_PLACEHOLDER,
			ik: DUO_SECRET_PLACEHOLDER,
			sk: DUO_SECRET_PLACEHOLDER
		}
		dataStr = ""
	}

	await db
		.delete(twofactor)
		.where(and(eq(twofactor.userUuid, user.uuid), eq(twofactor.atype, TwoFactorType.Duo)))
	await db.insert(twofactor).values({
		uuid: uuid(),
		userUuid: user.uuid,
		atype: TwoFactorType.Duo,
		enabled: true,
		data: dataStr,
		lastUsed: 0
	})

	await ensureRecoveryCode(db, user)
	await clearTwofactorRemember(db, user.uuid)
	await logUserEvent(
		db,
		c.get("config"),
		EventType.UserUpdated2fa,
		user.uuid,
		device.atype,
		c.get("ip")
	)

	return c.json({
		enabled: true,
		host: responseData.host,
		clientSecret: responseData.sk,
		clientId: responseData.ik,
		object: "twoFactorDuo"
	})
}
twofactorRoutes.post("/two-factor/duo", activateDuo)
twofactorRoutes.put("/two-factor/duo", activateDuo)
