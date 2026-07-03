import {
	generateAuthenticationOptions,
	generateRegistrationOptions,
	verifyAuthenticationResponse,
	verifyRegistrationResponse
} from "@simplewebauthn/server"
import type {
	AuthenticationResponseJSON,
	PublicKeyCredentialCreationOptionsJSON,
	PublicKeyCredentialRequestOptionsJSON,
	RegistrationResponseJSON
} from "@simplewebauthn/server"
import { and, eq } from "drizzle-orm"

import type { Config } from "../config"
import { twofactor, type Db } from "../db"
import { err } from "../error"
import { TwoFactorType } from "../shared"
import { ci, uuid } from "../util"

/**
 * WebAuthn 2FA, ported from vaultwarden src/api/core/two_factor/webauthn.rs.
 *
 * vaultwarden delegates the FIDO2 protocol to webauthn-rs; here the equivalent
 * is @simplewebauthn/server (pure WebCrypto, Workers-compatible). Credentials
 * are stored in the `twofactor` row (atype 7) as a JSON array; in-flight
 * challenges live in transient rows (atype 1003/1004), exactly like
 * vaultwarden's WebauthnRegisterChallenge/WebauthnLoginChallenge.
 *
 * U2F-migrated credentials (appid-scoped) are not supported: vaultur has no
 * u2f data to migrate. The `appid` extension is still advertised on login for
 * wire parity with vaultwarden.
 */

const CHALLENGE_TIMEOUT_MS = 60_000

export interface WebauthnRegistration {
	id: number // 1..5, chosen by the client
	name: string
	migrated: boolean
	credential: {
		/** base64url credential id */
		credId: string
		/** base64url COSE public key */
		publicKey: string
		counter: number
		transports?: string[]
		backupEligible: boolean
		backupState: boolean
	}
}

export function rpIdFromConfig(config: Config): string {
	return new URL(config.domain).hostname
}

function originFromConfig(config: Config): string {
	return new URL(config.domain).origin
}

/** Accepts base64 / base64url, padded or not; returns base64url without padding. */
export function normalizeB64Url(value: string): string {
	return Buffer.from(value.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("base64url")
}

export async function getWebauthnRegistrations(
	db: Db,
	userUuid: string
): Promise<{ enabled: boolean; registrations: WebauthnRegistration[] }> {
	const row = await db.query.twofactor.findFirst({
		where: and(eq(twofactor.userUuid, userUuid), eq(twofactor.atype, TwoFactorType.Webauthn))
	})
	if (!row) return { enabled: false, registrations: [] }
	return { enabled: row.enabled, registrations: JSON.parse(row.data) as WebauthnRegistration[] }
}

async function saveRegistrations(
	db: Db,
	userUuid: string,
	registrations: WebauthnRegistration[]
): Promise<void> {
	const data = JSON.stringify(registrations)
	const existing = await db.query.twofactor.findFirst({
		where: and(eq(twofactor.userUuid, userUuid), eq(twofactor.atype, TwoFactorType.Webauthn))
	})
	if (existing) {
		await db.update(twofactor).set({ data, enabled: true }).where(eq(twofactor.uuid, existing.uuid))
	} else {
		await db.insert(twofactor).values({
			uuid: uuid(),
			userUuid,
			atype: TwoFactorType.Webauthn,
			enabled: true,
			data,
			lastUsed: 0
		})
	}
}

/** Stores a transient challenge row (register/login), replacing any previous one. */
async function saveChallenge(
	db: Db,
	userUuid: string,
	atype: TwoFactorType,
	data: Record<string, unknown>
): Promise<void> {
	await db
		.delete(twofactor)
		.where(and(eq(twofactor.userUuid, userUuid), eq(twofactor.atype, atype)))
	await db.insert(twofactor).values({
		uuid: uuid(),
		userUuid,
		atype,
		enabled: false,
		data: JSON.stringify({ ...data, expiresAt: Date.now() + CHALLENGE_TIMEOUT_MS }),
		lastUsed: 0
	})
}

/** Fetches and deletes a transient challenge row; errors if missing or expired. */
async function takeChallenge<T extends { expiresAt: number }>(
	db: Db,
	userUuid: string,
	atype: TwoFactorType,
	missingMessage: string
): Promise<T> {
	const row = await db.query.twofactor.findFirst({
		where: and(eq(twofactor.userUuid, userUuid), eq(twofactor.atype, atype))
	})
	if (!row) err(missingMessage)
	await db.delete(twofactor).where(eq(twofactor.uuid, row.uuid))
	const data = JSON.parse(row.data) as T
	if (Date.now() > data.expiresAt) err(missingMessage)
	return data
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

export async function startWebauthnRegistration(
	db: Db,
	config: Config,
	user: { uuid: string; email: string; name: string }
): Promise<PublicKeyCredentialCreationOptionsJSON & { status: string; errorMessage: string }> {
	const { registrations } = await getWebauthnRegistrations(db, user.uuid)

	const options = await generateRegistrationOptions({
		rpName: config.domain,
		rpID: rpIdFromConfig(config),
		userID: new Uint8Array(new TextEncoder().encode(user.uuid)) as Uint8Array<ArrayBuffer>,
		userName: user.email,
		userDisplayName: user.name,
		timeout: CHALLENGE_TIMEOUT_MS,
		attestationType: "none",
		// Return existing credentialIds so clients avoid double-registering
		excludeCredentials: registrations.map((r) => ({ id: r.credential.credId })),
		// 2FA "security key" mode: never require user verification or resident keys
		authenticatorSelection: {
			residentKey: "discouraged",
			requireResidentKey: false,
			userVerification: "discouraged"
		},
		supportedAlgorithmIDs: [-7, -257] // ES256, RS256 (matches webauthn-rs defaults)
	})

	await saveChallenge(db, user.uuid, TwoFactorType.WebauthnRegisterChallenge, {
		challenge: options.challenge
	})

	// vaultwarden strips extensions and adds a U2F-era status envelope
	delete (options as unknown as Record<string, unknown>).extensions
	return { ...options, status: "ok", errorMessage: "" }
}

/** Maps a Bitwarden client `deviceResponse` (clientDataJson casing, padded b64) to standard JSON. */
function toRegistrationResponse(deviceResponse: Record<string, unknown>): RegistrationResponseJSON {
	const response = ci<Record<string, unknown>>(deviceResponse, "response") ?? {}
	const rawId = normalizeB64Url(
		String(ci(deviceResponse, "rawId") ?? ci(deviceResponse, "id") ?? "")
	)
	const attestationObject = ci<string>(response, "attestationObject")
	const clientDataJSON =
		ci<string>(response, "clientDataJSON") ?? ci<string>(response, "clientDataJson")
	if (!rawId || !attestationObject || !clientDataJSON) err("Invalid WebAuthn response")
	return {
		id: rawId,
		rawId,
		type: "public-key",
		response: {
			attestationObject: normalizeB64Url(attestationObject),
			clientDataJSON: normalizeB64Url(clientDataJSON)
		},
		clientExtensionResults: {}
	}
}

export async function finishWebauthnRegistration(
	db: Db,
	config: Config,
	userUuid: string,
	entryId: number,
	name: string,
	deviceResponse: Record<string, unknown>
): Promise<WebauthnRegistration[]> {
	const state = await takeChallenge<{ challenge: string; expiresAt: number }>(
		db,
		userUuid,
		TwoFactorType.WebauthnRegisterChallenge,
		"Can't recover challenge"
	)

	let verification
	try {
		verification = await verifyRegistrationResponse({
			response: toRegistrationResponse(deviceResponse),
			expectedChallenge: state.challenge,
			expectedOrigin: originFromConfig(config),
			expectedRPID: rpIdFromConfig(config),
			requireUserVerification: false,
			supportedAlgorithmIDs: [-7, -257]
		})
	} catch (e) {
		err(`WebAuthn registration failed: ${e instanceof Error ? e.message : e}`)
	}
	if (!verification.verified || !verification.registrationInfo) {
		err("WebAuthn registration could not be verified")
	}

	const info = verification.registrationInfo
	const { registrations } = await getWebauthnRegistrations(db, userUuid)
	registrations.push({
		id: entryId,
		name,
		migrated: false,
		credential: {
			credId: info.credential.id,
			publicKey: Buffer.from(info.credential.publicKey).toString("base64url"),
			counter: info.credential.counter,
			transports: info.credential.transports,
			backupEligible: info.credentialDeviceType === "multiDevice",
			backupState: info.credentialBackedUp
		}
	})
	await saveRegistrations(db, userUuid, registrations)
	return registrations
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

export async function generateWebauthnLoginOptions(
	db: Db,
	config: Config,
	userUuid: string
): Promise<PublicKeyCredentialRequestOptionsJSON> {
	const { registrations } = await getWebauthnRegistrations(db, userUuid)
	if (registrations.length === 0) err("No Webauthn devices registered")

	const options = await generateAuthenticationOptions({
		rpID: rpIdFromConfig(config),
		timeout: CHALLENGE_TIMEOUT_MS,
		userVerification: "discouraged",
		allowCredentials: registrations.map((r) => ({
			id: r.credential.credId,
			transports: r.credential.transports as never
		}))
	})

	await saveChallenge(db, userUuid, TwoFactorType.WebauthnLoginChallenge, {
		challenge: options.challenge
	})

	// U2F-compat appid, advertised like vaultwarden (harmless for non-migrated keys)
	options.extensions = { ...options.extensions, appid: `${config.domain}/app-id.json` }
	return options
}

function toAuthenticationResponse(raw: Record<string, unknown>): AuthenticationResponseJSON {
	const response = ci<Record<string, unknown>>(raw, "response") ?? {}
	const rawId = normalizeB64Url(String(ci(raw, "rawId") ?? ci(raw, "id") ?? ""))
	const authenticatorData = ci<string>(response, "authenticatorData")
	const clientDataJSON =
		ci<string>(response, "clientDataJSON") ?? ci<string>(response, "clientDataJson")
	const signature = ci<string>(response, "signature")
	const userHandle = ci<string>(response, "userHandle")
	if (!rawId || !authenticatorData || !clientDataJSON || !signature) {
		err("Invalid WebAuthn response")
	}
	return {
		id: rawId,
		rawId,
		type: "public-key",
		response: {
			authenticatorData: normalizeB64Url(authenticatorData),
			clientDataJSON: normalizeB64Url(clientDataJSON),
			signature: normalizeB64Url(signature),
			userHandle: userHandle ? normalizeB64Url(userHandle) : undefined
		},
		clientExtensionResults: {}
	}
}

/** Validates the 2FA login assertion (the client sends the credential JSON as the token). */
export async function validateWebauthnLogin(
	db: Db,
	config: Config,
	userUuid: string,
	tokenJson: string
): Promise<void> {
	const state = await takeChallenge<{ challenge: string; expiresAt: number }>(
		db,
		userUuid,
		TwoFactorType.WebauthnLoginChallenge,
		"Can't recover login challenge"
	)

	let raw: Record<string, unknown>
	try {
		raw = JSON.parse(tokenJson) as Record<string, unknown>
	} catch {
		err("Invalid WebAuthn response")
	}
	const response = toAuthenticationResponse(raw)

	const { registrations } = await getWebauthnRegistrations(db, userUuid)
	const registration = registrations.find((r) => r.credential.credId === response.rawId)
	if (!registration) err("Credential not present")

	let verification
	try {
		verification = await verifyAuthenticationResponse({
			response,
			expectedChallenge: state.challenge,
			expectedOrigin: originFromConfig(config),
			expectedRPID: rpIdFromConfig(config),
			requireUserVerification: false,
			credential: {
				id: registration.credential.credId,
				publicKey: new Uint8Array(Buffer.from(registration.credential.publicKey, "base64url")),
				counter: registration.credential.counter,
				transports: registration.credential.transports as never
			}
		})
	} catch (e) {
		err(`WebAuthn login failed: ${e instanceof Error ? e.message : e}`)
	}
	if (!verification.verified) err("WebAuthn login could not be verified")

	registration.credential.counter = verification.authenticationInfo.newCounter
	registration.credential.backupState = verification.authenticationInfo.credentialBackedUp
	if (verification.authenticationInfo.credentialDeviceType === "multiDevice") {
		registration.credential.backupEligible = true
	}
	await saveRegistrations(db, userUuid, registrations)
}
