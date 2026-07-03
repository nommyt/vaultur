import type { Config } from "../config"
import type { Bindings } from "../env"

/**
 * Mobile push relay (vaultwarden src/api/push.rs): authenticates against
 * Bitwarden's identity service with the installation id/key and relays push
 * payloads so the official mobile apps get native push notifications.
 */

const TOKEN_KV_KEY = "push:relay-token"

async function getPushToken(env: Bindings, config: Config): Promise<string | null> {
	if (!config.pushInstallationId || !config.pushInstallationKey) return null

	const cached = await env.VAULTUR_KV.get(TOKEN_KV_KEY)
	if (cached) return cached

	const res = await fetch(`${config.pushIdentityUri}/connect/token`, {
		method: "POST",
		headers: { "Content-Type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams({
			grant_type: "client_credentials",
			scope: "api.push",
			client_id: `installation.${config.pushInstallationId}`,
			client_secret: config.pushInstallationKey
		}).toString()
	})
	if (!res.ok) {
		console.error(`Push relay token request failed: ${res.status}`)
		return null
	}
	const body = (await res.json()) as { access_token: string; expires_in: number }
	await env.VAULTUR_KV.put(TOKEN_KV_KEY, body.access_token, {
		expirationTtl: Math.max(60, body.expires_in - 60)
	})
	return body.access_token
}

export interface PushPayload {
	userId: string | null
	organizationId: string | null
	deviceId: string | null
	identifier: string | null
	type: number
	payload: Record<string, unknown>
}

export async function sendPushNotification(
	env: Bindings,
	config: Config,
	data: PushPayload
): Promise<void> {
	if (!config.pushEnabled) return
	const token = await getPushToken(env, config)
	if (!token) return

	const res = await fetch(`${config.pushRelayUri}/push/send`, {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			Authorization: `Bearer ${token}`
		},
		body: JSON.stringify(data)
	})
	if (!res.ok) {
		console.error(`Push relay send failed: ${res.status} ${await res.text().catch(() => "")}`)
	}
}

/** Registers a device with the Bitwarden push relay (called on login for mobile clients). */
export async function registerPushDevice(
	env: Bindings,
	config: Config,
	device: {
		uuid: string
		userUuid: string
		pushToken: string | null
		pushUuid: string | null
		atype: number
	}
): Promise<void> {
	if (!config.pushEnabled || !device.pushToken) return
	const token = await getPushToken(env, config)
	if (!token) return

	const res = await fetch(`${config.pushRelayUri}/push/register`, {
		method: "POST",
		headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
		body: JSON.stringify({
			userId: device.userUuid,
			deviceId: device.pushUuid,
			identifier: device.uuid,
			type: device.atype,
			pushToken: device.pushToken
		})
	})
	if (!res.ok) {
		console.error(`Push register failed: ${res.status}`)
	}
}
