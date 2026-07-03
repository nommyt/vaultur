import { createHmac } from "node:crypto"

import type { Config } from "../config"
import { yubicoConfigured } from "../config"
import { err } from "../error"
import { constantTimeEqualStr, randomAlphanum } from "../util"

/**
 * YubiKey OTP 2FA, ported from vaultwarden src/api/core/two_factor/yubikey.rs.
 *
 * vaultwarden uses the `yubico` crate; this is a direct implementation of the
 * YubiCloud OTP validation protocol
 * (https://developers.yubico.com/OTP/Specifications/OTP_validation_protocol.html)
 * with node:crypto HMAC-SHA1 request/response signing.
 */

export interface YubikeyMetadata {
	keys: string[] // 12-char public key ids
	nfc: boolean
}

/** Signs a YubiCloud request/response: sorted `k=v` pairs joined with `&`, HMAC-SHA1, base64. */
export function yubicoSign(secretKeyB64: string, params: Record<string, string>): string {
	const payload = Object.keys(params)
		.filter((k) => k !== "h")
		.sort()
		.map((k) => `${k}=${params[k]}`)
		.join("&")
	return createHmac("sha1", Buffer.from(secretKeyB64, "base64")).update(payload).digest("base64")
}

function parseYubicoResponse(text: string): Record<string, string> {
	const out: Record<string, string> = {}
	for (const line of text.split(/\r?\n/)) {
		const idx = line.indexOf("=")
		if (idx > 0) out[line.slice(0, idx).trim()] = line.slice(idx + 1).trim()
	}
	return out
}

const MODHEX = /^[cbdefghijklnrtuv]{32,48}$/

export async function verifyYubikeyOtp(config: Config, otp: string): Promise<void> {
	if (!yubicoConfigured(config)) {
		err(
			"`YUBICO_CLIENT_ID` or `YUBICO_SECRET_KEY` environment variable is not set. Yubikey OTP Disabled"
		)
	}
	if (!MODHEX.test(otp)) err("Invalid Yubikey OTP")

	const nonce = randomAlphanum(32)
	const params: Record<string, string> = { id: config.yubicoClientId, nonce, otp }
	params.h = yubicoSign(config.yubicoSecretKey, params)

	const url = new URL(config.yubicoServer)
	for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v)

	let text: string
	try {
		const res = await fetch(url, { headers: { "User-Agent": "vaultur:Yubico/1.0" } })
		text = await res.text()
	} catch (e) {
		err(`Failed to verify OTP: ${e instanceof Error ? e.message : e}`)
	}

	const response = parseYubicoResponse(text)

	// Verify the response signature before trusting any of it
	if (response.h) {
		const expected = yubicoSign(config.yubicoSecretKey, response)
		if (!constantTimeEqualStr(expected, response.h))
			err("Failed to verify OTP: bad response signature")
	}
	if (response.otp !== otp || (response.nonce != null && response.nonce !== nonce)) {
		err("Failed to verify OTP: response mismatch")
	}
	if (response.status !== "OK") err(`Failed to verify OTP: ${response.status ?? "no status"}`)
}

/** Login-time validation (vaultwarden validate_yubikey_login). */
export async function validateYubikeyLogin(
	config: Config,
	otp: string,
	twofactorData: string
): Promise<void> {
	if (otp.length !== 44) err("Invalid Yubikey OTP length")

	const metadata = JSON.parse(twofactorData) as YubikeyMetadata
	const responseId = otp.slice(0, 12)
	if (!metadata.keys.includes(responseId)) err("Given Yubikey is not registered")

	await verifyYubikeyOtp(config, otp)
}
