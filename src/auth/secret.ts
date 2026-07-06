/**
 * Fail-closed validation for the HS256 JWT signing secret.
 *
 * Every auth token in Vaultur (login access tokens, the admin session cookie,
 * invite / emergency-access / email-verification / account-delete tokens,
 * 2FA-remember tokens, and Send / attachment download tokens) is signed with
 * HS256 over env.JWT_SECRET (see src/auth/jwt.ts). A missing, trivially short,
 * or shipped-placeholder secret makes every one of those tokens forgeable —
 * full account takeover of the whole server. This guard lets the server refuse
 * to run rather than run with a forgeable key.
 */

const MIN_SECRET_LENGTH = 32

// Placeholder markers that must never reach production. .env.example ships
// JWT_SECRET="change-me-to-64-random-bytes-base64"; refuse anything still
// carrying a "change me" marker regardless of length.
const PLACEHOLDER_MARKERS = ["change-me", "changeme", "change me", "your-secret", "replace-me"]

/**
 * Returns a short human-readable reason the secret is unacceptable, or null
 * when it passes. Never returns, logs, or embeds the secret value itself.
 */
export function jwtSecretProblem(secret: string | undefined | null): string | null {
	if (!secret) return "JWT_SECRET is not set"
	if (secret.length < MIN_SECRET_LENGTH) {
		return `JWT_SECRET is too short (minimum ${MIN_SECRET_LENGTH} characters)`
	}
	const lower = secret.toLowerCase()
	if (PLACEHOLDER_MARKERS.some((m) => lower.includes(m))) {
		return "JWT_SECRET is still set to a placeholder value"
	}
	return null
}
