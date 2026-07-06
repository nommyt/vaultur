import type { Config } from "../config"
import { errCode } from "../error"

/**
 * Simple fixed-window login rate limiter backed by KV (per-IP).
 * KV is eventually consistent, so this is a soft limit — good enough to slow
 * credential stuffing; strict limits should also use Cloudflare WAF rules.
 */
export async function checkLoginRateLimit(
	kv: KVNamespace,
	config: Config,
	ip: string
): Promise<void> {
	const windowSeconds = 60
	const key = `ratelimit:login:${ip}:${Math.floor(Date.now() / 1000 / windowSeconds)}`
	const current = Number((await kv.get(key)) ?? "0")
	if (current >= config.loginRatelimitMaxBurst) {
		errCode("Too many requests. Try again later.", 429)
	}
	// Best-effort increment; KV has no atomic incr, acceptable for a soft limit.
	await kv.put(key, String(current + 1), { expirationTtl: windowSeconds * 2 })
}

/**
 * Per-IP fixed-window limiter for admin authentication attempts (login POST and
 * failed bearer/cookie checks). Separate key namespace from checkLoginRateLimit.
 */
export async function checkAdminLoginRateLimit(
	kv: KVNamespace,
	config: Config,
	ip: string
): Promise<void> {
	const windowSeconds = 60
	const key = `ratelimit:admin-login:${ip}:${Math.floor(Date.now() / 1000 / windowSeconds)}`
	const current = Number((await kv.get(key)) ?? "0")
	if (current >= config.loginRatelimitMaxBurst) {
		errCode("Too many requests. Try again later.", 429)
	}
	await kv.put(key, String(current + 1), { expirationTtl: windowSeconds * 2 })
}
