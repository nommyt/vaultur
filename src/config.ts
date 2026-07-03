import type { Bindings } from "./env"

const bool = (v: string | undefined, dflt: boolean) =>
	v == null || v === "" ? dflt : v === "true" || v === "1"
const int = (v: string | undefined, dflt: number) => {
	const n = Number(v)
	return v != null && v !== "" && Number.isFinite(n) ? Math.floor(n) : dflt
}

export interface Config {
	/** Public origin, e.g. https://vault.example.com (no trailing slash). */
	domain: string
	signupsAllowed: boolean
	signupsDomainsWhitelist: string[]
	signupsVerify: boolean
	invitationsAllowed: boolean
	emergencyAccessAllowed: boolean
	sendsAllowed: boolean
	orgCreationUsers: string // 'all' | 'none' | comma-separated emails
	passwordHintsAllow: boolean
	showPasswordHint: boolean
	passwordIterations: number
	emailFrom: string
	emailFromName: string
	emailEnabled: boolean
	pushEnabled: boolean
	pushInstallationId: string
	pushInstallationKey: string
	pushRelayUri: string
	pushIdentityUri: string
	trashAutoDeleteDays: number
	iconService: string
	iconCacheTtlSeconds: number
	loginRatelimitMaxBurst: number
	adminSessionLifetimeMinutes: number
	adminTokenSet: boolean
	userAttachmentLimitKb: number | null
	userSendLimitKb: number | null
}

export function loadConfig(env: Bindings, requestUrl: string): Config {
	const url = new URL(requestUrl)
	const domain = (env.DOMAIN && env.DOMAIN.replace(/\/+$/, "")) || `${url.protocol}//${url.host}`
	const emailFrom = env.EMAIL_FROM ?? ""
	return {
		domain,
		signupsAllowed: bool(env.SIGNUPS_ALLOWED, true),
		signupsDomainsWhitelist: (env.SIGNUPS_DOMAINS_WHITELIST ?? "")
			.split(",")
			.map((s) => s.trim().toLowerCase())
			.filter(Boolean),
		signupsVerify: bool(env.SIGNUPS_VERIFY, false),
		invitationsAllowed: bool(env.INVITATIONS_ALLOWED, true),
		emergencyAccessAllowed: bool(env.EMERGENCY_ACCESS_ALLOWED, true),
		sendsAllowed: bool(env.SENDS_ALLOWED, true),
		orgCreationUsers: (env.ORG_CREATION_USERS ?? "all").toLowerCase(),
		passwordHintsAllow: bool(env.PASSWORD_HINTS_ALLOW, true),
		showPasswordHint: bool(env.SHOW_PASSWORD_HINT, false),
		// Server-side PBKDF2 over the client's already-derived master-password hash.
		// Uses @noble/hashes (pure JS) to avoid workerd's 100k cap on native crypto —
		// matches vaultwarden's 600k default and allows up to 2M (Bitwarden KDF ceiling).
		passwordIterations: Math.min(Math.max(int(env.PASSWORD_ITERATIONS, 600_000), 1), 2_000_000),
		emailFrom,
		emailFromName: env.EMAIL_FROM_NAME || "Vaultur",
		emailEnabled: Boolean(env.VAULTUR_EMAIL && emailFrom),
		pushEnabled: bool(env.PUSH_ENABLED, false),
		pushInstallationId: env.PUSH_INSTALLATION_ID ?? "",
		pushInstallationKey: env.PUSH_INSTALLATION_KEY ?? "",
		pushRelayUri: env.PUSH_RELAY_URI || "https://push.bitwarden.com",
		pushIdentityUri: env.PUSH_IDENTITY_URI || "https://identity.bitwarden.com",
		trashAutoDeleteDays: int(env.TRASH_AUTO_DELETE_DAYS, 30),
		iconService: env.ICON_SERVICE || "internal",
		iconCacheTtlSeconds: int(env.ICON_CACHE_TTL_SECONDS, 2_592_000),
		loginRatelimitMaxBurst: int(env.LOGIN_RATELIMIT_MAX_BURST, 10),
		adminSessionLifetimeMinutes: int(env.ADMIN_SESSION_LIFETIME_MINUTES, 20),
		adminTokenSet: Boolean(env.ADMIN_TOKEN && env.ADMIN_TOKEN.length >= 8),
		userAttachmentLimitKb: env.ATTACHMENT_LIMIT_PER_USER_KB
			? int(env.ATTACHMENT_LIMIT_PER_USER_KB, 0)
			: null,
		userSendLimitKb: env.SEND_LIMIT_PER_USER_KB ? int(env.SEND_LIMIT_PER_USER_KB, 0) : null
	}
}
