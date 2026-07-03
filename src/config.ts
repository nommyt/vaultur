import { clamp } from "es-toolkit"

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
	/**
	 * Feature toggles. Everything Bitwarden gates behind paid tiers is free
	 * here and ON by default; these exist so an admin can turn a surface off
	 * (vaultwarden's ORG_GROUPS_ENABLED / ORG_EVENTS_ENABLED / _ENABLE_* — note
	 * vaultwarden defaults groups+events to off, vaultur defaults them to on).
	 */
	orgGroupsEnabled: boolean
	orgEventsEnabled: boolean
	enableEmail2fa: boolean
	enableDuo: boolean
	enableYubico: boolean
	/** YubiCloud OTP validation (two-factor). Both must be set to enable. */
	yubicoClientId: string
	yubicoSecretKey: string
	yubicoServer: string
	/** Global Duo Security keys (two-factor). All three must be set to enable. */
	duoIkey: string
	duoSkey: string
	duoHost: string
	/** OIDC single sign-on (ported from vaultwarden's SSO support). */
	ssoEnabled: boolean
	ssoAuthority: string
	ssoClientId: string
	ssoClientSecret: string
	ssoScopes: string
	ssoOnly: boolean
	ssoSignupsMatchEmail: boolean
	ssoAllowUnknownEmailVerification: boolean
	ssoPkce: boolean
	ssoOrganizationsInvite: boolean
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
		passwordIterations: clamp(int(env.PASSWORD_ITERATIONS, 600_000), 1, 2_000_000),
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
		userSendLimitKb: env.SEND_LIMIT_PER_USER_KB ? int(env.SEND_LIMIT_PER_USER_KB, 0) : null,
		// Defaults mirror vaultwarden exactly: groups and event logs off,
		// hardware 2FA on. All are free to enable (paid tiers in Bitwarden).
		orgGroupsEnabled: bool(env.ORG_GROUPS_ENABLED, false),
		orgEventsEnabled: bool(env.ORG_EVENTS_ENABLED, false),
		// vaultwarden defaults email 2FA availability to "mail is configured"
		enableEmail2fa: bool(env._ENABLE_EMAIL_2FA, Boolean(env.VAULTUR_EMAIL && emailFrom)),
		enableDuo: bool(env._ENABLE_DUO, true),
		enableYubico: bool(env._ENABLE_YUBICO, true),
		yubicoClientId: env.YUBICO_CLIENT_ID ?? "",
		yubicoSecretKey: env.YUBICO_SECRET_KEY ?? "",
		yubicoServer: env.YUBICO_SERVER || "https://api.yubico.com/wsapi/2.0/verify",
		duoIkey: env.DUO_IKEY ?? "",
		duoSkey: env.DUO_SKEY ?? "",
		duoHost: env.DUO_HOST ?? "",
		ssoEnabled: bool(env.SSO_ENABLED, false),
		ssoAuthority: (env.SSO_AUTHORITY ?? "").replace(/\/+$/, ""),
		ssoClientId: env.SSO_CLIENT_ID ?? "",
		ssoClientSecret: env.SSO_CLIENT_SECRET ?? "",
		ssoScopes: env.SSO_SCOPES || "email profile",
		ssoOnly: bool(env.SSO_ONLY, false),
		ssoSignupsMatchEmail: bool(env.SSO_SIGNUPS_MATCH_EMAIL, true),
		ssoAllowUnknownEmailVerification: bool(env.SSO_ALLOW_UNKNOWN_EMAIL_VERIFICATION, false),
		ssoPkce: bool(env.SSO_PKCE, true),
		ssoOrganizationsInvite: bool(env.SSO_ORGANIZATIONS_INVITE, false)
	}
}

/**
 * Global Duo credentials are usable only when enabled and all three values are
 * configured. Matches vaultwarden: `_ENABLE_DUO=false` hides the global keys
 * but does not disable per-user Duo configurations.
 */
export function duoGlobalConfigured(config: Config): boolean {
	return Boolean(config.enableDuo && config.duoIkey && config.duoSkey && config.duoHost)
}

/** YubiCloud OTP validation is usable only when enabled and credentials are configured. */
export function yubicoConfigured(config: Config): boolean {
	return Boolean(config.enableYubico && config.yubicoClientId && config.yubicoSecretKey)
}

/**
 * WebAuthn requires a registrable domain as RP ID — an IP address or localhost
 * origin cannot be used (vaultwarden is_webauthn_2fa_supported).
 */
export function webauthnSupported(config: Config): boolean {
	try {
		const host = new URL(config.domain).hostname
		return host.length > 0 && !/^\d+\.\d+\.\d+\.\d+$/.test(host) && !host.includes(":")
	} catch {
		return false
	}
}

/** SSO is usable only when enabled and fully configured. */
export function ssoConfigured(config: Config): boolean {
	return Boolean(config.ssoEnabled && config.ssoAuthority && config.ssoClientId)
}
