/**
 * Admin-panel settings schema. Declares the config groups/fields shown in the
 * admin Settings page (vaultwarden `make_config!` parity), mapped onto Vaultur's
 * {@link Config}. Editable values are layered on top of the env-derived config
 * via {@link applyOverrides}; secrets (ADMIN_TOKEN, JWT_SECRET, push keys) are
 * never editable and never persisted — they live in read-only fields.
 */
import { isEqual } from "es-toolkit"

import type { Config } from "./config"

export type FieldType = "text" | "number" | "checkbox" | "password" | "select"

export interface SettingField {
	/** Form key (snake_case, mirrors vaultwarden naming). */
	name: string
	label: string
	type: FieldType
	description: string
	/** Placeholder shown as "Default: …". */
	default?: string
	options?: { value: string; label: string }[]
	/** Current value in form terms (string | number | boolean | null). */
	get(cfg: Config): string | number | boolean | null
	/** Apply a parsed override value onto a mutable config. */
	apply(cfg: Config, value: unknown): void
}

export interface SettingGroup {
	group: string
	label: string
	fields: SettingField[]
}

const str = (v: unknown): string => (v == null ? "" : String(v))
const b = (v: unknown): boolean => v === true || v === "true" || v === "1" || v === "on"

export const SETTINGS_GROUPS: SettingGroup[] = [
	{
		group: "settings",
		label: "General Settings",
		fields: [
			{
				name: "domain",
				label: "Domain URL",
				type: "text",
				description:
					"The full URL clients use to reach this server, e.g. https://vault.example.com. Must be correct for attachments, U2F/WebAuthn and email links.",
				get: (c) => c.domain,
				apply: (c, v) => {
					const s = str(v).replace(/\/+$/, "")
					if (s) c.domain = s
				}
			},
			{
				name: "signups_allowed",
				label: "Allow new signups",
				type: "checkbox",
				description: "Controls whether new users can register. Existing users are unaffected.",
				get: (c) => c.signupsAllowed,
				apply: (c, v) => (c.signupsAllowed = b(v))
			},
			{
				name: "signups_verify",
				label: "Require email verification on signup",
				type: "checkbox",
				description: "Verify the email address of new users before they can log in.",
				get: (c) => c.signupsVerify,
				apply: (c, v) => (c.signupsVerify = b(v))
			},
			{
				name: "signups_domains_whitelist",
				label: "Allowed signup domains",
				type: "text",
				description:
					'Comma-separated list of domain names for allowed signups. If set, this overrides "Allow new signups".',
				get: (c) => c.signupsDomainsWhitelist.join(","),
				apply: (c, v) =>
					(c.signupsDomainsWhitelist = str(v)
						.split(",")
						.map((s) => s.trim().toLowerCase())
						.filter(Boolean))
			},
			{
				name: "login_allowed_emails",
				label: "Allowed login emails",
				type: "text",
				description:
					"Comma-separated list of email addresses allowed to log in or register. If set, every other account is refused at all login grants (password, SSO, API key, refresh) and at registration. Empty allows all accounts.",
				get: (c) => c.loginAllowedEmails.join(","),
				apply: (c, v) =>
					(c.loginAllowedEmails = str(v)
						.split(",")
						.map((s) => s.trim().toLowerCase())
						.filter(Boolean))
			},
			{
				name: "invitations_allowed",
				label: "Allow invitations",
				type: "checkbox",
				description: "Even when signups are disabled, an existing user can invite new users.",
				get: (c) => c.invitationsAllowed,
				apply: (c, v) => (c.invitationsAllowed = b(v))
			},
			{
				name: "emergency_access_allowed",
				label: "Allow emergency access",
				type: "checkbox",
				description: "Controls whether users can enable emergency access to their accounts.",
				get: (c) => c.emergencyAccessAllowed,
				apply: (c, v) => (c.emergencyAccessAllowed = b(v))
			},
			{
				name: "sends_allowed",
				label: "Allow Bitwarden Sends",
				type: "checkbox",
				description: "Controls whether users can create and use Bitwarden Sends.",
				get: (c) => c.sendsAllowed,
				apply: (c, v) => (c.sendsAllowed = b(v))
			},
			{
				name: "org_creation_users",
				label: "Org creation users",
				type: "text",
				description:
					"Which users can create organizations. 'all', 'none', or a comma-separated list of emails.",
				default: "all",
				get: (c) => c.orgCreationUsers,
				apply: (c, v) => (c.orgCreationUsers = str(v).toLowerCase() || "all")
			},
			{
				name: "password_hints_allowed",
				label: "Allow password hints",
				type: "checkbox",
				description: "Controls whether users can set and retrieve master-password hints.",
				get: (c) => c.passwordHintsAllow,
				apply: (c, v) => (c.passwordHintsAllow = b(v))
			},
			{
				name: "show_password_hint",
				label: "Show password hint (unauthenticated)",
				type: "checkbox",
				description:
					"Show the password hint to anyone who requests it. Leaks whether an email is registered; email delivery is preferred.",
				get: (c) => c.showPasswordHint,
				apply: (c, v) => (c.showPasswordHint = b(v))
			},
			{
				name: "trash_auto_delete_days",
				label: "Trash auto-delete days",
				type: "number",
				description:
					"Number of days to keep items in the trash before permanently deleting them. Empty disables auto-deletion.",
				default: "30",
				get: (c) => c.trashAutoDeleteDays,
				apply: (c, v) => {
					if (v != null) c.trashAutoDeleteDays = Number(v)
				}
			}
		]
	},
	{
		group: "limits",
		label: "Storage Limits",
		fields: [
			{
				name: "user_attachment_limit",
				label: "Per-user attachment storage (KB)",
				type: "number",
				description: "Total attachment storage a user may consume, in KB. Empty means unlimited.",
				get: (c) => c.userAttachmentLimitKb,
				apply: (c, v) => (c.userAttachmentLimitKb = v == null ? null : Number(v))
			},
			{
				name: "user_send_limit",
				label: "Per-user Send storage (KB)",
				type: "number",
				description: "Total Send storage a user may consume, in KB. Empty means unlimited.",
				get: (c) => c.userSendLimitKb,
				apply: (c, v) => (c.userSendLimitKb = v == null ? null : Number(v))
			}
		]
	},
	{
		group: "org_features",
		label: "Organization Features",
		fields: [
			{
				// Bitwarden gates groups behind Enterprise; free to enable here.
				name: "org_groups_enabled",
				label: "Enable organization groups",
				type: "checkbox",
				description:
					"Group-based collection access. Free in Vaultur (a paid Enterprise feature in Bitwarden). Off by default, matching vaultwarden.",
				get: (c) => c.orgGroupsEnabled,
				apply: (c, v) => (c.orgGroupsEnabled = b(v))
			},
			{
				// Bitwarden gates the event log behind Enterprise; free to enable here.
				name: "org_events_enabled",
				label: "Enable event logs",
				type: "checkbox",
				description:
					"Organization and user audit event logging. Free in Vaultur (a paid Enterprise feature in Bitwarden). Off by default, matching vaultwarden.",
				get: (c) => c.orgEventsEnabled,
				apply: (c, v) => (c.orgEventsEnabled = b(v))
			}
		]
	},
	{
		group: "icons",
		label: "Icon Settings",
		fields: [
			{
				name: "icon_service",
				label: "Icon service",
				type: "text",
				description:
					"The favicon service: 'internal' (proxy), a template URL with {}, or 'bitwarden'/'duckduckgo'/'google'.",
				default: "internal",
				get: (c) => c.iconService,
				apply: (c, v) => (c.iconService = str(v) || "internal")
			},
			{
				name: "icon_cache_ttl",
				label: "Icon cache TTL (seconds)",
				type: "number",
				description: "How long to cache successfully-fetched icons, in seconds.",
				default: "2592000",
				get: (c) => c.iconCacheTtlSeconds,
				apply: (c, v) => {
					if (v != null) c.iconCacheTtlSeconds = Number(v)
				}
			}
		]
	},
	{
		group: "smtp",
		label: "Email (Cloudflare Email Sending)",
		fields: [
			{
				name: "email_enabled",
				label: "Enable email",
				type: "checkbox",
				description:
					"Send transactional email (invites, verification, hints) via Cloudflare Email Sending. Requires the VAULTUR_EMAIL binding and a From address.",
				get: (c) => c.emailEnabled,
				apply: (c, v) => (c.emailEnabled = b(v))
			},
			{
				name: "smtp_from",
				label: "From address",
				type: "text",
				description:
					"The envelope From address for outgoing mail. Must be a verified sender on your Cloudflare Email domain.",
				get: (c) => c.emailFrom,
				apply: (c, v) => (c.emailFrom = str(v))
			},
			{
				name: "smtp_from_name",
				label: "From name",
				type: "text",
				description: "The display name for outgoing mail.",
				default: "Vaultur",
				get: (c) => c.emailFromName,
				apply: (c, v) => (c.emailFromName = str(v) || "Vaultur")
			},
			{
				name: "_enable_email_2fa",
				label: "Enable email 2FA",
				type: "checkbox",
				description:
					"Allow email-based two-factor. Defaults to on whenever email is configured (VAULTUR_EMAIL binding + From address).",
				get: (c) => c.enableEmail2fa,
				apply: (c, v) => (c.enableEmail2fa = b(v))
			}
		]
	},
	{
		group: "push",
		label: "Mobile Push Notifications",
		fields: [
			{
				name: "push_enabled",
				label: "Enable push notifications",
				type: "checkbox",
				description:
					"Relay push notifications to mobile clients via the Bitwarden push relay. Requires installation id/key (read-only).",
				get: (c) => c.pushEnabled,
				apply: (c, v) => (c.pushEnabled = b(v))
			},
			{
				name: "push_relay_uri",
				label: "Push relay URI",
				type: "text",
				description: "Base URL of the Bitwarden push relay.",
				default: "https://push.bitwarden.com",
				get: (c) => c.pushRelayUri,
				apply: (c, v) => (c.pushRelayUri = str(v) || "https://push.bitwarden.com")
			},
			{
				name: "push_identity_uri",
				label: "Push identity URI",
				type: "text",
				description: "Base URL of the Bitwarden identity server used for push auth.",
				default: "https://identity.bitwarden.com",
				get: (c) => c.pushIdentityUri,
				apply: (c, v) => (c.pushIdentityUri = str(v) || "https://identity.bitwarden.com")
			}
		]
	},
	{
		group: "yubico",
		label: "Yubikey Settings",
		fields: [
			{
				name: "_enable_yubico",
				label: "Enable YubiKey OTP",
				type: "checkbox",
				description: "Master switch for YubiKey OTP two-factor. Requires client id + secret below.",
				get: (c) => c.enableYubico,
				apply: (c, v) => (c.enableYubico = b(v))
			},
			{
				name: "yubico_client_id",
				label: "Yubico Client ID",
				type: "text",
				description: "YubiCloud API client id (register at upgrade.yubico.com/getapikey).",
				get: (c) => c.yubicoClientId,
				apply: (c, v) => (c.yubicoClientId = str(v))
			},
			{
				name: "yubico_secret_key",
				label: "Yubico Secret Key",
				type: "password",
				description: "YubiCloud API secret key (base64).",
				get: (c) => c.yubicoSecretKey,
				apply: (c, v) => (c.yubicoSecretKey = str(v))
			},
			{
				name: "yubico_server",
				label: "Yubico Server",
				type: "text",
				description: "OTP validation server. Leave the default for YubiCloud.",
				default: "https://api.yubico.com/wsapi/2.0/verify",
				get: (c) => c.yubicoServer,
				apply: (c, v) => (c.yubicoServer = str(v) || "https://api.yubico.com/wsapi/2.0/verify")
			}
		]
	},
	{
		group: "duo",
		label: "Global Duo Settings",
		fields: [
			{
				name: "_enable_duo",
				label: "Enable Duo",
				type: "checkbox",
				description:
					"Master switch for the global Duo credentials below. Disabling hides the global keys but leaves per-user Duo configs intact.",
				get: (c) => c.enableDuo,
				apply: (c, v) => (c.enableDuo = b(v))
			},
			{
				name: "duo_ikey",
				label: "Duo Client Id",
				type: "text",
				description: "Client id of the Duo 'Web SDK' application (Universal Prompt).",
				get: (c) => c.duoIkey,
				apply: (c, v) => (c.duoIkey = str(v))
			},
			{
				name: "duo_skey",
				label: "Duo Client Secret",
				type: "password",
				description: "Client secret of the Duo 'Web SDK' application.",
				get: (c) => c.duoSkey,
				apply: (c, v) => (c.duoSkey = str(v))
			},
			{
				name: "duo_host",
				label: "Duo API Hostname",
				type: "text",
				description: "Your Duo API hostname, e.g. api-xxxxxxxx.duosecurity.com.",
				get: (c) => c.duoHost,
				apply: (c, v) => (c.duoHost = str(v))
			}
		]
	},
	{
		group: "sso",
		label: "OIDC Single Sign-On",
		fields: [
			{
				name: "sso_enabled",
				label: "Enable SSO",
				type: "checkbox",
				description: "Allow login through an OpenID Connect identity provider.",
				get: (c) => c.ssoEnabled,
				apply: (c, v) => (c.ssoEnabled = b(v))
			},
			{
				name: "sso_only",
				label: "SSO only",
				type: "checkbox",
				description: "Disable master-password login entirely; every login must go through SSO.",
				get: (c) => c.ssoOnly,
				apply: (c, v) => (c.ssoOnly = b(v))
			},
			{
				name: "sso_authority",
				label: "Authority (issuer URL)",
				type: "text",
				description: "OIDC issuer base URL; /.well-known/openid-configuration must exist below it.",
				get: (c) => c.ssoAuthority,
				apply: (c, v) => (c.ssoAuthority = str(v).replace(/\/+$/, ""))
			},
			{
				name: "sso_client_id",
				label: "Client ID",
				type: "text",
				description: "OIDC client id registered with the provider.",
				get: (c) => c.ssoClientId,
				apply: (c, v) => (c.ssoClientId = str(v))
			},
			{
				name: "sso_client_secret",
				label: "Client Secret",
				type: "password",
				description: "OIDC client secret.",
				get: (c) => c.ssoClientSecret,
				apply: (c, v) => (c.ssoClientSecret = str(v))
			},
			{
				name: "sso_scopes",
				label: "Scopes",
				type: "text",
				description: "Additional scopes requested from the provider (openid is always added).",
				default: "email profile",
				get: (c) => c.ssoScopes,
				apply: (c, v) => (c.ssoScopes = str(v) || "email profile")
			},
			{
				name: "sso_signups_match_email",
				label: "Associate existing accounts by email",
				type: "checkbox",
				description:
					"On first SSO login, link to an existing non-SSO account with the same (verified) email.",
				get: (c) => c.ssoSignupsMatchEmail,
				apply: (c, v) => (c.ssoSignupsMatchEmail = b(v))
			},
			{
				name: "sso_allow_unknown_email_verification",
				label: "Allow unknown email verification status",
				type: "checkbox",
				description: "Log users in even when the provider does not report an email_verified claim.",
				get: (c) => c.ssoAllowUnknownEmailVerification,
				apply: (c, v) => (c.ssoAllowUnknownEmailVerification = b(v))
			},
			{
				name: "sso_pkce",
				label: "Forward PKCE to the provider",
				type: "checkbox",
				description:
					"Pass the client's PKCE challenge through to the IdP (recommended; disable only for providers without S256 support).",
				get: (c) => c.ssoPkce,
				apply: (c, v) => (c.ssoPkce = b(v))
			}
		]
	},
	{
		group: "advanced",
		label: "Advanced Settings",
		fields: [
			{
				name: "login_ratelimit_max_burst",
				label: "Login rate-limit burst",
				type: "number",
				description: "Allowed burst of failed login attempts before rate-limiting kicks in.",
				default: "10",
				get: (c) => c.loginRatelimitMaxBurst,
				apply: (c, v) => {
					if (v != null) c.loginRatelimitMaxBurst = Number(v)
				}
			},
			{
				name: "admin_session_lifetime",
				label: "Admin session lifetime (minutes)",
				type: "number",
				description: "How long an admin panel session stays valid, in minutes.",
				default: "20",
				get: (c) => c.adminSessionLifetimeMinutes,
				apply: (c, v) => {
					if (v != null) c.adminSessionLifetimeMinutes = Number(v)
				}
			}
		]
	}
]

/** Read-only fields (env-only) shown in the Read-Only Config section. */
export interface ReadonlyField {
	name: string
	label: string
	type: "text" | "password"
	description: string
	value(cfg: Config): string
}

const MASK = "••••••••"

export const READONLY_FIELDS: ReadonlyField[] = [
	{
		name: "email_transport",
		label: "Email transport",
		type: "text",
		description: "Vaultur sends mail via the Cloudflare Email Sending binding (VAULTUR_EMAIL).",
		value: (c) =>
			c.emailEnabled ? "Cloudflare Email Sending" : "Cloudflare Email Sending (disabled)"
	},
	{
		name: "admin_token",
		label: "Admin token",
		type: "password",
		description: "Set via the ADMIN_TOKEN secret. Rotate with `wrangler secret put ADMIN_TOKEN`.",
		value: (c) => (c.adminTokenSet ? MASK : "")
	},
	{
		name: "password_iterations",
		label: "Server password iterations",
		type: "text",
		description:
			"Server-side PBKDF2 iterations. Defaults to 600000 (vaultwarden parity via node:crypto); set via PASSWORD_ITERATIONS.",
		value: (c) => String(c.passwordIterations)
	},
	{
		name: "push_installation_id",
		label: "Push installation id",
		type: "password",
		description: "Set via the PUSH_INSTALLATION_ID secret.",
		value: (c) => (c.pushInstallationId ? MASK : "")
	},
	{
		name: "push_installation_key",
		label: "Push installation key",
		type: "password",
		description: "Set via the PUSH_INSTALLATION_KEY secret.",
		value: (c) => (c.pushInstallationKey ? MASK : "")
	}
]

const EDITABLE_FIELDS = new Map<string, SettingField>(
	SETTINGS_GROUPS.flatMap((g) => g.fields.map((f) => [f.name, f] as const))
)

/** Parse a raw posted form value into its stored representation, by field type. */
function parseByType(type: FieldType, raw: unknown): unknown {
	if (type === "checkbox") return b(raw)
	if (type === "number") {
		if (raw == null || raw === "") return null
		const n = Math.floor(Number(raw))
		return Number.isFinite(n) ? n : null
	}
	return raw == null || raw === "" ? null : String(raw)
}

/** Layer a stored overrides object on top of an env-derived config. */
export function applyOverrides(base: Config, overrides: Record<string, unknown>): Config {
	const cfg: Config = { ...base }
	for (const [name, value] of Object.entries(overrides)) {
		const field = EDITABLE_FIELDS.get(name)
		if (field) field.apply(cfg, value)
	}
	return cfg
}

/**
 * Given the posted form data and the env-only base config, return the minimal
 * set of overrides to persist: only fields whose value differs from the env
 * default. Unknown/non-editable keys are ignored.
 */
export function diffOverrides(
	posted: Record<string, unknown>,
	envBase: Config
): Record<string, unknown> {
	const out: Record<string, unknown> = {}
	for (const [name, field] of EDITABLE_FIELDS) {
		if (!(name in posted)) continue
		const parsed = parseByType(field.type, posted[name])
		const envValue = field.get(envBase)
		if (!isEqual(parsed, normalizeForCompare(field.type, envValue))) {
			out[name] = parsed
		}
	}
	return out
}

function normalizeForCompare(type: FieldType, value: string | number | boolean | null): unknown {
	if (type === "checkbox") return Boolean(value)
	if (type === "number") return value == null || value === "" ? null : Number(value)
	return value == null || value === "" ? null : String(value)
}
