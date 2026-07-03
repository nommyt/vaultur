/**
 * Admin-panel settings schema. Declares the config groups/fields shown in the
 * admin Settings page (vaultwarden `make_config!` parity), mapped onto Vaultur's
 * {@link Config}. Editable values are layered on top of the env-derived config
 * via {@link applyOverrides}; secrets (ADMIN_TOKEN, JWT_SECRET, push keys) are
 * never editable and never persisted — they live in read-only fields.
 */
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
		if (JSON.stringify(parsed) !== JSON.stringify(normalizeForCompare(field.type, envValue))) {
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
