import type { AuthContext } from "./auth/middleware"
import type { Config } from "./config"
import type { Db } from "./db"
import type { EmailBinding } from "./services/mail"
import type { BlobStore } from "./services/storage"

/** Worker bindings — mirrors wrangler.jsonc. */
export interface Bindings {
	VAULTUR_DB: D1Database
	VAULTUR_KV: KVNamespace
	// R2 requires a paid Cloudflare plan — optional; falls back to KV (see
	// src/services/storage.ts) when the binding isn't present.
	VAULTUR_FILES?: R2Bucket
	VAULTUR_NOTIFICATIONS: DurableObjectNamespace
	// Required: all server-side PBKDF2 is offloaded to this DO (see src/crypto.ts
	// / src/app.ts). The Worker has no inline fallback, so this binding must be
	// configured in every deployment. src/app.ts also guards it at runtime, since
	// Worker bindings are populated at runtime and the type cannot enforce config.
	VAULTUR_HEAVY: DurableObjectNamespace
	VAULTUR_EMAIL?: EmailBinding
	VAULTUR_ASSETS?: Fetcher

	// Secrets
	JWT_SECRET: string
	ADMIN_TOKEN?: string

	// Vars (strings; parsed by config.ts)
	DOMAIN?: string
	SIGNUPS_ALLOWED?: string
	SIGNUPS_DOMAINS_WHITELIST?: string
	SIGNUPS_VERIFY?: string
	LOGIN_ALLOWED_EMAILS?: string
	INVITATIONS_ALLOWED?: string
	EMERGENCY_ACCESS_ALLOWED?: string
	SENDS_ALLOWED?: string
	ORG_CREATION_USERS?: string
	PASSWORD_HINTS_ALLOW?: string
	SHOW_PASSWORD_HINT?: string
	PASSWORD_ITERATIONS?: string
	EMAIL_FROM?: string
	EMAIL_FROM_NAME?: string
	PUSH_ENABLED?: string
	PUSH_INSTALLATION_ID?: string
	PUSH_INSTALLATION_KEY?: string
	PUSH_RELAY_URI?: string
	PUSH_IDENTITY_URI?: string
	TRASH_AUTO_DELETE_DAYS?: string
	ICON_SERVICE?: string
	ICON_CACHE_TTL_SECONDS?: string
	LOGIN_RATELIMIT_MAX_BURST?: string
	LOGIN_RATELIMIT_USER_MAX_FAILURES?: string
	ADMIN_SESSION_LIFETIME_MINUTES?: string
	USER_ATTACHMENT_LIMIT?: string
	SEND_LIMIT_PER_USER_KB?: string
	ATTACHMENT_LIMIT_PER_USER_KB?: string
	ORG_GROUPS_ENABLED?: string
	ORG_EVENTS_ENABLED?: string
	_ENABLE_EMAIL_2FA?: string
	_ENABLE_DUO?: string
	_ENABLE_YUBICO?: string
	YUBICO_CLIENT_ID?: string
	YUBICO_SECRET_KEY?: string
	YUBICO_SERVER?: string
	DUO_IKEY?: string
	DUO_SKEY?: string
	DUO_HOST?: string
	SSO_ENABLED?: string
	SSO_AUTHORITY?: string
	SSO_CLIENT_ID?: string
	SSO_CLIENT_SECRET?: string
	SSO_SCOPES?: string
	SSO_ONLY?: string
	SSO_SIGNUPS_MATCH_EMAIL?: string
	SSO_ALLOW_UNKNOWN_EMAIL_VERIFICATION?: string
	SSO_PKCE?: string
	SSO_ORGANIZATIONS_INVITE?: string

	// Test-only
	TEST_MIGRATIONS?: unknown
}

/** Request-scoped variables set by middleware. */
export interface Variables {
	db: Db
	config: Config
	storage: BlobStore
	auth?: AuthContext
	ip: string
}

export type AppEnv = { Bindings: Bindings; Variables: Variables }
