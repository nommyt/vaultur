import type { AuthContext } from "./auth/middleware"
import type { Config } from "./config"
import type { Db } from "./db"
import type { EmailBinding } from "./services/mail"

/** Worker bindings — mirrors wrangler.jsonc. */
export interface Bindings {
	VAULTUR_DB: D1Database
	VAULTUR_KV: KVNamespace
	VAULTUR_FILES: R2Bucket
	VAULTUR_NOTIFICATIONS: DurableObjectNamespace
	VAULTUR_HEAVY?: DurableObjectNamespace
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
	ADMIN_SESSION_LIFETIME_MINUTES?: string
	USER_ATTACHMENT_LIMIT?: string
	SEND_LIMIT_PER_USER_KB?: string
	ATTACHMENT_LIMIT_PER_USER_KB?: string

	// Test-only
	TEST_MIGRATIONS?: unknown
}

/** Request-scoped variables set by middleware. */
export interface Variables {
	db: Db
	config: Config
	auth?: AuthContext
	ip: string
}

export type AppEnv = { Bindings: Bindings; Variables: Variables }
