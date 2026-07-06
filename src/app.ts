import { Hono } from "hono"
import { secureHeaders } from "hono/secure-headers"

import { accountRoutes } from "./api/accounts"
import { adminRoutes } from "./api/admin"
import { attachmentRoutes, attachmentDownloadRoutes } from "./api/attachments"
import { authRequestRoutes } from "./api/auth-requests"
import { cipherRoutes } from "./api/ciphers"
import { deviceRoutes } from "./api/devices"
import { domainRoutes } from "./api/domains"
import { emergencyAccessRoutes } from "./api/emergency-access"
import { eventRoutes, eventCollectRoutes } from "./api/events"
import { folderRoutes } from "./api/folders"
import { iconRoutes } from "./api/icons"
import { identityRoutes } from "./api/identity"
import { metaRoutes } from "./api/meta"
import { miscRoutes } from "./api/misc"
import { notificationRoutes } from "./api/notifications"
import { orgMemberRoutes } from "./api/org-members"
import { organizationRoutes } from "./api/organizations"
import { publicRoutes } from "./api/public"
import { sendRoutes, sendAccessRoutes } from "./api/sends"
import { syncRoutes } from "./api/sync"
import { twofactorRoutes } from "./api/twofactor"
import { jwtSecretProblem } from "./auth/secret"
import { loadConfig } from "./config"
import { applyOverrides } from "./config-schema"
import { pbkdf2Als } from "./crypto"
import { createDb } from "./db"
import type { AppEnv } from "./env"
import { onError, errorBody, errCode } from "./error"
import { heavyRunner } from "./services/pbkdf2-offload"
import { getConfigOverrides } from "./services/server-config"

export function createApp() {
	const app = new Hono<AppEnv>()

	// Curated hardening headers. Cross-origin isolation headers (CORP/COOP/COEP)
	// are explicitly disabled so the browser-extension client's cross-origin API
	// fetches and the SSO popup flow keep working. The web vault SPA is served by
	// the native `assets` runtime, not this app, so it is unaffected either way.
	app.use(
		secureHeaders({
			crossOriginEmbedderPolicy: false,
			crossOriginResourcePolicy: false,
			crossOriginOpenerPolicy: false,
			originAgentCluster: false,
			// Plain max-age (no includeSubDomains) — safer for self-hosters whose
			// apex/sibling subdomains are not all HTTPS.
			strictTransportSecurity: "max-age=31536000",
			referrerPolicy: "no-referrer",
			xContentTypeOptions: "nosniff",
			// X-Frame-Options is decided by the dedicated middleware below, not here —
			// see its comment for why (Hono's LIFO middleware unwind).
			xFrameOptions: false
		})
	)

	// X-Frame-Options / frame-ancestors decided once, by path, in one place. Hono
	// middleware unwinds LIFO (post-next() code of the FIRST-registered middleware
	// runs LAST), so a value set here by a route-local override nested inside this
	// app's routing (e.g. inside adminRoutes) would always be overwritten by
	// whichever global middleware wraps it. Rather than fight that ordering, only
	// one middleware ever sets this header, decided by path.
	app.use(async (c, next) => {
		await next()
		const pathname = new URL(c.req.url).pathname
		const isAdmin = pathname === "/admin" || pathname.startsWith("/admin/")
		c.res.headers.set("X-Frame-Options", isAdmin ? "DENY" : "SAMEORIGIN")
		if (isAdmin) c.res.headers.set("Content-Security-Policy", "frame-ancestors 'none'")
	})

	app.use(async (c, next) => {
		const secretProblem = jwtSecretProblem(c.env.JWT_SECRET)
		if (secretProblem) {
			console.error(
				`Refusing request: ${secretProblem}. Set a strong JWT_SECRET, e.g. \`openssl rand -base64 64\`.`
			)
			errCode("Server configuration error", 500)
		}

		const db = createDb(c.env.VAULTUR_DB)
		c.set("db", db)
		const base = loadConfig(c.env, c.req.url)
		const overrides = await getConfigOverrides(db)
		c.set("config", applyOverrides(base, overrides))
		c.set("ip", c.req.header("CF-Connecting-IP") ?? "0.0.0.0")
		const runner = c.env.VAULTUR_HEAVY ? heavyRunner(c.env.VAULTUR_HEAVY) : undefined
		return pbkdf2Als.run(runner, () => next())
	})

	app.onError(onError)
	app.notFound((c) => c.json(errorBody("Not found"), 404))

	app.route("/identity", identityRoutes)
	app.route("/api", metaRoutes)
	// Public (unauthenticated) API routes must be mounted before the
	// requireAuth-guarded routers that share the /api prefix.
	app.route("/api", sendAccessRoutes)
	app.route("/api", publicRoutes)
	app.route("/api", syncRoutes)
	app.route("/api", cipherRoutes)
	app.route("/api", attachmentRoutes)
	app.route("/api", sendRoutes)
	app.route("/api", folderRoutes)
	app.route("/api", accountRoutes)
	app.route("/api", domainRoutes)
	app.route("/api", deviceRoutes)
	app.route("/api", twofactorRoutes)
	app.route("/api", authRequestRoutes)
	app.route("/api", organizationRoutes)
	app.route("/api", orgMemberRoutes)
	app.route("/api", emergencyAccessRoutes)
	app.route("/api", eventRoutes)
	app.route("/api", miscRoutes)
	app.route("/events", eventCollectRoutes)
	app.route("/notifications", notificationRoutes)
	// attachmentDownloadRoutes declares its own full /attachments/... paths
	app.route("/", attachmentDownloadRoutes)
	app.route("/icons", iconRoutes)
	app.route("/admin", adminRoutes)
	app.get("/alive", (c) => c.json(new Date().toISOString()))

	// FIDO U2F trusted-facets document (vaultwarden web.rs app_id) — advertised
	// in WebAuthn login options for legacy-key compatibility.
	app.get("/app-id.json", (c) => {
		c.header("Content-Type", "application/fido.trusted-apps+json")
		c.header("Cache-Control", "public, max-age=604800")
		return c.body(
			JSON.stringify({
				trustedFacets: [
					{
						version: { major: 1, minor: 0 },
						ids: [
							new URL(c.get("config").domain).origin,
							"ios:bundle-id:com.8bit.bitwarden",
							"android:apk-key-hash:dUGFzUzf3lmHSLBDBIv+WaFyZMI"
						]
					}
				]
			})
		)
	})

	// iOS passkey/password AutoFill association (vaultwarden web.rs)
	app.get("/.well-known/apple-app-site-association", (c) => {
		c.header("Cache-Control", "public, max-age=604800")
		return c.json({
			webcredentials: {
				apps: ["LTZ2PFU5D6.com.8bit.bitwarden", "LTZ2PFU5D6.com.8bit.bitwarden.beta"]
			}
		})
	})

	return app
}

export type App = ReturnType<typeof createApp>
