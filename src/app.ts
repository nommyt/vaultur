import { Hono } from "hono"

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
import { loadConfig } from "./config"
import { applyOverrides } from "./config-schema"
import { createDb } from "./db"
import type { AppEnv } from "./env"
import { onError, errorBody } from "./error"
import { getConfigOverrides } from "./services/server-config"

export function createApp() {
	const app = new Hono<AppEnv>()

	app.use(async (c, next) => {
		const db = createDb(c.env.VAULTUR_DB)
		c.set("db", db)
		const base = loadConfig(c.env, c.req.url)
		const overrides = await getConfigOverrides(db)
		c.set("config", applyOverrides(base, overrides))
		c.set("ip", c.req.header("CF-Connecting-IP") ?? "0.0.0.0")
		await next()
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

	return app
}

export type App = ReturnType<typeof createApp>
