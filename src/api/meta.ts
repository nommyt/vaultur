import { Hono } from "hono"

import type { AppEnv } from "../env"

const VERSION = "2025.12.0" // Bitwarden server version we emulate (matches vaultwarden)

export const metaRoutes = new Hono<AppEnv>()

metaRoutes.get("/alive", (c) => c.json(new Date().toISOString()))
metaRoutes.get("/now", (c) => c.json(new Date().toISOString()))
metaRoutes.get("/version", (c) => c.json(VERSION))

metaRoutes.get("/config", (c) => {
	const domain = c.get("config").domain
	return c.json({
		version: VERSION,
		gitHash: null,
		server: {
			name: "Vaultur",
			url: "https://github.com/nommyt/vaultur"
		},
		settings: {
			disableUserRegistration: !c.get("config").signupsAllowed
		},
		environment: {
			vault: domain,
			api: `${domain}/api`,
			identity: `${domain}/identity`,
			notifications: `${domain}/notifications`,
			sso: "",
			cloudRegion: null
		},
		push: {
			pushTechnology: 0,
			vapidPublicKey: null
		},
		featureStates: {
			"pm-19148-innovation-archive": true
		},
		object: "config"
	})
})
