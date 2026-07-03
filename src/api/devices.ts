import { and, eq } from "drizzle-orm"
import { Hono } from "hono"
import type { Context } from "hono"

import { requireAuth, auth } from "../auth/middleware"
import { devices, nowDb, toApi } from "../db"
import type { AppEnv } from "../env"
import { err, notFound } from "../error"
import { registerPushDevice } from "../services/push"
import { findUserByEmail } from "../services/users"
import { b64Decode, ci } from "../util"

export const deviceRoutes = new Hono<AppEnv>()

type Ctx = Context<AppEnv>

// ---------------------------------------------------------------------------
// Public: known-device probe (pre-login). Headers:
//   X-Device-Identifier, X-Request-Email (base64url, possibly padded)
// ---------------------------------------------------------------------------

deviceRoutes.get("/devices/knowndevice", async (c) => {
	const deviceId = c.req.header("X-Device-Identifier")
	const emailB64 = c.req.header("X-Request-Email")
	if (!deviceId || !emailB64) err("X-Device-Identifier and X-Request-Email headers are required")

	let email: string
	try {
		const normalized = emailB64.replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, "")
		email = new TextDecoder().decode(
			b64Decode(normalized + "=".repeat((4 - (normalized.length % 4)) % 4))
		)
	} catch {
		err("X-Request-Email value failed to decode as base64url")
	}

	const db = c.get("db")
	const user = await findUserByEmail(db, email)
	if (!user) return c.json(false)
	const device = await db.query.devices.findFirst({
		where: and(eq(devices.uuid, deviceId), eq(devices.userUuid, user.uuid))
	})
	return c.json(Boolean(device))
})

// ---------------------------------------------------------------------------
// Authenticated device management
// ---------------------------------------------------------------------------

deviceRoutes.use("*", requireAuth)

function deviceToJson(d: typeof devices.$inferSelect) {
	return {
		id: d.uuid,
		name: d.name,
		type: d.atype,
		identifier: d.uuid,
		creationDate: toApi(d.createdAt),
		isTrusted: false,
		object: "device"
	}
}

deviceRoutes.get("/devices", async (c) => {
	const { user } = auth(c)
	const rows = await c.get("db").query.devices.findMany({ where: eq(devices.userUuid, user.uuid) })
	return c.json({ data: rows.map(deviceToJson), object: "list", continuationToken: null })
})

deviceRoutes.get("/devices/identifier/:id", async (c) => {
	const { user } = auth(c)
	const row = await c.get("db").query.devices.findFirst({
		where: and(eq(devices.uuid, c.req.param("id")), eq(devices.userUuid, user.uuid))
	})
	if (!row) notFound("No device found")
	return c.json(deviceToJson(row))
})

async function putToken(c: Ctx) {
	const { user } = auth(c)
	const id = c.req.param("id")
	if (!id) notFound("No device found")
	const body = (await c.req.json()) as Record<string, unknown>
	const pushToken = ci<string>(body, "pushToken")
	if (!pushToken) err("pushToken cannot be blank")

	const db = c.get("db")
	const row = await db.query.devices.findFirst({
		where: and(eq(devices.uuid, id), eq(devices.userUuid, user.uuid))
	})
	if (!row) notFound("No device found")

	await db
		.update(devices)
		.set({ pushToken, updatedAt: nowDb() })
		.where(and(eq(devices.uuid, id), eq(devices.userUuid, user.uuid)))

	const config = c.get("config")
	if (config.pushEnabled) {
		c.executionCtx.waitUntil(
			registerPushDevice(c.env, config, { ...row, pushToken }).catch((e) =>
				console.error("push register", e)
			)
		)
	}
	return c.body(null, 200)
}
deviceRoutes.post("/devices/identifier/:id/token", putToken)
deviceRoutes.put("/devices/identifier/:id/token", putToken)

async function clearToken(c: Ctx) {
	const { user } = auth(c)
	const id = c.req.param("id")
	if (!id) notFound("No device found")
	const db = c.get("db")
	await db
		.update(devices)
		.set({ pushToken: null, updatedAt: nowDb() })
		.where(and(eq(devices.uuid, id), eq(devices.userUuid, user.uuid)))
	return c.body(null, 200)
}
deviceRoutes.post("/devices/identifier/:id/clear-token", clearToken)
deviceRoutes.put("/devices/identifier/:id/clear-token", clearToken)

// Deauthorize (remove) a device — used by the web vault device management page
deviceRoutes.delete("/devices/:id", async (c) => {
	const { user } = auth(c)
	const db = c.get("db")
	await db
		.delete(devices)
		.where(and(eq(devices.uuid, c.req.param("id")), eq(devices.userUuid, user.uuid)))
	return c.body(null, 200)
})
