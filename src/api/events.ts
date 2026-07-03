import { and, desc, eq, gte, lte } from "drizzle-orm"
import { Hono } from "hono"
import type { Context } from "hono"

import { requireAuth, auth } from "../auth/middleware"
import { ciphers, event, nowDb, toApi, toDb, type Db } from "../db"
import type { AppEnv } from "../env"
import { notFound } from "../error"
import { findConfirmedMembership, isAtLeast } from "../services/memberships"
import { MembershipType } from "../shared"
import { ci, uuid } from "../util"

/**
 * Event log endpoints, ported from vaultwarden src/api/core/events.rs.
 * Gated by ORG_EVENTS_ENABLED (vaultur default: on): when disabled, reads
 * return empty lists and collection is a no-op — nothing is recorded.
 */
export const eventRoutes = new Hono<AppEnv>()
export const eventCollectRoutes = new Hono<AppEnv>()

type Ctx = Context<AppEnv>

const EVENT_LIMIT = 300

const EMPTY_LIST = { data: [], object: "list", continuationToken: null }

function eventToJson(e: typeof event.$inferSelect) {
	return {
		type: e.eventType,
		userId: e.userUuid,
		organizationId: e.orgUuid,
		cipherId: e.cipherUuid,
		collectionId: e.collectionUuid,
		groupId: e.groupUuid,
		organizationUserId: e.orgUserUuid,
		actingUserId: e.actUserUuid,
		date: toApi(e.eventDate),
		deviceType: e.deviceType,
		ipAddress: e.ipAddress,
		policyId: e.policyUuid,
		providerId: e.providerUuid,
		providerUserId: e.providerUserUuid,
		providerOrganizationId: e.providerOrgUuid,
		installationId: null,
		systemUser: null,
		domainName: null,
		object: "event"
	}
}

function dateFilters(c: Ctx) {
	const start = c.req.query("start")
	const end = c.req.query("end")
	const filters = []
	if (start) filters.push(gte(event.eventDate, toDb(new Date(start))))
	if (end) filters.push(lte(event.eventDate, toDb(new Date(end))))
	return filters
}

eventRoutes.use("*", requireAuth)

eventRoutes.get("/organizations/:orgId/events", async (c) => {
	if (!c.get("config").orgEventsEnabled) return c.json(EMPTY_LIST)
	const { user } = auth(c)
	const orgId = c.req.param("orgId")
	if (!orgId) notFound("Organization doesn't exist")
	const member = await findConfirmedMembership(c.get("db"), user.uuid, orgId)
	if (!member || !isAtLeast(member.atype, MembershipType.Admin)) notFound("Not authorized")

	const rows = await c
		.get("db")
		.select()
		.from(event)
		.where(and(eq(event.orgUuid, orgId), ...dateFilters(c)))
		.orderBy(desc(event.eventDate))
		.limit(EVENT_LIMIT)
	return c.json({ data: rows.map(eventToJson), object: "list", continuationToken: null })
})

eventRoutes.get("/organizations/:orgId/users/:memberId/events", async (c) => {
	if (!c.get("config").orgEventsEnabled) return c.json(EMPTY_LIST)
	const { user } = auth(c)
	const orgId = c.req.param("orgId")!
	const member = await findConfirmedMembership(c.get("db"), user.uuid, orgId)
	if (!member || !isAtLeast(member.atype, MembershipType.Admin)) notFound("Not authorized")

	const rows = await c
		.get("db")
		.select()
		.from(event)
		.where(
			and(
				eq(event.orgUuid, orgId),
				eq(event.orgUserUuid, c.req.param("memberId")!),
				...dateFilters(c)
			)
		)
		.orderBy(desc(event.eventDate))
		.limit(EVENT_LIMIT)
	return c.json({ data: rows.map(eventToJson), object: "list", continuationToken: null })
})

eventRoutes.get("/ciphers/:id/events", async (c) => {
	if (!c.get("config").orgEventsEnabled) return c.json(EMPTY_LIST)
	const { user } = auth(c)
	const db = c.get("db")
	const cipher = await db.query.ciphers.findFirst({ where: eq(ciphers.uuid, c.req.param("id")!) })
	if (!cipher || !cipher.organizationUuid) notFound("Cipher doesn't exist")
	const member = await findConfirmedMembership(db, user.uuid, cipher.organizationUuid)
	if (!member || !isAtLeast(member.atype, MembershipType.Admin)) notFound("Not authorized")

	const rows = await db
		.select()
		.from(event)
		.where(and(eq(event.cipherUuid, cipher.uuid), ...dateFilters(c)))
		.orderBy(desc(event.eventDate))
		.limit(EVENT_LIMIT)
	return c.json({ data: rows.map(eventToJson), object: "list", continuationToken: null })
})

// ---------------------------------------------------------------------------
// Client event collection (POST /events/collect) — mounted at /events
// ---------------------------------------------------------------------------

async function collectHandler(c: Ctx) {
	if (!c.get("config").orgEventsEnabled) return c.body(null, 200)
	const { user, device } = auth(c)
	const db = c.get("db")
	const body = (await c.req.json()) as unknown
	const items = Array.isArray(body) ? (body as Record<string, unknown>[]) : []

	for (const item of items) {
		const type = Number(ci(item, "type") ?? -1)
		if (type < 0) continue
		const cipherId = (ci<string>(item, "cipherId") ?? null) as string | null
		const dateStr = ci<string>(item, "date")
		const orgId = (ci<string>(item, "organizationId") ?? null) as string | null

		// Resolve org for cipher-scoped client events
		let orgUuid = orgId
		if (cipherId && !orgUuid) {
			const cipher = await db.query.ciphers.findFirst({ where: eq(ciphers.uuid, cipherId) })
			orgUuid = cipher?.organizationUuid ?? null
		}
		if (!orgUuid) continue // vaultwarden only records events tied to an org

		await db.insert(event).values({
			uuid: uuid(),
			eventType: type,
			userUuid: user.uuid,
			orgUuid,
			cipherUuid: cipherId,
			actUserUuid: user.uuid,
			deviceType: device.atype,
			ipAddress: c.get("ip"),
			eventDate: dateStr ? toDb(new Date(dateStr)) : nowDb()
		})
	}
	return c.body(null, 200)
}

// Clients post events to /api/collect and (older) /events/collect.
eventRoutes.post("/collect", collectHandler)

eventCollectRoutes.use("*", requireAuth)
eventCollectRoutes.post("/collect", collectHandler)
