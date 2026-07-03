import { eq } from "drizzle-orm"
import { Hono } from "hono"
import type { Context } from "hono"

import { requireAuth, auth } from "../auth/middleware"
import { users, type User } from "../db"
import type { AppEnv } from "../env"
import { Notify } from "../services/notify"
import { GLOBAL_EQUIVALENT_DOMAINS } from "../shared"
import { UpdateType } from "../shared"
import { ci } from "../util"

export function eqDomainsJson(user: User, excludeDisabled: boolean) {
	const excluded = new Set<number>(JSON.parse(user.excludedGlobals || "[]") as number[])
	const equivalentDomains = JSON.parse(user.equivalentDomains || "[]") as string[][]

	let globals = GLOBAL_EQUIVALENT_DOMAINS.map((g) => ({
		type: g.type,
		domains: g.domains,
		excluded: excluded.has(g.type)
	}))
	if (excludeDisabled) globals = globals.filter((g) => !g.excluded)

	return {
		equivalentDomains,
		globalEquivalentDomains: globals,
		object: "domains"
	}
}

export const domainRoutes = new Hono<AppEnv>()
domainRoutes.use("*", requireAuth)

domainRoutes.get("/settings/domains", (c) => {
	const { user } = auth(c)
	return c.json(eqDomainsJson(user, false))
})

async function postDomains(c: Context<AppEnv>) {
	const { user } = auth(c)
	const body = (await c.req.json()) as Record<string, unknown>
	const equivalentDomains = ci<string[][]>(body, "equivalentDomains") ?? []
	const excludedGlobals = ci<number[]>(body, "excludedGlobalEquivalentDomains") ?? []

	const db = c.get("db")
	await db
		.update(users)
		.set({
			equivalentDomains: JSON.stringify(equivalentDomains),
			excludedGlobals: JSON.stringify(excludedGlobals)
		})
		.where(eq(users.uuid, user.uuid))

	new Notify(c.env, c.get("config"), c.executionCtx).userUpdate(UpdateType.SyncSettings, user.uuid)

	return c.json({})
}

domainRoutes.post("/settings/domains", (c) => postDomains(c))
domainRoutes.put("/settings/domains", (c) => postDomains(c))
