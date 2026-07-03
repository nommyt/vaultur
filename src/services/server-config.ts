/**
 * Persistence for admin-panel config overrides (the `server_config` D1 table).
 * A single JSON row is layered on top of the env-derived config on every
 * request, so it is read-through cached in the isolate for a short TTL and
 * busted immediately on save.
 */
import { eq } from "drizzle-orm"

import { serverConfig, nowDb, type Db } from "../db"

const ROW_ID = "singleton"
const TTL_MS = 10_000

let cache: { at: number; data: Record<string, unknown> } | null = null

/** Returns the stored overrides (read-through cached). Empty object if none. */
export async function getConfigOverrides(db: Db): Promise<Record<string, unknown>> {
	const now = Date.now()
	if (cache && now - cache.at < TTL_MS) return cache.data
	let data: Record<string, unknown> = {}
	try {
		const row = await db.query.serverConfig.findFirst({ where: eq(serverConfig.id, ROW_ID) })
		if (row?.json) {
			const parsed = JSON.parse(row.json) as unknown
			if (parsed && typeof parsed === "object") data = parsed as Record<string, unknown>
		}
	} catch {
		// Table may not exist yet (migration not applied); fall back to env-only.
		data = {}
	}
	cache = { at: now, data }
	return data
}

/** Persist a new overrides object and refresh the isolate cache. */
export async function saveConfigOverrides(db: Db, data: Record<string, unknown>): Promise<void> {
	const json = JSON.stringify(data)
	const updatedAt = nowDb()
	await db
		.insert(serverConfig)
		.values({ id: ROW_ID, json, updatedAt })
		.onConflictDoUpdate({ target: serverConfig.id, set: { json, updatedAt } })
	cache = { at: Date.now(), data }
}

/** Clear all overrides (reset to env defaults) and refresh the cache. */
export async function clearConfigOverrides(db: Db): Promise<void> {
	await db.delete(serverConfig).where(eq(serverConfig.id, ROW_ID))
	cache = { at: Date.now(), data: {} }
}
