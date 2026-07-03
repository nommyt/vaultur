import type { Config } from "../config"
import { event, nowDb, type Db } from "../db"
import { uuid } from "../util"

/**
 * Event logging (vaultwarden log_user_event / log_event). Best-effort; writes
 * are skipped entirely when the admin disables the event log
 * (ORG_EVENTS_ENABLED), matching vaultwarden.
 */
export async function logUserEvent(
	db: Db,
	config: Config,
	eventType: number,
	userUuid: string,
	deviceType: number | null,
	ip: string
): Promise<void> {
	if (!config.orgEventsEnabled) return
	try {
		await db.insert(event).values({
			uuid: uuid(),
			eventType,
			userUuid,
			actUserUuid: userUuid,
			deviceType,
			ipAddress: ip,
			eventDate: nowDb()
		})
	} catch (e) {
		console.error("Failed to log user event", e)
	}
}

export interface OrgEventInput {
	eventType: number
	orgUuid: string
	actUserUuid: string
	deviceType?: number | null
	ip: string
	cipherUuid?: string | null
	collectionUuid?: string | null
	groupUuid?: string | null
	orgUserUuid?: string | null
	policyUuid?: string | null
}

/** Append an organization event row (vaultwarden log_event). Best-effort. */
export async function logOrgEvent(db: Db, config: Config, input: OrgEventInput): Promise<void> {
	if (!config.orgEventsEnabled) return
	try {
		await db.insert(event).values({
			uuid: uuid(),
			eventType: input.eventType,
			orgUuid: input.orgUuid,
			actUserUuid: input.actUserUuid,
			deviceType: input.deviceType ?? null,
			ipAddress: input.ip,
			eventDate: nowDb(),
			cipherUuid: input.cipherUuid ?? null,
			collectionUuid: input.collectionUuid ?? null,
			groupUuid: input.groupUuid ?? null,
			orgUserUuid: input.orgUserUuid ?? null,
			policyUuid: input.policyUuid ?? null
		})
	} catch (e) {
		console.error("Failed to log org event", e)
	}
}
