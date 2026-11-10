import { and, asc, eq, exists, inArray, isNotNull, lt, not, sql } from "drizzle-orm"
import { chunk } from "es-toolkit"

import {
	attachments,
	authRequests,
	ciphers,
	createDb,
	sends,
	toDb,
	twofactorIncomplete
} from "../db"
import type { Bindings } from "../env"
import { purgeExpiredDuoContexts } from "../services/duo"
import { purgeExpiredSsoAuth } from "../services/sso"
import { getBlobStore } from "../services/storage"

// Free tier allows 50 subrequests (D1 queries, R2 and KV calls) per invocation. An item that needs
// blob cleanup costs about 2 (list + delete) and the rest of the job about 8, so 15 stay under 50.
export const MAX_PURGE_PER_RUN = 15

// D1 caps bound parameters per query (~100), same batch size as ciphers.ts.
const ID_BATCH = 90

function describeError(e: unknown): string {
	return e instanceof Error ? e.message : "unknown error"
}

/**
 * Cron jobs (vaultwarden's background tasks); both early-out when nothing to purge:
 *  - weekly Sunday 07:12 (`12 7 * * 1`, CF cron where 1=Sun): purge soft-deleted
 *    ciphers older than TRASH_AUTO_DELETE_DAYS
 *    NOTE: tweak back to daily cadence (`12 7 * * *`) — currently weekly.
 *  - every 15 min:  purge expired sends (and their blobs), expired auth
 *    requests, and stale incomplete-2FA records.
 */
export async function runScheduledJobs(
	controller: ScheduledController,
	env: Bindings
): Promise<void> {
	const db = createDb(env.VAULTUR_DB)
	const now = new Date()

	// Weekly (Sunday at 07:12 UTC; CF cron uses 1=Sun): purge soft-deleted ciphers.
	if (controller.cron.startsWith("12 7")) {
		const days = Number(env.TRASH_AUTO_DELETE_DAYS ?? "30")
		if (days <= 0) {
			return
		}
		const cutoff = toDb(new Date(now.getTime() - days * 24 * 60 * 60 * 1000))
		const trashed = and(isNotNull(ciphers.deletedAt), lt(ciphers.deletedAt, cutoff))
		const hasAttachments = exists(
			db
				.select({ one: sql`1` })
				.from(attachments)
				.where(eq(attachments.cipherUuid, ciphers.uuid))
		)
		// No attachments means no blobs to clean: one bulk delete, uncapped.
		await db.delete(ciphers).where(and(trashed, not(hasAttachments)))

		const withBlobs = await db
			.select({ uuid: ciphers.uuid })
			.from(ciphers)
			.where(and(trashed, hasAttachments))
			.orderBy(asc(ciphers.deletedAt))
			.limit(MAX_PURGE_PER_RUN)
		// Attachment blobs go before the row; a cipher whose blobs fail to delete keeps its row for the next run.
		const store = getBlobStore(env)
		const purged: string[] = []
		for (const c of withBlobs) {
			try {
				await store.deletePrefix(`attachments/${c.uuid}/`)
				purged.push(c.uuid)
			} catch (e) {
				console.error("Trash purge: attachment cleanup failed, will retry:", describeError(e))
			}
		}
		for (const batch of chunk(purged, ID_BATCH)) {
			await db.delete(ciphers).where(inArray(ciphers.uuid, batch))
		}
		return
	}

	// Every 15 minutes: purge sensitive expired data.
	// Probe first and early-out when nothing needs purging (avoids blob-store/DB writes).
	const nowStr = toDb(now)
	const expiredSends = await db
		.select({ uuid: sends.uuid, atype: sends.atype })
		.from(sends)
		.where(lt(sends.deletionDate, nowStr))
		.orderBy(asc(sends.deletionDate))
		.limit(MAX_PURGE_PER_RUN)

	const authCutoff = toDb(new Date(now.getTime() - 15 * 60 * 1000))
	const expiredAuth = await db
		.select({ uuid: authRequests.uuid })
		.from(authRequests)
		.where(and(lt(authRequests.creationDate, authCutoff), sql`${authRequests.approved} IS NULL`))
		.limit(1)

	const tfCutoff = toDb(new Date(now.getTime() - 24 * 60 * 60 * 1000))
	const expiredTf = await db
		.select({ loginTime: twofactorIncomplete.loginTime })
		.from(twofactorIncomplete)
		.where(lt(twofactorIncomplete.loginTime, tfCutoff))
		.limit(1)

	if (expiredSends.length === 0 && expiredAuth.length === 0 && expiredTf.length === 0) {
		return
	}

	// Purge expired sends and their blobs (file sends are keyed sends/<uuid>/)
	// A Send whose blob cleanup fails keeps its row and is retried on the next run.
	const store = getBlobStore(env)
	const purgedSends: string[] = []
	for (const s of expiredSends) {
		try {
			if (s.atype === 1) {
				await store.deletePrefix(`sends/${s.uuid}/`)
			}
			purgedSends.push(s.uuid)
		} catch (e) {
			console.error("Send purge: blob cleanup failed, will retry:", describeError(e))
		}
	}
	for (const batch of chunk(purgedSends, ID_BATCH)) {
		await db.delete(sends).where(inArray(sends.uuid, batch))
	}

	// Purge expired auth requests
	if (expiredAuth.length > 0) {
		await db
			.delete(authRequests)
			.where(and(lt(authRequests.creationDate, authCutoff), sql`${authRequests.approved} IS NULL`))
	}

	// Purge stale incomplete 2FA records
	if (expiredTf.length > 0) {
		await db.delete(twofactorIncomplete).where(lt(twofactorIncomplete.loginTime, tfCutoff))
	}

	// Purge expired Duo auth contexts and abandoned in-flight SSO logins
	await purgeExpiredDuoContexts(db)
	await purgeExpiredSsoAuth(db)
}
