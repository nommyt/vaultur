import { and, asc, eq, exists, inArray, isNull, lt, sql } from "drizzle-orm"

import {
	attachments,
	authRequests,
	ciphers,
	createDb,
	pendingBlobDeletions,
	sends,
	toDb,
	twofactorIncomplete,
	type Db
} from "../db"
import type { Bindings } from "../env"
import { purgeExpiredDuoContexts } from "../services/duo"
import { purgeExpiredSsoAuth } from "../services/sso"
import { getBlobStore } from "../services/storage"
import { SendType } from "../shared/constants"

// Bound the storage work per invocation and keep each IN() below D1's parameter limit.
export const MAX_PURGE_PER_RUN = 15

async function drainBlobDeletions(db: Db, env: Bindings): Promise<void> {
	const pending = await db
		.select({ prefix: pendingBlobDeletions.prefix })
		.from(pendingBlobDeletions)
		.orderBy(asc(pendingBlobDeletions.attempts), asc(pendingBlobDeletions.prefix))
		.limit(MAX_PURGE_PER_RUN)

	const store = getBlobStore(env)
	const completed: string[] = []
	const failed: string[] = []
	for (const { prefix } of pending) {
		try {
			await store.deletePrefix(prefix)
			completed.push(prefix)
		} catch (error) {
			failed.push(prefix)
			console.error(
				"Blob cleanup failed, will retry:",
				error instanceof Error ? error.message : error
			)
		}
	}
	if (completed.length > 0) {
		await db.delete(pendingBlobDeletions).where(inArray(pendingBlobDeletions.prefix, completed))
	}
	if (failed.length > 0) {
		await db
			.update(pendingBlobDeletions)
			.set({ attempts: sql`${pendingBlobDeletions.attempts} + 1` })
			.where(inArray(pendingBlobDeletions.prefix, failed))
	}
}

export async function runScheduledJobs(
	controller: ScheduledController,
	env: Bindings
): Promise<void> {
	const db = createDb(env.VAULTUR_DB)
	const now = Date.now()

	// Weekly (Sunday at 07:12 UTC; Cloudflare cron uses 1=Sun): purge old trash.
	if (controller.cron.startsWith("12 7")) {
		const days = Number(env.TRASH_AUTO_DELETE_DAYS ?? "30")
		if (!Number.isFinite(days) || days <= 0) return
		const cutoff = toDb(new Date(now - days * 24 * 60 * 60 * 1000))
		const trashed = lt(ciphers.deletedAt, cutoff)
		const hasAttachments = exists(
			db
				.select({ one: sql`1` })
				.from(attachments)
				.where(eq(attachments.cipherUuid, ciphers.uuid))
		)
		// Queue blobs and remove the corresponding records in the same D1 transaction.
		// A restore that commits first excludes the cipher from both statements.
		await db.batch([
			db.insert(pendingBlobDeletions).select(
				db
					.select({
						prefix: sql<string>`'attachments/' || ${ciphers.uuid} || '/'`.as("prefix"),
						attempts: sql<number>`0`.as("attempts")
					})
					.from(ciphers)
					.where(and(trashed, hasAttachments))
			),
			db.delete(ciphers).where(trashed)
		])
		await drainBlobDeletions(db, env)
		return
	}

	// Every 15 minutes: purge expired records and drain queued blob deletions from either schedule.
	const expiredSends = db
		.select({ uuid: sends.uuid })
		.from(sends)
		.where(lt(sends.deletionDate, toDb(new Date(now))))
		.orderBy(asc(sends.deletionDate), asc(sends.uuid))
		.limit(MAX_PURGE_PER_RUN)
	const dueForDeletion = inArray(sends.uuid, expiredSends)
	const authCutoff = toDb(new Date(now - 15 * 60 * 1000))
	const tfCutoff = toDb(new Date(now - 24 * 60 * 60 * 1000))

	await db.batch([
		db.insert(pendingBlobDeletions).select(
			db
				.select({
					prefix: sql<string>`'sends/' || ${sends.uuid} || '/'`.as("prefix"),
					attempts: sql<number>`0`.as("attempts")
				})
				.from(sends)
				.where(and(dueForDeletion, eq(sends.atype, SendType.File)))
		),
		db.delete(sends).where(dueForDeletion),
		db
			.delete(authRequests)
			.where(and(lt(authRequests.creationDate, authCutoff), isNull(authRequests.approved))),
		db.delete(twofactorIncomplete).where(lt(twofactorIncomplete.loginTime, tfCutoff))
	])
	await purgeExpiredDuoContexts(db)
	await purgeExpiredSsoAuth(db)
	await drainBlobDeletions(db, env)
}
