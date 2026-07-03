import { and, eq, isNotNull, lt, sql } from "drizzle-orm"

import { authRequests, ciphers, createDb, sends, toDb, twofactorIncomplete } from "../db"
import type { Bindings } from "../env"
import { purgeExpiredDuoContexts } from "../services/duo"
import { purgeExpiredSsoAuth } from "../services/sso"

/**
 * Cron jobs (vaultwarden's background tasks); both early-out when nothing to purge:
 *  - weekly Sunday 07:12 (`12 7 * * 1`, CF cron where 1=Sun): purge soft-deleted
 *    ciphers older than TRASH_AUTO_DELETE_DAYS
 *    NOTE: tweak back to daily cadence (`12 7 * * *`) — currently weekly.
 *  - every 15 min:  purge expired sends (and their R2 objects), expired auth
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
		const expired = await db
			.select({ uuid: ciphers.uuid })
			.from(ciphers)
			.where(and(isNotNull(ciphers.deletedAt), lt(ciphers.deletedAt, cutoff)))
			.limit(1)
		if (expired.length === 0) {
			return
		}
		await db.delete(ciphers).where(and(isNotNull(ciphers.deletedAt), lt(ciphers.deletedAt, cutoff)))
		return
	}

	// Every 15 minutes: purge sensitive expired data.
	// Probe first and early-out when nothing needs purging (avoids R2/DB writes).
	const nowStr = toDb(now)
	const expiredSends = await db
		.select({ uuid: sends.uuid, atype: sends.atype })
		.from(sends)
		.where(lt(sends.deletionDate, nowStr))

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

	// Purge expired sends and their R2 objects (file sends are keyed sends/<uuid>/)
	for (const s of expiredSends) {
		if (s.atype === 1) {
			const list = await env.VAULTUR_FILES.list({ prefix: `sends/${s.uuid}/` })
			await Promise.all(list.objects.map((o) => env.VAULTUR_FILES.delete(o.key)))
		}
	}
	if (expiredSends.length > 0) {
		await db.delete(sends).where(lt(sends.deletionDate, nowStr))
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
