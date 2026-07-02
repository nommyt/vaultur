import { and, eq, isNotNull, lt, sql } from 'drizzle-orm';
import { authRequests, ciphers, createDb, sends, toDb, twofactorIncomplete } from '@vaultur/db';
import type { Bindings } from '../env';

/**
 * Cron jobs (vaultwarden's background tasks):
 *  - daily:    purge soft-deleted ciphers older than TRASH_AUTO_DELETE_DAYS
 *  - 15-min:   purge expired sends, expired auth requests, alert incomplete 2FA logins
 */
export async function runScheduledJobs(
  controller: ScheduledController,
  env: Bindings,
): Promise<void> {
  const db = createDb(env.DB);
  const now = new Date();

  if (controller.cron.startsWith('11 3')) {
    const days = Number(env.TRASH_AUTO_DELETE_DAYS ?? '30');
    if (days > 0) {
      const cutoff = toDb(new Date(now.getTime() - days * 24 * 60 * 60 * 1000));
      await db
        .delete(ciphers)
        .where(and(isNotNull(ciphers.deletedAt), lt(ciphers.deletedAt, cutoff)));
    }
    return;
  }

  // Every 15 minutes
  const nowStr = toDb(now);
  // Purge sends past their deletion date (R2 objects are keyed send/<uuid>; cleaned lazily)
  const expired = await db
    .select({ uuid: sends.uuid, atype: sends.atype })
    .from(sends)
    .where(lt(sends.deletionDate, nowStr));
  for (const s of expired) {
    if (s.atype === 1) {
      // File send: delete stored objects under sends/<uuid>/
      const list = await env.FILES.list({ prefix: `sends/${s.uuid}/` });
      await Promise.all(list.objects.map((o) => env.FILES.delete(o.key)));
    }
  }
  if (expired.length > 0) {
    await db.delete(sends).where(lt(sends.deletionDate, nowStr));
  }

  // Expired auth requests (older than 15 minutes, per vaultwarden purge job ~ daily; we do 15m granularity)
  const authCutoff = toDb(new Date(now.getTime() - 15 * 60 * 1000));
  await db
    .delete(authRequests)
    .where(and(lt(authRequests.creationDate, authCutoff), sql`${authRequests.approved} IS NULL`));

  // Incomplete 2FA logins older than the alert window are cleaned up
  const tfCutoff = toDb(new Date(now.getTime() - 24 * 60 * 60 * 1000));
  await db.delete(twofactorIncomplete).where(lt(twofactorIncomplete.loginTime, tfCutoff));
}
