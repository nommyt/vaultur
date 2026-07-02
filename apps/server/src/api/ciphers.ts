import { Hono } from 'hono';
import type { Context } from 'hono';
import { and, eq, inArray, isNull } from 'drizzle-orm';
import {
  archives,
  ciphers,
  ciphersCollections,
  collections,
  folders,
  foldersCiphers,
  nowDb,
  users,
  type Cipher,
} from '@vaultur/db';
import { EventType, UpdateType } from '@vaultur/shared';
import type { AppEnv } from '../env';
import { requireAuth, auth } from '../auth/middleware';
import { err, notFound } from '../error';
import { verifyPassword } from '../crypto';
import { ci, uuid } from '../util';
import {
  deleteCipher,
  newCipherShell,
  parseCipherData,
  setFavorite,
  updateCipherFromData,
  updateUsersRevisionForCipher,
  usersWithCipherAccess,
  moveToFolder,
  enforcePersonalOwnershipPolicy,
  type CipherData,
} from '../services/ciphers';
import {
  cipherToJson,
  findCiphersVisibleToUser,
  getAccessRestrictions,
  loadCipherSyncData,
} from '../services/vault';
import { hasFullAccess, findConfirmedMembership } from '../services/memberships';
import { touchUser } from '../services/users';
import { Notify } from '../services/notify';
import { logOrgEvent, logUserEvent } from '../services/events';

export const cipherRoutes = new Hono<AppEnv>();
cipherRoutes.use('*', requireAuth);

type Ctx = Context<AppEnv>;

async function jsonOptions(c: Ctx, userUuid: string) {
  const sync = await loadCipherSyncData(c.get('db'), userUuid, 'user');
  return { config: c.get('config'), secret: c.env.JWT_SECRET, userUuid, sync, syncType: 'user' as const };
}

async function loadCipher(c: Ctx, id: string | undefined): Promise<Cipher> {
  if (!id) notFound("Cipher doesn't exist");
  const row = await c.get('db').query.ciphers.findFirst({ where: eq(ciphers.uuid, id) });
  if (!row) notFound("Cipher doesn't exist");
  return row;
}

async function loadAccessibleCipher(c: Ctx, id: string | undefined, write: boolean): Promise<Cipher> {
  const { user } = auth(c);
  const cipher = await loadCipher(c, id);
  const sync = await loadCipherSyncData(c.get('db'), user.uuid, 'user');
  const access = getAccessRestrictions(cipher, user.uuid, sync);
  if (!access) notFound('Cipher is not owned by user');
  if (write && access.readOnly) err('Cipher is not write accessible');
  return cipher;
}

function notifier(c: Ctx): Notify {
  return new Notify(c.env, c.get('config'), c.executionCtx);
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

cipherRoutes.get('/ciphers', async (c) => {
  const { user } = auth(c);
  const db = c.get('db');
  const opts = await jsonOptions(c, user.uuid);
  const rows = await findCiphersVisibleToUser(db, user.uuid, opts.sync);
  const data = await Promise.all(rows.map((r) => cipherToJson(r, opts)));
  return c.json({ data, object: 'list', continuationToken: null });
});

cipherRoutes.get('/ciphers/:id', async (c) => {
  const { user } = auth(c);
  const cipher = await loadAccessibleCipher(c, c.req.param('id'), false);
  return c.json(await cipherToJson(cipher, await jsonOptions(c, user.uuid)));
});

cipherRoutes.get('/ciphers/:id/admin', async (c) => {
  const { user } = auth(c);
  const cipher = await loadCipher(c, c.req.param('id'));
  if (cipher.organizationUuid) {
    const member = await findConfirmedMembership(c.get('db'), user.uuid, cipher.organizationUuid);
    if (!member || !hasFullAccess(member)) err('Cipher is not accessible');
  }
  return c.json(await cipherToJson(cipher, await jsonOptions(c, user.uuid)));
});

cipherRoutes.get('/ciphers/:id/details', async (c) => {
  const { user } = auth(c);
  const cipher = await loadAccessibleCipher(c, c.req.param('id'), false);
  return c.json(await cipherToJson(cipher, await jsonOptions(c, user.uuid)));
});

// ---------------------------------------------------------------------------
// Create / update
// ---------------------------------------------------------------------------

async function createCipher(c: Ctx, data: CipherData, collectionIds?: string[]) {
  const { user, device } = auth(c);
  const db = c.get('db');

  const cipher = newCipherShell(data.type, data.name);
  await updateCipherFromData(cipher, data, { db, userUuid: user.uuid }, {
    sharedToCollections: collectionIds,
    skipRevisionCheck: true,
  });

  if (cipher.organizationUuid && collectionIds && collectionIds.length > 0) {
    const validCollections = await db
      .select({ uuid: collections.uuid })
      .from(collections)
      .where(and(inArray(collections.uuid, collectionIds), eq(collections.orgUuid, cipher.organizationUuid)));
    for (const col of validCollections) {
      await db.insert(ciphersCollections).values({ cipherUuid: cipher.uuid, collectionUuid: col.uuid }).onConflictDoNothing();
    }
    await logOrgEvent(db, {
      eventType: EventType.CipherCreated,
      orgUuid: cipher.organizationUuid,
      actUserUuid: user.uuid,
      cipherUuid: cipher.uuid,
      deviceType: device.atype,
      ip: c.get('ip'),
    });
  }

  const affected = await usersWithCipherAccess(db, cipher);
  notifier(c).cipherUpdate(UpdateType.SyncCipherCreate, cipher, affected, device.uuid);

  return c.json(await cipherToJson(cipher, await jsonOptions(c, user.uuid)));
}

// POST /ciphers — personal create (data may still carry an orgId for direct org add)
cipherRoutes.post('/ciphers', async (c) => {
  const body = (await c.req.json()) as Record<string, unknown>;
  const data = parseCipherData(body);
  // vaultwarden's post_ciphers clears these to enforce the plain create path
  data.lastKnownRevisionDate = null;
  return createCipher(c, data);
});

// POST /ciphers/create — { cipher, collectionIds } org-aware create
cipherRoutes.post('/ciphers/create', async (c) => {
  const body = (await c.req.json()) as Record<string, unknown>;
  const cipherBody = (ci<Record<string, unknown>>(body, 'cipher') ?? body) as Record<string, unknown>;
  const collectionIds = ci<string[]>(body, 'collectionIds') ?? [];
  const data = parseCipherData(cipherBody);
  if (data.organizationId && collectionIds.length === 0) {
    err('You must select at least one collection.');
  }
  return createCipher(c, data, collectionIds);
});

async function updateCipherHandler(c: Ctx) {
  const { user, device } = auth(c);
  const db = c.get('db');
  const cipher = await loadAccessibleCipher(c, c.req.param('id'), true);
  const data = parseCipherData((await c.req.json()) as Record<string, unknown>);

  await updateCipherFromData(cipher, data, { db, userUuid: user.uuid });

  const affected = await usersWithCipherAccess(db, cipher);
  notifier(c).cipherUpdate(UpdateType.SyncCipherUpdate, cipher, affected, device.uuid);
  if (cipher.organizationUuid) {
    await logOrgEvent(db, {
      eventType: EventType.CipherUpdated,
      orgUuid: cipher.organizationUuid,
      actUserUuid: user.uuid,
      cipherUuid: cipher.uuid,
      deviceType: device.atype,
      ip: c.get('ip'),
    });
  }

  return c.json(await cipherToJson(cipher, await jsonOptions(c, user.uuid)));
}

cipherRoutes.put('/ciphers/:id/admin', updateCipherHandler);
cipherRoutes.post('/ciphers/:id/admin', updateCipherHandler);
// NOTE: bare `/ciphers/:id` PUT/POST/DELETE registrations live at the bottom of
// this file so static routes (/ciphers/move, /ciphers/import, …) match first.

// Partial update: folder + favorite (+ archived)
async function partialUpdate(c: Ctx) {
  const { user } = auth(c);
  const db = c.get('db');
  const cipher = await loadAccessibleCipher(c, c.req.param('id'), false);
  const body = (await c.req.json()) as Record<string, unknown>;
  const folderId = (ci<string>(body, 'folderId') || null) as string | null;
  const favorite = Boolean(ci(body, 'favorite'));

  if (folderId) {
    const folder = await db.query.folders.findFirst({
      where: and(eq(folders.uuid, folderId), eq(folders.userUuid, user.uuid)),
    });
    if (!folder) err('Folder doesn\'t exist');
  }

  await moveToFolder(db, cipher.uuid, folderId, user.uuid);
  await setFavorite(db, cipher.uuid, user.uuid, favorite);
  await touchUser(db, user.uuid);

  return c.json(await cipherToJson(cipher, await jsonOptions(c, user.uuid)));
}

cipherRoutes.put('/ciphers/:id/partial', partialUpdate);
cipherRoutes.post('/ciphers/:id/partial', partialUpdate);

// ---------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------

cipherRoutes.post('/ciphers/import', async (c) => {
  const { user, device } = auth(c);
  const db = c.get('db');
  const body = (await c.req.json()) as Record<string, unknown>;

  const folderData = ci<Record<string, unknown>[]>(body, 'folders') ?? [];
  const cipherData = ci<Record<string, unknown>[]>(body, 'ciphers') ?? [];
  const relationships = ci<{ key: number; value: number }[]>(body, 'folderRelationships') ?? [];

  await enforcePersonalOwnershipPolicy(db, user.uuid, null);

  // Existing folders can be referenced by id; new ones are created
  const folderIds: string[] = [];
  for (const f of folderData) {
    const existingId = ci<string>(f, 'id');
    if (existingId) {
      const existing = await db.query.folders.findFirst({
        where: and(eq(folders.uuid, existingId), eq(folders.userUuid, user.uuid)),
      });
      if (existing) {
        folderIds.push(existing.uuid);
        continue;
      }
    }
    const now = nowDb();
    const folder = { uuid: uuid(), createdAt: now, updatedAt: now, userUuid: user.uuid, name: String(ci(f, 'name') ?? '') };
    await db.insert(folders).values(folder);
    folderIds.push(folder.uuid);
  }

  const relMap = new Map<number, number>();
  for (const rel of relationships) relMap.set(rel.key, rel.value);

  const sync = await loadCipherSyncData(db, user.uuid, 'user');
  for (let i = 0; i < cipherData.length; i++) {
    const data = parseCipherData(cipherData[i]!);
    data.folderId = relMap.has(i) ? (folderIds[relMap.get(i)!] ?? null) : null;
    // vaultwarden skips the revision check on import
    data.lastKnownRevisionDate = null;
    const cipher = newCipherShell(data.type, data.name);
    await updateCipherFromData(cipher, data, { db, userUuid: user.uuid, sync }, { skipRevisionCheck: true });
  }

  await touchUser(db, user.uuid);
  notifier(c).userUpdate(UpdateType.SyncVault, user.uuid);
  await logUserEvent(db, EventType.UserClientExportedVault, user.uuid, device.atype, c.get('ip'));
  return c.body(null, 200);
});

// ---------------------------------------------------------------------------
// Share
// ---------------------------------------------------------------------------

async function shareCipher(c: Ctx, cipherId: string, body: Record<string, unknown>) {
  const { user, device } = auth(c);
  const db = c.get('db');

  const cipherBody = ci<Record<string, unknown>>(body, 'cipher');
  const collectionIds = ci<string[]>(body, 'collectionIds') ?? [];
  if (!cipherBody) err('Cipher data missing');
  if (collectionIds.length === 0) err('You must select at least one collection.');

  const data = parseCipherData(cipherBody);
  if (!data.organizationId) err('Organization id not provided');

  const cipher = await loadAccessibleCipher(c, cipherId, true);

  const validCollections = await db
    .select({ uuid: collections.uuid })
    .from(collections)
    .where(and(inArray(collections.uuid, collectionIds), eq(collections.orgUuid, data.organizationId!)));
  if (validCollections.length === 0) err('No valid collections provided');

  await updateCipherFromData(cipher, data, { db, userUuid: user.uuid }, { sharedToCollections: collectionIds });

  await db.delete(ciphersCollections).where(eq(ciphersCollections.cipherUuid, cipher.uuid));
  for (const col of validCollections) {
    await db.insert(ciphersCollections).values({ cipherUuid: cipher.uuid, collectionUuid: col.uuid }).onConflictDoNothing();
  }

  const affected = await usersWithCipherAccess(db, cipher);
  notifier(c).cipherUpdate(UpdateType.SyncCipherUpdate, cipher, affected, device.uuid);
  await logOrgEvent(db, {
    eventType: EventType.CipherShared,
    orgUuid: cipher.organizationUuid!,
    actUserUuid: user.uuid,
    cipherUuid: cipher.uuid,
    deviceType: device.atype,
    ip: c.get('ip'),
  });

  return c.json(await cipherToJson(cipher, await jsonOptions(c, user.uuid)));
}

cipherRoutes.post('/ciphers/:id/share', async (c) =>
  shareCipher(c, c.req.param('id'), (await c.req.json()) as Record<string, unknown>),
);
cipherRoutes.put('/ciphers/:id/share', async (c) =>
  shareCipher(c, c.req.param('id'), (await c.req.json()) as Record<string, unknown>),
);

cipherRoutes.put('/ciphers/share', async (c) => {
  const { user } = auth(c);
  const body = (await c.req.json()) as Record<string, unknown>;
  const cipherBodies = ci<Record<string, unknown>[]>(body, 'ciphers') ?? [];
  const collectionIds = ci<string[]>(body, 'collectionIds') ?? [];
  for (const cb of cipherBodies) {
    const id = ci<string>(cb, 'id');
    if (!id) err('Request missing ids field');
    await shareCipher(c, id, { cipher: cb, collectionIds });
  }
  return c.body(null, 200);
});

// ---------------------------------------------------------------------------
// Collections membership
// ---------------------------------------------------------------------------

async function updateCipherCollections(c: Ctx) {
  const { user, device } = auth(c);
  const db = c.get('db');
  const cipher = await loadAccessibleCipher(c, c.req.param('id'), true);
  if (!cipher.organizationUuid) err('Cipher is not organization owned');

  const body = (await c.req.json()) as Record<string, unknown>;
  const collectionIds = new Set(ci<string[]>(body, 'collectionIds') ?? []);

  const current = new Set(
    (await db.select().from(ciphersCollections).where(eq(ciphersCollections.cipherUuid, cipher.uuid))).map(
      (r) => r.collectionUuid,
    ),
  );

  const sync = await loadCipherSyncData(db, user.uuid, 'user');
  const member = sync.members.get(cipher.organizationUuid!);

  for (const target of new Set([...collectionIds, ...current])) {
    const col = await db.query.collections.findFirst({ where: eq(collections.uuid, target) });
    if (!col || col.orgUuid !== cipher.organizationUuid) continue;
    // Only allow changing collections the user can access
    const accessible =
      (member && hasFullAccess(member)) || sync.userCollections.has(target) || sync.userCollectionsGroups.has(target);
    if (!accessible) continue;

    if (collectionIds.has(target) && !current.has(target)) {
      await db.insert(ciphersCollections).values({ cipherUuid: cipher.uuid, collectionUuid: target }).onConflictDoNothing();
    } else if (!collectionIds.has(target) && current.has(target)) {
      await db
        .delete(ciphersCollections)
        .where(and(eq(ciphersCollections.cipherUuid, cipher.uuid), eq(ciphersCollections.collectionUuid, target)));
    }
  }

  const affected = await updateUsersRevisionForCipher(db, cipher);
  notifier(c).cipherUpdate(UpdateType.SyncCipherUpdate, cipher, affected, device.uuid);
  await logOrgEvent(db, {
    eventType: EventType.CipherUpdatedCollections,
    orgUuid: cipher.organizationUuid!,
    actUserUuid: user.uuid,
    cipherUuid: cipher.uuid,
    deviceType: device.atype,
    ip: c.get('ip'),
  });
  return c.json(await cipherToJson(cipher, await jsonOptions(c, user.uuid)));
}

cipherRoutes.post('/ciphers/:id/collections', updateCipherCollections);
cipherRoutes.put('/ciphers/:id/collections', updateCipherCollections);
cipherRoutes.post('/ciphers/:id/collections_v2', updateCipherCollections);
cipherRoutes.put('/ciphers/:id/collections_v2', updateCipherCollections);
cipherRoutes.post('/ciphers/:id/collections-admin', updateCipherCollections);
cipherRoutes.put('/ciphers/:id/collections-admin', updateCipherCollections);

// ---------------------------------------------------------------------------
// Delete / restore / archive
// ---------------------------------------------------------------------------

async function softDelete(c: Ctx, cipher: Cipher) {
  const db = c.get('db');
  const { user, device } = auth(c);
  cipher.deletedAt = nowDb();
  cipher.updatedAt = cipher.deletedAt;
  await db.update(ciphers).set({ deletedAt: cipher.deletedAt, updatedAt: cipher.updatedAt }).where(eq(ciphers.uuid, cipher.uuid));
  const affected = await updateUsersRevisionForCipher(db, cipher);
  notifier(c).cipherUpdate(UpdateType.SyncCipherUpdate, cipher, affected, device.uuid);
  if (cipher.organizationUuid) {
    await logOrgEvent(db, {
      eventType: EventType.CipherSoftDeleted,
      orgUuid: cipher.organizationUuid,
      actUserUuid: user.uuid,
      cipherUuid: cipher.uuid,
      deviceType: device.atype,
      ip: c.get('ip'),
    });
  }
}

async function hardDelete(c: Ctx, cipher: Cipher) {
  const db = c.get('db');
  const { user, device } = auth(c);
  const affected = await usersWithCipherAccess(db, cipher);
  await deleteCipher(db, c.env.FILES, cipher);
  notifier(c).cipherUpdate(UpdateType.SyncCipherDelete, cipher, affected, device.uuid);
  if (cipher.organizationUuid) {
    await logOrgEvent(db, {
      eventType: EventType.CipherDeleted,
      orgUuid: cipher.organizationUuid,
      actUserUuid: user.uuid,
      cipherUuid: cipher.uuid,
      deviceType: device.atype,
      ip: c.get('ip'),
    });
  }
}

async function restore(c: Ctx, cipher: Cipher) {
  const db = c.get('db');
  const { user, device } = auth(c);
  cipher.deletedAt = null;
  cipher.updatedAt = nowDb();
  await db.update(ciphers).set({ deletedAt: null, updatedAt: cipher.updatedAt }).where(eq(ciphers.uuid, cipher.uuid));
  const affected = await updateUsersRevisionForCipher(db, cipher);
  notifier(c).cipherUpdate(UpdateType.SyncCipherUpdate, cipher, affected, device.uuid);
  if (cipher.organizationUuid) {
    await logOrgEvent(db, {
      eventType: EventType.CipherRestored,
      orgUuid: cipher.organizationUuid,
      actUserUuid: user.uuid,
      cipherUuid: cipher.uuid,
      deviceType: device.atype,
      ip: c.get('ip'),
    });
  }
}

// Single soft delete
cipherRoutes.put('/ciphers/:id/delete', async (c) => {
  const cipher = await loadAccessibleCipher(c, c.req.param('id'), true);
  await softDelete(c, cipher);
  return c.body(null, 200);
});
cipherRoutes.put('/ciphers/:id/delete-admin', async (c) => {
  const cipher = await loadAccessibleCipher(c, c.req.param('id'), true);
  await softDelete(c, cipher);
  return c.body(null, 200);
});

// Single hard delete
async function hardDeleteHandler(c: Ctx) {
  const cipher = await loadAccessibleCipher(c, c.req.param('id'), true);
  await hardDelete(c, cipher);
  return c.body(null, 200);
}
cipherRoutes.post('/ciphers/:id/delete', hardDeleteHandler);
cipherRoutes.delete('/ciphers/:id/admin', hardDeleteHandler);
cipherRoutes.post('/ciphers/:id/delete-admin', hardDeleteHandler);

async function bulkIds(c: Ctx): Promise<string[]> {
  const body = (await c.req.json()) as Record<string, unknown>;
  const ids = ci<string[]>(body, 'ids');
  if (!ids || ids.length === 0) err('Request missing ids field');
  return ids;
}

// Bulk soft delete
cipherRoutes.put('/ciphers/delete', async (c) => {
  for (const id of await bulkIds(c)) {
    const cipher = await loadAccessibleCipher(c, id, true);
    await softDelete(c, cipher);
  }
  return c.body(null, 200);
});

// Bulk hard delete
async function bulkHardDelete(c: Ctx) {
  for (const id of await bulkIds(c)) {
    const cipher = await loadAccessibleCipher(c, id, true);
    await hardDelete(c, cipher);
  }
  return c.body(null, 200);
}
cipherRoutes.delete('/ciphers', bulkHardDelete);
cipherRoutes.post('/ciphers/delete', bulkHardDelete);
cipherRoutes.delete('/ciphers/admin', bulkHardDelete);
cipherRoutes.post('/ciphers/delete-admin', bulkHardDelete);

// Restore
cipherRoutes.put('/ciphers/:id/restore', async (c) => {
  const cipher = await loadAccessibleCipher(c, c.req.param('id'), true);
  await restore(c, cipher);
  const { user } = auth(c);
  return c.json(await cipherToJson(cipher, await jsonOptions(c, user.uuid)));
});
cipherRoutes.put('/ciphers/:id/restore-admin', async (c) => {
  const cipher = await loadAccessibleCipher(c, c.req.param('id'), true);
  await restore(c, cipher);
  const { user } = auth(c);
  return c.json(await cipherToJson(cipher, await jsonOptions(c, user.uuid)));
});
cipherRoutes.put('/ciphers/restore', async (c) => {
  const { user } = auth(c);
  const ids = await bulkIds(c);
  const restored = [];
  for (const id of ids) {
    const cipher = await loadAccessibleCipher(c, id, true);
    await restore(c, cipher);
    restored.push(cipher);
  }
  const opts = await jsonOptions(c, user.uuid);
  return c.json({
    data: await Promise.all(restored.map((r) => cipherToJson(r, opts))),
    object: 'list',
    continuationToken: null,
  });
});

// Archive / unarchive
async function setArchived(c: Ctx, ids: string[], archived: boolean) {
  const { user } = auth(c);
  const db = c.get('db');
  for (const id of ids) {
    const cipher = await loadAccessibleCipher(c, id, true);
    if (archived) {
      await db
        .insert(archives)
        .values({ userUuid: user.uuid, cipherUuid: cipher.uuid, archivedAt: nowDb() })
        .onConflictDoNothing();
    } else {
      await db.delete(archives).where(and(eq(archives.userUuid, user.uuid), eq(archives.cipherUuid, cipher.uuid)));
    }
    await db.update(ciphers).set({ updatedAt: nowDb() }).where(eq(ciphers.uuid, cipher.uuid));
  }
  await touchUser(db, user.uuid);
  notifier(c).userUpdate(UpdateType.SyncCiphers, user.uuid);
}

cipherRoutes.put('/ciphers/:id/archive', async (c) => {
  await setArchived(c, [c.req.param('id')], true);
  const { user } = auth(c);
  const cipher = await loadCipher(c, c.req.param('id'));
  return c.json(await cipherToJson(cipher, await jsonOptions(c, user.uuid)));
});
cipherRoutes.put('/ciphers/:id/unarchive', async (c) => {
  await setArchived(c, [c.req.param('id')], false);
  const { user } = auth(c);
  const cipher = await loadCipher(c, c.req.param('id'));
  return c.json(await cipherToJson(cipher, await jsonOptions(c, user.uuid)));
});
cipherRoutes.put('/ciphers/archive', async (c) => {
  await setArchived(c, await bulkIds(c), true);
  return c.body(null, 200);
});
cipherRoutes.put('/ciphers/unarchive', async (c) => {
  await setArchived(c, await bulkIds(c), false);
  return c.body(null, 200);
});

// ---------------------------------------------------------------------------
// Move & purge
// ---------------------------------------------------------------------------

async function moveSelected(c: Ctx) {
  const { user } = auth(c);
  const db = c.get('db');
  const body = (await c.req.json()) as Record<string, unknown>;
  const ids = ci<string[]>(body, 'ids') ?? [];
  const folderId = (ci<string>(body, 'folderId') || null) as string | null;

  if (folderId) {
    const folder = await db.query.folders.findFirst({
      where: and(eq(folders.uuid, folderId), eq(folders.userUuid, user.uuid)),
    });
    if (!folder) err('Invalid folder');
  }

  for (const id of ids) {
    const cipher = await loadAccessibleCipher(c, id, false);
    await moveToFolder(db, cipher.uuid, folderId, user.uuid);
  }
  await touchUser(db, user.uuid);
  notifier(c).userUpdate(UpdateType.SyncCiphers, user.uuid);
  return c.body(null, 200);
}

cipherRoutes.post('/ciphers/move', moveSelected);
cipherRoutes.put('/ciphers/move', moveSelected);

cipherRoutes.post('/ciphers/purge', async (c) => {
  const { user, device } = auth(c);
  const db = c.get('db');
  const body = (await c.req.json()) as Record<string, unknown>;
  const passwordHash = ci<string>(body, 'masterPasswordHash');
  if (!passwordHash) err('masterPasswordHash cannot be blank');
  const valid = await verifyPassword(passwordHash, {
    hash: user.passwordHash,
    salt: user.salt,
    iterations: user.passwordIterations,
  });
  if (!valid) err('Invalid password');

  const orgId = c.req.query('organizationId');
  if (orgId) {
    const member = await findConfirmedMembership(db, user.uuid, orgId);
    if (!member || !hasFullAccess(member)) err('You do not have permission to purge the organization vault');
    const orgCiphers = await db.select().from(ciphers).where(eq(ciphers.organizationUuid, orgId));
    for (const cipher of orgCiphers) await deleteCipher(db, c.env.FILES, cipher);
    await logOrgEvent(db, {
      eventType: EventType.OrganizationPurgedVault,
      orgUuid: orgId,
      actUserUuid: user.uuid,
      deviceType: device.atype,
      ip: c.get('ip'),
    });
  } else {
    const owned = await db.select().from(ciphers).where(eq(ciphers.userUuid, user.uuid));
    for (const cipher of owned) await deleteCipher(db, c.env.FILES, cipher);
    await db.delete(folders).where(eq(folders.userUuid, user.uuid));
    await touchUser(db, user.uuid);
  }

  notifier(c).userUpdate(UpdateType.SyncVault, user.uuid);
  return c.body(null, 200);
});

// ---------------------------------------------------------------------------
// Param routes — registered last so static /ciphers/<action> paths win
// ---------------------------------------------------------------------------

cipherRoutes.put('/ciphers/:id', updateCipherHandler);
cipherRoutes.post('/ciphers/:id', updateCipherHandler);
cipherRoutes.delete('/ciphers/:id', hardDeleteHandler);
