import { and, eq, inArray, isNull } from 'drizzle-orm';
import {
  archives,
  attachments,
  ciphers,
  ciphersCollections,
  collectionsGroups,
  favorites,
  folders,
  foldersCiphers,
  groupsUsers,
  nowDb,
  orgPolicies,
  toDb,
  fromDb,
  users,
  usersCollections,
  usersOrganizations,
  type Cipher,
  type Db,
} from '../db';
import { CipherType, MembershipStatus, MembershipType, OrgPolicyType } from '../shared';
import { err } from '../error';
import { ci, uuid } from '../util';
import { hasFullAccess, isAtLeast, findConfirmedMembership } from './memberships';
import { loadCipherSyncData, getAccessRestrictions, type CipherSyncData } from './vault';

// ---------------------------------------------------------------------------
// Write payload (vaultwarden CipherData)
// ---------------------------------------------------------------------------

export interface CipherData {
  id?: string;
  folderId?: string | null;
  organizationId?: string | null;
  key?: string | null;
  type: number;
  name: string;
  notes?: string | null;
  fields?: unknown;
  login?: Record<string, unknown>;
  secureNote?: Record<string, unknown>;
  card?: Record<string, unknown>;
  identity?: Record<string, unknown>;
  sshKey?: Record<string, unknown>;
  favorite?: boolean;
  reprompt?: number | null;
  passwordHistory?: unknown;
  attachments2?: Record<string, { fileName: string; key: string }>;
  lastKnownRevisionDate?: string | null;
  archivedDate?: string | null;
}

export function parseCipherData(body: Record<string, unknown>): CipherData {
  const folderIdRaw = ci<string>(body, 'folderId');
  return {
    id: ci<string>(body, 'id'),
    folderId: folderIdRaw === '' ? null : folderIdRaw,
    organizationId:
      ci<string>(body, 'organizationId') ?? ci<string>(body, 'organizationID') ?? null,
    key: ci<string>(body, 'key') ?? null,
    type: Number(ci(body, 'type') ?? 0),
    name: String(ci(body, 'name') ?? ''),
    notes: (ci<string>(body, 'notes') ?? null) as string | null,
    fields: ci(body, 'fields'),
    login: ci(body, 'login') as Record<string, unknown> | undefined,
    secureNote: ci(body, 'secureNote') as Record<string, unknown> | undefined,
    card: ci(body, 'card') as Record<string, unknown> | undefined,
    identity: ci(body, 'identity') as Record<string, unknown> | undefined,
    sshKey: ci(body, 'sshKey') as Record<string, unknown> | undefined,
    favorite: ci<boolean>(body, 'favorite'),
    reprompt: (ci<number>(body, 'reprompt') ?? null) as number | null,
    passwordHistory: ci(body, 'passwordHistory'),
    attachments2: ci(body, 'attachments2') as CipherData['attachments2'],
    lastKnownRevisionDate: (ci<string>(body, 'lastKnownRevisionDate') ?? null) as string | null,
    archivedDate: (ci<string>(body, 'archivedDate') ?? null) as string | null,
  };
}

function stripResponseKey(value: unknown): unknown {
  if (Array.isArray(value)) {
    for (const item of value) {
      if (item && typeof item === 'object') delete (item as Record<string, unknown>).response;
    }
  }
  return value;
}

const MAX_NOTE_SIZE = 10_000;

/**
 * Personal ownership policy: when active for the user, ciphers must belong to
 * an organization (vaultwarden enforce_personal_ownership_policy).
 */
export async function enforcePersonalOwnershipPolicy(
  db: Db,
  userUuid: string,
  data: CipherData | null,
): Promise<void> {
  if (data && data.organizationId) return;
  const rows = await db
    .select({ atype: usersOrganizations.atype, status: usersOrganizations.status })
    .from(orgPolicies)
    .innerJoin(usersOrganizations, eq(orgPolicies.orgUuid, usersOrganizations.orgUuid))
    .where(
      and(
        eq(orgPolicies.atype, OrgPolicyType.PersonalOwnership),
        eq(orgPolicies.enabled, true),
        eq(usersOrganizations.userUuid, userUuid),
      ),
    );
  const applies = rows.some(
    (r) => r.status >= MembershipStatus.Accepted && !isAtLeast(r.atype, MembershipType.Admin),
  );
  if (applies) {
    err(
      'Due to an Enterprise Policy, you are restricted from saving items to your personal vault.',
    );
  }
}

export interface CipherWriteContext {
  db: Db;
  userUuid: string;
  sync?: CipherSyncData;
}

export function newCipherShell(atype: number, name: string): Cipher {
  const now = nowDb();
  return {
    uuid: uuid(),
    createdAt: now,
    updatedAt: now,
    userUuid: null,
    organizationUuid: null,
    key: null,
    atype,
    name,
    notes: null,
    fields: null,
    data: '{}',
    passwordHistory: null,
    deletedAt: null,
    reprompt: null,
  };
}

/** Core write path — vaultwarden update_cipher_from_data. Returns the saved cipher. */
export async function updateCipherFromData(
  cipher: Cipher,
  data: CipherData,
  ctx: CipherWriteContext,
  options: { sharedToCollections?: string[]; skipRevisionCheck?: boolean } = {},
): Promise<Cipher> {
  const { db, userUuid } = ctx;

  await enforcePersonalOwnershipPolicy(db, userUuid, data);

  if (!options.skipRevisionCheck && data.lastKnownRevisionDate) {
    const known = new Date(data.lastKnownRevisionDate).getTime();
    if (Number.isFinite(known)) {
      const current = fromDb(cipher.updatedAt).getTime();
      if (current - known > 1000) {
        err('The client copy of this cipher is out of date. Resync the client and try again.');
      }
    }
  }

  if (cipher.organizationUuid && cipher.organizationUuid !== data.organizationId) {
    err('Organization mismatch. Please resync the client before updating the cipher');
  }

  if (data.notes && data.notes.length > MAX_NOTE_SIZE) {
    err(
      `The field Notes exceeds the maximum encrypted value length of ${MAX_NOTE_SIZE} characters.`,
    );
  }

  const sync = ctx.sync ?? (await loadCipherSyncData(db, userUuid, 'user'));

  if (data.organizationId) {
    const member = await findConfirmedMembership(db, userUuid, data.organizationId);
    if (!member) err("You don't have permission to add item to organization");
    const writable =
      options.sharedToCollections !== undefined ||
      hasFullAccess(member) ||
      cipher.userUuid === userUuid ||
      getAccessRestrictions(cipher, userUuid, sync)?.readOnly === false;
    if (!writable) err("You don't have permission to add cipher directly to organization");
    cipher.organizationUuid = data.organizationId;
    cipher.userUuid = null;
  } else {
    cipher.userUuid = userUuid;
  }

  if (data.folderId) {
    const folder = await db.query.folders.findFirst({
      where: and(eq(folders.uuid, data.folderId), eq(folders.userUuid, userUuid)),
    });
    if (!folder) err('Invalid folder');
  }

  // Attachment metadata rotation
  if (data.attachments2) {
    for (const [attId, meta] of Object.entries(data.attachments2)) {
      const saved = await db.query.attachments.findFirst({ where: eq(attachments.id, attId) });
      if (!saved) continue;
      if (saved.cipherUuid !== cipher.uuid) break;
      await db
        .update(attachments)
        .set({ akey: meta.key, fileName: meta.fileName })
        .where(eq(attachments.id, attId));
    }
  }

  const typeData = (
    {
      [CipherType.Login]: data.login,
      [CipherType.SecureNote]: data.secureNote,
      [CipherType.Card]: data.card,
      [CipherType.Identity]: data.identity,
      [CipherType.SshKey]: data.sshKey,
    } as Record<number, Record<string, unknown> | undefined>
  )[data.type];
  if (data.type < 1 || data.type > 5) err('Invalid type');
  if (!typeData) err('Data missing');

  delete typeData.response;
  if (Array.isArray(typeData.uris)) stripResponseKey(typeData.uris);

  cipher.key = data.key ?? null;
  cipher.name = data.name;
  cipher.notes = data.notes ?? null;
  cipher.fields = data.fields != null ? JSON.stringify(stripResponseKey(data.fields)) : null;
  cipher.data = JSON.stringify(typeData);
  cipher.passwordHistory =
    data.passwordHistory != null ? JSON.stringify(data.passwordHistory) : null;
  cipher.reprompt = data.reprompt === 0 || data.reprompt === 1 ? data.reprompt : null;
  cipher.updatedAt = nowDb();

  await db
    .insert(ciphers)
    .values(cipher)
    .onConflictDoUpdate({ target: ciphers.uuid, set: { ...cipher } });

  await moveToFolder(db, cipher.uuid, data.folderId ?? null, userUuid);
  await setFavorite(db, cipher.uuid, userUuid, data.favorite);

  if (data.archivedDate) {
    const d = new Date(data.archivedDate);
    if (Number.isFinite(d.getTime())) {
      await db
        .insert(archives)
        .values({ userUuid, cipherUuid: cipher.uuid, archivedAt: toDb(d) })
        .onConflictDoUpdate({
          target: [archives.userUuid, archives.cipherUuid],
          set: { archivedAt: toDb(d) },
        });
    }
  }

  await updateUsersRevisionForCipher(db, cipher);
  return cipher;
}

export async function moveToFolder(
  db: Db,
  cipherUuid: string,
  folderUuid: string | null,
  userUuid: string,
): Promise<void> {
  // Remove existing mapping for this user's folders
  const existing = await db
    .select({ folderUuid: foldersCiphers.folderUuid })
    .from(foldersCiphers)
    .innerJoin(folders, eq(foldersCiphers.folderUuid, folders.uuid))
    .where(and(eq(foldersCiphers.cipherUuid, cipherUuid), eq(folders.userUuid, userUuid)));
  for (const row of existing) {
    if (row.folderUuid === folderUuid) return;
    await db
      .delete(foldersCiphers)
      .where(
        and(
          eq(foldersCiphers.cipherUuid, cipherUuid),
          eq(foldersCiphers.folderUuid, row.folderUuid),
        ),
      );
  }
  if (folderUuid) {
    await db.insert(foldersCiphers).values({ cipherUuid, folderUuid }).onConflictDoNothing();
  }
}

export async function setFavorite(
  db: Db,
  cipherUuid: string,
  userUuid: string,
  favorite: boolean | undefined,
): Promise<void> {
  if (favorite === undefined) return;
  if (favorite) {
    await db.insert(favorites).values({ userUuid, cipherUuid }).onConflictDoNothing();
  } else {
    await db
      .delete(favorites)
      .where(and(eq(favorites.userUuid, userUuid), eq(favorites.cipherUuid, cipherUuid)));
  }
}

/** Users whose vaults include this cipher — used for revision bumps and notifications. */
export async function usersWithCipherAccess(db: Db, cipher: Cipher): Promise<string[]> {
  if (cipher.userUuid) return [cipher.userUuid];
  if (!cipher.organizationUuid) return [];

  const members = await db.query.usersOrganizations.findMany({
    where: and(
      eq(usersOrganizations.orgUuid, cipher.organizationUuid),
      eq(usersOrganizations.status, MembershipStatus.Confirmed),
    ),
  });

  const collectionIds = (
    await db.select().from(ciphersCollections).where(eq(ciphersCollections.cipherUuid, cipher.uuid))
  ).map((r) => r.collectionUuid);

  const result = new Set<string>();
  const needCheck: typeof members = [];
  for (const m of members) {
    if (hasFullAccess(m)) result.add(m.userUuid);
    else needCheck.push(m);
  }

  if (needCheck.length > 0 && collectionIds.length > 0) {
    const direct = await db
      .select({ userUuid: usersCollections.userUuid })
      .from(usersCollections)
      .where(inArray(usersCollections.collectionUuid, collectionIds));
    for (const r of direct) result.add(r.userUuid);

    const viaGroups = await db
      .select({ memberUuid: groupsUsers.usersOrganizationsUuid })
      .from(collectionsGroups)
      .innerJoin(groupsUsers, eq(collectionsGroups.groupsUuid, groupsUsers.groupsUuid))
      .where(inArray(collectionsGroups.collectionsUuid, collectionIds));
    const memberByUuid = new Map(members.map((m) => [m.uuid, m.userUuid]));
    for (const r of viaGroups) {
      const u = memberByUuid.get(r.memberUuid);
      if (u) result.add(u);
    }
  }

  // Filter to actual org members
  const memberUserIds = new Set(members.map((m) => m.userUuid));
  return [...result].filter((u) => memberUserIds.has(u));
}

export async function updateUsersRevisionForCipher(db: Db, cipher: Cipher): Promise<string[]> {
  const userIds = await usersWithCipherAccess(db, cipher);
  if (userIds.length > 0) {
    await db.update(users).set({ updatedAt: nowDb() }).where(inArray(users.uuid, userIds));
  }
  return userIds;
}

export async function deleteCipher(db: Db, files: R2Bucket, cipher: Cipher): Promise<void> {
  // Delete attachment blobs
  const atts = await db.select().from(attachments).where(eq(attachments.cipherUuid, cipher.uuid));
  await Promise.all(atts.map((a) => files.delete(`attachments/${cipher.uuid}/${a.id}`)));
  await db.delete(ciphers).where(eq(ciphers.uuid, cipher.uuid));
  await updateUsersRevisionForCipher(db, cipher);
}
