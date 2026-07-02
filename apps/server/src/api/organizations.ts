import { Hono } from 'hono';
import type { Context } from 'hono';
import { and, eq, inArray } from 'drizzle-orm';
import {
  ciphers,
  collections,
  collectionsGroups,
  groupsUsers,
  organizations,
  usersCollections,
  usersOrganizations,
  type Collection,
  type Db,
  type Membership,
  type Organization,
} from '@vaultur/db';
import { EventType, MembershipStatus, MembershipType, UpdateType } from '@vaultur/shared';
import type { AppEnv } from '../env';
import { requireAuth, auth } from '../auth/middleware';
import { err, notFound } from '../error';
import { verifyPassword } from '../crypto';
import { ci, uuid } from '../util';
import {
  findConfirmedMembership,
  findConfirmedMemberships,
  hasFullAccess,
  isAtLeast,
} from '../services/memberships';
import {
  cipherToJson,
  collectionToJson,
  collectionToJsonDetails,
  loadCipherSyncData,
} from '../services/vault';
import { logOrgEvent } from '../services/events';
import { Notify } from '../services/notify';

/**
 * Organizations core (org CRUD/keys, collections, org vault details), ported
 * from vaultwarden src/api/core/organizations.rs.
 */
export const organizationRoutes = new Hono<AppEnv>();
organizationRoutes.use('*', requireAuth);

type Ctx = Context<AppEnv>;

export function organizationToJson(org: Organization, emailEnabled: boolean) {
  return {
    id: org.uuid,
    name: org.name,
    seats: null,
    maxCollections: null,
    maxStorageGb: 32767,
    use2fa: true,
    useCustomPermissions: true,
    useDirectory: false,
    useEvents: true,
    useGroups: true,
    useTotp: true,
    usePolicies: true,
    useScim: false,
    useSso: false,
    useKeyConnector: false,
    usePasswordManager: true,
    useSecretsManager: false,
    selfHost: true,
    useApi: true,
    hasPublicAndPrivateKeys: org.privateKey != null && org.publicKey != null,
    useResetPassword: emailEnabled,
    allowAdminAccessToAllCollectionItems: true,
    limitCollectionCreation: true,
    limitCollectionDeletion: true,
    businessName: org.name,
    businessAddress1: null,
    businessAddress2: null,
    businessAddress3: null,
    businessCountry: null,
    businessTaxNumber: null,
    maxAutoscaleSeats: null,
    maxAutoscaleSmSeats: null,
    maxAutoscaleSmServiceAccounts: null,
    secretsManagerPlan: null,
    smSeats: null,
    smServiceAccounts: null,
    plan: 'VaultWarden',
    planType: 6,
    billingEmail: org.billingEmail,
    usersGetPremium: true,
    object: 'organization',
  };
}

async function loadOrg(c: Ctx, orgId: string | undefined): Promise<Organization> {
  if (!orgId) notFound("Organization doesn't exist");
  const org = await c
    .get('db')
    .query.organizations.findFirst({ where: eq(organizations.uuid, orgId) });
  if (!org) notFound("Organization doesn't exist");
  return org;
}

/** Requires a confirmed membership of at least the given logical rank. */
async function requireMember(c: Ctx, orgId: string, minType: MembershipType): Promise<Membership> {
  const { user } = auth(c);
  const member = await findConfirmedMembership(c.get('db'), user.uuid, orgId);
  if (!member) notFound('You are not a member of this organization');
  if (!isAtLeast(member.atype, minType)) err('You do not have permission to perform this action');
  return member;
}

async function confirmedOwnerCount(db: Db, orgUuid: string): Promise<number> {
  const rows = await db.query.usersOrganizations.findMany({
    where: and(
      eq(usersOrganizations.orgUuid, orgUuid),
      eq(usersOrganizations.atype, MembershipType.Owner),
      eq(usersOrganizations.status, MembershipStatus.Confirmed),
    ),
  });
  return rows.length;
}

// ---------------------------------------------------------------------------
// Org CRUD
// ---------------------------------------------------------------------------

organizationRoutes.post('/organizations', async (c) => {
  const { user } = auth(c);
  const db = c.get('db');
  const config = c.get('config');
  const body = (await c.req.json()) as Record<string, unknown>;

  // Org creation permission (vaultwarden org_creation_users)
  const allowed =
    config.orgCreationUsers === 'all' ||
    config.orgCreationUsers === '' ||
    config.orgCreationUsers
      .split(',')
      .map((s) => s.trim())
      .includes(user.email);
  if (!allowed || config.orgCreationUsers === 'none') {
    err('User not allowed to create organizations');
  }

  const name = ci<string>(body, 'name');
  const key = ci<string>(body, 'key');
  const keys = ci<Record<string, unknown>>(body, 'keys');
  const billingEmail = ci<string>(body, 'billingEmail') ?? user.email;
  const collectionName = ci<string>(body, 'collectionName');
  if (!name || !key) err('Missing required fields');

  const org: Organization = {
    uuid: uuid(),
    name,
    billingEmail,
    privateKey: keys ? (ci<string>(keys, 'encryptedPrivateKey') ?? null) : null,
    publicKey: keys ? (ci<string>(keys, 'publicKey') ?? null) : null,
  };
  await db.insert(organizations).values(org);

  const membership: Membership = {
    uuid: uuid(),
    userUuid: user.uuid,
    orgUuid: org.uuid,
    invitedByEmail: null,
    accessAll: true,
    akey: key,
    status: MembershipStatus.Confirmed,
    atype: MembershipType.Owner,
    resetPasswordKey: null,
    externalId: null,
  };
  await db.insert(usersOrganizations).values(membership);

  if (collectionName) {
    await db
      .insert(collections)
      .values({ uuid: uuid(), orgUuid: org.uuid, name: collectionName, externalId: null });
  }

  return c.json(organizationToJson(org, c.get('config').emailEnabled));
});

organizationRoutes.get('/organizations/:orgId', async (c) => {
  const orgId = c.req.param('orgId');
  await requireMember(c, orgId, MembershipType.Owner);
  const org = await loadOrg(c, orgId);
  return c.json(organizationToJson(org, c.get('config').emailEnabled));
});

async function updateOrg(c: Ctx) {
  const orgId = c.req.param('orgId');
  if (!orgId) notFound("Organization doesn't exist");
  await requireMember(c, orgId, MembershipType.Owner);
  const org = await loadOrg(c, orgId);
  const body = (await c.req.json()) as Record<string, unknown>;
  const name = ci<string>(body, 'name') ?? org.name;
  const billingEmail = ci<string>(body, 'billingEmail') ?? org.billingEmail;

  const db = c.get('db');
  await db.update(organizations).set({ name, billingEmail }).where(eq(organizations.uuid, orgId));
  const { user, device } = auth(c);
  await logOrgEvent(db, {
    eventType: EventType.OrganizationUpdated,
    orgUuid: orgId,
    actUserUuid: user.uuid,
    deviceType: device.atype,
    ip: c.get('ip'),
  });
  return c.json(organizationToJson({ ...org, name, billingEmail }, c.get('config').emailEnabled));
}
organizationRoutes.put('/organizations/:orgId', updateOrg);
organizationRoutes.post('/organizations/:orgId', updateOrg);

async function deleteOrg(c: Ctx) {
  const { user } = auth(c);
  const orgId = c.req.param('orgId');
  if (!orgId) notFound("Organization doesn't exist");
  await requireMember(c, orgId, MembershipType.Owner);

  const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
  const passwordHash = ci<string>(body, 'masterPasswordHash');
  if (!passwordHash) err('Request missing master password');
  const valid = await verifyPassword(passwordHash, {
    hash: user.passwordHash,
    salt: user.salt,
    iterations: user.passwordIterations,
  });
  if (!valid) err('Invalid password');

  const db = c.get('db');
  // Org ciphers don't FK-cascade from organizations (no FK) — delete explicitly
  await db.delete(ciphers).where(eq(ciphers.organizationUuid, orgId));
  await db.delete(organizations).where(eq(organizations.uuid, orgId));
  return c.body(null, 200);
}
organizationRoutes.delete('/organizations/:orgId', deleteOrg);
organizationRoutes.post('/organizations/:orgId/delete', deleteOrg);

organizationRoutes.post('/organizations/:orgId/leave', async (c) => {
  const { user } = auth(c);
  const orgId = c.req.param('orgId');
  const db = c.get('db');
  const member = await db.query.usersOrganizations.findFirst({
    where: and(eq(usersOrganizations.userUuid, user.uuid), eq(usersOrganizations.orgUuid, orgId)),
  });
  if (!member) notFound('User not part of organization');

  if (
    member.atype === MembershipType.Owner &&
    member.status === MembershipStatus.Confirmed &&
    (await confirmedOwnerCount(db, orgId)) <= 1
  ) {
    err('The last owner can not leave the organization');
  }

  await db.delete(usersOrganizations).where(eq(usersOrganizations.uuid, member.uuid));
  await logOrgEvent(db, {
    eventType: EventType.OrganizationUserRemoved,
    orgUuid: orgId,
    actUserUuid: user.uuid,
    orgUserUuid: member.uuid,
    ip: c.get('ip'),
  });
  return c.body(null, 200);
});

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

organizationRoutes.get('/organizations/:orgId/keys', async (c) => {
  const org = await loadOrg(c, c.req.param('orgId'));
  return c.json({
    publicKey: org.publicKey,
    privateKey: org.privateKey,
    object: 'organizationKeys',
  });
});

organizationRoutes.get('/organizations/:orgId/public-key', async (c) => {
  const org = await loadOrg(c, c.req.param('orgId'));
  return c.json({ publicKey: org.publicKey, object: 'organizationPublicKey' });
});

organizationRoutes.post('/organizations/:orgId/keys', async (c) => {
  const orgId = c.req.param('orgId');
  await requireMember(c, orgId, MembershipType.Admin);
  const org = await loadOrg(c, orgId);
  if (org.privateKey || org.publicKey) err('Organization Keys already exist');

  const body = (await c.req.json()) as Record<string, unknown>;
  const publicKey = ci<string>(body, 'publicKey');
  const privateKey = ci<string>(body, 'encryptedPrivateKey') ?? ci<string>(body, 'privateKey');
  if (!publicKey || !privateKey) err('Missing keys');

  await c
    .get('db')
    .update(organizations)
    .set({ publicKey, privateKey })
    .where(eq(organizations.uuid, orgId));
  return c.json({ publicKey, privateKey, object: 'organizationKeys' });
});

// ---------------------------------------------------------------------------
// Collections
// ---------------------------------------------------------------------------

interface CollectionAssignment {
  id: string;
  readOnly: boolean;
  hidePasswords: boolean;
  manage: boolean;
}

function parseAssignments(value: unknown): CollectionAssignment[] {
  if (!Array.isArray(value)) return [];
  return value
    .filter((v): v is Record<string, unknown> => v != null && typeof v === 'object')
    .map((v) => ({
      id: String(ci(v, 'id') ?? ''),
      readOnly: Boolean(ci(v, 'readOnly')),
      hidePasswords: Boolean(ci(v, 'hidePasswords')),
      manage: Boolean(ci(v, 'manage')),
    }))
    .filter((v) => v.id !== '');
}

/** All collections across the user's orgs (GET /collections). */
organizationRoutes.get('/collections', async (c) => {
  const { user } = auth(c);
  const db = c.get('db');
  const memberships = await findConfirmedMemberships(db, user.uuid);
  const orgIds = memberships.map((m) => m.orgUuid);
  const rows =
    orgIds.length > 0
      ? await db.select().from(collections).where(inArray(collections.orgUuid, orgIds))
      : [];
  return c.json({ data: rows.map(collectionToJson), object: 'list', continuationToken: null });
});

organizationRoutes.get('/organizations/:orgId/collections', async (c) => {
  const { user } = auth(c);
  const orgId = c.req.param('orgId');
  await requireMember(c, orgId, MembershipType.User);
  const db = c.get('db');

  const sync = await loadCipherSyncData(db, user.uuid, 'org', orgId);
  const member = sync.members.get(orgId);
  const rows = await db.select().from(collections).where(eq(collections.orgUuid, orgId));
  const visible = rows.filter(
    (col) =>
      (member && hasFullAccess(member)) ||
      sync.userCollections.has(col.uuid) ||
      sync.userCollectionsGroups.has(col.uuid),
  );
  return c.json({
    data: visible.map((col) => collectionToJsonDetails(col, user.uuid, sync)),
    object: 'list',
    continuationToken: null,
  });
});

async function loadCollection(
  c: Ctx,
  orgId: string,
  colId: string | undefined,
): Promise<Collection> {
  if (!colId) notFound('Collection not found');
  const col = await c.get('db').query.collections.findFirst({ where: eq(collections.uuid, colId) });
  if (!col || col.orgUuid !== orgId) notFound('Collection not found');
  return col;
}

organizationRoutes.get('/organizations/:orgId/collections/:colId/details', async (c) => {
  const { user } = auth(c);
  const orgId = c.req.param('orgId');
  await requireMember(c, orgId, MembershipType.User);
  const col = await loadCollection(c, orgId, c.req.param('colId'));
  const db = c.get('db');
  const sync = await loadCipherSyncData(db, user.uuid, 'org', orgId);

  const userRows = await db
    .select()
    .from(usersCollections)
    .where(eq(usersCollections.collectionUuid, col.uuid));
  const memberByUser = new Map(
    (
      await db.query.usersOrganizations.findMany({ where: eq(usersOrganizations.orgUuid, orgId) })
    ).map((m) => [m.userUuid, m]),
  );
  const groupRows = await db
    .select()
    .from(collectionsGroups)
    .where(eq(collectionsGroups.collectionsUuid, col.uuid));

  return c.json({
    ...collectionToJsonDetails(col, user.uuid, sync),
    users: userRows
      .filter((r) => memberByUser.has(r.userUuid))
      .map((r) => ({
        id: memberByUser.get(r.userUuid)!.uuid,
        readOnly: r.readOnly,
        hidePasswords: r.hidePasswords,
        manage: r.manage,
      })),
    groups: groupRows.map((g) => ({
      id: g.groupsUuid,
      readOnly: g.readOnly,
      hidePasswords: g.hidePasswords,
      manage: g.manage,
    })),
    object: 'collectionAccessDetails',
  });
});

organizationRoutes.post('/organizations/:orgId/collections', async (c) => {
  const { user, device } = auth(c);
  const orgId = c.req.param('orgId');
  const member = await requireMember(c, orgId, MembershipType.Manager);
  const db = c.get('db');
  const body = (await c.req.json()) as Record<string, unknown>;
  const name = ci<string>(body, 'name');
  if (!name) err('The field Name is required.');

  const col: Collection = {
    uuid: uuid(),
    orgUuid: orgId,
    name,
    externalId: (ci<string>(body, 'externalId') ?? null) as string | null,
  };
  await db.insert(collections).values(col);

  for (const assignment of parseAssignments(ci(body, 'users'))) {
    const target = await db.query.usersOrganizations.findFirst({
      where: and(eq(usersOrganizations.uuid, assignment.id), eq(usersOrganizations.orgUuid, orgId)),
    });
    if (!target || target.accessAll) continue;
    await db.insert(usersCollections).values({
      userUuid: target.userUuid,
      collectionUuid: col.uuid,
      readOnly: assignment.readOnly,
      hidePasswords: assignment.hidePasswords,
      manage: assignment.manage,
    });
  }
  for (const assignment of parseAssignments(ci(body, 'groups'))) {
    await db.insert(collectionsGroups).values({
      collectionsUuid: col.uuid,
      groupsUuid: assignment.id,
      readOnly: assignment.readOnly,
      hidePasswords: assignment.hidePasswords,
      manage: assignment.manage,
    });
  }

  // Non-access-all managers get explicit manage access to their new collection
  if (!member.accessAll && member.atype === MembershipType.Manager) {
    await db
      .insert(usersCollections)
      .values({
        userUuid: user.uuid,
        collectionUuid: col.uuid,
        readOnly: false,
        hidePasswords: false,
        manage: true,
      })
      .onConflictDoNothing();
  }

  await logOrgEvent(db, {
    eventType: EventType.CollectionCreated,
    orgUuid: orgId,
    actUserUuid: user.uuid,
    collectionUuid: col.uuid,
    deviceType: device.atype,
    ip: c.get('ip'),
  });
  return c.json(collectionToJson(col));
});

// Registered before the :colId param routes so the static path wins
organizationRoutes.post('/organizations/:orgId/collections/bulk-delete', async (c) => {
  const { user, device } = auth(c);
  const orgId = c.req.param('orgId');
  await requireMember(c, orgId, MembershipType.Manager);
  const body = (await c.req.json()) as Record<string, unknown>;
  const ids = ci<string[]>(body, 'ids') ?? [];
  const db = c.get('db');
  for (const id of ids) {
    const col = await db.query.collections.findFirst({ where: eq(collections.uuid, id) });
    if (!col || col.orgUuid !== orgId) continue;
    await db.delete(collections).where(eq(collections.uuid, id));
    await logOrgEvent(db, {
      eventType: EventType.CollectionDeleted,
      orgUuid: orgId,
      actUserUuid: user.uuid,
      collectionUuid: id,
      deviceType: device.atype,
      ip: c.get('ip'),
    });
  }
  return c.body(null, 200);
});

async function updateCollection(c: Ctx) {
  const { user, device } = auth(c);
  const orgId = c.req.param('orgId');
  if (!orgId) notFound("Organization doesn't exist");
  await requireMember(c, orgId, MembershipType.Manager);
  const col = await loadCollection(c, orgId, c.req.param('colId'));
  const db = c.get('db');
  const body = (await c.req.json()) as Record<string, unknown>;
  const name = ci<string>(body, 'name') ?? col.name;
  const externalId = (ci<string>(body, 'externalId') ?? null) as string | null;

  await db.update(collections).set({ name, externalId }).where(eq(collections.uuid, col.uuid));

  const users = parseAssignments(ci(body, 'users'));
  const groups = parseAssignments(ci(body, 'groups'));
  if (ci(body, 'users') !== undefined) {
    await db.delete(usersCollections).where(eq(usersCollections.collectionUuid, col.uuid));
    for (const assignment of users) {
      const target = await db.query.usersOrganizations.findFirst({
        where: and(
          eq(usersOrganizations.uuid, assignment.id),
          eq(usersOrganizations.orgUuid, orgId),
        ),
      });
      if (!target || target.accessAll) continue;
      await db.insert(usersCollections).values({
        userUuid: target.userUuid,
        collectionUuid: col.uuid,
        readOnly: assignment.readOnly,
        hidePasswords: assignment.hidePasswords,
        manage: assignment.manage,
      });
    }
  }
  if (ci(body, 'groups') !== undefined) {
    await db.delete(collectionsGroups).where(eq(collectionsGroups.collectionsUuid, col.uuid));
    for (const assignment of groups) {
      await db.insert(collectionsGroups).values({
        collectionsUuid: col.uuid,
        groupsUuid: assignment.id,
        readOnly: assignment.readOnly,
        hidePasswords: assignment.hidePasswords,
        manage: assignment.manage,
      });
    }
  }

  await logOrgEvent(db, {
    eventType: EventType.CollectionUpdated,
    orgUuid: orgId,
    actUserUuid: user.uuid,
    collectionUuid: col.uuid,
    deviceType: device.atype,
    ip: c.get('ip'),
  });
  return c.json(collectionToJson({ ...col, name, externalId }));
}
organizationRoutes.put('/organizations/:orgId/collections/:colId', updateCollection);
organizationRoutes.post('/organizations/:orgId/collections/:colId', updateCollection);

async function deleteCollectionHandler(c: Ctx) {
  const { user, device } = auth(c);
  const orgId = c.req.param('orgId');
  if (!orgId) notFound("Organization doesn't exist");
  await requireMember(c, orgId, MembershipType.Manager);
  const col = await loadCollection(c, orgId, c.req.param('colId'));
  const db = c.get('db');

  await db.delete(collections).where(eq(collections.uuid, col.uuid));
  await logOrgEvent(db, {
    eventType: EventType.CollectionDeleted,
    orgUuid: orgId,
    actUserUuid: user.uuid,
    collectionUuid: col.uuid,
    deviceType: device.atype,
    ip: c.get('ip'),
  });
  return c.body(null, 200);
}
organizationRoutes.delete('/organizations/:orgId/collections/:colId', deleteCollectionHandler);
organizationRoutes.post('/organizations/:orgId/collections/:colId/delete', deleteCollectionHandler);

organizationRoutes.get('/organizations/:orgId/collections/:colId/users', async (c) => {
  const orgId = c.req.param('orgId');
  await requireMember(c, orgId, MembershipType.Manager);
  const col = await loadCollection(c, orgId, c.req.param('colId'));
  const db = c.get('db');

  const rows = await db
    .select()
    .from(usersCollections)
    .where(eq(usersCollections.collectionUuid, col.uuid));
  const memberByUser = new Map(
    (
      await db.query.usersOrganizations.findMany({ where: eq(usersOrganizations.orgUuid, orgId) })
    ).map((m) => [m.userUuid, m]),
  );
  return c.json(
    rows
      .filter((r) => memberByUser.has(r.userUuid))
      .map((r) => ({
        id: memberByUser.get(r.userUuid)!.uuid,
        readOnly: r.readOnly,
        hidePasswords: r.hidePasswords,
        manage: r.manage,
      })),
  );
});

organizationRoutes.put('/organizations/:orgId/collections/:colId/users', async (c) => {
  const orgId = c.req.param('orgId');
  await requireMember(c, orgId, MembershipType.Manager);
  const col = await loadCollection(c, orgId, c.req.param('colId'));
  const db = c.get('db');
  const assignments = parseAssignments(await c.req.json());

  await db.delete(usersCollections).where(eq(usersCollections.collectionUuid, col.uuid));
  for (const assignment of assignments) {
    const target = await db.query.usersOrganizations.findFirst({
      where: and(eq(usersOrganizations.uuid, assignment.id), eq(usersOrganizations.orgUuid, orgId)),
    });
    if (!target || target.accessAll) continue;
    await db.insert(usersCollections).values({
      userUuid: target.userUuid,
      collectionUuid: col.uuid,
      readOnly: assignment.readOnly,
      hidePasswords: assignment.hidePasswords,
      manage: assignment.manage,
    });
  }
  return c.body(null, 200);
});

// ---------------------------------------------------------------------------
// Org vault (admin console cipher listing)
// ---------------------------------------------------------------------------

organizationRoutes.get('/organizations/:orgId/details', async (c) => {
  const { user } = auth(c);
  const orgId = c.req.param('orgId');
  await requireMember(c, orgId, MembershipType.User);
  const db = c.get('db');

  const sync = await loadCipherSyncData(db, user.uuid, 'org', orgId);
  const rows = await db.select().from(ciphers).where(eq(ciphers.organizationUuid, orgId));
  const opts = {
    config: c.get('config'),
    secret: c.env.JWT_SECRET,
    userUuid: user.uuid,
    sync,
    syncType: 'org' as const,
  };
  return c.json({
    data: await Promise.all(rows.map((r) => cipherToJson(r, opts))),
    object: 'list',
    continuationToken: null,
  });
});
