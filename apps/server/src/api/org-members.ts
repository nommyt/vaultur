import { Hono } from 'hono';
import type { Context } from 'hono';
import { and, eq, inArray } from 'drizzle-orm';
import {
  collections,
  collectionsGroups,
  groups,
  groupsUsers,
  invitations,
  nowDb,
  orgPolicies,
  organizations,
  twofactor,
  users,
  usersCollections,
  usersOrganizations,
  type Db,
  type Group,
  type Membership,
} from '@vaultur/db';
import { EventType, MembershipStatus, MembershipType, OrgPolicyType } from '@vaultur/shared';
import type { AppEnv } from '../env';
import { requireAuth, auth } from '../auth/middleware';
import { err, notFound } from '../error';
import { basicClaims, decodeJwt, encodeJwt, issuer } from '../auth/jwt';
import { ci, normalizeEmail, uuid } from '../util';
import { findUserByEmail, newUserShell, passwordFields } from '../services/users';
import { createMailer, mail } from '../services/mail';
import {
  findConfirmedMembership,
  hasFullAccess,
  isAtLeast,
  membershipRank,
} from '../services/memberships';
import { policyToJson } from '../services/vault';
import { logOrgEvent } from '../services/events';

/**
 * Organization membership lifecycle, groups, and policies — ported from
 * vaultwarden src/api/core/organizations.rs.
 */
export const orgMemberRoutes = new Hono<AppEnv>();

type Ctx = Context<AppEnv>;

interface InviteClaims {
  sub: string;
  email: string;
  member_id: string;
  org_id: string;
  invited_by_email: string | null;
  iss: string;
  [k: string]: unknown;
}

async function requireMember(
  c: Ctx,
  orgId: string | undefined,
  minType: MembershipType,
): Promise<Membership> {
  if (!orgId) notFound("Organization doesn't exist");
  const { user } = auth(c);
  const member = await findConfirmedMembership(c.get('db'), user.uuid, orgId);
  if (!member) notFound('You are not a member of this organization');
  if (!isAtLeast(member.atype, minType)) err('You do not have permission to perform this action');
  return member;
}

async function confirmedOwnerCount(db: Db, orgUuid: string): Promise<number> {
  return (
    await db.query.usersOrganizations.findMany({
      where: and(
        eq(usersOrganizations.orgUuid, orgUuid),
        eq(usersOrganizations.atype, MembershipType.Owner),
        eq(usersOrganizations.status, MembershipStatus.Confirmed),
      ),
    })
  ).length;
}

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

/** Wire type: Manager is presented as Custom(4) — vaultwarden type_manager_as_custom. */
function wireType(m: Membership): number {
  return m.atype === MembershipType.Manager ? 4 : m.atype;
}

/** Parse an incoming type value; Custom(4) maps back to Manager. */
function parseMemberType(value: unknown): number {
  const n = Number(value ?? MembershipType.User);
  if (n === 4) return MembershipType.Manager;
  if (
    ![
      MembershipType.Owner,
      MembershipType.Admin,
      MembershipType.User,
      MembershipType.Manager,
    ].includes(n)
  ) {
    err('Invalid membership type');
  }
  return n;
}

async function membershipUserDetailsJson(
  db: Db,
  m: Membership,
  opts: { includeCollections?: boolean; includeGroups?: boolean } = {},
): Promise<Record<string, unknown>> {
  const user = (await db.query.users.findFirst({ where: eq(users.uuid, m.userUuid) }))!;
  const status = m.status < MembershipStatus.Revoked ? MembershipStatus.Revoked : m.status;
  const tf = await db.query.twofactor.findFirst({ where: eq(twofactor.userUuid, m.userUuid) });

  const groupIds = opts.includeGroups
    ? (
        await db.select().from(groupsUsers).where(eq(groupsUsers.usersOrganizationsUuid, m.uuid))
      ).map((g) => g.groupsUuid)
    : [];

  let collectionsJson: Record<string, unknown>[] = [];
  if (opts.includeCollections && !m.accessAll) {
    const rows = await db
      .select({
        collectionUuid: usersCollections.collectionUuid,
        readOnly: usersCollections.readOnly,
        hidePasswords: usersCollections.hidePasswords,
        manage: usersCollections.manage,
      })
      .from(usersCollections)
      .innerJoin(collections, eq(usersCollections.collectionUuid, collections.uuid))
      .where(and(eq(usersCollections.userUuid, m.userUuid), eq(collections.orgUuid, m.orgUuid)));
    collectionsJson = rows.map((r) => ({
      id: r.collectionUuid,
      readOnly: r.readOnly,
      hidePasswords: r.hidePasswords,
      manage: r.manage || (m.atype === MembershipType.Manager && !r.readOnly && !r.hidePasswords),
    }));
  }

  const type = wireType(m);
  const permissions =
    type === 4 && m.accessAll
      ? {
          accessEventLogs: false,
          accessImportExport: false,
          accessReports: false,
          createNewCollections: true,
          editAnyCollection: true,
          deleteAnyCollection: true,
          manageGroups: false,
          managePolicies: false,
          manageSso: false,
          manageUsers: false,
          manageResetPassword: false,
          manageScim: false,
        }
      : null;

  return {
    id: m.uuid,
    userId: m.userUuid,
    name: m.status >= MembershipStatus.Accepted ? user.name : null,
    email: user.email,
    externalId: m.externalId,
    avatarColor: user.avatarColor,
    groups: groupIds,
    collections: collectionsJson,
    status,
    type,
    accessAll: m.accessAll,
    twoFactorEnabled: Boolean(tf),
    resetPasswordEnrolled: m.resetPasswordKey != null,
    hasMasterPassword: user.passwordHash !== '',
    permissions,
    ssoBound: false,
    managedByOrganization: false,
    claimedByOrganization: false,
    usesKeyConnector: false,
    accessSecretsManager: false,
    object: 'organizationUserUserDetails',
  };
}

async function replaceMemberCollections(
  db: Db,
  m: Membership,
  assignments: CollectionAssignment[],
): Promise<void> {
  const orgCollections = new Set(
    (
      await db
        .select({ uuid: collections.uuid })
        .from(collections)
        .where(eq(collections.orgUuid, m.orgUuid))
    ).map((r) => r.uuid),
  );
  // Remove existing org-scoped assignments for this user
  const existing = await db
    .select()
    .from(usersCollections)
    .where(eq(usersCollections.userUuid, m.userUuid));
  for (const row of existing) {
    if (orgCollections.has(row.collectionUuid)) {
      await db
        .delete(usersCollections)
        .where(
          and(
            eq(usersCollections.userUuid, m.userUuid),
            eq(usersCollections.collectionUuid, row.collectionUuid),
          ),
        );
    }
  }
  for (const a of assignments) {
    if (!orgCollections.has(a.id)) continue;
    await db.insert(usersCollections).values({
      userUuid: m.userUuid,
      collectionUuid: a.id,
      readOnly: a.readOnly,
      hidePasswords: a.hidePasswords,
      manage: a.manage,
    });
  }
}

async function replaceMemberGroups(db: Db, m: Membership, groupIds: string[]): Promise<void> {
  await db.delete(groupsUsers).where(eq(groupsUsers.usersOrganizationsUuid, m.uuid));
  for (const gid of groupIds) {
    const group = await db.query.groups.findFirst({ where: eq(groups.uuid, gid) });
    if (!group || group.organizationsUuid !== m.orgUuid) continue;
    await db
      .insert(groupsUsers)
      .values({ groupsUuid: gid, usersOrganizationsUuid: m.uuid })
      .onConflictDoNothing();
  }
}

// ===========================================================================
// All routes require auth except policies/token (registered first)
// ===========================================================================

orgMemberRoutes.get('/organizations/:orgId/policies/token', async (c) => {
  const orgId = c.req.param('orgId');
  const token = c.req.query('token') ?? '';
  const config = c.get('config');
  let claims: InviteClaims;
  try {
    claims = await decodeJwt<InviteClaims>(
      c.env.JWT_SECRET,
      token,
      issuer(config.domain, 'invite'),
    );
  } catch {
    err('Invalid token');
  }
  if (claims.org_id !== orgId) err('Token not valid for this organization');
  const rows = await c
    .get('db')
    .query.orgPolicies.findMany({ where: eq(orgPolicies.orgUuid, orgId) });
  return c.json({ data: rows.map(policyToJson), object: 'list', continuationToken: null });
});

orgMemberRoutes.use('*', requireAuth);

// ===========================================================================
// Members
// ===========================================================================

orgMemberRoutes.get('/organizations/:orgId/users', async (c) => {
  const orgId = c.req.param('orgId');
  await requireMember(c, orgId, MembershipType.Manager);
  const db = c.get('db');
  const includeCollections = c.req.query('includeCollections') === 'true';
  const includeGroups = c.req.query('includeGroups') === 'true';

  const members = await db.query.usersOrganizations.findMany({
    where: eq(usersOrganizations.orgUuid, orgId!),
  });
  const data = await Promise.all(
    members.map((m) => membershipUserDetailsJson(db, m, { includeCollections, includeGroups })),
  );
  return c.json({ data, object: 'list', continuationToken: null });
});

orgMemberRoutes.get('/organizations/:orgId/users/mini-details', async (c) => {
  const orgId = c.req.param('orgId');
  await requireMember(c, orgId, MembershipType.User);
  const db = c.get('db');
  const members = await db.query.usersOrganizations.findMany({
    where: eq(usersOrganizations.orgUuid, orgId!),
  });
  const data = await Promise.all(
    members.map(async (m) => {
      const user = (await db.query.users.findFirst({ where: eq(users.uuid, m.userUuid) }))!;
      return {
        id: m.uuid,
        userId: m.userUuid,
        type: wireType(m),
        status: m.status < MembershipStatus.Revoked ? MembershipStatus.Revoked : m.status,
        name: user.name,
        email: user.email,
        object: 'organizationUserUserMiniDetails',
      };
    }),
  );
  return c.json({ data, object: 'list', continuationToken: null });
});

orgMemberRoutes.post('/organizations/:orgId/users/invite', async (c) => {
  const { user: inviter, device } = auth(c);
  const orgId = c.req.param('orgId')!;
  await requireMember(c, orgId, MembershipType.Admin);
  const db = c.get('db');
  const config = c.get('config');
  const mailer = createMailer(c.env.EMAIL, config);
  const org = (await db.query.organizations.findFirst({ where: eq(organizations.uuid, orgId) }))!;

  const body = (await c.req.json()) as Record<string, unknown>;
  const emails = (ci<string[]>(body, 'emails') ?? []).map(normalizeEmail).filter(Boolean);
  const type = parseMemberType(ci(body, 'type'));
  const accessAll = Boolean(ci(body, 'accessAll'));
  const collectionAssignments = parseAssignments(ci(body, 'collections'));
  const groupIds = ci<string[]>(body, 'groups') ?? [];
  if (emails.length === 0) err('No email addresses provided');
  if (type === MembershipType.Owner) {
    const member = await findConfirmedMembership(db, inviter.uuid, orgId);
    if (!member || member.atype !== MembershipType.Owner) err('Only Owners can invite Owners');
  }

  for (const email of emails) {
    let user = await findUserByEmail(db, email);
    let userCreated = false;
    if (!user) {
      if (!config.invitationsAllowed) err(`User does not exist: ${email}`);
      if (
        !config.signupsAllowed &&
        config.signupsDomainsWhitelist.length === 0 &&
        !mailer.enabled
      ) {
        // Invitation table lets restricted-signup servers accept invited users
      }
      const shell = newUserShell(email, null);
      await db.insert(users).values(shell);
      user = (await findUserByEmail(db, email))!;
      userCreated = true;
      if (!mailer.enabled) {
        await db.insert(invitations).values({ email }).onConflictDoNothing();
      }
    } else {
      const existing = await db.query.usersOrganizations.findFirst({
        where: and(
          eq(usersOrganizations.userUuid, user.uuid),
          eq(usersOrganizations.orgUuid, orgId),
        ),
      });
      if (existing) err(`User already in organization: ${email}`);
    }

    const membership: Membership = {
      uuid: uuid(),
      userUuid: user.uuid,
      orgUuid: orgId,
      invitedByEmail: inviter.email,
      accessAll,
      akey: '',
      // Without mail, invited users are auto-accepted (vaultwarden behavior)
      status: mailer.enabled ? MembershipStatus.Invited : MembershipStatus.Accepted,
      atype: type,
      resetPasswordKey: null,
      externalId: null,
    };
    await db.insert(usersOrganizations).values(membership);

    if (!accessAll) {
      await replaceMemberCollections(db, membership, collectionAssignments);
    }
    await replaceMemberGroups(db, membership, groupIds);

    if (mailer.enabled) {
      const token = await encodeJwt(
        c.env.JWT_SECRET,
        basicClaims({
          domain: config.domain,
          kind: 'invite',
          sub: user.uuid,
          ttlSeconds: 5 * 24 * 3600,
          extra: {
            email,
            member_id: membership.uuid,
            org_id: orgId,
            invited_by_email: inviter.email,
          },
        }),
      );
      c.executionCtx.waitUntil(
        mail.orgInvite(
          mailer,
          config,
          email,
          org.name,
          orgId,
          membership.uuid,
          token,
          !userCreated && Boolean(user.privateKey),
        ),
      );
    }

    await logOrgEvent(db, {
      eventType: EventType.OrganizationUserInvited,
      orgUuid: orgId,
      actUserUuid: inviter.uuid,
      orgUserUuid: membership.uuid,
      deviceType: device.atype,
      ip: c.get('ip'),
    });
  }

  return c.body(null, 200);
});

async function reinviteMember(c: Ctx, orgId: string, memberId: string): Promise<void> {
  const db = c.get('db');
  const config = c.get('config');
  const mailer = createMailer(c.env.EMAIL, config);
  const { user: inviter } = auth(c);

  const membership = await db.query.usersOrganizations.findFirst({
    where: and(eq(usersOrganizations.uuid, memberId), eq(usersOrganizations.orgUuid, orgId)),
  });
  if (!membership) err("The user hasn't been invited to the organization.");
  if (membership.status !== MembershipStatus.Invited)
    err('The user is already accepted or confirmed to the organization');

  const target = (await db.query.users.findFirst({ where: eq(users.uuid, membership.userUuid) }))!;
  const org = (await db.query.organizations.findFirst({ where: eq(organizations.uuid, orgId) }))!;

  if (mailer.enabled) {
    const token = await encodeJwt(
      c.env.JWT_SECRET,
      basicClaims({
        domain: config.domain,
        kind: 'invite',
        sub: target.uuid,
        ttlSeconds: 5 * 24 * 3600,
        extra: {
          email: target.email,
          member_id: membership.uuid,
          org_id: orgId,
          invited_by_email: inviter.email,
        },
      }),
    );
    await mail.orgInvite(
      mailer,
      config,
      target.email,
      org.name,
      orgId,
      membership.uuid,
      token,
      Boolean(target.privateKey),
    );
  } else {
    await db.insert(invitations).values({ email: target.email }).onConflictDoNothing();
  }
}

orgMemberRoutes.post('/organizations/:orgId/users/:memberId/reinvite', async (c) => {
  const orgId = c.req.param('orgId');
  await requireMember(c, orgId, MembershipType.Admin);
  await reinviteMember(c, orgId!, c.req.param('memberId')!);
  return c.body(null, 200);
});

orgMemberRoutes.post('/organizations/:orgId/users/reinvite', async (c) => {
  const orgId = c.req.param('orgId');
  await requireMember(c, orgId, MembershipType.Admin);
  const body = (await c.req.json()) as Record<string, unknown>;
  const ids = ci<string[]>(body, 'ids') ?? [];
  const results = [];
  for (const id of ids) {
    let error = '';
    try {
      await reinviteMember(c, orgId!, id);
    } catch (e) {
      error = e instanceof Error ? e.message : 'error';
    }
    results.push({ object: 'OrganizationBulkConfirmResponseModel', id, error });
  }
  return c.json({ data: results, object: 'list', continuationToken: null });
});

orgMemberRoutes.post('/organizations/:orgId/users/:memberId/accept', async (c) => {
  const { user } = auth(c);
  const orgId = c.req.param('orgId')!;
  const memberId = c.req.param('memberId')!;
  const db = c.get('db');
  const config = c.get('config');
  const body = (await c.req.json()) as Record<string, unknown>;
  const token = ci<string>(body, 'token');

  const membership = await db.query.usersOrganizations.findFirst({
    where: and(eq(usersOrganizations.uuid, memberId), eq(usersOrganizations.orgUuid, orgId)),
  });
  if (!membership || membership.userUuid !== user.uuid) err('User not found in organization');
  if (membership.status !== MembershipStatus.Invited) err('User already accepted the invitation');

  const mailer = createMailer(c.env.EMAIL, config);
  if (mailer.enabled) {
    if (!token) err('Invite token not provided');
    let claims: InviteClaims;
    try {
      claims = await decodeJwt<InviteClaims>(
        c.env.JWT_SECRET,
        token,
        issuer(config.domain, 'invite'),
      );
    } catch {
      err('Invalid invite token');
    }
    if (claims.member_id !== memberId || claims.email !== user.email)
      err('Invitation does not match');
  }

  // 2FA policy: users without 2FA can't join orgs that require it
  const tfCount = (await db.query.twofactor.findMany({ where: eq(twofactor.userUuid, user.uuid) }))
    .length;
  if (tfCount === 0) {
    const policy = await db.query.orgPolicies.findFirst({
      where: and(
        eq(orgPolicies.orgUuid, orgId),
        eq(orgPolicies.atype, OrgPolicyType.TwoFactorAuthentication),
        eq(orgPolicies.enabled, true),
      ),
    });
    if (policy && !isAtLeast(membership.atype, MembershipType.Admin)) {
      err('You cannot join this organization until you enable two-step login on your user account');
    }
  }

  // Single-org policy of the target org
  const singleOrg = await db.query.orgPolicies.findFirst({
    where: and(
      eq(orgPolicies.orgUuid, orgId),
      eq(orgPolicies.atype, OrgPolicyType.SingleOrg),
      eq(orgPolicies.enabled, true),
    ),
  });
  if (singleOrg && !isAtLeast(membership.atype, MembershipType.Admin)) {
    const others = await db.query.usersOrganizations.findMany({
      where: eq(usersOrganizations.userUuid, user.uuid),
    });
    if (others.some((m) => m.orgUuid !== orgId && m.status >= MembershipStatus.Accepted)) {
      err(
        'You cannot join this organization because you are a member of another organization which forbids it',
      );
    }
  }

  await db
    .update(usersOrganizations)
    .set({ status: MembershipStatus.Accepted })
    .where(eq(usersOrganizations.uuid, memberId));

  if (mailer.enabled && membership.invitedByEmail) {
    const org = (await db.query.organizations.findFirst({ where: eq(organizations.uuid, orgId) }))!;
    c.executionCtx.waitUntil(
      mail.inviteAccepted(mailer, config, membership.invitedByEmail, user.email, org.name),
    );
  }

  return c.body(null, 200);
});

async function confirmMember(c: Ctx, orgId: string, memberId: string, key: string): Promise<void> {
  const db = c.get('db');
  const config = c.get('config');
  const { user: actor, device } = auth(c);

  const membership = await db.query.usersOrganizations.findFirst({
    where: and(eq(usersOrganizations.uuid, memberId), eq(usersOrganizations.orgUuid, orgId)),
  });
  if (!membership) err("The specified user isn't a member of the organization");
  if (membership.status !== MembershipStatus.Accepted)
    err("The specified user isn't in an Accepted state");
  if (membership.atype === MembershipType.Owner) {
    const actorMember = await findConfirmedMembership(db, actor.uuid, orgId);
    if (!actorMember || actorMember.atype !== MembershipType.Owner)
      err('Only Owners can confirm Owners');
  }

  await db
    .update(usersOrganizations)
    .set({ status: MembershipStatus.Confirmed, akey: key })
    .where(eq(usersOrganizations.uuid, memberId));

  const mailer = createMailer(c.env.EMAIL, config);
  if (mailer.enabled) {
    const target = (await db.query.users.findFirst({
      where: eq(users.uuid, membership.userUuid),
    }))!;
    const org = (await db.query.organizations.findFirst({ where: eq(organizations.uuid, orgId) }))!;
    await mail.inviteConfirmed(mailer, config, target.email, org.name);
  }

  await logOrgEvent(db, {
    eventType: EventType.OrganizationUserConfirmed,
    orgUuid: orgId,
    actUserUuid: actor.uuid,
    orgUserUuid: memberId,
    deviceType: device.atype,
    ip: c.get('ip'),
  });
}

orgMemberRoutes.post('/organizations/:orgId/users/:memberId/confirm', async (c) => {
  const orgId = c.req.param('orgId');
  await requireMember(c, orgId, MembershipType.Admin);
  const body = (await c.req.json()) as Record<string, unknown>;
  const key = ci<string>(body, 'key');
  if (!key) err('key cannot be blank');
  await confirmMember(c, orgId!, c.req.param('memberId')!, key);
  return c.body(null, 200);
});

orgMemberRoutes.post('/organizations/:orgId/users/confirm', async (c) => {
  const orgId = c.req.param('orgId');
  await requireMember(c, orgId, MembershipType.Admin);
  const body = (await c.req.json()) as Record<string, unknown>;
  const keys = ci<{ id: string; key: string }[]>(body, 'keys') ?? [];
  const results = [];
  for (const entry of keys) {
    let error = '';
    try {
      await confirmMember(c, orgId!, entry.id, entry.key);
    } catch (e) {
      error = e instanceof Error ? e.message : 'error';
    }
    results.push({ object: 'OrganizationBulkConfirmResponseModel', id: entry.id, error });
  }
  return c.json({ data: results, object: 'list', continuationToken: null });
});

// Bulk revoke/restore — registered before the /users/:memberId param routes
// so the static "revoke"/"restore" segments never match :memberId.
async function setRevokedBulk(c: Ctx, revoke: boolean) {
  const orgId = c.req.param('orgId');
  await requireMember(c, orgId, MembershipType.Admin);
  const body = (await c.req.json()) as Record<string, unknown>;
  const ids = ci<string[]>(body, 'ids') ?? [];
  const results = [];
  for (const id of ids) {
    let error = '';
    try {
      await setRevoked(c, orgId!, id, revoke);
    } catch (e) {
      error = e instanceof Error ? e.message : 'error';
    }
    results.push({ object: 'OrganizationUserBulkResponseModel', id, error });
  }
  return c.json({ data: results, object: 'list', continuationToken: null });
}
orgMemberRoutes.put('/organizations/:orgId/users/revoke', (c) => setRevokedBulk(c, true));
orgMemberRoutes.put('/organizations/:orgId/users/restore', (c) => setRevokedBulk(c, false));

orgMemberRoutes.get('/organizations/:orgId/users/:memberId', async (c) => {
  const orgId = c.req.param('orgId');
  await requireMember(c, orgId, MembershipType.Manager);
  const db = c.get('db');
  const membership = await db.query.usersOrganizations.findFirst({
    where: and(
      eq(usersOrganizations.uuid, c.req.param('memberId')!),
      eq(usersOrganizations.orgUuid, orgId!),
    ),
  });
  if (!membership) err("The specified user isn't a member of the organization");
  return c.json(
    await membershipUserDetailsJson(db, membership, {
      includeCollections: true,
      includeGroups: true,
    }),
  );
});

async function editMember(c: Ctx) {
  const { user: actor, device } = auth(c);
  const orgId = c.req.param('orgId')!;
  const actorMember = await requireMember(c, orgId, MembershipType.Admin);
  const db = c.get('db');
  const body = (await c.req.json()) as Record<string, unknown>;

  const membership = await db.query.usersOrganizations.findFirst({
    where: and(
      eq(usersOrganizations.uuid, c.req.param('memberId')!),
      eq(usersOrganizations.orgUuid, orgId),
    ),
  });
  if (!membership) err("The specified user isn't a member of the organization");

  const newType = parseMemberType(ci(body, 'type'));
  const accessAll = Boolean(ci(body, 'accessAll'));

  if (
    (newType === MembershipType.Owner || membership.atype === MembershipType.Owner) &&
    actorMember.atype !== MembershipType.Owner
  ) {
    err('Only Owners can grant and remove Owner privileges');
  }

  // Last confirmed owner cannot be demoted
  if (
    membership.atype === MembershipType.Owner &&
    newType !== MembershipType.Owner &&
    membership.status === MembershipStatus.Confirmed &&
    (await confirmedOwnerCount(db, orgId)) <= 1
  ) {
    err("Can't delete the last owner");
  }

  await db
    .update(usersOrganizations)
    .set({ atype: newType, accessAll })
    .where(eq(usersOrganizations.uuid, membership.uuid));

  if (!accessAll) {
    await replaceMemberCollections(db, membership, parseAssignments(ci(body, 'collections')));
  } else {
    await replaceMemberCollections(db, membership, []);
  }
  const groupIds = ci<string[]>(body, 'groups');
  if (groupIds !== undefined) await replaceMemberGroups(db, membership, groupIds ?? []);

  await logOrgEvent(db, {
    eventType: EventType.OrganizationUserUpdated,
    orgUuid: orgId,
    actUserUuid: actor.uuid,
    orgUserUuid: membership.uuid,
    deviceType: device.atype,
    ip: c.get('ip'),
  });
  return c.body(null, 200);
}
orgMemberRoutes.put('/organizations/:orgId/users/:memberId', editMember);
orgMemberRoutes.post('/organizations/:orgId/users/:memberId', editMember);

async function removeMember(c: Ctx, orgId: string, memberId: string): Promise<void> {
  const db = c.get('db');
  const { user: actor, device } = auth(c);
  const actorMember = await findConfirmedMembership(db, actor.uuid, orgId);

  const membership = await db.query.usersOrganizations.findFirst({
    where: and(eq(usersOrganizations.uuid, memberId), eq(usersOrganizations.orgUuid, orgId)),
  });
  if (!membership) err("User to delete isn't member of the organization");
  if (membership.atype === MembershipType.Owner) {
    if (actorMember?.atype !== MembershipType.Owner)
      err('Only Owners can delete Admins and Owners');
    if (
      membership.status === MembershipStatus.Confirmed &&
      (await confirmedOwnerCount(db, orgId)) <= 1
    ) {
      err("Can't delete the last owner");
    }
  }

  await db.delete(usersOrganizations).where(eq(usersOrganizations.uuid, membership.uuid));
  await logOrgEvent(db, {
    eventType: EventType.OrganizationUserRemoved,
    orgUuid: orgId,
    actUserUuid: actor.uuid,
    orgUserUuid: membership.uuid,
    deviceType: device.atype,
    ip: c.get('ip'),
  });
}

orgMemberRoutes.delete('/organizations/:orgId/users/:memberId', async (c) => {
  const orgId = c.req.param('orgId');
  await requireMember(c, orgId, MembershipType.Admin);
  await removeMember(c, orgId!, c.req.param('memberId')!);
  return c.body(null, 200);
});
orgMemberRoutes.post('/organizations/:orgId/users/:memberId/delete', async (c) => {
  const orgId = c.req.param('orgId');
  await requireMember(c, orgId, MembershipType.Admin);
  await removeMember(c, orgId!, c.req.param('memberId')!);
  return c.body(null, 200);
});
orgMemberRoutes.delete('/organizations/:orgId/users', async (c) => {
  const orgId = c.req.param('orgId');
  await requireMember(c, orgId, MembershipType.Admin);
  const body = (await c.req.json()) as Record<string, unknown>;
  const ids = ci<string[]>(body, 'ids') ?? [];
  const results = [];
  for (const id of ids) {
    let error = '';
    try {
      await removeMember(c, orgId!, id);
    } catch (e) {
      error = e instanceof Error ? e.message : 'error';
    }
    results.push({ object: 'OrganizationBulkConfirmResponseModel', id, error });
  }
  return c.json({ data: results, object: 'list', continuationToken: null });
});

async function setRevoked(c: Ctx, orgId: string, memberId: string, revoke: boolean): Promise<void> {
  const db = c.get('db');
  const { user: actor } = auth(c);
  const actorMember = await findConfirmedMembership(db, actor.uuid, orgId);

  const membership = await db.query.usersOrganizations.findFirst({
    where: and(eq(usersOrganizations.uuid, memberId), eq(usersOrganizations.orgUuid, orgId)),
  });
  if (!membership) err("User isn't member of the organization");

  if (revoke) {
    if (membership.status < MembershipStatus.Invited) err('User is already revoked');
    if (membership.atype === MembershipType.Owner) {
      if (actorMember?.atype !== MembershipType.Owner) err('Only owners can revoke other owners');
      if (
        membership.status === MembershipStatus.Confirmed &&
        (await confirmedOwnerCount(db, orgId)) <= 1
      ) {
        err('Organization must have at least one confirmed owner');
      }
    }
    // vaultwarden stores previous status as (status - 128)
    await db
      .update(usersOrganizations)
      .set({ status: membership.status - 128 })
      .where(eq(usersOrganizations.uuid, membership.uuid));
    await logOrgEvent(db, {
      eventType: EventType.OrganizationUserRevoked,
      orgUuid: orgId,
      actUserUuid: actor.uuid,
      orgUserUuid: membership.uuid,
      ip: c.get('ip'),
    });
  } else {
    if (membership.status >= MembershipStatus.Invited) err('User is not revoked');
    await db
      .update(usersOrganizations)
      .set({ status: membership.status + 128 })
      .where(eq(usersOrganizations.uuid, membership.uuid));
    await logOrgEvent(db, {
      eventType: EventType.OrganizationUserRestored,
      orgUuid: orgId,
      actUserUuid: actor.uuid,
      orgUserUuid: membership.uuid,
      ip: c.get('ip'),
    });
  }
}

for (const [path, revoke] of [
  ['revoke', true],
  ['restore', false],
] as const) {
  const handler = async (c: Ctx) => {
    const orgId = c.req.param('orgId');
    await requireMember(c, orgId, MembershipType.Admin);
    await setRevoked(c, orgId!, c.req.param('memberId')!, revoke);
    return c.body(null, 200);
  };
  orgMemberRoutes.put(`/organizations/:orgId/users/:memberId/${path}`, handler);
  // Newer clients append /vnext to the restore path
  if (path === 'restore') {
    orgMemberRoutes.put('/organizations/:orgId/users/:memberId/restore/vnext', handler);
  }
}

// ===========================================================================
// Groups
// ===========================================================================

function groupToJson(g: Group) {
  return {
    id: g.uuid,
    organizationId: g.organizationsUuid,
    name: g.name,
    externalId: g.externalId,
    object: 'group',
  };
}

orgMemberRoutes.get('/organizations/:orgId/groups', async (c) => {
  const orgId = c.req.param('orgId');
  await requireMember(c, orgId, MembershipType.Manager);
  const rows = await c
    .get('db')
    .query.groups.findMany({ where: eq(groups.organizationsUuid, orgId!) });
  return c.json({ data: rows.map(groupToJson), object: 'list', continuationToken: null });
});

// Groups with their collection assignments (admin console) — /groups/details
orgMemberRoutes.get('/organizations/:orgId/groups/details', async (c) => {
  const orgId = c.req.param('orgId')!;
  await requireMember(c, orgId, MembershipType.Manager);
  const db = c.get('db');
  const rows = await db.query.groups.findMany({ where: eq(groups.organizationsUuid, orgId) });
  const data = [];
  for (const g of rows) {
    const cols = await db
      .select()
      .from(collectionsGroups)
      .where(eq(collectionsGroups.groupsUuid, g.uuid));
    data.push({
      ...groupToJson(g),
      collections: cols.map((r) => ({
        id: r.collectionsUuid,
        readOnly: r.readOnly,
        hidePasswords: r.hidePasswords,
        manage: r.manage,
      })),
    });
  }
  return c.json({ data, object: 'list', continuationToken: null });
});

async function upsertGroup(c: Ctx, existing: Group | null) {
  const { user, device } = auth(c);
  const orgId = c.req.param('orgId')!;
  await requireMember(c, orgId, MembershipType.Admin);
  const db = c.get('db');
  const body = (await c.req.json()) as Record<string, unknown>;

  const name = ci<string>(body, 'name');
  if (!name) err('The field Name is required.');
  const accessAll = Boolean(ci(body, 'accessAll'));
  const externalId = (ci<string>(body, 'externalId') ?? null) as string | null;

  const now = nowDb();
  const group: Group = existing
    ? { ...existing, name, accessAll, externalId, revisionDate: now }
    : {
        uuid: uuid(),
        organizationsUuid: orgId,
        name,
        accessAll,
        externalId,
        creationDate: now,
        revisionDate: now,
      };

  if (existing) {
    await db
      .update(groups)
      .set({ name, accessAll, externalId, revisionDate: now })
      .where(eq(groups.uuid, group.uuid));
    await db.delete(collectionsGroups).where(eq(collectionsGroups.groupsUuid, group.uuid));
    await db.delete(groupsUsers).where(eq(groupsUsers.groupsUuid, group.uuid));
  } else {
    await db.insert(groups).values(group);
  }

  for (const a of parseAssignments(ci(body, 'collections'))) {
    await db.insert(collectionsGroups).values({
      collectionsUuid: a.id,
      groupsUuid: group.uuid,
      readOnly: a.readOnly,
      hidePasswords: a.hidePasswords,
      manage: a.manage,
    });
  }
  for (const memberId of ci<string[]>(body, 'users') ?? []) {
    const membership = await db.query.usersOrganizations.findFirst({
      where: and(eq(usersOrganizations.uuid, memberId), eq(usersOrganizations.orgUuid, orgId)),
    });
    if (!membership) continue;
    await db
      .insert(groupsUsers)
      .values({ groupsUuid: group.uuid, usersOrganizationsUuid: memberId })
      .onConflictDoNothing();
  }

  await logOrgEvent(db, {
    eventType: existing ? EventType.GroupUpdated : EventType.GroupCreated,
    orgUuid: orgId,
    actUserUuid: user.uuid,
    groupUuid: group.uuid,
    deviceType: device.atype,
    ip: c.get('ip'),
  });
  return c.json(groupToJson(group));
}

orgMemberRoutes.post('/organizations/:orgId/groups', (c) => upsertGroup(c, null));

async function loadGroup(c: Ctx, orgId: string): Promise<Group> {
  const group = await c
    .get('db')
    .query.groups.findFirst({ where: eq(groups.uuid, c.req.param('groupId')!) });
  if (!group || group.organizationsUuid !== orgId) notFound('Group not found');
  return group;
}

orgMemberRoutes.get('/organizations/:orgId/groups/:groupId/details', async (c) => {
  const orgId = c.req.param('orgId')!;
  await requireMember(c, orgId, MembershipType.Admin);
  const db = c.get('db');
  const group = await loadGroup(c, orgId);
  const cols = await db
    .select()
    .from(collectionsGroups)
    .where(eq(collectionsGroups.groupsUuid, group.uuid));
  const members = await db.select().from(groupsUsers).where(eq(groupsUsers.groupsUuid, group.uuid));
  return c.json({
    ...groupToJson(group),
    collections: cols.map((r) => ({
      id: r.collectionsUuid,
      readOnly: r.readOnly,
      hidePasswords: r.hidePasswords,
      manage: r.manage,
    })),
    users: members.map((m) => m.usersOrganizationsUuid),
  });
});

orgMemberRoutes.get('/organizations/:orgId/groups/:groupId', async (c) => {
  const orgId = c.req.param('orgId')!;
  await requireMember(c, orgId, MembershipType.Admin);
  return c.json(groupToJson(await loadGroup(c, orgId)));
});

async function updateGroupHandler(c: Ctx) {
  const orgId = c.req.param('orgId')!;
  await requireMember(c, orgId, MembershipType.Admin);
  return upsertGroup(c, await loadGroup(c, orgId));
}
orgMemberRoutes.put('/organizations/:orgId/groups/:groupId', updateGroupHandler);
orgMemberRoutes.post('/organizations/:orgId/groups/:groupId', updateGroupHandler);

// Remove a single member from a group
orgMemberRoutes.post('/organizations/:orgId/groups/:groupId/delete-user/:memberId', async (c) => {
  const orgId = c.req.param('orgId')!;
  await requireMember(c, orgId, MembershipType.Admin);
  const db = c.get('db');
  const group = await loadGroup(c, orgId);
  await db
    .delete(groupsUsers)
    .where(
      and(
        eq(groupsUsers.groupsUuid, group.uuid),
        eq(groupsUsers.usersOrganizationsUuid, c.req.param('memberId')!),
      ),
    );
  return c.body(null, 200);
});
orgMemberRoutes.delete('/organizations/:orgId/groups/:groupId/user/:memberId', async (c) => {
  const orgId = c.req.param('orgId')!;
  await requireMember(c, orgId, MembershipType.Admin);
  const db = c.get('db');
  const group = await loadGroup(c, orgId);
  await db
    .delete(groupsUsers)
    .where(
      and(
        eq(groupsUsers.groupsUuid, group.uuid),
        eq(groupsUsers.usersOrganizationsUuid, c.req.param('memberId')!),
      ),
    );
  return c.body(null, 200);
});

async function deleteGroupHandler(c: Ctx) {
  const { user, device } = auth(c);
  const orgId = c.req.param('orgId')!;
  await requireMember(c, orgId, MembershipType.Admin);
  const db = c.get('db');
  const group = await loadGroup(c, orgId);
  await db.delete(groups).where(eq(groups.uuid, group.uuid));
  await logOrgEvent(db, {
    eventType: EventType.GroupDeleted,
    orgUuid: orgId,
    actUserUuid: user.uuid,
    groupUuid: group.uuid,
    deviceType: device.atype,
    ip: c.get('ip'),
  });
  return c.body(null, 200);
}
orgMemberRoutes.delete('/organizations/:orgId/groups/:groupId', deleteGroupHandler);
orgMemberRoutes.post('/organizations/:orgId/groups/:groupId/delete', deleteGroupHandler);

// Bulk delete groups ({ ids }) via DELETE on the base path
orgMemberRoutes.delete('/organizations/:orgId/groups', async (c) => {
  const { user, device } = auth(c);
  const orgId = c.req.param('orgId')!;
  await requireMember(c, orgId, MembershipType.Admin);
  const db = c.get('db');
  const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
  const ids = ci<string[]>(body, 'ids') ?? [];
  for (const id of ids) {
    const group = await db.query.groups.findFirst({ where: eq(groups.uuid, id) });
    if (!group || group.organizationsUuid !== orgId) continue;
    await db.delete(groups).where(eq(groups.uuid, id));
    await logOrgEvent(db, {
      eventType: EventType.GroupDeleted,
      orgUuid: orgId,
      actUserUuid: user.uuid,
      groupUuid: id,
      deviceType: device.atype,
      ip: c.get('ip'),
    });
  }
  return c.body(null, 200);
});

orgMemberRoutes.get('/organizations/:orgId/groups/:groupId/users', async (c) => {
  const orgId = c.req.param('orgId')!;
  await requireMember(c, orgId, MembershipType.Admin);
  const group = await loadGroup(c, orgId);
  const rows = await c
    .get('db')
    .select()
    .from(groupsUsers)
    .where(eq(groupsUsers.groupsUuid, group.uuid));
  return c.json(rows.map((r) => r.usersOrganizationsUuid));
});

orgMemberRoutes.put('/organizations/:orgId/groups/:groupId/users', async (c) => {
  const orgId = c.req.param('orgId')!;
  await requireMember(c, orgId, MembershipType.Admin);
  const db = c.get('db');
  const group = await loadGroup(c, orgId);
  const memberIds = (await c.req.json()) as string[];
  await db.delete(groupsUsers).where(eq(groupsUsers.groupsUuid, group.uuid));
  for (const memberId of memberIds) {
    const membership = await db.query.usersOrganizations.findFirst({
      where: and(eq(usersOrganizations.uuid, memberId), eq(usersOrganizations.orgUuid, orgId)),
    });
    if (!membership) continue;
    await db
      .insert(groupsUsers)
      .values({ groupsUuid: group.uuid, usersOrganizationsUuid: memberId })
      .onConflictDoNothing();
  }
  return c.body(null, 200);
});

orgMemberRoutes.get('/organizations/:orgId/users/:memberId/groups', async (c) => {
  const orgId = c.req.param('orgId')!;
  await requireMember(c, orgId, MembershipType.Admin);
  const rows = await c
    .get('db')
    .select()
    .from(groupsUsers)
    .where(eq(groupsUsers.usersOrganizationsUuid, c.req.param('memberId')!));
  return c.json(rows.map((r) => r.groupsUuid));
});

orgMemberRoutes.put('/organizations/:orgId/users/:memberId/groups', async (c) => {
  const orgId = c.req.param('orgId')!;
  await requireMember(c, orgId, MembershipType.Admin);
  const db = c.get('db');
  const membership = await db.query.usersOrganizations.findFirst({
    where: and(
      eq(usersOrganizations.uuid, c.req.param('memberId')!),
      eq(usersOrganizations.orgUuid, orgId),
    ),
  });
  if (!membership) err("User isn't member of the organization");
  const body = (await c.req.json()) as Record<string, unknown>;
  await replaceMemberGroups(db, membership, ci<string[]>(body, 'groupIds') ?? []);
  return c.body(null, 200);
});

// ===========================================================================
// Policies
// ===========================================================================

orgMemberRoutes.get('/organizations/:orgId/policies', async (c) => {
  const orgId = c.req.param('orgId');
  await requireMember(c, orgId, MembershipType.Admin);
  const rows = await c
    .get('db')
    .query.orgPolicies.findMany({ where: eq(orgPolicies.orgUuid, orgId!) });
  return c.json({ data: rows.map(policyToJson), object: 'list', continuationToken: null });
});

orgMemberRoutes.get('/organizations/:orgId/policies/master-password', async (c) => {
  const orgId = c.req.param('orgId')!;
  await requireMember(c, orgId, MembershipType.User);
  const row = await c.get('db').query.orgPolicies.findFirst({
    where: and(eq(orgPolicies.orgUuid, orgId), eq(orgPolicies.atype, OrgPolicyType.MasterPassword)),
  });
  return c.json(
    row
      ? policyToJson(row)
      : { enabled: false, type: OrgPolicyType.MasterPassword, data: null, object: 'policy' },
  );
});

orgMemberRoutes.get('/organizations/:orgId/policies/:type', async (c) => {
  const orgId = c.req.param('orgId')!;
  await requireMember(c, orgId, MembershipType.Admin);
  const type = Number.parseInt(c.req.param('type')!, 10);
  const row = await c.get('db').query.orgPolicies.findFirst({
    where: and(eq(orgPolicies.orgUuid, orgId), eq(orgPolicies.atype, type)),
  });
  if (!row)
    return c.json({
      id: null,
      organizationId: orgId,
      type,
      data: null,
      enabled: false,
      object: 'policy',
    });
  return c.json(policyToJson(row));
});

async function putPolicyHandler(c: Ctx) {
  const { user: actor, device } = auth(c);
  const orgId = c.req.param('orgId')!;
  await requireMember(c, orgId, MembershipType.Admin);
  const db = c.get('db');
  const config = c.get('config');
  const type = Number.parseInt(c.req.param('type')!, 10);
  const body = (await c.req.json()) as Record<string, unknown>;
  const enabled = Boolean(ci(body, 'enabled'));
  const data = ci(body, 'data') ?? null;

  // Side effects when enabling (ported from vaultwarden put_policy)
  if (enabled) {
    const mailer = createMailer(c.env.EMAIL, config);
    const org = (await db.query.organizations.findFirst({ where: eq(organizations.uuid, orgId) }))!;
    const members = await db.query.usersOrganizations.findMany({
      where: eq(usersOrganizations.orgUuid, orgId),
    });

    if (type === OrgPolicyType.TwoFactorAuthentication) {
      for (const m of members) {
        if (isAtLeast(m.atype, MembershipType.Admin) || m.status < MembershipStatus.Accepted)
          continue;
        const tf = await db.query.twofactor.findFirst({
          where: eq(twofactor.userUuid, m.userUuid),
        });
        if (!tf) {
          await db
            .update(usersOrganizations)
            .set({ status: m.status - 128 })
            .where(eq(usersOrganizations.uuid, m.uuid));
          const target = (await db.query.users.findFirst({ where: eq(users.uuid, m.userUuid) }))!;
          c.executionCtx.waitUntil(
            mail.twoFactorRemovedFromOrg(mailer, config, target.email, org.name),
          );
        }
      }
    }

    if (type === OrgPolicyType.SingleOrg) {
      for (const m of members) {
        if (isAtLeast(m.atype, MembershipType.Admin) || m.status < MembershipStatus.Accepted)
          continue;
        const others = await db.query.usersOrganizations.findMany({
          where: eq(usersOrganizations.userUuid, m.userUuid),
        });
        if (others.some((o) => o.orgUuid !== orgId && o.status >= MembershipStatus.Accepted)) {
          await db
            .update(usersOrganizations)
            .set({ status: m.status - 128 })
            .where(eq(usersOrganizations.uuid, m.uuid));
          const target = (await db.query.users.findFirst({ where: eq(users.uuid, m.userUuid) }))!;
          c.executionCtx.waitUntil(
            mail.singleOrgRemovedFromOrg(mailer, config, target.email, org.name),
          );
        }
      }
    }
  }

  const existing = await db.query.orgPolicies.findFirst({
    where: and(eq(orgPolicies.orgUuid, orgId), eq(orgPolicies.atype, type)),
  });
  const row = {
    uuid: existing?.uuid ?? uuid(),
    orgUuid: orgId,
    atype: type,
    enabled,
    data: JSON.stringify(data),
  };
  if (existing) {
    await db
      .update(orgPolicies)
      .set({ enabled, data: row.data })
      .where(eq(orgPolicies.uuid, existing.uuid));
  } else {
    await db.insert(orgPolicies).values(row);
  }

  await logOrgEvent(db, {
    eventType: EventType.PolicyUpdated,
    orgUuid: orgId,
    actUserUuid: actor.uuid,
    policyUuid: row.uuid,
    deviceType: device.atype,
    ip: c.get('ip'),
  });
  return c.json(policyToJson(row));
}
orgMemberRoutes.put('/organizations/:orgId/policies/:type', putPolicyHandler);
orgMemberRoutes.put('/organizations/:orgId/policies/:type/vnext', putPolicyHandler);

// Auto-enroll status (admin password reset — not supported)
orgMemberRoutes.get('/organizations/:orgId/auto-enroll-status', async (c) => {
  const orgId = c.req.param('orgId')!;
  const org = await c
    .get('db')
    .query.organizations.findFirst({ where: eq(organizations.uuid, orgId) });
  if (!org) notFound("Organization doesn't exist");
  return c.json({ id: org.uuid, resetPasswordEnabled: false });
});

// Admin account recovery: view a member's reset-password details
orgMemberRoutes.get('/organizations/:orgId/users/:memberId/reset-password-details', async (c) => {
  const orgId = c.req.param('orgId')!;
  await requireMember(c, orgId, MembershipType.Admin);
  const db = c.get('db');
  const org = (await db.query.organizations.findFirst({ where: eq(organizations.uuid, orgId) }))!;
  const membership = await db.query.usersOrganizations.findFirst({
    where: and(
      eq(usersOrganizations.uuid, c.req.param('memberId')!),
      eq(usersOrganizations.orgUuid, orgId),
    ),
  });
  if (!membership) err("User to reset isn't member of required organization");
  const member = (await db.query.users.findFirst({ where: eq(users.uuid, membership.userUuid) }))!;
  return c.json({
    object: 'organizationUserResetPasswordDetails',
    organizationUserId: membership.uuid,
    kdf: member.clientKdfType,
    kdfIterations: member.clientKdfIter,
    kdfMemory: member.clientKdfMemory,
    kdfParallelism: member.clientKdfParallelism,
    resetPasswordKey: membership.resetPasswordKey,
    encryptedPrivateKey: org.privateKey,
  });
});

// Admin account recovery: reset a member's master password
orgMemberRoutes.put('/organizations/:orgId/users/:memberId/reset-password', async (c) => {
  const { user: actor, device } = auth(c);
  const orgId = c.req.param('orgId')!;
  await requireMember(c, orgId, MembershipType.Admin);
  const db = c.get('db');
  const config = c.get('config');
  const body = (await c.req.json()) as Record<string, unknown>;

  const membership = await db.query.usersOrganizations.findFirst({
    where: and(
      eq(usersOrganizations.uuid, c.req.param('memberId')!),
      eq(usersOrganizations.orgUuid, orgId),
    ),
  });
  if (!membership) err("User to reset isn't member of required organization");
  if (!membership.resetPasswordKey) err('Password reset not or not correctly enrolled');
  if (membership.status !== MembershipStatus.Confirmed) {
    err('Organization user must be confirmed for password reset functionality');
  }

  const newHash = ci<string>(body, 'newMasterPasswordHash');
  const key = ci<string>(body, 'key');
  if (!newHash || !key) err('Missing required fields');

  const member = (await db.query.users.findFirst({ where: eq(users.uuid, membership.userUuid) }))!;
  const org = (await db.query.organizations.findFirst({ where: eq(organizations.uuid, orgId) }))!;
  const pw = await passwordFields(newHash, config.passwordIterations);
  await db
    .update(users)
    .set({ ...pw, akey: key, securityStamp: uuid(), updatedAt: nowDb() })
    .where(eq(users.uuid, member.uuid));

  const mailer = createMailer(c.env.EMAIL, config);
  if (mailer.enabled) {
    c.executionCtx.waitUntil(
      mail.adminResetPassword(mailer, config, member.email, member.name, org.name),
    );
  }

  await logOrgEvent(db, {
    eventType: EventType.OrganizationUserAdminResetPassword,
    orgUuid: orgId,
    actUserUuid: actor.uuid,
    orgUserUuid: membership.uuid,
    deviceType: device.atype,
    ip: c.get('ip'),
  });
  return c.body(null, 200);
});

// Account-recovery (reset password) enrollment — user stores their org-wrapped
// key so admins can reset their master password (vaultwarden reset-password-enrollment).
orgMemberRoutes.put(
  '/organizations/:orgId/users/:memberId/reset-password-enrollment',
  async (c) => {
    const { user } = auth(c);
    const orgId = c.req.param('orgId')!;
    const memberId = c.req.param('memberId')!;
    const db = c.get('db');
    const body = (await c.req.json()) as Record<string, unknown>;

    const membership = await db.query.usersOrganizations.findFirst({
      where: and(eq(usersOrganizations.uuid, memberId), eq(usersOrganizations.orgUuid, orgId)),
    });
    if (!membership || membership.userUuid !== user.uuid) {
      err("User to enroll isn't member of required organization");
    }

    const rawKey = ci<string>(body, 'resetPasswordKey');
    const resetPasswordKey = rawKey && rawKey !== '' ? rawKey : null;

    await db
      .update(usersOrganizations)
      .set({ resetPasswordKey })
      .where(eq(usersOrganizations.uuid, memberId));

    await logOrgEvent(db, {
      eventType: resetPasswordKey
        ? EventType.OrganizationUserResetPasswordEnroll
        : EventType.OrganizationUserResetPasswordWithdraw,
      orgUuid: orgId,
      actUserUuid: user.uuid,
      orgUserUuid: memberId,
      ip: c.get('ip'),
    });
    return c.body(null, 200);
  },
);
