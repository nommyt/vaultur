import { Hono } from 'hono';
import type { Context } from 'hono';
import { and, eq, or } from 'drizzle-orm';
import {
  ciphers,
  emergencyAccess,
  nowDb,
  toApi,
  twofactor,
  users,
  type Db,
  type EmergencyAccess,
} from '../db';
import { EmergencyAccessStatus, EmergencyAccessType } from '../shared';
import type { AppEnv } from '../env';
import { requireAuth, auth } from '../auth/middleware';
import { err, notFound } from '../error';
import { basicClaims, decodeJwt, encodeJwt, issuer } from '../auth/jwt';
import { ci, normalizeEmail, uuid } from '../util';
import { passwordFields, findUserByEmail } from '../services/users';
import { createMailer, mail } from '../services/mail';
import { cipherToJson, loadCipherSyncData } from '../services/vault';

/**
 * Emergency access, ported from vaultwarden src/api/core/emergency_access.rs.
 */
export const emergencyAccessRoutes = new Hono<AppEnv>();
emergencyAccessRoutes.use('*', requireAuth);

type Ctx = Context<AppEnv>;

function ensureEnabled(c: Ctx): void {
  if (!c.get('config').emergencyAccessAllowed) err('Emergency access is not allowed.');
}

function baseJson(ea: EmergencyAccess) {
  return {
    id: ea.uuid,
    status: ea.status,
    type: ea.atype,
    waitTimeDays: ea.waitTimeDays,
    object: 'emergencyAccess',
  };
}

// ---------------------------------------------------------------------------
// Listings
// ---------------------------------------------------------------------------

emergencyAccessRoutes.get('/emergency-access/trusted', async (c) => {
  ensureEnabled(c);
  const { user } = auth(c);
  const db = c.get('db');
  const rows = await db.query.emergencyAccess.findMany({
    where: eq(emergencyAccess.grantorUuid, user.uuid),
  });
  const data = [];
  for (const ea of rows) {
    let grantee = ea.granteeUuid
      ? await db.query.users.findFirst({ where: eq(users.uuid, ea.granteeUuid) })
      : null;
    if (!grantee && ea.email) grantee = (await findUserByEmail(db, ea.email)) ?? null;
    data.push({
      id: ea.uuid,
      status: ea.status,
      type: ea.atype,
      waitTimeDays: ea.waitTimeDays,
      granteeId: grantee?.uuid ?? null,
      email: grantee?.email ?? ea.email,
      name: grantee?.name ?? null,
      avatarColor: grantee?.avatarColor ?? null,
      object: 'emergencyAccessGranteeDetails',
    });
  }
  return c.json({ data, object: 'list', continuationToken: null });
});

emergencyAccessRoutes.get('/emergency-access/granted', async (c) => {
  ensureEnabled(c);
  const { user } = auth(c);
  const db = c.get('db');
  const rows = await db.query.emergencyAccess.findMany({
    where: eq(emergencyAccess.granteeUuid, user.uuid),
  });
  const data = [];
  for (const ea of rows) {
    const grantor = await db.query.users.findFirst({ where: eq(users.uuid, ea.grantorUuid) });
    data.push({
      id: ea.uuid,
      status: ea.status,
      type: ea.atype,
      waitTimeDays: ea.waitTimeDays,
      grantorId: grantor?.uuid ?? null,
      email: grantor?.email ?? null,
      name: grantor?.name ?? null,
      avatarColor: grantor?.avatarColor ?? null,
      object: 'emergencyAccessGrantorDetails',
    });
  }
  return c.json({ data, object: 'list', continuationToken: null });
});

async function loadForGrantor(c: Ctx, id: string | undefined): Promise<EmergencyAccess> {
  if (!id) notFound('Emergency access not valid.');
  const { user } = auth(c);
  const ea = await c.get('db').query.emergencyAccess.findFirst({
    where: and(eq(emergencyAccess.uuid, id), eq(emergencyAccess.grantorUuid, user.uuid)),
  });
  if (!ea) notFound('Emergency access not valid.');
  return ea;
}

async function loadForGrantee(c: Ctx, id: string | undefined): Promise<EmergencyAccess> {
  if (!id) notFound('Emergency access not valid.');
  const { user } = auth(c);
  const ea = await c.get('db').query.emergencyAccess.findFirst({
    where: and(eq(emergencyAccess.uuid, id), eq(emergencyAccess.granteeUuid, user.uuid)),
  });
  if (!ea) notFound('Emergency access not valid.');
  return ea;
}

// Static /invite must be registered before the /:id param routes below so it
// is not captured as an id (Hono matches in registration order).
emergencyAccessRoutes.post('/emergency-access/invite', async (c) => {
  ensureEnabled(c);
  const { user: grantor } = auth(c);
  const db = c.get('db');
  const config = c.get('config');
  const body = (await c.req.json()) as Record<string, unknown>;
  const email = normalizeEmail(String(ci(body, 'email') ?? ''));
  const type = Number(ci(body, 'type') ?? EmergencyAccessType.View);
  const waitTimeDays = Number(ci(body, 'waitTimeDays') ?? 7);
  if (!email) err('Email is required');
  if (email === grantor.email) err('You cannot use yourself as an emergency contact');
  if (waitTimeDays < 1) err('Wait time must be at least 1 day');

  const grantee = await findUserByEmail(db, email);
  const now = nowDb();
  const ea: EmergencyAccess = {
    uuid: uuid(),
    grantorUuid: grantor.uuid,
    granteeUuid: grantee?.uuid ?? null,
    email: grantee ? null : email,
    keyEncrypted: null,
    atype: type,
    status: EmergencyAccessStatus.Invited,
    waitTimeDays,
    recoveryInitiatedAt: null,
    lastNotificationAt: null,
    updatedAt: now,
    createdAt: now,
  };

  const mailer = createMailer(c.env.EMAIL, config);
  if (mailer.enabled) {
    const token = await encodeJwt(
      c.env.JWT_SECRET,
      basicClaims({
        domain: config.domain,
        kind: 'emergencyaccessinvite',
        sub: ea.uuid,
        ttlSeconds: 5 * 24 * 3600,
        extra: {
          email,
          emer_id: ea.uuid,
          grantor_name: grantor.name,
          grantor_email: grantor.email,
        },
      }),
    );
    await db.insert(emergencyAccess).values(ea);
    c.executionCtx.waitUntil(
      mail.emergencyAccessInvite(mailer, config, email, ea.uuid, grantor.name, token),
    );
  } else {
    // No mail: auto-accept if the grantee already has an account
    if (grantee) {
      ea.granteeUuid = grantee.uuid;
      ea.email = null;
      ea.status = EmergencyAccessStatus.Accepted;
    }
    await db.insert(emergencyAccess).values(ea);
  }

  return c.json(baseJson(ea));
});

emergencyAccessRoutes.get('/emergency-access/:id', async (c) => {
  ensureEnabled(c);
  const ea = await loadForGrantor(c, c.req.param('id'));
  return c.json(baseJson(ea));
});

async function updateEa(c: Ctx) {
  ensureEnabled(c);
  const ea = await loadForGrantor(c, c.req.param('id'));
  const body = (await c.req.json()) as Record<string, unknown>;
  const type = Number(ci(body, 'type') ?? ea.atype);
  const waitTimeDays = Number(ci(body, 'waitTimeDays') ?? ea.waitTimeDays);
  if (waitTimeDays < 1) err('Wait time must be at least 1 day');

  await c
    .get('db')
    .update(emergencyAccess)
    .set({ atype: type, waitTimeDays, updatedAt: nowDb() })
    .where(eq(emergencyAccess.uuid, ea.uuid));
  return c.json(baseJson({ ...ea, atype: type, waitTimeDays }));
}
emergencyAccessRoutes.put('/emergency-access/:id', updateEa);
emergencyAccessRoutes.post('/emergency-access/:id', updateEa);

async function deleteEa(c: Ctx) {
  ensureEnabled(c);
  const { user } = auth(c);
  const db = c.get('db');
  const id = c.req.param('id')!;
  // Either party can remove the relationship
  await db
    .delete(emergencyAccess)
    .where(
      and(
        eq(emergencyAccess.uuid, id),
        or(eq(emergencyAccess.grantorUuid, user.uuid), eq(emergencyAccess.granteeUuid, user.uuid)),
      ),
    );
  return c.body(null, 200);
}
emergencyAccessRoutes.delete('/emergency-access/:id', deleteEa);
emergencyAccessRoutes.post('/emergency-access/:id/delete', deleteEa);

// ---------------------------------------------------------------------------
// Invite → accept → confirm
// ---------------------------------------------------------------------------

emergencyAccessRoutes.post('/emergency-access/:id/reinvite', async (c) => {
  ensureEnabled(c);
  const ea = await loadForGrantor(c, c.req.param('id'));
  if (ea.status !== EmergencyAccessStatus.Invited) err('The invitation has already been accepted');
  const config = c.get('config');
  const mailer = createMailer(c.env.EMAIL, config);
  const { user: grantor } = auth(c);
  if (mailer.enabled && ea.email) {
    const token = await encodeJwt(
      c.env.JWT_SECRET,
      basicClaims({
        domain: config.domain,
        kind: 'emergencyaccessinvite',
        sub: ea.uuid,
        ttlSeconds: 5 * 24 * 3600,
        extra: {
          email: ea.email,
          emer_id: ea.uuid,
          grantor_name: grantor.name,
          grantor_email: grantor.email,
        },
      }),
    );
    await mail.emergencyAccessInvite(mailer, config, ea.email, ea.uuid, grantor.name, token);
  }
  return c.body(null, 200);
});

emergencyAccessRoutes.post('/emergency-access/:id/accept', async (c) => {
  ensureEnabled(c);
  const { user } = auth(c);
  const db = c.get('db');
  const config = c.get('config');
  const id = c.req.param('id')!;
  const body = (await c.req.json()) as Record<string, unknown>;
  const token = ci<string>(body, 'token');

  const ea = await db.query.emergencyAccess.findFirst({ where: eq(emergencyAccess.uuid, id) });
  if (!ea) notFound('Emergency access not valid.');
  if (ea.status !== EmergencyAccessStatus.Invited)
    err('Emergency access already accepted or confirmed.');

  const mailer = createMailer(c.env.EMAIL, config);
  if (mailer.enabled) {
    if (!token) err('Invite token required');
    try {
      const claims = await decodeJwt<{ emer_id: string; email: string }>(
        c.env.JWT_SECRET,
        token,
        issuer(config.domain, 'emergencyaccessinvite'),
      );
      if (claims.emer_id !== id || claims.email !== user.email) err('Invitation does not match');
    } catch {
      err('Invalid invite token');
    }
  } else if (ea.email && ea.email !== user.email) {
    err('Invitation does not match');
  }

  await db
    .update(emergencyAccess)
    .set({
      granteeUuid: user.uuid,
      email: null,
      status: EmergencyAccessStatus.Accepted,
      updatedAt: nowDb(),
    })
    .where(eq(emergencyAccess.uuid, id));

  if (mailer.enabled) {
    const grantor = await db.query.users.findFirst({ where: eq(users.uuid, ea.grantorUuid) });
    if (grantor)
      c.executionCtx.waitUntil(
        mail.emergencyAccessInviteAccepted(mailer, config, grantor.email, user.email),
      );
  }
  return c.body(null, 200);
});

emergencyAccessRoutes.post('/emergency-access/:id/confirm', async (c) => {
  ensureEnabled(c);
  const ea = await loadForGrantor(c, c.req.param('id'));
  if (ea.status !== EmergencyAccessStatus.Accepted) err('Emergency access not in accepted state.');
  const body = (await c.req.json()) as Record<string, unknown>;
  const key = ci<string>(body, 'key');
  if (!key) err('Key required');

  const db = c.get('db');
  const config = c.get('config');
  await db
    .update(emergencyAccess)
    .set({ keyEncrypted: key, status: EmergencyAccessStatus.Confirmed, updatedAt: nowDb() })
    .where(eq(emergencyAccess.uuid, ea.uuid));

  const mailer = createMailer(c.env.EMAIL, config);
  if (mailer.enabled && ea.granteeUuid) {
    const grantee = await db.query.users.findFirst({ where: eq(users.uuid, ea.granteeUuid) });
    const { user: grantor } = auth(c);
    if (grantee)
      c.executionCtx.waitUntil(
        mail.emergencyAccessInviteConfirmed(mailer, config, grantee.email, grantor.name),
      );
  }
  return c.body(null, 200);
});

// ---------------------------------------------------------------------------
// Recovery flow
// ---------------------------------------------------------------------------

emergencyAccessRoutes.post('/emergency-access/:id/initiate', async (c) => {
  ensureEnabled(c);
  const ea = await loadForGrantee(c, c.req.param('id'));
  if (ea.status !== EmergencyAccessStatus.Confirmed) err('Emergency access not confirmed.');

  const db = c.get('db');
  const config = c.get('config');
  const now = nowDb();
  await db
    .update(emergencyAccess)
    .set({
      status: EmergencyAccessStatus.RecoveryInitiated,
      recoveryInitiatedAt: now,
      updatedAt: now,
    })
    .where(eq(emergencyAccess.uuid, ea.uuid));

  const mailer = createMailer(c.env.EMAIL, config);
  if (mailer.enabled) {
    const grantor = await db.query.users.findFirst({ where: eq(users.uuid, ea.grantorUuid) });
    const { user: grantee } = auth(c);
    const typeName = ea.atype === EmergencyAccessType.Takeover ? 'takeover' : 'view';
    if (grantor) {
      c.executionCtx.waitUntil(
        mail.emergencyAccessRecoveryInitiated(
          mailer,
          config,
          grantor.email,
          grantee.name,
          typeName,
          ea.waitTimeDays,
        ),
      );
    }
  }
  return c.json(baseJson({ ...ea, status: EmergencyAccessStatus.RecoveryInitiated }));
});

emergencyAccessRoutes.post('/emergency-access/:id/approve', async (c) => {
  ensureEnabled(c);
  const ea = await loadForGrantor(c, c.req.param('id'));
  if (ea.status !== EmergencyAccessStatus.RecoveryInitiated)
    err('Emergency access not in recovery-initiated state.');

  const db = c.get('db');
  const config = c.get('config');
  await db
    .update(emergencyAccess)
    .set({ status: EmergencyAccessStatus.RecoveryApproved, updatedAt: nowDb() })
    .where(eq(emergencyAccess.uuid, ea.uuid));

  const mailer = createMailer(c.env.EMAIL, config);
  if (mailer.enabled && ea.granteeUuid) {
    const grantee = await db.query.users.findFirst({ where: eq(users.uuid, ea.granteeUuid) });
    const { user: grantor } = auth(c);
    if (grantee)
      c.executionCtx.waitUntil(
        mail.emergencyAccessRecoveryApproved(mailer, config, grantee.email, grantor.name),
      );
  }
  return c.body(null, 200);
});

emergencyAccessRoutes.post('/emergency-access/:id/reject', async (c) => {
  ensureEnabled(c);
  const ea = await loadForGrantor(c, c.req.param('id'));
  if (
    ea.status !== EmergencyAccessStatus.RecoveryInitiated &&
    ea.status !== EmergencyAccessStatus.RecoveryApproved
  ) {
    err('Emergency access not in recovery state.');
  }

  const db = c.get('db');
  const config = c.get('config');
  await db
    .update(emergencyAccess)
    .set({ status: EmergencyAccessStatus.Confirmed, recoveryInitiatedAt: null, updatedAt: nowDb() })
    .where(eq(emergencyAccess.uuid, ea.uuid));

  const mailer = createMailer(c.env.EMAIL, config);
  if (mailer.enabled && ea.granteeUuid) {
    const grantee = await db.query.users.findFirst({ where: eq(users.uuid, ea.granteeUuid) });
    const { user: grantor } = auth(c);
    if (grantee)
      c.executionCtx.waitUntil(
        mail.emergencyAccessRecoveryRejected(mailer, config, grantee.email, grantor.name),
      );
  }
  return c.body(null, 200);
});

// ---------------------------------------------------------------------------
// View / takeover / password
// ---------------------------------------------------------------------------

function isValidRequest(
  ea: EmergencyAccess,
  granteeUuid: string,
  type: EmergencyAccessType,
): boolean {
  return (
    ea.granteeUuid === granteeUuid &&
    ea.status === EmergencyAccessStatus.RecoveryApproved &&
    ea.atype === type
  );
}

emergencyAccessRoutes.post('/emergency-access/:id/view', async (c) => {
  ensureEnabled(c);
  const { user } = auth(c);
  const ea = await loadForGrantee(c, c.req.param('id'));
  if (!isValidRequest(ea, user.uuid, EmergencyAccessType.View)) err('Emergency access not valid.');

  const db = c.get('db');
  const grantorCiphers = await db
    .select()
    .from(ciphers)
    .where(eq(ciphers.userUuid, ea.grantorUuid));
  const sync = await loadCipherSyncData(db, ea.grantorUuid, 'user');
  const opts = {
    config: c.get('config'),
    secret: c.env.JWT_SECRET,
    userUuid: ea.grantorUuid,
    sync,
    syncType: 'user' as const,
  };
  const ciphersJson = await Promise.all(grantorCiphers.map((cph) => cipherToJson(cph, opts)));

  return c.json({
    ciphers: ciphersJson,
    keyEncrypted: ea.keyEncrypted,
    object: 'emergencyAccessView',
  });
});

emergencyAccessRoutes.post('/emergency-access/:id/takeover', async (c) => {
  ensureEnabled(c);
  const { user } = auth(c);
  const ea = await loadForGrantee(c, c.req.param('id'));
  if (!isValidRequest(ea, user.uuid, EmergencyAccessType.Takeover))
    err('Emergency access not valid.');

  const grantor = await c
    .get('db')
    .query.users.findFirst({ where: eq(users.uuid, ea.grantorUuid) });
  if (!grantor) err('Grantor user not found.');
  return c.json({
    kdf: grantor.clientKdfType,
    kdfIterations: grantor.clientKdfIter,
    kdfMemory: grantor.clientKdfMemory,
    kdfParallelism: grantor.clientKdfParallelism,
    keyEncrypted: ea.keyEncrypted,
    object: 'emergencyAccessTakeover',
  });
});

emergencyAccessRoutes.post('/emergency-access/:id/password', async (c) => {
  ensureEnabled(c);
  const { user } = auth(c);
  const ea = await loadForGrantee(c, c.req.param('id'));
  if (!isValidRequest(ea, user.uuid, EmergencyAccessType.Takeover))
    err('Emergency access not valid.');

  const body = (await c.req.json()) as Record<string, unknown>;
  const newHash = ci<string>(body, 'newMasterPasswordHash');
  const key = ci<string>(body, 'key');
  if (!newHash || !key) err('Missing required fields');

  const db = c.get('db');
  const config = c.get('config');
  const pw = await passwordFields(newHash, config.passwordIterations);
  await db
    .update(users)
    .set({ ...pw, akey: key, securityStamp: uuid(), updatedAt: nowDb() })
    .where(eq(users.uuid, ea.grantorUuid));
  // Takeover disables the grantor's 2FA (vaultwarden behavior)
  await db.delete(twofactor).where(eq(twofactor.userUuid, ea.grantorUuid));

  return c.body(null, 200);
});

// Policies applicable to a takeover (master password policies) — none by default
emergencyAccessRoutes.get('/emergency-access/:id/policies', async (c) => {
  ensureEnabled(c);
  const { user } = auth(c);
  const ea = await loadForGrantee(c, c.req.param('id'));
  if (!isValidRequest(ea, user.uuid, EmergencyAccessType.Takeover))
    err('Emergency access not valid.');
  return c.json({ data: [], object: 'list', continuationToken: null });
});
