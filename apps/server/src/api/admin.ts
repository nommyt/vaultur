import { Hono } from 'hono';
import type { Context } from 'hono';
import { eq, sql } from 'drizzle-orm';
import { getCookie, setCookie } from 'hono/cookie';
import {
  attachments,
  ciphers,
  devices,
  invitations,
  nowDb,
  organizations,
  twofactor,
  users,
  usersOrganizations,
  toApi,
  type Db,
} from '@vaultur/db';
import { MembershipStatus } from '@vaultur/shared';
import type { AppEnv } from '../env';
import { errCode, unauthorized } from '../error';
import { basicClaims, decodeJwt, encodeJwt, issuer } from '../auth/jwt';
import { ci, constantTimeEqualStr, normalizeEmail, uuid } from '../util';
import { newUserShell } from '../services/users';

/**
 * Admin API (JSON-first port of vaultwarden src/api/admin.rs). Enabled only
 * when ADMIN_TOKEN is configured; otherwise every route 404s.
 */
export const adminRoutes = new Hono<AppEnv>();

type Ctx = Context<AppEnv>;

const ADMIN_COOKIE = 'VAULTUR_ADMIN';

// Disable the whole surface when no admin token is set
adminRoutes.use('*', async (c, next) => {
  if (!c.get('config').adminTokenSet) return c.body(null, 404);
  await next();
});

// Token login → admin session cookie. Registered for both '/' and '' so it
// matches whether the client posts to /admin or /admin/.
async function adminLogin(c: Ctx) {
  const contentType = c.req.header('Content-Type') ?? '';
  let token = '';
  if (contentType.includes('application/json')) {
    token = String(
      ci((await c.req.json().catch(() => ({}))) as Record<string, unknown>, 'token') ?? '',
    );
  } else {
    const form = await c.req.parseBody().catch(() => ({}) as Record<string, unknown>);
    token = typeof form.token === 'string' ? form.token : '';
  }

  if (!c.env.ADMIN_TOKEN || !constantTimeEqualStr(token, c.env.ADMIN_TOKEN)) {
    errCode('Invalid admin token', 401);
  }

  const config = c.get('config');
  const jwt = await encodeJwt(
    c.env.JWT_SECRET,
    basicClaims({
      domain: config.domain,
      kind: 'admin',
      sub: 'admin',
      ttlSeconds: config.adminSessionLifetimeMinutes * 60,
    }),
  );
  setCookie(c, ADMIN_COOKIE, jwt, {
    httpOnly: true,
    secure: true,
    sameSite: 'Strict',
    path: '/admin',
    maxAge: config.adminSessionLifetimeMinutes * 60,
  });
  return c.json({ ok: true });
}
adminRoutes.post('/', adminLogin);
adminRoutes.post('', adminLogin);

// Auth guard for the rest: admin cookie OR bearer ADMIN_TOKEN
adminRoutes.use('*', async (c, next) => {
  if (c.req.path === '/admin' || c.req.path === '/admin/') {
    await next();
    return;
  }
  const config = c.get('config');
  const bearer = c.req.header('Authorization') ?? '';
  const bearerToken = bearer.startsWith('Bearer ') ? bearer.slice(7) : '';
  if (c.env.ADMIN_TOKEN && bearerToken && constantTimeEqualStr(bearerToken, c.env.ADMIN_TOKEN)) {
    await next();
    return;
  }
  const cookie = getCookie(c, ADMIN_COOKIE);
  if (cookie) {
    try {
      await decodeJwt(c.env.JWT_SECRET, cookie, issuer(config.domain, 'admin'));
      await next();
      return;
    } catch {
      // fall through
    }
  }
  unauthorized('Admin authentication required');
});

async function userOverview(db: Db, userUuid: string) {
  const user = (await db.query.users.findFirst({ where: eq(users.uuid, userUuid) }))!;
  const cipherCount = (
    await db
      .select({ n: sql<number>`count(*)` })
      .from(ciphers)
      .where(eq(ciphers.userUuid, user.uuid))
  )[0]!.n;
  const attachmentSize = (
    await db
      .select({ total: sql<number>`coalesce(sum(${attachments.fileSize}), 0)` })
      .from(attachments)
      .innerJoin(ciphers, eq(attachments.cipherUuid, ciphers.uuid))
      .where(eq(ciphers.userUuid, user.uuid))
  )[0]!.total;
  const twoFactor =
    (await db.query.twofactor.findMany({ where: eq(twofactor.userUuid, user.uuid) })).length > 0;
  const orgCount = (
    await db
      .select({ n: sql<number>`count(*)` })
      .from(usersOrganizations)
      .where(eq(usersOrganizations.userUuid, user.uuid))
  )[0]!.n;

  return {
    id: user.uuid,
    name: user.name,
    email: user.email,
    emailVerified: user.verifiedAt != null,
    twoFactorEnabled: twoFactor,
    userEnabled: user.enabled,
    createdAt: toApi(user.createdAt),
    lastActive: toApi(user.updatedAt),
    cipherCount,
    attachmentCount: 0,
    attachmentSize,
    organizationCount: orgCount,
    object: 'adminUser',
  };
}

adminRoutes.get('/users', async (c) => {
  const db = c.get('db');
  const all = await db.select({ uuid: users.uuid }).from(users);
  const data = await Promise.all(all.map((u) => userOverview(db, u.uuid)));
  return c.json(data);
});

adminRoutes.get('/users/:uuid', async (c) => {
  const db = c.get('db');
  const user = await db.query.users.findFirst({ where: eq(users.uuid, c.req.param('uuid')) });
  if (!user) return c.json({ message: 'User not found' }, 404);
  return c.json(await userOverview(db, user.uuid));
});

adminRoutes.post('/users/:uuid/delete', async (c) => {
  await c
    .get('db')
    .delete(users)
    .where(eq(users.uuid, c.req.param('uuid')));
  return c.body(null, 200);
});

adminRoutes.post('/users/:uuid/deauth', async (c) => {
  const db = c.get('db');
  const uuidParam = c.req.param('uuid');
  await db.delete(devices).where(eq(devices.userUuid, uuidParam));
  await db
    .update(users)
    .set({ securityStamp: uuid(), updatedAt: nowDb() })
    .where(eq(users.uuid, uuidParam));
  return c.body(null, 200);
});

adminRoutes.post('/users/:uuid/disable', async (c) => {
  const db = c.get('db');
  const uuidParam = c.req.param('uuid');
  await db.delete(devices).where(eq(devices.userUuid, uuidParam));
  await db
    .update(users)
    .set({ enabled: false, securityStamp: uuid(), updatedAt: nowDb() })
    .where(eq(users.uuid, uuidParam));
  return c.body(null, 200);
});

adminRoutes.post('/users/:uuid/enable', async (c) => {
  await c
    .get('db')
    .update(users)
    .set({ enabled: true, updatedAt: nowDb() })
    .where(eq(users.uuid, c.req.param('uuid')));
  return c.body(null, 200);
});

adminRoutes.post('/users/:uuid/remove-2fa', async (c) => {
  const db = c.get('db');
  const uuidParam = c.req.param('uuid');
  await db.delete(twofactor).where(eq(twofactor.userUuid, uuidParam));
  await db.update(users).set({ totpRecover: null }).where(eq(users.uuid, uuidParam));
  return c.body(null, 200);
});

adminRoutes.post('/invite', async (c) => {
  const db = c.get('db');
  const config = c.get('config');
  const body = (await c.req.json()) as Record<string, unknown>;
  const email = normalizeEmail(String(ci(body, 'email') ?? ''));
  if (!email) return c.json({ message: 'Email required' }, 400);

  const existing = await db.query.users.findFirst({ where: eq(users.email, email) });
  if (existing) return c.json({ message: 'User already exists' }, 400);

  // Create a shell user + invitation (admin invites bypass signup restrictions)
  await db.insert(users).values(newUserShell(email, null));
  await db.insert(invitations).values({ email }).onConflictDoNothing();
  return c.json({ email, object: 'invitation' });
});

adminRoutes.get('/organizations', async (c) => {
  const db = c.get('db');
  const orgs = await db.select().from(organizations);
  const data = await Promise.all(
    orgs.map(async (org) => {
      const userCount = (
        await db
          .select({ n: sql<number>`count(*)` })
          .from(usersOrganizations)
          .where(eq(usersOrganizations.orgUuid, org.uuid))
      )[0]!.n;
      const cipherCount = (
        await db
          .select({ n: sql<number>`count(*)` })
          .from(ciphers)
          .where(eq(ciphers.organizationUuid, org.uuid))
      )[0]!.n;
      return {
        id: org.uuid,
        name: org.name,
        billingEmail: org.billingEmail,
        userCount,
        cipherCount,
        object: 'adminOrganization',
      };
    }),
  );
  return c.json(data);
});

adminRoutes.post('/organizations/:uuid/delete', async (c) => {
  const db = c.get('db');
  const orgId = c.req.param('uuid');
  await db.delete(ciphers).where(eq(ciphers.organizationUuid, orgId));
  await db.delete(organizations).where(eq(organizations.uuid, orgId));
  return c.body(null, 200);
});

adminRoutes.get('/diagnostics', async (c) => {
  const db = c.get('db');
  const userCount = (await db.select({ n: sql<number>`count(*)` }).from(users))[0]!.n;
  return c.json({
    version: '2025.12.0',
    dbType: 'd1',
    running: true,
    userCount,
    time: new Date().toISOString(),
  });
});
