import { Hono } from 'hono';
import type { Context } from 'hono';
import { and, eq, desc } from 'drizzle-orm';
import { authRequests, fromDb, nowDb, toApi, type AuthRequest, type Db } from '@vaultur/db';
import { DeviceType, EventType } from '@vaultur/shared';
import type { AppEnv } from '../env';
import { requireAuth, auth } from '../auth/middleware';
import { err, notFound } from '../error';
import { ci, constantTimeEqualStr, uuid } from '../util';
import { findUserByEmail } from '../services/users';
import { Notify } from '../services/notify';
import { logUserEvent } from '../services/events';

/**
 * Login-with-device auth requests, ported from vaultwarden
 * (src/api/core/accounts.rs auth-request handlers).
 */
export const authRequestRoutes = new Hono<AppEnv>();

type Ctx = Context<AppEnv>;

const AUTH_REQUEST_TTL_MS = 15 * 60 * 1000;

/** Device type display names (vaultwarden DeviceType Display impl). */
export function deviceTypeName(atype: number): string {
  const names: Record<number, string> = {
    [DeviceType.Android]: 'Android',
    [DeviceType.Ios]: 'iOS',
    [DeviceType.ChromeExtension]: 'Chrome Extension',
    [DeviceType.FirefoxExtension]: 'Firefox Extension',
    [DeviceType.OperaExtension]: 'Opera Extension',
    [DeviceType.EdgeExtension]: 'Edge Extension',
    [DeviceType.WindowsDesktop]: 'Windows',
    [DeviceType.MacOsDesktop]: 'macOS',
    [DeviceType.LinuxDesktop]: 'Linux',
    [DeviceType.ChromeBrowser]: 'Chrome',
    [DeviceType.FirefoxBrowser]: 'Firefox',
    [DeviceType.OperaBrowser]: 'Opera',
    [DeviceType.EdgeBrowser]: 'Edge',
    [DeviceType.IEBrowser]: 'Internet Explorer',
    [DeviceType.UnknownBrowser]: 'Unknown Browser',
    [DeviceType.AndroidAmazon]: 'Android',
    [DeviceType.Uwp]: 'UWP',
    [DeviceType.SafariBrowser]: 'Safari',
    [DeviceType.VivaldiBrowser]: 'Vivaldi',
    [DeviceType.VivaldiExtension]: 'Vivaldi Extension',
    [DeviceType.SafariExtension]: 'Safari Extension',
    [DeviceType.Sdk]: 'SDK',
    [DeviceType.Server]: 'Server',
    [DeviceType.WindowsCLI]: 'Windows CLI',
    [DeviceType.MacOsCLI]: 'macOS CLI',
    [DeviceType.LinuxCLI]: 'Linux CLI',
  };
  return names[atype] ?? 'Unknown Browser';
}

function isExpired(ar: AuthRequest): boolean {
  return Date.now() >= fromDb(ar.creationDate).getTime() + AUTH_REQUEST_TTL_MS;
}

function authRequestJson(ar: AuthRequest, domain: string, opts: { includeKey: boolean }) {
  return {
    id: ar.uuid,
    publicKey: ar.publicKey,
    requestDeviceType: deviceTypeName(ar.deviceType),
    requestIpAddress: ar.requestIp,
    key: opts.includeKey ? ar.encKey : null,
    masterPasswordHash: opts.includeKey ? ar.masterPasswordHash : null,
    creationDate: toApi(ar.creationDate),
    responseDate: toApi(ar.responseDate),
    requestApproved: ar.approved ?? false,
    origin: new URL(domain).origin,
    object: 'auth-request',
  };
}

// ---------------------------------------------------------------------------
// Public: create a request (from the unauthenticated new device) and poll it
// ---------------------------------------------------------------------------

authRequestRoutes.post('/auth-requests', async (c) => {
  const body = (await c.req.json()) as Record<string, unknown>;
  const email = String(ci(body, 'email') ?? '');
  const publicKey = ci<string>(body, 'publicKey');
  const deviceIdentifier = ci<string>(body, 'deviceIdentifier');
  const accessCode = ci<string>(body, 'accessCode');
  if (!email || !publicKey || !deviceIdentifier || !accessCode) err('Missing required fields');

  const db = c.get('db');
  const user = await findUserByEmail(db, email);
  if (!user) err("AuthRequest doesn't exist");

  const deviceTypeHeader = Number.parseInt(c.req.header('Device-Type') ?? '', 10);
  const deviceType = Number.isFinite(deviceTypeHeader)
    ? deviceTypeHeader
    : DeviceType.UnknownBrowser;

  const ar: AuthRequest = {
    uuid: uuid(),
    userUuid: user.uuid,
    organizationUuid: null,
    requestDeviceIdentifier: deviceIdentifier,
    deviceType,
    requestIp: c.get('ip'),
    responseDeviceId: null,
    accessCode,
    publicKey,
    encKey: null,
    masterPasswordHash: null,
    approved: null,
    creationDate: nowDb(),
    responseDate: null,
    authenticationDate: null,
  };
  await db.insert(authRequests).values(ar);

  new Notify(c.env, c.get('config'), c.executionCtx).authRequest(
    user.uuid,
    ar.uuid,
    deviceIdentifier,
  );
  await logUserEvent(db, EventType.UserLoggedIn, user.uuid, deviceType, c.get('ip'));

  return c.json(authRequestJson(ar, c.get('config').domain, { includeKey: false }));
});

authRequestRoutes.get('/auth-requests/:id/response', async (c) => {
  const db = c.get('db');
  const code = c.req.query('code') ?? '';
  const ar = await db.query.authRequests.findFirst({
    where: eq(authRequests.uuid, c.req.param('id')),
  });
  if (!ar || isExpired(ar) || !constantTimeEqualStr(ar.accessCode, code)) {
    notFound("AuthRequest doesn't exist");
  }
  return c.json(authRequestJson(ar, c.get('config').domain, { includeKey: true }));
});

// ---------------------------------------------------------------------------
// Authenticated: list, inspect, approve/deny
// ---------------------------------------------------------------------------

authRequestRoutes.use('*', requireAuth);

authRequestRoutes.get('/auth-requests', async (c) => {
  const { user } = auth(c);
  const rows = await c.get('db').query.authRequests.findMany({
    where: eq(authRequests.userUuid, user.uuid),
    orderBy: desc(authRequests.creationDate),
  });
  const domain = c.get('config').domain;
  return c.json({
    data: rows
      .filter((ar) => !isExpired(ar))
      .map((ar) => authRequestJson(ar, domain, { includeKey: true })),
    object: 'list',
    continuationToken: null,
  });
});

authRequestRoutes.get('/auth-requests/:id', async (c) => {
  const { user } = auth(c);
  const ar = await c.get('db').query.authRequests.findFirst({
    where: and(eq(authRequests.uuid, c.req.param('id')), eq(authRequests.userUuid, user.uuid)),
  });
  if (!ar || isExpired(ar)) err("AuthRequest doesn't exist");
  return c.json(authRequestJson(ar, c.get('config').domain, { includeKey: true }));
});

authRequestRoutes.put('/auth-requests/:id', async (c) => {
  const { user } = auth(c);
  const db = c.get('db');
  const body = (await c.req.json()) as Record<string, unknown>;
  const key = ci<string>(body, 'key');
  const masterPasswordHash = (ci<string>(body, 'masterPasswordHash') ?? null) as string | null;
  const requestApproved = Boolean(ci(body, 'requestApproved'));
  const deviceIdentifier = ci<string>(body, 'deviceIdentifier');
  if (!deviceIdentifier) err('deviceIdentifier cannot be blank');

  const ar = await db.query.authRequests.findFirst({
    where: and(eq(authRequests.uuid, c.req.param('id')), eq(authRequests.userUuid, user.uuid)),
  });
  if (!ar || isExpired(ar)) err("AuthRequest doesn't exist");
  if (ar.approved != null) err('An authentication request with the same device already exists');

  const responseDate = nowDb();
  await db
    .update(authRequests)
    .set({
      approved: requestApproved,
      encKey: requestApproved ? (key ?? null) : null,
      masterPasswordHash: requestApproved ? masterPasswordHash : null,
      responseDeviceId: deviceIdentifier,
      responseDate,
    })
    .where(eq(authRequests.uuid, ar.uuid));

  if (requestApproved) {
    new Notify(c.env, c.get('config'), c.executionCtx).authRequestResponse(
      user.uuid,
      ar.uuid,
      deviceIdentifier,
    );
  }

  const updated = (await db.query.authRequests.findFirst({
    where: eq(authRequests.uuid, ar.uuid),
  }))!;
  return c.json(authRequestJson(updated, c.get('config').domain, { includeKey: true }));
});
