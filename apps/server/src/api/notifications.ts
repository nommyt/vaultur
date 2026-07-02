import { Hono } from 'hono';
import type { Context } from 'hono';
import type { AppEnv } from '../env';
import { unauthorized } from '../error';
import { decodeJwt, issuer, type LoginJwtClaims } from '../auth/jwt';

/**
 * SignalR-compatible notification endpoints, ported from vaultwarden
 * src/api/notifications.rs. WebSocket state lives in the NotificationsHub
 * Durable Object; this module authenticates and proxies the upgrade.
 */
export const notificationRoutes = new Hono<AppEnv>();

type Ctx = Context<AppEnv>;

async function verifyAccessToken(c: Ctx): Promise<LoginJwtClaims> {
  const header = c.req.header('Authorization') ?? '';
  const token =
    c.req.query('access_token') ?? (header.startsWith('Bearer ') ? header.slice(7) : '');
  if (!token) unauthorized('Missing access token');
  try {
    return await decodeJwt<LoginJwtClaims>(
      c.env.JWT_SECRET,
      token,
      issuer(c.get('config').domain, 'login'),
    );
  } catch {
    unauthorized('Invalid claim');
  }
}

async function proxyToHub(c: Ctx, room: string): Promise<Response> {
  if (c.req.header('Upgrade')?.toLowerCase() !== 'websocket') {
    return c.json({ message: 'Expected websocket upgrade' }, 426);
  }
  const id = c.env.NOTIFICATIONS.idFromName(room);
  const stub = c.env.NOTIFICATIONS.get(id);
  const url = new URL(c.req.url);
  url.pathname = '/connect';
  return stub.fetch(new Request(url.toString(), c.req.raw));
}

notificationRoutes.get('/hub', async (c) => {
  const claims = await verifyAccessToken(c);
  return proxyToHub(c, claims.sub);
});

// SignalR negotiate — clients call this before the WebSocket connect
async function negotiate(c: Ctx) {
  await verifyAccessToken(c);
  return c.json({
    connectionId: crypto.randomUUID(),
    negotiateVersion: 0,
    availableTransports: [{ transport: 'WebSockets', transferFormats: ['Text', 'Binary'] }],
  });
}
notificationRoutes.post('/hub/negotiate', negotiate);
notificationRoutes.options('/hub/negotiate', (c) => c.body(null, 204));

// Anonymous hub: used by login-with-device before authentication.
// The token is the auth-request identifier; approvals are pushed to this room.
notificationRoutes.get('/anonymous-hub', async (c) => {
  const token = c.req.query('token') ?? c.req.query('Token') ?? '';
  if (!token) unauthorized('Missing token');
  return proxyToHub(c, `anon:${token}`);
});

notificationRoutes.post('/anonymous-hub/negotiate', (c) =>
  c.json({
    connectionId: crypto.randomUUID(),
    negotiateVersion: 0,
    availableTransports: [{ transport: 'WebSockets', transferFormats: ['Text', 'Binary'] }],
  }),
);
