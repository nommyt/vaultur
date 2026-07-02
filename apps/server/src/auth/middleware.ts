import { createMiddleware } from 'hono/factory';
import { eq, and } from 'drizzle-orm';
import { devices, users, type Device, type User } from '@vaultur/db';
import type { AppEnv } from '../env';
import { unauthorized } from '../error';
import { decodeJwt, issuer, type LoginJwtClaims } from './jwt';

export interface AuthContext {
  user: User;
  device: Device;
  claims: LoginJwtClaims;
}

/**
 * Bearer-token guard for /api/* routes — vaultwarden's `Headers` guard.
 * Verifies the login JWT, loads user + device, and enforces the security stamp
 * (with stamp exceptions for the routes vaultwarden allows during forced
 * password resets).
 */
export const requireAuth = createMiddleware<AppEnv>(async (c, next) => {
  const header = c.req.header('Authorization') ?? c.req.query('access_token') ?? '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : header;
  if (!token) unauthorized('Missing access token');

  const config = c.get('config');
  let claims: LoginJwtClaims;
  try {
    claims = await decodeJwt<LoginJwtClaims>(
      c.env.JWT_SECRET,
      token,
      issuer(config.domain, 'login'),
    );
  } catch {
    unauthorized('Invalid claim');
  }

  const db = c.get('db');
  const user = await db.query.users.findFirst({ where: eq(users.uuid, claims.sub) });
  if (!user) unauthorized('Invalid claim');
  if (!user.enabled) unauthorized('This user has been disabled');

  if (user.securityStamp !== claims.sstamp) {
    // vaultwarden allows specific routes while a stamp exception is active
    let allowed = false;
    if (user.stampException) {
      try {
        const exception = JSON.parse(user.stampException) as {
          routes: string[];
          security_stamp: string;
          expire: number;
        };
        const path = new URL(c.req.url).pathname;
        if (
          exception.security_stamp === claims.sstamp &&
          exception.expire >= Math.floor(Date.now() / 1000) &&
          exception.routes.some((r) => path.endsWith(r))
        ) {
          allowed = true;
        }
      } catch {
        // fall through to reject
      }
    }
    if (!allowed) unauthorized('Invalid security stamp');
  }

  const device = await db.query.devices.findFirst({
    where: and(eq(devices.uuid, claims.device), eq(devices.userUuid, user.uuid)),
  });
  if (!device) unauthorized('Invalid device id');

  c.set('auth', { user, device, claims });
  await next();
});

/** Returns the authenticated context; only call under requireAuth. */
export function auth(c: { get: (key: 'auth') => AuthContext | undefined }): AuthContext {
  const ctx = c.get('auth');
  if (!ctx) unauthorized('Missing auth context');
  return ctx;
}
