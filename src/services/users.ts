import { eq } from 'drizzle-orm';
import { nowDb, users, type Db, type NewUser, type User } from '../db';
import { KDF_DEFAULTS, KdfType } from '../shared';
import { hashPassword } from '../crypto';
import { normalizeEmail, randomAlphanum, uuid } from '../util';

export async function findUserByEmail(db: Db, email: string): Promise<User | undefined> {
  return db.query.users.findFirst({ where: eq(users.email, normalizeEmail(email)) });
}

export async function findUserByUuid(db: Db, userUuid: string): Promise<User | undefined> {
  return db.query.users.findFirst({ where: eq(users.uuid, userUuid) });
}

/** Blank user shell — vaultwarden User::new. Password is set separately. */
export function newUserShell(email: string, name?: string | null): NewUser {
  const now = nowDb();
  return {
    uuid: uuid(),
    enabled: true,
    createdAt: now,
    updatedAt: now,
    email: normalizeEmail(email),
    name: name ?? normalizeEmail(email),
    passwordHash: '',
    salt: '',
    passwordIterations: 0,
    akey: '',
    securityStamp: uuid(),
    equivalentDomains: '[]',
    excludedGlobals: '[]',
    clientKdfType: KdfType.Pbkdf2,
    clientKdfIter: KDF_DEFAULTS.pbkdf2Iterations,
    loginVerifyCount: 0,
  };
}

export interface SetPasswordOptions {
  newKey?: string | null;
  resetSecurityStamp?: boolean;
  /** Route suffixes that stay allowed with the old stamp (vaultwarden stamp exception). */
  allowNextRoutes?: string[];
}

/** Computes server-side hash fields for a user (vaultwarden User::set_password). */
export async function passwordFields(
  clientHash: string,
  iterations: number,
): Promise<Pick<NewUser, 'passwordHash' | 'salt' | 'passwordIterations'>> {
  const rec = await hashPassword(clientHash, iterations);
  return { passwordHash: rec.hash, salt: rec.salt, passwordIterations: rec.iterations };
}

export function stampException(routes: string[], currentStamp: string): string {
  return JSON.stringify({
    routes,
    security_stamp: currentStamp,
    expire: Math.floor(Date.now() / 1000) + 90,
  });
}

/** Bumps the user revision date (returned by /api/accounts/revision-date). */
export async function touchUser(db: Db, userUuid: string): Promise<void> {
  await db.update(users).set({ updatedAt: nowDb() }).where(eq(users.uuid, userUuid));
}

export function generateApiKey(): string {
  return randomAlphanum(30);
}
