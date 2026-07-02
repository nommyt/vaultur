import { Hono } from 'hono';
import type { Context } from 'hono';
import { and, eq } from 'drizzle-orm';
import {
  ciphers,
  devices,
  emergencyAccess,
  folders,
  fromDb,
  nowDb,
  sends as sendsTable,
  twofactor,
  users,
  type User,
} from '@vaultur/db';
import { EventType, TwoFactorType, UpdateType } from '@vaultur/shared';
import type { AppEnv } from '../env';
import { requireAuth, auth } from '../auth/middleware';
import { err, errCode, notFound, unauthorized } from '../error';
import { verifyPassword } from '../crypto';
import { basicClaims, decodeJwt, encodeJwt, issuer } from '../auth/jwt';
import { ci, normalizeEmail, randomNumericCode, uuid } from '../util';
import {
  findUserByEmail,
  generateApiKey,
  passwordFields,
  stampException,
  touchUser,
} from '../services/users';
import { createMailer, mail } from '../services/mail';
import { masterPasswordPolicy } from '../services/policies';
import { profileJson } from '../services/vault';
import { parseCipherData, updateCipherFromData } from '../services/ciphers';
import { Notify } from '../services/notify';
import { logUserEvent } from '../services/events';

export const accountRoutes = new Hono<AppEnv>();

type Ctx = Context<AppEnv>;

// Public endpoints first (no auth)
accountRoutes.post('/accounts/password-hint', async (c) => {
  const config = c.get('config');
  const body = (await c.req.json()) as Record<string, unknown>;
  const email = normalizeEmail(String(ci(body, 'email') ?? ''));
  if (!email) err('The field Email is required.');

  const mailer = createMailer(c.env.EMAIL, config);
  if (!config.passwordHintsAllow || (!mailer.enabled && !config.showPasswordHint)) {
    err('This server is not configured to provide password hints.');
  }

  const user = await findUserByEmail(c.get('db'), email);
  if (mailer.enabled) {
    if (user) {
      c.executionCtx.waitUntil(mail.passwordHint(mailer, config, email, user.passwordHint));
    }
    // Same response whether or not the user exists (anti-enumeration)
    return c.body(null, 200);
  }
  if (config.showPasswordHint && user?.passwordHint) {
    err(`Your password hint is: ${user.passwordHint}`);
  }
  err('Sorry, you have no password hint...');
});

// Email verification callback (public; token authenticated)
accountRoutes.post('/accounts/verify-email-token', async (c) => {
  const body = (await c.req.json()) as Record<string, unknown>;
  const userId = ci<string>(body, 'userId');
  const token = ci<string>(body, 'token');
  if (!userId || !token) err('UserId or Token missing');

  const db = c.get('db');
  const config = c.get('config');
  try {
    const claims = await decodeJwt<{ sub: string }>(
      c.env.JWT_SECRET,
      token,
      issuer(config.domain, 'verifyemail'),
    );
    if (claims.sub !== userId) err('Invalid claim');
  } catch {
    err('Invalid claim');
  }
  const user = await db.query.users.findFirst({ where: eq(users.uuid, userId) });
  if (!user) err("User doesn't exist");
  await db
    .update(users)
    .set({ verifiedAt: nowDb(), lastVerifyingAt: null, loginVerifyCount: 0, updatedAt: nowDb() })
    .where(eq(users.uuid, userId));
  return c.body(null, 200);
});

// Account recovery delete (public; token authenticated)
accountRoutes.post('/accounts/recover-delete', async (c) => {
  const config = c.get('config');
  const body = (await c.req.json()) as Record<string, unknown>;
  const email = normalizeEmail(String(ci(body, 'email') ?? ''));
  const mailer = createMailer(c.env.EMAIL, config);
  if (!mailer.enabled) err('Please contact the administrator to delete your account');

  const user = await findUserByEmail(c.get('db'), email);
  if (user) {
    const token = await encodeJwt(
      c.env.JWT_SECRET,
      basicClaims({ domain: config.domain, kind: 'delete', sub: user.uuid, ttlSeconds: 24 * 3600 }),
    );
    c.executionCtx.waitUntil(mail.deleteAccount(mailer, config, email, user.uuid, token));
  }
  return c.body(null, 200);
});

accountRoutes.post('/accounts/delete-recover-token', async (c) => {
  const body = (await c.req.json()) as Record<string, unknown>;
  const userId = ci<string>(body, 'userId');
  const token = ci<string>(body, 'token');
  if (!userId || !token) err('UserId or Token missing');

  const db = c.get('db');
  const config = c.get('config');
  try {
    const claims = await decodeJwt<{ sub: string }>(
      c.env.JWT_SECRET,
      token,
      issuer(config.domain, 'delete'),
    );
    if (claims.sub !== userId) err('Invalid claim');
  } catch {
    err('Invalid claim');
  }
  const user = await db.query.users.findFirst({ where: eq(users.uuid, userId) });
  if (!user) err("User doesn't exist");
  await db.delete(users).where(eq(users.uuid, userId));
  return c.body(null, 200);
});

// Everything below requires auth
accountRoutes.use('*', requireAuth);

// ---------------------------------------------------------------------------
// PasswordOrOtp verification (vaultwarden PasswordOrOtpData)
// ---------------------------------------------------------------------------

async function validatePasswordOrOtp(
  c: Ctx,
  user: User,
  body: Record<string, unknown>,
): Promise<void> {
  const passwordHash = ci<string>(body, 'masterPasswordHash');
  const otp = ci<string>(body, 'otp');
  if (passwordHash) {
    const valid = await verifyPassword(passwordHash, {
      hash: user.passwordHash,
      salt: user.salt,
      iterations: user.passwordIterations,
    });
    if (!valid) err('Invalid password');
    return;
  }
  if (otp) {
    const stored = await c.env.KV.get(`protected-action:${user.uuid}`);
    if (!stored || stored !== otp) err('Invalid token');
    await c.env.KV.delete(`protected-action:${user.uuid}`);
    return;
  }
  err('No validation provided');
}

// Send a protected-action OTP (used when user has no master password)
accountRoutes.post('/accounts/request-otp', async (c) => {
  const { user } = auth(c);
  const config = c.get('config');
  const mailer = createMailer(c.env.EMAIL, config);
  if (!mailer.enabled) err('Email is not enabled on this server');
  const token = randomNumericCode(6);
  await c.env.KV.put(`protected-action:${user.uuid}`, token, { expirationTtl: 600 });
  await mail.protectedAction(mailer, config, user.email, token);
  return c.body(null, 200);
});

accountRoutes.post('/accounts/verify-otp', async (c) => {
  const { user } = auth(c);
  const body = (await c.req.json()) as Record<string, unknown>;
  await validatePasswordOrOtp(c, user, { otp: ci<string>(body, 'otp') ?? ci<string>(body, 'OTP') });
  return c.body(null, 200);
});

// ---------------------------------------------------------------------------
// Profile
// ---------------------------------------------------------------------------

accountRoutes.get('/accounts/profile', async (c) => {
  const { user } = auth(c);
  return c.json(await profileJson(c.get('db'), user, c.get('config').emailEnabled));
});

async function updateProfile(c: Ctx) {
  const { user } = auth(c);
  const body = (await c.req.json()) as Record<string, unknown>;
  const name = ci<string>(body, 'name');
  if (name && name.length > 50) err('The field Name must be a string with a maximum length of 50.');

  const db = c.get('db');
  await db
    .update(users)
    .set({ name: name ?? user.name, updatedAt: nowDb() })
    .where(eq(users.uuid, user.uuid));
  const updated = (await db.query.users.findFirst({ where: eq(users.uuid, user.uuid) }))!;
  return c.json(await profileJson(db, updated, c.get('config').emailEnabled));
}
accountRoutes.post('/accounts/profile', updateProfile);
accountRoutes.put('/accounts/profile', updateProfile);

accountRoutes.put('/accounts/avatar', async (c) => {
  const { user } = auth(c);
  const body = (await c.req.json()) as Record<string, unknown>;
  const avatarColor = (ci<string>(body, 'avatarColor') ?? null) as string | null;
  const db = c.get('db');
  await db.update(users).set({ avatarColor, updatedAt: nowDb() }).where(eq(users.uuid, user.uuid));
  const updated = (await db.query.users.findFirst({ where: eq(users.uuid, user.uuid) }))!;
  return c.json(await profileJson(db, updated, c.get('config').emailEnabled));
});

accountRoutes.get('/users/:id/public-key', async (c) => {
  const db = c.get('db');
  const target = await db.query.users.findFirst({ where: eq(users.uuid, c.req.param('id')) });
  if (!target) notFound("User doesn't exist");
  return c.json({ userId: target.uuid, publicKey: target.publicKey, object: 'userKey' });
});

accountRoutes.post('/accounts/keys', async (c) => {
  const { user } = auth(c);
  const body = (await c.req.json()) as Record<string, unknown>;
  const encryptedPrivateKey = ci<string>(body, 'encryptedPrivateKey');
  const publicKey = ci<string>(body, 'publicKey');
  if (!encryptedPrivateKey || !publicKey) err('Keys missing');
  const db = c.get('db');
  await db
    .update(users)
    .set({ privateKey: encryptedPrivateKey, publicKey, updatedAt: nowDb() })
    .where(eq(users.uuid, user.uuid));
  return c.json({ privateKey: encryptedPrivateKey, publicKey, object: 'keys' });
});

// ---------------------------------------------------------------------------
// Password / KDF / security stamp
// ---------------------------------------------------------------------------

accountRoutes.post('/accounts/password', async (c) => {
  const { user, device } = auth(c);
  const config = c.get('config');
  const body = (await c.req.json()) as Record<string, unknown>;
  const currentHash = ci<string>(body, 'masterPasswordHash');
  const newHash = ci<string>(body, 'newMasterPasswordHash');
  const key = ci<string>(body, 'key');
  const hint = (ci<string>(body, 'masterPasswordHint') ?? null) as string | null;
  if (!currentHash || !newHash || !key) err('Missing required fields');

  const valid = await verifyPassword(currentHash, {
    hash: user.passwordHash,
    salt: user.salt,
    iterations: user.passwordIterations,
  });
  if (!valid) err('Invalid password');

  const db = c.get('db');
  const pw = await passwordFields(newHash, config.passwordIterations);
  const newStamp = uuid();
  await db
    .update(users)
    .set({
      ...pw,
      akey: key,
      passwordHint: hint && hint.trim() !== '' ? hint.trim() : null,
      securityStamp: newStamp,
      stampException: stampException(['/accounts/key-management/rotate'], user.securityStamp),
      updatedAt: nowDb(),
    })
    .where(eq(users.uuid, user.uuid));

  await logUserEvent(db, EventType.UserChangedPassword, user.uuid, device.atype, c.get('ip'));
  notifier(c).userUpdate(UpdateType.LogOut, user.uuid);
  return c.body(null, 200);
});

accountRoutes.post('/accounts/kdf', async (c) => {
  const { user } = auth(c);
  const config = c.get('config');
  const body = (await c.req.json()) as Record<string, unknown>;
  const currentHash = ci<string>(body, 'masterPasswordHash');
  const newHash = ci<string>(body, 'newMasterPasswordHash');
  const key = ci<string>(body, 'key');
  if (!currentHash || !newHash || !key) err('Missing required fields');

  const valid = await verifyPassword(currentHash, {
    hash: user.passwordHash,
    salt: user.salt,
    iterations: user.passwordIterations,
  });
  if (!valid) err('Invalid password');

  const kdf = Number(ci(body, 'kdf') ?? 0);
  const kdfIterations = Number(ci(body, 'kdfIterations') ?? 600_000);
  const kdfMemory = (ci<number>(body, 'kdfMemory') ?? null) as number | null;
  const kdfParallelism = (ci<number>(body, 'kdfParallelism') ?? null) as number | null;

  const db = c.get('db');
  const pw = await passwordFields(newHash, config.passwordIterations);
  await db
    .update(users)
    .set({
      ...pw,
      akey: key,
      clientKdfType: kdf,
      clientKdfIter: kdfIterations,
      clientKdfMemory: kdf === 1 ? kdfMemory : null,
      clientKdfParallelism: kdf === 1 ? kdfParallelism : null,
      securityStamp: uuid(),
      updatedAt: nowDb(),
    })
    .where(eq(users.uuid, user.uuid));

  notifier(c).userUpdate(UpdateType.LogOut, user.uuid);
  return c.body(null, 200);
});

accountRoutes.post('/accounts/security-stamp', async (c) => {
  const { user } = auth(c);
  const body = (await c.req.json()) as Record<string, unknown>;
  await validatePasswordOrOtp(c, user, body);

  const db = c.get('db');
  await db.delete(devices).where(eq(devices.userUuid, user.uuid));
  await db
    .update(users)
    .set({ securityStamp: uuid(), updatedAt: nowDb() })
    .where(eq(users.uuid, user.uuid));
  notifier(c).userUpdate(UpdateType.LogOut, user.uuid);
  return c.body(null, 200);
});

accountRoutes.post('/accounts/verify-password', async (c) => {
  const { user } = auth(c);
  const body = (await c.req.json()) as Record<string, unknown>;
  const passwordHash = ci<string>(body, 'masterPasswordHash');
  if (!passwordHash) err('masterPasswordHash cannot be blank');
  const valid = await verifyPassword(passwordHash, {
    hash: user.passwordHash,
    salt: user.salt,
    iterations: user.passwordIterations,
  });
  if (!valid) err('Invalid password');
  return c.json(await masterPasswordPolicy(c.get('db'), user.uuid));
});

// ---------------------------------------------------------------------------
// Email change
// ---------------------------------------------------------------------------

accountRoutes.post('/accounts/email-token', async (c) => {
  const { user } = auth(c);
  const config = c.get('config');
  const body = (await c.req.json()) as Record<string, unknown>;
  const newEmail = normalizeEmail(String(ci(body, 'newEmail') ?? ''));
  const passwordHash = ci<string>(body, 'masterPasswordHash');
  if (!passwordHash) err('masterPasswordHash cannot be blank');

  const valid = await verifyPassword(passwordHash, {
    hash: user.passwordHash,
    salt: user.salt,
    iterations: user.passwordIterations,
  });
  if (!valid) err('Invalid password');

  const db = c.get('db');
  if (await findUserByEmail(db, newEmail)) err('Email already in use');

  const token = randomNumericCode(6);
  await db
    .update(users)
    .set({ emailNew: newEmail, emailNewToken: token, updatedAt: nowDb() })
    .where(eq(users.uuid, user.uuid));

  const mailer = createMailer(c.env.EMAIL, config);
  if (mailer.enabled) {
    c.executionCtx.waitUntil(mail.changeEmail(mailer, config, newEmail, token));
    c.executionCtx.waitUntil(mail.changeEmailExisting(mailer, config, user.email, newEmail));
  } else {
    console.warn(`Email change token for ${user.email}: ${token}`);
  }
  return c.body(null, 200);
});

accountRoutes.post('/accounts/email', async (c) => {
  const { user } = auth(c);
  const config = c.get('config');
  const body = (await c.req.json()) as Record<string, unknown>;
  const newEmail = normalizeEmail(String(ci(body, 'newEmail') ?? ''));
  const passwordHash = ci<string>(body, 'masterPasswordHash');
  const newHash = ci<string>(body, 'newMasterPasswordHash');
  const key = ci<string>(body, 'key');
  const token = ci<string>(body, 'token');
  if (!passwordHash || !newHash || !key || !token) err('Missing required fields');

  const valid = await verifyPassword(passwordHash, {
    hash: user.passwordHash,
    salt: user.salt,
    iterations: user.passwordIterations,
  });
  if (!valid) err('Invalid password');

  const db = c.get('db');
  if (await findUserByEmail(db, newEmail)) err('Email already in use');
  if (user.emailNew !== newEmail || user.emailNewToken !== token) err('Email change mismatch');

  const pw = await passwordFields(newHash, config.passwordIterations);
  await db
    .update(users)
    .set({
      email: newEmail,
      emailNew: null,
      emailNewToken: null,
      verifiedAt: config.emailEnabled ? nowDb() : null,
      ...pw,
      akey: key,
      securityStamp: uuid(),
      updatedAt: nowDb(),
    })
    .where(eq(users.uuid, user.uuid));

  notifier(c).userUpdate(UpdateType.LogOut, user.uuid);
  return c.body(null, 200);
});

accountRoutes.post('/accounts/verify-email', async (c) => {
  const { user } = auth(c);
  const config = c.get('config');
  const mailer = createMailer(c.env.EMAIL, config);
  if (!mailer.enabled) err('Cannot verify email address');
  const token = await encodeJwt(
    c.env.JWT_SECRET,
    basicClaims({
      domain: config.domain,
      kind: 'verifyemail',
      sub: user.uuid,
      ttlSeconds: 5 * 24 * 3600,
    }),
  );
  c.executionCtx.waitUntil(mail.verifyEmail(mailer, config, user.email, user.uuid, token));
  return c.body(null, 200);
});

// ---------------------------------------------------------------------------
// API key
// ---------------------------------------------------------------------------

async function apiKeyHandler(c: Ctx, rotate: boolean) {
  const { user } = auth(c);
  const body = (await c.req.json()) as Record<string, unknown>;
  await validatePasswordOrOtp(c, user, body);

  const db = c.get('db');
  let apiKey = user.apiKey;
  if (rotate || !apiKey) {
    apiKey = generateApiKey();
    await db.update(users).set({ apiKey, updatedAt: nowDb() }).where(eq(users.uuid, user.uuid));
  }
  const updated = (await db.query.users.findFirst({ where: eq(users.uuid, user.uuid) }))!;
  return c.json({
    apiKey,
    revisionDate: fromDb(updated.updatedAt).toISOString(),
    object: 'apiKey',
  });
}

accountRoutes.post('/accounts/api-key', (c) => apiKeyHandler(c, false));
accountRoutes.post('/accounts/rotate-api-key', (c) => apiKeyHandler(c, true));

// ---------------------------------------------------------------------------
// Key rotation
// ---------------------------------------------------------------------------

const ROTATE_PATHS = ['/accounts/key', '/accounts/key-management/rotate'] as const;
for (const path of ROTATE_PATHS) {
  accountRoutes.post(path, rotateKey);
  accountRoutes.put(path, rotateKey);
}

async function rotateKey(c: Ctx) {
  const { user, device } = auth(c);
  const config = c.get('config');
  const db = c.get('db');
  const body = (await c.req.json()) as Record<string, unknown>;

  // Newer clients wrap data in accountUnlockData/accountKeys/accountData
  const unlockData = ci<Record<string, unknown>>(body, 'accountUnlockData');
  const accountKeys = ci<Record<string, unknown>>(body, 'accountKeys');
  const accountData = ci<Record<string, unknown>>(body, 'accountData');

  let masterPasswordHash: string | undefined;
  let newMasterPasswordHash: string | undefined;
  let key: string | undefined;
  let privateKey: string | undefined;
  let cipherList: Record<string, unknown>[];
  let folderList: Record<string, unknown>[];

  if (unlockData && accountKeys && accountData) {
    const mpu = ci<Record<string, unknown>>(unlockData, 'masterPasswordUnlockData') ?? {};
    masterPasswordHash = ci<string>(mpu, 'masterKeyAuthenticationHash');
    newMasterPasswordHash = masterPasswordHash;
    key = ci<string>(mpu, 'masterKeyEncryptedUserKey');
    const keyPair = ci<Record<string, unknown>>(accountKeys, 'accountPublicKey')
      ? accountKeys
      : (ci<Record<string, unknown>>(accountKeys, 'publicKeyEncryptionKeyPair') ?? accountKeys);
    privateKey =
      ci<string>(keyPair, 'wrappedPrivateKey') ??
      ci<string>(accountKeys, 'userKeyEncryptedAccountPrivateKey');
    cipherList = ci<Record<string, unknown>[]>(accountData, 'ciphers') ?? [];
    folderList = ci<Record<string, unknown>[]>(accountData, 'folders') ?? [];
  } else {
    masterPasswordHash = ci<string>(body, 'masterPasswordHash');
    newMasterPasswordHash = ci<string>(body, 'newMasterPasswordHash') ?? masterPasswordHash;
    key = ci<string>(body, 'key');
    privateKey = ci<string>(body, 'privateKey');
    cipherList = ci<Record<string, unknown>[]>(body, 'ciphers') ?? [];
    folderList = ci<Record<string, unknown>[]>(body, 'folders') ?? [];
  }

  if (!masterPasswordHash || !key) err('Missing required fields');

  const valid = await verifyPassword(masterPasswordHash, {
    hash: user.passwordHash,
    salt: user.salt,
    iterations: user.passwordIterations,
  });
  if (!valid) err('Invalid password');

  // Update folders
  for (const f of folderList) {
    const id = ci<string>(f, 'id');
    const name = ci<string>(f, 'name');
    if (!id || !name) continue;
    await db
      .update(folders)
      .set({ name, updatedAt: nowDb() })
      .where(and(eq(folders.uuid, id), eq(folders.userUuid, user.uuid)));
  }

  // Update ciphers (owned only)
  for (const cb of cipherList) {
    const data = parseCipherData(cb);
    if (data.organizationId || !data.id) continue;
    const cipher = await db.query.ciphers.findFirst({
      where: and(eq(ciphers.uuid, data.id), eq(ciphers.userUuid, user.uuid)),
    });
    if (!cipher) err('The cipher is not owned by the user');
    data.lastKnownRevisionDate = null;
    await updateCipherFromData(
      cipher,
      data,
      { db, userUuid: user.uuid },
      { skipRevisionCheck: true },
    );
  }

  // Update sends
  const sendList =
    ci<Record<string, unknown>[]>(body, 'sends') ??
    ci<Record<string, unknown>[]>(accountData ?? {}, 'sends') ??
    [];
  for (const s of sendList) {
    const id = ci<string>(s, 'id');
    const akey = ci<string>(s, 'key');
    if (!id || !akey) continue;
    await db
      .update(sendsTable)
      .set({ akey, revisionDate: nowDb() })
      .where(and(eq(sendsTable.uuid, id), eq(sendsTable.userUuid, user.uuid)));
  }

  // Update emergency access keys
  const emergencyList =
    ci<Record<string, unknown>[]>(body, 'emergencyAccessKeys') ??
    ci<Record<string, unknown>[]>(accountData ?? {}, 'emergencyAccessKeys') ??
    [];
  for (const ea of emergencyList) {
    const id = ci<string>(ea, 'id');
    const keyEncrypted = ci<string>(ea, 'keyEncrypted');
    if (!id || !keyEncrypted) continue;
    await db
      .update(emergencyAccess)
      .set({ keyEncrypted, updatedAt: nowDb() })
      .where(and(eq(emergencyAccess.uuid, id), eq(emergencyAccess.grantorUuid, user.uuid)));
  }

  const pw = await passwordFields(newMasterPasswordHash!, config.passwordIterations);
  await db
    .update(users)
    .set({
      ...pw,
      akey: key,
      privateKey: privateKey ?? user.privateKey,
      securityStamp: uuid(),
      updatedAt: nowDb(),
    })
    .where(eq(users.uuid, user.uuid));

  notifier(c).userUpdate(UpdateType.LogOut, user.uuid);
  return c.body(null, 200);
}

// ---------------------------------------------------------------------------
// Delete account, revision date, misc
// ---------------------------------------------------------------------------

async function deleteAccount(c: Ctx) {
  const { user } = auth(c);
  const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
  await validatePasswordOrOtp(c, user, body);
  await c.get('db').delete(users).where(eq(users.uuid, user.uuid));
  return c.body(null, 200);
}
accountRoutes.delete('/accounts', deleteAccount);
accountRoutes.post('/accounts/delete', deleteAccount);

accountRoutes.get('/accounts/revision-date', async (c) => {
  const { user } = auth(c);
  return c.json(fromDb(user.updatedAt).getTime());
});

// Pending auth tasks (newer clients poll this)
accountRoutes.get('/tasks', (c) => c.json({ data: [], object: 'list', continuationToken: null }));

function notifier(c: Ctx): Notify {
  return new Notify(c.env, c.get('config'), c.executionCtx);
}
