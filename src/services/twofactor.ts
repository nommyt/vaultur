import { and, eq } from 'drizzle-orm';
import * as OTPAuth from 'otpauth';
import {
  devices,
  twofactor,
  twofactorIncomplete,
  usersOrganizations,
  orgPolicies,
  organizations,
  nowDb,
  users,
  type Db,
  type Device,
  type TwoFactor,
  type User,
} from '../db';
import { MembershipStatus, MembershipType, OrgPolicyType, TwoFactorType } from '../shared';
import type { Config } from '../config';
import { err, errJson } from '../error';
import { basicClaims, decodeJwt, encodeJwt, issuer } from '../auth/jwt';
import { constantTimeEqualStr, randomNumericCode, uuid } from '../util';
import { mail, type Mailer } from './mail';

const EMAIL_TOKEN_TTL_SECONDS = 600;
const EMAIL_ATTEMPTS_LIMIT = 3;
const REMEMBER_TTL_SECONDS = 30 * 24 * 60 * 60;

export interface EmailTokenData {
  email: string;
  last_token: string | null;
  token_sent: string;
  attempts: number;
}

export async function findTwoFactors(db: Db, userUuid: string): Promise<TwoFactor[]> {
  return db.query.twofactor.findMany({ where: eq(twofactor.userUuid, userUuid) });
}

/** Obscures the local part of an email — exact port of vaultwarden obscure_email. */
export function obscureEmail(email: string): string {
  const at = email.lastIndexOf('@');
  const name = at >= 0 ? email.slice(0, at) : email;
  const domain = at >= 0 ? email.slice(at + 1) : '';
  const size = [...name].length;
  const obscured =
    size >= 1 && size <= 3 ? '*'.repeat(size) : name.slice(0, 2) + '*'.repeat(size - 2);
  return `${obscured}@${domain}`;
}

// ---------------------------------------------------------------------------
// TOTP (authenticator)
// ---------------------------------------------------------------------------

/** Validates a TOTP code with ±1 step drift and replay protection (vaultwarden parity). */
export async function validateTotpCode(
  db: Db,
  userUuid: string,
  code: string,
  secret: string,
  ip: string,
): Promise<void> {
  if (!/^\d{6}$/.test(code)) err('TOTP code is not a number');

  let totp: OTPAuth.TOTP;
  try {
    totp = new OTPAuth.TOTP({
      secret: OTPAuth.Secret.fromBase32(secret.toUpperCase()),
      digits: 6,
      period: 30,
    });
  } catch {
    err('Invalid TOTP secret');
  }

  const record = await db.query.twofactor.findFirst({
    where: and(eq(twofactor.userUuid, userUuid), eq(twofactor.atype, TwoFactorType.Authenticator)),
  });

  const currentStep = Math.floor(Date.now() / 1000 / 30);
  for (const delta of [0, -1, 1]) {
    const step = currentStep + delta;
    const generated = totp.generate({ timestamp: step * 30 * 1000 });
    if (constantTimeEqualStr(generated, code)) {
      if (record && step <= record.lastUsed) {
        console.warn(`This TOTP token has already been used! IP: ${ip}`);
        err('TOTP code has already been used');
      }
      if (record) {
        await db.update(twofactor).set({ lastUsed: step }).where(eq(twofactor.uuid, record.uuid));
      }
      return;
    }
  }
  err(`Invalid TOTP code! Server time: ${new Date().toISOString()} IP: ${ip}`);
}

// ---------------------------------------------------------------------------
// Email 2FA
// ---------------------------------------------------------------------------

export async function sendEmailLoginToken(
  db: Db,
  mailer: Mailer,
  config: Config,
  userUuid: string,
  ip: string,
): Promise<void> {
  const record = await db.query.twofactor.findFirst({
    where: and(eq(twofactor.userUuid, userUuid), eq(twofactor.atype, TwoFactorType.Email)),
  });
  if (!record) err('No twofactor email registered');

  const data = JSON.parse(record.data) as EmailTokenData;
  const token = randomNumericCode(6);
  data.last_token = token;
  data.token_sent = nowDb();
  data.attempts = 0;
  await db
    .update(twofactor)
    .set({ data: JSON.stringify(data) })
    .where(eq(twofactor.uuid, record.uuid));
  await mail.twofactorEmail(mailer, config, data.email, token, ip);
}

export async function validateEmailCode(
  db: Db,
  userUuid: string,
  code: string,
  data: string,
): Promise<void> {
  const record = await db.query.twofactor.findFirst({
    where: and(eq(twofactor.userUuid, userUuid), eq(twofactor.atype, TwoFactorType.Email)),
  });
  if (!record) err('Two factor email is not enabled');

  const tokenData = JSON.parse(data) as EmailTokenData;
  if (!tokenData.last_token) err('No token available');

  if (!constantTimeEqualStr(tokenData.last_token, code)) {
    tokenData.attempts += 1;
    if (tokenData.attempts >= EMAIL_ATTEMPTS_LIMIT) tokenData.last_token = null;
    await db
      .update(twofactor)
      .set({ data: JSON.stringify(tokenData) })
      .where(eq(twofactor.uuid, record.uuid));
    err('Token is invalid');
  }

  const sentAt = new Date(`${tokenData.token_sent.replace(' ', 'T')}Z`).getTime();
  if (!Number.isFinite(sentAt) || Date.now() - sentAt > EMAIL_TOKEN_TTL_SECONDS * 1000) {
    err('Token has expired');
  }

  tokenData.last_token = null;
  tokenData.attempts = 0;
  await db
    .update(twofactor)
    .set({ data: JSON.stringify(tokenData) })
    .where(eq(twofactor.uuid, record.uuid));
}

// ---------------------------------------------------------------------------
// 2FA remember tokens (JWT, vaultwarden parity)
// ---------------------------------------------------------------------------

export async function generateRememberToken(
  config: Config,
  secret: string,
  device: Device,
): Promise<string> {
  return encodeJwt(
    secret,
    basicClaims({
      domain: config.domain,
      kind: '2faremember',
      sub: device.uuid,
      ttlSeconds: REMEMBER_TTL_SECONDS,
      extra: { user_uuid: device.userUuid },
    }),
  );
}

async function isValidRememberToken(
  config: Config,
  secret: string,
  token: string,
  device: Device,
): Promise<boolean> {
  try {
    const claims = await decodeJwt<{ sub: string; user_uuid: string; iss: string }>(
      secret,
      token,
      issuer(config.domain, '2faremember'),
    );
    return claims.sub === device.uuid && claims.user_uuid === device.userUuid;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Org 2FA policy enforcement
// ---------------------------------------------------------------------------

/**
 * Revokes org memberships that require 2FA when the user has none
 * (vaultwarden enforce_2fa_policy). Owners/Admins are exempt.
 */
export async function enforce2faPolicy(
  db: Db,
  mailer: Mailer,
  config: Config,
  user: User,
): Promise<void> {
  const rows = await db
    .select({
      membershipUuid: usersOrganizations.uuid,
      atype: usersOrganizations.atype,
      status: usersOrganizations.status,
      orgName: organizations.name,
    })
    .from(orgPolicies)
    .innerJoin(usersOrganizations, eq(orgPolicies.orgUuid, usersOrganizations.orgUuid))
    .innerJoin(organizations, eq(organizations.uuid, orgPolicies.orgUuid))
    .where(
      and(
        eq(orgPolicies.atype, OrgPolicyType.TwoFactorAuthentication),
        eq(orgPolicies.enabled, true),
        eq(usersOrganizations.userUuid, user.uuid),
      ),
    );

  for (const row of rows) {
    if (row.atype <= MembershipType.Admin) continue; // Owner=0 and Admin=1 are exempt
    if (row.status < MembershipStatus.Accepted) continue;
    await db
      .update(usersOrganizations)
      .set({ status: MembershipStatus.Revoked })
      .where(eq(usersOrganizations.uuid, row.membershipUuid));
    await mail.twoFactorRemovedFromOrg(mailer, config, user.email, row.orgName);
  }
}

// ---------------------------------------------------------------------------
// Login-time 2FA dispatch (vaultwarden twofactor_auth)
// ---------------------------------------------------------------------------

export interface TwoFactorLoginData {
  twoFactorProvider?: number;
  twoFactorToken?: string;
  twoFactorRemember?: number;
  clientVersion?: string;
}

export async function twofactorAuth(
  db: Db,
  mailer: Mailer,
  config: Config,
  secret: string,
  user: User,
  device: Device,
  data: TwoFactorLoginData,
  ip: string,
): Promise<string | null> {
  const twofactors = await findTwoFactors(db, user.uuid);

  if (twofactors.length === 0) {
    await enforce2faPolicy(db, mailer, config, user);
    return null;
  }

  await db
    .insert(twofactorIncomplete)
    .values({
      userUuid: user.uuid,
      deviceUuid: device.uuid,
      deviceName: device.name,
      deviceType: device.atype,
      loginTime: nowDb(),
      ipAddress: ip,
    })
    .onConflictDoNothing();

  const SUPPORTED = new Set<number>([TwoFactorType.Authenticator, TwoFactorType.Email]);
  const providerIds = twofactors
    .filter((tf) => tf.enabled && SUPPORTED.has(tf.atype))
    .map((tf) => tf.atype);
  if (providerIds.length === 0) {
    err('No enabled and usable two factor providers are available for this account');
  }

  const selectedId = data.twoFactorProvider ?? providerIds[0]!;
  const special = [TwoFactorType.Remember, TwoFactorType.RecoveryCode] as number[];
  if (!special.includes(selectedId) && !providerIds.includes(selectedId)) {
    errJson(
      await jsonErrTwofactor(db, mailer, config, providerIds, user.uuid, data, ip),
      'Invalid two factor provider',
    );
  }

  const code = data.twoFactorToken;
  if (!code) {
    errJson(
      await jsonErrTwofactor(db, mailer, config, providerIds, user.uuid, data, ip),
      '2FA token not provided',
    );
  }

  const selected = twofactors.find((tf) => tf.atype === selectedId && tf.enabled);

  switch (selectedId) {
    case TwoFactorType.Authenticator: {
      if (!selected) err("Two factor doesn't exist");
      await validateTotpCode(db, user.uuid, code, selected.data, ip);
      break;
    }
    case TwoFactorType.Email: {
      if (!selected) err("Two factor doesn't exist");
      await validateEmailCode(db, user.uuid, code, selected.data);
      break;
    }
    case TwoFactorType.Remember: {
      const ok =
        device.twofactorRemember != null &&
        constantTimeEqualStr(device.twofactorRemember, code) &&
        (await isValidRememberToken(config, secret, code, device));
      if (!ok) {
        errJson(
          await jsonErrTwofactor(db, mailer, config, providerIds, user.uuid, data, ip),
          '2FA Remember token not provided or expired',
        );
      }
      break;
    }
    case TwoFactorType.RecoveryCode: {
      if (
        !user.totpRecover ||
        !constantTimeEqualStr(user.totpRecover.toLowerCase(), code.replace(/\s/g, '').toLowerCase())
      ) {
        err('Recovery code is incorrect. Try again.');
      }
      await db.delete(twofactor).where(eq(twofactor.userUuid, user.uuid));
      await db.update(users).set({ totpRecover: null }).where(eq(users.uuid, user.uuid));
      await enforce2faPolicy(db, mailer, config, user);
      break;
    }
    default:
      err('Invalid two factor provider');
  }

  await db
    .delete(twofactorIncomplete)
    .where(
      and(
        eq(twofactorIncomplete.userUuid, user.uuid),
        eq(twofactorIncomplete.deviceUuid, device.uuid),
      ),
    );

  if (data.twoFactorRemember === 1) {
    const token = await generateRememberToken(config, secret, device);
    await db
      .update(devices)
      .set({ twofactorRemember: token })
      .where(and(eq(devices.uuid, device.uuid), eq(devices.userUuid, device.userUuid)));
    return token;
  }
  return null;
}

async function jsonErrTwofactor(
  db: Db,
  mailer: Mailer,
  config: Config,
  providers: number[],
  userUuid: string,
  data: TwoFactorLoginData,
  ip: string,
): Promise<Record<string, unknown>> {
  const providers2: Record<string, unknown> = {};

  for (const provider of providers) {
    providers2[String(provider)] = null;
    if (provider === TwoFactorType.Email) {
      const record = await db.query.twofactor.findFirst({
        where: and(eq(twofactor.userUuid, userUuid), eq(twofactor.atype, TwoFactorType.Email)),
      });
      if (!record) err('No twofactor email registered');
      const tokenData = JSON.parse(record.data) as EmailTokenData;

      // Clients >= 2025.5.0 call /api/two-factor/send-email-login themselves.
      const clientSendsItself = versionGte(data.clientVersion, [2025, 5, 0]);
      if (providers.length === 1 && !clientSendsItself) {
        await sendEmailLoginToken(db, mailer, config, userUuid, ip);
      }
      providers2[String(provider)] = { Email: obscureEmail(tokenData.email) };
    }
  }

  return {
    error: 'invalid_grant',
    error_description: 'Two factor required.',
    TwoFactorProviders: providers.map(String),
    TwoFactorProviders2: providers2,
    MasterPasswordPolicy: { Object: 'masterPasswordPolicy' },
  };
}

function versionGte(
  version: string | undefined,
  [maj, min, pat]: [number, number, number],
): boolean {
  if (!version) return false;
  const parts = version.split('.').map((p) => Number.parseInt(p, 10));
  const [a = 0, b = 0, c = 0] = parts;
  if (a !== maj) return a > maj;
  if (b !== min) return b > min;
  return c >= pat;
}
