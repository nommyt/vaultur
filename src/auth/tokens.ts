import type { Device, User } from '../db';
import type { Config } from '../config';
import { ACCESS_TOKEN_TTL_SECONDS, encodeJwt, issuer, type LoginJwtClaims } from './jwt';

export type AuthMethod = 'Password' | 'UserApiKey' | 'OrgApiKey' | 'Sso';

export function scopeFor(method: AuthMethod): string[] {
  switch (method) {
    case 'Password':
    case 'Sso':
      return ['api', 'offline_access'];
    case 'UserApiKey':
      return ['api'];
    case 'OrgApiKey':
      return ['api.organization'];
  }
}

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  scope: string;
}

export async function createAuthTokens(
  config: Config,
  secret: string,
  device: Device,
  user: User,
  method: AuthMethod,
  clientId: string | undefined,
): Promise<AuthTokens> {
  const now = Math.floor(Date.now() / 1000);
  const scope = scopeFor(method);
  const claims: LoginJwtClaims = {
    nbf: now,
    exp: now + ACCESS_TOKEN_TTL_SECONDS,
    iss: issuer(config.domain, 'login'),
    sub: user.uuid,
    premium: true,
    name: user.name,
    email: user.email,
    email_verified: user.verifiedAt != null,
    sstamp: user.securityStamp,
    device: device.uuid,
    devicetype: String(device.atype),
    client_id: clientId ?? 'undefined',
    scope,
    amr: ['Application'],
  };
  return {
    accessToken: await encodeJwt(secret, claims),
    refreshToken: device.refreshToken,
    expiresIn: ACCESS_TOKEN_TTL_SECONDS,
    scope: scope.join(' '),
  };
}
