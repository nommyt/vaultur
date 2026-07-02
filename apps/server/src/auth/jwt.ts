import { sign, verify } from 'hono/jwt';
import type { JWTPayload } from 'hono/utils/jwt/types';

/**
 * JWT issuance/verification, ported from vaultwarden src/auth.rs.
 * HS256 with the JWT_SECRET secret (vaultwarden uses RS256 with a generated
 * keypair; clients never validate the signature, only the server does).
 *
 * Issuer is `<domain-origin>|<kind>` exactly like vaultwarden.
 */

export type JwtKind =
  | 'login'
  | 'invite'
  | 'emergencyaccessinvite'
  | 'delete'
  | 'verifyemail'
  | 'admin'
  | 'send'
  | 'api.organization'
  | 'file_download'
  | 'register_verify'
  | '2faremember';

export interface LoginJwtClaims extends JWTPayload {
  nbf: number;
  exp: number;
  iss: string;
  sub: string; // user uuid
  premium: boolean;
  name: string;
  email: string;
  email_verified: boolean;
  sstamp: string;
  device: string;
  devicetype: string;
  client_id: string;
  scope: string[];
  amr: string[];
}

export const ACCESS_TOKEN_TTL_SECONDS = 2 * 60 * 60; // matches vaultwarden default (2h)

export function issuer(domain: string, kind: JwtKind): string {
  return `${new URL(domain).origin}|${kind}`;
}

export async function encodeJwt(secret: string, claims: JWTPayload): Promise<string> {
  return sign(claims, secret, 'HS256');
}

export async function decodeJwt<T extends JWTPayload>(
  secret: string,
  token: string,
  expectedIssuer: string,
): Promise<T> {
  const payload = (await verify(token, secret, 'HS256')) as T;
  if (payload.iss !== expectedIssuer) throw new Error('Invalid issuer');
  return payload;
}

interface BasicClaimsInput {
  domain: string;
  kind: JwtKind;
  sub: string;
  ttlSeconds: number;
  extra?: Record<string, unknown>;
}

export function basicClaims({ domain, kind, sub, ttlSeconds, extra }: BasicClaimsInput): JWTPayload {
  const now = Math.floor(Date.now() / 1000);
  return {
    nbf: now,
    exp: now + ttlSeconds,
    iss: issuer(domain, kind),
    sub,
    ...extra,
  };
}
