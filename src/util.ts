export function uuid(): string {
  return crypto.randomUUID();
}

export function b64Encode(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function b64Decode(value: string): Uint8Array {
  const s = atob(value);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

export function b64UrlEncode(bytes: Uint8Array): string {
  return b64Encode(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

/** Random lowercase-hex token. */
export function randomHex(bytes: number): string {
  return [...randomBytes(bytes)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

const ALPHANUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

/** Random alphanumeric string (vaultwarden's crypto::get_random_string_alphanum). */
export function randomAlphanum(length: number): string {
  const bytes = randomBytes(length);
  let out = '';
  for (let i = 0; i < length; i++) out += ALPHANUM[bytes[i]! % ALPHANUM.length];
  return out;
}

/** Random numeric string, used for email 2FA / device verification codes. */
export function randomNumericCode(length: number): string {
  const bytes = randomBytes(length);
  let out = '';
  for (let i = 0; i < length; i++) out += String(bytes[i]! % 10);
  return out;
}

export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

export function constantTimeEqualStr(a: string, b: string): boolean {
  return constantTimeEqual(new TextEncoder().encode(a), new TextEncoder().encode(b));
}

/** Lowercase + trim an email like vaultwarden does. */
export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

export function isValidEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email);
}

/** Parse a JSON body that may use PascalCase or camelCase keys (older/newer clients). */
export function ci<T = unknown>(
  obj: Record<string, unknown> | null | undefined,
  key: string,
): T | undefined {
  if (!obj) return undefined;
  if (key in obj) return obj[key] as T;
  const pascal = key.charAt(0).toUpperCase() + key.slice(1);
  if (pascal in obj) return obj[pascal] as T;
  const lower = key.toLowerCase();
  for (const k of Object.keys(obj)) {
    if (k.toLowerCase() === lower) return obj[k] as T;
  }
  return undefined;
}
