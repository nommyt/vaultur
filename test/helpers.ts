import { SELF } from 'cloudflare:test';

export const TEST_USER = {
  email: 'test@vaultur.dev',
  name: 'Test User',
  // A fake client-side master password hash (the server treats it as opaque)
  masterPasswordHash: 'fake-master-password-hash-base64==',
  key: '2.fakeProtectedSymmetricKey|fake==',
  kdf: 0,
  kdfIterations: 600_000,
  keys: {
    publicKey: 'fake-public-key',
    encryptedPrivateKey: '2.fakeEncryptedPrivateKey|fake==',
  },
};

export async function registerUser(overrides: Partial<typeof TEST_USER> = {}): Promise<Response> {
  const body = { ...TEST_USER, ...overrides };
  return SELF.fetch('https://vault.test/identity/accounts/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

export interface LoginResult {
  access_token: string;
  refresh_token: string;
  Key: string;
  PrivateKey: string;
  [k: string]: unknown;
}

export async function login(
  email = TEST_USER.email,
  passwordHash = TEST_USER.masterPasswordHash,
  extra: Record<string, string> = {},
): Promise<Response> {
  const form = new URLSearchParams({
    grant_type: 'password',
    username: email,
    password: passwordHash,
    scope: 'api offline_access',
    client_id: 'web',
    deviceType: '9',
    deviceIdentifier: 'test-device-id-1',
    deviceName: 'firefox',
    ...extra,
  });
  return SELF.fetch('https://vault.test/identity/connect/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form.toString(),
  });
}

export async function registerAndLogin(): Promise<LoginResult> {
  const reg = await registerUser();
  if (reg.status !== 200) throw new Error(`register failed: ${reg.status} ${await reg.text()}`);
  const res = await login();
  if (res.status !== 200) throw new Error(`login failed: ${res.status} ${await res.text()}`);
  return (await res.json()) as LoginResult;
}

export function authed(token: string): Record<string, string> {
  return { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };
}

export async function api(
  token: string,
  method: string,
  path: string,
  body?: unknown,
): Promise<Response> {
  return SELF.fetch(`https://vault.test${path}`, {
    method,
    headers: authed(token),
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}
