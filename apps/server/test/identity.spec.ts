import { SELF } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { TEST_USER, login, registerUser } from './helpers';

describe('identity', () => {
  it('GET /api/config returns server metadata', async () => {
    const res = await SELF.fetch('https://vault.test/api/config');
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, any>;
    expect(body.object).toBe('config');
    expect(body.server.name).toBe('Vaultur');
    expect(body.environment.api).toBe('https://vault.test/api');
  });

  it('prelogin returns defaults for unknown user', async () => {
    const res = await SELF.fetch('https://vault.test/identity/accounts/prelogin', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'nobody@vaultur.dev' }),
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      kdf: 0,
      kdfIterations: 600_000,
      kdfMemory: null,
      kdfParallelism: null,
    });
  });

  it('registers a new user and logs in', async () => {
    const reg = await registerUser();
    expect(reg.status).toBe(200);
    expect(await reg.json()).toEqual({ object: 'register', captchaBypassToken: '' });

    // prelogin now returns the user's KDF settings
    const pre = await SELF.fetch('https://vault.test/identity/accounts/prelogin', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: TEST_USER.email }),
    });
    const preBody = (await pre.json()) as Record<string, unknown>;
    expect(preBody.kdfIterations).toBe(600_000);

    const res = await login();
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, any>;
    expect(body.token_type).toBe('Bearer');
    expect(body.access_token).toBeTruthy();
    expect(body.refresh_token).toBeTruthy();
    expect(body.Key).toBe(TEST_USER.key);
    expect(body.PrivateKey).toBe(TEST_USER.keys.encryptedPrivateKey);
    expect(body.Kdf).toBe(0);
    expect(body.KdfIterations).toBe(600_000);
    expect(body.UserDecryptionOptions.HasMasterPassword).toBe(true);
    expect(body.UserDecryptionOptions.MasterPasswordUnlock.Salt).toBe(TEST_USER.email);
  });

  it('rejects duplicate registration', async () => {
    await registerUser();
    const res = await registerUser();
    expect(res.status).toBe(400);
    const body = (await res.json()) as Record<string, any>;
    expect(body.errorModel.message).toContain('Registration not allowed');
  });

  it('rejects login with the wrong password', async () => {
    await registerUser();
    const res = await login(TEST_USER.email, 'wrong-hash');
    expect(res.status).toBe(400);
    const body = (await res.json()) as Record<string, any>;
    expect(body.errorModel.message).toContain('Username or password is incorrect');
  });

  it('refresh grant issues a new access token', async () => {
    await registerUser();
    const first = (await (await login()).json()) as Record<string, any>;

    const form = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: first.refresh_token,
      client_id: 'web',
    });
    const res = await SELF.fetch('https://vault.test/identity/connect/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form.toString(),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, any>;
    expect(body.access_token).toBeTruthy();
    expect(body.refresh_token).toBe(first.refresh_token);
    expect(body.scope).toBe('api offline_access');
  });

  it('rejects a bogus refresh token with invalid_grant', async () => {
    const form = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: 'bogus',
      client_id: 'web',
    });
    const res = await SELF.fetch('https://vault.test/identity/connect/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form.toString(),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as Record<string, any>;
    expect(body.error).toBe('invalid_grant');
  });
});
