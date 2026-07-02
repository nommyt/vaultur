import { SELF } from 'cloudflare:test';
import * as OTPAuth from 'otpauth';
import { describe, expect, it } from 'vitest';
import { api, login, registerAndLogin, TEST_USER } from './helpers';

function totpFor(key: string, stepOffset = 0): string {
  const totp = new OTPAuth.TOTP({ secret: OTPAuth.Secret.fromBase32(key), digits: 6, period: 30 });
  // Offset lets a later call present a fresh code (enrollment consumes the
  // current step, so login must use the next window's code — as a real user
  // would seconds later).
  return totp.generate({ timestamp: Date.now() + stepOffset * 30_000 });
}

describe('two-factor (authenticator)', () => {
  it('enrolls TOTP, then requires it on login, then disables it', async () => {
    const session = await registerAndLogin();
    const token = session.access_token;

    // Get a fresh authenticator secret
    const getRes = await api(token, 'POST', '/api/two-factor/get-authenticator', {
      masterPasswordHash: TEST_USER.masterPasswordHash,
    });
    expect(getRes.status).toBe(200);
    const { key, enabled } = (await getRes.json()) as { key: string; enabled: boolean };
    expect(enabled).toBe(false);
    expect(key).toMatch(/^[A-Z2-7]+$/);

    // Enable with a valid TOTP code
    const enableRes = await api(token, 'POST', '/api/two-factor/authenticator', {
      masterPasswordHash: TEST_USER.masterPasswordHash,
      key,
      token: totpFor(key),
    });
    expect(enableRes.status).toBe(200);
    expect(((await enableRes.json()) as { enabled: boolean }).enabled).toBe(true);

    // Listed as an enabled provider
    const list = (await (await api(token, 'GET', '/api/two-factor')).json()) as { data: { type: number }[] };
    expect(list.data.some((p) => p.type === 0)).toBe(true);

    // Login now demands 2FA
    const twoFaLogin = await login();
    expect(twoFaLogin.status).toBe(400);
    const body = (await twoFaLogin.json()) as Record<string, any>;
    expect(body.error).toBe('invalid_grant');
    expect(body.TwoFactorProviders2).toHaveProperty('0');

    // Provide the TOTP token to complete login (next window, so not a replay)
    const withTotp = await login(TEST_USER.email, TEST_USER.masterPasswordHash, {
      twoFactorToken: totpFor(key, 1),
      twoFactorProvider: '0',
    });
    expect(withTotp.status).toBe(200);
    const newToken = ((await withTotp.json()) as { access_token: string }).access_token;

    // A recovery code now exists
    const recover = (await (
      await api(newToken, 'POST', '/api/two-factor/get-recover', { masterPasswordHash: TEST_USER.masterPasswordHash })
    ).json()) as { code: string };
    expect(recover.code).toBeTruthy();

    // Disable
    const disable = await api(newToken, 'POST', '/api/two-factor/disable', {
      masterPasswordHash: TEST_USER.masterPasswordHash,
      type: 0,
    });
    expect(disable.status).toBe(200);

    // Login works without 2FA again
    expect((await login()).status).toBe(200);
  });

  it('rejects enrollment with an invalid TOTP code', async () => {
    const session = await registerAndLogin();
    const token = session.access_token;
    const { key } = (await (
      await api(token, 'POST', '/api/two-factor/get-authenticator', { masterPasswordHash: TEST_USER.masterPasswordHash })
    ).json()) as { key: string };

    const res = await api(token, 'POST', '/api/two-factor/authenticator', {
      masterPasswordHash: TEST_USER.masterPasswordHash,
      key,
      token: '000000',
    });
    expect(res.status).toBe(400);
    // Not enrolled
    expect((await login()).status).toBe(200);
  });

  it('recovers 2FA with the recovery code', async () => {
    const session = await registerAndLogin();
    const token = session.access_token;
    const { key } = (await (
      await api(token, 'POST', '/api/two-factor/get-authenticator', { masterPasswordHash: TEST_USER.masterPasswordHash })
    ).json()) as { key: string };
    await api(token, 'POST', '/api/two-factor/authenticator', {
      masterPasswordHash: TEST_USER.masterPasswordHash,
      key,
      token: totpFor(key),
    });
    const recover = (await (
      await api(token, 'POST', '/api/two-factor/get-recover', { masterPasswordHash: TEST_USER.masterPasswordHash })
    ).json()) as { code: string };

    const res = await SELF.fetch('https://vault.test/api/two-factor/recover', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: TEST_USER.email,
        masterPasswordHash: TEST_USER.masterPasswordHash,
        recoveryCode: recover.code,
      }),
    });
    expect(res.status).toBe(200);

    // 2FA cleared → plain login works
    expect((await login()).status).toBe(200);
  });
});
