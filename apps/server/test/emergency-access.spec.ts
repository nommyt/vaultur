import { SELF } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { api } from './helpers';

async function registerUser(email: string) {
  const res = await SELF.fetch('https://vault.test/identity/accounts/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email,
      name: email.split('@')[0],
      masterPasswordHash: `hash-${email}`,
      key: `2.userKey-${email}|iv==`,
      kdf: 0,
      kdfIterations: 600_000,
      keys: { publicKey: `pub-${email}`, encryptedPrivateKey: `2.priv-${email}|iv==` },
    }),
  });
  if (res.status !== 200) throw new Error(`register ${email}: ${await res.text()}`);
}

async function loginUser(email: string): Promise<string> {
  const form = new URLSearchParams({
    grant_type: 'password',
    username: email,
    password: `hash-${email}`,
    scope: 'api offline_access',
    client_id: 'web',
    deviceType: '9',
    deviceIdentifier: `dev-${email}`,
    deviceName: 'test',
  });
  const res = await SELF.fetch('https://vault.test/identity/connect/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form.toString(),
  });
  if (res.status !== 200) throw new Error(`login ${email}: ${await res.text()}`);
  return ((await res.json()) as { access_token: string }).access_token;
}

describe('emergency access (takeover, mail disabled)', () => {
  it('runs invite → confirm → initiate → approve → password reset', async () => {
    const grantorEmail = 'grantor@ea.test';
    const granteeEmail = 'grantee@ea.test';
    await registerUser(grantorEmail);
    await registerUser(granteeEmail);
    const grantorToken = await loginUser(grantorEmail);
    const granteeToken = await loginUser(granteeEmail);

    // Grantor invites grantee for Takeover; mail disabled → auto-accepted
    const invite = await api(grantorToken, 'POST', '/api/emergency-access/invite', {
      email: granteeEmail,
      type: 1, // Takeover
      waitTimeDays: 1,
    });
    expect(invite.status).toBe(200);
    const ea = (await invite.json()) as Record<string, any>;
    expect(ea.object).toBe('emergencyAccess');
    expect(ea.status).toBe(1); // Accepted

    // Grantor confirms with the grantee's encrypted key
    const confirm = await api(grantorToken, 'POST', `/api/emergency-access/${ea.id}/confirm`, {
      key: '2.emergencyKey|iv==',
    });
    expect(confirm.status).toBe(200);

    // Grantee initiates recovery
    const initiate = await api(granteeToken, 'POST', `/api/emergency-access/${ea.id}/initiate`);
    expect(initiate.status).toBe(200);
    expect(((await initiate.json()) as Record<string, any>).status).toBe(3); // RecoveryInitiated

    // Grantor approves
    expect((await api(grantorToken, 'POST', `/api/emergency-access/${ea.id}/approve`)).status).toBe(
      200,
    );

    // Grantee performs takeover → gets grantor KDF params + encrypted key
    const takeover = await api(granteeToken, 'POST', `/api/emergency-access/${ea.id}/takeover`);
    expect(takeover.status).toBe(200);
    const takeoverBody = (await takeover.json()) as Record<string, any>;
    expect(takeoverBody.object).toBe('emergencyAccessTakeover');
    expect(takeoverBody.keyEncrypted).toBe('2.emergencyKey|iv==');
    expect(takeoverBody.kdf).toBe(0);

    // Grantee sets a new master password for the grantor
    const reset = await api(granteeToken, 'POST', `/api/emergency-access/${ea.id}/password`, {
      newMasterPasswordHash: 'new-grantor-hash==',
      key: '2.newGrantorKey|iv==',
    });
    expect(reset.status).toBe(200);

    // Grantor can now log in with the new password
    const form = new URLSearchParams({
      grant_type: 'password',
      username: grantorEmail,
      password: 'new-grantor-hash==',
      scope: 'api offline_access',
      client_id: 'web',
      deviceType: '9',
      deviceIdentifier: 'dev-grantor-new',
      deviceName: 'test',
    });
    const newLogin = await SELF.fetch('https://vault.test/identity/connect/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form.toString(),
    });
    expect(newLogin.status).toBe(200);
  });

  it('lists trusted and granted relationships', async () => {
    const grantorEmail = 'g2@ea.test';
    const granteeEmail = 'g3@ea.test';
    await registerUser(grantorEmail);
    await registerUser(granteeEmail);
    const grantorToken = await loginUser(grantorEmail);
    const granteeToken = await loginUser(granteeEmail);

    await api(grantorToken, 'POST', '/api/emergency-access/invite', {
      email: granteeEmail,
      type: 0,
      waitTimeDays: 2,
    });

    const trusted = (await (
      await api(grantorToken, 'GET', '/api/emergency-access/trusted')
    ).json()) as Record<string, any>;
    expect(trusted.data.some((t: any) => t.email === granteeEmail)).toBe(true);

    const granted = (await (
      await api(granteeToken, 'GET', '/api/emergency-access/granted')
    ).json()) as Record<string, any>;
    expect(granted.data.some((g: any) => g.email === grantorEmail)).toBe(true);
  });

  it('rejects takeover before recovery is approved', async () => {
    const grantorEmail = 'g4@ea.test';
    const granteeEmail = 'g5@ea.test';
    await registerUser(grantorEmail);
    await registerUser(granteeEmail);
    const grantorToken = await loginUser(grantorEmail);
    const granteeToken = await loginUser(granteeEmail);

    const ea = (await (
      await api(grantorToken, 'POST', '/api/emergency-access/invite', {
        email: granteeEmail,
        type: 1,
        waitTimeDays: 1,
      })
    ).json()) as Record<string, any>;
    await api(grantorToken, 'POST', `/api/emergency-access/${ea.id}/confirm`, { key: '2.k|iv==' });

    // No initiate/approve yet → takeover invalid
    const takeover = await api(granteeToken, 'POST', `/api/emergency-access/${ea.id}/takeover`);
    expect(takeover.status).toBe(400);
  });
});
