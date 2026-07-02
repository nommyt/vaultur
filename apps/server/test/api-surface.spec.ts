import { SELF } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { api, registerAndLogin, registerUser, TEST_USER } from './helpers';

const ORG = {
  name: 'Surface Inc',
  billingEmail: 'b@surface.test',
  key: '2.k|iv==',
  collectionName: '2.c|iv==',
  keys: { publicKey: 'pub', encryptedPrivateKey: '2.pk|iv==' },
};

describe('additional API surface', () => {
  it('serves the static plans list', async () => {
    const { access_token: token } = await registerAndLogin();
    const res = await api(token, 'GET', '/api/plans');
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, any>;
    expect(body.object).toBe('list');
    expect(body.data[0].object).toBe('plan');
  });

  it('answers /api/accounts/prelogin and /identity/accounts/prelogin/password', async () => {
    await registerUser();
    for (const url of [
      'https://vault.test/api/accounts/prelogin',
      'https://vault.test/identity/accounts/prelogin/password',
    ]) {
      const res = await SELF.fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: TEST_USER.email }),
      });
      expect(res.status).toBe(200);
      expect(((await res.json()) as Record<string, any>).kdfIterations).toBe(600_000);
    }
  });

  it('returns device-verification-settings and auth-requests/pending', async () => {
    const { access_token: token } = await registerAndLogin();
    const dv = (await (
      await api(token, 'GET', '/api/two-factor/get-device-verification-settings')
    ).json()) as Record<string, any>;
    expect(dv.object).toBe('deviceVerificationSettings');

    const pending = (await (
      await api(token, 'GET', '/api/auth-requests/pending')
    ).json()) as Record<string, any>;
    expect(pending.object).toBe('list');
  });

  it('issues an organization API key and accepts org-api-key login', async () => {
    const { access_token: token } = await registerAndLogin();
    const org = (await (await api(token, 'POST', '/api/organizations', ORG)).json()) as Record<
      string,
      any
    >;

    const keyRes = await api(token, 'POST', `/api/organizations/${org.id}/api-key`, {
      masterPasswordHash: TEST_USER.masterPasswordHash,
    });
    expect(keyRes.status).toBe(200);
    const { apiKey } = (await keyRes.json()) as { apiKey: string };
    expect(apiKey).toBeTruthy();

    // Log in with the org API key (client_credentials, scope api.organization)
    const form = new URLSearchParams({
      grant_type: 'client_credentials',
      scope: 'api.organization',
      client_id: `organization.${org.id}`,
      client_secret: apiKey,
      deviceType: '9',
      deviceIdentifier: 'dir-connector',
      deviceName: 'connector',
    });
    const login = await SELF.fetch('https://vault.test/identity/connect/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form.toString(),
    });
    expect(login.status).toBe(200);
    const loginBody = (await login.json()) as Record<string, any>;
    expect(loginBody.scope).toBe('api.organization');
    const orgToken = loginBody.access_token as string;

    // Use the org token to run an LDAP-style directory import
    const importRes = await SELF.fetch('https://vault.test/api/public/organization/import', {
      method: 'POST',
      headers: { Authorization: `Bearer ${orgToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        members: [{ email: 'ldap-user@surface.test', externalId: 'ext-1', deleted: false }],
        groups: [{ name: 'Eng', externalId: 'g-1', memberExternalIds: ['ext-1'] }],
        overwriteExisting: false,
      }),
    });
    expect(importRes.status).toBe(200);

    // The imported member now shows up in the org member list
    const members = (await (
      await api(token, 'GET', `/api/organizations/${org.id}/users`)
    ).json()) as Record<string, any>;
    expect(members.data.some((m: any) => m.email === 'ldap-user@surface.test')).toBe(true);
  });

  it('bulk-assigns ciphers to collections in the org view', async () => {
    const { access_token: token } = await registerAndLogin();
    const org = (await (await api(token, 'POST', '/api/organizations', ORG)).json()) as Record<
      string,
      any
    >;
    const cols = (await (
      await api(token, 'GET', `/api/organizations/${org.id}/collections`)
    ).json()) as Record<string, any>;
    const collectionId = cols.data[0].id;

    // Create an org-owned cipher via /ciphers/create
    const cipher = (await (
      await api(token, 'POST', '/api/ciphers/create', {
        cipher: {
          type: 1,
          name: '2.n|iv==',
          organizationId: org.id,
          login: { username: '2.u|iv==', uris: [] },
        },
        collectionIds: [collectionId],
      })
    ).json()) as Record<string, any>;

    // Make a second collection and bulk-assign the cipher to it
    const col2 = (await (
      await api(token, 'POST', `/api/organizations/${org.id}/collections`, { name: '2.c2|iv==' })
    ).json()) as Record<string, any>;

    const bulk = await api(token, 'POST', '/api/ciphers/bulk-collections', {
      organizationId: org.id,
      cipherIds: [cipher.id],
      collectionIds: [col2.id],
      removeCollections: false,
    });
    expect(bulk.status).toBe(200);

    const details = (await (
      await api(token, 'GET', `/api/organizations/${org.id}/details`)
    ).json()) as Record<string, any>;
    const found = details.data.find((cph: any) => cph.id === cipher.id);
    expect(found.collectionIds).toContain(col2.id);
  });
});
