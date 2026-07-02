import { SELF } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { api } from './helpers';

const ORG = {
  name: 'Members Inc',
  billingEmail: 'billing@members.test',
  key: '2.orgKey|iv==',
  collectionName: '2.default|iv==',
  keys: { publicKey: 'pub', encryptedPrivateKey: '2.priv|iv==' },
};

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
  if (res.status !== 200) throw new Error(`register ${email} failed: ${await res.text()}`);
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
  if (res.status !== 200) throw new Error(`login ${email} failed: ${await res.text()}`);
  return ((await res.json()) as { access_token: string }).access_token;
}

describe('org members (mail-disabled auto-accept flow)', () => {
  it('invites, confirms, edits, revokes and restores a member', async () => {
    const ownerEmail = 'owner@members.test';
    const memberEmail = 'member@members.test';
    await registerUser(ownerEmail);
    await registerUser(memberEmail);
    const ownerToken = await loginUser(ownerEmail);
    const memberToken = await loginUser(memberEmail);

    const org = (await (await api(ownerToken, 'POST', '/api/organizations', ORG)).json()) as Record<string, any>;

    // Invite (mail disabled → member auto-accepted, status 1)
    const invite = await api(ownerToken, 'POST', `/api/organizations/${org.id}/users/invite`, {
      emails: [memberEmail],
      type: 2, // User
      accessAll: false,
      collections: [],
      groups: [],
    });
    expect(invite.status).toBe(200);

    let users = (await (
      await api(ownerToken, 'GET', `/api/organizations/${org.id}/users`)
    ).json()) as Record<string, any>;
    const memberRow = users.data.find((u: any) => u.email === memberEmail);
    expect(memberRow).toBeTruthy();
    expect(memberRow.status).toBe(1); // Accepted (mail disabled)
    expect(memberRow.type).toBe(2);

    // Confirm with a key → status Confirmed(2)
    const confirm = await api(ownerToken, 'POST', `/api/organizations/${org.id}/users/${memberRow.id}/confirm`, {
      key: '2.memberOrgKey|iv==',
    });
    expect(confirm.status).toBe(200);

    users = (await (await api(ownerToken, 'GET', `/api/organizations/${org.id}/users`)).json()) as Record<string, any>;
    expect(users.data.find((u: any) => u.email === memberEmail).status).toBe(2);

    // Member now sees the org in their sync profile
    const memberSync = (await (await api(memberToken, 'GET', '/api/sync')).json()) as Record<string, any>;
    expect(memberSync.profile.organizations.some((o: any) => o.id === org.id)).toBe(true);

    // Promote to Admin
    const edit = await api(ownerToken, 'PUT', `/api/organizations/${org.id}/users/${memberRow.id}`, {
      type: 1,
      accessAll: false,
      collections: [],
    });
    expect(edit.status).toBe(200);
    users = (await (await api(ownerToken, 'GET', `/api/organizations/${org.id}/users`)).json()) as Record<string, any>;
    expect(users.data.find((u: any) => u.email === memberEmail).type).toBe(1);

    // Revoke → status -1
    expect((await api(ownerToken, 'PUT', `/api/organizations/${org.id}/users/${memberRow.id}/revoke`)).status).toBe(200);
    users = (await (await api(ownerToken, 'GET', `/api/organizations/${org.id}/users`)).json()) as Record<string, any>;
    expect(users.data.find((u: any) => u.email === memberEmail).status).toBe(-1);

    // Restore
    expect((await api(ownerToken, 'PUT', `/api/organizations/${org.id}/users/${memberRow.id}/restore`)).status).toBe(200);
    users = (await (await api(ownerToken, 'GET', `/api/organizations/${org.id}/users`)).json()) as Record<string, any>;
    expect(users.data.find((u: any) => u.email === memberEmail).status).toBe(2);
  });

  it('manages groups and assigns members', async () => {
    const ownerEmail = 'gowner@members.test';
    await registerUser(ownerEmail);
    const ownerToken = await loginUser(ownerEmail);
    const org = (await (await api(ownerToken, 'POST', '/api/organizations', ORG)).json()) as Record<string, any>;

    const group = (await (
      await api(ownerToken, 'POST', `/api/organizations/${org.id}/groups`, {
        name: 'Engineers',
        accessAll: false,
        collections: [],
        users: [],
      })
    ).json()) as Record<string, any>;
    expect(group.object).toBe('group');
    expect(group.name).toBe('Engineers');

    const groups = (await (await api(ownerToken, 'GET', `/api/organizations/${org.id}/groups`)).json()) as Record<
      string,
      any
    >;
    expect(groups.data.some((g: any) => g.id === group.id)).toBe(true);

    // Rename
    const renamed = await api(ownerToken, 'PUT', `/api/organizations/${org.id}/groups/${group.id}`, {
      name: 'Platform',
      accessAll: false,
      collections: [],
      users: [],
    });
    expect(((await renamed.json()) as Record<string, any>).name).toBe('Platform');

    // Delete
    expect((await api(ownerToken, 'DELETE', `/api/organizations/${org.id}/groups/${group.id}`)).status).toBe(200);
  });

  it('enabling the 2FA policy revokes members without 2FA', async () => {
    const ownerEmail = 'powner@members.test';
    const memberEmail = 'pmember@members.test';
    await registerUser(ownerEmail);
    await registerUser(memberEmail);
    const ownerToken = await loginUser(ownerEmail);
    const org = (await (await api(ownerToken, 'POST', '/api/organizations', ORG)).json()) as Record<string, any>;

    await api(ownerToken, 'POST', `/api/organizations/${org.id}/users/invite`, {
      emails: [memberEmail],
      type: 2,
      accessAll: false,
      collections: [],
    });
    let users = (await (await api(ownerToken, 'GET', `/api/organizations/${org.id}/users`)).json()) as Record<string, any>;
    const memberRow = users.data.find((u: any) => u.email === memberEmail);
    await api(ownerToken, 'POST', `/api/organizations/${org.id}/users/${memberRow.id}/confirm`, { key: '2.k|iv==' });

    // Enable the Two-Factor Authentication policy (type 0)
    const policy = await api(ownerToken, 'PUT', `/api/organizations/${org.id}/policies/0`, {
      type: 0,
      enabled: true,
      data: null,
    });
    expect(policy.status).toBe(200);
    expect(((await policy.json()) as Record<string, any>).enabled).toBe(true);

    // The 2FA-less member is revoked; the owner (admin) is exempt
    users = (await (await api(ownerToken, 'GET', `/api/organizations/${org.id}/users`)).json()) as Record<string, any>;
    expect(users.data.find((u: any) => u.email === memberEmail).status).toBe(-1);
    expect(users.data.find((u: any) => u.email === ownerEmail).status).toBe(2);

    // Policy list reflects it
    const policies = (await (await api(ownerToken, 'GET', `/api/organizations/${org.id}/policies`)).json()) as Record<
      string,
      any
    >;
    expect(policies.data.find((p: any) => p.type === 0).enabled).toBe(true);
  });

  it('prevents a member from reading another org\'s users', async () => {
    const aEmail = 'a-iso@members.test';
    const bEmail = 'b-iso@members.test';
    await registerUser(aEmail);
    await registerUser(bEmail);
    const aToken = await loginUser(aEmail);
    const bToken = await loginUser(bEmail);
    const orgA = (await (await api(aToken, 'POST', '/api/organizations', ORG)).json()) as Record<string, any>;

    // B is not a member of orgA → forbidden
    const res = await api(bToken, 'GET', `/api/organizations/${orgA.id}/users`);
    expect([403, 404, 400]).toContain(res.status);
  });
});
