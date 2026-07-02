import { describe, expect, it } from 'vitest';
import { api, registerAndLogin, TEST_USER } from './helpers';

const LOGIN_CIPHER = {
  type: 1,
  name: '2.encryptedName|iv==',
  notes: null,
  favorite: false,
  login: {
    uris: [{ uri: '2.encryptedUri|iv==', match: null }],
    username: '2.encryptedUser|iv==',
    password: '2.encryptedPass|iv==',
    totp: null,
  },
  fields: [{ type: 0, name: '2.f|iv==', value: '2.v|iv==' }],
  passwordHistory: [{ password: '2.old|iv==', lastUsedDate: '2026-01-01T00:00:00.000Z' }],
};

describe('vault', () => {
  it('creates, reads, updates and deletes a cipher', async () => {
    const session = await registerAndLogin();
    const token = session.access_token;

    // Create
    const created = await api(token, 'POST', '/api/ciphers', LOGIN_CIPHER);
    expect(created.status).toBe(200);
    const cipher = (await created.json()) as Record<string, any>;
    expect(cipher.object).toBe('cipherDetails');
    expect(cipher.type).toBe(1);
    expect(cipher.name).toBe(LOGIN_CIPHER.name);
    expect(cipher.login.username).toBe(LOGIN_CIPHER.login.username);
    expect(cipher.login.uri).toBe(LOGIN_CIPHER.login.uris[0]!.uri);
    expect(cipher.data.username).toBe(LOGIN_CIPHER.login.username);
    expect(cipher.edit).toBe(true);
    expect(cipher.viewPassword).toBe(true);
    expect(cipher.permissions).toEqual({ delete: true, restore: true });
    expect(cipher.fields[0].type).toBe(0);

    // Read
    const got = await api(token, 'GET', `/api/ciphers/${cipher.id}`);
    expect(got.status).toBe(200);

    // Update
    const updated = await api(token, 'PUT', `/api/ciphers/${cipher.id}`, {
      ...LOGIN_CIPHER,
      name: '2.newName|iv==',
      lastKnownRevisionDate: cipher.revisionDate,
    });
    expect(updated.status).toBe(200);
    expect(((await updated.json()) as Record<string, any>).name).toBe('2.newName|iv==');

    // Stale update is rejected
    const stale = await api(token, 'PUT', `/api/ciphers/${cipher.id}`, {
      ...LOGIN_CIPHER,
      lastKnownRevisionDate: '2020-01-01T00:00:00.000Z',
    });
    expect(stale.status).toBe(400);
    expect(((await stale.json()) as Record<string, any>).errorModel.message).toContain(
      'out of date',
    );

    // Soft delete → appears with deletedDate
    const softDeleted = await api(token, 'PUT', `/api/ciphers/${cipher.id}/delete`);
    expect(softDeleted.status).toBe(200);
    const afterSoft = (await (
      await api(token, 'GET', `/api/ciphers/${cipher.id}`)
    ).json()) as Record<string, any>;
    expect(afterSoft.deletedDate).toBeTruthy();

    // Restore
    const restored = await api(token, 'PUT', `/api/ciphers/${cipher.id}/restore`);
    expect(restored.status).toBe(200);
    expect(((await restored.json()) as Record<string, any>).deletedDate).toBeNull();

    // Hard delete
    const deleted = await api(token, 'DELETE', `/api/ciphers/${cipher.id}`);
    expect(deleted.status).toBe(200);
    const gone = await api(token, 'GET', `/api/ciphers/${cipher.id}`);
    expect(gone.status).toBe(404);
  });

  it('manages folders and moves ciphers', async () => {
    const session = await registerAndLogin();
    const token = session.access_token;

    const folderRes = await api(token, 'POST', '/api/folders', { name: '2.folderName|iv==' });
    expect(folderRes.status).toBe(200);
    const folder = (await folderRes.json()) as Record<string, any>;
    expect(folder.object).toBe('folder');

    const cipherRes = await api(token, 'POST', '/api/ciphers', {
      ...LOGIN_CIPHER,
      folderId: folder.id,
    });
    const cipher = (await cipherRes.json()) as Record<string, any>;
    expect(cipher.folderId).toBe(folder.id);

    // Rename folder
    const renamed = await api(token, 'PUT', `/api/folders/${folder.id}`, {
      name: '2.renamed|iv==',
    });
    expect(((await renamed.json()) as Record<string, any>).name).toBe('2.renamed|iv==');

    // Move out via /ciphers/move
    const moved = await api(token, 'POST', '/api/ciphers/move', {
      ids: [cipher.id],
      folderId: null,
    });
    expect(moved.status).toBe(200);
    const afterMove = (await (
      await api(token, 'GET', `/api/ciphers/${cipher.id}`)
    ).json()) as Record<string, any>;
    expect(afterMove.folderId).toBeNull();

    // Delete folder
    const del = await api(token, 'DELETE', `/api/folders/${folder.id}`);
    expect(del.status).toBe(200);
  });

  it('returns a complete sync payload', async () => {
    const session = await registerAndLogin();
    const token = session.access_token;
    await api(token, 'POST', '/api/ciphers', LOGIN_CIPHER);
    await api(token, 'POST', '/api/folders', { name: '2.folder|iv==' });

    const res = await api(token, 'GET', '/api/sync');
    expect(res.status).toBe(200);
    const sync = (await res.json()) as Record<string, any>;
    expect(sync.object).toBe('sync');
    expect(sync.profile.object).toBe('profile');
    expect(sync.profile.email).toBe(TEST_USER.email);
    expect(sync.profile.key).toBe(TEST_USER.key);
    expect(sync.ciphers).toHaveLength(1);
    expect(sync.folders).toHaveLength(1);
    expect(sync.collections).toEqual([]);
    expect(sync.policies).toEqual([]);
    expect(sync.sends).toEqual([]);
    expect(sync.domains.object).toBe('domains');
    expect(sync.userDecryption.masterPasswordUnlock.salt).toBe(TEST_USER.email);
  });

  it('imports ciphers with folder relationships', async () => {
    const session = await registerAndLogin();
    const token = session.access_token;

    const res = await api(token, 'POST', '/api/ciphers/import', {
      folders: [{ name: '2.importedFolder|iv==' }],
      ciphers: [LOGIN_CIPHER, { ...LOGIN_CIPHER, name: '2.second|iv==' }],
      folderRelationships: [{ key: 0, value: 0 }],
    });
    expect(res.status).toBe(200);

    const sync = (await (await api(token, 'GET', '/api/sync')).json()) as Record<string, any>;
    expect(sync.ciphers).toHaveLength(2);
    expect(sync.folders).toHaveLength(1);
    const inFolder = sync.ciphers.find((c: any) => c.folderId != null);
    expect(inFolder).toBeTruthy();
  });

  it('purges the vault with password verification', async () => {
    const session = await registerAndLogin();
    const token = session.access_token;
    await api(token, 'POST', '/api/ciphers', LOGIN_CIPHER);

    const badPurge = await api(token, 'POST', '/api/ciphers/purge', {
      masterPasswordHash: 'wrong',
    });
    expect(badPurge.status).toBe(400);

    const purge = await api(token, 'POST', '/api/ciphers/purge', {
      masterPasswordHash: TEST_USER.masterPasswordHash,
    });
    expect(purge.status).toBe(200);

    const sync = (await (await api(token, 'GET', '/api/sync')).json()) as Record<string, any>;
    expect(sync.ciphers).toEqual([]);
  });

  it('accounts: profile update, revision date, password change invalidates token', async () => {
    const session = await registerAndLogin();
    const token = session.access_token;

    const profile = await api(token, 'PUT', '/api/accounts/profile', { name: 'Renamed User' });
    expect(((await profile.json()) as Record<string, any>).name).toBe('Renamed User');

    const rev = await api(token, 'GET', '/api/accounts/revision-date');
    expect(typeof (await rev.json())).toBe('number');

    const change = await api(token, 'POST', '/api/accounts/password', {
      masterPasswordHash: TEST_USER.masterPasswordHash,
      newMasterPasswordHash: 'new-master-hash==',
      key: '2.newProtectedKey|iv==',
    });
    expect(change.status).toBe(200);

    // Old access token carries the old security stamp → rejected
    const after = await api(token, 'GET', '/api/sync');
    expect(after.status).toBe(401);
  });

  it('equivalent domains: read and update', async () => {
    const session = await registerAndLogin();
    const token = session.access_token;

    const domains = (await (await api(token, 'GET', '/api/settings/domains')).json()) as Record<
      string,
      any
    >;
    expect(domains.object).toBe('domains');
    expect(domains.globalEquivalentDomains.length).toBeGreaterThan(50);

    const update = await api(token, 'PUT', '/api/settings/domains', {
      equivalentDomains: [['example.com', 'example.org']],
      excludedGlobalEquivalentDomains: [2],
    });
    expect(update.status).toBe(200);

    const after = (await (await api(token, 'GET', '/api/settings/domains')).json()) as Record<
      string,
      any
    >;
    expect(after.equivalentDomains).toEqual([['example.com', 'example.org']]);
    expect(after.globalEquivalentDomains.find((g: any) => g.type === 2).excluded).toBe(true);
  });
});
