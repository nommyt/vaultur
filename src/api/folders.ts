import { Hono } from 'hono';
import type { Context } from 'hono';
import { and, eq } from 'drizzle-orm';
import { folders, foldersCiphers, nowDb, type Folder } from '../db';
import { UpdateType } from '../shared';
import type { AppEnv } from '../env';
import { requireAuth, auth } from '../auth/middleware';
import { err, notFound } from '../error';
import { ci, uuid } from '../util';
import { folderToJson } from '../services/vault';
import { touchUser } from '../services/users';
import { Notify } from '../services/notify';

export const folderRoutes = new Hono<AppEnv>();
folderRoutes.use('*', requireAuth);

folderRoutes.get('/folders', async (c) => {
  const { user } = auth(c);
  const rows = await c.get('db').query.folders.findMany({ where: eq(folders.userUuid, user.uuid) });
  return c.json({ data: rows.map(folderToJson), object: 'list', continuationToken: null });
});

folderRoutes.get('/folders/:id', async (c) => {
  const { user } = auth(c);
  const row = await findFolder(c, user.uuid, c.req.param('id'));
  return c.json(folderToJson(row));
});

folderRoutes.post('/folders', async (c) => {
  const { user, device } = auth(c);
  const body = (await c.req.json()) as Record<string, unknown>;
  const name = ci<string>(body, 'name');
  if (!name) err('The field Name is required.');

  const db = c.get('db');
  const now = nowDb();
  const folder: Folder = {
    uuid: uuid(),
    createdAt: now,
    updatedAt: now,
    userUuid: user.uuid,
    name,
  };
  await db.insert(folders).values(folder);
  await touchUser(db, user.uuid);

  new Notify(c.env, c.get('config'), c.executionCtx).folderUpdate(
    UpdateType.SyncFolderCreate,
    folder,
    device.uuid,
  );
  return c.json(folderToJson(folder));
});

async function updateFolder(c: Context<AppEnv>) {
  const { user, device } = auth(c);
  const body = (await c.req.json()) as Record<string, unknown>;
  const name = ci<string>(body, 'name');
  if (!name) err('The field Name is required.');

  const db = c.get('db');
  const row = await findFolder(c, user.uuid, c.req.param('id'));
  const updated: Folder = { ...row, name, updatedAt: nowDb() };
  await db
    .update(folders)
    .set({ name, updatedAt: updated.updatedAt })
    .where(eq(folders.uuid, row.uuid));
  await touchUser(db, user.uuid);

  new Notify(c.env, c.get('config'), c.executionCtx).folderUpdate(
    UpdateType.SyncFolderUpdate,
    updated,
    device.uuid,
  );
  return c.json(folderToJson(updated));
}

folderRoutes.put('/folders/:id', (c) => updateFolder(c));
folderRoutes.post('/folders/:id', (c) => updateFolder(c));

async function deleteFolder(c: Context<AppEnv>) {
  const { user, device } = auth(c);
  const db = c.get('db');
  const row = await findFolder(c, user.uuid, c.req.param('id'));

  // Cipher-folder mappings cascade via FK; delete explicitly for clarity
  await db.delete(foldersCiphers).where(eq(foldersCiphers.folderUuid, row.uuid));
  await db.delete(folders).where(eq(folders.uuid, row.uuid));
  await touchUser(db, user.uuid);

  new Notify(c.env, c.get('config'), c.executionCtx).folderUpdate(
    UpdateType.SyncFolderDelete,
    row,
    device.uuid,
  );
  return c.body(null, 200);
}

folderRoutes.delete('/folders/:id', (c) => deleteFolder(c));
folderRoutes.post('/folders/:id/delete', (c) => deleteFolder(c));

async function findFolder(
  c: Context<AppEnv>,
  userUuid: string,
  id: string | undefined,
): Promise<Folder> {
  if (!id) notFound('Folder not found');
  const row = await c.get('db').query.folders.findFirst({
    where: and(eq(folders.uuid, id), eq(folders.userUuid, userUuid)),
  });
  if (!row) notFound('Folder not found');
  return row;
}
