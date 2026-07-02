import { Hono } from 'hono';
import type { Context } from 'hono';
import { eq } from 'drizzle-orm';
import { attachments, ciphers, type Attachment, type Cipher } from '@vaultur/db';
import { UpdateType } from '@vaultur/shared';
import type { AppEnv } from '../env';
import { requireAuth, auth } from '../auth/middleware';
import { err, notFound } from '../error';
import { decodeJwt, issuer } from '../auth/jwt';
import { randomAlphanum, ci } from '../util';
import { attachmentToJson, cipherToJson, getAccessRestrictions, loadCipherSyncData } from '../services/vault';
import { updateUsersRevisionForCipher, usersWithCipherAccess } from '../services/ciphers';
import { Notify } from '../services/notify';

export const attachmentRoutes = new Hono<AppEnv>();

type Ctx = Context<AppEnv>;

function fileKey(cipherUuid: string, attachmentId: string): string {
  return `attachments/${cipherUuid}/${attachmentId}`;
}

// ---------------------------------------------------------------------------
// Anonymous download endpoint (token-authenticated), mirrors vaultwarden
// GET /attachments/<cipher>/<id>?token=<jwt>
// ---------------------------------------------------------------------------

export const attachmentDownloadRoutes = new Hono<AppEnv>();

attachmentDownloadRoutes.get('/attachments/:cipherId/:attachmentId', async (c) => {
  const cipherId = c.req.param('cipherId');
  const attachmentId = c.req.param('attachmentId');
  const token = c.req.query('token') ?? '';
  const config = c.get('config');

  try {
    const claims = await decodeJwt<{ sub: string; file_id: string }>(
      c.env.JWT_SECRET,
      token,
      issuer(config.domain, 'file_download'),
    );
    if (claims.sub !== cipherId || claims.file_id !== attachmentId) notFound();
  } catch {
    notFound();
  }

  const object = await c.env.FILES.get(fileKey(cipherId, attachmentId));
  if (!object) notFound();

  return new Response(object.body, {
    headers: {
      'Content-Type': 'application/octet-stream',
      'Content-Length': String(object.size),
      'Content-Disposition': `attachment; filename="${attachmentId}"`,
    },
  });
});

// ---------------------------------------------------------------------------
// Authenticated attachment management under /api
// ---------------------------------------------------------------------------

attachmentRoutes.use('*', requireAuth);

async function loadWritableCipher(c: Ctx, id: string | undefined): Promise<Cipher> {
  if (!id) notFound("Cipher doesn't exist");
  const { user } = auth(c);
  const cipher = await c.get('db').query.ciphers.findFirst({ where: eq(ciphers.uuid, id) });
  if (!cipher) notFound("Cipher doesn't exist");
  const sync = await loadCipherSyncData(c.get('db'), user.uuid, 'user');
  const access = getAccessRestrictions(cipher, user.uuid, sync);
  if (!access) notFound('Cipher is not accessible');
  if (access.readOnly) err('Cipher is not write accessible');
  return cipher;
}

// v2 flow: metadata first, then upload
attachmentRoutes.post('/ciphers/:id/attachment/v2', async (c) => {
  const { user } = auth(c);
  const db = c.get('db');
  const cipher = await loadWritableCipher(c, c.req.param('id'));
  const body = (await c.req.json()) as Record<string, unknown>;

  const key = ci<string>(body, 'key');
  const fileName = ci<string>(body, 'fileName');
  const fileSize = Number(ci(body, 'fileSize') ?? -1);
  const adminRequest = Boolean(ci(body, 'adminRequest'));
  if (!key || !fileName) err('Missing attachment metadata');
  if (!Number.isFinite(fileSize) || fileSize < 0) err("Attachment size can't be negative");

  const attachmentId = randomAlphanum(10).toLowerCase();
  const attachment: Attachment = { id: attachmentId, cipherUuid: cipher.uuid, fileName, fileSize, akey: key };
  await db.insert(attachments).values(attachment);

  const sync = await loadCipherSyncData(db, user.uuid, 'user');
  const opts = { config: c.get('config'), secret: c.env.JWT_SECRET, userUuid: user.uuid, sync, syncType: 'user' as const };

  return c.json({
    object: 'attachment-fileUpload',
    attachmentId,
    url: `/ciphers/${cipher.uuid}/attachment/${attachmentId}`,
    fileUploadType: 0, // direct
    [adminRequest ? 'cipherMiniResponse' : 'cipherResponse']: await cipherToJson(cipher, opts),
  });
});

// Upload data for a v2 attachment
attachmentRoutes.post('/ciphers/:id/attachment/:attachmentId', async (c) => {
  const { user, device } = auth(c);
  const db = c.get('db');
  const cipher = await loadWritableCipher(c, c.req.param('id'));
  const attachmentId = c.req.param('attachmentId');

  const attachment = await db.query.attachments.findFirst({ where: eq(attachments.id, attachmentId) });
  if (!attachment || attachment.cipherUuid !== cipher.uuid) {
    err('Attachment doesn\'t exist');
  }

  const form = await c.req.parseBody();
  const file = form.data ?? form.file;
  if (!(file instanceof File)) err('No data to upload');

  if (Math.abs(attachment.fileSize - file.size) > 1) {
    // vaultwarden tolerates ±1 byte (leeway for encryption overhead reporting)
    err(`Attachment size mismatch (expected within [${attachment.fileSize - 1}, ${attachment.fileSize + 1}], got ${file.size})`);
  }

  await c.env.FILES.put(fileKey(cipher.uuid, attachmentId), file.stream(), {
    httpMetadata: { contentType: 'application/octet-stream' },
  });

  const affected = await updateUsersRevisionForCipher(db, cipher);
  new Notify(c.env, c.get('config'), c.executionCtx).cipherUpdate(
    UpdateType.SyncCipherUpdate,
    cipher,
    affected,
    device.uuid,
  );
  return c.body(null, 200);
});

// Legacy one-shot upload: multipart with data + key
async function legacyUpload(c: Ctx) {
  const { user, device } = auth(c);
  const db = c.get('db');
  const cipher = await loadWritableCipher(c, c.req.param('id'));

  const form = await c.req.parseBody();
  const file = form.data ?? form.file;
  if (!(file instanceof File)) err('No data to upload');
  const key = typeof form.key === 'string' ? form.key : null;

  const attachmentId = randomAlphanum(10).toLowerCase();
  const attachment: Attachment = {
    id: attachmentId,
    cipherUuid: cipher.uuid,
    fileName: file.name,
    fileSize: file.size,
    akey: key,
  };
  await db.insert(attachments).values(attachment);
  await c.env.FILES.put(fileKey(cipher.uuid, attachmentId), file.stream(), {
    httpMetadata: { contentType: 'application/octet-stream' },
  });

  const affected = await updateUsersRevisionForCipher(db, cipher);
  new Notify(c.env, c.get('config'), c.executionCtx).cipherUpdate(
    UpdateType.SyncCipherUpdate,
    cipher,
    affected,
    device.uuid,
  );

  const sync = await loadCipherSyncData(db, user.uuid, 'user');
  const opts = { config: c.get('config'), secret: c.env.JWT_SECRET, userUuid: user.uuid, sync, syncType: 'user' as const };
  return c.json(await cipherToJson(cipher, opts));
}
attachmentRoutes.post('/ciphers/:id/attachment', legacyUpload);
attachmentRoutes.post('/ciphers/:id/attachment-admin', legacyUpload);

// Attachment metadata (download descriptor)
attachmentRoutes.get('/ciphers/:id/attachment/:attachmentId', async (c) => {
  const { user } = auth(c);
  const db = c.get('db');
  const cipherId = c.req.param('id');
  const attachmentId = c.req.param('attachmentId');

  const cipher = await db.query.ciphers.findFirst({ where: eq(ciphers.uuid, cipherId) });
  if (!cipher) notFound("Cipher doesn't exist");
  const sync = await loadCipherSyncData(db, user.uuid, 'user');
  if (!getAccessRestrictions(cipher, user.uuid, sync)) notFound('Cipher is not accessible');

  const attachment = await db.query.attachments.findFirst({ where: eq(attachments.id, attachmentId) });
  if (!attachment || attachment.cipherUuid !== cipher.uuid) notFound("Attachment doesn't exist");

  return c.json(await attachmentToJson(c.get('config'), c.env.JWT_SECRET, attachment));
});

// Delete
async function deleteAttachment(c: Ctx) {
  const { device } = auth(c);
  const db = c.get('db');
  const cipher = await loadWritableCipher(c, c.req.param('id'));
  const attachmentId = c.req.param('attachmentId');
  if (!attachmentId) notFound("Attachment doesn't exist");

  const attachment = await db.query.attachments.findFirst({ where: eq(attachments.id, attachmentId) });
  if (!attachment || attachment.cipherUuid !== cipher.uuid) notFound("Attachment doesn't exist");

  await c.env.FILES.delete(fileKey(cipher.uuid, attachmentId));
  await db.delete(attachments).where(eq(attachments.id, attachmentId));

  const affected = await updateUsersRevisionForCipher(db, cipher);
  new Notify(c.env, c.get('config'), c.executionCtx).cipherUpdate(
    UpdateType.SyncCipherUpdate,
    cipher,
    affected,
    device.uuid,
  );
  return c.json({ object: 'attachment', ...(await attachmentToJson(c.get('config'), c.env.JWT_SECRET, attachment)) });
}
attachmentRoutes.delete('/ciphers/:id/attachment/:attachmentId', deleteAttachment);
attachmentRoutes.post('/ciphers/:id/attachment/:attachmentId/delete', deleteAttachment);
attachmentRoutes.delete('/ciphers/:id/attachment/:attachmentId/admin', deleteAttachment);
attachmentRoutes.post('/ciphers/:id/attachment/:attachmentId/delete-admin', deleteAttachment);

// Legacy share endpoint (upload attachment then share)
attachmentRoutes.post('/ciphers/:id/attachment/:attachmentId/share', legacyUpload);
