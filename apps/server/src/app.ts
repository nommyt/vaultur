import { Hono } from 'hono';
import { createDb } from '@vaultur/db';
import type { AppEnv } from './env';
import { loadConfig } from './config';
import { onError, errorBody } from './error';
import { identityRoutes } from './api/identity';
import { metaRoutes } from './api/meta';
import { syncRoutes } from './api/sync';
import { cipherRoutes } from './api/ciphers';
import { folderRoutes } from './api/folders';
import { accountRoutes } from './api/accounts';
import { domainRoutes } from './api/domains';
import { attachmentRoutes, attachmentDownloadRoutes } from './api/attachments';
import { sendRoutes, sendAccessRoutes } from './api/sends';
import { deviceRoutes } from './api/devices';
import { twofactorRoutes } from './api/twofactor';
import { authRequestRoutes } from './api/auth-requests';
import { notificationRoutes } from './api/notifications';
import { organizationRoutes } from './api/organizations';
import { orgMemberRoutes } from './api/org-members';
import { emergencyAccessRoutes } from './api/emergency-access';
import { eventRoutes, eventCollectRoutes } from './api/events';
import { iconRoutes } from './api/icons';
import { adminRoutes } from './api/admin';
import { miscRoutes } from './api/misc';
import { publicRoutes } from './api/public';

export function createApp() {
  const app = new Hono<AppEnv>();

  app.use(async (c, next) => {
    c.set('db', createDb(c.env.DB));
    c.set('config', loadConfig(c.env, c.req.url));
    c.set('ip', c.req.header('CF-Connecting-IP') ?? '0.0.0.0');
    await next();
  });

  app.onError(onError);
  app.notFound((c) => c.json(errorBody('Not found'), 404));

  app.route('/identity', identityRoutes);
  app.route('/api', metaRoutes);
  // Public (unauthenticated) API routes must be mounted before the
  // requireAuth-guarded routers that share the /api prefix.
  app.route('/api', sendAccessRoutes);
  app.route('/api', publicRoutes);
  app.route('/api', syncRoutes);
  app.route('/api', cipherRoutes);
  app.route('/api', attachmentRoutes);
  app.route('/api', sendRoutes);
  app.route('/api', folderRoutes);
  app.route('/api', accountRoutes);
  app.route('/api', domainRoutes);
  app.route('/api', deviceRoutes);
  app.route('/api', twofactorRoutes);
  app.route('/api', authRequestRoutes);
  app.route('/api', organizationRoutes);
  app.route('/api', orgMemberRoutes);
  app.route('/api', emergencyAccessRoutes);
  app.route('/api', eventRoutes);
  app.route('/api', miscRoutes);
  app.route('/events', eventCollectRoutes);
  app.route('/notifications', notificationRoutes);
  // attachmentDownloadRoutes declares its own full /attachments/... paths
  app.route('/', attachmentDownloadRoutes);
  app.route('/icons', iconRoutes);
  app.route('/admin', adminRoutes);
  app.get('/alive', (c) => c.json(new Date().toISOString()));

  return app;
}

export type App = ReturnType<typeof createApp>;
