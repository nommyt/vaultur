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
  app.route('/api', syncRoutes);
  app.route('/api', cipherRoutes);
  app.route('/api', folderRoutes);
  app.route('/api', accountRoutes);
  app.route('/api', domainRoutes);
  app.get('/alive', (c) => c.json(new Date().toISOString()));

  return app;
}

export type App = ReturnType<typeof createApp>;
