import { Hono } from 'hono';
import type { AppEnv } from '../env';

/**
 * WebSocket notifications endpoints (/notifications/hub, /notifications/anonymous-hub).
 * Ported from vaultwarden src/api/notifications.rs; sockets live in the
 * NotificationsHub Durable Object (src/durable/notifications-hub.ts).
 */
export const notificationRoutes = new Hono<AppEnv>();
