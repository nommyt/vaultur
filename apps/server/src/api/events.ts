import { Hono } from 'hono';
import type { AppEnv } from '../env';

/**
 * Event log endpoints (/api/organizations/:id/events, /api/ciphers/:id/events,
 * /events/collect). Ported from vaultwarden src/api/core/events.rs.
 */
export const eventRoutes = new Hono<AppEnv>();

/** Client-side event collection is mounted at /events (separate origin path). */
export const eventCollectRoutes = new Hono<AppEnv>();
