import { Hono } from 'hono';
import type { AppEnv } from '../env';

/**
 * Website icon proxy (/icons/:domain/icon.png) with KV caching.
 * Simplified port of vaultwarden src/api/icons.rs.
 */
export const iconRoutes = new Hono<AppEnv>();
