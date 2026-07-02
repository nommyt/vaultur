import { Hono } from 'hono';
import type { AppEnv } from '../env';

/**
 * Organizations core: org CRUD/keys, collections, org vault details.
 * Ported from vaultwarden src/api/core/organizations.rs (org + collection parts).
 */
export const organizationRoutes = new Hono<AppEnv>();
