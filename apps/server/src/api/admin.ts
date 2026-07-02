import { Hono } from 'hono';
import type { AppEnv } from '../env';

/**
 * Admin API (/admin/*): token login → admin JWT cookie, user management,
 * invites, org overview. JSON-first port of vaultwarden src/api/admin.rs.
 */
export const adminRoutes = new Hono<AppEnv>();
