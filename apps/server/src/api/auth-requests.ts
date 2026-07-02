import { Hono } from 'hono';
import type { AppEnv } from '../env';

/**
 * Login-with-device auth requests (/api/auth-requests/*).
 * Ported from vaultwarden src/api/core/auth_requests.rs.
 */
export const authRequestRoutes = new Hono<AppEnv>();
