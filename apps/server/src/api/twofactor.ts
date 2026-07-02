import { Hono } from 'hono';
import type { AppEnv } from '../env';

/**
 * Two-factor management endpoints (/api/two-factor/*).
 * Ported from vaultwarden src/api/core/two_factor/{mod,authenticator,email}.rs.
 */
export const twofactorRoutes = new Hono<AppEnv>();
