import { Hono } from 'hono';
import type { AppEnv } from '../env';

/**
 * Emergency access (/api/emergency-access/*).
 * Ported from vaultwarden src/api/core/emergency_access.rs.
 */
export const emergencyAccessRoutes = new Hono<AppEnv>();
