import { Hono } from 'hono';
import type { AppEnv } from '../env';

/**
 * Organization membership lifecycle, groups, and policies.
 * Ported from vaultwarden src/api/core/organizations.rs (member/group/policy parts).
 */
export const orgMemberRoutes = new Hono<AppEnv>();
