import { and, eq } from 'drizzle-orm';
import { orgPolicies, usersOrganizations, type Db } from '@vaultur/db';
import { MembershipStatus, OrgPolicyType } from '@vaultur/shared';

interface MasterPasswordPolicyData {
  minComplexity: number | null;
  minLength: number | null;
  requireLower: boolean;
  requireUpper: boolean;
  requireNumbers: boolean;
  requireSpecial: boolean;
  enforceOnLogin: boolean;
}

/**
 * Merged master-password policy across the user's confirmed orgs
 * (vaultwarden master_password_policy in identity.rs).
 */
export async function masterPasswordPolicy(
  db: Db,
  userUuid: string,
): Promise<Record<string, unknown>> {
  const rows = await db
    .select({ data: orgPolicies.data })
    .from(orgPolicies)
    .innerJoin(usersOrganizations, eq(orgPolicies.orgUuid, usersOrganizations.orgUuid))
    .where(
      and(
        eq(usersOrganizations.userUuid, userUuid),
        eq(usersOrganizations.status, MembershipStatus.Confirmed),
        eq(orgPolicies.atype, OrgPolicyType.MasterPassword),
        eq(orgPolicies.enabled, true),
      ),
    );

  if (rows.length === 0) return { object: 'masterPasswordPolicy' };

  const merged: MasterPasswordPolicyData = {
    minComplexity: null,
    minLength: null,
    requireLower: false,
    requireUpper: false,
    requireNumbers: false,
    requireSpecial: false,
    enforceOnLogin: false,
  };
  for (const row of rows) {
    let data: Partial<MasterPasswordPolicyData>;
    try {
      data = JSON.parse(row.data) as Partial<MasterPasswordPolicyData>;
    } catch {
      continue;
    }
    if (data.minComplexity != null) {
      merged.minComplexity = Math.max(merged.minComplexity ?? 0, data.minComplexity);
    }
    if (data.minLength != null) merged.minLength = Math.max(merged.minLength ?? 0, data.minLength);
    merged.requireLower ||= Boolean(data.requireLower);
    merged.requireUpper ||= Boolean(data.requireUpper);
    merged.requireNumbers ||= Boolean(data.requireNumbers);
    merged.requireSpecial ||= Boolean(data.requireSpecial);
    merged.enforceOnLogin ||= Boolean(data.enforceOnLogin);
  }

  return { ...merged, object: 'masterPasswordPolicy' };
}
