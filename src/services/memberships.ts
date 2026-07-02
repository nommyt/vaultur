import { and, eq } from 'drizzle-orm';
import { usersOrganizations, type Db, type Membership } from '../db';
import { MembershipStatus, MembershipType } from '../shared';

/**
 * vaultwarden's MembershipType has a custom ordering: Owner > Admin > Manager > User.
 * The numeric wire values (Owner=0, Admin=1, User=2, Manager=3) don't sort that way,
 * so all comparisons go through this rank.
 */
export function membershipRank(atype: number): number {
  switch (atype) {
    case MembershipType.Owner:
      return 3;
    case MembershipType.Admin:
      return 2;
    case MembershipType.Manager:
      return 1;
    default:
      return 0;
  }
}

export function isAtLeast(atype: number, minimum: MembershipType): boolean {
  return membershipRank(atype) >= membershipRank(minimum);
}

export function hasFullAccess(m: Pick<Membership, 'atype' | 'accessAll'>): boolean {
  return m.accessAll || isAtLeast(m.atype, MembershipType.Admin);
}

export async function findConfirmedMembership(
  db: Db,
  userUuid: string,
  orgUuid: string,
): Promise<Membership | undefined> {
  return db.query.usersOrganizations.findFirst({
    where: and(
      eq(usersOrganizations.userUuid, userUuid),
      eq(usersOrganizations.orgUuid, orgUuid),
      eq(usersOrganizations.status, MembershipStatus.Confirmed),
    ),
  });
}

export async function findConfirmedMemberships(db: Db, userUuid: string): Promise<Membership[]> {
  return db.query.usersOrganizations.findMany({
    where: and(
      eq(usersOrganizations.userUuid, userUuid),
      eq(usersOrganizations.status, MembershipStatus.Confirmed),
    ),
  });
}
