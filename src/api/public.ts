import { and, eq } from "drizzle-orm"
import { Hono } from "hono"
import type { Context } from "hono"

import { decodeJwt, issuer } from "../auth/jwt"
import {
	groups,
	groupsUsers,
	invitations,
	nowDb,
	organizationApiKey,
	organizations,
	usersOrganizations,
	users
} from "../db"
import type { AppEnv } from "../env"
import { err, unauthorized } from "../error"
import { createMailer } from "../services/mail"
import { newUserShell } from "../services/users"
import { MembershipStatus, MembershipType } from "../shared"
import { ci, normalizeEmail, uuid } from "../util"

/**
 * Public (organization-API-key authenticated) endpoints — the directory
 * connector's LDAP sync. Ported from vaultwarden src/api/core/public.rs.
 *
 * Mounted at /api. Auth is the org API-key bearer token from
 * `/identity/connect/token` with scope api.organization.
 */
export const publicRoutes = new Hono<AppEnv>()

interface OrgApiClaims {
	sub: string
	client_id: string
	client_sub: string
	iss: string
	[k: string]: unknown
}

/** Verify the org-api-key bearer token; returns the org id. */
async function verifyPublicToken(c: Context<AppEnv>): Promise<string> {
	const header = c.req.header("Authorization") ?? ""
	const token = header.startsWith("Bearer ") ? header.slice(7) : ""
	if (!token) unauthorized("No access token provided")

	const config = c.get("config")
	let claims: OrgApiClaims
	try {
		claims = await decodeJwt<OrgApiClaims>(
			c.env.JWT_SECRET,
			token,
			issuer(config.domain, "api.organization")
		)
	} catch {
		unauthorized("Invalid claim")
	}
	const orgId = claims.client_id.startsWith("organization.")
		? claims.client_id.slice("organization.".length)
		: ""
	if (!orgId || orgId !== claims.client_sub) unauthorized("Token not issued for this org")

	const row = await c.get("db").query.organizationApiKey.findFirst({
		where: eq(organizationApiKey.orgUuid, orgId)
	})
	if (!row || row.uuid !== claims.sub) unauthorized("Invalid client_id")
	return orgId
}

publicRoutes.post("/public/organization/import", async (c) => {
	const orgId = await verifyPublicToken(c)
	const db = c.get("db")
	const config = c.get("config")
	const mailer = createMailer(c.env.VAULTUR_EMAIL, config)
	const body = (await c.req.json()) as Record<string, unknown>

	const org = await db.query.organizations.findFirst({ where: eq(organizations.uuid, orgId) })
	if (!org) err("Error looking up organization")

	const members = ci<Record<string, unknown>[]>(body, "members") ?? []
	const groupData = ci<Record<string, unknown>[]>(body, "groups") ?? []

	for (const member of members) {
		const email = normalizeEmail(String(ci(member, "email") ?? ""))
		const externalId = (ci<string>(member, "externalId") ?? null) as string | null
		const deleted = Boolean(ci(member, "deleted"))
		if (!email) continue

		const existing = await db
			.select()
			.from(usersOrganizations)
			.innerJoin(users, eq(usersOrganizations.userUuid, users.uuid))
			.where(and(eq(users.email, email), eq(usersOrganizations.orgUuid, orgId)))
		const membership = existing[0]?.users_organizations

		if (deleted) {
			if (membership) {
				// Revoke unless last confirmed owner
				const canRevoke =
					membership.atype !== MembershipType.Owner ||
					membership.status !== MembershipStatus.Confirmed ||
					(await confirmedOwnerCount(c, orgId)) > 1
				if (canRevoke && membership.status >= MembershipStatus.Invited) {
					await db
						.update(usersOrganizations)
						.set({ status: membership.status - 128, externalId })
						.where(eq(usersOrganizations.uuid, membership.uuid))
				}
			}
			continue
		}

		if (membership) {
			// Restore if revoked
			if (membership.status < MembershipStatus.Invited) {
				await db
					.update(usersOrganizations)
					.set({ status: membership.status + 128, externalId })
					.where(eq(usersOrganizations.uuid, membership.uuid))
			} else {
				await db
					.update(usersOrganizations)
					.set({ externalId })
					.where(eq(usersOrganizations.uuid, membership.uuid))
			}
			continue
		}

		// New member — find or create the user shell
		let user = (await db.select().from(users).where(eq(users.email, email)))[0]
		if (!user) {
			const shell = newUserShell(email, null)
			await db.insert(users).values(shell)
			user = (await db.select().from(users).where(eq(users.email, email)))[0]!
			if (!mailer.enabled) await db.insert(invitations).values({ email }).onConflictDoNothing()
		}
		const status =
			mailer.enabled || user.passwordHash === ""
				? MembershipStatus.Invited
				: MembershipStatus.Accepted
		await db.insert(usersOrganizations).values({
			uuid: uuid(),
			userUuid: user.uuid,
			orgUuid: orgId,
			invitedByEmail: org.billingEmail,
			accessAll: false,
			akey: "",
			status,
			atype: MembershipType.User,
			resetPasswordKey: null,
			externalId
		})
	}

	// Groups
	for (const g of groupData) {
		const name = String(ci(g, "name") ?? "")
		const externalId = String(ci(g, "externalId") ?? "")
		const memberExternalIds = ci<string[]>(g, "memberExternalIds") ?? []
		if (!externalId) continue

		let group = (
			await db
				.select()
				.from(groups)
				.where(and(eq(groups.externalId, externalId), eq(groups.organizationsUuid, orgId)))
		)[0]
		if (!group) {
			const now = nowDb()
			const row = {
				uuid: uuid(),
				organizationsUuid: orgId,
				name,
				accessAll: false,
				externalId,
				creationDate: now,
				revisionDate: now
			}
			await db.insert(groups).values(row)
			group = row
		}

		await db.delete(groupsUsers).where(eq(groupsUsers.groupsUuid, group.uuid))
		for (const extId of memberExternalIds) {
			const member = (
				await db
					.select()
					.from(usersOrganizations)
					.where(
						and(eq(usersOrganizations.externalId, extId), eq(usersOrganizations.orgUuid, orgId))
					)
			)[0]
			if (member) {
				await db
					.insert(groupsUsers)
					.values({ groupsUuid: group.uuid, usersOrganizationsUuid: member.uuid })
					.onConflictDoNothing()
			}
		}
	}

	return c.body(null, 200)
})

async function confirmedOwnerCount(c: Context<AppEnv>, orgUuid: string): Promise<number> {
	return (
		await c.get("db").query.usersOrganizations.findMany({
			where: and(
				eq(usersOrganizations.orgUuid, orgUuid),
				eq(usersOrganizations.atype, MembershipType.Owner),
				eq(usersOrganizations.status, MembershipStatus.Confirmed)
			)
		})
	).length
}
