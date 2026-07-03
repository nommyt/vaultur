import { eq, sql } from "drizzle-orm"
import { Hono } from "hono"
import type { Context } from "hono"
import { getCookie, setCookie } from "hono/cookie"

import { basicClaims, decodeJwt, encodeJwt, issuer } from "../auth/jwt"
import { loadConfig } from "../config"
import { diffOverrides } from "../config-schema"
import {
	attachments,
	ciphers,
	devices,
	invitations,
	nowDb,
	organizations,
	twofactor,
	users,
	usersOrganizations,
	toApi,
	type Db
} from "../db"
import type { AppEnv } from "../env"
import { errCode, unauthorized } from "../error"
import { createMailer } from "../services/mail"
import {
	getConfigOverrides,
	saveConfigOverrides,
	clearConfigOverrides
} from "../services/server-config"
import { newUserShell } from "../services/users"
import { MembershipStatus } from "../shared"
import { ci, constantTimeEqualStr, normalizeEmail, uuid } from "../util"
import {
	renderLogin,
	renderSettings,
	renderUsers,
	renderOrganizations,
	renderDiagnostics,
	type AdminUserRow,
	type AdminOrgRow
} from "./admin-views"

/**
 * Admin panel — a Hono-JSX port of vaultwarden's admin (src/api/admin.rs +
 * templates/admin/*.hbs). Enabled only when ADMIN_TOKEN is configured;
 * otherwise every route 404s. Editable settings are persisted in D1 and layered
 * on top of the env-derived config (see config-schema.ts / server-config.ts).
 */
export const adminRoutes = new Hono<AppEnv>()

type Ctx = Context<AppEnv>

const ADMIN_COOKIE = "VAULTUR_ADMIN"

// Disable the whole surface when no admin token is set
adminRoutes.use("*", async (c, next) => {
	if (!c.get("config").adminTokenSet) return c.body(null, 404)
	await next()
})

/** True when the request carries a valid admin cookie or bearer ADMIN_TOKEN. */
async function isAdminAuthed(c: Ctx): Promise<boolean> {
	const bearer = c.req.header("Authorization") ?? ""
	const bearerToken = bearer.startsWith("Bearer ") ? bearer.slice(7) : ""
	if (c.env.ADMIN_TOKEN && bearerToken && constantTimeEqualStr(bearerToken, c.env.ADMIN_TOKEN)) {
		return true
	}
	const cookie = getCookie(c, ADMIN_COOKIE)
	if (cookie) {
		try {
			await decodeJwt(c.env.JWT_SECRET, cookie, issuer(c.get("config").domain, "admin"))
			return true
		} catch {
			// fall through
		}
	}
	return false
}

// Token login → admin session cookie. Accepts a browser form post (redirects
// back to /admin) or a JSON body (returns {ok:true}); registered for both '/'
// and '' so it matches /admin and /admin/.
async function adminLogin(c: Ctx) {
	const isJson = (c.req.header("Content-Type") ?? "").includes("application/json")
	let token = ""
	if (isJson) {
		token = String(
			ci((await c.req.json().catch(() => ({}))) as Record<string, unknown>, "token") ?? ""
		)
	} else {
		const form = await c.req.parseBody().catch(() => ({}) as Record<string, unknown>)
		token = typeof form.token === "string" ? form.token : ""
	}

	if (!c.env.ADMIN_TOKEN || !constantTimeEqualStr(token, c.env.ADMIN_TOKEN)) {
		if (isJson) errCode("Invalid admin token", 401)
		return c.html(renderLogin("Invalid admin token"), 401)
	}

	const config = c.get("config")
	const jwt = await encodeJwt(
		c.env.JWT_SECRET,
		basicClaims({
			domain: config.domain,
			kind: "admin",
			sub: "admin",
			ttlSeconds: config.adminSessionLifetimeMinutes * 60
		})
	)
	setCookie(c, ADMIN_COOKIE, jwt, {
		httpOnly: true,
		secure: true,
		sameSite: "Strict",
		path: "/admin",
		maxAge: config.adminSessionLifetimeMinutes * 60
	})
	if (isJson) return c.json({ ok: true })
	return c.redirect("/admin", 303)
}
adminRoutes.post("/", adminLogin)
adminRoutes.post("", adminLogin)

// GET /admin → Settings page when authenticated, otherwise the login page.
async function adminIndex(c: Ctx) {
	if (!(await isAdminAuthed(c))) return c.html(renderLogin())
	const db = c.get("db")
	const cfg = c.get("config")
	const overridden = new Set(Object.keys(await getConfigOverrides(db)))
	return c.html(
		renderSettings({
			cfg,
			overridden,
			bindingPresent: Boolean(c.env.VAULTUR_EMAIL),
			adminTokenInsecure: false
		})
	)
}
adminRoutes.get("/", adminIndex)
adminRoutes.get("", adminIndex)

// Auth guard for the rest: admin cookie OR bearer ADMIN_TOKEN
adminRoutes.use("*", async (c, next) => {
	if (c.req.path === "/admin" || c.req.path === "/admin/") {
		await next()
		return
	}
	if (await isAdminAuthed(c)) {
		await next()
		return
	}
	unauthorized("Admin authentication required")
})

// ---------------------------------------------------------------------------
// Config editor (persisted in D1, layered over env)
// ---------------------------------------------------------------------------

adminRoutes.post("/config", async (c) => {
	const db = c.get("db")
	const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>
	// Diff posted values against the env-only baseline so overrides stay minimal.
	const envBase = loadConfig(c.env, c.req.url)
	const overrides = diffOverrides(body, envBase)
	await saveConfigOverrides(db, overrides)
	return c.json({ ok: true })
})

adminRoutes.post("/config/delete", async (c) => {
	await clearConfigOverrides(c.get("db"))
	return c.json({ ok: true })
})

adminRoutes.post("/test/smtp", async (c) => {
	const config = c.get("config")
	const mailer = createMailer(c.env.VAULTUR_EMAIL, config)
	if (!mailer.enabled) {
		return c.json(
			{ message: "Email is not configured (missing VAULTUR_EMAIL binding or From address)." },
			400
		)
	}
	const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>
	const email = normalizeEmail(String(ci(body, "email") ?? ""))
	if (!email) return c.json({ message: "A valid email address is required." }, 400)
	await mailer.send(
		email,
		"Vaultur SMTP test",
		"<p>This is a test email from your Vaultur admin panel. Cloudflare Email Sending is working.</p>",
		"This is a test email from your Vaultur admin panel. Cloudflare Email Sending is working."
	)
	return c.json({ ok: true })
})

async function userOverview(db: Db, userUuid: string) {
	const user = (await db.query.users.findFirst({ where: eq(users.uuid, userUuid) }))!
	const cipherCount = (
		await db
			.select({ n: sql<number>`count(*)` })
			.from(ciphers)
			.where(eq(ciphers.userUuid, user.uuid))
	)[0]!.n
	const attachmentSize = (
		await db
			.select({ total: sql<number>`coalesce(sum(${attachments.fileSize}), 0)` })
			.from(attachments)
			.innerJoin(ciphers, eq(attachments.cipherUuid, ciphers.uuid))
			.where(eq(ciphers.userUuid, user.uuid))
	)[0]!.total
	const twoFactor =
		(await db.query.twofactor.findMany({ where: eq(twofactor.userUuid, user.uuid) })).length > 0
	const orgCount = (
		await db
			.select({ n: sql<number>`count(*)` })
			.from(usersOrganizations)
			.where(eq(usersOrganizations.userUuid, user.uuid))
	)[0]!.n

	return {
		id: user.uuid,
		name: user.name,
		email: user.email,
		emailVerified: user.verifiedAt != null,
		twoFactorEnabled: twoFactor,
		userEnabled: user.enabled,
		createdAt: toApi(user.createdAt),
		lastActive: toApi(user.updatedAt),
		cipherCount,
		attachmentCount: 0,
		attachmentSize,
		organizationCount: orgCount,
		object: "adminUser"
	}
}

async function allUsersOverview(db: Db): Promise<AdminUserRow[]> {
	const all = await db.select({ uuid: users.uuid }).from(users)
	return Promise.all(all.map((u) => userOverview(db, u.uuid)))
}

// JSON list (data API); HTML overview page renders the same data.
adminRoutes.get("/users", async (c) => c.json(await allUsersOverview(c.get("db"))))
adminRoutes.get("/users/overview", async (c) =>
	c.html(renderUsers(await allUsersOverview(c.get("db"))))
)

// End the admin session (nav link → clear cookie and return to the login page)
adminRoutes.get("/logout", (c) => {
	setCookie(c, ADMIN_COOKIE, "", {
		httpOnly: true,
		secure: true,
		sameSite: "Strict",
		path: "/admin",
		maxAge: 0
	})
	return c.redirect("/admin", 303)
})

adminRoutes.get("/users/by-mail/:email", async (c) => {
	const db = c.get("db")
	const user = await db.query.users.findFirst({
		where: eq(users.email, c.req.param("email").toLowerCase())
	})
	if (!user) return c.json({ message: "User not found" }, 404)
	return c.json(await userOverview(db, user.uuid))
})

adminRoutes.get("/users/:uuid", async (c) => {
	const db = c.get("db")
	const user = await db.query.users.findFirst({ where: eq(users.uuid, c.req.param("uuid")) })
	if (!user) return c.json({ message: "User not found" }, 404)
	return c.json(await userOverview(db, user.uuid))
})

adminRoutes.post("/users/:uuid/delete", async (c) => {
	await c
		.get("db")
		.delete(users)
		.where(eq(users.uuid, c.req.param("uuid")))
	return c.body(null, 200)
})

adminRoutes.post("/users/:uuid/deauth", async (c) => {
	const db = c.get("db")
	const uuidParam = c.req.param("uuid")
	await db.delete(devices).where(eq(devices.userUuid, uuidParam))
	await db
		.update(users)
		.set({ securityStamp: uuid(), updatedAt: nowDb() })
		.where(eq(users.uuid, uuidParam))
	return c.body(null, 200)
})

adminRoutes.post("/users/:uuid/disable", async (c) => {
	const db = c.get("db")
	const uuidParam = c.req.param("uuid")
	await db.delete(devices).where(eq(devices.userUuid, uuidParam))
	await db
		.update(users)
		.set({ enabled: false, securityStamp: uuid(), updatedAt: nowDb() })
		.where(eq(users.uuid, uuidParam))
	return c.body(null, 200)
})

adminRoutes.post("/users/:uuid/enable", async (c) => {
	await c
		.get("db")
		.update(users)
		.set({ enabled: true, updatedAt: nowDb() })
		.where(eq(users.uuid, c.req.param("uuid")))
	return c.body(null, 200)
})

adminRoutes.post("/users/:uuid/remove-2fa", async (c) => {
	const db = c.get("db")
	const uuidParam = c.req.param("uuid")
	await db.delete(twofactor).where(eq(twofactor.userUuid, uuidParam))
	await db.update(users).set({ totpRecover: null }).where(eq(users.uuid, uuidParam))
	return c.body(null, 200)
})

adminRoutes.post("/invite", async (c) => {
	const db = c.get("db")
	const config = c.get("config")
	const body = (await c.req.json()) as Record<string, unknown>
	const email = normalizeEmail(String(ci(body, "email") ?? ""))
	if (!email) return c.json({ message: "Email required" }, 400)

	const existing = await db.query.users.findFirst({ where: eq(users.email, email) })
	if (existing) return c.json({ message: "User already exists" }, 400)

	// Create a shell user + invitation (admin invites bypass signup restrictions)
	await db.insert(users).values(newUserShell(email, null))
	await db.insert(invitations).values({ email }).onConflictDoNothing()
	return c.json({ email, object: "invitation" })
})

async function allOrgsOverview(db: Db): Promise<AdminOrgRow[]> {
	const orgs = await db.select().from(organizations)
	return Promise.all(
		orgs.map(async (org) => {
			const userCount = (
				await db
					.select({ n: sql<number>`count(*)` })
					.from(usersOrganizations)
					.where(eq(usersOrganizations.orgUuid, org.uuid))
			)[0]!.n
			const cipherCount = (
				await db
					.select({ n: sql<number>`count(*)` })
					.from(ciphers)
					.where(eq(ciphers.organizationUuid, org.uuid))
			)[0]!.n
			return {
				id: org.uuid,
				name: org.name,
				billingEmail: org.billingEmail,
				userCount,
				cipherCount
			}
		})
	)
}

adminRoutes.get("/organizations", async (c) => {
	const data = await allOrgsOverview(c.get("db"))
	return c.json(data.map((o) => ({ ...o, object: "adminOrganization" })))
})
adminRoutes.get("/organizations/overview", async (c) =>
	c.html(renderOrganizations(await allOrgsOverview(c.get("db"))))
)

adminRoutes.post("/organizations/:uuid/delete", async (c) => {
	const db = c.get("db")
	const orgId = c.req.param("uuid")
	await db.delete(ciphers).where(eq(ciphers.organizationUuid, orgId))
	await db.delete(organizations).where(eq(organizations.uuid, orgId))
	return c.body(null, 200)
})

async function diagnosticsData(c: Ctx) {
	const db = c.get("db")
	const cfg = c.get("config")
	const userCount = (await db.select({ n: sql<number>`count(*)` }).from(users))[0]!.n
	return {
		version: "2025.12.0",
		dbType: "d1",
		running: true,
		userCount,
		time: new Date().toISOString(),
		domain: cfg.domain,
		emailEnabled: cfg.emailEnabled,
		pushEnabled: cfg.pushEnabled
	}
}

adminRoutes.get("/diagnostics", async (c) => c.html(renderDiagnostics(await diagnosticsData(c))))
adminRoutes.get("/diagnostics/config", async (c) => c.json(await diagnosticsData(c)))
