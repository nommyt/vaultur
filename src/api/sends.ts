import { and, eq } from "drizzle-orm"
import { Hono } from "hono"
import type { Context } from "hono"

import { basicClaims, decodeJwt, encodeJwt, issuer } from "../auth/jwt"
import { requireAuth, auth } from "../auth/middleware"
import { pbkdf2 } from "../crypto"
import {
	nowDb,
	toDb,
	fromDb,
	sends,
	usersOrganizations,
	orgPolicies,
	type Db,
	type Send,
	type User
} from "../db"
import type { AppEnv } from "../env"
import { err, errCode, notFound } from "../error"
import { isAtLeast } from "../services/memberships"
import { Notify } from "../services/notify"
import { touchUser } from "../services/users"
import { sendToJson, sendAccessId, displaySize } from "../services/vault"
import { MembershipStatus, MembershipType, OrgPolicyType, SendType, UpdateType } from "../shared"
import {
	b64Decode,
	b64Encode,
	ci,
	constantTimeEqual,
	randomAlphanum,
	randomBytes,
	uuid
} from "../util"

const SEND_INACCESSIBLE_MSG = "Send does not exist or is no longer available"

type Ctx = Context<AppEnv>

function fileKey(sendUuid: string, fileId: string): string {
	return `sends/${sendUuid}/${fileId}`
}

// ---------------------------------------------------------------------------
// Send password hashing (PBKDF2-100k like vaultwarden's Send::set_password)
// ---------------------------------------------------------------------------

async function hashSendPassword(
	password: string
): Promise<{ hash: string; salt: string; iter: number }> {
	const salt = randomBytes(64)
	const digest = await pbkdf2(new TextEncoder().encode(password), salt, 100_000)
	return { hash: b64Encode(digest), salt: b64Encode(salt), iter: 100_000 }
}

async function checkSendPassword(send: Send, password: string): Promise<boolean> {
	if (!send.passwordHash || !send.passwordSalt || !send.passwordIter) return false
	const digest = await pbkdf2(
		new TextEncoder().encode(password),
		b64Decode(send.passwordSalt),
		send.passwordIter
	)
	return constantTimeEqual(digest, b64Decode(send.passwordHash))
}

// ---------------------------------------------------------------------------
// Send creation payload
// ---------------------------------------------------------------------------

interface SendData {
	type: number
	key: string
	password?: string | null
	maxAccessCount?: number | null
	expirationDate?: string | null
	deletionDate: string
	disabled?: boolean
	hideEmail?: boolean | null
	name: string
	notes?: string | null
	text?: Record<string, unknown>
	file?: Record<string, unknown>
	fileLength?: number
}

function parseSendData(body: Record<string, unknown>): SendData {
	return {
		type: Number(ci(body, "type") ?? 0),
		key: String(ci(body, "key") ?? ""),
		password: (ci<string>(body, "password") ?? null) as string | null,
		maxAccessCount: (ci<number>(body, "maxAccessCount") ?? null) as number | null,
		expirationDate: (ci<string>(body, "expirationDate") ?? null) as string | null,
		deletionDate: String(ci(body, "deletionDate") ?? ""),
		disabled: Boolean(ci(body, "disabled")),
		hideEmail: (ci<boolean>(body, "hideEmail") ?? null) as boolean | null,
		name: String(ci(body, "name") ?? ""),
		notes: (ci<string>(body, "notes") ?? null) as string | null,
		text: ci(body, "text") as Record<string, unknown> | undefined,
		file: ci(body, "file") as Record<string, unknown> | undefined,
		fileLength: ci<number>(body, "fileLength")
	}
}

async function enforceDisableSendPolicy(db: Db, user: User): Promise<void> {
	const rows = await db
		.select({ atype: usersOrganizations.atype, status: usersOrganizations.status })
		.from(orgPolicies)
		.innerJoin(usersOrganizations, eq(orgPolicies.orgUuid, usersOrganizations.orgUuid))
		.where(
			and(
				eq(orgPolicies.atype, OrgPolicyType.DisableSend),
				eq(orgPolicies.enabled, true),
				eq(usersOrganizations.userUuid, user.uuid)
			)
		)
	const applies = rows.some(
		(r) => r.status >= MembershipStatus.Accepted && !isAtLeast(r.atype, MembershipType.Admin)
	)
	if (applies) err("Due to an Enterprise Policy, you are only able to delete an existing Send.")
}

async function newSendFromData(db: Db, user: User, data: SendData): Promise<Send> {
	if (!data.key) err("Send data not provided")
	if (!data.deletionDate) err("Send data not provided")
	const deletion = new Date(data.deletionDate)
	if (
		!Number.isFinite(deletion.getTime()) ||
		deletion.getTime() > Date.now() + 31 * 24 * 3600 * 1000
	) {
		err(
			"You cannot have a Send with a deletion date that far into the future. Adjust the Deletion Date to a value less than 31 days from now and try again."
		)
	}

	const now = nowDb()
	const send: Send = {
		uuid: uuid(),
		userUuid: user.uuid,
		organizationUuid: null,
		name: data.name,
		notes: data.notes ?? null,
		atype: data.type,
		data: "{}",
		akey: data.key,
		passwordHash: null,
		passwordSalt: null,
		passwordIter: null,
		maxAccessCount: data.maxAccessCount ?? null,
		accessCount: 0,
		creationDate: now,
		revisionDate: now,
		expirationDate: data.expirationDate ? toDb(new Date(data.expirationDate)) : null,
		deletionDate: toDb(deletion),
		disabled: data.disabled ?? false,
		hideEmail: data.hideEmail ?? null
	}

	if (data.password) {
		const pw = await hashSendPassword(data.password)
		send.passwordHash = pw.hash
		send.passwordSalt = pw.salt
		send.passwordIter = pw.iter
	}

	return send
}

function sendNotifier(c: Ctx): Notify {
	return new Notify(c.env, c.get("config"), c.executionCtx)
}

// ---------------------------------------------------------------------------
// Public access endpoints (no auth)
// ---------------------------------------------------------------------------

export const sendAccessRoutes = new Hono<AppEnv>()

function checkAccessible(send: Send): void {
	if (send.maxAccessCount != null && send.accessCount >= send.maxAccessCount) {
		errCode(SEND_INACCESSIBLE_MSG, 404)
	}
	if (send.expirationDate && Date.now() >= fromDb(send.expirationDate).getTime()) {
		errCode(SEND_INACCESSIBLE_MSG, 404)
	}
	if (Date.now() >= fromDb(send.deletionDate).getTime()) {
		errCode(SEND_INACCESSIBLE_MSG, 404)
	}
	if (send.disabled) errCode(SEND_INACCESSIBLE_MSG, 404)
}

async function sendToJsonAccess(db: Db, send: Send): Promise<Record<string, unknown>> {
	let creatorIdentifier: string | null = null
	if (!send.hideEmail && send.userUuid) {
		const { users } = await import("../db")
		const owner = await db.query.users.findFirst({ where: eq(users.uuid, send.userUuid) })
		creatorIdentifier = owner?.email ?? null
	}
	const full = sendToJson(send)
	return {
		id: send.uuid,
		type: send.atype,
		name: send.name,
		text: full.text,
		file: full.file,
		expirationDate: full.expirationDate,
		creatorIdentifier,
		object: "send-access"
	}
}

sendAccessRoutes.post("/sends/access/:accessId", async (c) => {
	const db = c.get("db")
	const accessId = c.req.param("accessId")
	const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>
	const password = ci<string>(body, "password")

	const all = await db.select().from(sends)
	const send = all.find((s) => sendAccessId(s.uuid) === accessId)
	if (!send) errCode(SEND_INACCESSIBLE_MSG, 404)
	checkAccessible(send)

	if (send.passwordHash) {
		if (!password) errCode("Password not provided", 401)
		if (!(await checkSendPassword(send, password))) err("Invalid password")
	}

	if (send.atype === SendType.Text) {
		send.accessCount += 1
		await db.update(sends).set({ accessCount: send.accessCount }).where(eq(sends.uuid, send.uuid))
	}
	if (send.userUuid) {
		sendNotifier(c).sendUpdate(UpdateType.SyncSendUpdate, send, [send.userUuid], null)
	}
	return c.json(await sendToJsonAccess(db, send))
})

sendAccessRoutes.post("/sends/:sendId/access/file/:fileId", async (c) => {
	const db = c.get("db")
	const config = c.get("config")
	const sendId = c.req.param("sendId")
	const fileId = c.req.param("fileId")
	const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>
	const password = ci<string>(body, "password")

	const send = await db.query.sends.findFirst({ where: eq(sends.uuid, sendId) })
	if (!send) errCode(SEND_INACCESSIBLE_MSG, 404)
	checkAccessible(send)

	if (send.passwordHash) {
		if (!password) errCode("Password not provided", 401)
		if (!(await checkSendPassword(send, password))) err("Invalid password.")
	}

	await db
		.update(sends)
		.set({ accessCount: send.accessCount + 1 })
		.where(eq(sends.uuid, send.uuid))

	const token = await encodeJwt(
		c.env.JWT_SECRET,
		basicClaims({
			domain: config.domain,
			kind: "send",
			sub: `${sendId}/${fileId}`,
			ttlSeconds: 300
		})
	)
	return c.json({
		object: "send-fileDownload",
		id: fileId,
		url: `${config.domain}/api/sends/${sendId}/${fileId}?t=${token}`
	})
})

// Token-authenticated file download
sendAccessRoutes.get("/sends/:sendId/:fileId", async (c) => {
	const sendId = c.req.param("sendId")
	const fileId = c.req.param("fileId")
	const t = c.req.query("t") ?? ""
	const config = c.get("config")
	try {
		const claims = await decodeJwt<{ sub: string }>(
			c.env.JWT_SECRET,
			t,
			issuer(config.domain, "send")
		)
		if (claims.sub !== `${sendId}/${fileId}`) notFound()
	} catch {
		notFound()
	}
	const object = await c.get("storage").get(fileKey(sendId, fileId))
	if (!object) notFound()
	return new Response(object.body, {
		headers: {
			"Content-Type": "application/octet-stream",
			"Content-Length": String(object.size),
			"Content-Disposition": `attachment; filename="${fileId}"`
		}
	})
})

// ---------------------------------------------------------------------------
// Authenticated send management
// ---------------------------------------------------------------------------

export const sendRoutes = new Hono<AppEnv>()
sendRoutes.use("*", requireAuth)

sendRoutes.get("/sends", async (c) => {
	const { user } = auth(c)
	const rows = await c.get("db").query.sends.findMany({ where: eq(sends.userUuid, user.uuid) })
	return c.json({ data: rows.map(sendToJson), object: "list", continuationToken: null })
})

async function loadOwnSend(c: Ctx, id: string | undefined): Promise<Send> {
	if (!id) notFound("Send not found")
	const { user } = auth(c)
	const send = await c.get("db").query.sends.findFirst({
		where: and(eq(sends.uuid, id), eq(sends.userUuid, user.uuid))
	})
	if (!send) notFound("Send not found")
	return send
}

// Text send create
sendRoutes.post("/sends", async (c) => {
	const { user, device } = auth(c)
	const db = c.get("db")
	const config = c.get("config")
	if (!config.sendsAllowed) err("Sends are disabled on this server")
	await enforceDisableSendPolicy(db, user)

	const data = parseSendData((await c.req.json()) as Record<string, unknown>)
	if (data.type === SendType.File) err("File sends should use /api/sends/file")
	if (!data.text) err("Send data not provided")

	const send = await newSendFromData(db, user, data)
	send.data = JSON.stringify(data.text)
	await db.insert(sends).values(send)
	await touchUser(db, user.uuid)
	sendNotifier(c).sendUpdate(UpdateType.SyncSendCreate, send, [user.uuid], device.uuid)
	return c.json(sendToJson(send))
})

// File send v2: create metadata, get upload url
sendRoutes.post("/sends/file/v2", async (c) => {
	const { user } = auth(c)
	const db = c.get("db")
	const config = c.get("config")
	if (!config.sendsAllowed) err("Sends are disabled on this server")
	await enforceDisableSendPolicy(db, user)

	const data = parseSendData((await c.req.json()) as Record<string, unknown>)
	if (data.type !== SendType.File) err("Send content is not a file")
	if (!data.file) err("Send data not provided")
	const fileLength = Number(data.fileLength ?? 0)
	if (!Number.isFinite(fileLength) || fileLength <= 0) err("Invalid fileLength")
	const maxBytes = c.get("storage").maxBytes
	if (fileLength > maxBytes) {
		err(`Send storage limit exceeded (max ${displaySize(maxBytes)})`)
	}

	const send = await newSendFromData(db, user, data)
	const fileId = randomAlphanum(24).toLowerCase()
	send.data = JSON.stringify({
		...data.file,
		id: fileId,
		fileName: ci(data.file, "fileName"),
		size: fileLength,
		sizeName: displaySize(fileLength)
	})
	await db.insert(sends).values(send)

	return c.json({
		object: "send-fileUpload",
		fileUploadType: 0,
		sendResponse: sendToJson(send),
		url: `/sends/${send.uuid}/file/${fileId}`
	})
})

// File upload for v2
sendRoutes.post("/sends/:id/file/:fileId", async (c) => {
	const { user, device } = auth(c)
	const db = c.get("db")
	const send = await loadOwnSend(c, c.req.param("id"))
	const fileId = c.req.param("fileId")

	const data = JSON.parse(send.data) as Record<string, unknown>
	if (data.id !== fileId) err("Send file id mismatch")

	const form = await c.req.parseBody()
	const file = form.data ?? form.file
	if (!(file instanceof File)) err("No data to upload")

	const expected = Number(data.size ?? 0)
	if (Math.abs(expected - file.size) > 1) {
		err(
			`Send file size mismatch (expected within [${expected - 1}, ${expected + 1}], got ${file.size})`
		)
	}

	const storage = c.get("storage")
	if (file.size > storage.maxBytes) {
		err(`Send storage limit exceeded (max ${displaySize(storage.maxBytes)})`)
	}
	await storage.put(fileKey(send.uuid, fileId), file.stream(), file.size)
	await touchUser(db, user.uuid)
	sendNotifier(c).sendUpdate(UpdateType.SyncSendCreate, send, [user.uuid], device.uuid)
	return c.body(null, 200)
})

// Legacy one-shot file send
sendRoutes.post("/sends/file", async (c) => {
	const { user, device } = auth(c)
	const db = c.get("db")
	const config = c.get("config")
	if (!config.sendsAllowed) err("Sends are disabled on this server")
	await enforceDisableSendPolicy(db, user)

	const form = await c.req.parseBody()
	const model =
		typeof form.model === "string" ? (JSON.parse(form.model) as Record<string, unknown>) : null
	const file = form.data ?? form.file
	if (!model || !(file instanceof File)) err("Invalid multipart data")

	const storage = c.get("storage")
	if (file.size > storage.maxBytes) {
		err(`Send storage limit exceeded (max ${displaySize(storage.maxBytes)})`)
	}

	const data = parseSendData(model)
	const send = await newSendFromData(db, user, data)
	const fileId = randomAlphanum(24).toLowerCase()
	send.data = JSON.stringify({
		id: fileId,
		fileName: file.name,
		size: file.size,
		sizeName: displaySize(file.size)
	})
	await db.insert(sends).values(send)
	await storage.put(fileKey(send.uuid, fileId), file.stream(), file.size)
	await touchUser(db, user.uuid)
	sendNotifier(c).sendUpdate(UpdateType.SyncSendCreate, send, [user.uuid], device.uuid)
	return c.json(sendToJson(send))
})

sendRoutes.get("/sends/:id", async (c) => {
	const send = await loadOwnSend(c, c.req.param("id"))
	return c.json(sendToJson(send))
})

sendRoutes.put("/sends/:id", async (c) => {
	const { user, device } = auth(c)
	const db = c.get("db")
	await enforceDisableSendPolicy(db, user)
	const send = await loadOwnSend(c, c.req.param("id"))
	const data = parseSendData((await c.req.json()) as Record<string, unknown>)

	if (data.type !== send.atype) err("Sends can't change type")

	if (send.atype === SendType.Text) {
		if (!data.text) err("Send data not provided")
		send.data = JSON.stringify(data.text)
	}

	const deletion = new Date(data.deletionDate)
	if (
		!Number.isFinite(deletion.getTime()) ||
		deletion.getTime() > Date.now() + 31 * 24 * 3600 * 1000
	) {
		err(
			"You cannot have a Send with a deletion date that far into the future. Adjust the Deletion Date to a value less than 31 days from now and try again."
		)
	}

	send.name = data.name
	send.akey = data.key || send.akey
	send.deletionDate = toDb(deletion)
	send.notes = data.notes ?? null
	send.maxAccessCount = data.maxAccessCount ?? null
	send.expirationDate = data.expirationDate ? toDb(new Date(data.expirationDate)) : null
	send.hideEmail = data.hideEmail ?? null
	send.disabled = data.disabled ?? false
	send.revisionDate = nowDb()

	if (data.password) {
		const pw = await hashSendPassword(data.password)
		send.passwordHash = pw.hash
		send.passwordSalt = pw.salt
		send.passwordIter = pw.iter
	}

	await db
		.update(sends)
		.set({ ...send })
		.where(eq(sends.uuid, send.uuid))
	await touchUser(db, user.uuid)
	sendNotifier(c).sendUpdate(UpdateType.SyncSendUpdate, send, [user.uuid], device.uuid)
	return c.json(sendToJson(send))
})

sendRoutes.put("/sends/:id/remove-password", async (c) => {
	const { user, device } = auth(c)
	const db = c.get("db")
	const send = await loadOwnSend(c, c.req.param("id"))
	send.passwordHash = null
	send.passwordSalt = null
	send.passwordIter = null
	send.revisionDate = nowDb()
	await db
		.update(sends)
		.set({ ...send })
		.where(eq(sends.uuid, send.uuid))
	sendNotifier(c).sendUpdate(UpdateType.SyncSendUpdate, send, [user.uuid], device.uuid)
	return c.json(sendToJson(send))
})

sendRoutes.delete("/sends/:id", async (c) => {
	const { user, device } = auth(c)
	const db = c.get("db")
	const send = await loadOwnSend(c, c.req.param("id"))

	if (send.atype === SendType.File) {
		const data = JSON.parse(send.data) as { id?: string }
		if (data.id) await c.get("storage").delete(fileKey(send.uuid, data.id))
	}
	await db.delete(sends).where(eq(sends.uuid, send.uuid))
	await touchUser(db, user.uuid)
	sendNotifier(c).sendUpdate(UpdateType.SyncSendDelete, send, [user.uuid], device.uuid)
	return c.body(null, 200)
})
