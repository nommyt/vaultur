import { encode } from "@msgpack/msgpack"

import type { Config } from "../config"
import { fromDb, type Cipher, type Folder, type Send } from "../db"
import type { Bindings } from "../env"
import { UpdateType } from "../shared"
import { sendPushNotification } from "./push"

/**
 * Live-sync notifications (vaultwarden src/api/notifications.rs).
 *
 * Bitwarden clients receive SignalR "ReceiveMessage" invocations whose single
 * argument is a MessagePack map { ContextId, Type, Payload }. Payload keys are
 * PascalCase; dates are msgpack timestamp extensions (@msgpack/msgpack encodes
 * JS Date values that way natively).
 *
 * Frames are fully encoded here in the Worker; the per-user Durable Object
 * just broadcasts the bytes to connected sockets.
 */

function withVarintLength(body: Uint8Array): Uint8Array {
	const lengthBytes: number[] = []
	let length = body.length
	do {
		let byte = length & 0x7f
		length >>>= 7
		if (length > 0) byte |= 0x80
		lengthBytes.push(byte)
	} while (length > 0)
	const out = new Uint8Array(lengthBytes.length + body.length)
	out.set(lengthBytes, 0)
	out.set(body, lengthBytes.length)
	return out
}

function buildFrame(
	ut: UpdateType,
	payload: Map<string, unknown>,
	actingDeviceId: string | null
): Uint8Array {
	const arg = new Map<string, unknown>([
		["ContextId", actingDeviceId],
		["Type", ut],
		["Payload", payload]
	])
	const body = encode([1, new Map(), null, "ReceiveMessage", [arg]])
	return withVarintLength(body)
}

/** Structural subset of ExecutionContext — avoids Hono/workers-types version skew. */
interface WaitUntilContext {
	waitUntil(promise: Promise<unknown>): void
}

export class Notify {
	constructor(
		private readonly env: Bindings,
		private readonly config: Config,
		private readonly ctx: WaitUntilContext
	) {}

	private async broadcast(userUuid: string, frame: Uint8Array): Promise<void> {
		const id = this.env.VAULTUR_NOTIFICATIONS.idFromName(userUuid)
		const stub = this.env.VAULTUR_NOTIFICATIONS.get(id)
		await stub.fetch("https://do/publish", { method: "POST", body: frame as unknown as BodyInit })
	}

	private dispatch(userUuids: string[], frame: Uint8Array, push?: () => Promise<void>): void {
		this.ctx.waitUntil(
			(async () => {
				await Promise.all(
					userUuids.map((u) => this.broadcast(u, frame).catch((e) => console.error("notify", e)))
				)
				if (push && this.config.pushEnabled) await push().catch((e) => console.error("push", e))
			})()
		)
	}

	cipherUpdate(
		ut: UpdateType,
		cipher: Cipher,
		userUuids: string[],
		actingDeviceId: string | null
	): void {
		const payload = new Map<string, unknown>([
			["Id", cipher.uuid],
			["UserId", cipher.userUuid],
			["OrganizationId", cipher.organizationUuid],
			["CollectionIds", null],
			["RevisionDate", fromDb(cipher.updatedAt)]
		])
		const frame = buildFrame(ut, payload, actingDeviceId)
		this.dispatch(userUuids, frame, () =>
			sendPushNotification(this.env, this.config, {
				userId: cipher.userUuid ?? userUuids[0] ?? null,
				organizationId: cipher.organizationUuid,
				deviceId: actingDeviceId,
				identifier: actingDeviceId,
				type: ut,
				payload: {
					Id: cipher.uuid,
					UserId: cipher.userUuid,
					OrganizationId: cipher.organizationUuid,
					RevisionDate: fromDb(cipher.updatedAt).toISOString()
				}
			})
		)
	}

	folderUpdate(ut: UpdateType, folder: Folder, actingDeviceId: string | null): void {
		const payload = new Map<string, unknown>([
			["Id", folder.uuid],
			["UserId", folder.userUuid],
			["RevisionDate", fromDb(folder.updatedAt)]
		])
		const frame = buildFrame(ut, payload, actingDeviceId)
		this.dispatch([folder.userUuid], frame, () =>
			sendPushNotification(this.env, this.config, {
				userId: folder.userUuid,
				organizationId: null,
				deviceId: actingDeviceId,
				identifier: actingDeviceId,
				type: ut,
				payload: {
					Id: folder.uuid,
					UserId: folder.userUuid,
					RevisionDate: fromDb(folder.updatedAt).toISOString()
				}
			})
		)
	}

	sendUpdate(ut: UpdateType, send: Send, userUuids: string[], actingDeviceId: string | null): void {
		const payload = new Map<string, unknown>([
			["Id", send.uuid],
			["UserId", send.userUuid],
			["RevisionDate", fromDb(send.revisionDate)]
		])
		const frame = buildFrame(ut, payload, actingDeviceId)
		this.dispatch(userUuids, frame)
	}

	userUpdate(ut: UpdateType, userUuid: string): void {
		const payload = new Map<string, unknown>([
			["UserId", userUuid],
			["Date", new Date()]
		])
		const frame = buildFrame(ut, payload, null)
		this.dispatch([userUuid], frame, () =>
			sendPushNotification(this.env, this.config, {
				userId: userUuid,
				organizationId: null,
				deviceId: null,
				identifier: null,
				type: ut,
				payload: { UserId: userUuid, Date: new Date().toISOString() }
			})
		)
	}

	authRequest(userUuid: string, authRequestUuid: string, actingDeviceId: string | null): void {
		const payload = new Map<string, unknown>([
			["Id", authRequestUuid],
			["UserId", userUuid]
		])
		const frame = buildFrame(UpdateType.AuthRequest, payload, actingDeviceId)
		this.dispatch([userUuid], frame, () =>
			sendPushNotification(this.env, this.config, {
				userId: userUuid,
				organizationId: null,
				deviceId: actingDeviceId,
				identifier: actingDeviceId,
				type: UpdateType.AuthRequest,
				payload: { Id: authRequestUuid, UserId: userUuid }
			})
		)
	}

	authRequestResponse(
		userUuid: string,
		authRequestUuid: string,
		approvingDeviceId: string | null
	): void {
		const payload = new Map<string, unknown>([
			["Id", authRequestUuid],
			["UserId", userUuid]
		])
		const frame = buildFrame(UpdateType.AuthRequestResponse, payload, approvingDeviceId)
		this.dispatch([userUuid], frame, () =>
			sendPushNotification(this.env, this.config, {
				userId: userUuid,
				organizationId: null,
				deviceId: approvingDeviceId,
				identifier: approvingDeviceId,
				type: UpdateType.AuthRequestResponse,
				payload: { Id: authRequestUuid, UserId: userUuid }
			})
		)
		// The requesting (still unauthenticated) device listens on the anonymous
		// hub keyed by the auth-request id (vaultwarden's AnonymousNotify).
		this.ctx.waitUntil(
			this.broadcast(`anon:${authRequestUuid}`, frame).catch((e) => console.error("anon notify", e))
		)
	}
}
