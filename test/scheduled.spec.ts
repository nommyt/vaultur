import { env } from "cloudflare:test"
import { eq } from "drizzle-orm"
import { beforeEach, describe, expect, it } from "vitest"

import { attachments, ciphers, createDb, sends, toDb, twofactorDuoCtx } from "../src/db"
import type { Bindings } from "../src/env"
import { MAX_PURGE_PER_RUN, runScheduledJobs } from "../src/jobs/scheduled"

const bindings = env as unknown as Bindings
const db = createDb(bindings.VAULTUR_DB)
const bucket = bindings.VAULTUR_FILES!

const EVERY_15_MIN = { cron: "*/15 * * * *" } as ScheduledController
const WEEKLY = { cron: "12 7 * * 1" } as ScheduledController

const DAY = 24 * 60 * 60 * 1000

function ago(ms: number): string {
	return toDb(new Date(Date.now() - ms))
}

async function addSend(uuid: string, deletionDate: string, atype = 1): Promise<void> {
	await db.insert(sends).values({
		uuid,
		name: "n",
		atype,
		data: "{}",
		akey: "k",
		creationDate: deletionDate,
		revisionDate: deletionDate,
		deletionDate
	})
	if (atype === 1) await bucket.put(`sends/${uuid}/file`, "x")
}

async function addTrashedCipher(uuid: string, deletedAt: string, attachmentIds: string[]) {
	await db.insert(ciphers).values({
		uuid,
		createdAt: deletedAt,
		updatedAt: deletedAt,
		atype: 1,
		name: "n",
		data: "{}",
		deletedAt
	})
	for (const id of attachmentIds) {
		await db
			.insert(attachments)
			.values({ id, cipherUuid: uuid, fileName: "f", fileSize: 1, akey: "k" })
		await bucket.put(`attachments/${uuid}/${id}`, "x")
	}
}

// Wraps the real bucket and fails every call under one prefix.
function bucketFailingFor(prefix: string): R2Bucket {
	return {
		list: (o?: R2ListOptions) => {
			if (o?.prefix?.startsWith(prefix)) throw new Error("list failed")
			return bucket.list(o)
		},
		delete: (k: string | string[]) => bucket.delete(k)
	} as unknown as R2Bucket
}

function envWith(files: R2Bucket): Bindings {
	return Object.create(bindings, { VAULTUR_FILES: { value: files } }) as Bindings
}

async function sendUuids(): Promise<string[]> {
	return (await db.select({ uuid: sends.uuid }).from(sends)).map((s) => s.uuid)
}

describe("scheduled: expired sends", () => {
	beforeEach(async () => {
		await db.delete(sends)
		await db.delete(twofactorDuoCtx)
	})

	it("keeps going when one Send cleanup fails", async () => {
		await addSend("sched-a", ago(3 * DAY))
		await addSend("sched-bad", ago(2 * DAY))
		await addSend("sched-c", ago(DAY))
		await db.insert(twofactorDuoCtx).values({ state: "s", userEmail: "e", nonce: "n", exp: 1 })

		await runScheduledJobs(EVERY_15_MIN, envWith(bucketFailingFor("sends/sched-bad/")))

		expect(await sendUuids()).toEqual(["sched-bad"])
		expect((await bucket.list({ prefix: "sends/sched-a/" })).objects).toHaveLength(0)
		expect((await bucket.list({ prefix: "sends/sched-c/" })).objects).toHaveLength(0)
		// Cleanup after the Sends loop still ran.
		expect(await db.select().from(twofactorDuoCtx)).toHaveLength(0)

		// The next run retries the failed Send.
		await runScheduledJobs(EVERY_15_MIN, bindings)
		expect(await sendUuids()).toEqual([])
		expect((await bucket.list({ prefix: "sends/sched-bad/" })).objects).toHaveLength(0)
	})

	it("caps one run at the limit and the next run drains the rest", async () => {
		const total = MAX_PURGE_PER_RUN + 3
		for (let i = 0; i < total; i++) {
			// Oldest first: index 0 is the oldest.
			await addSend(`sched-lim-${String(i).padStart(3, "0")}`, ago((total - i + 1) * 60_000), 0)
		}

		await runScheduledJobs(EVERY_15_MIN, bindings)
		const left = await sendUuids()
		expect(left.sort()).toEqual(
			Array.from(
				{ length: 3 },
				(_, i) => `sched-lim-${String(MAX_PURGE_PER_RUN + i).padStart(3, "0")}`
			)
		)

		await runScheduledJobs(EVERY_15_MIN, bindings)
		expect(await sendUuids()).toEqual([])
	})
})

describe("scheduled: trash purge", () => {
	beforeEach(async () => {
		await db.delete(ciphers)
	})

	it("removes attachment blobs and rows, leaves recent trash alone", async () => {
		await addTrashedCipher("sched-old", ago(40 * DAY), ["a1", "a2"])
		await addTrashedCipher("sched-new", ago(DAY), ["b1"])

		await runScheduledJobs(WEEKLY, bindings)

		expect((await bucket.list({ prefix: "attachments/sched-old/" })).objects).toHaveLength(0)
		expect(
			await db.select().from(attachments).where(eq(attachments.cipherUuid, "sched-old"))
		).toEqual([])
		expect(await db.select().from(ciphers).where(eq(ciphers.uuid, "sched-old"))).toEqual([])
		expect((await bucket.list({ prefix: "attachments/sched-new/" })).objects).toHaveLength(1)
		expect(await db.select().from(ciphers).where(eq(ciphers.uuid, "sched-new"))).toHaveLength(1)
	})

	it("keeps a cipher whose blob cleanup fails and purges the others", async () => {
		await addTrashedCipher("sched-x", ago(50 * DAY), ["x1"])
		await addTrashedCipher("sched-bad", ago(45 * DAY), ["y1"])
		await addTrashedCipher("sched-z", ago(40 * DAY), ["z1"])

		await runScheduledJobs(WEEKLY, envWith(bucketFailingFor("attachments/sched-bad/")))

		const left = (await db.select({ uuid: ciphers.uuid }).from(ciphers)).map((c) => c.uuid)
		expect(left).toEqual(["sched-bad"])
		expect(
			await db.select().from(attachments).where(eq(attachments.cipherUuid, "sched-bad"))
		).toHaveLength(1)
		expect((await bucket.list({ prefix: "attachments/sched-z/" })).objects).toHaveLength(0)
	})

	it("caps one run at the limit and the next run drains the rest", async () => {
		const total = MAX_PURGE_PER_RUN + 2
		for (let i = 0; i < total; i++) {
			await addTrashedCipher(
				`sched-t-${String(i).padStart(3, "0")}`,
				ago((60 + total - i) * DAY),
				[]
			)
		}

		await runScheduledJobs(WEEKLY, bindings)
		expect(await db.select().from(ciphers)).toHaveLength(2)

		await runScheduledJobs(WEEKLY, bindings)
		expect(await db.select().from(ciphers)).toHaveLength(0)
	})
})
