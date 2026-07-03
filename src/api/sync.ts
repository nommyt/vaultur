import { Hono } from "hono"

import { requireAuth, auth } from "../auth/middleware"
import type { AppEnv } from "../env"
import {
	cipherToJson,
	collectionToJsonDetails,
	findCiphersVisibleToUser,
	findCollectionsForUser,
	findFoldersByUser,
	findPoliciesForUser,
	findSendsByUser,
	folderToJson,
	loadCipherSyncData,
	policyToJson,
	profileJson,
	sendToJson
} from "../services/vault"
import { eqDomainsJson } from "./domains"

export const syncRoutes = new Hono<AppEnv>()

syncRoutes.use("*", requireAuth)

syncRoutes.get("/sync", async (c) => {
	const { user } = auth(c)
	const db = c.get("db")
	const config = c.get("config")
	const excludeDomains = c.req.query("excludeDomains") === "true"

	const sync = await loadCipherSyncData(db, user.uuid, "user")

	let ciphers = await findCiphersVisibleToUser(db, user.uuid, sync)

	// Hide SSH keys from clients older than 2024.12.0 (they crash on unknown types)
	const clientVersion = c.req.header("Bitwarden-Client-Version")
	const showSshKeys = clientVersion ? gteVersion(clientVersion, [2024, 12, 0]) : false
	if (!showSshKeys) ciphers = ciphers.filter((ci) => ci.atype !== 5)

	const opts = {
		config,
		secret: c.env.JWT_SECRET,
		userUuid: user.uuid,
		sync,
		syncType: "user" as const
	}
	const ciphersJson = await Promise.all(ciphers.map((ci) => cipherToJson(ci, opts)))

	const collections = await findCollectionsForUser(db, user.uuid, sync)
	const collectionsJson = collections.map((col) => collectionToJsonDetails(col, user.uuid, sync))

	const foldersJson = (await findFoldersByUser(db, user.uuid)).map(folderToJson)
	const sendsJson = (await findSendsByUser(db, user.uuid)).map(sendToJson)
	const policiesJson = (await findPoliciesForUser(db, user.uuid)).map(policyToJson)

	const domainsJson = excludeDomains ? null : eqDomainsJson(user, true)

	const hasMasterPassword = user.passwordHash !== ""
	const masterPasswordUnlock = hasMasterPassword
		? {
				kdf: {
					kdfType: user.clientKdfType,
					iterations: user.clientKdfIter,
					memory: user.clientKdfMemory,
					parallelism: user.clientKdfParallelism
				},
				masterKeyEncryptedUserKey: user.akey,
				masterKeyWrappedUserKey: user.akey,
				salt: user.email
			}
		: null

	return c.json({
		profile: await profileJson(db, user, c.get("config").emailEnabled),
		folders: foldersJson,
		collections: collectionsJson,
		policies: policiesJson,
		ciphers: ciphersJson,
		domains: domainsJson,
		sends: sendsJson,
		userDecryption: { masterPasswordUnlock },
		object: "sync"
	})
})

function gteVersion(version: string, [maj, min, pat]: [number, number, number]): boolean {
	const [a = 0, b = 0, cNum = 0] = version.split(".").map((p) => Number.parseInt(p, 10) || 0)
	if (a !== maj) return a > maj
	if (b !== min) return b > min
	return cNum >= pat
}
