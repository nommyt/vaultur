import { defineWorkersConfig, readD1Migrations } from "@cloudflare/vitest-pool-workers/config"

export default defineWorkersConfig(async () => {
	const migrationsPath = new URL("./migrations", import.meta.url).pathname
	const migrations = await readD1Migrations(migrationsPath)

	return {
		test: {
			include: ["test/heavy-compute.spec.ts"],
			setupFiles: ["./test/apply-migrations.ts"],
			poolOptions: {
				workers: {
					singleWorker: true,
					// HeavyCompute is a stateless DO (no ctx.storage). Per-test isolated
					// storage adds nothing here, and its SQLite-backed DO snapshot/restore
					// trips an assertion on the .sqlite-shm WAL file when popping the stack
					// frame after the suite (vitest-pool-workers isolated-storage known
					// issue). Disable it — tests share one unisolated storage.
					isolatedStorage: false,
					main: "./src/index.ts",
					miniflare: {
						compatibilityDate: "2025-09-06",
						compatibilityFlags: ["nodejs_compat"],
						d1Databases: ["VAULTUR_DB"],
						kvNamespaces: ["VAULTUR_KV"],
						r2Buckets: ["VAULTUR_FILES"],
						durableObjects: {
							VAULTUR_NOTIFICATIONS: "NotificationsHub",
							VAULTUR_HEAVY: "HeavyCompute"
						},
						bindings: {
							TEST_MIGRATIONS: migrations,
							JWT_SECRET: "vaultur-test-jwt-secret-vaultur-test-jwt-secret",
							ADMIN_TOKEN: "vaultur-test-admin-token",
							SIGNUPS_ALLOWED: "true"
						}
					}
				}
			}
		}
	}
})
