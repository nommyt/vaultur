import { defineWorkersConfig, readD1Migrations } from "@cloudflare/vitest-pool-workers/config"

// Proves the free-tier fallback path: no r2Buckets binding, so getBlobStore()
// (src/services/storage.ts) selects KvBlobStore. Runs the same attachments/
// sends specs as the main suite — separate config only because bindings are
// fixed per miniflare instance, so R2-bound and R2-unbound runs can't share one.
export default defineWorkersConfig(async () => {
	const migrationsPath = new URL("./migrations", import.meta.url).pathname
	const migrations = await readD1Migrations(migrationsPath)

	return {
		test: {
			include: ["test/attachments.spec.ts", "test/sends.spec.ts"],
			testTimeout: 30_000,
			setupFiles: ["./test/apply-migrations.ts"],
			poolOptions: {
				workers: {
					singleWorker: true,
					main: "./src/index.ts",
					miniflare: {
						compatibilityDate: "2025-09-06",
						compatibilityFlags: ["nodejs_compat"],
						d1Databases: ["VAULTUR_DB"],
						kvNamespaces: ["VAULTUR_KV"],
						durableObjects: { VAULTUR_NOTIFICATIONS: "NotificationsHub" },
						bindings: {
							TEST_MIGRATIONS: migrations,
							JWT_SECRET: "vaultur-test-jwt-secret-vaultur-test-jwt-secret",
							ADMIN_TOKEN: "vaultur-test-admin-token",
							SIGNUPS_ALLOWED: "true",
							PASSWORD_ITERATIONS: "1000"
						}
					}
				}
			}
		}
	}
})
