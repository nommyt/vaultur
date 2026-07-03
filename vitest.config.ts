import { defineWorkersConfig, readD1Migrations } from "@cloudflare/vitest-pool-workers/config"
import { configDefaults } from "vitest/config"

export default defineWorkersConfig(async () => {
	const migrationsPath = new URL("./migrations", import.meta.url).pathname
	const migrations = await readD1Migrations(migrationsPath)

	return {
		test: {
			// Keep vitest's built-in excludes (node_modules, dist, …) — replacing
			// the array instead of extending it would make vitest scan node_modules.
			exclude: [...configDefaults.exclude, "test/heavy-compute.spec.ts"],
			// Pure-JS PBKDF2 (@noble/hashes, to bypass workerd's 100k native cap)
			// is slow at production iteration counts; give integration flows that
			// chain several logins room beyond the 5s default.
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
						r2Buckets: ["VAULTUR_FILES"],
						durableObjects: { VAULTUR_NOTIFICATIONS: "NotificationsHub" },
						bindings: {
							TEST_MIGRATIONS: migrations,
							JWT_SECRET: "vaultur-test-jwt-secret-vaultur-test-jwt-secret",
							ADMIN_TOKEN: "vaultur-test-admin-token",
							SIGNUPS_ALLOWED: "true",
							// Low server-side PBKDF2 rounds so the pure-JS hash stays fast in tests
							// (production defaults to 600k; the algorithm under test is identical).
							PASSWORD_ITERATIONS: "1000",
							// Exercise the free-to-enable features (production defaults them off,
							// matching vaultwarden).
							ORG_GROUPS_ENABLED: "true",
							ORG_EVENTS_ENABLED: "true",
							YUBICO_CLIENT_ID: "12345",
							YUBICO_SECRET_KEY: Buffer.from("yubico-test-secret").toString("base64"),
							DUO_IKEY: "DI_TEST_CLIENT_ID_XX",
							DUO_SKEY: "duo-test-client-secret-duo-test-client-secret",
							DUO_HOST: "api-test.duosecurity.com",
							SSO_ENABLED: "true",
							SSO_AUTHORITY: "https://idp.test",
							SSO_CLIENT_ID: "vaultur-client",
							SSO_CLIENT_SECRET: "vaultur-oidc-secret"
						}
					}
				}
			}
		}
	}
})
