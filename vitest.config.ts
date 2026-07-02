import { defineWorkersConfig, readD1Migrations } from '@cloudflare/vitest-pool-workers/config';

export default defineWorkersConfig(async () => {
  const migrationsPath = new URL('./migrations', import.meta.url).pathname;
  const migrations = await readD1Migrations(migrationsPath);

  return {
    test: {
      setupFiles: ['./test/apply-migrations.ts'],
      poolOptions: {
        workers: {
          singleWorker: true,
          main: './src/index.ts',
          miniflare: {
            compatibilityDate: '2025-09-06',
            compatibilityFlags: ['nodejs_compat'],
            d1Databases: ['DB'],
            kvNamespaces: ['KV'],
            r2Buckets: ['FILES'],
            durableObjects: { NOTIFICATIONS: 'NotificationsHub' },
            bindings: {
              TEST_MIGRATIONS: migrations,
              JWT_SECRET: 'vaultur-test-jwt-secret-vaultur-test-jwt-secret',
              ADMIN_TOKEN: 'vaultur-test-admin-token',
              SIGNUPS_ALLOWED: 'true',
            },
          },
        },
      },
    },
  };
});
