/**
 * Vaultur D1 schema — a 1:1 port of vaultwarden's SQLite schema (src/db/schema.rs).
 *
 * Table and column names match vaultwarden exactly so that data migration from a
 * vaultwarden SQLite dump is a mechanical copy (binary password hash/salt columns
 * are stored base64-encoded here; everything else is identical).
 *
 * Timestamps are TEXT in vaultwarden's NaiveDateTime format: `YYYY-MM-DD HH:MM:SS.SSSSSS` (UTC).
 * Use the helpers in `./datetime.ts`.
 */
import { index, integer, primaryKey, sqliteTable, text } from 'drizzle-orm/sqlite-core';

const bool = (name: string) => integer(name, { mode: 'boolean' });

// ---------------------------------------------------------------------------
// Users & auth
// ---------------------------------------------------------------------------

export const users = sqliteTable('users', {
  uuid: text('uuid').primaryKey(),
  enabled: bool('enabled').notNull().default(true),
  createdAt: text('created_at').notNull(),
  updatedAt: text('updated_at').notNull(),
  verifiedAt: text('verified_at'),
  lastVerifyingAt: text('last_verifying_at'),
  loginVerifyCount: integer('login_verify_count').notNull().default(0),
  email: text('email').notNull().unique(),
  emailNew: text('email_new'),
  emailNewToken: text('email_new_token'),
  name: text('name').notNull(),
  /** base64(PBKDF2-HMAC-SHA256(client master password hash, salt, passwordIterations)) */
  passwordHash: text('password_hash').notNull(),
  /** base64 random salt for the server-side hash */
  salt: text('salt').notNull(),
  passwordIterations: integer('password_iterations').notNull(),
  passwordHint: text('password_hint'),
  /** protected symmetric key (EncString) */
  akey: text('akey').notNull(),
  privateKey: text('private_key'),
  publicKey: text('public_key'),
  totpSecret: text('totp_secret'),
  totpRecover: text('totp_recover'),
  securityStamp: text('security_stamp').notNull(),
  stampException: text('stamp_exception'),
  equivalentDomains: text('equivalent_domains').notNull().default('[]'),
  excludedGlobals: text('excluded_globals').notNull().default('[]'),
  clientKdfType: integer('client_kdf_type').notNull().default(0),
  clientKdfIter: integer('client_kdf_iter').notNull().default(600000),
  clientKdfMemory: integer('client_kdf_memory'),
  clientKdfParallelism: integer('client_kdf_parallelism'),
  apiKey: text('api_key'),
  avatarColor: text('avatar_color'),
  externalId: text('external_id'),
});

export const devices = sqliteTable(
  'devices',
  {
    uuid: text('uuid').notNull(),
    createdAt: text('created_at').notNull(),
    updatedAt: text('updated_at').notNull(),
    userUuid: text('user_uuid')
      .notNull()
      .references(() => users.uuid, { onDelete: 'cascade' }),
    name: text('name').notNull(),
    atype: integer('atype').notNull(),
    pushUuid: text('push_uuid'),
    pushToken: text('push_token'),
    refreshToken: text('refresh_token').notNull(),
    twofactorRemember: text('twofactor_remember'),
  },
  (t) => [
    primaryKey({ columns: [t.uuid, t.userUuid] }),
    index('idx_devices_user_uuid').on(t.userUuid),
    index('idx_devices_refresh_token').on(t.refreshToken),
  ],
);

export const twofactor = sqliteTable(
  'twofactor',
  {
    uuid: text('uuid').primaryKey(),
    userUuid: text('user_uuid')
      .notNull()
      .references(() => users.uuid, { onDelete: 'cascade' }),
    atype: integer('atype').notNull(),
    enabled: bool('enabled').notNull(),
    data: text('data').notNull(),
    lastUsed: integer('last_used').notNull().default(0),
  },
  (t) => [index('idx_twofactor_user_uuid').on(t.userUuid)],
);

export const twofactorIncomplete = sqliteTable(
  'twofactor_incomplete',
  {
    userUuid: text('user_uuid')
      .notNull()
      .references(() => users.uuid, { onDelete: 'cascade' }),
    deviceUuid: text('device_uuid').notNull(),
    deviceName: text('device_name').notNull(),
    deviceType: integer('device_type').notNull(),
    loginTime: text('login_time').notNull(),
    ipAddress: text('ip_address').notNull(),
  },
  (t) => [primaryKey({ columns: [t.userUuid, t.deviceUuid] })],
);

export const twofactorDuoCtx = sqliteTable('twofactor_duo_ctx', {
  state: text('state').primaryKey(),
  userEmail: text('user_email').notNull(),
  nonce: text('nonce').notNull(),
  exp: integer('exp').notNull(),
});

export const invitations = sqliteTable('invitations', {
  email: text('email').primaryKey(),
});

export const authRequests = sqliteTable(
  'auth_requests',
  {
    uuid: text('uuid').primaryKey(),
    userUuid: text('user_uuid')
      .notNull()
      .references(() => users.uuid, { onDelete: 'cascade' }),
    organizationUuid: text('organization_uuid'),
    requestDeviceIdentifier: text('request_device_identifier').notNull(),
    deviceType: integer('device_type').notNull(),
    requestIp: text('request_ip').notNull(),
    responseDeviceId: text('response_device_id'),
    accessCode: text('access_code').notNull(),
    publicKey: text('public_key').notNull(),
    encKey: text('enc_key'),
    masterPasswordHash: text('master_password_hash'),
    approved: bool('approved'),
    creationDate: text('creation_date').notNull(),
    responseDate: text('response_date'),
    authenticationDate: text('authentication_date'),
  },
  (t) => [index('idx_auth_requests_user_uuid').on(t.userUuid)],
);

// ---------------------------------------------------------------------------
// Vault data
// ---------------------------------------------------------------------------

export const ciphers = sqliteTable(
  'ciphers',
  {
    uuid: text('uuid').primaryKey(),
    createdAt: text('created_at').notNull(),
    updatedAt: text('updated_at').notNull(),
    userUuid: text('user_uuid').references(() => users.uuid, { onDelete: 'cascade' }),
    organizationUuid: text('organization_uuid'),
    /** per-cipher key (EncString), aka "cipher key encryption" */
    key: text('key'),
    atype: integer('atype').notNull(),
    name: text('name').notNull(),
    notes: text('notes'),
    fields: text('fields'),
    data: text('data').notNull(),
    passwordHistory: text('password_history'),
    deletedAt: text('deleted_at'),
    reprompt: integer('reprompt'),
  },
  (t) => [
    index('idx_ciphers_user_uuid').on(t.userUuid),
    index('idx_ciphers_organization_uuid').on(t.organizationUuid),
  ],
);

export const folders = sqliteTable(
  'folders',
  {
    uuid: text('uuid').primaryKey(),
    createdAt: text('created_at').notNull(),
    updatedAt: text('updated_at').notNull(),
    userUuid: text('user_uuid')
      .notNull()
      .references(() => users.uuid, { onDelete: 'cascade' }),
    name: text('name').notNull(),
  },
  (t) => [index('idx_folders_user_uuid').on(t.userUuid)],
);

export const foldersCiphers = sqliteTable(
  'folders_ciphers',
  {
    cipherUuid: text('cipher_uuid')
      .notNull()
      .references(() => ciphers.uuid, { onDelete: 'cascade' }),
    folderUuid: text('folder_uuid')
      .notNull()
      .references(() => folders.uuid, { onDelete: 'cascade' }),
  },
  (t) => [primaryKey({ columns: [t.cipherUuid, t.folderUuid] })],
);

export const favorites = sqliteTable(
  'favorites',
  {
    userUuid: text('user_uuid')
      .notNull()
      .references(() => users.uuid, { onDelete: 'cascade' }),
    cipherUuid: text('cipher_uuid')
      .notNull()
      .references(() => ciphers.uuid, { onDelete: 'cascade' }),
  },
  (t) => [primaryKey({ columns: [t.userUuid, t.cipherUuid] })],
);

export const archives = sqliteTable(
  'archives',
  {
    userUuid: text('user_uuid')
      .notNull()
      .references(() => users.uuid, { onDelete: 'cascade' }),
    cipherUuid: text('cipher_uuid')
      .notNull()
      .references(() => ciphers.uuid, { onDelete: 'cascade' }),
    archivedAt: text('archived_at').notNull(),
  },
  (t) => [primaryKey({ columns: [t.userUuid, t.cipherUuid] })],
);

export const attachments = sqliteTable(
  'attachments',
  {
    id: text('id').primaryKey(),
    cipherUuid: text('cipher_uuid')
      .notNull()
      .references(() => ciphers.uuid, { onDelete: 'cascade' }),
    fileName: text('file_name').notNull(),
    fileSize: integer('file_size').notNull(),
    akey: text('akey'),
  },
  (t) => [index('idx_attachments_cipher_uuid').on(t.cipherUuid)],
);

export const sends = sqliteTable(
  'sends',
  {
    uuid: text('uuid').primaryKey(),
    userUuid: text('user_uuid').references(() => users.uuid, { onDelete: 'cascade' }),
    organizationUuid: text('organization_uuid'),
    name: text('name').notNull(),
    notes: text('notes'),
    atype: integer('atype').notNull(),
    data: text('data').notNull(),
    akey: text('akey').notNull(),
    /** base64 — vaultwarden stores raw bytes */
    passwordHash: text('password_hash'),
    passwordSalt: text('password_salt'),
    passwordIter: integer('password_iter'),
    maxAccessCount: integer('max_access_count'),
    accessCount: integer('access_count').notNull().default(0),
    creationDate: text('creation_date').notNull(),
    revisionDate: text('revision_date').notNull(),
    expirationDate: text('expiration_date'),
    deletionDate: text('deletion_date').notNull(),
    disabled: bool('disabled').notNull().default(false),
    hideEmail: bool('hide_email'),
  },
  (t) => [
    index('idx_sends_user_uuid').on(t.userUuid),
    index('idx_sends_deletion_date').on(t.deletionDate),
  ],
);

// ---------------------------------------------------------------------------
// Organizations
// ---------------------------------------------------------------------------

export const organizations = sqliteTable('organizations', {
  uuid: text('uuid').primaryKey(),
  name: text('name').notNull(),
  billingEmail: text('billing_email').notNull(),
  privateKey: text('private_key'),
  publicKey: text('public_key'),
});

export const usersOrganizations = sqliteTable(
  'users_organizations',
  {
    uuid: text('uuid').primaryKey(),
    userUuid: text('user_uuid')
      .notNull()
      .references(() => users.uuid, { onDelete: 'cascade' }),
    orgUuid: text('org_uuid')
      .notNull()
      .references(() => organizations.uuid, { onDelete: 'cascade' }),
    invitedByEmail: text('invited_by_email'),
    accessAll: bool('access_all').notNull().default(false),
    akey: text('akey').notNull(),
    status: integer('status').notNull(),
    atype: integer('atype').notNull(),
    resetPasswordKey: text('reset_password_key'),
    externalId: text('external_id'),
  },
  (t) => [
    index('idx_users_organizations_user_uuid').on(t.userUuid),
    index('idx_users_organizations_org_uuid').on(t.orgUuid),
  ],
);

export const organizationApiKey = sqliteTable(
  'organization_api_key',
  {
    uuid: text('uuid').notNull(),
    orgUuid: text('org_uuid')
      .notNull()
      .references(() => organizations.uuid, { onDelete: 'cascade' }),
    atype: integer('atype').notNull(),
    apiKey: text('api_key').notNull(),
    revisionDate: text('revision_date').notNull(),
  },
  (t) => [primaryKey({ columns: [t.uuid, t.orgUuid] })],
);

export const collections = sqliteTable(
  'collections',
  {
    uuid: text('uuid').primaryKey(),
    orgUuid: text('org_uuid')
      .notNull()
      .references(() => organizations.uuid, { onDelete: 'cascade' }),
    name: text('name').notNull(),
    externalId: text('external_id'),
  },
  (t) => [index('idx_collections_org_uuid').on(t.orgUuid)],
);

export const usersCollections = sqliteTable(
  'users_collections',
  {
    userUuid: text('user_uuid')
      .notNull()
      .references(() => users.uuid, { onDelete: 'cascade' }),
    collectionUuid: text('collection_uuid')
      .notNull()
      .references(() => collections.uuid, { onDelete: 'cascade' }),
    readOnly: bool('read_only').notNull().default(false),
    hidePasswords: bool('hide_passwords').notNull().default(false),
    manage: bool('manage').notNull().default(false),
  },
  (t) => [primaryKey({ columns: [t.userUuid, t.collectionUuid] })],
);

export const ciphersCollections = sqliteTable(
  'ciphers_collections',
  {
    cipherUuid: text('cipher_uuid')
      .notNull()
      .references(() => ciphers.uuid, { onDelete: 'cascade' }),
    collectionUuid: text('collection_uuid')
      .notNull()
      .references(() => collections.uuid, { onDelete: 'cascade' }),
  },
  (t) => [primaryKey({ columns: [t.cipherUuid, t.collectionUuid] })],
);

export const orgPolicies = sqliteTable(
  'org_policies',
  {
    uuid: text('uuid').primaryKey(),
    orgUuid: text('org_uuid')
      .notNull()
      .references(() => organizations.uuid, { onDelete: 'cascade' }),
    atype: integer('atype').notNull(),
    enabled: bool('enabled').notNull(),
    data: text('data').notNull(),
  },
  (t) => [index('idx_org_policies_org_uuid').on(t.orgUuid)],
);

export const groups = sqliteTable(
  'groups',
  {
    uuid: text('uuid').primaryKey(),
    organizationsUuid: text('organizations_uuid')
      .notNull()
      .references(() => organizations.uuid, { onDelete: 'cascade' }),
    name: text('name').notNull(),
    accessAll: bool('access_all').notNull().default(false),
    externalId: text('external_id'),
    creationDate: text('creation_date').notNull(),
    revisionDate: text('revision_date').notNull(),
  },
  (t) => [index('idx_groups_organizations_uuid').on(t.organizationsUuid)],
);

export const groupsUsers = sqliteTable(
  'groups_users',
  {
    groupsUuid: text('groups_uuid')
      .notNull()
      .references(() => groups.uuid, { onDelete: 'cascade' }),
    usersOrganizationsUuid: text('users_organizations_uuid')
      .notNull()
      .references(() => usersOrganizations.uuid, { onDelete: 'cascade' }),
  },
  (t) => [primaryKey({ columns: [t.groupsUuid, t.usersOrganizationsUuid] })],
);

export const collectionsGroups = sqliteTable(
  'collections_groups',
  {
    collectionsUuid: text('collections_uuid')
      .notNull()
      .references(() => collections.uuid, { onDelete: 'cascade' }),
    groupsUuid: text('groups_uuid')
      .notNull()
      .references(() => groups.uuid, { onDelete: 'cascade' }),
    readOnly: bool('read_only').notNull().default(false),
    hidePasswords: bool('hide_passwords').notNull().default(false),
    manage: bool('manage').notNull().default(false),
  },
  (t) => [primaryKey({ columns: [t.collectionsUuid, t.groupsUuid] })],
);

// ---------------------------------------------------------------------------
// Emergency access, events, SSO
// ---------------------------------------------------------------------------

export const emergencyAccess = sqliteTable(
  'emergency_access',
  {
    uuid: text('uuid').primaryKey(),
    grantorUuid: text('grantor_uuid')
      .notNull()
      .references(() => users.uuid, { onDelete: 'cascade' }),
    granteeUuid: text('grantee_uuid').references(() => users.uuid, { onDelete: 'cascade' }),
    email: text('email'),
    keyEncrypted: text('key_encrypted'),
    atype: integer('atype').notNull(),
    status: integer('status').notNull(),
    waitTimeDays: integer('wait_time_days').notNull(),
    recoveryInitiatedAt: text('recovery_initiated_at'),
    lastNotificationAt: text('last_notification_at'),
    updatedAt: text('updated_at').notNull(),
    createdAt: text('created_at').notNull(),
  },
  (t) => [
    index('idx_emergency_access_grantor_uuid').on(t.grantorUuid),
    index('idx_emergency_access_grantee_uuid').on(t.granteeUuid),
  ],
);

export const event = sqliteTable(
  'event',
  {
    uuid: text('uuid').primaryKey(),
    eventType: integer('event_type').notNull(),
    userUuid: text('user_uuid'),
    orgUuid: text('org_uuid'),
    cipherUuid: text('cipher_uuid'),
    collectionUuid: text('collection_uuid'),
    groupUuid: text('group_uuid'),
    orgUserUuid: text('org_user_uuid'),
    actUserUuid: text('act_user_uuid'),
    deviceType: integer('device_type'),
    ipAddress: text('ip_address'),
    eventDate: text('event_date').notNull(),
    policyUuid: text('policy_uuid'),
    providerUuid: text('provider_uuid'),
    providerUserUuid: text('provider_user_uuid'),
    providerOrgUuid: text('provider_org_uuid'),
  },
  (t) => [
    index('idx_event_org_uuid_event_date').on(t.orgUuid, t.eventDate),
    index('idx_event_user_uuid_event_date').on(t.userUuid, t.eventDate),
  ],
);

export const ssoAuth = sqliteTable('sso_auth', {
  state: text('state').primaryKey(),
  clientChallenge: text('client_challenge').notNull(),
  nonce: text('nonce').notNull(),
  redirectUri: text('redirect_uri').notNull(),
  codeResponse: text('code_response'),
  codeResponseError: text('code_response_error'),
  authResponse: text('auth_response'),
  createdAt: text('created_at').notNull(),
  updatedAt: text('updated_at').notNull(),
  bindingHash: text('binding_hash'),
});

export const ssoUsers = sqliteTable('sso_users', {
  userUuid: text('user_uuid')
    .primaryKey()
    .references(() => users.uuid, { onDelete: 'cascade' }),
  identifier: text('identifier').notNull(),
});
