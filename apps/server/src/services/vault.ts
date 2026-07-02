import { and, eq, inArray, isNull, or } from 'drizzle-orm';
import {
  archives,
  attachments,
  ciphers,
  ciphersCollections,
  collections,
  collectionsGroups,
  favorites,
  folders,
  foldersCiphers,
  groupsUsers,
  organizations,
  orgPolicies,
  sends,
  twofactor,
  usersCollections,
  usersOrganizations,
  toApi,
  type Attachment,
  type Cipher,
  type Collection,
  type Db,
  type Folder,
  type Membership,
  type OrgPolicy,
  type Send,
  type User,
} from '@vaultur/db';
import { CipherType, MembershipStatus, MembershipType, OrgPolicyType, SendType } from '@vaultur/shared';
import type { Config } from '../config';
import { basicClaims, encodeJwt } from '../auth/jwt';
import { b64UrlEncode } from '../util';
import { hasFullAccess, isAtLeast } from './memberships';

// ---------------------------------------------------------------------------
// Batched sync data (vaultwarden CipherSyncData)
// ---------------------------------------------------------------------------

export interface CipherSyncData {
  cipherFolders: Map<string, string>;
  cipherFavorites: Set<string>;
  cipherArchives: Map<string, string>;
  cipherAttachments: Map<string, Attachment[]>;
  cipherCollections: Map<string, string[]>;
  members: Map<string, Membership>;
  userCollections: Map<string, { readOnly: boolean; hidePasswords: boolean; manage: boolean }>;
  userCollectionsGroups: Map<string, { readOnly: boolean; hidePasswords: boolean; manage: boolean }>;
}

export type CipherSyncType = 'user' | 'org';

export async function loadCipherSyncData(
  db: Db,
  userUuid: string,
  syncType: CipherSyncType,
  orgUuid?: string,
): Promise<CipherSyncData> {
  const data: CipherSyncData = {
    cipherFolders: new Map(),
    cipherFavorites: new Set(),
    cipherArchives: new Map(),
    cipherAttachments: new Map(),
    cipherCollections: new Map(),
    members: new Map(),
    userCollections: new Map(),
    userCollectionsGroups: new Map(),
  };

  if (syncType === 'user') {
    const folderRows = await db
      .select({ cipherUuid: foldersCiphers.cipherUuid, folderUuid: foldersCiphers.folderUuid })
      .from(foldersCiphers)
      .innerJoin(folders, eq(foldersCiphers.folderUuid, folders.uuid))
      .where(eq(folders.userUuid, userUuid));
    for (const r of folderRows) data.cipherFolders.set(r.cipherUuid, r.folderUuid);

    const favRows = await db.select().from(favorites).where(eq(favorites.userUuid, userUuid));
    for (const r of favRows) data.cipherFavorites.add(r.cipherUuid);

    const archRows = await db.select().from(archives).where(eq(archives.userUuid, userUuid));
    for (const r of archRows) data.cipherArchives.set(r.cipherUuid, r.archivedAt);
  }

  // Attachments for all ciphers the user can see; loaded broadly and filtered on use.
  const attRows =
    syncType === 'user'
      ? await db
          .select({ att: attachments })
          .from(attachments)
          .innerJoin(ciphers, eq(attachments.cipherUuid, ciphers.uuid))
          .where(eq(ciphers.userUuid, userUuid))
      : [];
  for (const { att } of attRows) {
    const list = data.cipherAttachments.get(att.cipherUuid) ?? [];
    list.push(att);
    data.cipherAttachments.set(att.cipherUuid, list);
  }

  const membershipRows = await db.query.usersOrganizations.findMany({
    where: and(eq(usersOrganizations.userUuid, userUuid), eq(usersOrganizations.status, MembershipStatus.Confirmed)),
  });
  for (const m of membershipRows) data.members.set(m.orgUuid, m);

  const orgIds = orgUuid ? [orgUuid] : membershipRows.map((m) => m.orgUuid);
  if (orgIds.length > 0) {
    // Org attachments
    const orgAttRows = await db
      .select({ att: attachments })
      .from(attachments)
      .innerJoin(ciphers, eq(attachments.cipherUuid, ciphers.uuid))
      .where(inArray(ciphers.organizationUuid, orgIds));
    for (const { att } of orgAttRows) {
      const list = data.cipherAttachments.get(att.cipherUuid) ?? [];
      list.push(att);
      data.cipherAttachments.set(att.cipherUuid, list);
    }

    // Cipher → collection ids
    const ccRows = await db
      .select({ cipherUuid: ciphersCollections.cipherUuid, collectionUuid: ciphersCollections.collectionUuid })
      .from(ciphersCollections)
      .innerJoin(collections, eq(ciphersCollections.collectionUuid, collections.uuid))
      .where(inArray(collections.orgUuid, orgIds));
    for (const r of ccRows) {
      const list = data.cipherCollections.get(r.cipherUuid) ?? [];
      list.push(r.collectionUuid);
      data.cipherCollections.set(r.cipherUuid, list);
    }

    // Direct per-user collection access
    const ucRows = await db.select().from(usersCollections).where(eq(usersCollections.userUuid, userUuid));
    for (const r of ucRows) {
      data.userCollections.set(r.collectionUuid, {
        readOnly: r.readOnly,
        hidePasswords: r.hidePasswords,
        manage: r.manage,
      });
    }

    // Group-based collection access
    const memberUuids = membershipRows.map((m) => m.uuid);
    if (memberUuids.length > 0) {
      const cgRows = await db
        .select({
          collectionUuid: collectionsGroups.collectionsUuid,
          readOnly: collectionsGroups.readOnly,
          hidePasswords: collectionsGroups.hidePasswords,
          manage: collectionsGroups.manage,
        })
        .from(collectionsGroups)
        .innerJoin(groupsUsers, eq(collectionsGroups.groupsUuid, groupsUsers.groupsUuid))
        .where(inArray(groupsUsers.usersOrganizationsUuid, memberUuids));
      for (const r of cgRows) {
        const existing = data.userCollectionsGroups.get(r.collectionUuid);
        // Merge multiple group rows with the most permissive access (vaultwarden semantics)
        data.userCollectionsGroups.set(r.collectionUuid, {
          readOnly: existing ? existing.readOnly && r.readOnly : r.readOnly,
          hidePasswords: existing ? existing.hidePasswords && r.hidePasswords : r.hidePasswords,
          manage: existing ? existing.manage || r.manage : r.manage,
        });
      }
    }
  }

  return data;
}

// ---------------------------------------------------------------------------
// Access restrictions
// ---------------------------------------------------------------------------

export interface AccessRestrictions {
  readOnly: boolean;
  hidePasswords: boolean;
  manage: boolean;
}

export function getAccessRestrictions(
  cipher: Cipher,
  userUuid: string,
  sync: CipherSyncData,
): AccessRestrictions | null {
  if (cipher.userUuid === userUuid) return { readOnly: false, hidePasswords: false, manage: true };
  if (!cipher.organizationUuid) return null;

  const member = sync.members.get(cipher.organizationUuid);
  if (!member) return null;
  if (hasFullAccess(member)) return { readOnly: false, hidePasswords: false, manage: true };

  const collectionIds = sync.cipherCollections.get(cipher.uuid) ?? [];
  let found = false;
  const agg = { readOnly: true, hidePasswords: true, manage: false };
  for (const cid of collectionIds) {
    for (const source of [sync.userCollections.get(cid), sync.userCollectionsGroups.get(cid)]) {
      if (!source) continue;
      found = true;
      agg.readOnly &&= source.readOnly;
      agg.hidePasswords &&= source.hidePasswords;
      agg.manage ||= source.manage;
    }
  }
  return found ? agg : null;
}

export function isWriteAccessible(cipher: Cipher, userUuid: string, sync: CipherSyncData): boolean {
  const access = getAccessRestrictions(cipher, userUuid, sync);
  return access != null && !access.readOnly;
}

// ---------------------------------------------------------------------------
// Serializers (vaultwarden to_json ports)
// ---------------------------------------------------------------------------

const EPOCH = '1970-01-01T00:00:00.000000Z';

function validateAndFormatDate(value: unknown): string {
  if (typeof value === 'string') {
    const d = new Date(value);
    if (Number.isFinite(d.getTime())) return d.toISOString();
  }
  return EPOCH;
}

type JsonMap = Record<string, unknown>;

function parseObject(value: string | null | undefined): JsonMap {
  if (!value) return {};
  try {
    const parsed = JSON.parse(value) as unknown;
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? (parsed as JsonMap) : {};
  } catch {
    return {};
  }
}

function parseArray(value: string | null | undefined): JsonMap[] {
  if (!value) return [];
  try {
    const parsed = JSON.parse(value) as unknown;
    return Array.isArray(parsed) ? (parsed.filter((v) => v && typeof v === 'object') as JsonMap[]) : [];
  } catch {
    return [];
  }
}

export async function attachmentToJson(config: Config, secret: string, att: Attachment): Promise<JsonMap> {
  const token = await encodeJwt(
    secret,
    basicClaims({
      domain: config.domain,
      kind: 'file_download',
      sub: att.cipherUuid,
      ttlSeconds: 5 * 60,
      extra: { file_id: att.id },
    }),
  );
  return {
    id: att.id,
    url: `${config.domain}/attachments/${att.cipherUuid}/${att.id}?token=${token}`,
    fileName: att.fileName,
    size: String(att.fileSize),
    sizeName: displaySize(att.fileSize),
    key: att.akey,
    object: 'attachment',
  };
}

export function displaySize(size: number): string {
  const units = ['bytes', 'KB', 'MB', 'GB', 'TB'];
  let value = size;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i++;
  }
  return `${i === 0 ? value : value.toFixed(2)} ${units[i]}`;
}

export interface CipherJsonOptions {
  config: Config;
  secret: string;
  userUuid: string;
  sync: CipherSyncData;
  syncType: CipherSyncType;
}

export async function cipherToJson(cipher: Cipher, opts: CipherJsonOptions): Promise<JsonMap> {
  const { config, secret, userUuid, sync, syncType } = opts;

  const attList = sync.cipherAttachments.get(cipher.uuid) ?? [];
  const attachmentsJson =
    attList.length > 0 ? await Promise.all(attList.map((a) => attachmentToJson(config, secret, a))) : null;

  let readOnly = false;
  let hidePasswords = false;
  if (syncType === 'user') {
    const access = getAccessRestrictions(cipher, userUuid, sync);
    if (access) {
      readOnly = access.readOnly;
      hidePasswords = access.hidePasswords;
    } else {
      console.error('Cipher ownership assertion failure');
      readOnly = true;
      hidePasswords = true;
    }
  }

  // fields: force numeric `type` (fallback hidden=1)
  const fieldsJson = parseArray(cipher.fields).map((f) => {
    const t = f.type;
    if (typeof t !== 'number') {
      const parsed = typeof t === 'string' ? Number.parseInt(t, 10) : NaN;
      f.type = Number.isFinite(parsed) ? parsed : 1;
    }
    return f;
  });

  // password history: drop invalid entries, normalize lastUsedDate
  const passwordHistoryJson = parseArray(cipher.passwordHistory)
    .filter((d) => typeof d.password === 'string')
    .map((d) => ({ ...d, lastUsedDate: validateAndFormatDate(d.lastUsedDate) }));

  // type-specific data
  let typeData: JsonMap | null = parseObject(cipher.data);

  if (cipher.atype === CipherType.Login) {
    typeData.uri = null;
    const uris = typeData.uris;
    if (Array.isArray(uris) && uris.length > 0) {
      for (const uri of uris as JsonMap[]) {
        if (typeof uri.match === 'string') {
          const n = Number.parseInt(uri.match, 10);
          uri.match = Number.isFinite(n) ? n : null;
        }
      }
      typeData.uri = (uris[0] as JsonMap).uri ?? null;
    }
    if (typeof typeData.passwordRevisionDate === 'string') {
      typeData.passwordRevisionDate = validateAndFormatDate(typeData.passwordRevisionDate);
    }
  }

  if (cipher.atype === CipherType.SecureNote) {
    if (typeof typeData.type !== 'number') typeData = { type: 0 };
  }

  if (cipher.atype === CipherType.SshKey) {
    const required = ['keyFingerprint', 'privateKey', 'publicKey'];
    if (required.some((k) => typeof typeData?.[k] !== 'string' || typeData[k] === '')) {
      typeData = null;
    }
  }

  const dataJson: JsonMap | null =
    typeData == null
      ? null
      : {
          ...typeData,
          fields: fieldsJson,
          name: cipher.name,
          notes: cipher.notes,
          passwordHistory: passwordHistoryJson,
        };

  const collectionIds = sync.cipherCollections.get(cipher.uuid) ?? [];

  const json: JsonMap = {
    object: 'cipherDetails',
    id: cipher.uuid,
    type: cipher.atype,
    creationDate: toApi(cipher.createdAt),
    revisionDate: toApi(cipher.updatedAt),
    deletedDate: toApi(cipher.deletedAt),
    reprompt: cipher.reprompt === 1 ? 1 : 0,
    organizationId: cipher.organizationUuid,
    key: cipher.key,
    attachments: attachmentsJson,
    organizationUseTotp: true,
    collectionIds,
    name: cipher.name,
    notes: cipher.notes,
    fields: fieldsJson,
    data: dataJson,
    passwordHistory: passwordHistoryJson,
    login: null,
    secureNote: null,
    card: null,
    identity: null,
    sshKey: null,
  };

  if (syncType === 'user') {
    json.folderId = sync.cipherFolders.get(cipher.uuid) ?? null;
    json.favorite = sync.cipherFavorites.has(cipher.uuid);
    json.archivedDate = toApi(sync.cipherArchives.get(cipher.uuid) ?? null);
    json.edit = !readOnly;
    json.viewPassword = !hidePasswords;
    json.permissions = { delete: !readOnly, restore: !readOnly };
  }

  const typeKey = (
    {
      [CipherType.Login]: 'login',
      [CipherType.SecureNote]: 'secureNote',
      [CipherType.Card]: 'card',
      [CipherType.Identity]: 'identity',
      [CipherType.SshKey]: 'sshKey',
    } as Record<number, string>
  )[cipher.atype];
  if (!typeKey) throw new Error(`Cipher ${cipher.uuid} has an invalid type ${cipher.atype}`);
  json[typeKey] = typeData;

  return json;
}

export function folderToJson(folder: Folder): JsonMap {
  return {
    id: folder.uuid,
    revisionDate: toApi(folder.updatedAt),
    name: folder.name,
    object: 'folder',
  };
}

export function policyToJson(policy: OrgPolicy): JsonMap {
  let data: unknown = null;
  try {
    data = JSON.parse(policy.data);
  } catch {
    data = null;
  }
  const json: JsonMap = {
    id: policy.uuid,
    organizationId: policy.orgUuid,
    type: policy.atype,
    data,
    enabled: policy.enabled,
    object: 'policy',
  };
  if (policy.atype === OrgPolicyType.ResetPassword) json.canToggleState = true;
  return json;
}

export function sendAccessId(sendUuid: string): string {
  // base64url(uuid bytes), no padding — vaultwarden's access_id
  const hex = sendUuid.replace(/-/g, '');
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return b64UrlEncode(bytes);
}

export function sendToJson(send: Send): JsonMap {
  const data = parseObject(send.data);
  if (typeof data.size === 'number') data.size = String(data.size);

  return {
    id: send.uuid,
    accessId: sendAccessId(send.uuid),
    type: send.atype,
    name: send.name,
    notes: send.notes,
    text: send.atype === SendType.Text ? data : null,
    file: send.atype === SendType.File ? data : null,
    key: send.akey,
    maxAccessCount: send.maxAccessCount,
    accessCount: send.accessCount,
    password: send.passwordHash ? send.passwordHash.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') : null,
    authType: send.passwordHash ? 1 : 0,
    disabled: send.disabled,
    hideEmail: send.hideEmail,
    revisionDate: toApi(send.revisionDate),
    expirationDate: toApi(send.expirationDate),
    deletionDate: toApi(send.deletionDate),
    object: 'send',
  };
}

export function collectionToJson(col: Collection): JsonMap {
  return {
    externalId: col.externalId,
    id: col.uuid,
    organizationId: col.orgUuid,
    name: col.name,
    object: 'collection',
  };
}

export function collectionToJsonDetails(col: Collection, userUuid: string, sync: CipherSyncData): JsonMap {
  let readOnly = true;
  let hidePasswords = true;
  let manage = false;

  const member = sync.members.get(col.orgUuid);
  if (member) {
    if (hasFullAccess(member)) {
      readOnly = false;
      hidePasswords = false;
      manage = isAtLeast(member.atype, MembershipType.Manager);
    } else {
      const isManager = member.atype === MembershipType.Manager;
      const cu = sync.userCollections.get(col.uuid);
      const cg = sync.userCollectionsGroups.get(col.uuid);
      const source = cu ?? cg;
      if (source) {
        readOnly = source.readOnly;
        hidePasswords = source.hidePasswords;
        manage = isManager && (source.manage || (!source.readOnly && !source.hidePasswords));
      } else {
        readOnly = false;
        hidePasswords = false;
        manage = false;
      }
    }
  }

  return {
    ...collectionToJson(col),
    object: 'collectionDetails',
    readOnly,
    hidePasswords,
    manage,
  };
}

export async function membershipToJson(db: Db, m: Membership, emailEnabled: boolean): Promise<JsonMap> {
  const org = await db.query.organizations.findFirst({ where: eq(organizations.uuid, m.orgUuid) });
  const membershipType = m.atype === MembershipType.Manager ? 4 : m.atype;

  return {
    id: m.orgUuid,
    identifier: null,
    name: org?.name ?? '',
    seats: 20,
    maxCollections: null,
    usersGetPremium: true,
    use2fa: true,
    useDirectory: false,
    useEvents: true,
    useGroups: true,
    useTotp: true,
    useScim: false,
    usePolicies: true,
    useApi: true,
    selfHost: true,
    hasPublicAndPrivateKeys: org?.privateKey != null && org?.publicKey != null,
    resetPasswordEnrolled: m.resetPasswordKey != null,
    useResetPassword: emailEnabled,
    ssoBound: false,
    useSso: false,
    useKeyConnector: false,
    useSecretsManager: false,
    usePasswordManager: true,
    useCustomPermissions: true,
    useActivateAutofillPolicy: false,
    useAdminSponsoredFamilies: false,
    useRiskInsights: false,
    organizationUserId: m.uuid,
    providerId: null,
    providerName: null,
    providerType: null,
    familySponsorshipFriendlyName: null,
    familySponsorshipAvailable: false,
    productTierType: 3,
    keyConnectorEnabled: false,
    keyConnectorUrl: null,
    familySponsorshipLastSyncDate: null,
    familySponsorshipValidUntil: null,
    familySponsorshipToDelete: null,
    accessSecretsManager: false,
    limitCollectionCreation: !isAtLeast(m.atype, MembershipType.Manager) || !m.accessAll,
    limitCollectionDeletion: true,
    limitItemDeletion: false,
    allowAdminAccessToAllCollectionItems: true,
    userIsManagedByOrganization: false,
    userIsClaimedByOrganization: false,
    permissions: {
      accessEventLogs: false,
      accessImportExport: false,
      accessReports: false,
      createNewCollections: membershipType === 4 && m.accessAll,
      editAnyCollection: membershipType === 4 && m.accessAll,
      deleteAnyCollection: membershipType === 4 && m.accessAll,
      manageGroups: false,
      managePolicies: false,
      manageSso: false,
      manageUsers: false,
      manageResetPassword: false,
      manageScim: false,
    },
    maxStorageGb: 32767,
    userId: m.userUuid,
    key: m.akey,
    status: m.status,
    type: membershipType,
    enabled: true,
    object: 'profileOrganization',
  };
}

export async function profileJson(db: Db, user: User, emailEnabled: boolean): Promise<JsonMap> {
  const memberships = await db.query.usersOrganizations.findMany({
    where: and(eq(usersOrganizations.userUuid, user.uuid), eq(usersOrganizations.status, MembershipStatus.Confirmed)),
  });
  const orgsJson = await Promise.all(memberships.map((m) => membershipToJson(db, m, emailEnabled)));

  const tf = await db.query.twofactor.findFirst({ where: eq(twofactor.userUuid, user.uuid) });

  return {
    _status: user.passwordHash === '' ? 1 : 0,
    id: user.uuid,
    name: user.name,
    email: user.email,
    emailVerified: !emailEnabled || user.verifiedAt != null,
    premium: true,
    premiumFromOrganization: false,
    culture: 'en-US',
    twoFactorEnabled: Boolean(tf),
    key: user.akey,
    privateKey: user.privateKey,
    securityStamp: user.securityStamp,
    organizations: orgsJson,
    providers: [],
    providerOrganizations: [],
    forcePasswordReset: false,
    avatarColor: user.avatarColor,
    usesKeyConnector: false,
    creationDate: toApi(user.createdAt),
    object: 'profile',
  };
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

/** All ciphers visible to a user: owned + in orgs where confirmed member with access. */
export async function findCiphersVisibleToUser(db: Db, userUuid: string, sync: CipherSyncData): Promise<Cipher[]> {
  const orgIds = [...sync.members.keys()];
  const rows = await db
    .select()
    .from(ciphers)
    .where(
      orgIds.length > 0
        ? or(eq(ciphers.userUuid, userUuid), inArray(ciphers.organizationUuid, orgIds))
        : eq(ciphers.userUuid, userUuid),
    );

  // Restrict org ciphers to those actually accessible (collection/group access or full access)
  return rows.filter((c) => {
    if (c.userUuid === userUuid) return true;
    if (!c.organizationUuid) return false;
    return getAccessRestrictions(c, userUuid, sync) != null;
  });
}

/** Collections visible to the user (direct or via groups or full access). */
export async function findCollectionsForUser(db: Db, userUuid: string, sync: CipherSyncData): Promise<Collection[]> {
  const orgIds = [...sync.members.keys()];
  if (orgIds.length === 0) return [];
  const rows = await db.select().from(collections).where(inArray(collections.orgUuid, orgIds));
  return rows.filter((col) => {
    const member = sync.members.get(col.orgUuid);
    if (!member) return false;
    if (hasFullAccess(member)) return true;
    return sync.userCollections.has(col.uuid) || sync.userCollectionsGroups.has(col.uuid);
  });
}

export async function findPoliciesForUser(db: Db, userUuid: string): Promise<OrgPolicy[]> {
  const rows = await db
    .select({ policy: orgPolicies })
    .from(orgPolicies)
    .innerJoin(usersOrganizations, eq(orgPolicies.orgUuid, usersOrganizations.orgUuid))
    .where(
      and(eq(usersOrganizations.userUuid, userUuid), eq(usersOrganizations.status, MembershipStatus.Confirmed)),
    );
  return rows.map((r) => r.policy);
}

export async function findSendsByUser(db: Db, userUuid: string): Promise<Send[]> {
  return db.query.sends.findMany({ where: eq(sends.userUuid, userUuid) });
}

export async function findFoldersByUser(db: Db, userUuid: string): Promise<Folder[]> {
  return db.query.folders.findMany({ where: eq(folders.userUuid, userUuid) });
}
