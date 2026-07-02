/**
 * Bitwarden protocol enums, ported from vaultwarden (src/db/models/*).
 * Numeric values are part of the wire protocol — do not change them.
 */

export enum CipherType {
  Login = 1,
  SecureNote = 2,
  Card = 3,
  Identity = 4,
  SshKey = 5,
}

export enum SendType {
  Text = 0,
  File = 1,
}

export enum KdfType {
  Pbkdf2 = 0,
  Argon2id = 1,
}

export const KDF_DEFAULTS = {
  pbkdf2Iterations: 600_000,
  argon2Iterations: 3,
  argon2MemoryMiB: 64,
  argon2Parallelism: 4,
} as const;

export enum DeviceType {
  Android = 0,
  Ios = 1,
  ChromeExtension = 2,
  FirefoxExtension = 3,
  OperaExtension = 4,
  EdgeExtension = 5,
  WindowsDesktop = 6,
  MacOsDesktop = 7,
  LinuxDesktop = 8,
  ChromeBrowser = 9,
  FirefoxBrowser = 10,
  OperaBrowser = 11,
  EdgeBrowser = 12,
  IEBrowser = 13,
  UnknownBrowser = 14,
  AndroidAmazon = 15,
  Uwp = 16,
  SafariBrowser = 17,
  VivaldiBrowser = 18,
  VivaldiExtension = 19,
  SafariExtension = 20,
  Sdk = 21,
  Server = 22,
  WindowsCLI = 23,
  MacOsCLI = 24,
  LinuxCLI = 25,
}

export enum TwoFactorType {
  Authenticator = 0,
  Email = 1,
  Duo = 2,
  YubiKey = 3,
  U2f = 4,
  Remember = 5,
  OrganizationDuo = 6,
  Webauthn = 7,
  RecoveryCode = 8,
}

export enum MembershipStatus {
  Revoked = -1,
  Invited = 0,
  Accepted = 1,
  Confirmed = 2,
}

export enum MembershipType {
  Owner = 0,
  Admin = 1,
  User = 2,
  Manager = 3,
}

export enum OrgPolicyType {
  TwoFactorAuthentication = 0,
  MasterPassword = 1,
  PasswordGenerator = 2,
  SingleOrg = 3,
  RequireSso = 4,
  PersonalOwnership = 5,
  DisableSend = 6,
  SendOptions = 7,
  ResetPassword = 8,
  MaximumVaultTimeout = 9,
  DisablePersonalVaultExport = 10,
  ActivateAutofill = 11,
  AutomaticAppLogIn = 12,
  FreeFamiliesSponsorshipPolicy = 13,
  RemoveUnlockWithPin = 14,
}

export enum EmergencyAccessType {
  View = 0,
  Takeover = 1,
}

export enum EmergencyAccessStatus {
  Invited = 0,
  Accepted = 1,
  Confirmed = 2,
  RecoveryInitiated = 3,
  RecoveryApproved = 4,
}

export enum AuthRequestType {
  AuthenticateAndUnlock = 0,
  AdminApproval = 1,
}

export enum OrganizationApiKeyType {
  Default = 0,
  BillingSync = 1,
  Scim = 2,
}

/** Bitwarden event types (subset used by vaultwarden's event log). */
export enum EventType {
  // User events
  UserLoggedIn = 1000,
  UserChangedPassword = 1001,
  UserUpdated2fa = 1002,
  UserDisabled2fa = 1003,
  UserRecovered2fa = 1004,
  UserFailedLogIn = 1005,
  UserFailedLogIn2fa = 1006,
  UserClientExportedVault = 1007,
  // Cipher events
  CipherCreated = 1100,
  CipherUpdated = 1101,
  CipherDeleted = 1102,
  CipherAttachmentCreated = 1103,
  CipherAttachmentDeleted = 1104,
  CipherShared = 1105,
  CipherUpdatedCollections = 1106,
  CipherClientViewed = 1107,
  CipherClientToggledPasswordVisible = 1108,
  CipherClientToggledHiddenFieldVisible = 1109,
  CipherClientToggledCardCodeVisible = 1110,
  CipherClientCopiedPassword = 1111,
  CipherClientCopiedHiddenField = 1112,
  CipherClientCopiedCardCode = 1113,
  CipherClientAutofilled = 1114,
  CipherSoftDeleted = 1115,
  CipherRestored = 1116,
  CipherClientToggledCardNumberVisible = 1117,
  // Collection events
  CollectionCreated = 1300,
  CollectionUpdated = 1301,
  CollectionDeleted = 1302,
  // Group events
  GroupCreated = 1400,
  GroupUpdated = 1401,
  GroupDeleted = 1402,
  // Membership events
  OrganizationUserInvited = 1500,
  OrganizationUserConfirmed = 1501,
  OrganizationUserUpdated = 1502,
  OrganizationUserRemoved = 1503,
  OrganizationUserUpdatedGroups = 1504,
  OrganizationUserUnlinkedSso = 1505,
  OrganizationUserResetPasswordEnroll = 1506,
  OrganizationUserResetPasswordWithdraw = 1507,
  OrganizationUserAdminResetPassword = 1508,
  OrganizationUserResetSsoLink = 1509,
  OrganizationUserFirstSsoLogin = 1510,
  OrganizationUserRevoked = 1511,
  OrganizationUserRestored = 1512,
  // Organization events
  OrganizationUpdated = 1600,
  OrganizationPurgedVault = 1601,
  OrganizationClientExportedVault = 1602,
  OrganizationVaultAccessed = 1603,
  OrganizationEnabledSso = 1604,
  OrganizationDisabledSso = 1605,
  OrganizationEnabledKeyConnector = 1606,
  OrganizationDisabledKeyConnector = 1607,
  OrganizationSponsorshipsSynced = 1608,
  OrganizationCollectionManagementUpdated = 1609,
  // Policy events
  PolicyUpdated = 1700,
}

/** Push notification update types (vaultwarden src/api/push.rs / notifications). */
export enum UpdateType {
  SyncCipherUpdate = 0,
  SyncCipherCreate = 1,
  SyncLoginDelete = 2,
  SyncFolderDelete = 3,
  SyncCiphers = 4,
  SyncVault = 5,
  SyncOrgKeys = 6,
  SyncFolderCreate = 7,
  SyncFolderUpdate = 8,
  SyncCipherDelete = 9,
  SyncSettings = 10,
  LogOut = 11,
  SyncSendCreate = 12,
  SyncSendUpdate = 13,
  SyncSendDelete = 14,
  AuthRequest = 15,
  AuthRequestResponse = 16,
  None = 100,
}

/** OAuth2 error payload shapes expected by Bitwarden clients. */
export const IDENTITY_INVALID_GRANT = 'invalid_grant';

/** Default equivalent-domains "excluded globals" — none. */
export const DEFAULT_EQUIVALENT_DOMAINS = '[]';
export const DEFAULT_EXCLUDED_GLOBALS = '[]';

/** Client versions this server has been verified against. */
export const COMPAT = {
  /** api version reported by /api/config; mirrors vaultwarden. */
  apiVersion: '2026.4.0',
  serverName: 'Vaultur',
  serverUrl: 'https://github.com/nommyt/vaultur',
} as const;
