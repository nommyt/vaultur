import { drizzle } from "drizzle-orm/d1"

import * as schema from "./schema"

export * from "./schema"
export * from "./datetime"
export { schema }

export function createDb(d1: D1Database) {
	return drizzle(d1, { schema, casing: "snake_case" })
}

export type Db = ReturnType<typeof createDb>

export type User = typeof schema.users.$inferSelect
export type NewUser = typeof schema.users.$inferInsert
export type Device = typeof schema.devices.$inferSelect
export type NewDevice = typeof schema.devices.$inferInsert
export type Cipher = typeof schema.ciphers.$inferSelect
export type NewCipher = typeof schema.ciphers.$inferInsert
export type Folder = typeof schema.folders.$inferSelect
export type Attachment = typeof schema.attachments.$inferSelect
export type Send = typeof schema.sends.$inferSelect
export type NewSend = typeof schema.sends.$inferInsert
export type Organization = typeof schema.organizations.$inferSelect
export type Membership = typeof schema.usersOrganizations.$inferSelect
export type Collection = typeof schema.collections.$inferSelect
export type CollectionUser = typeof schema.usersCollections.$inferSelect
export type OrgPolicy = typeof schema.orgPolicies.$inferSelect
export type Group = typeof schema.groups.$inferSelect
export type TwoFactor = typeof schema.twofactor.$inferSelect
export type EmergencyAccess = typeof schema.emergencyAccess.$inferSelect
export type AuthRequest = typeof schema.authRequests.$inferSelect
export type EventRow = typeof schema.event.$inferSelect
export type SsoAuthRow = typeof schema.ssoAuth.$inferSelect
export type SsoUserRow = typeof schema.ssoUsers.$inferSelect
