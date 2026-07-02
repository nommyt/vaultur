CREATE TABLE `archives` (
	`user_uuid` text NOT NULL,
	`cipher_uuid` text NOT NULL,
	`archived_at` text NOT NULL,
	PRIMARY KEY(`user_uuid`, `cipher_uuid`),
	FOREIGN KEY (`user_uuid`) REFERENCES `users`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`cipher_uuid`) REFERENCES `ciphers`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `attachments` (
	`id` text PRIMARY KEY NOT NULL,
	`cipher_uuid` text NOT NULL,
	`file_name` text NOT NULL,
	`file_size` integer NOT NULL,
	`akey` text,
	FOREIGN KEY (`cipher_uuid`) REFERENCES `ciphers`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_attachments_cipher_uuid` ON `attachments` (`cipher_uuid`);--> statement-breakpoint
CREATE TABLE `auth_requests` (
	`uuid` text PRIMARY KEY NOT NULL,
	`user_uuid` text NOT NULL,
	`organization_uuid` text,
	`request_device_identifier` text NOT NULL,
	`device_type` integer NOT NULL,
	`request_ip` text NOT NULL,
	`response_device_id` text,
	`access_code` text NOT NULL,
	`public_key` text NOT NULL,
	`enc_key` text,
	`master_password_hash` text,
	`approved` integer,
	`creation_date` text NOT NULL,
	`response_date` text,
	`authentication_date` text,
	FOREIGN KEY (`user_uuid`) REFERENCES `users`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_auth_requests_user_uuid` ON `auth_requests` (`user_uuid`);--> statement-breakpoint
CREATE TABLE `ciphers` (
	`uuid` text PRIMARY KEY NOT NULL,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL,
	`user_uuid` text,
	`organization_uuid` text,
	`key` text,
	`atype` integer NOT NULL,
	`name` text NOT NULL,
	`notes` text,
	`fields` text,
	`data` text NOT NULL,
	`password_history` text,
	`deleted_at` text,
	`reprompt` integer,
	FOREIGN KEY (`user_uuid`) REFERENCES `users`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_ciphers_user_uuid` ON `ciphers` (`user_uuid`);--> statement-breakpoint
CREATE INDEX `idx_ciphers_organization_uuid` ON `ciphers` (`organization_uuid`);--> statement-breakpoint
CREATE TABLE `ciphers_collections` (
	`cipher_uuid` text NOT NULL,
	`collection_uuid` text NOT NULL,
	PRIMARY KEY(`cipher_uuid`, `collection_uuid`),
	FOREIGN KEY (`cipher_uuid`) REFERENCES `ciphers`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`collection_uuid`) REFERENCES `collections`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `collections` (
	`uuid` text PRIMARY KEY NOT NULL,
	`org_uuid` text NOT NULL,
	`name` text NOT NULL,
	`external_id` text,
	FOREIGN KEY (`org_uuid`) REFERENCES `organizations`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_collections_org_uuid` ON `collections` (`org_uuid`);--> statement-breakpoint
CREATE TABLE `collections_groups` (
	`collections_uuid` text NOT NULL,
	`groups_uuid` text NOT NULL,
	`read_only` integer DEFAULT false NOT NULL,
	`hide_passwords` integer DEFAULT false NOT NULL,
	`manage` integer DEFAULT false NOT NULL,
	PRIMARY KEY(`collections_uuid`, `groups_uuid`),
	FOREIGN KEY (`collections_uuid`) REFERENCES `collections`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`groups_uuid`) REFERENCES `groups`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `devices` (
	`uuid` text NOT NULL,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL,
	`user_uuid` text NOT NULL,
	`name` text NOT NULL,
	`atype` integer NOT NULL,
	`push_uuid` text,
	`push_token` text,
	`refresh_token` text NOT NULL,
	`twofactor_remember` text,
	PRIMARY KEY(`uuid`, `user_uuid`),
	FOREIGN KEY (`user_uuid`) REFERENCES `users`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_devices_user_uuid` ON `devices` (`user_uuid`);--> statement-breakpoint
CREATE INDEX `idx_devices_refresh_token` ON `devices` (`refresh_token`);--> statement-breakpoint
CREATE TABLE `emergency_access` (
	`uuid` text PRIMARY KEY NOT NULL,
	`grantor_uuid` text NOT NULL,
	`grantee_uuid` text,
	`email` text,
	`key_encrypted` text,
	`atype` integer NOT NULL,
	`status` integer NOT NULL,
	`wait_time_days` integer NOT NULL,
	`recovery_initiated_at` text,
	`last_notification_at` text,
	`updated_at` text NOT NULL,
	`created_at` text NOT NULL,
	FOREIGN KEY (`grantor_uuid`) REFERENCES `users`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`grantee_uuid`) REFERENCES `users`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_emergency_access_grantor_uuid` ON `emergency_access` (`grantor_uuid`);--> statement-breakpoint
CREATE INDEX `idx_emergency_access_grantee_uuid` ON `emergency_access` (`grantee_uuid`);--> statement-breakpoint
CREATE TABLE `event` (
	`uuid` text PRIMARY KEY NOT NULL,
	`event_type` integer NOT NULL,
	`user_uuid` text,
	`org_uuid` text,
	`cipher_uuid` text,
	`collection_uuid` text,
	`group_uuid` text,
	`org_user_uuid` text,
	`act_user_uuid` text,
	`device_type` integer,
	`ip_address` text,
	`event_date` text NOT NULL,
	`policy_uuid` text,
	`provider_uuid` text,
	`provider_user_uuid` text,
	`provider_org_uuid` text
);
--> statement-breakpoint
CREATE INDEX `idx_event_org_uuid_event_date` ON `event` (`org_uuid`,`event_date`);--> statement-breakpoint
CREATE INDEX `idx_event_user_uuid_event_date` ON `event` (`user_uuid`,`event_date`);--> statement-breakpoint
CREATE TABLE `favorites` (
	`user_uuid` text NOT NULL,
	`cipher_uuid` text NOT NULL,
	PRIMARY KEY(`user_uuid`, `cipher_uuid`),
	FOREIGN KEY (`user_uuid`) REFERENCES `users`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`cipher_uuid`) REFERENCES `ciphers`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `folders` (
	`uuid` text PRIMARY KEY NOT NULL,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL,
	`user_uuid` text NOT NULL,
	`name` text NOT NULL,
	FOREIGN KEY (`user_uuid`) REFERENCES `users`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_folders_user_uuid` ON `folders` (`user_uuid`);--> statement-breakpoint
CREATE TABLE `folders_ciphers` (
	`cipher_uuid` text NOT NULL,
	`folder_uuid` text NOT NULL,
	PRIMARY KEY(`cipher_uuid`, `folder_uuid`),
	FOREIGN KEY (`cipher_uuid`) REFERENCES `ciphers`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`folder_uuid`) REFERENCES `folders`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `groups` (
	`uuid` text PRIMARY KEY NOT NULL,
	`organizations_uuid` text NOT NULL,
	`name` text NOT NULL,
	`access_all` integer DEFAULT false NOT NULL,
	`external_id` text,
	`creation_date` text NOT NULL,
	`revision_date` text NOT NULL,
	FOREIGN KEY (`organizations_uuid`) REFERENCES `organizations`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_groups_organizations_uuid` ON `groups` (`organizations_uuid`);--> statement-breakpoint
CREATE TABLE `groups_users` (
	`groups_uuid` text NOT NULL,
	`users_organizations_uuid` text NOT NULL,
	PRIMARY KEY(`groups_uuid`, `users_organizations_uuid`),
	FOREIGN KEY (`groups_uuid`) REFERENCES `groups`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`users_organizations_uuid`) REFERENCES `users_organizations`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `invitations` (
	`email` text PRIMARY KEY NOT NULL
);
--> statement-breakpoint
CREATE TABLE `org_policies` (
	`uuid` text PRIMARY KEY NOT NULL,
	`org_uuid` text NOT NULL,
	`atype` integer NOT NULL,
	`enabled` integer NOT NULL,
	`data` text NOT NULL,
	FOREIGN KEY (`org_uuid`) REFERENCES `organizations`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_org_policies_org_uuid` ON `org_policies` (`org_uuid`);--> statement-breakpoint
CREATE TABLE `organization_api_key` (
	`uuid` text NOT NULL,
	`org_uuid` text NOT NULL,
	`atype` integer NOT NULL,
	`api_key` text NOT NULL,
	`revision_date` text NOT NULL,
	PRIMARY KEY(`uuid`, `org_uuid`),
	FOREIGN KEY (`org_uuid`) REFERENCES `organizations`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `organizations` (
	`uuid` text PRIMARY KEY NOT NULL,
	`name` text NOT NULL,
	`billing_email` text NOT NULL,
	`private_key` text,
	`public_key` text
);
--> statement-breakpoint
CREATE TABLE `sends` (
	`uuid` text PRIMARY KEY NOT NULL,
	`user_uuid` text,
	`organization_uuid` text,
	`name` text NOT NULL,
	`notes` text,
	`atype` integer NOT NULL,
	`data` text NOT NULL,
	`akey` text NOT NULL,
	`password_hash` text,
	`password_salt` text,
	`password_iter` integer,
	`max_access_count` integer,
	`access_count` integer DEFAULT 0 NOT NULL,
	`creation_date` text NOT NULL,
	`revision_date` text NOT NULL,
	`expiration_date` text,
	`deletion_date` text NOT NULL,
	`disabled` integer DEFAULT false NOT NULL,
	`hide_email` integer,
	FOREIGN KEY (`user_uuid`) REFERENCES `users`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_sends_user_uuid` ON `sends` (`user_uuid`);--> statement-breakpoint
CREATE INDEX `idx_sends_deletion_date` ON `sends` (`deletion_date`);--> statement-breakpoint
CREATE TABLE `sso_auth` (
	`state` text PRIMARY KEY NOT NULL,
	`client_challenge` text NOT NULL,
	`nonce` text NOT NULL,
	`redirect_uri` text NOT NULL,
	`code_response` text,
	`code_response_error` text,
	`auth_response` text,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL,
	`binding_hash` text
);
--> statement-breakpoint
CREATE TABLE `sso_users` (
	`user_uuid` text PRIMARY KEY NOT NULL,
	`identifier` text NOT NULL,
	FOREIGN KEY (`user_uuid`) REFERENCES `users`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `twofactor` (
	`uuid` text PRIMARY KEY NOT NULL,
	`user_uuid` text NOT NULL,
	`atype` integer NOT NULL,
	`enabled` integer NOT NULL,
	`data` text NOT NULL,
	`last_used` integer DEFAULT 0 NOT NULL,
	FOREIGN KEY (`user_uuid`) REFERENCES `users`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_twofactor_user_uuid` ON `twofactor` (`user_uuid`);--> statement-breakpoint
CREATE TABLE `twofactor_duo_ctx` (
	`state` text PRIMARY KEY NOT NULL,
	`user_email` text NOT NULL,
	`nonce` text NOT NULL,
	`exp` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `twofactor_incomplete` (
	`user_uuid` text NOT NULL,
	`device_uuid` text NOT NULL,
	`device_name` text NOT NULL,
	`device_type` integer NOT NULL,
	`login_time` text NOT NULL,
	`ip_address` text NOT NULL,
	PRIMARY KEY(`user_uuid`, `device_uuid`),
	FOREIGN KEY (`user_uuid`) REFERENCES `users`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `users` (
	`uuid` text PRIMARY KEY NOT NULL,
	`enabled` integer DEFAULT true NOT NULL,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL,
	`verified_at` text,
	`last_verifying_at` text,
	`login_verify_count` integer DEFAULT 0 NOT NULL,
	`email` text NOT NULL,
	`email_new` text,
	`email_new_token` text,
	`name` text NOT NULL,
	`password_hash` text NOT NULL,
	`salt` text NOT NULL,
	`password_iterations` integer NOT NULL,
	`password_hint` text,
	`akey` text NOT NULL,
	`private_key` text,
	`public_key` text,
	`totp_secret` text,
	`totp_recover` text,
	`security_stamp` text NOT NULL,
	`stamp_exception` text,
	`equivalent_domains` text DEFAULT '[]' NOT NULL,
	`excluded_globals` text DEFAULT '[]' NOT NULL,
	`client_kdf_type` integer DEFAULT 0 NOT NULL,
	`client_kdf_iter` integer DEFAULT 600000 NOT NULL,
	`client_kdf_memory` integer,
	`client_kdf_parallelism` integer,
	`api_key` text,
	`avatar_color` text,
	`external_id` text
);
--> statement-breakpoint
CREATE UNIQUE INDEX `users_email_unique` ON `users` (`email`);--> statement-breakpoint
CREATE TABLE `users_collections` (
	`user_uuid` text NOT NULL,
	`collection_uuid` text NOT NULL,
	`read_only` integer DEFAULT false NOT NULL,
	`hide_passwords` integer DEFAULT false NOT NULL,
	`manage` integer DEFAULT false NOT NULL,
	PRIMARY KEY(`user_uuid`, `collection_uuid`),
	FOREIGN KEY (`user_uuid`) REFERENCES `users`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`collection_uuid`) REFERENCES `collections`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `users_organizations` (
	`uuid` text PRIMARY KEY NOT NULL,
	`user_uuid` text NOT NULL,
	`org_uuid` text NOT NULL,
	`invited_by_email` text,
	`access_all` integer DEFAULT false NOT NULL,
	`akey` text NOT NULL,
	`status` integer NOT NULL,
	`atype` integer NOT NULL,
	`reset_password_key` text,
	`external_id` text,
	FOREIGN KEY (`user_uuid`) REFERENCES `users`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`org_uuid`) REFERENCES `organizations`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_users_organizations_user_uuid` ON `users_organizations` (`user_uuid`);--> statement-breakpoint
CREATE INDEX `idx_users_organizations_org_uuid` ON `users_organizations` (`org_uuid`);