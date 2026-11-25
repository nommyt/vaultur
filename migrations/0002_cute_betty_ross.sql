CREATE TABLE `pending_blob_deletions` (
	`prefix` text PRIMARY KEY NOT NULL,
	`attempts` integer DEFAULT 0 NOT NULL
);
--> statement-breakpoint
CREATE INDEX `idx_pending_blob_deletions_attempts` ON `pending_blob_deletions` (`attempts`,`prefix`);