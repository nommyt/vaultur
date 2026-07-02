/**
 * Vaultwarden stores timestamps as NaiveDateTime strings: `YYYY-MM-DD HH:MM:SS.SSSSSS` (UTC).
 * We keep the same storage format for dump-level compatibility.
 * Bitwarden API responses use ISO-8601 with `Z` suffix.
 */

/** Current UTC time in DB storage format. */
export function nowDb(): string {
  return toDb(new Date());
}

/** Date → DB storage format (UTC, microsecond padding like vaultwarden). */
export function toDb(date: Date): string {
  const iso = date.toISOString(); // 2026-07-01T12:34:56.789Z
  return `${iso.slice(0, 10)} ${iso.slice(11, 23)}000`;
}

/** DB storage format → Date. Accepts both `YYYY-MM-DD HH:MM:SS[.f+]` and ISO strings. */
export function fromDb(value: string): Date {
  // Normalize "YYYY-MM-DD HH:MM:SS.ffffff" to ISO by replacing the space and appending Z.
  const normalized = value.includes('T') ? value : `${value.replace(' ', 'T')}Z`;
  return new Date(normalized);
}

/** DB storage format → Bitwarden API format (ISO-8601, `Z`). */
export function toApi(value: string | null | undefined): string | null {
  if (value == null) return null;
  return fromDb(value).toISOString();
}

/** Epoch seconds helper for JWT claims. */
export function epoch(date: Date = new Date()): number {
  return Math.floor(date.getTime() / 1000);
}
