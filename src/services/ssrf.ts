/**
 * SSRF protection for the icon proxy, ported from vaultwarden src/http_client.rs.
 *
 * The icon endpoint fetches `https://<domain>/` server-side, so an attacker can
 * try to make the Worker reach internal addresses. Browsers/curl accept many
 * non-dotted IP encodings (decimal, hex, octal, IPv6, IPv4-mapped-IPv6), so a
 * naive "looks like a domain" regex is not enough. We normalise the host to a
 * canonical IP where possible and reject any non-global address, plus obvious
 * internal hostnames.
 *
 * Note: on Cloudflare Workers `fetch` performs its own DNS and cannot reach the
 * edge's private network, so this is defense-in-depth against literal-IP and
 * known-internal-name SSRF rather than a full DNS-rebinding guard.
 */

export type ParsedHost =
  | { kind: 'ipv4'; value: string } // dotted "a.b.c.d"
  | { kind: 'ipv6'; value: string } // canonical lowercase
  | { kind: 'domain'; value: string }; // ascii/punycode domain

/** Parse a bare integer / hex / octal / dotted host into a 32-bit IPv4, if it is one. */
export function parseToIpv4(input: string): [number, number, number, number] | null {
  const s = input.trim();
  if (s === '') return null;

  // Whole-number forms: 0x..., 0..., or plain decimal → single 32-bit value.
  const single = parseUint(s);
  if (single != null && !s.includes('.')) {
    if (single > 0xffffffff) return null;
    return [(single >>> 24) & 0xff, (single >>> 16) & 0xff, (single >>> 8) & 0xff, single & 0xff];
  }

  // Dotted forms — each part may itself be decimal/hex/octal (e.g. 0x7f.0.0.1).
  const parts = s.split('.');
  if (parts.length < 2 || parts.length > 4) return null;
  const nums: number[] = [];
  for (const part of parts) {
    const n = parseUint(part);
    if (n == null) return null;
    nums.push(n);
  }
  // Standard 4-octet form
  if (nums.length === 4) {
    if (nums.some((n) => n > 0xff)) return null;
    return [nums[0]!, nums[1]!, nums[2]!, nums[3]!];
  }
  // a.b.c  → a.b.(c as 16-bit) ; a.b → a.(b as 24-bit) (classic inet_aton)
  if (nums.length === 3) {
    if (nums[0]! > 0xff || nums[1]! > 0xff || nums[2]! > 0xffff) return null;
    return [nums[0]!, nums[1]!, (nums[2]! >> 8) & 0xff, nums[2]! & 0xff];
  }
  if (nums.length === 2) {
    if (nums[0]! > 0xff || nums[1]! > 0xffffff) return null;
    return [nums[0]!, (nums[1]! >> 16) & 0xff, (nums[1]! >> 8) & 0xff, nums[1]! & 0xff];
  }
  return null;
}

function parseUint(part: string): number | null {
  if (part === '') return null;
  let value: number;
  if (/^0x[0-9a-f]+$/i.test(part)) value = Number.parseInt(part.slice(2), 16);
  else if (/^0[0-7]+$/.test(part)) value = Number.parseInt(part.slice(1), 8);
  else if (/^0$/.test(part)) value = 0;
  else if (/^[1-9][0-9]*$/.test(part)) value = Number.parseInt(part, 10);
  else return null;
  return Number.isFinite(value) && value >= 0 ? value : null;
}

/** True if the IPv4 octets are a globally-routable address. */
export function isGlobalIpv4(o: [number, number, number, number]): boolean {
  const [a, b] = o;
  if (a === 0) return false; // 0.0.0.0/8 "this network"
  if (a === 10) return false; // RFC1918
  if (a === 127) return false; // loopback
  if (a === 169 && b === 254) return false; // link-local incl. AWS/GCP metadata
  if (a === 172 && b >= 16 && b <= 31) return false; // RFC1918
  if (a === 192 && b === 168) return false; // RFC1918
  if (a === 192 && b === 0 && o[2] === 0) return false; // IETF protocol assignments
  if (a === 100 && b >= 64 && b <= 127) return false; // CGNAT 100.64/10
  if (a === 198 && (b === 18 || b === 19)) return false; // benchmarking
  if (a >= 224) return false; // multicast + reserved (224.0.0.0/3)
  if (a === 255 && b === 255) return false; // broadcast
  return true;
}

/** Expand an IPv6 string to 8 16-bit groups, or null if invalid. */
export function expandIpv6(input: string): number[] | null {
  let s = input.trim().toLowerCase();
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1);
  if (!s.includes(':')) return null;

  // Substitute an embedded IPv4 tail (e.g. ::ffff:127.0.0.1) with two hex
  // groups so normal expansion can place them correctly.
  const lastColon = s.lastIndexOf(':');
  const tail = s.slice(lastColon + 1);
  if (tail.includes('.')) {
    const v4 = parseToIpv4(tail);
    if (!v4) return null;
    const hi = ((v4[0] << 8) | v4[1]).toString(16);
    const lo = ((v4[2] << 8) | v4[3]).toString(16);
    s = s.slice(0, lastColon + 1) + `${hi}:${lo}`;
  }

  const halves = s.split('::');
  if (halves.length > 2) return null;

  const parse = (chunk: string): number[] | null => {
    if (chunk === '') return [];
    const out: number[] = [];
    for (const g of chunk.split(':')) {
      if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
      out.push(Number.parseInt(g, 16));
    }
    return out;
  };

  let groups: number[];
  if (halves.length === 2) {
    const head = parse(halves[0]!);
    const rest = parse(halves[1]!);
    if (!head || !rest) return null;
    const fill = 8 - head.length - rest.length;
    if (fill < 0) return null;
    groups = [...head, ...new Array(fill).fill(0), ...rest];
  } else {
    const all = parse(halves[0]!);
    if (!all) return null;
    groups = all;
  }
  return groups.length === 8 ? groups : null;
}

export function isGlobalIpv6(groups: number[]): boolean {
  const [g0] = groups;
  // ::1 loopback and :: unspecified
  if (groups.every((g) => g === 0)) return false;
  if (groups.slice(0, 7).every((g) => g === 0) && groups[7] === 1) return false;
  if ((g0! & 0xfe00) === 0xfc00) return false; // fc00::/7 unique-local
  if ((g0! & 0xffc0) === 0xfe80) return false; // fe80::/10 link-local
  // IPv4-mapped ::ffff:a.b.c.d → check the embedded v4
  if (groups.slice(0, 5).every((g) => g === 0) && groups[5] === 0xffff) {
    return isGlobalIpv4([
      (groups[6]! >> 8) & 0xff,
      groups[6]! & 0xff,
      (groups[7]! >> 8) & 0xff,
      groups[7]! & 0xff,
    ]);
  }
  return true;
}

const INTERNAL_HOST_SUFFIXES = ['.local', '.internal', '.localhost', '.home.arpa'];
const INTERNAL_HOST_EXACT = new Set(['localhost', 'metadata.google.internal']);

/**
 * Validate and normalise a host for outbound fetching. Returns the canonical
 * host string to use, or null if it must be blocked.
 */
export function getSafeHost(rawHost: string): ParsedHost | null {
  const host = rawHost.trim().toLowerCase();
  if (host === '' || host.length > 253) return null;

  // IPv6 literal
  if (host.startsWith('[') || (host.includes(':') && !host.includes('.'))) {
    const groups = expandIpv6(host);
    if (!groups) return null;
    if (!isGlobalIpv6(groups)) return null;
    return { kind: 'ipv6', value: host.replace(/^\[|\]$/g, '') };
  }

  // Any IPv4 encoding (dotted, decimal, hex, octal)
  const v4 = parseToIpv4(host);
  if (v4) {
    if (!isGlobalIpv4(v4)) return null;
    return { kind: 'ipv4', value: v4.join('.') };
  }

  // Domain name
  if (INTERNAL_HOST_EXACT.has(host)) return null;
  if (INTERNAL_HOST_SUFFIXES.some((s) => host.endsWith(s))) return null;
  const labels = host.split('.');
  if (labels.length < 2) return null; // require a TLD
  for (const label of labels) {
    if (label === '' || label.length > 63) return null;
    if (label.startsWith('-') || label.endsWith('-')) return null;
    // punycode/ascii only (browsers should have IDN-encoded already)
    if (!/^[a-z0-9-]+$/.test(label)) return null;
  }
  const tld = labels[labels.length - 1]!;
  if (!/^[a-z]{2,}$/.test(tld)) return null;
  return { kind: 'domain', value: host };
}

/** Convenience wrapper used by the icon proxy. */
export function isSafeFetchHost(host: string): boolean {
  return getSafeHost(host) != null;
}
