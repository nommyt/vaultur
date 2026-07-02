import { describe, expect, it } from 'vitest';
import {
  expandIpv6,
  getSafeHost,
  isGlobalIpv4,
  isGlobalIpv6,
  isSafeFetchHost,
  parseToIpv4,
} from '../src/services/ssrf';
import { obscureEmail } from '../src/services/twofactor';

/**
 * Ports vaultwarden's src/http_client.rs SSRF tests — the icon proxy fetches
 * arbitrary hosts server-side, so these encodings must all be blocked.
 */
describe('ssrf host validation', () => {
  it('normalises decimal / hex / octal IPv4 encodings', () => {
    expect(parseToIpv4('2130706433')).toEqual([127, 0, 0, 1]); // decimal loopback
    expect(parseToIpv4('0x7f000001')).toEqual([127, 0, 0, 1]); // hex loopback
    expect(parseToIpv4('017700000001')).toEqual([127, 0, 0, 1]); // octal loopback
    expect(parseToIpv4('2852039166')).toEqual([169, 254, 169, 254]); // AWS IMDS
    expect(parseToIpv4('0x0a000001')).toEqual([10, 0, 0, 1]); // hex RFC1918
    expect(parseToIpv4('134744072')).toEqual([8, 8, 8, 8]); // public
  });

  it('blocks non-global IPv4 in every encoding', () => {
    for (const host of [
      '127.0.0.1',
      '2130706433', // 127.0.0.1 decimal
      '0x7f000001', // 127.0.0.1 hex
      '017700000001', // 127.0.0.1 octal
      '10.0.0.1',
      '0x0a000001', // 10.0.0.1 hex
      '172.16.0.5',
      '192.168.1.1',
      '169.254.169.254', // AWS/GCP metadata
      '2852039166', // metadata decimal
      '100.64.0.1', // CGNAT
      '0.0.0.0',
    ]) {
      expect(isSafeFetchHost(host), `${host} should be blocked`).toBe(false);
    }
  });

  it('allows public IPv4', () => {
    expect(isGlobalIpv4([8, 8, 8, 8])).toBe(true);
    expect(isSafeFetchHost('8.8.8.8')).toBe(true);
  });

  it('blocks non-global IPv6 (loopback, unique-local, link-local, mapped)', () => {
    expect(isGlobalIpv6(expandIpv6('::1')!)).toBe(false);
    expect(isSafeFetchHost('[::1]')).toBe(false);
    expect(isGlobalIpv6(expandIpv6('fc00::1')!)).toBe(false); // unique-local
    expect(isGlobalIpv6(expandIpv6('fe80::1')!)).toBe(false); // link-local
    expect(isGlobalIpv6(expandIpv6('::ffff:127.0.0.1')!)).toBe(false); // v4-mapped loopback
    expect(isGlobalIpv6(expandIpv6('2606:4700:4700::1111')!)).toBe(true); // public (1.1.1.1 dns)
  });

  it('blocks internal hostnames', () => {
    for (const host of ['localhost', 'foo.local', 'db.internal', 'metadata.google.internal']) {
      expect(isSafeFetchHost(host), `${host} should be blocked`).toBe(false);
    }
  });

  it('accepts and rejects domains by label validity', () => {
    expect(getSafeHost('example.com')).toEqual({ kind: 'domain', value: 'example.com' });
    expect(getSafeHost('sub.example.co.uk')?.kind).toBe('domain');
    expect(getSafeHost('-bad.example.com')).toBeNull(); // leading hyphen
    expect(getSafeHost('a'.repeat(64) + '.com')).toBeNull(); // label too long
    expect(getSafeHost('nodot')).toBeNull(); // no TLD
    expect(getSafeHost('under_score.com')).toBeNull(); // underscore rejected
  });
});

describe('email obscuring (2FA)', () => {
  it('matches vaultwarden obscure_email behaviour', () => {
    // 4+ chars: first two visible, rest starred (count = size - 2)
    expect(obscureEmail('bytes@example.ext')).toBe('by***@example.ext');
    expect(obscureEmail('johndoe@example.com')).toBe('jo*****@example.com');
    // 1..=3 chars: all asterisks
    expect(obscureEmail('byt@example.ext')).toBe('***@example.ext');
    expect(obscureEmail('ab@example.com')).toBe('**@example.com');
  });
});
