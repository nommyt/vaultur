import { Hono } from 'hono';
import type { AppEnv } from '../env';

/**
 * Website icon proxy (/icons/:domain/icon.png) with KV caching.
 * Simplified port of vaultwarden src/api/icons.rs — fetches the site's
 * favicon and caches the bytes (positive and negative) in KV.
 */
export const iconRoutes = new Hono<AppEnv>();

const MAX_ICON_BYTES = 5 * 1024 * 1024;
const NEGATIVE_TTL = 24 * 60 * 60;

function isValidDomain(domain: string): boolean {
  if (!domain || domain.length > 255 || domain.includes('..')) return false;
  // Reject IPs, localhost, and anything without a dot TLD
  if (domain === 'localhost' || /^\d{1,3}(\.\d{1,3}){3}$/.test(domain)) return false;
  if (/[^a-z0-9.\-]/i.test(domain)) return false;
  return /^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i.test(domain);
}

function extractIconHref(html: string): string | null {
  // Look for <link rel="...icon..." href="...">
  const linkRe = /<link\b[^>]*>/gi;
  let match: RegExpExecArray | null;
  const candidates: string[] = [];
  while ((match = linkRe.exec(html))) {
    const tag = match[0];
    if (!/rel=["'][^"']*icon[^"']*["']/i.test(tag)) continue;
    const href = /href=["']([^"']+)["']/i.exec(tag);
    if (href?.[1]) candidates.push(href[1]);
  }
  return candidates[0] ?? null;
}

iconRoutes.get('/:domain/icon.png', async (c) => {
  const domain = (c.req.param('domain') ?? '').toLowerCase();
  const config = c.get('config');
  if (config.iconService !== 'internal') {
    // External services (e.g. Bitwarden's) — redirect
    return c.redirect(`https://icons.bitwarden.net/${domain}/icon.png`, 302);
  }
  if (!isValidDomain(domain)) return c.body(null, 404);

  const cacheKey = `icon:${domain}`;
  const cached = await c.env.KV.getWithMetadata(cacheKey, 'arrayBuffer');
  if (cached.value) {
    const meta = (cached.metadata ?? {}) as { contentType?: string; miss?: boolean };
    if (meta.miss) return c.body(null, 404);
    return new Response(cached.value, {
      headers: {
        'Content-Type': meta.contentType ?? 'image/x-icon',
        'Cache-Control': `public, max-age=${config.iconCacheTtlSeconds}`,
      },
    });
  }

  const iconBytes = await fetchIcon(domain);
  if (!iconBytes) {
    await c.env.KV.put(cacheKey, 'x', { expirationTtl: NEGATIVE_TTL, metadata: { miss: true } });
    return c.body(null, 404);
  }

  c.executionCtx.waitUntil(
    c.env.KV.put(cacheKey, iconBytes.bytes, {
      expirationTtl: config.iconCacheTtlSeconds,
      metadata: { contentType: iconBytes.contentType },
    }),
  );
  return new Response(iconBytes.bytes, {
    headers: {
      'Content-Type': iconBytes.contentType,
      'Cache-Control': `public, max-age=${config.iconCacheTtlSeconds}`,
    },
  });
});

async function fetchIcon(
  domain: string,
): Promise<{ bytes: ArrayBuffer; contentType: string } | null> {
  const headers = {
    'User-Agent':
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36',
  };

  let iconUrl: string | null = null;
  try {
    const page = await fetch(`https://${domain}/`, {
      headers,
      signal: AbortSignal.timeout(5000),
      redirect: 'follow',
    });
    if (page.ok) {
      const html = await page.text();
      const href = extractIconHref(html);
      if (href) iconUrl = new URL(href, `https://${domain}/`).toString();
    }
  } catch {
    // fall through to /favicon.ico
  }
  if (!iconUrl) iconUrl = `https://${domain}/favicon.ico`;

  try {
    const res = await fetch(iconUrl, {
      headers,
      signal: AbortSignal.timeout(5000),
      redirect: 'follow',
    });
    if (!res.ok) return null;
    const contentType = res.headers.get('Content-Type') ?? 'image/x-icon';
    if (!contentType.startsWith('image/')) return null;
    const bytes = await res.arrayBuffer();
    if (bytes.byteLength === 0 || bytes.byteLength > MAX_ICON_BYTES) return null;
    return { bytes, contentType };
  } catch {
    return null;
  }
}
