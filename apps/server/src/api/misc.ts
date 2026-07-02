import { Hono } from 'hono';
import type { AppEnv } from '../env';
import { requireAuth } from '../auth/middleware';
import { errCode } from '../error';

export const miscRoutes = new Hono<AppEnv>();

miscRoutes.use('*', requireAuth);

// FIDO2/WebAuthn login credentials list — no credentials until webauthn 2FA ships
miscRoutes.get('/webauthn', (c) => c.json({ data: [], object: 'list', continuationToken: null }));

// HIBP breach report proxy — vaultwarden requires an API key; without one,
// clients show a friendly error.
miscRoutes.get('/hibp/breach', (c) => {
  const username = c.req.query('username') ?? '';
  return c.json(
    [
      {
        name: 'HaveIBeenPwned',
        title: 'Manual HIBP Check',
        domain: 'haveibeenpwned.com',
        breachDate: '2019-08-18T00:00:00Z',
        addedDate: '2019-08-18T00:00:00Z',
        description: `Go to: <a href="https://haveibeenpwned.com/account/${encodeURIComponent(username)}" target="_blank" rel="noreferrer">https://haveibeenpwned.com/account/${encodeURIComponent(username)}</a> for a manual check.<br/><br/>HaveIBeenPwned API key not set!`,
        logoPath: 'vw_static/hibp.png',
        pwnCount: 0,
        dataClasses: [],
      },
    ],
    200,
  );
});
