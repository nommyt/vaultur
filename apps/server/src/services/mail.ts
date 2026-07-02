import type { Config } from '../config';

/**
 * Transactional email via the Cloudflare Email Sending binding.
 * Templates are ports of vaultwarden's src/static/templates/email/*.
 */

/** Structural type for the Email Sending binding's object API. */
export interface EmailBinding {
  send(message: {
    to: string | string[];
    from: { email: string; name?: string } | string;
    replyTo?: string;
    subject: string;
    html?: string;
    text?: string;
  }): Promise<unknown>;
}

export interface Mailer {
  enabled: boolean;
  send(to: string, subject: string, html: string, text: string): Promise<void>;
}

export function createMailer(binding: EmailBinding | undefined, config: Config): Mailer {
  const enabled = Boolean(binding && config.emailFrom);
  return {
    enabled,
    async send(to, subject, html, text) {
      if (!enabled) {
        console.warn(`Mail disabled; skipping "${subject}" to ${to}`);
        return;
      }
      await binding!.send({
        to,
        from: { email: config.emailFrom, name: config.emailFromName },
        subject,
        html,
        text,
      });
    },
  };
}

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------

function layout(title: string, bodyHtml: string, domain: string): string {
  return `<!doctype html>
<html>
<body style="margin:0;padding:0;background:#f6f7fb;font-family:Helvetica,Arial,sans-serif;color:#333;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="padding:24px 0;">
    <tr><td align="center">
      <table role="presentation" width="600" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:8px;overflow:hidden;">
        <tr><td style="background:#175ddc;color:#fff;padding:18px 28px;font-size:18px;font-weight:bold;">Vaultur</td></tr>
        <tr><td style="padding:28px;font-size:15px;line-height:1.6;">
          <h2 style="margin-top:0;font-size:18px;">${title}</h2>
          ${bodyHtml}
        </td></tr>
        <tr><td style="padding:16px 28px;color:#888;font-size:12px;border-top:1px solid #eee;">
          Sent by your Vaultur server — <a href="${domain}" style="color:#175ddc;">${domain}</a>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`;
}

function btn(url: string, label: string): string {
  return `<p style="text-align:center;margin:28px 0;"><a href="${url}" style="background:#175ddc;color:#fff;text-decoration:none;padding:12px 24px;border-radius:6px;font-weight:bold;">${label}</a></p>
<p style="font-size:12px;color:#888;">If the button doesn't work, copy this link into your browser:<br>${url}</p>`;
}

function stripHtml(html: string): string {
  return html
    .replace(/<style[\s\S]*?<\/style>/g, '')
    .replace(/<br\s*\/?>(?=.)/g, '\n')
    .replace(/<\/(p|h\d|tr|div)>/g, '\n')
    .replace(/<[^>]+>/g, '')
    .replace(/&amp;/g, '&')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

async function send(mailer: Mailer, to: string, subject: string, title: string, bodyHtml: string, domain: string) {
  const html = layout(title, bodyHtml, domain);
  await mailer.send(to, subject, html, `${title}\n\n${stripHtml(bodyHtml)}`);
}

const enc = encodeURIComponent;

// ---------------------------------------------------------------------------
// Templates (vaultwarden parity)
// ---------------------------------------------------------------------------

export const mail = {
  async welcome(m: Mailer, cfg: Config, to: string) {
    await send(m, to, 'Welcome', 'Welcome to Vaultur', `<p>Your new account has been created! You can now log in and start storing passwords securely.</p>${btn(cfg.domain, 'Open the web vault')}`, cfg.domain);
  },

  async welcomeMustVerify(m: Mailer, cfg: Config, to: string, userId: string, token: string) {
    const url = `${cfg.domain}/#/verify-email/?userId=${enc(userId)}&token=${enc(token)}`;
    await send(m, to, 'Welcome', 'Welcome to Vaultur', `<p>Your new account has been created. Verify your email address to activate your account.</p>${btn(url, 'Verify Email Address Now')}`, cfg.domain);
  },

  async verifyEmail(m: Mailer, cfg: Config, to: string, userId: string, token: string) {
    const url = `${cfg.domain}/#/verify-email/?userId=${enc(userId)}&token=${enc(token)}`;
    await send(m, to, 'Verify Your Email', 'Verify your email address', `<p>Verify this email address for your account by clicking the link below.</p>${btn(url, 'Verify Email Address Now')}`, cfg.domain);
  },

  async registerVerifyEmail(m: Mailer, cfg: Config, to: string, token: string) {
    const url = `${cfg.domain}/#/finish-signup/?email=${enc(to)}&token=${enc(token)}`;
    await send(m, to, 'Verify your email', 'Verify your email to finish signing up', `<p>To finish creating your account, verify this email address by clicking the link below. This link expires in 30 minutes.</p>${btn(url, 'Verify email')}<p>If you did not request this, you can safely ignore this email.</p>`, cfg.domain);
  },

  async newDeviceLoggedIn(m: Mailer, cfg: Config, to: string, deviceName: string, deviceType: string, ip: string, dt: string) {
    await send(m, to, `New Device Logged In From ${deviceName}`, 'New device logged in', `<p>Your account was just logged into from a new device.</p>
<ul><li><b>Date:</b> ${dt}</li><li><b>IP Address:</b> ${ip}</li><li><b>Device Name:</b> ${deviceName}</li><li><b>Device Type:</b> ${deviceType}</li></ul>
<p>You can deauthorize all devices that have access to your account from the web vault under Settings &gt; My Account &gt; Deauthorize Sessions.</p>`, cfg.domain);
  },

  async incomplete2faLogin(m: Mailer, cfg: Config, to: string, deviceName: string, ip: string, dt: string) {
    await send(m, to, 'Incomplete Two-Step Login From New Device', 'Incomplete two-step login', `<p>Someone attempted to log into your account with the correct master password, but did not provide the correct token or action required to complete two-step login.</p>
<ul><li><b>Date:</b> ${dt}</li><li><b>IP Address:</b> ${ip}</li><li><b>Device:</b> ${deviceName}</li></ul>
<p>If this was not you, change your master password as soon as possible.</p>`, cfg.domain);
  },

  async twofactorEmail(m: Mailer, cfg: Config, to: string, token: string, deviceIp: string) {
    await send(m, to, 'Vaultur Login Verification Code', 'Your verification code', `<p>Your two-step verification code is:</p>
<p style="text-align:center;font-size:28px;letter-spacing:6px;font-weight:bold;">${token}</p>
<p>Use this code to complete logging in (request from ${deviceIp}). The code is valid for 10 minutes.</p>`, cfg.domain);
  },

  async changeEmail(m: Mailer, cfg: Config, to: string, token: string) {
    await send(m, to, 'Your Email Change', 'Confirm your new email', `<p>To finalize changing your email address, enter the following token in the web vault:</p>
<p style="text-align:center;font-size:28px;letter-spacing:6px;font-weight:bold;">${token}</p>
<p>If you did not try to change your email address, contact your administrator.</p>`, cfg.domain);
  },

  async changeEmailExisting(m: Mailer, cfg: Config, to: string, newEmail: string) {
    await send(m, to, 'Your Email Change', 'Email change requested', `<p>A request was just made to change your account's email address to <b>${newEmail}</b>.</p>
<p>If you did not make this request, contact your administrator immediately.</p>`, cfg.domain);
  },

  async deleteAccount(m: Mailer, cfg: Config, to: string, userId: string, token: string) {
    const url = `${cfg.domain}/#/verify-recover-delete?userId=${enc(userId)}&token=${enc(token)}&email=${enc(to)}`;
    await send(m, to, 'Delete Your Account', 'Delete your account', `<p>Click the link below to delete your account.</p>${btn(url, 'Delete Your Account')}<p>If you did not request this email, you can safely ignore it.</p>`, cfg.domain);
  },

  async passwordHint(m: Mailer, cfg: Config, to: string, hint: string | null) {
    const body = hint
      ? `<p>You (or someone) recently requested your master password hint. Your hint is:</p><p style="text-align:center;font-weight:bold;">${hint}</p>`
      : `<p>You (or someone) recently requested your master password hint. Unfortunately, your account does not have a master password hint.</p>`;
    await send(m, to, 'Your Master Password Hint', 'Master password hint', `${body}<p>If you did not request this, you can safely ignore this email.</p>`, cfg.domain);
  },

  async orgInvite(m: Mailer, cfg: Config, to: string, orgName: string, orgId: string, memberId: string, token: string, hasExistingUser: boolean) {
    const params = new URLSearchParams({
      email: to,
      organizationName: orgName,
      organizationId: orgId,
      organizationUserId: memberId,
      token,
    });
    if (hasExistingUser) params.set('orgUserHasExistingUser', 'true');
    const url = `${cfg.domain}/#/accept-organization/?${params.toString()}`;
    await send(m, to, `Join ${orgName}`, `Join ${orgName}`, `<p>You have been invited to join the <b>${orgName}</b> organization.</p>${btn(url, 'Join Organization Now')}<p>If you do not wish to join this organization, you can safely ignore this email.</p>`, cfg.domain);
  },

  async inviteAccepted(m: Mailer, cfg: Config, to: string, invitedEmail: string, orgName: string) {
    await send(m, to, `Invitation to ${orgName} accepted`, 'Invitation accepted', `<p>Your invitation for <b>${invitedEmail}</b> to join <b>${orgName}</b> was accepted. Please confirm the user from the organization members page.</p>`, cfg.domain);
  },

  async inviteConfirmed(m: Mailer, cfg: Config, to: string, orgName: string) {
    await send(m, to, `Invitation to ${orgName} confirmed`, 'Invitation confirmed', `<p>Your invitation to join <b>${orgName}</b> was confirmed. It will now appear under the Organizations section in the web vault.</p>`, cfg.domain);
  },

  async emergencyAccessInvite(m: Mailer, cfg: Config, to: string, emerId: string, grantorName: string, token: string) {
    const params = new URLSearchParams({ id: emerId, name: grantorName, email: to, token });
    const url = `${cfg.domain}/#/accept-emergency/?${params.toString()}`;
    await send(m, to, `Emergency access contact request from ${grantorName}`, 'Emergency access invitation', `<p><b>${grantorName}</b> has invited you to become an emergency access contact.</p>${btn(url, 'Become emergency access contact')}<p>If you do not wish to accept, you can safely ignore this email.</p>`, cfg.domain);
  },

  async emergencyAccessInviteAccepted(m: Mailer, cfg: Config, to: string, granteeEmail: string) {
    await send(m, to, 'Accepted Emergency Access', 'Emergency access accepted', `<p><b>${granteeEmail}</b> has accepted your emergency access invitation. Confirm them from your emergency access settings.</p>`, cfg.domain);
  },

  async emergencyAccessInviteConfirmed(m: Mailer, cfg: Config, to: string, grantorName: string) {
    await send(m, to, 'Confirmed as Emergency Access Contact', 'Emergency access confirmed', `<p>You have been confirmed as an emergency access contact for <b>${grantorName}</b>.</p>`, cfg.domain);
  },

  async emergencyAccessRecoveryInitiated(m: Mailer, cfg: Config, to: string, granteeName: string, atype: string, waitDays: number) {
    await send(m, to, 'Emergency Access Initiated', 'Emergency access initiated', `<p><b>${granteeName}</b> has initiated emergency access to <b>${atype}</b> your account. You have ${waitDays} day(s) to reject this request before access is automatically approved.</p>`, cfg.domain);
  },

  async emergencyAccessRecoveryApproved(m: Mailer, cfg: Config, to: string, grantorName: string) {
    await send(m, to, 'Emergency Access Approved', 'Emergency access approved', `<p><b>${grantorName}</b> has approved your emergency access request.</p>`, cfg.domain);
  },

  async emergencyAccessRecoveryRejected(m: Mailer, cfg: Config, to: string, grantorName: string) {
    await send(m, to, 'Emergency Access Rejected', 'Emergency access rejected', `<p><b>${grantorName}</b> has rejected your emergency access request.</p>`, cfg.domain);
  },

  async emergencyAccessRecoveryReminder(m: Mailer, cfg: Config, to: string, granteeName: string, atype: string, daysLeft: number) {
    await send(m, to, 'Pending Emergency Access Request', 'Pending emergency access request', `<p><b>${granteeName}</b> has a pending request for emergency access to <b>${atype}</b> your account. Access will be granted in ${daysLeft} day(s) unless you reject it.</p>`, cfg.domain);
  },

  async emergencyAccessRecoveryTimedOut(m: Mailer, cfg: Config, to: string, granteeName: string, atype: string) {
    await send(m, to, 'Emergency Access Granted', 'Emergency access granted', `<p>The wait period for <b>${granteeName}</b>'s emergency access request (${atype}) has elapsed and access has been granted.</p>`, cfg.domain);
  },

  async twoFactorRemovedFromOrg(m: Mailer, cfg: Config, to: string, orgName: string) {
    await send(m, to, `Removed from ${orgName}`, 'Removed from organization', `<p>You were removed from <b>${orgName}</b> because it requires two-step login on your account.</p>`, cfg.domain);
  },

  async singleOrgRemovedFromOrg(m: Mailer, cfg: Config, to: string, orgName: string) {
    await send(m, to, `Removed from ${orgName}`, 'Removed from organization', `<p>You were removed from <b>${orgName}</b> because its policy requires membership in a single organization only.</p>`, cfg.domain);
  },

  async adminResetPassword(m: Mailer, cfg: Config, to: string, userName: string, orgName: string) {
    await send(m, to, `Master Password Has Been Changed`, 'Master password reset', `<p>The master password for <b>${userName}</b> was recently reset by an administrator of <b>${orgName}</b>. Log in with the new master password given to you.</p>`, cfg.domain);
  },

  async protectedAction(m: Mailer, cfg: Config, to: string, token: string) {
    await send(m, to, 'Your Vaultur Verification Code', 'Verification code', `<p>Your verification code for this protected action is:</p>
<p style="text-align:center;font-size:28px;letter-spacing:6px;font-weight:bold;">${token}</p>
<p>The code is valid for 10 minutes.</p>`, cfg.domain);
  },
};
