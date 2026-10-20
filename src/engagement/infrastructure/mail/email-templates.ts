/**
 * Email templates.
 *
 * One function per email type. Each returns `{subject, text, html}`
 * suitable for direct use with `MailSender.send()`.
 *
 * Templating is intentionally minimal — no template engine, just
 * string interpolation. The link URL is provided as a parameter so
 * the templates don't depend on the base URL configuration.
 *
 * 2026-10-19 audit MEDIUM (template escaping): every piece of USER
 * text (displayName) is HTML-escaped before it reaches the HTML body
 * — the templates interpolate through `escapeHtml`. URLs are built by
 * trusted code (not user input) and are asserted against the
 * configured `EMAIL_PUBLIC_URL` origin by the caller before building
 * (see `assertTrustedUrl`), so they are kept as-is.
 */

/**
 * Minimal HTML escaper for interpolated user text. Covers the five
 * characters that matter in element content and double-quoted
 * attribute values.
 */
export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Assert that `url` starts with the configured public-origin prefix.
 * The mail dispatcher calls this BEFORE handing the URL to a template
 * so a misconfigured/malicious `EMAIL_PUBLIC_URL` can never turn an
 * email into an open-redirect / phishing vehicle.
 */
export function assertTrustedUrl(url: string, publicOrigin: string): string {
  const origin = publicOrigin.endsWith('/')
    ? publicOrigin.slice(0, -1)
    : publicOrigin;
  if (!url.startsWith(`${origin}/`)) {
    throw new Error(
      'Refusing to build an email link outside the configured EMAIL_PUBLIC_URL origin',
    );
  }
  return url;
}

/**
 * Email-verification email.
 *
 * V1: link points at `verificationUrl`. The user clicks → the web app
 * should hit `POST /v1/engagement/email-verification/confirm` with
 * `{token}` in the body. The web app is out of scope for V1.
 */
export function emailVerificationTemplate(params: {
  displayName: string | null;
  verificationUrl: string;
  expiresInHours: number;
}): { subject: string; text: string; html: string } {
  const greeting = params.displayName ? `Hi ${params.displayName},` : 'Hi,';
  const safeGreeting =
    params.displayName !== null
      ? `Hi ${escapeHtml(params.displayName)},`
      : 'Hi,';
  const subject = 'Verify your Cerberus email address';
  const text = [
    greeting,
    '',
    'Welcome to Cerberus. Please verify your email address by visiting:',
    '',
    params.verificationUrl,
    '',
    `This link expires in ${params.expiresInHours} hours.`,
    '',
    'If you did not sign up, you can ignore this email.',
    '',
    '— The Cerberus team',
  ].join('\n');
  const html = [
    `<p>${safeGreeting}</p>`,
    '<p>Welcome to Cerberus. Please verify your email address by visiting:</p>',
    `<p><a href="${params.verificationUrl}">${params.verificationUrl}</a></p>`,
    `<p>This link expires in ${params.expiresInHours} hours.</p>`,
    '<p>If you did not sign up, you can ignore this email.</p>',
    '<p>— The Cerberus team</p>',
  ].join('\n');
  return { subject, text, html };
}

/**
 * Password-reset email.
 *
 * Per your explicit requirement, password reset requires confirmation
 * via this token. The link points at a page in the consumer app that
 * prompts for a new password and POSTs `{token, newPassword}` to
 * `POST /v1/engagement/password-reset/confirm`.
 */
export function passwordResetTemplate(params: {
  displayName: string | null;
  resetUrl: string;
  expiresInHours: number;
}): { subject: string; text: string; html: string } {
  const greeting = params.displayName ? `Hi ${params.displayName},` : 'Hi,';
  const safeGreeting =
    params.displayName !== null
      ? `Hi ${escapeHtml(params.displayName)},`
      : 'Hi,';
  const subject = 'Reset your Cerberus password';
  const text = [
    greeting,
    '',
    'We received a request to reset your Cerberus password.',
    '',
    'If you made this request, follow this link to set a new password:',
    '',
    params.resetUrl,
    '',
    `This link expires in ${params.expiresInHours} hours.`,
    '',
    "If you didn't request this, you can safely ignore this email —",
    'your password will remain unchanged.',
    '',
    '— The Cerberus team',
  ].join('\n');
  const html = [
    `<p>${safeGreeting}</p>`,
    '<p>We received a request to reset your Cerberus password.</p>',
    '<p>If you made this request, follow this link to set a new password:</p>',
    `<p><a href="${params.resetUrl}">${params.resetUrl}</a></p>`,
    `<p>This link expires in ${params.expiresInHours} hours.</p>`,
    "<p>If you didn't request this, you can safely ignore this email — your password will remain unchanged.</p>",
    '<p>— The Cerberus team</p>',
  ].join('\n');
  return { subject, text, html };
}
