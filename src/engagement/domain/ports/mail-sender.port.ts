/**
 * Outbound port for sending transactional email.
 *
 * The infrastructure layer provides three adapters:
 *   * `LogMailSender` — console-log every email (dev).
 *   * `SmtpMailSender` — nodemailer + SMTP relay.
 *   * `SendgridMailSender` — SendGrid HTTP API.
 *
 * Selection is driven by `EMAIL_TRANSPORT` config (one adapter per
 * process). The `MailSender` interface is intentionally minimal — no
 * attachments, no templates, just plain text + HTML body + subject +
 * recipients. Templating happens at the call site.
 */
export interface MailMessage {
  readonly to: string;
  readonly subject: string;
  readonly text: string;
  readonly html?: string;
}

export abstract class MailSender {
  public abstract send(message: MailMessage): Promise<void>;
}

export const MAIL_SENDER = Symbol('MailSender');
