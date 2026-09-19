import { Injectable, Logger } from '@nestjs/common';
import { MailMessage, MailSender } from '../../domain/ports/mail-sender.port';

/**
 * Default mail sender — logs the email to stdout.
 *
 * V1 default. Useful in dev (you see the verification link in the
 * server log) and in tests. Production deployments should switch to
 * `smtp` or `sendgrid` via `EMAIL_TRANSPORT` env var.
 *
 * The log is structured (one line per email with all fields) so it
 * can be grep'd by ops.
 */
@Injectable()
export class LogMailSender extends MailSender {
  private readonly logger = new Logger(LogMailSender.name);

  public send(message: MailMessage): Promise<void> {
    this.logger.log(
      `[email] to=${message.to} subject=${JSON.stringify(message.subject)} text=${JSON.stringify(message.text.slice(0, 120))}${message.html ? ' (with html)' : ''}`,
    );
    return Promise.resolve();
  }
}
