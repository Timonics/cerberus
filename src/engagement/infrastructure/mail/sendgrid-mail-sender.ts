import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AppConfig } from '../../../config/configuration';
import { MailMessage, MailSender } from '../../domain/ports/mail-sender.port';

/**
 * SendGrid HTTP API mail sender.
 *
 * Hits `https://api.sendgrid.com/v3/mail/send` directly — no extra
 * dependencies (no `@sendgrid/mail` package). SendGrid recommends
 * HTTPS for everything; the API key is sent as a bearer token.
 *
 * If `SENDGRID_API_KEY` is unset, `send()` throws — the module wiring
 * should not bind this adapter unless the key is present.
 */
@Injectable()
export class SendgridMailSender extends MailSender {
  private readonly logger = new Logger(SendgridMailSender.name);
  private readonly apiKey: string;
  private readonly fromAddress: string;

  public constructor(configService: ConfigService) {
    super();
    this.apiKey =
      configService.getOrThrow<AppConfig['email']['sendgrid']>(
        'email.sendgrid',
      ).apiKey;
    this.fromAddress =
      configService.getOrThrow<AppConfig['email']['from']>('email.from');
    // We intentionally don't throw at construction time even if the
    // API key is empty — NestJS instantiates ALL providers eagerly,
    // and that would prevent the app from booting when using a
    // different transport (log/smtp). We throw on `send()` instead.
  }

  public async send(message: MailMessage): Promise<void> {
    if (!this.apiKey) {
      throw new Error(
        'SendgridMailSender requires SENDGRID_API_KEY — set it in env or use a different transport',
      );
    }
    const body = {
      personalizations: [{ to: [{ email: message.to }] }],
      from: { email: this.fromAddress },
      subject: message.subject,
      content: [
        { type: 'text/plain', value: message.text },
        ...(message.html ? [{ type: 'text/html', value: message.html }] : []),
      ],
    };

    const res = await fetch('https://api.sendgrid.com/v3/mail/send', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      const text = await res.text();
      this.logger.error(
        `SendGrid send failed status=${res.status} body=${text.slice(0, 200)}`,
      );
      throw new Error(`SendGrid API returned ${res.status}`);
    }
  }
}
