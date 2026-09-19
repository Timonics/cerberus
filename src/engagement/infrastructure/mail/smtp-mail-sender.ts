import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';
import { AppConfig } from '../../../config/configuration';
import { MailMessage, MailSender } from '../../domain/ports/mail-sender.port';

/**
 * SMTP mail sender (nodemailer).
 *
 * Connects to whatever SMTP relay is configured via
 * `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASSWORD` /
 * `SMTP_SECURE`. Used both for direct-SMTP setups (Mailgun, Postmark,
 * generic SMTP) and via MailHog/Mailpit in dev.
 *
 * V1 supports plain SMTP only. If `SMTP_USER` is empty, we attempt
 * unauthenticated SMTP (useful for Mailpit on localhost).
 */
@Injectable()
export class SmtpMailSender extends MailSender {
  private readonly logger = new Logger(SmtpMailSender.name);
  private readonly transporter: nodemailer.Transporter;
  private readonly fromAddress: string;

  public constructor(configService: ConfigService) {
    super();
    const smtp =
      configService.getOrThrow<AppConfig['email']['smtp']>('email.smtp');
    this.fromAddress =
      configService.getOrThrow<AppConfig['email']['from']>('email.from');
    this.transporter = nodemailer.createTransport({
      host: smtp.host,
      port: smtp.port,
      secure: smtp.secure,
      auth:
        smtp.user || smtp.password
          ? { user: smtp.user, pass: smtp.password }
          : undefined,
    });
  }

  public async send(message: MailMessage): Promise<void> {
    try {
      await this.transporter.sendMail({
        from: this.fromAddress,
        to: message.to,
        subject: message.subject,
        text: message.text,
        html: message.html,
      });
    } catch (err) {
      this.logger.error(
        `SMTP send failed to=${message.to} subject=${message.subject}: ${String(err)}`,
      );
      throw err;
    }
  }
}
