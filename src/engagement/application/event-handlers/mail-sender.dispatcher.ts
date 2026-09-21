import { Inject, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  EVENT_BUS,
  EventBus,
  TRANSACTION_RUNNER,
  TransactionRunner,
  Tx,
} from '../../../shared/domain';
import { AppConfig } from '../../../config/configuration';
import {
  EmailVerificationRequested,
  PasswordResetRequested,
} from '../../domain/events/engagement.events';
import { MAIL_SENDER, MailSender } from '../../domain/ports/mail-sender.port';
import {
  emailVerificationTemplate,
  passwordResetTemplate,
} from '../../infrastructure/mail/email-templates';
import {
  USER_REPOSITORY,
  UserRepository,
} from '../../../identity/domain/ports/user.repository.port';
import { UserId } from '../../../identity/domain/value-objects/user-id';

/**
 * Cross-context event handler: when an email-verification or
 * password-reset token is requested, actually send the email.
 *
 * V1.5 fix: previously the `engagement.email_verification.requested`
 * and `engagement.password_reset.requested` events fired but no
 * subscriber consumed them. As a result, users who registered never
 * received their verification email, and password-reset requests
 * looked like they succeeded but the user never got the link. This
 * handler closes that loop.
 *
 * The plaintext token travels in the event payload (never persisted)
 * — we use it once here to build the link, then it stays in the
 * in-process event bus until the process exits.
 *
 * Failures are logged but do not throw — the token is already
 * persisted (in hashed form) and the user can request a new one
 * later if this delivery fails.
 */
@Injectable()
export class MailSenderDispatcher implements OnModuleInit {
  private readonly logger = new Logger(MailSenderDispatcher.name);

  public constructor(
    @Inject(EVENT_BUS) private readonly bus: EventBus,
    @Inject(MAIL_SENDER) private readonly mailSender: MailSender,
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    private readonly config: ConfigService,
    @Inject(USER_REPOSITORY) private readonly userRepo: UserRepository,
  ) {}

  public onModuleInit(): void {
    this.bus.subscribe(
      'engagement.email_verification.requested',
      async (event) => {
        if (event instanceof EmailVerificationRequested) {
          await this.handleVerification(event);
        }
      },
    );
    this.bus.subscribe('engagement.password_reset.requested', async (event) => {
      if (event instanceof PasswordResetRequested) {
        await this.handlePasswordReset(event);
      }
    });
  }
  private async handleVerification(
    event: EmailVerificationRequested,
  ): Promise<void> {
    try {
      const user = await this.txRunner.run(async (tx: Tx) =>
        this.userRepo.findById(tx, UserId.create(event.userId)),
      );
      if (!user) {
        this.logger.warn(
          `EmailVerificationRequested for unknown user ${event.userId}, skipping send`,
        );
        return;
      }

      const publicUrl =
        this.config.getOrThrow<AppConfig['email']['publicUrl']>(
          'email.publicUrl',
        );
      const ttlSeconds = 60 * 60 * 24; // 24 hours
      const tpl = emailVerificationTemplate({
        displayName: user.displayName,
        verificationUrl: `${publicUrl}/v1/engagement/email-verification/confirm?token=${event.plaintextToken}`,
        expiresInHours: ttlSeconds / 3600,
      });

      await this.mailSender.send({
        to: user.email.value,
        subject: tpl.subject,
        text: tpl.text,
        html: tpl.html,
      });
      this.logger.log(`Sent verification email to ${user.email.value}`);
    } catch (err) {
      this.logger.error(
        `Failed to send verification email for user ${event.userId}: ${String(err)}`,
      );
    }
  }

  private async handlePasswordReset(
    event: PasswordResetRequested,
  ): Promise<void> {
    try {
      const user = await this.txRunner.run(async (tx: Tx) =>
        this.userRepo.findById(tx, UserId.create(event.userId)),
      );
      if (!user) {
        this.logger.warn(
          `PasswordResetRequested for unknown user ${event.userId}, skipping send`,
        );
        return;
      }

      const publicUrl =
        this.config.getOrThrow<AppConfig['email']['publicUrl']>(
          'email.publicUrl',
        );
      const ttlSeconds = 60 * 60; // 1 hour
      const tpl = passwordResetTemplate({
        displayName: user.displayName,
        resetUrl: `${publicUrl}/v1/engagement/password-reset/confirm?token=${event.plaintextToken}`,
        expiresInHours: ttlSeconds / 3600,
      });

      await this.mailSender.send({
        to: user.email.value,
        subject: tpl.subject,
        text: tpl.text,
        html: tpl.html,
      });
      this.logger.log(`Sent password-reset email to ${user.email.value}`);
    } catch (err) {
      this.logger.error(
        `Failed to send password-reset email for user ${event.userId}: ${String(err)}`,
      );
    }
  }
}
