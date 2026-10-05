import { Global, Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AppConfig } from '../config/configuration';
import { AuthorizationModule } from '../authorization/authorization.module';
import { IdentityModule } from '../identity/identity.module';
import { ConfirmEmailVerificationUseCase } from './application/use-cases/confirm-email-verification.use-case';
import { ConfirmPasswordResetUseCase } from './application/use-cases/confirm-password-reset.use-case';
import { GetAuditLogForUserUseCase } from './application/use-cases/get-audit-log-for-user.use-case';
import { RecordAuditEventUseCase } from './application/use-cases/record-audit-event.use-case';
import { RequestEmailVerificationUseCase } from './application/use-cases/request-email-verification.use-case';
import { RequestPasswordResetUseCase } from './application/use-cases/request-password-reset.use-case';
import { UserRegisteredVerificationRequester } from './application/event-handlers/user-registered.handler';
import { MailSenderDispatcher } from './application/event-handlers/mail-sender.dispatcher';
import { EngagementAuditLogHandler } from './application/event-handlers/engagement-audit-log.handler';
import { AUDIT_LOG_REPOSITORY } from './domain/ports/audit-log.repository.port';
import { EMAIL_VERIFICATION_REPOSITORY } from './domain/ports/email-verification.repository.port';
import { MAIL_SENDER } from './domain/ports/mail-sender.port';
import { PASSWORD_RESET_REPOSITORY } from './domain/ports/password-reset.repository.port';
import { LogMailSender } from './infrastructure/mail/log-mail-sender';
import { SendgridMailSender } from './infrastructure/mail/sendgrid-mail-sender';
import { SmtpMailSender } from './infrastructure/mail/smtp-mail-sender';
import { PrismaAuditLogRepository } from './infrastructure/persistence/prisma-audit-log.repository';
import { PrismaEmailVerificationRepository } from './infrastructure/persistence/prisma-email-verification.repository';
import { PrismaPasswordResetRepository } from './infrastructure/persistence/prisma-password-reset.repository';
import { Sha256TokenService } from './infrastructure/security/sha256-token.service';
import { EngagementController } from './interfaces/http/engagement.controller';
import { EngagementResolver } from './interfaces/graphql/engagement.resolver';

/**
 * Engagement bounded context — Nest wiring.
 *
 * The MailSender adapter is selected at module init from `EMAIL_TRANSPORT`:
 *   * `log`       — LogMailSender (default for dev)
 *   * `smtp`      — SmtpMailSender
 *   * `sendgrid`  — SendgridMailSender
 *
 * Other bounded contexts (Identity, Authentication) can inject
 * `RecordAuditEventUseCase` to write to the audit log.
 *
 * Marked `@Global()` (V1.5) so the admin app can also import this
 * module and reach `AuditLogRepository` / `MailSender` without
 * having to re-export each one.
 */
@Global()
@Module({
  // IdentityModule is imported (not just relied-upon as @Global()) so
  // that `UserRepository` is visible to `MailSenderDispatcher`'s
  // constructor-injection. Even though IdentityModule is itself
  // `@Global()`, the engagement module's provider scan requires the
  // import to be explicit.
  imports: [IdentityModule, AuthorizationModule],
  controllers: [EngagementController],
  providers: [
    // Infrastructure
    Sha256TokenService,
    PrismaEmailVerificationRepository,
    PrismaPasswordResetRepository,
    PrismaAuditLogRepository,
    LogMailSender,
    SmtpMailSender,
    SendgridMailSender,
    {
      provide: EMAIL_VERIFICATION_REPOSITORY,
      useClass: PrismaEmailVerificationRepository,
    },
    {
      provide: PASSWORD_RESET_REPOSITORY,
      useClass: PrismaPasswordResetRepository,
    },
    {
      provide: AUDIT_LOG_REPOSITORY,
      useClass: PrismaAuditLogRepository,
    },
    // Mail sender — selected via factory based on EMAIL_TRANSPORT config.
    {
      provide: MAIL_SENDER,
      inject: [
        ConfigService,
        LogMailSender,
        SmtpMailSender,
        SendgridMailSender,
      ],
      useFactory: (
        config: ConfigService,
        log: LogMailSender,
        smtp: SmtpMailSender,
        sendgrid: SendgridMailSender,
      ) => {
        const transport =
          config.getOrThrow<AppConfig['email']['transport']>('email.transport');
        if (transport === 'smtp') return smtp;
        if (transport === 'sendgrid') return sendgrid;
        return log;
      },
    },

    // Use-cases
    RequestEmailVerificationUseCase,
    ConfirmEmailVerificationUseCase,
    RequestPasswordResetUseCase,
    ConfirmPasswordResetUseCase,
    RecordAuditEventUseCase,
    GetAuditLogForUserUseCase,

    // Cross-context event handler
    UserRegisteredVerificationRequester,
    MailSenderDispatcher,
    EngagementAuditLogHandler,

    // GraphQL resolver
    EngagementResolver,
  ],
  exports: [
    RequestEmailVerificationUseCase,
    ConfirmEmailVerificationUseCase,
    RequestPasswordResetUseCase,
    ConfirmPasswordResetUseCase,
    RecordAuditEventUseCase,
    GetAuditLogForUserUseCase,
    MAIL_SENDER,
    AUDIT_LOG_REPOSITORY,
    EMAIL_VERIFICATION_REPOSITORY,
    PASSWORD_RESET_REPOSITORY,
  ],
})
export class EngagementModule {}
