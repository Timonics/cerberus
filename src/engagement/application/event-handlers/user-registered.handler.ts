import { Inject, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { EVENT_BUS, EventBus } from '../../../shared/domain';
import { UserRegistered } from '../../../identity/domain/events/identity.events';
import { RequestEmailVerificationUseCase } from '../use-cases/request-email-verification.use-case';

/**
 * Cross-context event handler: when a user registers, immediately
 * request an email-verification token so the welcome email goes out
 * with a fresh verification link.
 *
 * We don't await the email send here — that happens in the mail
 * sender subscriber. We just trigger the token issuance.
 */
@Injectable()
export class UserRegisteredVerificationRequester implements OnModuleInit {
  private readonly logger = new Logger(
    UserRegisteredVerificationRequester.name,
  );

  public constructor(
    @Inject(EVENT_BUS) private readonly bus: EventBus,
    private readonly requestEmailVerificationUc: RequestEmailVerificationUseCase,
  ) {}

  public onModuleInit(): void {
    this.bus.subscribe('identity.user.registered', async (event) => {
      if (event instanceof UserRegistered) {
        await this.handle(event);
      }
    });
  }

  public async handle(event: UserRegistered): Promise<void> {
    try {
      await this.requestEmailVerificationUc.execute({
        userId: event.userId.value,
      });
    } catch (err) {
      this.logger.error(
        `Failed to issue email-verification token for newly-registered user ${event.userId.value}: ${String(err)}`,
      );
    }
  }
}
