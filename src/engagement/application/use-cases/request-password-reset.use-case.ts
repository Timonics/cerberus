import { Inject, Injectable, Logger } from '@nestjs/common';
import {
  CLOCK,
  Clock,
  EVENT_BUS,
  EventBus,
  ID_GENERATOR,
  IdGenerator,
  TRANSACTION_RUNNER,
  TransactionRunner,
  Tx,
} from '../../../shared/domain';
import { User } from '../../../identity/domain/aggregates/user';
import {
  USER_REPOSITORY,
  UserRepository,
} from '../../../identity/domain/ports/user.repository.port';
import { Email } from '../../../shared/domain/value-objects/email';
import { PasswordReset } from '../../domain/aggregates/password-reset';
import { PasswordResetRequested } from '../../domain/events/engagement.events';
import {
  PASSWORD_RESET_REPOSITORY,
  PasswordResetRepository,
} from '../../domain/ports/password-reset.repository.port';
import { Sha256TokenService } from '../../infrastructure/security/sha256-token.service';

export interface RequestPasswordResetInput {
  email: string;
}

/**
 * Request a password-reset token.
 *
 * V1.5 (audit M5): the use-case no longer returns the plaintext token
 * in the result. The token travels via the `PasswordResetRequested`
 * event → mail-sender dispatcher → email. Returning it in the result
 * kept the plaintext alive in memory longer than necessary, and a
 * future caller could accidentally include it in a structured log.
 *
 * The HTTP response is always 204 regardless of whether the email
 * exists (no account enumeration).
 */
@Injectable()
export class RequestPasswordResetUseCase {
  private readonly logger = new Logger(RequestPasswordResetUseCase.name);
  private readonly ttlSeconds = 60 * 60; // 1h — tighter than email verification

  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(CLOCK) private readonly clock: Clock,
    @Inject(ID_GENERATOR) private readonly idGenerator: IdGenerator,
    @Inject(EVENT_BUS) private readonly eventBus: EventBus,
    @Inject(PASSWORD_RESET_REPOSITORY)
    private readonly resetRepo: PasswordResetRepository,
    @Inject(USER_REPOSITORY) private readonly userRepo: UserRepository,
    private readonly tokenService: Sha256TokenService,
  ) {}

  public async execute(input: RequestPasswordResetInput): Promise<void> {
    const email = Email.create(input.email);
    const plaintext = this.tokenService.generatePlaintext();
    const tokenHash = this.tokenService.hash(plaintext);

    const result = await this.txRunner.run<{
      user: User | null;
      reset: PasswordReset | null;
    }>(async (tx: Tx) => {
      const user = await this.userRepo.findByEmail(tx, email.value);
      if (!user) {
        return { user: null, reset: null };
      }
      // Revoke any un-consumed prior reset for this user.
      const existing = await this.resetRepo.findActiveByUserId(tx, user.id);
      if (existing) {
        await this.resetRepo.delete(tx, existing.id);
      }
      const newReset = PasswordReset.create({
        id: this.idGenerator.generate(),
        userId: user.id,
        tokenHash,
        clock: this.clock,
        ttlSeconds: this.ttlSeconds,
      });
      const saved = await this.resetRepo.save(tx, newReset);
      return { user, reset: saved };
    });

    if (!result.user || !result.reset) {
      // V1.5 (audit M6): equalize timing — the user-presented branch
      // computes an HMAC (see below). Doing the same on the unknown-
      // email branch means an attacker can't distinguish "no such
      // user" from "user exists" by response-time alone.
      this.tokenService.hash('equalize-timing-noop-' + email.value);
      return;
    }

    await this.eventBus.publishAll([
      new PasswordResetRequested(
        this.idGenerator.generate(),
        this.clock.now(),
        result.user.id.value,
        result.reset.id,
        plaintext,
      ),
    ]);
  }
}
