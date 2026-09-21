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

export interface RequestPasswordResetResult {
  /** The plaintext token (returned exactly once). Empty string if the email is unknown. */
  token: string;
  expiresAt: Date | null;
}

/**
 * Request a password-reset token.
 *
 * Looks up the user by email. If the user exists, generates a fresh
 * token and persists the hash. If the user does NOT exist, returns an
 * empty token (no token created). The HTTP status code is the same in
 * both cases (200/204) so we don't leak account existence.
 *
 * Per your explicit requirement, password reset requires email
 * confirmation — this endpoint issues the token; `ConfirmPasswordReset`
 * validates it and rotates the password.
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

  public async execute(
    input: RequestPasswordResetInput,
  ): Promise<RequestPasswordResetResult> {
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
      return { token: '', expiresAt: null };
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

    return {
      token: plaintext,
      expiresAt: result.reset.expiresAt,
    };
  }
}
