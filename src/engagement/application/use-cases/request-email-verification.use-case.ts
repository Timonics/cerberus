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
import { UserId } from '../../../identity/domain/value-objects/user-id';
import { EmailVerificationRequested } from '../../domain/events/engagement.events';
import { EmailVerification } from '../../domain/aggregates/email-verification';
import {
  EMAIL_VERIFICATION_REPOSITORY,
  EmailVerificationRepository,
} from '../../domain/ports/email-verification.repository.port';
import {
  USER_REPOSITORY,
  UserRepository,
} from '../../../identity/domain/ports/user.repository.port';
import { Sha256TokenService } from '../../infrastructure/security/sha256-token.service';

export interface RequestEmailVerificationInput {
  userId: string;
}

export interface RequestEmailVerificationResult {
  /** The plaintext token (returned exactly once). */
  token: string;
  expiresAt: Date;
}

/**
 * Issue an email-verification token.
 *
 * Generates a fresh random token, stores its SHA-256 hash, and emits
 * `EmailVerificationRequested` so downstream consumers (mail sender,
 * audit log) can react. The plaintext token is returned to the caller
 * (controller) exactly once.
 *
 * If an un-consumed token already exists for this user, we revoke it
 * and issue a fresh one. (Otherwise the user would receive two
 * verification emails and either could be used — confusing UX.)
 */
@Injectable()
export class RequestEmailVerificationUseCase {
  private readonly logger = new Logger(RequestEmailVerificationUseCase.name);
  private readonly ttlSeconds = 24 * 60 * 60; // 24h

  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(CLOCK) private readonly clock: Clock,
    @Inject(ID_GENERATOR) private readonly idGenerator: IdGenerator,
    @Inject(EVENT_BUS) private readonly eventBus: EventBus,
    @Inject(EMAIL_VERIFICATION_REPOSITORY)
    private readonly repo: EmailVerificationRepository,
    @Inject(USER_REPOSITORY)
    private readonly userRepo: UserRepository,
    private readonly tokenService: Sha256TokenService,
  ) {}

  public async execute(
    input: RequestEmailVerificationInput,
  ): Promise<RequestEmailVerificationResult> {
    const userId = UserId.create(input.userId);

    // V1.7 audit fix #22: short-circuit if the user's email is
    // already verified. Pre-fix the use case generated a token +
    // emitted a "verification requested" event every time the
    // endpoint was hit, which let any caller spam the mail
    // pipeline for an already-verified user. The controller
    // surfaces 204 (no-op) in that case.
    const alreadyVerified = await this.txRunner.run<boolean>(async (tx: Tx) => {
      const user = await this.userRepo.findById(tx, userId);
      return (
        user?.emailVerifiedAt !== null && user?.emailVerifiedAt !== undefined
      );
    });
    if (alreadyVerified) {
      return { token: '', expiresAt: new Date(0) };
    }

    const plaintext = this.tokenService.generatePlaintext();
    const tokenHash = this.tokenService.hash(plaintext);

    const verification = await this.txRunner.run<EmailVerification>(
      async (tx: Tx) => {
        // Revoke any pre-existing unconsumed token for this user.
        const existing = await this.repo.findActiveByUserId(tx, userId);
        if (existing) {
          await this.repo.delete(tx, existing.id);
        }
        const v = EmailVerification.create({
          id: this.idGenerator.generate(),
          userId,
          tokenHash,
          clock: this.clock,
          ttlSeconds: this.ttlSeconds,
        });
        return this.repo.save(tx, v);
      },
    );

    await this.eventBus.publishAll([
      new EmailVerificationRequested(
        this.idGenerator.generate(),
        this.clock.now(),
        verification.userId.value,
        verification.id,
        plaintext,
      ),
    ]);

    void this.logger; // reserved for future per-user rate-limit log

    return {
      token: plaintext,
      expiresAt: verification.expiresAt,
    };
  }
}
