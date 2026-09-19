import { Inject, Injectable } from '@nestjs/common';
import {
  CLOCK,
  Clock,
  DomainError,
  EVENT_BUS,
  EventBus,
  ID_GENERATOR,
  IdGenerator,
  TRANSACTION_RUNNER,
  TransactionRunner,
  Tx,
} from '../../../shared/domain';
import { Session } from '../../../authentication/domain/aggregates/session';
import { SessionRevoked } from '../../../authentication/domain/events/auth.events';
import {
  SESSION_REPOSITORY,
  SessionRepository,
} from '../../../authentication/domain/ports/session.repository.port';

export interface RevokeTokenInput {
  token: string;
  tokenTypeHint?: 'access_token' | 'refresh_token';
}

/**
 * RFC 7009 token revocation.
 *
 * For refresh tokens: we look up the session by hash and revoke it. If
 * we find a session, we emit `SessionRevoked(..., 'ADMIN_REVOKED')`.
 *
 * For access tokens: we cannot revoke them directly (JWTs are stateless).
 * The standard practice is to use the introspect endpoint + a revocation
 * list, or to rotate the signing key (forces ALL tokens signed with
 * the old key to be invalid). V1: revoking an access token returns
 * `200 OK` with no action — the spec says revocation of an unsupported
 * token type is a no-op.
 *
 * Always returns `200 OK` per the spec (regardless of whether anything
 * was actually revoked).
 */
@Injectable()
export class RevokeTokenUseCase {
  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(CLOCK) private readonly clock: Clock,
    @Inject(ID_GENERATOR) private readonly idGenerator: IdGenerator,
    @Inject(EVENT_BUS) private readonly eventBus: EventBus,
    @Inject(SESSION_REPOSITORY) private readonly sessionRepo: SessionRepository,
  ) {}

  public async execute(input: RevokeTokenInput): Promise<void> {
    const hint = input.tokenTypeHint ?? 'refresh_token';

    if (hint === 'access_token') {
      // Cannot revoke JWTs. Per RFC 7009, return success without action.
      return;
    }

    const { RefreshTokenHash } =
      await import('../../../authentication/domain/value-objects/refresh-token-hash');
    const presentedHash = await RefreshTokenHash.fromPlaintext(input.token);

    const session = await this.txRunner.run<Session | null>(async (tx: Tx) => {
      const s = await this.sessionRepo.findByRefreshHash(
        tx,
        presentedHash.value,
      );
      if (!s) return null;
      if (s.revokedAt !== null) return null;
      const revoked = await this.sessionRepo.save(
        tx,
        s.revoke(this.clock, 'ADMIN_REVOKED'),
      );
      return revoked;
    });

    if (!session) {
      // Per RFC 7009 §2.2: invalid tokens are also a no-op success.
      // Don't leak existence.
      return;
    }

    await this.eventBus.publishAll([
      new SessionRevoked(
        this.idGenerator.generate(),
        this.clock.now(),
        session.id,
        session.userId,
        'ADMIN_REVOKED',
      ),
    ]);
  }
}

/**
 * Re-export so the controller can import the type without a separate
 * import line.
 */

const _ensureDomainErrorImported: DomainError = null as unknown as DomainError;
void _ensureDomainErrorImported;
