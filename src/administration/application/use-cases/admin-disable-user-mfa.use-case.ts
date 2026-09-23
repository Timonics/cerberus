import { Inject, Injectable } from '@nestjs/common';
import {
  CLOCK,
  Clock,
  DomainError,
  ID_GENERATOR,
  IdGenerator,
  TRANSACTION_RUNNER,
  TransactionRunner,
  Tx,
} from '../../../shared/domain';
import { UserId } from '../../../identity/domain/value-objects/user-id';
import { OrgId } from '../../../identity/domain/value-objects/org-id';
import {
  MFA_SECRET_REPOSITORY,
  MfaSecretRepository,
} from '../../../identity/domain/ports/mfa-secret.repository.port';
import {
  MEMBERSHIP_REPOSITORY,
  MembershipRepository,
} from '../../../identity/domain/ports/membership.repository.port';
import { GetUserUseCase } from '../../../identity/application/use-cases/get-user.use-case';
import {
  AUDIT_LOG_REPOSITORY,
  AuditLogRepository,
} from '../../../engagement/domain/ports/audit-log.repository.port';
import { AuditLog } from '../../../engagement/domain/aggregates/audit-log';
import { AuditEventType } from '../../../engagement/domain/value-objects/audit-event-type';

export interface AdminDisableUserMfaInput {
  /** The user whose MFA will be disabled. */
  userId: string;
  /**
   * V1.5 (audit C-1): when the caller is a JWT user (GraphQL), pass
   * their user id here. The use-case resolves the caller's org from
   * membership and refuses to disable MFA on a target user in a
   * different org — this is the security boundary against
   * cross-tenant IDOR via the `org:admin` GraphQL scope. When the
   * caller is the admin REST surface (admin API key), pass null:
   * that path has its own IP allowlist + API-key auth and operates
   * globally.
   */
  callerUserId?: string | null;
  /**
   * Identifier of the admin key performing the action (for audit).
   * Optional when invoked via GraphQL (no API key in scope) or by a
   * SUPER_ADMIN operator who used only their JWT. The audit row
   * records `null` in that case.
   */
  adminKeyId?: string | null;
  /** Optional human-readable reason for the override. */
  reason?: string | null;
}

export interface AdminDisableUserMfaResult {
  userId: string;
  adminKeyId: string | null;
  occurredAt: Date;
}

/**
 * Admin-override MFA disable.
 *
 * Bypasses the user-facing TOTP check by going directly to
 * `MfaSecretRepository.delete()`. Used by admins to recover accounts
 * where the user has lost their authenticator device.
 *
 * Records an audit-log entry tagged `identity.mfa.disabled` with the
 * adminKeyId as metadata, so the event is traceable back to the
 * operator that performed it.
 *
 * V1: uses no event bus — the audit log row IS the audit trail. The
 * `MfaDisabled` domain event still fires from the underlying
 * `DisableMfaUseCase` flow if you re-enable TOTP checks; in V1 we
 * write directly to the audit log because the disable path doesn't go
 * through the aggregate.
 */
@Injectable()
export class AdminDisableUserMfaUseCase {
  public constructor(
    @Inject(TRANSACTION_RUNNER) private readonly txRunner: TransactionRunner,
    @Inject(CLOCK) private readonly clock: Clock,
    @Inject(ID_GENERATOR) private readonly idGenerator: IdGenerator,
    @Inject(MFA_SECRET_REPOSITORY)
    private readonly mfaRepo: MfaSecretRepository,
    @Inject(GetUserUseCase) private readonly getUser: GetUserUseCase,
    @Inject(MEMBERSHIP_REPOSITORY)
    private readonly membershipRepo: MembershipRepository,
    @Inject(AUDIT_LOG_REPOSITORY)
    private readonly auditRepo: AuditLogRepository,
  ) {}

  public async execute(
    input: AdminDisableUserMfaInput,
  ): Promise<AdminDisableUserMfaResult> {
    const userId = UserId.create(input.userId);
    const occurredAt = this.clock.now();

    await this.txRunner.run<void>(async (tx: Tx) => {
      // Confirm there's an MFA secret row to delete. Admins can clean
      // up both pending (unconfirmed) AND confirmed secrets — a user
      // who started enrolling but never finished is still a stuck
      // state, and admins should be able to recover it.
      const existing = await this.mfaRepo.findById(tx, userId);
      if (!existing) {
        throw new DomainError(
          'admin.user.mfa_not_enabled',
          'No MFA secret row found for this user',
          { userId: input.userId },
        );
      }

      // Touch the user record to confirm they exist (404 if not).
      const target = await this.getUser.execute({ userId: input.userId });

      // V1.5 (audit C-1): defense in depth against cross-tenant IDOR.
      // For JWT callers (callerUserId set), resolve their org from
      // membership and refuse if the target is in a different org.
      // For REST admin-API-key callers (callerUserId null), no org
      // check — that surface has its own IP-allowlist + API-key auth
      // and operates globally.
      if (input.callerUserId) {
        const callerId = UserId.create(input.callerUserId);
        const callerMembership = await this.membershipRepo.findByUserId(
          tx,
          callerId,
        );
        if (!callerMembership) {
          // No membership = no org = no org:admin scope should reach
          // here, but defense in depth.
          throw new DomainError(
            'admin.forbidden',
            'Caller has no organization',
          );
        }
        const callerOrgId = callerMembership.organizationId;
        const targetOrgId = OrgId.create(target.organizationId);
        if (!targetOrgId.equals(callerOrgId)) {
          throw new DomainError(
            'admin.forbidden',
            'Target user is outside your organization',
            { callerOrgId: callerOrgId.value },
          );
        }
      }

      // Delete the MFA secret + recovery codes (FK cascade).
      await this.mfaRepo.delete(tx, userId);

      // 4. Audit-log the override.
      const audit = AuditLog.create({
        id: this.idGenerator.generate(),
        userId: input.userId,
        // V1.5 fix: dedicated event type `admin.user.mfa_disabled` (was
        // reusing `identity.mfa.disabled`). The two are distinct: a
        // user-initiated disable fires `identity.mfa.disabled` from
        // DisableMfaUseCase; an admin-override fires this one.
        eventType: AuditEventType.create('admin.user.mfa_disabled'),
        payload: {
          adminKeyId: input.adminKeyId,
          reason: input.reason ?? 'admin override (no TOTP)',
          override: true,
        },
        ipAddress: null,
        userAgent: null,
        clock: this.clock,
      });
      await this.auditRepo.save(tx, audit);
    });

    return {
      userId: input.userId,
      adminKeyId: input.adminKeyId ?? null,
      occurredAt,
    };
  }
}
