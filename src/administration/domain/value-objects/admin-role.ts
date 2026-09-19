import { DomainError } from '../../../shared/domain/errors/domain-error';

/**
 * Role of an admin operator within the Administration context.
 *
 * V1 only ships `ADMIN`. `SUPER_ADMIN` is reserved for V1.5 and will
 * gain the ability to rotate admin keys, revoke other admins' keys,
 * and read the full audit stream.
 */
export type AdminRoleLiteral = 'ADMIN' | 'SUPER_ADMIN';

export class AdminRole {
  public readonly value: AdminRoleLiteral;

  private constructor(value: AdminRoleLiteral) {
    this.value = value;
  }

  public static create(raw: string): AdminRole {
    if (raw === 'ADMIN' || raw === 'SUPER_ADMIN') {
      return new AdminRole(raw);
    }
    throw new DomainError('admin.role.unknown', `Unknown admin role: ${raw}`, {
      value: raw,
    });
  }

  public static rehydrate(value: string): AdminRole {
    return AdminRole.create(value);
  }

  public equals(other: AdminRole): boolean {
    return this.value === other.value;
  }

  public isSuperAdmin(): boolean {
    return this.value === 'SUPER_ADMIN';
  }
}
