import {
  CanActivate,
  ExecutionContext,
  Injectable,
  Logger,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';
import { AppConfig } from '../../../config/configuration';

/**
 * Allowlist of CIDR ranges that may reach the admin surface.
 *
 * Configured via the `admin.ipAllowlist` env var (comma-separated
 * CIDRs). Empty = deny all (V1 fails closed — V1.5 should expose a
 * `ADMIN_ALLOW_LOOPBACK=true` escape hatch for local dev).
 */
@Injectable()
export class IpAllowlistGuard implements CanActivate {
  private readonly allowedRanges: ReadonlyArray<readonly [string, number]>;

  public constructor(config: ConfigService) {
    const allow =
      config.get<AppConfig['admin']['ipAllowlist']>('admin.ipAllowlist') ?? [];
    this.allowedRanges = allow.length
      ? parseIpAllowlist(allow.join(','))
      : parseIpAllowlist('');
  }

  public canActivate(context: ExecutionContext): boolean {
    const req = context.switchToHttp().getRequest<Request>();
    const ip = (req.ip ?? req.socket?.remoteAddress ?? '').trim();
    if (!ip) return false;
    // Normalize IPv4-mapped-IPv6 (::ffff:127.0.0.1).
    const normalized = ip.startsWith('::ffff:') ? ip.slice(7) : ip;
    for (const [cidr, prefix] of this.allowedRanges) {
      if (ipv4InCidr(normalized, cidr, prefix)) return true;
    }
    return false;
  }
}

/**
 * Pure-JS CIDR match for IPv4 only. The admin surface accepts only
 * IPv4 (configurable later if needed). Supports the common forms:
 *   * `1.2.3.4`      — exact
 *   * `1.2.3.0/24`   — subnet
 *   * `0.0.0.0/0`    — match-all
 *
 * IPv6 CIDR is out of scope for V1.
 */
export function ipv4InCidr(ip: string, cidr: string, prefix: number): boolean {
  if (!cidr.includes('/')) {
    return ip === cidr;
  }
  const [base] = cidr.split('/');
  const ipInt = ipv4ToInt(ip);
  const baseInt = ipv4ToInt(base);
  if (ipInt === null || baseInt === null) return false;
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  return (ipInt & mask) === (baseInt & mask);
}

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let acc = 0;
  for (const p of parts) {
    const n = Number(p);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    acc = (acc << 8) + n;
  }
  return acc >>> 0;
}

/**
 * Build the parsed allowlist from a comma-separated env string. Used
 * by the admin module factory.
 */
export function parseIpAllowlist(
  raw: string,
): ReadonlyArray<readonly [string, number]> {
  return raw
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
    .map((entry) => {
      if (entry.includes('/')) {
        const [base, p] = entry.split('/');
        return [base, Number(p)] as const;
      }
      return [entry, 32] as const;
    });
}

void Logger;
