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
 * CIDRs). Empty = deny all (V1 fails closed).
 *
 * Supports both IPv4 and IPv6. Entries without a `/N` prefix default
 * to /32 (IPv4) or /128 (IPv6). Mixed families are fine in one list.
 */
type IpFamily = 4 | 6;

interface ParsedCidr {
  family: IpFamily;
  /** The base address as a BigInt, normalized (no colons/dots, just bits). */
  addr: bigint;
  /** Prefix length in bits. */
  prefix: number;
}

/**
 * Resolve the caller's IP. Handles common Express / proxy shapes:
 *   * `req.ip` (set by `app.set('trust proxy', ...)`)
 *   * `req.socket.remoteAddress` (fallback)
 *   * IPv4-mapped IPv6 (`::ffff:1.2.3.4`) → unwrapped to plain IPv4
 *     so an allowlist of `127.0.0.1/32` matches loopback on either family.
 */
function extractIp(req: Request): string {
  const raw = (req.ip ?? req.socket?.remoteAddress ?? '').trim();
  if (!raw) return '';
  if (raw.startsWith('::ffff:')) return raw.slice(7);
  return raw;
}

@Injectable()
export class IpAllowlistGuard implements CanActivate {
  private readonly allowedRanges: ReadonlyArray<ParsedCidr>;
  private readonly logger = new Logger(IpAllowlistGuard.name);

  public constructor(config: ConfigService) {
    const allow =
      config.get<AppConfig['admin']['ipAllowlist']>('admin.ipAllowlist') ?? [];
    const parsed = allow.length
      ? parseIpAllowlist(allow.join(','))
      : parseIpAllowlist('');
    // Log bad entries so operators don't silently lose coverage.
    for (let i = 0; i < allow.length; i++) {
      if (!parsed[i]) {
        this.logger.warn(
          `Admin IP allowlist entry "${allow[i]}" is malformed and was skipped`,
        );
      }
    }
    this.allowedRanges = parsed.filter((r): r is ParsedCidr => r !== null);
  }

  public canActivate(context: ExecutionContext): boolean {
    const ip = extractIp(context.switchToHttp().getRequest<Request>());
    if (!ip) return false;
    const caller = parseIp(ip);
    if (!caller) return false;
    for (const range of this.allowedRanges) {
      if (ipInCidr(caller, range)) return true;
    }
    return false;
  }
}

// ---------------------------------------------------------------------------
// CIDR parsing + matching
// ---------------------------------------------------------------------------

/**
 * Parse an IP address (with optional `/N` prefix) into the internal
 * `ParsedCidr` shape. Returns null on malformed input.
 */
function parseCidr(input: string): ParsedCidr | null {
  const [base, prefixStr] = input.includes('/')
    ? input.split('/')
    : [input, null];

  if (base.includes(':')) {
    // IPv6
    const big = ipv6ToBigInt(base);
    if (big === null) return null;
    const prefix = prefixStr === null ? 128 : Number.parseInt(prefixStr, 10);
    if (!Number.isInteger(prefix) || prefix < 0 || prefix > 128) return null;
    return { family: 6, addr: big, prefix };
  }

  // IPv4
  const num = ipv4ToInt(base);
  if (num === null) return null;
  const prefix = prefixStr === null ? 32 : Number.parseInt(prefixStr, 10);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;
  // Store IPv4 as a 32-bit BigInt for unified comparison.
  return { family: 4, addr: BigInt(num), prefix };
}

/**
 * Parse an IP address (without a CIDR prefix) into a `ParsedCidr` with
 * the implicit host prefix. Returns null on malformed input.
 */
function parseIp(ip: string): { family: IpFamily; addr: bigint } | null {
  if (ip.includes(':')) {
    const big = ipv6ToBigInt(ip);
    if (big === null) return null;
    return { family: 6, addr: big };
  }
  const num = ipv4ToInt(ip);
  if (num === null) return null;
  return { family: 4, addr: BigInt(num) };
}

/** True iff `ip` is in `range`. Both must be the same address family. */
function ipInCidr(
  ip: { family: IpFamily; addr: bigint },
  range: ParsedCidr,
): boolean {
  if (ip.family !== range.family) return false;
  // Build the prefix mask and apply to both addresses. For a /0
  // (match-all) the mask is 0; for /32 (IPv4) or /128 (IPv6) the
  // mask is the full address space.
  const bits = range.family === 4 ? 32n : 128n;
  const prefixBig = BigInt(range.prefix);
  if (prefixBig === 0n) return true;
  const mask = ((1n << prefixBig) - 1n) << (bits - prefixBig);
  return (ip.addr & mask) === (range.addr & mask);
}

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let acc = 0;
  for (const p of parts) {
    // Audit 2026-10-19 (admin LOW): reject empty / non-decimal
    // segments outright. `Number('')` is 0 and `Number('0x10')` is
    // 16 — both used to be silently coerced, so `10.0..5/32`
    // parsed as `10.0.0.5` instead of being rejected as malformed.
    if (!/^\d{1,3}$/.test(p)) return null;
    const n = Number(p);
    if (n < 0 || n > 255) return null;
    acc = (acc << 8) + n;
  }
  return acc >>> 0;
}

/** Normalize an IPv6 group to 4 lowercase hex chars. */
function normalizeGroup(g: string): string {
  return g.toLowerCase().padStart(4, '0');
}

/**
 * Parse an IPv6 address string into a 128-bit BigInt. Supports the
 * common forms:
 *   * `2001:db8::1`
 *   * `::1` (loopback)
 *   * `::` (all zeros)
 *   * `fe80::1%eth0` (with zone — the zone is stripped before parsing)
 *
 * Returns null on malformed input.
 */
function ipv6ToBigInt(ip: string): bigint | null {
  // Strip a zone identifier (RFC 4007 `%zone` suffix). The zone
  // doesn't affect the address bits; we ignore it for matching.
  const zoneIdx = ip.indexOf('%');
  if (zoneIdx !== -1) ip = ip.slice(0, zoneIdx);

  // Empty / double-colon forms
  if (ip === '::') return 0n;

  // Split on '::' — the double-colon group is implicit zeros. We
  // resolve it by counting the missing groups.
  const dblColon = ip.split('::');
  if (dblColon.length > 2) return null; // more than one '::' is invalid

  const left: string[] = dblColon[0] ? dblColon[0].split(':') : [];
  const right: string[] =
    dblColon.length === 2 && dblColon[1] ? dblColon[1].split(':') : [];

  // Each group must be 1–4 hex digits. Embedded IPv4 (e.g. `::ffff:1.2.3.4`)
  // is allowed in notation but expand it here.
  const allGroups: string[] = [];
  for (const g of [...left, ...right]) {
    if (g.includes('.')) {
      // IPv4 tail — convert to two hex groups
      const v4 = ipv4ToInt(g);
      if (v4 === null) return null;
      allGroups.push(v4.toString(16).padStart(8, '0').slice(0, 4));
      allGroups.push(v4.toString(16).padStart(8, '0').slice(4, 8));
    } else if (/^[0-9a-fA-F]{1,4}$/.test(g)) {
      allGroups.push(g.toLowerCase().padStart(4, '0'));
    } else {
      return null;
    }
  }

  const missing = 8 - allGroups.length;
  if (missing < 0) return null; // more than 8 groups
  const hasDblColon = dblColon.length === 2;
  // dblColon[1] is undefined when there's no `::`, but when length === 2
  // it's a (possibly-empty) string. Build the final list explicitly so
  // TS doesn't widen dblColon[1] to string | undefined inside the spread.
  const finalGroups: string[] = hasDblColon
    ? [
        ...left.map(normalizeGroup),
        ...Array<string>(missing).fill('0000'),
        ...right.map(normalizeGroup),
      ]
    : allGroups;

  if (finalGroups.length !== 8) return null;
  let acc = 0n;
  for (const g of finalGroups) {
    // BigInt() rejects strings like "0db8" because it sees the leading
    // 0 as octal. Prefix with "0x" so it's parsed as hex.
    acc = (acc << 16n) | BigInt(`0x${g}`);
  }
  return acc;
}

/**
 * Build the parsed allowlist from a comma-separated env string.
 * Returns an array with the same length as the input — entries that
 * can't be parsed are `null` (caller is expected to log a warning).
 */
export function parseIpAllowlist(
  raw: string,
): ReadonlyArray<ParsedCidr | null> {
  return raw
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
    .map((entry) => parseCidr(entry));
}

void Logger;
