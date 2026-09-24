/**
 * IpAllowlistGuard contract tests.
 *
 * The guard sits in front of every admin endpoint (see commit
 * d7546b3 / Phase 15). Pin its three behaviours:
 *   1. CIDR matching for IPv4 and IPv6.
 *   2. Empty allowlist = fail closed (denies all).
 *   3. IPv4-mapped IPv6 (::ffff:1.2.3.4) unwraps to plain IPv4 so
 *      an allowlist of `127.0.0.1/32` matches loopback on either family.
 */

import { ExecutionContext } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';
import { IpAllowlistGuard } from './ip-allowlist.guard';

function mockConfig(allowlist: string[]): ConfigService {
  return {
    get: () => allowlist,
  } as unknown as ConfigService;
}

function mockContext(ip: string | undefined): ExecutionContext {
  const req = { ip, socket: { remoteAddress: ip } } as unknown as Request;
  return {
    switchToHttp: () => ({
      getRequest: () => req,
    }),
  } as unknown as ExecutionContext;
}

describe('IpAllowlistGuard', () => {
  describe('CIDR matching', () => {
    it('allows an IPv4 in the allowlist range', () => {
      const guard = new IpAllowlistGuard(mockConfig(['10.0.0.0/8']));
      expect(guard.canActivate(mockContext('10.5.6.7'))).toBe(true);
    });

    it('rejects an IPv4 outside the allowlist range', () => {
      const guard = new IpAllowlistGuard(mockConfig(['10.0.0.0/8']));
      expect(guard.canActivate(mockContext('192.168.1.1'))).toBe(false);
    });

    it('allows an IPv6 in the allowlist range', () => {
      const guard = new IpAllowlistGuard(mockConfig(['2001:db8::/32']));
      expect(guard.canActivate(mockContext('2001:db8::1'))).toBe(true);
    });

    it('rejects an IPv6 outside the allowlist range', () => {
      const guard = new IpAllowlistGuard(mockConfig(['2001:db8::/32']));
      expect(guard.canActivate(mockContext('fe80::1'))).toBe(false);
    });

    it('allows multiple ranges — caller matches the second one', () => {
      const guard = new IpAllowlistGuard(
        mockConfig(['10.0.0.0/8', '192.168.0.0/16']),
      );
      expect(guard.canActivate(mockContext('192.168.50.50'))).toBe(true);
    });

    it('treats a bare IP as /32', () => {
      const guard = new IpAllowlistGuard(mockConfig(['192.168.1.5']));
      expect(guard.canActivate(mockContext('192.168.1.5'))).toBe(true);
      expect(guard.canActivate(mockContext('192.168.1.6'))).toBe(false);
    });
  });

  describe('IPv4-mapped IPv6 unwrapping', () => {
    it('matches IPv4 allowlist when caller uses ::ffff:1.2.3.4 form', () => {
      const guard = new IpAllowlistGuard(mockConfig(['192.168.1.5']));
      expect(guard.canActivate(mockContext('::ffff:192.168.1.5'))).toBe(true);
    });

    it('rejects IPv4-mapped form when not in allowlist', () => {
      const guard = new IpAllowlistGuard(mockConfig(['10.0.0.0/8']));
      expect(guard.canActivate(mockContext('::ffff:192.168.1.5'))).toBe(false);
    });
  });

  describe('fail-closed on empty allowlist', () => {
    it('denies all callers when allowlist is empty (V1 default)', () => {
      const guard = new IpAllowlistGuard(mockConfig([]));
      expect(guard.canActivate(mockContext('127.0.0.1'))).toBe(false);
      expect(guard.canActivate(mockContext('::1'))).toBe(false);
    });

    it('denies all callers when allowlist entry is malformed', () => {
      const guard = new IpAllowlistGuard(mockConfig(['not-an-ip']));
      // 'not-an-ip' won't parse, so the guard has zero valid ranges
      // → fails closed.
      expect(guard.canActivate(mockContext('127.0.0.1'))).toBe(false);
    });
  });

  describe('missing IP', () => {
    it('denies when the request has no IP', () => {
      const guard = new IpAllowlistGuard(mockConfig(['0.0.0.0/0']));
      // Even with a catch-all allowlist, an empty IP denies —
      // we can't possibly verify "is this caller in the allowlist"
      // without an address to check.
      expect(guard.canActivate(mockContext(undefined))).toBe(false);
    });
  });
});
