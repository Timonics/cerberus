import { Injectable } from '@nestjs/common';
import { randomBytes } from 'node:crypto';

/**
 * Outbound port for refresh-token generation.
 *
 * The implementation MUST use a CSPRNG. The 32-byte default gives
 * 256 bits of entropy — collision probability is negligible.
 */
export interface RefreshTokenGenerator {
  generate(): string;
}

export const REFRESH_TOKEN_GENERATOR = Symbol('RefreshTokenGenerator');

/**
 * Default implementation using `crypto.randomBytes`.
 *
 * Output is base64url-encoded (no padding) so the token is safe to put
 * in URLs and HTTP headers.
 */
@Injectable()
export class RandomRefreshTokenGenerator implements RefreshTokenGenerator {
  public generate(): string {
    return randomBytes(32).toString('base64url');
  }
}
