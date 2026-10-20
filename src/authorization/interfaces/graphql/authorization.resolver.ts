import { Inject } from '@nestjs/common';
import { Args, Query, Resolver } from '@nestjs/graphql';
import { GetJwksUseCase } from '../../application/use-cases/get-jwks.use-case';
import { VerifyAccessTokenUseCase } from '../../application/use-cases/verify-access-token.use-case';
import { VerifyAccessTokenInput } from '../../../graphql/models/inputs';

/**
 * Authorization GraphQL resolver.
 *
 * Exposes JWT verification + JWKS read for resource servers.
 *
 * The OAuth2 protocol endpoints (`/v1/oauth/token`, `/v1/oauth/introspect`,
 * `/v1/oauth/revoke`) are NOT exposed here — they're RFC 6749/7662/7009
 * REST endpoints with fixed request/response shapes that don't
 * translate cleanly to GraphQL.
 */
@Resolver()
export class AuthorizationResolver {
  public constructor(
    @Inject(GetJwksUseCase) private readonly getJwksUc: GetJwksUseCase,
    @Inject(VerifyAccessTokenUseCase)
    private readonly verifyTokenUc: VerifyAccessTokenUseCase,
  ) {}

  @Query(() => 'JwksDocument', {
    description:
      'The JWKS document with all currently-verifying public keys. Resource servers should cache this on startup and refresh on JWT `kid` rotation.',
  })
  public async jwks() {
    return this.getJwksUc.execute(new Date());
  }

  @Query(() => 'AccessTokenClaims', {
    description:
      'Verify a JWT access token and return its real claims (sub/org/role/scope/jti/typ/iss/aud/iat/exp as present in the verified token). Throws UNAUTHENTICATED for invalid, expired, or unknown-kid tokens. App-bound tokens (typ: app) are accepted here — this is the introspection path for resource servers.',
  })
  public async verifyAccessToken(@Args('input') input: VerifyAccessTokenInput) {
    // allowAppTokens: this query IS the resource-server introspection
    // path — it must report claims for whichever token was presented,
    // user- or app-bound. User-principal endpoints reject app tokens
    // by default in VerifyAccessTokenUseCase.
    const claims = await this.verifyTokenUc.execute(input.token, {
      allowAppTokens: true,
    });
    return {
      sub: claims.subject,
      org: claims.organizationId,
      role: claims.role,
      scope: claims.scopes.join(' '),
      jti: claims.jti,
      typ: claims.tokenType,
      iss: claims.issuer,
      aud: claims.audience,
      iat: claims.issuedAt,
      exp: claims.expiresAt,
    };
  }
}
