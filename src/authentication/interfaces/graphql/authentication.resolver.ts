import { Inject, Injectable } from '@nestjs/common';
import { Args, Context, Mutation, Resolver } from '@nestjs/graphql';
import {
  GqlBadRequestException,
  GqlUnauthenticatedException,
} from '../../../graphql/graphql-errors';
import { LoginUseCase } from '../../application/use-cases/login.use-case';
import { LogoutUseCase } from '../../application/use-cases/logout.use-case';
import { RefreshSessionUseCase } from '../../application/use-cases/refresh-session.use-case';
import { VerifyAppApiKeyUseCase } from '../../../apps/application/use-cases/verify-app-api-key.use-case';
import { IssueAccessTokenUseCase } from '../../../authorization/application/use-cases/issue-access-token.use-case';
import { LoginInput, RefreshTokenInput } from '../../../graphql/models/inputs';

/**
 * Authentication GraphQL resolver.
 *
 * Mirrors the REST `AuthController` session endpoints:
 *
 *   * `login(input)` — POST /v1/auth/login twin. MFA-pending logins
 *     return ONLY the scoped `mfaToken` + sessionId — never a usable
 *     refresh token (audit fix C1). Complete via `Identity.verifyMfa`.
 *   * `refresh(input)` — POST /v1/auth/refresh twin; rotates the
 *     refresh token and issues a fresh access token.
 *   * `logout(input)` — POST /v1/auth/logout twin; revokes the session
 *     bound to the presented refresh token.
 *
 * Auth: all three are open to unauthenticated callers (session
 * ESTABLISHMENT); throttling + the in-DB login lockout apply exactly as
 * on REST. The `X-Cerberus-App-Id` / `X-Cerberus-App-Secret` headers
 * are honored for app-pinned org scoping, fail-closed, same as REST.
 */
@Injectable()
@Resolver()
export class AuthenticationResolver {
  public constructor(
    @Inject(LoginUseCase) private readonly loginUc: LoginUseCase,
    @Inject(RefreshSessionUseCase)
    private readonly refreshUc: RefreshSessionUseCase,
    @Inject(LogoutUseCase) private readonly logoutUc: LogoutUseCase,
    @Inject(VerifyAppApiKeyUseCase)
    private readonly verifyAppApiKeyUc: VerifyAppApiKeyUseCase,
    @Inject(IssueAccessTokenUseCase)
    private readonly issueAccessTokenUc: IssueAccessTokenUseCase,
  ) {}

  @Mutation(() => 'LoginPayload', {
    description:
      'Authenticate a user and establish a session (GraphQL twin of POST /v1/auth/login).',
  })
  public async login(
    @Args('input') input: LoginInput,
    @Context() gqlContext: { req: import('express').Request },
  ) {
    const appDefaultOrgSlug = await this.resolveAppDefaultOrgSlug(gqlContext);
    const result = await this.loginUc.execute({
      email: input.email,
      password: input.password,
      userAgent: input.userAgent,
      ipAddress: gqlContext.req.ip,
      appDefaultOrgSlug,
      mfaCode: input.mfaCode,
    });

    // MFA-pending branch: scoped token ONLY — no refresh token, no
    // access token (audit fix C1 — a usable refresh token here would
    // let a password-only attacker bypass MFA via refresh).
    if (result.mfaRequired) {
      return {
        mfaRequired: true,
        accessToken: null,
        refreshToken: null,
        mfaToken: result.mfaToken,
        sessionId: result.sessionId,
        userId: result.userId,
        familyId: result.familyId,
        expiresAt: result.expiresAt.toISOString(),
        expiresIn: null,
      };
    }

    const issued = await this.issueAccessTokenUc.execute({
      userId: result.userId,
      organizationSlug: appDefaultOrgSlug,
    });
    return {
      mfaRequired: false,
      accessToken: issued.accessToken,
      refreshToken: result.refreshToken,
      mfaToken: null,
      sessionId: result.sessionId,
      userId: result.userId,
      familyId: result.familyId,
      expiresAt: result.expiresAt.toISOString(),
      expiresIn: issued.expiresIn,
    };
  }

  @Mutation(() => 'RefreshPayload', {
    description:
      'Rotate a refresh token (GraphQL twin of POST /v1/auth/refresh).',
  })
  public async refresh(
    @Args('input') input: RefreshTokenInput,
    @Context() gqlContext: { req: import('express').Request },
  ) {
    const appDefaultOrgSlug = await this.resolveAppDefaultOrgSlug(gqlContext);
    const result = await this.refreshUc.execute({
      refreshToken: input.refreshToken,
      appDefaultOrgSlug,
    });
    const issued = await this.issueAccessTokenUc.execute({
      userId: result.userId,
      organizationSlug: appDefaultOrgSlug,
    });
    return {
      refreshToken: result.refreshToken,
      accessToken: issued.accessToken,
      sessionId: result.sessionId,
      userId: result.userId,
      familyId: result.familyId,
      expiresAt: result.expiresAt.toISOString(),
      expiresIn: issued.expiresIn,
    };
  }

  @Mutation(() => Boolean, {
    description:
      'Revoke the session bound to a refresh token (GraphQL twin of POST /v1/auth/logout).',
  })
  public async logout(@Args('input') input: RefreshTokenInput) {
    await this.logoutUc.execute({ refreshToken: input.refreshToken });
    return true;
  }

  /**
   * Resolve an optional app-pinned org slug from the
   * `X-Cerberus-App-Id` / `X-Cerberus-App-Secret` headers, mirroring
   * the REST controller AND the fail-closed contract the register
   * resolver already pins: partial headers → 400-shaped INPUT_INVALID;
   * any verify failure → UNAUTHENTICATED (the verify use-case maps
   * every failure mode to one uniform code, so app ids can't be
   * enumerated).
   */
  private async resolveAppDefaultOrgSlug(gqlContext: {
    req: import('express').Request;
  }): Promise<string | null> {
    const headerVal = (v: string | string[] | undefined): string | undefined =>
      typeof v === 'string' && v.trim() ? v.trim() : undefined;
    const appId = headerVal(gqlContext.req.headers['x-cerberus-app-id']);
    const appSecret = headerVal(
      gqlContext.req.headers['x-cerberus-app-secret'],
    );
    if ((appId && !appSecret) || (!appId && appSecret)) {
      throw new GqlBadRequestException(
        'X-Cerberus-App-Id and X-Cerberus-App-Secret must be sent together',
      );
    }
    if (!appId || !appSecret) return null;
    try {
      const verified = await this.verifyAppApiKeyUc.execute({
        appId,
        plaintextApiKey: appSecret,
      });
      return verified?.defaultOrgSlug ?? null;
    } catch {
      throw new GqlUnauthenticatedException('App credentials are invalid');
    }
  }
}
