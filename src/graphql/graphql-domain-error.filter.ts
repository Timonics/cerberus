import { Catch, ArgumentsHost } from '@nestjs/common';
import { GqlExceptionFilter, GqlArgumentsHost } from '@nestjs/graphql';
import { GraphQLError } from 'graphql';
import { DomainError } from '../shared/domain/errors/domain-error';

/**
 * GraphQL adapter for `DomainError`.
 *
 * Maps stable `DomainError.code` values to GraphQL errors. The
 * `extensions.code` field is what clients should switch on.
 *
 * Unknown codes fall through to `INTERNAL`.
 */
@Catch(DomainError)
export class GraphqlDomainErrorFilter implements GqlExceptionFilter {
  public catch(exception: DomainError, host: ArgumentsHost): GraphQLError {
    GqlArgumentsHost.create(host); // ensures we're in a GraphQL context
    const code = exception.code;
    const httpStatus = this.statusFor(code);
    const graphqlCode = this.graphqlCodeFor(httpStatus);
    return new GraphQLError(exception.message, {
      extensions: {
        code: graphqlCode,
        domainCode: code,
      },
    });
  }

  private statusFor(code: string): number {
    if (code.endsWith('.unauthenticated')) return 401;
    if (code.endsWith('.forbidden') || code.endsWith('.locked')) return 403;
    if (code.endsWith('.not_found')) return 404;
    if (
      code.endsWith('.taken') ||
      code.endsWith('.already_enabled') ||
      code.endsWith('.already_used') ||
      code.endsWith('.in_use')
    ) {
      return 409;
    }
    if (code.endsWith('.invalid') || code.endsWith('.expired')) return 400;
    return 500;
  }

  private graphqlCodeFor(httpStatus: number): string {
    switch (httpStatus) {
      case 400:
        return 'INPUT_INVALID';
      case 401:
        return 'UNAUTHENTICATED';
      case 403:
        return 'FORBIDDEN';
      case 404:
        return 'NOT_FOUND';
      case 409:
        return 'CONFLICT';
      default:
        return 'INTERNAL';
    }
  }
}
