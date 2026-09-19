import { GraphQLError } from 'graphql';

/**
 * GraphQL error helpers.
 *
 * Map domain exceptions to GraphQL errors with stable `extensions.code`
 * values. The `code` field is what clients should switch on.
 *
 * We extend the bare `GraphQLError` rather than Apollo-specific
 * classes so we're not coupled to Apollo Server's error semantics
 * (which shifted between v4 and v5).
 */
export class GqlBadRequestException extends GraphQLError {
  public constructor(message: string) {
    super(message, { extensions: { code: 'INPUT_INVALID' } });
  }
}

export class GqlUnauthenticatedException extends GraphQLError {
  public constructor(message = 'Authentication required') {
    super(message, { extensions: { code: 'UNAUTHENTICATED' } });
  }
}

export class GqlForbiddenException extends GraphQLError {
  public constructor(message = 'Forbidden') {
    super(message, { extensions: { code: 'FORBIDDEN' } });
  }
}

export class GqlNotFoundException extends GraphQLError {
  public constructor(message = 'Not found') {
    super(message, { extensions: { code: 'NOT_FOUND' } });
  }
}

export class GqlConflictException extends GraphQLError {
  public constructor(message: string) {
    super(message, { extensions: { code: 'CONFLICT' } });
  }
}
