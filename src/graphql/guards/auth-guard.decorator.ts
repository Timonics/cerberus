import { UseGuards, SetMetadata } from '@nestjs/common';
import { GraphqlAuthGuard } from './graphql-auth.guard';

/**
 * Decorate a resolver method to require authentication.
 *
 * Use:
 *   @AuthGuard()
 *   @Query(() => 'User')
 *   async me(@CurrentUser() user: ...) { ... }
 *
 * For admin-only queries:
 *   @AuthGuard({ requireOrgAdmin: true })
 *
 * The decorator sets a metadata key that `GraphqlAuthGuard` reads at
 * runtime. It also applies the guard via `@UseGuards`.
 */
export function AuthGuard(options?: {
  requireOrgAdmin?: boolean;
}): MethodDecorator {
  return (target, propertyKey, descriptor) => {
    SetMetadata('graphql-auth-options', options ?? {})(
      target,
      propertyKey,
      descriptor,
    );
    return UseGuards(GraphqlAuthGuard)(target, propertyKey, descriptor);
  };
}
