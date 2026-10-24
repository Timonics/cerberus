type AnyInput = { [key: string]: any };

/**
 * GraphQL input types — schema-first mode.
 *
 * In schema-first mode the SDL files in `src/graphql/types/*.graphql`
 * define the schema. We use plain TS interfaces as parameter
 * typings — no decorators needed. NestJS GraphQL validates inputs
 * against the SDL on the way in; we don't double-validate via
 * class-validator here.
 *
 * If we add `@InputType()` or `@ArgsType()` decorators, NestJS will
 * try to REGISTER another input type with the same name, which
 * conflicts with the SDL-defined one. Plain classes with `@Field()`
 * also fail because Nest reads the resolver signature and tries to
 * create GraphQL types from them.
 *
 * The cleanest pattern in schema-first mode: define inputs in SDL,
 * type resolvers with plain TS classes (no decorators), and let the
 * GraphQL runtime + global `ValidationPipe` (which we've configured
 * with `whitelist: true`) handle input shape.
 */

export interface RegisterInput extends AnyInput {
  email: string;
  password: string;
  organizationSlug?: string;
  displayName?: string;
}

export interface CreateOwnOrganizationInput extends AnyInput {
  slug: string;
  name: string;
  description?: string;
}

export interface ChangePasswordInput extends AnyInput {
  currentPassword: string;
  newPassword: string;
}

export interface UpdateDisplayNameInput extends AnyInput {
  displayName?: string;
  clearDisplayName?: boolean;
}

export interface MfaCodeInput extends AnyInput {
  code: string;
}

/**
 * Input for `Identity.enableMfa`. Fresh-auth: the current password
 * is verified server-side before the enrollment is created, so a
 * stolen bearer token alone cannot enable MFA (audit MEDIUM, MFA
 * enrollment fresh-auth).
 */
export interface EnableMfaInput extends AnyInput {
  currentPassword: string;
}

export interface VerifyMfaInput extends AnyInput {
  code: string;
  /** V1.5 (audit C-4): sessionId of the session to mark MFA-verified. */
  sessionId: string;
}

export interface RequestPasswordResetInput extends AnyInput {
  email: string;
}

export interface ConfirmPasswordResetInput extends AnyInput {
  token: string;
  newPassword: string;
}

export interface ConfirmEmailVerificationInput extends AnyInput {
  token: string;
}

export interface VerifyAccessTokenInput extends AnyInput {
  token: string;
}
