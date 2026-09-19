#!/usr/bin/env node
/**
 * Generate the Cerberus Postman Collection (v2.1) plus two
 * environment files. Run with `node scripts/gen-postman-collection.js`.
 *
 * Output:
 *   - postman/Cerberus.postman_collection.json
 *   - postman/Cerberus.dev.postman_environment.json
 *   - postman/Cerberus.staging.postman_environment.json
 *
 * The collection covers the full REST surface (Phases 11–14) AND the
 * full GraphQL surface (Phase 14.5). It auto-saves the bearer token,
 * refresh token, user ID, MFA secret, recovery codes, and JWT kid
 * into environment variables as you click through.
 */
const fs = require('node:fs');
const path = require('node:path');

const OUT_DIR = path.resolve(__dirname, '..', 'postman');
fs.mkdirSync(OUT_DIR, { recursive: true });

/**
 * Parse a JSON string safely — returns the parsed value, or null if
 * the input isn't valid JSON. Used by the GraphQL generator to
 * normalize `variables` arguments into real objects for Postman's
 * `body.graphql.variables` field (which doesn't accept strings).
 */
function safeParseJson(value) {
  if (value === null || value === undefined) return null;
  if (typeof value !== 'string') return value;
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

function uid() { return Math.random().toString(36).slice(2, 11); }

function req(name, opts) {
  const {
    method = 'GET',
    path: reqPath,
    description = '',
    headers = [],
    body = null,
    tests = '',
    prerequest = '',
  } = opts;

  return {
    name,
    request: {
      method,
      header: headers,
      body,
      url: {
        raw: '{{baseUrl}}' + reqPath,
        host: ['{{baseUrl}}'],
        path: reqPath.replace(/^\//, '').split('/'),
      },
      auth: { type: 'noauth' },
      description,
    },
    event: [
      prerequest
        ? { listen: 'prerequest', script: { type: 'text/javascript', exec: prerequest.split('\n') } }
        : null,
      { listen: 'test', script: { type: 'text/javascript', exec: tests.split('\n') } },
    ].filter(Boolean),
  };
}

function folder(name, items, description = '') {
  return { id: uid(), name, description, item: items };
}

function graphqlReq(name, opts) {
  const {
    description = '',
    query,
    variables = '{}',
    headers = [],
    tests = STANDARD_TESTS,
    authHeader = true,
    prerequest = '',
  } = opts;
  return {
    name,
    request: {
      method: 'POST',
      header: [
        ...(authHeader ? [{ key: 'Authorization', value: 'Bearer {{bearerToken}}' }] : []),
        { key: 'Content-Type', value: 'application/json' },
        ...headers,
      ],
      // Postman's native GraphQL mode (`body.mode = "graphql"`) does
      // three things for us:
      //   1. Activates the schema explorer / schema introspection
      //      button in the request UI (reads the schema from the
      //      server's introspection endpoint).
      //   2. Renders a GraphiQL-style query editor with field
      //      autocomplete, not a plain JSON textarea.
      //   3. Wraps the `body.graphql.query` + `body.graphql.variables`
      //      fields into the standard `{query, variables}` envelope
      //      that Apollo Server / Express expects on the wire.
      //
      // The Postman v2.1 schema is `body.graphql` (NOT the old
      // `body.graphqlData`). Verified against Postman Desktop 11.x.
      body: {
        mode: 'graphql',
        graphql: {
          query,
          // Postman expects variables to be a JSON object (or null),
          // NOT a stringified JSON. We accept either form at the call
          // site and normalize here.
          variables: typeof variables === 'string'
            ? safeParseJson(variables)
            : variables,
        },
        options: {
          graphql: {
            useSchemaFromServer: '{{baseUrl}}/graphql',
          },
        },
      },
      url: {
        raw: '{{baseUrl}}/graphql',
        host: ['{{baseUrl}}'],
        path: ['graphql'],
      },
      description,
    },
    event: [
      prerequest
        ? { listen: 'prerequest', script: { type: 'text/javascript', exec: prerequest.split('\n') } }
        : null,
      { listen: 'test', script: { type: 'text/javascript', exec: tests.split('\n') } },
    ].filter(Boolean),
  };
}

/* ----- Reusable scripts ----- */

const STANDARD_TESTS = `
pm.test("Status 2xx", () => pm.expect(pm.response.code).to.be.below(300));
const json = pm.response.json();
if (json && typeof json === "object") {
  const reqId = pm.response.headers.get("x-request-id");
  if (reqId) pm.collectionVariables.set("lastRequestId", reqId);
}
`.trim();

const SAVE_BEARER = `
const json = pm.response.json();
if (json.access_token) {
  pm.collectionVariables.set("bearerToken", json.access_token);
  pm.collectionVariables.set("expiresIn", json.expires_in);
}
if (json.refresh_token) {
  pm.collectionVariables.set("refreshToken", json.refresh_token);
}
`.trim();

const LOGIN_TEST = `${STANDARD_TESTS}\n${SAVE_BEARER}\n` +
  `pm.collectionVariables.set("currentSessionId", pm.response.json().sessionId);\n` +
  `pm.collectionVariables.set("currentFamilyId", pm.response.json().familyId);`;

const REQUIRE_AUTH = `
pm.test("Authenticated request succeeded", () => {
  if (pm.response.code === 401) {
    throw new Error("Got 401 — bearer token missing or expired. Run 'OAuth2 > Token (password)' first.");
  }
  pm.expect(pm.response.code).to.be.below(300);
});
`.trim();

// RFC 6238 TOTP, cross-checked against otplib's authenticator.generate().
// Reads {{mfaSecret}}, writes {{totpCode}}. 30s window, 6 digits, HMAC-SHA1.
const TOTP_PREREQUEST = `
const crypto = require("crypto");
const secret = pm.collectionVariables.get("mfaSecret");
function totp(s) {
  const ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = s.replace(/=+$/g, "").toUpperCase();
  let bits = "", bytes = [];
  for (const ch of clean) bits += ALPHA.indexOf(ch).toString(2).padStart(5, "0");
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  const key = Buffer.from(bytes);
  let counter = Math.floor(Date.now() / 30000);
  const buf = Buffer.alloc(8);
  for (let i = 7; i >= 0; i--) { buf[i] = counter & 0xff; counter = Math.floor(counter / 256); }
  const hmac = crypto.createHmac("sha1", key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16) | ((hmac[offset + 2] & 0xff) << 8) | (hmac[offset + 3] & 0xff);
  return String(code % 1_000_000).padStart(6, "0");
}
pm.collectionVariables.set("totpCode", totp(secret));
`.trim();

/* ----- REST requests ----- */

const healthFolder = folder('Health', [
  req('GET /health', {
    method: 'GET',
    path: '/health',
    description: 'Unauthenticated liveness probe. Used by load balancers and Kubernetes liveness.',
    tests: 'pm.test("Status 200", () => pm.expect(pm.response.code).to.eql(200));',
  }),
  req('GET /ready', {
    method: 'GET',
    path: '/ready',
    description: 'Unauthenticated readiness probe. Checks Postgres + Redis. Returns 200 only when both are reachable.',
    tests: 'pm.test("Status 200", () => pm.expect(pm.response.code).to.eql(200));',
  }),
]);

const authFolder = folder('Auth', [
  folder('Public', [
    req('POST /v1/auth/login', {
      method: 'POST',
      path: '/v1/auth/login',
      description: 'Authenticate with email + password. Returns a sessionId and familyId for the new session.',
      headers: [{ key: 'Content-Type', value: 'application/json' }],
      body: {
        mode: 'raw',
        raw: JSON.stringify({ email: 'alice@example.com', password: 'correct-horse-battery-staple' }, null, 2),
        options: { language: { json: {} } },
      },
      tests: LOGIN_TEST,
    }),
    req('POST /v1/auth/refresh', {
      method: 'POST',
      path: '/v1/auth/refresh',
      description: 'Rotate the refresh token. Returns a new pair. The old refresh token is consumed.',
      headers: [{ key: 'Content-Type', value: 'application/json' }],
      body: {
        mode: 'raw',
        raw: JSON.stringify({ refreshToken: '{{refreshToken}}' }, null, 2),
        options: { language: { json: {} } },
      },
      tests: `${STANDARD_TESTS}\n${SAVE_BEARER}`,
    }),
    req('POST /v1/auth/logout', {
      method: 'POST',
      path: '/v1/auth/logout',
      description: 'Revoke the session identified by the presented refresh token. Idempotent.',
      headers: [{ key: 'Content-Type', value: 'application/json' }],
      body: {
        mode: 'raw',
        raw: JSON.stringify({ refreshToken: '{{refreshToken}}' }, null, 2),
        options: { language: { json: {} } },
      },
      tests: STANDARD_TESTS,
    }),
  ]),
  folder('Sessions (V1: X-User-Id placeholder)', [
    req('GET /v1/auth/sessions', {
      method: 'GET',
      path: '/v1/auth/sessions',
      description:
        'List all active sessions for the authenticated user. ' +
        'V1 uses the Phase-11 X-User-Id placeholder header (Phase 13 ' +
        'JWT auth replaces this). Both headers are sent for clarity.',
      headers: [
        { key: 'X-User-Id', value: '{{userId}}' },
        { key: 'Authorization', value: 'Bearer {{bearerToken}}' },
      ],
      tests: REQUIRE_AUTH,
    }),
    req('POST /v1/auth/sessions/:id/revoke', {
      method: 'POST',
      path: '/v1/auth/sessions/{{otherSessionId}}/revoke',
      description:
        'Revoke a specific session. Must be your own session ' +
        '(cross-user revoke returns 404). V1 uses X-User-Id.',
      headers: [
        { key: 'X-User-Id', value: '{{userId}}' },
        { key: 'Authorization', value: 'Bearer {{bearerToken}}' },
        { key: 'Content-Type', value: 'application/json' },
      ],
      body: {
        mode: 'raw',
        raw: JSON.stringify({ sessionId: '{{otherSessionId}}' }, null, 2),
        options: { language: { json: {} } },
      },
      tests: STANDARD_TESTS,
    }),
  ]),
]);

const oauthFolder = folder('OAuth2 (RFC 6749 / 7662 / 7009)', [
  req('POST /v1/oauth/token — password grant', {
    method: 'POST',
    path: '/v1/oauth/token',
    description: 'Issue an access token (JWT) via the Resource Owner Password Credentials grant. The response is the OAuth2 standard shape.',
    headers: [{ key: 'Content-Type', value: 'application/json' }],
    body: {
      mode: 'raw',
      raw: JSON.stringify({
        grant_type: 'password',
        username: 'alice@example.com',
        password: 'correct-horse-battery-staple',
      }, null, 2),
      options: { language: { json: {} } },
    },
    tests: `${STANDARD_TESTS}\n${SAVE_BEARER}`,
  }),
  req('POST /v1/oauth/token — refresh_token grant', {
    method: 'POST',
    path: '/v1/oauth/token',
    description: 'Exchange a refresh token for a new access token (RFC 6749 §6).',
    headers: [{ key: 'Content-Type', value: 'application/json' }],
    body: {
      mode: 'raw',
      raw: JSON.stringify({
        grant_type: 'refresh_token',
        refresh_token: '{{refreshToken}}',
      }, null, 2),
      options: { language: { json: {} } },
    },
    tests: `${STANDARD_TESTS}\n${SAVE_BEARER}`,
  }),
  req('POST /v1/oauth/introspect', {
    method: 'POST',
    path: '/v1/oauth/introspect',
    description: 'RFC 7662 token introspection. Returns {active: true, ...} when valid; {active: false} otherwise.',
    headers: [{ key: 'Content-Type', value: 'application/json' }],
    body: {
      mode: 'raw',
      raw: JSON.stringify({
        token: '{{bearerToken}}',
        token_type_hint: 'access_token',
      }, null, 2),
      options: { language: { json: {} } },
    },
    tests: STANDARD_TESTS,
  }),
  req('POST /v1/oauth/revoke', {
    method: 'POST',
    path: '/v1/oauth/revoke',
    description: 'RFC 7009 token revocation. Always returns 200 OK (per spec).',
    headers: [{ key: 'Content-Type', value: 'application/json' }],
    body: {
      mode: 'raw',
      raw: JSON.stringify({
        token: '{{refreshToken}}',
        token_type_hint: 'refresh_token',
      }, null, 2),
      options: { language: { json: {} } },
    },
    tests: STANDARD_TESTS,
  }),
  req('GET /.well-known/jwks.json', {
    method: 'GET',
    path: '/.well-known/jwks.json',
    description: 'JWKS document with all currently-verifying public keys. Resource servers fetch this on startup.',
    tests: 'pm.test("Status 200", () => pm.expect(pm.response.code).to.eql(200));\npm.collectionVariables.set("kid", pm.response.json().keys[0].kid);',
  }),
  req('POST /v1/oauth/admin/keys/rotate', {
    method: 'POST',
    path: '/v1/oauth/admin/keys/rotate',
    description: 'Operator-only. Mint a new RSA signing key. The previous key is retired with a grace window.',
    tests: `${STANDARD_TESTS}\npm.collectionVariables.set("kid", pm.response.json().kid);`,
  }),
]);

const identityFolder = folder('Identity', [
  folder('Public', [
    req('POST /v1/identity/register', {
      method: 'POST',
      path: '/v1/identity/register',
      description: 'Register a new user. Open to unauthenticated callers. Auto-creates a personal organization when no slug is supplied AND no email-domain matches.',
      headers: [{ key: 'Content-Type', value: 'application/json' }],
      body: {
        mode: 'raw',
        raw: JSON.stringify({
          email: 'alice@example.com',
          password: 'correct-horse-battery-staple',
          organizationSlug: '',
          displayName: 'Alice Example',
        }, null, 2),
        options: { language: { json: {} } },
      },
      tests: `${STANDARD_TESTS}\npm.collectionVariables.set("userId", pm.response.json().userId);\npm.collectionVariables.set("organizationSlug", pm.response.json().organizationSlug);`,
    }),
  ]),
  folder('Authenticated (X-User-Id placeholder)', [
    req('POST /v1/identity/change-password', {
      method: 'POST',
      path: '/v1/identity/change-password',
      description: "Change the authenticated user's password. Emits identity.password.changed — all sessions are revoked.",
      headers: [
        { key: 'X-User-Id', value: '{{userId}}' },
        { key: 'Content-Type', value: 'application/json' },
      ],
      body: {
        mode: 'raw',
        raw: JSON.stringify({
          currentPassword: 'correct-horse-battery-staple',
          newPassword: 'new-correct-horse-battery-staple',
        }, null, 2),
        options: { language: { json: {} } },
      },
      tests: STANDARD_TESTS,
    }),
    req('PATCH /v1/identity/me — set display name', {
      method: 'PATCH',
      path: '/v1/identity/me',
      description: "Update the authenticated user's display name.",
      headers: [
        { key: 'X-User-Id', value: '{{userId}}' },
        { key: 'Content-Type', value: 'application/json' },
      ],
      body: {
        mode: 'raw',
        raw: JSON.stringify({ displayName: 'Alice Newname' }, null, 2),
        options: { language: { json: {} } },
      },
      tests: STANDARD_TESTS,
    }),
    req('PATCH /v1/identity/me — clear display name', {
      method: 'PATCH',
      path: '/v1/identity/me',
      description: 'Remove the display name.',
      headers: [
        { key: 'X-User-Id', value: '{{userId}}' },
        { key: 'Content-Type', value: 'application/json' },
      ],
      body: {
        mode: 'raw',
        raw: JSON.stringify({ clearDisplayName: true }, null, 2),
        options: { language: { json: {} } },
      },
      tests: STANDARD_TESTS,
    }),
    req('POST /v1/identity/mfa/enable', {
      method: 'POST',
      path: '/v1/identity/mfa/enable',
      description: 'Begin MFA enrollment. Returns the TOTP secret and 10 recovery codes (returned ONCE).',
      headers: [
        { key: 'X-User-Id', value: '{{userId}}' },
        { key: 'Content-Type', value: 'application/json' },
      ],
      body: { mode: 'raw', raw: '{}', options: { language: { json: {} } } },
      tests: `${STANDARD_TESTS}\npm.collectionVariables.set("mfaSecret", pm.response.json().secret);\nconst codes = pm.response.json().recoveryCodes;\npm.collectionVariables.set("recoveryCodes", JSON.stringify(codes));\npm.collectionVariables.set("recoveryCode1", codes[0]);`,
    }),
    req('POST /v1/identity/mfa/confirm', {
      method: 'POST',
      path: '/v1/identity/mfa/confirm',
      description: 'Confirm MFA enrollment with a 6-digit TOTP code. The prerequest script computes the TOTP from {{mfaSecret}}.',
      headers: [
        { key: 'X-User-Id', value: '{{userId}}' },
        { key: 'Content-Type', value: 'application/json' },
      ],
      body: {
        mode: 'raw',
        raw: JSON.stringify({ code: '{{totpCode}}' }, null, 2),
        options: { language: { json: {} } },
      },
      prerequest: TOTP_PREREQUEST,
      tests: STANDARD_TESTS,
    }),
    req('POST /v1/identity/mfa/disable', {
      method: 'POST',
      path: '/v1/identity/mfa/disable',
      description: 'Disable MFA. Requires a valid TOTP code.',
      headers: [
        { key: 'X-User-Id', value: '{{userId}}' },
        { key: 'Content-Type', value: 'application/json' },
      ],
      body: {
        mode: 'raw',
        raw: JSON.stringify({ code: '{{totpCode}}' }, null, 2),
        options: { language: { json: {} } },
      },
      prerequest: TOTP_PREREQUEST,
      tests: STANDARD_TESTS,
    }),
    req('POST /v1/identity/mfa/verify', {
      method: 'POST',
      path: '/v1/identity/mfa/verify',
      description: 'Verify a TOTP or recovery code. Returns {matched: "totp" | "recovery"}.',
      headers: [
        { key: 'X-User-Id', value: '{{userId}}' },
        { key: 'Content-Type', value: 'application/json' },
      ],
      body: {
        mode: 'raw',
        raw: JSON.stringify({ code: '{{totpCode}}' }, null, 2),
        options: { language: { json: {} } },
      },
      prerequest: TOTP_PREREQUEST,
      tests: STANDARD_TESTS,
    }),
  ]),
]);

const engagementFolder = folder('Engagement', [
  folder('Public', [
    req('POST /v1/engagement/email-verification/confirm', {
      method: 'POST',
      path: '/v1/engagement/email-verification/confirm',
      description: 'Redeem an email-verification token. Single-use; expires after 24 hours.',
      headers: [{ key: 'Content-Type', value: 'application/json' }],
      body: {
        mode: 'raw',
        raw: JSON.stringify({ token: '{{emailVerificationToken}}' }, null, 2),
        options: { language: { json: {} } },
      },
      tests: STANDARD_TESTS,
    }),
    req('POST /v1/engagement/password-reset/request', {
      method: 'POST',
      path: '/v1/engagement/password-reset/request',
      description: 'Request a password-reset token. Always returns 204 (no enumeration leak).',
      headers: [{ key: 'Content-Type', value: 'application/json' }],
      body: {
        mode: 'raw',
        raw: JSON.stringify({ email: 'alice@example.com' }, null, 2),
        options: { language: { json: {} } },
      },
      tests: 'pm.test("Status 204", () => pm.expect(pm.response.code).to.eql(204));',
    }),
    req('POST /v1/engagement/password-reset/confirm', {
      method: 'POST',
      path: '/v1/engagement/password-reset/confirm',
      description: 'Redeem a password-reset token and set a new password.',
      headers: [{ key: 'Content-Type', value: 'application/json' }],
      body: {
        mode: 'raw',
        raw: JSON.stringify({
          token: '{{passwordResetToken}}',
          newPassword: 'new-correct-horse-battery-staple',
        }, null, 2),
        options: { language: { json: {} } },
      },
      tests: STANDARD_TESTS,
    }),
  ]),
  folder('Authenticated', [
    req('POST /v1/engagement/email-verification/request', {
      method: 'POST',
      path: '/v1/engagement/email-verification/request',
      description: 'Request a fresh verification token for the calling user.',
      headers: [{ key: 'X-User-Id', value: '{{userId}}' }],
      tests: 'pm.test("Status 204", () => pm.expect(pm.response.code).to.eql(204));',
    }),
    req('GET /v1/engagement/audit-log/me', {
      method: 'GET',
      path: '/v1/engagement/audit-log/me',
      description: "The authenticated user's own audit log.",
      headers: [{ key: 'X-User-Id', value: '{{userId}}' }],
      tests: STANDARD_TESTS,
    }),
  ]),
]);

/* ----- GraphQL requests ----- */

const INTROSPECTION = `query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types { ...FullType }
    directives { name description locations args { ...InputValue } }
  }
}
fragment FullType on __Type {
  kind name description
  fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason }
  possibleTypes { ...TypeRef }
}
fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue }
fragment TypeRef on __Type {
  kind name
  ofType { kind name ofType { kind name ofType { kind name } } }
}`;

const ME_QUERY = `query Me {
  me {
    id
    email
    displayName
    emailVerifiedAt
    createdAt
    mfaEnabled
    role
    organization { id slug name }
  }
}`;

const graphqlFolder = folder('GraphQL (POST /graphql)', [
  graphqlReq('Introspect — full schema', {
    description: 'Dump the full GraphQL schema. Useful for client codegen tools.',
    query: INTROSPECTION,
    variables: '{}',
    authHeader: false,
    tests: `pm.collectionVariables.set("__schemaQuery", pm.response.json().data.__schema.queryType.name);\npm.collectionVariables.set("__mutationType", pm.response.json().data.__schema.mutationType.name);`.trim(),
  }),
  graphqlReq('Query: health (unauth)', {
    description: 'Unauthenticated liveness probe over GraphQL.',
    query: 'query { health }',
    variables: '{}',
    authHeader: false,
    tests: 'pm.test("health=true", () => pm.expect(pm.response.json().data.health).to.eql(true));',
  }),
  graphqlReq('Mutation: register', {
    description: 'Register a new user. Open to unauthenticated callers.',
    query: `mutation Register($input: RegisterInput!) {
  register(input: $input) {
    userId
    email
    organizationId
    organizationSlug
    autoCreatedOrg
  }
}`,
    variables: JSON.stringify({
      input: { email: 'gql-alice@example.com', password: 'correct-horse-battery-staple' },
    }),
    tests: `${STANDARD_TESTS}\npm.collectionVariables.set("userId", pm.response.json().data.register.userId);\npm.collectionVariables.set("organizationSlug", pm.response.json().data.register.organizationSlug);`.trim(),
  }),
  graphqlReq('Query: me (auth required)', {
    description: 'Returns the currently-authenticated user.',
    query: ME_QUERY,
    variables: '{}',
    tests: `${REQUIRE_AUTH}\npm.test("returns the right user", () => pm.expect(pm.response.json().data.me.email).to.eql("gql-alice@example.com"));`.trim(),
  }),
  graphqlReq('Mutation: updateDisplayName', {
    description: 'Update display name.',
    query: `mutation UpdateMe($input: UpdateDisplayNameInput!) {
  updateDisplayName(input: $input) { id displayName }
}`,
    variables: JSON.stringify({ input: { displayName: 'GraphQL Alice' } }),
  }),
  graphqlReq('Mutation: enableMfa', {
    description: 'Begin MFA enrollment. Returns secret + 10 recovery codes (returned ONCE).',
    query: 'mutation { enableMfa { secret otpauthUrl recoveryCodes } }',
    variables: '{}',
    tests: `pm.collectionVariables.set("mfaSecret", pm.response.json().data.enableMfa.secret);
const codes = pm.response.json().data.enableMfa.recoveryCodes;
pm.collectionVariables.set("recoveryCodes", JSON.stringify(codes));
pm.collectionVariables.set("recoveryCode1", codes[0]);`.trim(),
  }),
  graphqlReq('Mutation: confirmMfaEnrollment', {
    description: 'Confirm MFA enrollment with a TOTP code. The prerequest script computes the TOTP.',
    query: 'mutation Confirm($input: MfaCodeInput!) { confirmMfaEnrollment(input: $input) }',
    variables: JSON.stringify({ input: { code: '{{totpCode}}' } }),
    prerequest: TOTP_PREREQUEST,
    tests: STANDARD_TESTS,
  }),
  graphqlReq('Mutation: disableMfa', {
    description: 'Disable MFA. Requires valid TOTP code.',
    query: 'mutation Disable($input: MfaCodeInput!) { disableMfa(input: $input) }',
    variables: JSON.stringify({ input: { code: '{{totpCode}}' } }),
    prerequest: TOTP_PREREQUEST,
    tests: STANDARD_TESTS,
  }),
  graphqlReq('Mutation: verifyMfa', {
    description: 'Verify a TOTP or recovery code.',
    query: `mutation Verify($input: VerifyMfaInput!) {
  verifyMfa(input: $input) { matched }
}`,
    variables: JSON.stringify({ input: { code: '{{totpCode}}' } }),
    prerequest: TOTP_PREREQUEST,
    tests: STANDARD_TESTS,
  }),
  graphqlReq('Mutation: requestPasswordReset (public)', {
    description: 'Always returns true. No enumeration leak.',
    query: 'mutation Request($input: RequestPasswordResetInput!) { requestPasswordReset(input: $input) }',
    variables: JSON.stringify({ input: { email: 'gql-alice@example.com' } }),
    authHeader: false,
    tests: STANDARD_TESTS,
  }),
  graphqlReq('Query: jwks (public)', {
    description: 'JWKS document with public keys.',
    query: 'query { jwks { keys { kid kty alg use n e } } }',
    variables: '{}',
    authHeader: false,
    tests: STANDARD_TESTS,
  }),
  graphqlReq('Query: verifyAccessToken', {
    description: 'Verify a JWT and return its claims.',
    query: `query Verify($input: VerifyAccessTokenInput!) {
  verifyAccessToken(input: $input) {
    sub
    org
    role
    scope
    jti
    iss
    aud
    iat
    exp
  }
}`,
    variables: JSON.stringify({ input: { token: '{{bearerToken}}' } }),
    authHeader: false,
    tests: `${REQUIRE_AUTH}
const data = pm.response.json().data;
if (data && data.verifyAccessToken) {
  pm.collectionVariables.set("verifiedSub", data.verifyAccessToken.sub);
  pm.collectionVariables.set("verifiedOrg", data.verifyAccessToken.org);
  pm.collectionVariables.set("verifiedRole", data.verifyAccessToken.role);
  pm.collectionVariables.set("verifiedScope", data.verifyAccessToken.scope);
}`.trim(),
  }),
]);

const examplesFolder = folder('Examples — chained flows', [
  folder('1. New user happy path', [
    req('▶ Register a fresh user', {
      method: 'POST',
      path: '/v1/identity/register',
      headers: [{ key: 'Content-Type', value: 'application/json' }],
      body: {
        mode: 'raw',
        raw: JSON.stringify({ email: 'chain-alice@example.com', password: 'correct-horse-battery-staple' }, null, 2),
        options: { language: { json: {} } },
      },
      tests: 'pm.collectionVariables.set("userId", pm.response.json().userId);',
    }),
    req('▶ Login as alice (REST, saves bearer)', {
      method: 'POST',
      path: '/v1/auth/login',
      headers: [{ key: 'Content-Type', value: 'application/json' }],
      body: {
        mode: 'raw',
        raw: JSON.stringify({ email: 'chain-alice@example.com', password: 'correct-horse-battery-staple' }, null, 2),
        options: { language: { json: {} } },
      },
      tests: LOGIN_TEST,
    }),
    graphqlReq('▶ Call /me over GraphQL with the saved bearer', {
      description: 'Verifies the bearer token round-trip end-to-end.',
      query: 'query Me { me { id email role organization { slug } } }',
      variables: '{}',
      tests: REQUIRE_AUTH + '\npm.test("email matches", () => pm.expect(pm.response.json().data.me.email).to.eql("chain-alice@example.com"));',
    }),
    req('▶ List active sessions', {
      method: 'GET',
      path: '/v1/auth/sessions',
      headers: [{ key: 'Authorization', value: 'Bearer {{bearerToken}}' }],
      tests: REQUIRE_AUTH,
    }),
  ]),
  folder('2. Password reset flow', [
    req('▶ Request reset (always 204)', {
      method: 'POST',
      path: '/v1/engagement/password-reset/request',
      headers: [{ key: 'Content-Type', value: 'application/json' }],
      body: {
        mode: 'raw',
        raw: JSON.stringify({ email: 'chain-alice@example.com' }, null, 2),
        options: { language: { json: {} } },
      },
      tests: 'pm.test("Status 204", () => pm.expect(pm.response.code).to.eql(204));',
    }),
    req('▶ Confirm reset (set passwordResetToken first)', {
      method: 'POST',
      path: '/v1/engagement/password-reset/confirm',
      headers: [{ key: 'Content-Type', value: 'application/json' }],
      body: {
        mode: 'raw',
        raw: JSON.stringify({
          token: '{{passwordResetToken}}',
          newPassword: 'new-correct-horse-battery-staple',
        }, null, 2),
        options: { language: { json: {} } },
      },
      tests: STANDARD_TESTS,
    }),
    req('▶ Re-login with the NEW password (proves rotation worked)', {
      method: 'POST',
      path: '/v1/auth/login',
      headers: [{ key: 'Content-Type', value: 'application/json' }],
      body: {
        mode: 'raw',
        raw: JSON.stringify({ email: 'chain-alice@example.com', password: 'new-correct-horse-battery-staple' }, null, 2),
        options: { language: { json: {} } },
      },
      tests: LOGIN_TEST,
    }),
  ]),
]);

const restItems = [healthFolder, authFolder, oauthFolder, identityFolder, engagementFolder];

/* ----- Build the collection ----- */

const collection = {
  info: {
    _postman_id: 'cerberus-' + uid(),
    name: 'Cerberus',
    description:
      'Full REST + GraphQL surface for the Cerberus auth service.\n\n' +
      '**Setup**\n' +
      '1. Import `Cerberus.dev.postman_environment.json`.\n' +
      '2. Set `baseUrl` to your running server (default `http://localhost:3000`).\n' +
      '3. Run `OAuth2 > POST /v1/oauth/token — password grant` — the test script auto-saves the bearer token into the env.\n\n' +
      '**Conventions**\n' +
      '- Every authenticated REST endpoint expects `Authorization: Bearer {{bearerToken}}`.\n' +
      '- Phase-11 placeholder endpoints (change-password, MFA, audit-log/me, update-display-name) expect `X-User-Id: {{userId}}` instead.\n' +
      '- TOTP codes are auto-computed by the prerequest script of `/mfa/confirm`, `/mfa/disable`, `/mfa/verify`, and the GraphQL MFA mutations.\n' +
      '- GraphQL endpoints all hit `POST /graphql`; the request body is a `{query, variables}` envelope.\n' +
      '- Error responses include `code` (REST) or `extensions.code` (GraphQL) with stable strings — switch on those in client code.',
    schema: 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json',
  },
  item: [...restItems, graphqlFolder, examplesFolder],
};

fs.writeFileSync(
  path.join(OUT_DIR, 'Cerberus.postman_collection.json'),
  JSON.stringify(collection, null, 2),
);

/* ----- Environments ----- */

function makeEnv(name, baseUrl) {
  return {
    id: uid(),
    name,
    values: [
      { key: 'baseUrl', value: baseUrl, enabled: true, type: 'default' },

      { key: 'bearerToken', value: '', enabled: true, type: 'secret' },
      { key: 'refreshToken', value: '', enabled: true, type: 'secret' },
      { key: 'expiresIn', value: '900', enabled: true, type: 'default' },
      { key: 'accessTokenTtl', value: '900', enabled: true, type: 'default' },

      { key: 'userId', value: '', enabled: true, type: 'default' },
      { key: 'currentSessionId', value: '', enabled: true, type: 'default' },
      { key: 'currentFamilyId', value: '', enabled: true, type: 'default' },
      { key: 'otherSessionId', value: '', enabled: true, type: 'default' },
      { key: 'organizationSlug', value: '', enabled: true, type: 'default' },

      { key: 'kid', value: '', enabled: true, type: 'default' },

      { key: 'mfaSecret', value: '', enabled: true, type: 'secret' },
      { key: 'totpCode', value: '', enabled: true, type: 'default' },
      { key: 'recoveryCodes', value: '[]', enabled: true, type: 'default' },
      { key: 'recoveryCode1', value: '', enabled: true, type: 'default' },

      { key: 'emailVerificationToken', value: '', enabled: true, type: 'secret' },
      { key: 'passwordResetToken', value: '', enabled: true, type: 'secret' },

      { key: 'verifiedSub', value: '', enabled: true, type: 'default' },
      { key: 'verifiedOrg', value: '', enabled: true, type: 'default' },
      { key: 'verifiedRole', value: '', enabled: true, type: 'default' },
      { key: 'verifiedScope', value: '', enabled: true, type: 'default' },

      { key: 'lastRequestId', value: '', enabled: true, type: 'default' },

      { key: '__schemaQuery', value: 'Query', enabled: true, type: 'default' },
      { key: '__mutationType', value: 'Mutation', enabled: true, type: 'default' },
    ],
    _postman_variable_scope: 'environment',
    _postman_exported_at: new Date().toISOString(),
    _postman_exported_using: 'Cerberus/gen-postman-collection.js',
  };
}

fs.writeFileSync(
  path.join(OUT_DIR, 'Cerberus.dev.postman_environment.json'),
  JSON.stringify(makeEnv('Cerberus — dev', 'http://localhost:3000'), null, 2),
);

fs.writeFileSync(
  path.join(OUT_DIR, 'Cerberus.staging.postman_environment.json'),
  JSON.stringify(makeEnv('Cerberus — staging', 'https://cerberus-staging.example.com'), null, 2),
);

console.log('Wrote:');
console.log('  - postman/Cerberus.postman_collection.json');
console.log('  - postman/Cerberus.dev.postman_environment.json');
console.log('  - postman/Cerberus.staging.postman_environment.json');
