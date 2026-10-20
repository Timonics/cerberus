-- V1.8: enforce "at most one current signing key" at the database
-- level. The check was application-layer only, so two concurrent
-- rotations could both commit and leave two rows with isCurrent = true
-- (JWKS would then expose both as signers). The partial unique index
-- makes the second commit fail with P2002. Prisma cannot express
-- partial indexes — this index is SQL-only by design; keep
-- @@index([isCurrent]) in the schema for the non-partial read paths.
CREATE UNIQUE INDEX "signing_keys_one_current" ON "signing_keys" ("isCurrent") WHERE "isCurrent" = true;
