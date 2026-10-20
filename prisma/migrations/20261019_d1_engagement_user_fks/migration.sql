-- V1.8: the engagement token tables were orphan-prone (userId with no
-- FK). Remove pre-existing orphans first — their users no longer exist,
-- so the tokens can never complete a flow against a real user — then
-- add cascading FKs so user deletion invalidates outstanding tokens.
DELETE FROM "email_verifications"
WHERE NOT EXISTS (SELECT 1 FROM "users" WHERE "users"."id" = "email_verifications"."userId");

DELETE FROM "password_resets"
WHERE NOT EXISTS (SELECT 1 FROM "users" WHERE "users"."id" = "password_resets"."userId");

ALTER TABLE "email_verifications" ADD CONSTRAINT "email_verifications_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "password_resets" ADD CONSTRAINT "password_resets_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
