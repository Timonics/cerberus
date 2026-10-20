-- V1.8: one invite per (organizationId, email). Existing duplicate
-- pairs are deduped first — the NEWEST invite per pair wins (an older
-- superseded invite is the one the application layer would have
-- replaced anyway) — then the unique constraint is enforced.
DELETE FROM "invitations" a
USING "invitations" b
WHERE a."organizationId" = b."organizationId"
  AND a."email" = b."email"
  AND a."createdAt" < b."createdAt";

ALTER TABLE "invitations" ADD CONSTRAINT "invitations_organizationId_email_key" UNIQUE ("organizationId", "email");
