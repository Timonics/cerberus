-- AlterTable
-- V1.5 (audit C-4): add mfaVerified to track whether the session has
-- completed MFA. Sessions for users without MFA have it default to
-- false; the OAuth grants require it true before issuing access tokens.

ALTER TABLE "sessions"
  ADD COLUMN "mfaVerified" BOOLEAN NOT NULL DEFAULT false;
