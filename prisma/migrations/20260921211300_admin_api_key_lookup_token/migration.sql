-- AlterTable
-- V1.5: add lookupToken to admin_api_keys for O(1) admin auth lookups.
-- We previously scanned every admin key and ran argon2 verify on each
-- (O(N) per request, ~5s with 100 keys). With lookupToken we look up
-- by HMAC-SHA256(secret, plaintext) first, then verify the match with
-- argon2 (one verify per request instead of N).

ALTER TABLE "admin_api_keys"
  ADD COLUMN "lookupToken" VARCHAR(64) NOT NULL DEFAULT 'pending';

-- Backfill existing rows with a placeholder lookupToken. These are
-- legacy keys that predate the lookupToken column. Operators must
-- rotate any existing admin keys for them to work — V1.5 will surface
-- a warning at startup if any row has lookupToken='pending'.

UPDATE "admin_api_keys" SET "lookupToken" = 'pending-' || "id"
  WHERE "lookupToken" = 'pending';

-- Enforce uniqueness on lookupToken.
CREATE UNIQUE INDEX "admin_api_keys_lookupToken_key" ON "admin_api_keys"("lookupToken");
CREATE INDEX "admin_api_keys_lookupToken_idx" ON "admin_api_keys"("lookupToken");
