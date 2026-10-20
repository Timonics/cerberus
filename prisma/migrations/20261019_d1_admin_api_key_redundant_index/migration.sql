-- V1.8: drop the redundant index on admin_api_keys.lookupToken.
-- The column is @unique, whose implicit unique index already serves
-- the O(1) lookup path. (@@index([keyHash]) is kept: keyHash is a live
-- query path for the legacy plaintext-hash admin lookup.)
DROP INDEX "admin_api_keys_lookupToken_idx";
