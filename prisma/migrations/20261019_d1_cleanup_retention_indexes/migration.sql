-- V1.8: index the cleanup cron's purge predicates. The largest hot
-- table (sessions) previously had no index on revokedAt/expiresAt, so
-- every cleanup pass full-table-scanned it; the engagement token
-- tables had the same gap on expiresAt.
CREATE INDEX "sessions_revokedAt_idx" ON "sessions"("revokedAt");

CREATE INDEX "sessions_expiresAt_idx" ON "sessions"("expiresAt");

CREATE INDEX "email_verifications_expiresAt_idx" ON "email_verifications"("expiresAt");

CREATE INDEX "password_resets_expiresAt_idx" ON "password_resets"("expiresAt");

CREATE INDEX "invitations_expiresAt_idx" ON "invitations"("expiresAt");
