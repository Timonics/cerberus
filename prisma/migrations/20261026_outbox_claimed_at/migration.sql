-- Claim-based outbox relay: a relay marks rows it is about to
-- publish so a second relay instance (e.g. the admin listener
-- booted in the same process, or a second replica) cannot pick up
-- the same row and double-deliver the event.

ALTER TABLE "outbox_events" ADD COLUMN "claimedAt" TIMESTAMP(3);

CREATE INDEX "outbox_events_processedAt_claimedAt_idx" ON "outbox_events"("processedAt", "claimedAt");
