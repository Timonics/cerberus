-- V1.8 audit fix H-10: real audit dedup.
-- The prior constraint @@unique([eventType, id]) was tautological — `id`
-- is the row's own PK, freshly generated per insert — so re-published
-- events inserted duplicate rows. Replace it with @@unique([eventType,
-- eventId): event handlers pass the originating domain event's id, so
-- an outbox re-publish collides and is skipped (P2002).
--
-- Backfill eventId = id for existing rows: they are already unique per
-- (eventType, id), so the backfilled values satisfy the new constraint
-- with no dedup pass needed.
ALTER TABLE "audit_logs" ADD COLUMN "eventId" TEXT;

UPDATE "audit_logs" SET "eventId" = "id" WHERE "eventId" IS NULL;

ALTER TABLE "audit_logs" DROP CONSTRAINT "audit_logs_eventType_id_key";

ALTER TABLE "audit_logs" ADD CONSTRAINT "audit_logs_eventType_eventId_key" UNIQUE ("eventType", "eventId");
