-- V1.7 audit fix #31: dedup-by-(eventType, id) on audit_logs.
-- The outbox relay can re-publish a row if the process crashes
-- between bus.publish and the processedAt update (see #33). A
-- DB-level unique constraint makes the dedup atomic.
ALTER TABLE "audit_logs" ADD CONSTRAINT "audit_logs_eventType_id_key" UNIQUE ("eventType", "id");
