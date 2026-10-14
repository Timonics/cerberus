-- AlterTable
ALTER TABLE "admin_api_keys" ALTER COLUMN "lookupToken" DROP DEFAULT;

-- CreateTable
CREATE TABLE "outbox_events" (
    "id" UUID NOT NULL,
    "eventName" VARCHAR(120) NOT NULL,
    "aggregateType" VARCHAR(80),
    "aggregateId" UUID,
    "payload" JSONB NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "processedAt" TIMESTAMP(3),
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "lastError" VARCHAR(500),

    CONSTRAINT "outbox_events_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "outbox_events_processedAt_createdAt_idx" ON "outbox_events"("processedAt", "createdAt");

-- CreateIndex
CREATE INDEX "outbox_events_eventName_idx" ON "outbox_events"("eventName");
