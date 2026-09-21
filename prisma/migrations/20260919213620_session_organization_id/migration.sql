-- AlterTable
ALTER TABLE "sessions" ADD COLUMN     "organizationId" TEXT;

-- CreateIndex
CREATE INDEX "sessions_organizationId_idx" ON "sessions"("organizationId");
