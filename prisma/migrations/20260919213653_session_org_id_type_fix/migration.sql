/*
  Warnings:

  - The `organizationId` column on the `sessions` table would be dropped and recreated. This will lead to data loss if there is data in the column.

*/
-- AlterTable
ALTER TABLE "sessions" DROP COLUMN "organizationId",
ADD COLUMN     "organizationId" UUID;

-- CreateIndex
CREATE INDEX "sessions_organizationId_idx" ON "sessions"("organizationId");
