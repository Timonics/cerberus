-- AlterTable
ALTER TABLE "apps" ADD COLUMN     "idempotencyKey" VARCHAR(128);

-- CreateIndex
CREATE UNIQUE INDEX "apps_idempotencyKey_key" ON "apps"("idempotencyKey");

