-- CreateEnum
CREATE TYPE "admin_role" AS ENUM ('ADMIN', 'SUPER_ADMIN');

-- CreateTable
CREATE TABLE "admin_api_keys" (
    "id" UUID NOT NULL,
    "name" VARCHAR(80) NOT NULL,
    "keyHash" VARCHAR(255) NOT NULL,
    "role" "admin_role" NOT NULL DEFAULT 'ADMIN',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdBy" VARCHAR(120) NOT NULL,
    "lastUsedAt" TIMESTAMP(3),
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "revokedAt" TIMESTAMP(3),
    "notes" VARCHAR(255),

    CONSTRAINT "admin_api_keys_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "admin_api_keys_keyHash_idx" ON "admin_api_keys"("keyHash");

-- CreateIndex
CREATE INDEX "admin_api_keys_revokedAt_idx" ON "admin_api_keys"("revokedAt");

-- CreateIndex
CREATE INDEX "admin_api_keys_expiresAt_idx" ON "admin_api_keys"("expiresAt");
