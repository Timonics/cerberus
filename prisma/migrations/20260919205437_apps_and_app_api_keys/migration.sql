-- CreateTable
CREATE TABLE "apps" (
    "id" UUID NOT NULL,
    "name" VARCHAR(80) NOT NULL,
    "description" VARCHAR(500),
    "defaultOrgSlug" VARCHAR(80),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "contactEmail" VARCHAR(255) NOT NULL,
    "revokedAt" TIMESTAMP(3),
    "notes" VARCHAR(500),

    CONSTRAINT "apps_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "app_api_keys" (
    "id" UUID NOT NULL,
    "appId" UUID NOT NULL,
    "keyHash" VARCHAR(255) NOT NULL,
    "name" VARCHAR(80) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastUsedAt" TIMESTAMP(3),
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "revokedAt" TIMESTAMP(3),

    CONSTRAINT "app_api_keys_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "apps_defaultOrgSlug_idx" ON "apps"("defaultOrgSlug");

-- CreateIndex
CREATE INDEX "apps_revokedAt_idx" ON "apps"("revokedAt");

-- CreateIndex
CREATE INDEX "app_api_keys_appId_idx" ON "app_api_keys"("appId");

-- CreateIndex
CREATE INDEX "app_api_keys_keyHash_idx" ON "app_api_keys"("keyHash");

-- CreateIndex
CREATE INDEX "app_api_keys_revokedAt_idx" ON "app_api_keys"("revokedAt");

-- AddForeignKey
ALTER TABLE "app_api_keys" ADD CONSTRAINT "app_api_keys_appId_fkey" FOREIGN KEY ("appId") REFERENCES "apps"("id") ON DELETE CASCADE ON UPDATE CASCADE;
