-- V1.8: align sessions.organizationId with TEXT organizations.id
-- (the column was UUID — org scoping was never DB-validated) and add
-- the FK. ON DELETE SET NULL: deleting an org unscopes its sessions,
-- matching the V1 legacy semantics of NULL organizationId ("scoped to
-- the user's first org").
ALTER TABLE "sessions" ALTER COLUMN "organizationId" TYPE TEXT USING ("organizationId"::TEXT);

ALTER TABLE "sessions" ADD CONSTRAINT "sessions_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE SET NULL ON UPDATE CASCADE;
