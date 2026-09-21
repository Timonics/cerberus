-- AlterTable
ALTER TABLE "sessions" ADD COLUMN     "previousRefreshHashes" TEXT[] DEFAULT ARRAY[]::TEXT[];
