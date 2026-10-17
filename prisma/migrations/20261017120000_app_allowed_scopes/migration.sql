-- AlterTable
-- V1.6 client_credentials grant: per-app scope allowlist. Empty
-- string = the app authenticates but receives zero scopes (RFC 6749
-- §3.3 — caller can never get more than the server allows).
ALTER TABLE "apps" ADD COLUMN "allowedScopes" VARCHAR(1024) NOT NULL DEFAULT '';
