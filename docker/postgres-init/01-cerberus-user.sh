#!/bin/bash
# =============================================================================
# Cerberus — Postgres init hook (runs once at first container start)
# =============================================================================
# Postgres 16 switched the default auth method to scram-sha-256. That works
# fine for in-cluster clients but breaks md5-style authentication from
# Windows host machines over Docker Desktop port-forwarded connections
# (the symptom is "password authentication failed for user X" even when
# the password is correct).
#
# This script runs before Postgres opens its listening socket. It:
#
#   1. Sets the password to be md5-hashed.
#   2. Rewrites pg_hba.conf so any non-loopback host can connect with md5.
#
# After this completes the entrypoint script starts Postgres, which will
# re-read pg_hba.conf and begin accepting connections.
# =============================================================================
set -e

echo "[cerberus-init] forcing md5 password hashing + permissive pg_hba"

# Set password_encryption via a one-shot psql invocation. We connect over
# the unix socket as the bootstrapping postgres user (which is the default
# superuser during initdb).
psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" <<-EOSQL
  SET password_encryption = 'md5';
  ALTER USER "$POSTGRES_USER" WITH PASSWORD '$POSTGRES_PASSWORD';
EOSQL

# Rewrite pg_hba.conf to permit md5 from any address. The default file
# is left in place at first, so we overwrite it entirely with our minimal
# rule set. Loopback stays trust-authenticated so debugging via
# `docker exec psql` continues to work without a password.
cat > "$PGDATA/pg_hba.conf" <<'EOCONF'
local   all             all                                     trust
host    all             all             127.0.0.1/32            trust
host    all             all             ::1/128                 trust
host    all             all             0.0.0.0/0               md5
host    all             all             ::/0                    md5
EOCONF

echo "[cerberus-init] pg_hba.conf rewritten"
cat "$PGDATA/pg_hba.conf"