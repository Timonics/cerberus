#!/bin/sh
# Runtime entrypoint (baked into the Dockerfile, runtime stage):
#
#   1. `prisma migrate deploy` — apply pending migrations before the
#      server binds. Idempotent and fails loudly; `set -e` guarantees a
#      failed migration never lets the server start against a stale
#      schema.
#   2. `exec "$@"` — hand off to the image CMD (`node dist/main.js`).
#      Exec-form keeps Node as PID 1's direct child so SIGTERM reaches
#      it and the Nest shutdown hooks in src/main.ts can drain.
set -e

echo '[entrypoint] prisma migrate deploy'
npx prisma migrate deploy

echo '[entrypoint] node dist/main.js'
exec "$@"
