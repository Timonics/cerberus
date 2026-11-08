# syntax=docker/dockerfile:1.7

# ─── deps ────────────────────────────────────────────────────
FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

# ─── build ───────────────────────────────────────────────────
FROM node:22-alpine AS build
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npx prisma generate
RUN npm run build

# ─── runtime ─────────────────────────────────────────────────
FROM node:22-alpine AS runtime
ENV NODE_ENV=production
WORKDIR /app
RUN addgroup -g 1001 -S nodejs && adduser -S nestjs -u 1001

COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

# The start command runs `prisma migrate deploy`, so the Prisma CLI
# must exist in the runtime image even though it's a devDependency.
# Install it standalone (no-save) at the version pinned in
# package.json — this keeps the two in sync automatically. Dropping
# --omit=dev above instead would ship the entire dev toolchain
# (jest, eslint, ts-jest…) in the production image.
RUN npm install --no-save --no-audit --no-fund \
      "prisma@$(node -p "require('./package.json').devDependencies.prisma")"

COPY --from=build /app/dist ./dist
COPY --from=build /app/prisma ./prisma
COPY --from=build /app/node_modules/.prisma ./node_modules/.prisma
COPY --from=build /app/node_modules/@prisma ./node_modules/@prisma

USER nestjs
EXPOSE 3000

# Use exec-form so Node receives SIGTERM directly and shutdown hooks can run.
CMD ["node", "dist/main.js"]