# ============================================================
# Multi-stage Dockerfile for Country Flags App (React Frontend)
# Security: Alpine base, non-root user, minimal attack surface
# ============================================================

# ── Stage 1: Build ──────────────────────────────────────────
FROM node:20-alpine AS build

WORKDIR /app

# Install dependencies first (layer caching)
COPY country-flags-app-main/package.json country-flags-app-main/package-lock.json ./
RUN npm ci --ignore-scripts

# Copy source and build
COPY country-flags-app-main/ ./
RUN npm run build

# ── Stage 2: Production ────────────────────────────────────
FROM node:20-alpine AS production

# Security: Install only the static file server
RUN npm install -g serve@14 && npm cache clean --force

WORKDIR /app

# Security: Create non-root user
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# Copy built assets from build stage only
COPY --from=build --chown=appuser:appgroup /app/build ./build

# Security: Run as non-root
USER appuser

EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD node -e "require('http').get('http://localhost:8080/', (r) => { process.exit(r.statusCode === 200 ? 0 : 1) }).on('error', () => process.exit(1))"

CMD ["serve", "-s", "build", "-l", "8080"]
