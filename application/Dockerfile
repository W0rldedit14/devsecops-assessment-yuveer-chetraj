# ============================================================
# Multi-stage Dockerfile — Frontend & Backend
# Build targets: "frontend" and "backend"
# Security: Alpine bases, non-root users, minimal attack surface
# ============================================================

# ════════════════════════════════════════════════════════════
# FRONTEND (React → Node Alpine + serve)
# ════════════════════════════════════════════════════════════

# ── Frontend Build ──────────────────────────────────────────
FROM node:20-alpine AS frontend-build

WORKDIR /app

COPY country-flags-app-main/package.json country-flags-app-main/package-lock.json ./
RUN npm ci --ignore-scripts

COPY country-flags-app-main/ ./
RUN npm run build

# ── Frontend Production ─────────────────────────────────────
FROM node:20-alpine AS frontend

RUN npm install -g serve@14 && npm cache clean --force

WORKDIR /app

RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

COPY --from=frontend-build --chown=appuser:appgroup /app/build ./build

USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD node -e "require('http').get('http://localhost:8080/', (r) => { process.exit(r.statusCode === 200 ? 0 : 1) }).on('error', () => process.exit(1))"

CMD ["serve", "-s", "build", "-l", "8080"]


# ════════════════════════════════════════════════════════════
# BACKEND (Spring Boot → JRE Alpine)
# ════════════════════════════════════════════════════════════

# ── Backend Build ───────────────────────────────────────────
FROM maven:3.9-eclipse-temurin-17-alpine AS backend-build

WORKDIR /app

COPY country-service-main/pom.xml ./
COPY country-service-main/.mvn ./.mvn
COPY country-service-main/mvnw ./
RUN chmod +x mvnw && ./mvnw dependency:go-offline -B

COPY country-service-main/src ./src
RUN ./mvnw package -DskipTests -Dcheckstyle.skip=true -Djava.version=17 -Dmaven.compiler.release=17 -B

# ── Backend Production ──────────────────────────────────────
FROM eclipse-temurin:17-jre-alpine AS backend

RUN apk --no-cache add dumb-init

WORKDIR /app

RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

COPY --from=backend-build /app/target/*.jar app.jar

RUN chown appuser:appgroup app.jar && \
    chmod 400 app.jar

USER appuser

EXPOSE 8081

HEALTHCHECK --interval=10s --timeout=5s --start-period=60s --retries=5 \
    CMD wget --server-response --spider http://localhost:8081/ 2>&1 | grep -q 'HTTP' || exit 1

ENTRYPOINT ["dumb-init", "--"]
CMD ["java", "-Djava.security.egd=file:/dev/./urandom", "-jar", "app.jar", "--server.port=8081"]
