# Container Security Documentation

## Overview

Secure containerization of the Country Flags application (React frontend + Spring Boot backend) using a single multi-stage Dockerfile with build targets, Alpine base images, and runtime security constraints via Docker Compose.

## File Structure

```
application/
├── Dockerfile          # Multi-stage: targets "frontend" and "backend"
├── .dockerignore       # Prevents secrets/source from leaking into images
└── README.md           # This documentation

infrastructure/
└── docker-compose.yml  # Secure deployment with runtime constraints
```

---

## 1. Base Image Selection & Hardening

### Decisions

| Image | Used For | Why |
|-------|----------|-----|
| `node:20-alpine` | Frontend build + runtime | Alpine is ~5MB vs ~900MB for full Debian. Minimal OS = fewer CVEs to patch. |
| `maven:3.9-eclipse-temurin-17-alpine` | Backend build only | Full JDK + Maven needed for compilation, but never ships to production. |
| `eclipse-temurin:17-jre-alpine` | Backend runtime | JRE-only (no compiler/debugger), Alpine base. Removes entire JDK attack surface. |

### Hardening Measures

| Measure | Implementation | Security Benefit |
|---------|---------------|------------------|
| **Pinned image digests** | `FROM node:20-alpine@sha256:fb4cd12c...` | Prevents supply chain attacks — even if the tag is overwritten on Docker Hub, we pull the exact verified image |
| **Multi-stage builds** | Build tools in stage 1, only artifacts in stage 2 | Production image has no source code, no package managers, no compilers |
| **Alpine base** | All production images use Alpine Linux | ~5MB base with musl libc. Fewer packages = fewer vulnerabilities |
| **npm cache clean** | `npm cache clean --force` | Removes cached packages that could contain pre/post-install exploits |

### What's NOT in the production image

| Removed via multi-stage | Risk it eliminates |
|------------------------|-------------------|
| `node_modules/` (1000+ packages) | Supply chain vulnerabilities in dev dependencies |
| Maven, JDK, compiler tools | Compiler-based attacks, tool exploitation |
| Source code (`*.java`, `*.jsx`) | Source code disclosure |
| `.git/` directory | Credential/history leakage |
| `.env` files | Secret exposure |

---

## 2. Dependency Management

| Measure | Implementation | Security Benefit |
|---------|---------------|------------------|
| **Lock files** | `package-lock.json` for npm, `pom.xml` with fixed versions | Reproducible builds — same deps every time |
| **`npm ci --ignore-scripts`** | Dockerfile frontend build stage | Installs exact versions from lockfile. `--ignore-scripts` prevents `postinstall` scripts from executing (blocks supply chain attacks like event-stream) |
| **`mvnw dependency:go-offline`** | Dockerfile backend build stage | Pre-downloads all Maven deps in a cached layer. Deps are resolved once and frozen. |
| **`.dockerignore`** | Excludes `node_modules/`, `.env`, `.git/`, `target/` | Prevents local dev dependencies or secrets from accidentally entering the build context |
| **No `apt-get`/`apk add` in production** | Only `dumb-init` added to backend | Minimises additional packages. No package manager left in production image. |

---

## 3. Runtime Security (User, Permissions, Capabilities)

### Non-Root Execution

```dockerfile
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup
USER appuser
```

Both containers run as **UID 1001** (not root). If an attacker gains code execution, they cannot:
- Install packages or modify system files
- Read `/etc/shadow` or other sensitive system files
- Bind to privileged ports (< 1024)
- Exploit kernel vulnerabilities that require root

### File Permissions

```dockerfile
RUN chown appuser:appgroup app.jar && \
    chmod 400 app.jar
```

The backend JAR is **read-only by owner only** (400). Even if another process runs in the container, it cannot modify or replace the application binary.

### Capabilities (Docker Compose)

```yaml
cap_drop:
  - ALL
security_opt:
  - no-new-privileges:true
```

| Control | What it does |
|---------|-------------|
| `cap_drop: ALL` | Removes ALL Linux capabilities. No raw sockets, no network admin, no mount, no chown, no kill signals to other processes. |
| `no-new-privileges` | Prevents any process from gaining more privileges than its parent (blocks setuid/setgid exploitation). |

### Read-Only Filesystem

```yaml
read_only: true
tmpfs:
  - /tmp:noexec,nosuid,size=100M
```

| Control | What it does |
|---------|-------------|
| `read_only: true` | Entire container filesystem is immutable. Attackers cannot write backdoors, cron jobs, or scripts. |
| `tmpfs` with `noexec` | Only `/tmp` is writable (needed by JVM/Node). But nothing written there can be executed. |
| `nosuid` | No setuid binaries can be placed in writable areas. |
| `size=` limits | Caps tmpfs size to prevent disk-filling DoS. |

### Resource Limits

```yaml
deploy:
  resources:
    limits:
      cpus: "1.0"
      memory: 512M
```

Prevents a compromised container from consuming all host resources (CPU/memory DoS).

### Health Checks

```yaml
healthcheck:
  test: ["CMD-SHELL", "wget --server-response --spider http://localhost:8081/ 2>&1 | grep -q 'HTTP' || exit 1"]
  interval: 10s
  start_period: 60s
```

Containers are automatically restarted if they become unhealthy. Combined with `restart: unless-stopped`, this provides self-healing without manual intervention.

---

## 4. Scanning Integration

### Container Image Scanning (Trivy)

Scan built images for OS and library vulnerabilities:

```bash
# Build images
docker compose build

# Scan frontend image
trivy image infrastructure-frontend --severity HIGH,CRITICAL

# Scan backend image
trivy image infrastructure-backend --severity HIGH,CRITICAL

# Output as SARIF for CI integration
trivy image infrastructure-backend --format sarif --output trivy-backend.sarif
```

### Dockerfile Best Practice Scanning (Checkov)

Scan Dockerfiles for misconfigurations:

```bash
checkov --file application/Dockerfile --framework dockerfile
```

Example findings Checkov catches:
- Missing `HEALTHCHECK` instruction
- Running as root (no `USER` directive)
- Using `latest` tag instead of pinned versions
- Missing `--no-cache` on `apk add`

### Docker Compose Scanning (Checkov)

```bash
checkov --file infrastructure/docker-compose.yml
```

Example findings:
- Missing `cap_drop`
- No resource limits defined
- `privileged: true` usage
- Missing `read_only` filesystem

---

## 5. Security Decisions Summary

| Decision | Alternative Considered | Why This Choice |
|----------|----------------------|-----------------|
| Alpine over Debian/Ubuntu | Debian slim | Alpine has ~5MB base with far fewer CVEs. Tradeoff: musl libc can cause compatibility issues, but not for our use case. |
| `serve` over Nginx | Nginx Alpine | Simpler setup, fewer moving parts. For a production system, Nginx would provide security headers and better performance. |
| Pinned digests over tags | Just `:20-alpine` tag | Tags are mutable — a compromised Docker Hub account could push a malicious image to the same tag. Digests are immutable. |
| `cap_drop: ALL` over selective | Only drop dangerous ones | Principle of least privilege. Start with nothing, add back only if needed. Neither app needs any Linux capabilities. |
| Read-only + tmpfs over writable | Default writable filesystem | Prevents persistence. Even if attacker gets shell, they can't write malware. tmpfs with noexec means they can't execute anything either. |
| Non-root (UID 1001) over root | Run as root (default) | Container breakout exploits almost always require root. Non-root limits blast radius significantly. |
| `--ignore-scripts` on npm | Default npm install | Blocks supply chain attacks via postinstall scripts (like the event-stream incident). Build still works because our deps don't need lifecycle scripts. |
| `dumb-init` for backend | Direct `java -jar` | Proper signal handling (SIGTERM forwarded to JVM). Prevents zombie processes. Enables graceful shutdown. |
| Separate build targets in one Dockerfile | Two Dockerfiles | Single source of truth, easier to maintain, shared patterns visible. Docker Compose `target:` selects which to build. |

---

## Running the Application

```bash
cd infrastructure
docker compose up --build

# Frontend: http://localhost:8080
# Backend:  http://localhost:8081

# Stop
docker compose down
```

## Verifying Security Controls

```bash
# Confirm non-root
docker exec country-flags-frontend whoami
# → appuser

# Confirm read-only filesystem
docker exec country-flags-frontend sh -c "touch /pwned"
# → Read-only file system

# Confirm noexec tmpfs
docker exec country-flags-backend sh -c "echo '#!/bin/sh' > /tmp/test.sh && chmod +x /tmp/test.sh && /tmp/test.sh"
# → Permission denied

# Confirm no capabilities
docker exec country-flags-frontend sh -c "cat /proc/1/status | grep CapEff"
# → 0000000000000000 (no capabilities)

# Check resource usage
docker stats --no-stream
```
