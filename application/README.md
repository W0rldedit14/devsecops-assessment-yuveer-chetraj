# Container Security

## Overview

Secure containerization of the Country Flags application (React frontend + Spring Boot backend) using multi-stage Docker builds, Alpine base images, non-root users, and runtime security constraints via Docker Compose.

## Architecture

```
┌─────────────────────────────────────────────────┐
│              Docker Compose Network              │
│                                                 │
│  ┌──────────────┐       ┌──────────────────┐   │
│  │   Frontend   │       │     Backend      │   │
│  │  node:alpine │──────▶│  temurin:11-jre  │   │
│  │  serve :8080 │ /api/ │  :8081           │   │
│  │  non-root    │       │  non-root        │   │
│  │  read-only   │       │  read-only       │   │
│  └──────────────┘       └──────────────────┘   │
│         ▲                                       │
└─────────┼───────────────────────────────────────┘
          │
    Host :8080
```

## Security Measures Implemented

### 1. Base Image Selection & Hardening

| Decision | Rationale |
|----------|-----------|
| `node:20-alpine` (build) | Minimal build image, no unnecessary OS packages |
| `node:20-alpine` + `serve` (frontend prod) | Same small Alpine base, `serve` is a zero-config static file server (~5MB overhead) |
| `eclipse-temurin:11-jre-alpine` (backend prod) | JRE-only (no JDK/compiler), Alpine base |

### 2. Multi-Stage Builds

Both Dockerfiles use multi-stage builds:

```
Stage 1 (Build)          Stage 2 (Production)
┌──────────────┐         ┌───────────────────┐
│ node_modules │         │ Static HTML/JS/CSS │  ← Only built assets
│ source code  │   ──▶   │ serve (static svr) │
│ npm/maven    │         │ ~50MB total        │
│ ~800MB+      │         └───────────────────┘
└──────────────┘
```

**Security benefit:** Build tools, source code, dev dependencies, and package managers are NOT present in the production image. This eliminates entire classes of supply chain attacks.

### 3. Non-Root Execution

```dockerfile
# Both containers run as UID 1001, not root
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup
USER appuser
```

**Why this matters:** If an attacker achieves code execution inside the container, they cannot:
- Install packages
- Modify system files
- Access `/etc/shadow`
- Bind to privileged ports (<1024)
- Escape to the host via root-level exploits

### 4. Dependency Management

| Measure | Implementation |
|---------|---------------|
| Lock files | `package-lock.json` and Maven dependency resolution ensure reproducible builds |
| `npm ci --ignore-scripts` | Installs exact versions from lockfile, skips post-install scripts (prevents supply chain attacks) |
| `mvnw dependency:go-offline` | Pre-downloads all deps in a separate layer for caching and auditability |
| `.dockerignore` | Prevents `node_modules/`, `.env`, `.git/` from entering the build context |

### 5. Runtime Security (Docker Compose)

| Control | Setting | Purpose |
|---------|---------|---------|
| **Drop capabilities** | `cap_drop: [ALL]` | Removes all Linux capabilities (no raw sockets, no network admin, no mount) |
| **No privilege escalation** | `no-new-privileges:true` | Prevents `setuid`/`setgid` binaries from gaining root |
| **Read-only filesystem** | `read_only: true` | Container filesystem is immutable; writes only to tmpfs mounts |
| **tmpfs for writes** | `/tmp`, `/var/cache/nginx`, `/var/run` | Volatile storage for required writable paths only |
| **Resource limits** | CPU + memory caps | Prevents resource exhaustion / DoS attacks |
| **Health checks** | HTTP endpoint checks | Enables automatic restart of failed containers |
| **Restart policy** | `unless-stopped` | Auto-recovery without requiring manual intervention |

### 6. Network Security

- Containers communicate over an isolated Docker bridge network
- Only required ports are published to the host (8080, 8081)
- Frontend proxies `/api/` to backend — backend doesn't need direct external access

### 7. Scanning Commands

```bash
# Scan built images for vulnerabilities (Trivy)
docker build -t country-flags-frontend -f application/Dockerfile .
trivy image country-flags-frontend

# Scan Dockerfiles for misconfigurations (Checkov)
checkov --file application/Dockerfile --framework dockerfile
checkov --file application/Dockerfile.backend --framework dockerfile

# Scan Docker Compose for insecure settings (Checkov)
checkov --file infrastructure/docker-compose.yml
```

## Scanning Integration

### Container Image Scanning (Trivy)

```bash
# Scan the built frontend image
docker build -t country-flags-frontend -f application/Dockerfile .
trivy image country-flags-frontend --format sarif --output trivy-frontend.sarif

# Scan the built backend image
docker build -t country-flags-backend -f application/Dockerfile.backend .
trivy image country-flags-backend --format sarif --output trivy-backend.sarif
```

### Dockerfile Linting (Checkov)

```bash
# Scan Dockerfiles for misconfigurations
checkov --file application/Dockerfile --framework dockerfile
checkov --file application/Dockerfile.backend --framework dockerfile
```

### Docker Compose Security Check (Checkov)

```bash
# Scan compose file for insecure configurations
checkov --file infrastructure/docker-compose.yml
```

```bash
# From the repository root
cd infrastructure
docker compose up --build

# Access:
# Frontend: http://localhost:8080
# Backend:  http://localhost:8081
```

## File Structure

```
application/
├── Dockerfile              # Frontend (React → Node Alpine + serve)
├── Dockerfile.backend      # Backend (Spring Boot → JRE Alpine)
├── .dockerignore           # Prevents secrets/source from leaking into images
└── README.md               # This documentation

infrastructure/
└── docker-compose.yml      # Secure deployment with runtime constraints
```
