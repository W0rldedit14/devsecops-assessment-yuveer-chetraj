Block 3: Container Security (45 minutes)
Secure the provided application through containerization.

Requirements:
Create application/Dockerfile (multi-stage, minimal, non-root)
Add container scanning to catch vulnerabilities, we will use trivy, and checkov
Create secure deployment config (Docker Compose or K8s), we will use docker compose
Document security measures implemented
Focus areas:
Base image selection and hardening, we will use an alpine image
Dependency management
Runtime security (user, permissions, capabilities)
Scanning integration
Deliverables (45 min):
application/Dockerfile
infrastructure/docker-compose.yml OR infrastructure/k8s/, docker compose
Documentation of security decisions

