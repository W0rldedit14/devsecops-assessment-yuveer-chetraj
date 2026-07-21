# DevSecOps Architecture Design

## 1. Current State Analysis

Based on the provided Country Flags application (React frontend + Spring Boot backend):

### What Exists Today

| Area | Current State | Risk |
|------|--------------|------|
| Source Control | Git repo, no branch protection | Anyone can push to main |
| CI/CD | None (manual builds) | No automated checks, human error |
| Security Testing | None built-in | Vulnerabilities go to production undetected |
| Dependency Management | Lock files exist but not audited | Known CVEs in dependencies |
| Secrets Management | `.env` file in repo | Secrets exposed in source control |
| Container Security | No Dockerfiles existed | No standardized deployments |
| Monitoring | None | No visibility into runtime attacks |

### Key Gaps

1. **No automated security gates** — code goes from developer laptop to production with zero security checks
2. **Hardcoded secrets** — API keys and config in source files
3. **No container hardening** — if deployed, would run as root with full capabilities
4. **No dependency tracking** — no one knows which libraries have known vulnerabilities
5. **No visibility** — no logs, no alerts, no way to know if you're being attacked

---

## 2. Target Architecture

### High-Level Design

```
┌──────────────────────────────────────────────────────────────────────┐
│                        DEVELOPER WORKSTATION                          │
│                                                                      │
│  IDE + Pre-commit Hooks                                              │
│  • Secret scanning (prevent commits with keys)                       │
│  • Linting                                                           │
└──────────────────┬───────────────────────────────────────────────────┘
                   │ git push
                   ▼
┌──────────────────────────────────────────────────────────────────────┐
│                        SOURCE CONTROL (GitHub)                        │
│                                                                      │
│  • Branch protection (require PR reviews)                            │
│  • Signed commits                                                    │
│  • CODEOWNERS file                                                   │
└──────────────────┬───────────────────────────────────────────────────┘
                   │ triggers
                   ▼
┌──────────────────────────────────────────────────────────────────────┐
│                        CI PIPELINE (GitHub Actions)                   │
│                                                                      │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐  │
│  │ Secrets │  │   IaC   │  │  SAST   │  │   SCA   │  │Container│  │
│  │ Checkov │  │ Checkov │  │ Semgrep │  │  Grype  │  │  Trivy  │  │
│  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘  │
│       └─────────────┴───────────┴─────────────┴────────────┘        │
│                              │                                       │
│                    ┌─────────▼──────────┐                            │
│                    │   QUALITY GATE     │                            │
│                    │ Critical → FAIL    │                            │
│                    │ High → WARN        │                            │
│                    │ Med/Low → PASS     │                            │
│                    └─────────┬──────────┘                            │
│                              │                                       │
└──────────────────────────────┼───────────────────────────────────────┘
                               │ pass
                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│                        CD PIPELINE (Deploy)                           │
│                                                                      │
│  • Build container images (multi-stage, Alpine, non-root)            │
│  • Push to private registry                                          │
│  • Deploy to staging → production                                    │
└──────────────────┬───────────────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────────────────────────┐
│                        RUNTIME ENVIRONMENT                           │
│                                                                      │
│  ┌─────────────────────┐    ┌─────────────────────┐                 │
│  │  Frontend Container │    │  Backend Container  │                 │
│  │  • Non-root         │    │  • Non-root         │                 │
│  │  • Read-only FS     │    │  • Read-only FS     │                 │
│  │  • No capabilities  │    │  • No capabilities  │                 │
│  │  • Resource limits  │    │  • Resource limits  │                 │
│  └─────────────────────┘    └─────────────────────┘                 │
│                                                                      │
│  Runtime Monitoring: Logs → Alerts → Incident Response               │
└──────────────────────────────────────────────────────────────────────┘
```

### Security Integration Points

| Phase | What Happens | Tool | Automated? |
|-------|-------------|------|-----------|
| **Code** | Developer writes code | IDE linting | Yes (real-time) |
| **Pre-commit** | Block secrets before they hit Git | git-secrets / pre-commit hooks | Yes |
| **PR** | Peer review + automated scans | GitHub PR + pipeline | Yes |
| **Build** | SAST, SCA, secrets, IaC scanning | Semgrep, Grype, Checkov | Yes |
| **Quality Gate** | Fail on critical findings | Python SARIF parser | Yes |
| **Package** | Container image scanning | Trivy | Yes |
| **Deploy** | Only signed/scanned images deploy | Registry policy | Yes |
| **Runtime** | Container hardening, monitoring | Docker Compose / K8s policies / OPA | Yes |

---

## 3. Implementation Roadmap

### Phase 1: Foundation (Week 1-2) 

| Task | Status | Impact |
|------|--------|--------|
| CI pipeline with security scanners | ✅ Done | Automated security checks on every push on main|
| Quality gates (fail on critical) | ✅ Done | Blocks dangerous code from merging |
| Secure Dockerfiles (multi-stage, non-root) | ✅ Done | Hardened containers |
| Docker Compose with runtime security | ✅ Done | Defense in depth at runtime |
| Security scanning script (local) | ✅ Done | Developers can scan before pushing |

### Phase 2: Strengthen (Week 3-4)

| Task | Effort | Impact |
|------|--------|--------|
| Pre-commit hooks (block secrets locally) | Low | Prevent secrets from ever entering Git |
| Branch protection rules on main | Low | Enforce PR reviews |
| Fix existing critical/high findings | Medium | Reduce current risk |
| Add DAST scanning (ZAP) in staging | Medium | Find runtime vulnerabilities |
| Centralized secrets manager (Vault/AWS SM) | Medium | Remove secrets from code/env vars |

### Phase 3: Scale (Month 2-3)

| Task | Effort | Impact |
|------|--------|--------|
| Private container registry with scanning policy | Medium | Only clean images deploy |
| Runtime monitoring + alerting like Falco and send results to the SIEM| Medium | Know when you're being attacked |
| SBOM generation (Software Bill of Materials) | Low | Track what's in every deployment |
| Security dashboards | Medium | Visibility for management |
| Incident response playbooks | Low | Know what to do when things break |

### Phase 4: Mature (Month 3-6)

| Task | Effort | Impact |
|------|--------|--------|
| Policy-as-code (OPA/Gatekeeper) | High | Automated compliance enforcement, that we own and vendor intrul |
| Chaos engineering (security) | High | Test resilience to attacks |
| Bug bounty program | Medium | External security testing |
| SOC2/ISO27001 alignment | High | Formal compliance |

---

## 4. Tool Selection & Justification

### Chosen Tools

| Tool | Category | Why This One | Alternatives Considered |
|------|----------|-------------|------------------------|
| **Semgrep** | SAST | Fast, low false positives, free OSS tier, supports 30+ languages, custom rules | SonarQube (heavy, needs server), CodeQL (GitHub-only) |
| **Checkov** | Secrets + IaC | Single tool covers secrets AND infrastructure scanning, SARIF output, no server needed | tfsec (Terraform only), detect-secrets (secrets only) |
| **Grype** | SCA/Dependencies | Single binary, fast, multi-language, SARIF output, no API key needed | Snyk (requires auth), OWASP Dep-Check (slow, Java-based) |
| **Trivy** | Container scanning | Industry standard, scans OS packages + app deps in images, SARIF output | Clair (complex setup), Twistlock (enterprise-focused) |
| **GitHub Actions** | CI/CD | Free tier sufficient, native Git integration, no extra infrastructure | Jenkins (maintenance burden), GitLab CI (migration needed) |
| **Docker Compose** | Deployment | Simple, works locally and in CI, good for small-medium teams | Kubernetes (overkill for current scale) |

### Selection Criteria

1. **Free/OSS** — no licensing cost for a growing team
2. **SARIF output** — common format enables unified quality gates
3. **No server required** — tools run in CI, no infrastructure to maintain
4. **Fast** — scans complete in < 2 minutes total
5. **Low false positives** — developers won't ignore alerts if they're accurate

---

## 5. Scalability Considerations

### What Changes as the Team Grows

| Team Size | Architecture Change | Why |
|-----------|-------------------|-----|
| **1-5 devs** (now) | Single pipeline, Docker Compose, manual deploys | Simple, low overhead, everyone knows everything |
| **5-15 devs** | Add PR reviewers, separate staging env, scheduled scans | Need gatekeeping, can't review every change yourself |
| **15-50 devs** | Move to Kubernetes, add Vault for secrets, policy-as-code | Multiple services, need automated governance |
| **50+ devs** | Platform team, self-service pipelines, security champions program | Can't have one team review all code |

### Scaling the Security Pipeline

```
Today (2 apps):                 Future (20+ services):
                                
Single pipeline                 Template pipelines
All tools run every time        Only scan changed services
SARIF files as artifacts        Central security dashboard
Manual triage                   Auto-ticket creation (Jira)
```

---

## 6. Team Workflow Optimization

### Developer Experience (DX) First

Security tools that slow developers down get disabled. Our approach:

| Principle | Implementation |
|-----------|---------------|
| **Fast feedback** | Scans run in parallel, total pipeline < 5 min |
| **Fix guidance** | SARIF results link directly to remediation docs |
| **No noise** | Only critical blocks the build. High = warning, not a blocker |
| **Shift left** | Local scanning script lets devs check before pushing |
| **No extra tools to learn** | Everything runs in GitHub Actions, results in PR |

### Workflow

```
Developer writes code
    ↓
Runs local scan (optional, scripts/security-scan.py)
    ↓
Pushes to branch
    ↓
Opens PR → Pipeline runs automatically
    ↓
Quality gate passes? → Merge allowed
Quality gate fails? → PR blocked, findings shown in logs
    ↓
Merge to main → Deploy to staging → Manual promote to prod
```

---

## 7. Cost & Complexity Trade-offs

### What We Chose vs What We Didn't

| Decision | Cost | Complexity | Security Value |
|----------|------|-----------|---------------|
| ✅ Open-source tools (Semgrep, Checkov, Grype) | $0 | Low | High — covers SAST, SCA, secrets, IaC |
| ✅ GitHub Actions free tier | $0 (2000 min/month) | Low | Automated on every push |
| ✅ Alpine containers | $0 | Low | 90% fewer CVEs than Debian base |
| ✅ Read-only filesystems | $0 | Low | Blocks most persistence techniques |
| ❌ Didn't add: SonarQube server | Saves $150+/month hosting | Avoided server maintenance | Semgrep covers same ground |
| ❌ Didn't add: Kubernetes | Saves massive complexity | Docker Compose is sufficient at current scale | K8s adds security features but also attack surface |
| ❌ Didn't add: Commercial SAST (Checkmarx, Fortify) | Saves $10k+/year | Avoided vendor lock-in | OSS tools have adequate detection rates |

### Total Cost of This Architecture

| Item | Cost |
|------|------|
| GitHub (public repo) | Free |
| GitHub Actions (2000 min/month) | Free |
| Security tools (all OSS) | Free |
| Developer time to maintain | ~2 hours/month |
| **Total** | **$0 + 2 hours/month** |

---

## 8. Architecture Diagram (Text)

```
┌─────────────────────────────────────────────────────────────────┐
│                    DEVSECOPS ARCHITECTURE                         │
│                                                                   │
│  ┌───────────┐     ┌────────────────┐     ┌──────────────────┐  │
│  │           │     │                │     │                  │  │
│  │ Developer │────▶│  GitHub Repo   │────▶│  GitHub Actions  │  │
│  │           │     │  (main branch  │     │  CI Pipeline     │  │
│  │ • IDE     │     │   protected)   │     │                  │  │
│  │ • Hooks   │     │                │     │  ┌────────────┐  │  │
│  └───────────┘     └────────────────┘     │  │  Checkov   │  │  │
│                                           │  │  (secrets) │  │  │
│                                           │  ├────────────┤  │  │
│                                           │  │  Checkov   │  │  │
│                                           │  │  (IaC)     │  │  │
│                                           │  ├────────────┤  │  │
│                                           │  │  Grype     │  │  │
│                                           │  │  (SCA)     │  │  │
│                                           │  ├────────────┤  │  │
│                                           │  │  Semgrep   │  │  │
│                                           │  │  (SAST)    │  │  │
│                                           │  └─────┬──────┘  │  │
│                                           │        │         │  │
│                                           │  ┌─────▼──────┐  │  │
│                                           │  │  Quality   │  │  │
│                                           │  │  Gate      │  │  │
│                                           │  │            │  │  │
│                                           │  │ Crit→FAIL  │  │  │
│                                           │  │ High→WARN  │  │  │
│                                           │  │ Med →PASS  │  │  │
│                                           │  └─────┬──────┘  │  │
│                                           └────────┼─────────┘  │
│                                                    │ pass       │
│                                                    ▼            │
│                                           ┌──────────────────┐  │
│                                           │  Docker Build    │  │
│                                           │  • Multi-stage   │  │
│                                           │  • Alpine base   │  │
│                                           │  • Pinned digest │  │
│                                           │  • Non-root      │  │
│                                           └────────┬─────────┘  │
│                                                    │            │
│                                                    ▼            │
│                                           ┌──────────────────┐  │
│                                           │  Runtime         │  │
│                                           │  • Read-only FS  │  │
│                                           │  • cap_drop ALL  │  │
│                                           │  • no-new-privs  │  │
│                                           │  • Resource caps  │  │
│                                           │  • Health checks │  │
│                                           │  • Falco         │  │
│                                           └────────┬─────────┘  │
│                                                    │            │
│                                                    ▼            │
│                                           ┌──────────────────┐  │
│                                           │  • SIEM
                                            │      (Splunk)    │
│                                           └────────┬─────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 9. Suppression Process

Not every finding is a real issue. We need a way to suppress false positives without disabling security.

### How Suppressions Work

```
Developer gets finding → Is it a real issue?
    ↓                         ↓
   YES                       NO (false positive)
    ↓                         ↓
  Fix it              Create suppression with justification
                              ↓
                      PR reviewed by security champion
                              ↓
                      Suppression merged → finding ignored in future scans with a RA window
```

### Suppression by Tool

| Tool | How to Suppress | Where It Lives |
|------|----------------|----------------|
| **Checkov** | `#checkov:skip=CKV_SECRET_6:This is a test fixture` inline, or `.checkov.yaml` | In code or config file in repo root |
| **Grype** | `.grype.yaml` with `ignore rules by CVE | Repo root |
| **Semgrep** | .semgrepignore` file | In code or `.semgrepignore` |
| **Grype** | `.grype.yaml` with `ignore rules by CVE | Repo root |
| **Trivy** | `.trivyignore` file listing CVE IDs | Repo root |

### Governance Rules

1. **Every suppression must have a reason** — no blank suppressions allowed
2. **Suppressions expire** — force re-review quarterly
3. **Suppressions are PR-reviewed** — can't self-approve your own suppression
4. **Audit log** — Git history tracks who suppressed what and when

---



## 10. Reusable Pipeline Templates (Decorator Pattern)

### The Problem

Without templates, every repo needs its own copy of the security pipeline. When we update a tool version or add a scanner, we'd have to commit changes to 20+ repos manually.

### The Solution: Reusable Workflow (GitHub Actions)

Create a shared workflow that any repo can call with one line. When we update the template, ALL repos get the update automatically on their next run.

### Benefits

| Benefit | How |
|---------|-----|
| **No per-repo maintenance** | Update template once, all repos get it next run |
| **Consistent policy** | Same tools, same thresholds everywhere |
| **Easy onboarding** | New repo adds 5 lines of YAML |
| **Override when needed** | Repos pass custom inputs to adjust behaviour |


---

## 11. Security Dashboards & Metrics

### Key Metrics

| Metric | What It Tells You | Target |
|--------|------------------|--------|
| **Mean Time to Remediate (MTTR)** | How fast do we fix critical findings? | < 3 days for critical, < 14 days for high |
| **Open Critical Count** | How many unresolved critical vulns right now? | 0 (always) |
| **Fix Rate** | % of findings fixed vs suppressed | > 80% fixed, < 20% suppressed |
| **Pipeline Duration** | How long do security scans add to CI? | < 5 minutes |
| **False Positive Rate** | How often we suppress vs fix | < 10% suppressions |
| **Scan Coverage** | % of repos with security pipeline | 100% |
| **Dependency Freshness** | Average age of dependencies | < 6 months behind latest |
| **Recurrence Rate** | Same finding reappearing after "fix" | < 5% |

---

## 12. Jira Ticket Automation for Critical Findings

### How It Works

```
Quality gate detects critical finding
    ↓
Pipeline creates Jira ticket automatically
    ↓
Assigns to team that owns the repo (via CODEOWNERS)
    ↓
Priority = Blocker, Due date = today + 3 days
    ↓
Links to pipeline run with full details
    ↓
If not fixed in SLA → escalates to tech lead
    ↓
Next passing scan → auto-closes the ticket
```

### SLA Targets

| Severity | Response Time | Fix Time | Escalation |
|----------|--------------|----------|------------|
| Critical | Same day | 3 business days | Tech lead after 2 days |
| High | 2 days | 14 business days | Team lead after 7 days |
| Medium | Best effort | 30 days | No escalation |
| Low | Best effort | Next sprint | No escalation |

---



---

## 14. Cloud Security Controls (AWS)

If deploying to AWS, the key security layers to implement alongside the DevSecOps pipeline:

### Account & Organisation Level

- **AWS Control Tower** — sets up a secure multi-account landing zone with guardrails baked in from day one
- **AWS Organizations + SCPs (Service Control Policies)** — hard boundaries on what any account can do, even if someone has admin. Examples:
  - Deny disabling CloudTrail (no one can turn off logging)
  - Deny creation of IAM users with console access (force SSO)
  - Restrict regions (only deploy in eu-west-1, deny all others)
  - Deny public S3 buckets at the org level
- **Separate accounts per environment** — dev, staging, prod each get their own account. Blast radius is contained.

### Quick Summary Table

| Layer | AWS Service | What It Prevents |
|-------|-------------|-----------------|
| Account boundaries | Control Tower + SCPs | Lateral movement between environments |
| Identity | IAM Identity Center + MFA + Access Analyzer| Credential theft, privilege escalation |
| Network | VPC + WAF + Security Groups | Unauthorized access, injection attacks |
| Data | KMS + Secrets Manager + Maacie | Data breach, secret exposure |
| Detection | GuardDuty + CloudTrail + Security Hub | Undetected attacks, compliance drift |
| Containers | ECR scanning + task roles + Fargate | Vulnerable images, over-privileged containers |
| IaC | AWS Config Rules | Misconfigurations reaching production |
