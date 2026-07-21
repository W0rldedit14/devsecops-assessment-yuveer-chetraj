# Secure CI/CD Pipeline

## Overview

A GitHub Actions workflow that integrates 4 security scanners into the CI/CD pipeline with quality gates that enforce security standards. Runs on every push/PR to `main` and `candidate-assessment`.

## Security Controls

| # | Scanner | Category | What It Catches |
|---|---------|----------|-----------------|
| 1 | **Checkov** (secrets) | Secrets Detection | Hardcoded API keys, passwords, private keys, AWS credentials, connection strings |
| 2 | **Checkov** (IaC) | Infrastructure as Code | Misconfigurations in Terraform, CloudFormation, Kubernetes, Dockerfiles, GitHub Actions |
| 3 | **Grype** | Dependencies (SCA) | Known CVEs in packages from `requirements.txt`, `package.json`, `pom.xml`, etc. |
| 4 | **Semgrep** | SAST | SQL injection, command injection, insecure crypto, deserialization, path traversal, SSRF |

## Quality Gate Logic

All scanners output SARIF format. A Python quality gate script parses every `results/*.sarif` file and makes a single pass/fail decision:

| Severity | SARIF Level | Pipeline Action |
|----------|-------------|-----------------|
| **Critical** | `error` | ❌ **FAIL** — build is blocked, merge is prevented |
| **High** | `warning` | ⚠️ **WARN** — build passes, findings flagged for review |
| **Medium** | `note` | ✅ **PASS** — informational, logged only |
| **Low** | `none` | ✅ **PASS** — informational, logged only |

### Why this approach works

- **Fail on criticals** — these are exploitable issues (known CVEs with public exploits, hardcoded secrets, SQL injection). They must be fixed before merge.
- **Warn on highs** — these are real risks but may need context (e.g., a dependency vuln in a dev-only package). Developers are alerted but not blocked.
- **Pass on medium/low** — reduces noise. Teams can review these in batch during security sprints.

## Pipeline Flow

```
Push/PR to main or candidate-assessment
                    ↓
              Checkout Code
                    ↓
         Install checkov, grype, semgrep
                    ↓
    ┌───────────────┼───────────────┬──────────────────┐
    ↓               ↓               ↓                  ↓
 Checkov         Checkov         Grype            Semgrep
 (Secrets)       (IaC)           (SCA)            (SAST)
    ↓               ↓               ↓                  ↓
 .sarif          .sarif          .sarif            .sarif
    └───────────────┼───────────────┴──────────────────┘
                    ↓
         Quality Gate (Python script)
         Parse all results/*.sarif
                    ↓
         ┌──────────┼──────────┐
         ↓          ↓          ↓
      ❌ FAIL    ⚠️ WARN    ✅ PASS
    (criticals)  (highs)   (med/low)
                    ↓
         Upload artifacts (30-day retention)
```

## Triggers

| Event | Branches |
|-------|----------|
| Push | `main`, `candidate-assessment` |
| Pull Request | into `main`, `candidate-assessment` |
| Manual | `workflow_dispatch` (run anytime from Actions tab) |

## Example: Quality Gate in Action

### Build FAILS — critical findings detected

```
============================================================
  SECURITY QUALITY GATE RESULTS
============================================================
  Critical: 3
  High:     6
  Medium:   5
  Low:      0
============================================================

  Findings detail:
  🔴 CRITICAL [Checkov] CKV_SECRET_2: AWS Access Key
  🔴 CRITICAL [Grype] CVE-2020-14343: PyYAML incomplete fix for CVE-2020-1747
  🔴 CRITICAL [Grype] CVE-2023-30861: flask session cookie disclosure
  🟠 HIGH [Semgrep] subprocess-shell-true: Found subprocess with shell=True
  🟠 HIGH [Semgrep] md5-used-as-password: MD5 used as password hash
  🟠 HIGH [Checkov] CKV_DOCKER_2: Dockerfile healthcheck missing
  ...

  ❌ FAIL: 3 critical finding(s) detected!
  Pipeline will be failed.
```

## File Structure

```
.github/
└── workflows/
    ├── secure-pipeline.yml   # Workflow definition
    └── README.md             # This documentation
```

## Adding New Scanners

The quality gate is scanner-agnostic — it reads any SARIF file in `results/`. To add a new tool:

1. Add a step that runs the scanner with SARIF output
2. Write the SARIF file to `results/<tool-name>.sarif`
3. Done — the quality gate automatically includes it

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| SARIF as common format | Universal format supported by all tools, enables unified quality gate |
| Separate secrets + IaC steps for Checkov | Different frameworks have different rule sets; separating them gives clearer attribution in findings |
| `continue-on-error: true` on scan steps | Scanners return non-zero when findings exist — we don't want the scan failure to stop other scans from running |
| Single quality gate script | One place to define pass/fail logic, easy to adjust thresholds |
| Artifact upload (30 days) | Audit trail without requiring GitHub Advanced Security |
