# Secure CI/CD Pipeline

## Overview

A GitHub Actions workflow that integrates 3 security scanners into the CI/CD pipeline with quality gates that enforce security standards.

## Security Controls

| Scanner | Category | What It Catches |
|---------|----------|-----------------|
| **Checkov** | Secrets | Hardcoded API keys, passwords, private keys, AWS credentials |
| **Trivy** | Dependencies (SCA) | Known CVEs in packages listed in `requirements.txt`, `package.json`, `pom.xml` |
| **Semgrep** | SAST | SQL injection, command injection, insecure crypto, deserialization flaws |

## Quality Gate Logic

The pipeline uses SARIF output from all tools and applies a single quality gate decision:

```
┌─────────────────────────────────────────────────────┐
│               QUALITY GATE DECISION                  │
├─────────────┬───────────────────────────────────────┤
│ Severity    │ Action                                │
├─────────────┼───────────────────────────────────────┤
│ CRITICAL    │ ❌ FAIL the build (exit code 1)       │
│ HIGH        │ ⚠️  WARN (pass but flag for review)   │
│ MEDIUM/LOW  │ ✅ PASS (informational only)          │
└─────────────┴───────────────────────────────────────┘
```

### Severity Mapping (SARIF → Quality Gate)

| SARIF Level | Severity | Pipeline Impact |
|-------------|----------|-----------------|
| `error` | Critical | Blocks merge/deploy |
| `warning` | High | Passes with warning annotation |
| `note` | Medium | Reported only |
| `none` | Low | Reported only |

## How It Works

```
Push/PR → Checkout → Install Tools
                          ↓
         ┌────────────────┼────────────────┐
         ↓                ↓                ↓
    Checkov           Trivy           Semgrep
    (Secrets)         (SCA)           (SAST)
         ↓                ↓                ↓
    *.sarif           *.sarif          *.sarif
         └────────────────┼────────────────┘
                          ↓
                 Quality Gate Script
                 (Parse all SARIF files)
                          ↓
              ┌───────────┼───────────┐
              ↓           ↓           ↓
           ❌ FAIL     ⚠️ WARN      ✅ PASS
          (criticals)  (highs)     (med/low)
                          ↓
              Upload SARIF → GitHub Security Tab
              Upload Artifacts (30-day retention)
```

## Triggers

| Event | Branches |
|-------|----------|
| Push | `main`, `develop` |
| Pull Request | into `main` |
| Manual | `workflow_dispatch` |

## SARIF Integration

All scan results are uploaded to GitHub's Security tab via `github/codeql-action/upload-sarif`. This provides:
- Findings visible in the **Security → Code scanning alerts** section
- Inline annotations on PRs showing exactly which lines have issues
- Tracking of findings over time (fixed, open, dismissed)

## Example: Quality Gate in Action

### Scenario: Critical finding detected (FAIL)

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
  🔴 CRITICAL [Trivy] CVE-2020-14343: PyYAML: incomplete fix for CVE-2020-1747
  🔴 CRITICAL [Trivy] CVE-2023-30861: flask: Possible disclosure of permanent session cookie
  🟠 HIGH [Semgrep] python.lang.security.audit.subprocess-shell-true: Found subprocess with shell=True
  🟠 HIGH [Semgrep] python.lang.security.audit.md5-used-as-password: MD5 used as password hash
  ...

  ❌ FAIL: 3 critical finding(s) detected!
  Pipeline will be failed.
```

### Scenario: Only high findings (WARN — passes)

```
============================================================
  SECURITY QUALITY GATE RESULTS
============================================================
  Critical: 0
  High:     2
  Medium:   4
  Low:      0
============================================================

  ⚠️  WARN: 2 high finding(s) detected.
  Pipeline passes but findings should be reviewed.
```

### Scenario: Clean code (PASS)

```
============================================================
  SECURITY QUALITY GATE RESULTS
============================================================
  Critical: 0
  High:     0
  Medium:   1
  Low:      0
============================================================

  ✅ PASS: No critical or high findings.
```

## File Structure

```
.github/
└── workflows/
    ├── secure-pipeline.yml   # The workflow definition
    └── README.md             # This documentation
```

## Customization

- **Add more scanners:** Add a new step producing SARIF → quality gate automatically picks it up from `results/*.sarif`
- **Change gate thresholds:** Edit the Python quality gate script — e.g., fail on high findings too
- **Scope scans:** Add `--exclude` or `--skip-check` flags to individual scanner steps
- **Per-PR vs full scan:** Use `paths` filters on the trigger to scan only changed areas
