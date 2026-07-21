# Multi-Scanner Orchestrator

A security automation script that runs multiple security tools and aggregates their SARIF results into a unified JSON output with a pass/fail decision.

## Tools Used

| Tool | Category | Purpose |
|------|----------|---------|
| **Checkov** (secrets framework) | Secrets Detection | Finds hardcoded credentials, API keys, private keys |
| **Checkov** (sca_package framework) | Dependency Scanning | Identifies vulnerable packages with known CVEs |
| **Semgrep** | SAST | Static analysis for code vulnerabilities (SQLi, command injection, etc.) |

## Prerequisites

Install the required security tools:

```bash
pip install checkov semgrep
```

## Usage

```bash
# Basic scan with JSON output (default)
python security-scan.py --path ./app --format json

# Scan with text output
python security-scan.py --path ./app --format text

# Save results to file
python security-scan.py --path ./app --format json --output results.json
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `--path`, `-p` | Yes | Path to the application/code to scan |
| `--format`, `-f` | No | Output format: `json` (default) or `text` |
| `--output`, `-o` | No | Output file path (defaults to stdout) |

## How It Works

1. **Runs Checkov Secrets Scan** — Detects hardcoded secrets, API keys, passwords, and private keys in source code and config files.
2. **Runs Checkov SCA Scan** — Checks dependency manifest files (requirements.txt, package.json, pom.xml) for packages with known vulnerabilities.
3. **Runs Semgrep SAST Scan** — Performs static application security testing to find code-level vulnerabilities like SQL injection, command injection, insecure crypto, etc.
4. **Parses SARIF Output** — Each tool produces a SARIF (Static Analysis Results Interchange Format) file that is parsed for findings.
5. **Aggregates Results** — All findings are unified into a single JSON structure, categorized by type and severity.
6. **Pass/Fail Decision** — The script returns `FAIL` (exit code 1) if any **critical** severity findings exist in any category. Otherwise returns `PASS` (exit code 0).

## Output Structure

```json
{
  "scan_metadata": {
    "target": "/path/to/app",
    "timestamp": "2024-01-01T12:00:00",
    "tools": ["checkov", "semgrep"]
  },
  "summary": {
    "overall_result": "PASS | FAIL",
    "failed_categories": ["secrets", "dependencies", "sast"],
    "total_findings": 0,
    "findings_by_category": { "secrets": 0, "dependencies": 0, "sast": 0 },
    "findings_by_severity": { "critical": 0, "high": 0, "medium": 0, "low": 0 }
  },
  "findings": {
    "secrets": [...],
    "dependencies": [...],
    "sast": [...]
  }
}
```

## Examples

### Example 1: Clean Code (PASS)

```bash
python security-scan.py --path ./examples/pass-example --format json
```

**Expected Result:** `PASS` — No critical findings across all 3 categories.

The `pass-example/` contains:
- No hardcoded secrets (uses environment variables)
- Clean dependencies (latest patched versions)
- Secure code patterns (parameterized queries, proper hashing)

### Example 2: Vulnerable Code (FAIL)

```bash
python security-scan.py --path ./examples/fail-example --format json
```

**Expected Result:** `FAIL` — Critical findings in all 3 categories.

The `fail-example/` contains:
- **Secrets:** Hardcoded AWS keys, API keys, database passwords, RSA private key
- **Dependencies:** Vulnerable versions of flask, requests, pyyaml, urllib3, cryptography
- **SAST:** SQL injection, command injection, weak crypto (MD5), insecure deserialization, path traversal

### Example 3: CI/CD Integration

```bash
# In a CI pipeline - script exits with code 1 on failure
python security-scan.py --path . --format json --output scan-results.json
if [ $? -ne 0 ]; then
  echo "Security scan failed! Check scan-results.json"
  exit 1
fi
```

## Pass/Fail Logic

The orchestrator determines the overall result as follows:

- **FAIL** if there are any findings with `critical` severity (mapped from SARIF `error` level)
- **PASS** if all findings are `high`, `medium`, or `low` severity (or no findings at all)

This means the script acts as a quality gate — only truly critical issues cause a pipeline failure.

## Severity Mapping

| SARIF Level | Mapped Severity |
|-------------|-----------------|
| error | critical |
| warning | high |
| note | medium |
| none | low |
