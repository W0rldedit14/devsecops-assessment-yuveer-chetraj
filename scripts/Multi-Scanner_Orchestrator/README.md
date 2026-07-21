# Multi-Scanner Orchestrator

A security automation script that runs multiple security tools and aggregates their SARIF results into a unified JSON output with a pass/fail decision.

## Tools Used

| Tool | Category | Purpose |
|------|----------|---------|
| **Checkov** (secrets framework) | Secrets Detection | Finds hardcoded credentials, API keys, private keys |
| **Trivy** (fs vuln scanner) | Dependency Scanning | Identifies vulnerable packages with known CVEs |
| **Semgrep** (auto config) | SAST | Static analysis for code vulnerabilities (SQLi, command injection, insecure crypto, etc.) |

## Prerequisites

Install the required security tools:

```bash
# Python tools
pip install checkov semgrep

# Trivy — download the Windows binary from:
# https://github.com/aquasecurity/trivy/releases
# Extract trivy.exe to a folder (e.g. C:\Users\<you>\trivy\trivy.exe)
# The script auto-detects it in common locations without needing it on PATH
```

### Windows Notes

- **Checkov** requires the `.cmd` wrapper — the script uses `shell=True` to invoke it correctly.
- **Trivy** does not need to be on `PATH`. The script searches `~\trivy\trivy.exe` and other common locations automatically.
- **Semgrep** requires `SEMGREP_SEND_METRICS` to not be set to `off` when using `--config auto`. If you have this globally set, the script overrides it to `auto` for the scan process.

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
2. **Runs Trivy Dependency Scan** — Checks dependency manifest files (`requirements.txt`, `package.json`, `pom.xml`) for packages with known CVEs using the OSV/NVD database.
3. **Runs Semgrep SAST Scan** — Performs static application security testing to find code-level vulnerabilities like SQL injection, command injection, insecure crypto, insecure deserialization, and more.
4. **Parses SARIF Output** — Each tool produces a SARIF (Static Analysis Results Interchange Format) file that is parsed for findings.
5. **Aggregates Results** — All findings are unified into a single JSON structure, categorized by type and severity.
6. **Pass/Fail Decision** — The script returns `FAIL` (exit code 1) if any **critical** severity findings exist in any category. Otherwise returns `PASS` (exit code 0).

## Output Structure

```json
{
  "scan_metadata": {
    "target": "/path/to/app",
    "timestamp": "2024-01-01T12:00:00",
    "tools": ["checkov", "trivy", "semgrep"]
  },
  "summary": {
    "overall_result": "PASS | FAIL",
    "failed_categories": ["secrets", "dependencies", "sast"],
    "total_findings": 0,
    "findings_by_category": { "secrets": 0, "dependencies": 0, "sast": 0 },
    "findings_by_severity": { "critical": 0, "high": 0, "medium": 0, "low": 0 }
  },
  "scan_results": {
    "checkov_secrets": { "tool": "checkov", "category": "secrets", "success": true, "returncode": 0 },
    "trivy_sca":       { "tool": "trivy",   "category": "dependencies", "success": true, "returncode": 0 },
    "semgrep_sast":    { "tool": "semgrep", "category": "sast", "success": true, "returncode": 0 }
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
python security-scan.py --path ./examples/pass-example --format text
```

**Expected Result:** `✅ PASS` — No critical findings. 4 high/medium dependency findings (non-critical) do not fail the build.

The `pass-example/` contains:
- No hardcoded secrets (uses environment variables)
- Reasonably up-to-date dependencies (latest patched versions of flask, requests, pyyaml)
- Secure code patterns (parameterized queries, proper password hashing)

**Sample output:**
```
Overall Result: ✅ PASS
Total Findings: 4

By Category:
  - secrets: 0
  - dependencies: 4
  - sast: 0

By Severity:
  - critical: 0
  - high: 2
  - medium: 2
  - low: 0
```

---

### Example 2: Vulnerable Code (FAIL)

```bash
python security-scan.py --path ./examples/fail-example --format text
```

**Expected Result:** `❌ FAIL` — Critical findings in secrets, dependencies, and SAST categories.

The `fail-example/` contains intentional vulnerabilities across all 3 categories:

| Category | Tool | Findings |
|----------|------|---------|
| **Secrets** | Checkov | Hardcoded AWS keys, API key, high-entropy string in `config.json` |
| **Dependencies** | Trivy | 32 CVEs — critical/high in `cryptography`, `flask`, `urllib3`, `pyyaml`, `requests`, `jinja2` |
| **SAST** | Semgrep | SQL injection, `subprocess shell=True`, MD5 password hashing, pickle deserialization, disabled cert validation, hardcoded private key |

**Sample output:**
```
Overall Result: ❌ FAIL
Total Findings: 41

By Category:
  - secrets: 3
  - dependencies: 32
  - sast: 6

By Severity:
  - critical: 15
  - high: 21
  - medium: 5
  - low: 0

Failed Categories: secrets, dependencies
```

---

### Example 3: CI/CD Integration

```bash
# Script exits with code 1 on failure — use as a quality gate
python security-scan.py --path . --format json --output scan-results.json
if [ $? -ne 0 ]; then
  echo "Security scan failed! Check scan-results.json"
  exit 1
fi
```

## Pass/Fail Logic

The orchestrator determines the overall result as follows:

- **FAIL** if there are any findings with `critical` severity (mapped from SARIF `error` level) in any category
- **PASS** if all findings are `high`, `medium`, or `low` severity — or there are no findings at all

Only truly critical issues block the pipeline. High/medium findings are reported but don't cause failure.

## Severity Mapping

SARIF levels from each tool are normalized to a common severity scale:

| SARIF Level | Mapped Severity | Causes FAIL? |
|-------------|-----------------|--------------|
| `error` | `critical` | ✅ Yes |
| `warning` | `high` | ❌ No |
| `note` | `medium` | ❌ No |
| `none` | `low` | ❌ No |

## Troubleshooting

**Checkov not found:** Ensure it's installed with `pip install checkov`. On Windows the `.cmd` wrapper must be available in your Python Scripts directory.

**Trivy not found:** The script searches `~\trivy\trivy.exe` automatically. If installed elsewhere, add the directory to your `PATH`.

**Semgrep returns 0 findings / fails with metrics error:** If `SEMGREP_SEND_METRICS=off` is set in your environment, the script overrides it to `auto` for the subprocess. If you still see issues, run `semgrep scan --config auto --sarif <path>` manually to check.

**Paths with spaces:** All tool paths and target paths are automatically quoted in the generated commands. No manual quoting needed.
