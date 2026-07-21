#!/usr/bin/env python3
"""
Multi-Scanner Orchestrator
Runs multiple security tools (Checkov, Trivy, Semgrep) and aggregates SARIF results
into a unified JSON output with pass/fail decision.

Tools used:
- Checkov: Secrets detection
- Trivy: Dependency/vulnerability scanning (SCA)
- Semgrep: SAST (Static Application Security Testing)
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path


def find_tool(tool_name):
    """Find the full path to a tool, checking common install locations on Windows."""
    import shutil
    # Check if it's already on PATH
    found = shutil.which(tool_name)
    if found:
        return found
    # Check common Windows install locations
    if sys.platform == "win32":
        home = os.path.expanduser("~")
        candidates = [
            os.path.join(home, tool_name, f"{tool_name}.exe"),
            os.path.join(home, f"{tool_name}.exe"),
            os.path.join("C:\\ProgramData\\chocolatey\\bin", f"{tool_name}.exe"),
            os.path.join("C:\\ProgramData\\chocolatey\\lib", tool_name, "tools", f"{tool_name}.exe"),
        ]
        for candidate in candidates:
            if os.path.exists(candidate):
                return candidate
    return tool_name  # Fall back to just the name


def run_command(cmd, description):
    """Run a shell command and return success status and output."""
    # Join into a single string for shell=True (required on Windows for .cmd wrappers)
    cmd_str = " ".join(cmd)
    print(f"[*] Running: {description}")
    print(f"    Command: {cmd_str}")

    # Force UTF-8 for tools that emit emoji/unicode (e.g. semgrep)
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"

    try:
        result = subprocess.run(
            cmd_str,
            capture_output=True,
            timeout=300,
            shell=True,
            env=env
        )
        # Decode with utf-8, replacing any bytes that can't be decoded
        stdout = result.stdout.decode("utf-8", errors="replace")
        stderr = result.stderr.decode("utf-8", errors="replace")
        return {
            "success": result.returncode == 0,
            "returncode": result.returncode,
            "stdout": stdout,
            "stderr": stderr
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "returncode": -1, "stdout": "", "stderr": "Command timed out"}
    except FileNotFoundError:
        return {"success": False, "returncode": -1, "stdout": "", "stderr": f"Tool not found: {cmd[0]}"}


def parse_sarif(sarif_path):
    """Parse a SARIF file and extract findings."""
    findings = []
    if not os.path.exists(sarif_path):
        return findings

    try:
        with open(sarif_path, "r", encoding="utf-8") as f:
            sarif_data = json.load(f)
    except (json.JSONDecodeError, IOError, UnicodeDecodeError) as e:
        print(f"    [!] Error parsing SARIF file {sarif_path}: {e}")
        return findings

    for run in sarif_data.get("runs", []):
        tool_name = run.get("tool", {}).get("driver", {}).get("name", "unknown")
        rules = {r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}

        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")
            level = result.get("level", "warning")
            message = result.get("message", {}).get("text", "No message")

            # Map SARIF levels to severity
            severity = map_level_to_severity(level)

            # Try to get more context from the rule
            rule_info = rules.get(rule_id, {})
            rule_name = rule_info.get("shortDescription", {}).get("text", rule_id)

            locations = []
            for loc in result.get("locations", []):
                phys = loc.get("physicalLocation", {})
                artifact = phys.get("artifactLocation", {}).get("uri", "unknown")
                region = phys.get("region", {})
                start_line = region.get("startLine", 0)
                locations.append({"file": artifact, "line": start_line})

            findings.append({
                "tool": tool_name,
                "rule_id": rule_id,
                "rule_name": rule_name,
                "severity": severity,
                "level": level,
                "message": message,
                "locations": locations
            })

    return findings


def map_level_to_severity(level):
    """Map SARIF level to a normalized severity."""
    mapping = {
        "error": "critical",
        "warning": "high",
        "note": "medium",
        "none": "low"
    }
    return mapping.get(level, "medium")


def find_sarif_file(output_dir):
    """Find the SARIF file produced by Checkov in the output directory."""
    # Checkov may output as results_sarif.sarif or in a subdirectory
    for root, dirs, files in os.walk(output_dir):
        for f in files:
            if f.endswith(".sarif"):
                return os.path.join(root, f)
    return None


def run_checkov_secrets(target_path, output_dir):
    """Run Checkov for secrets scanning."""
    sarif_path = os.path.join(output_dir, "checkov_secrets.sarif")
    cmd = [
        "checkov",
        "--directory", f'"{str(target_path)}"',
        "--framework", "secrets",
        "--output", "sarif",
        "--output-file-path", f'"{output_dir}"',
        "--soft-fail"
    ]
    result = run_command(cmd, "Checkov Secrets Scan")

    # Checkov outputs to results_sarif.sarif in the output directory
    checkov_sarif = os.path.join(output_dir, "results_sarif.sarif")
    if os.path.exists(checkov_sarif):
        os.rename(checkov_sarif, sarif_path)
    else:
        # Search for any sarif file produced
        found = find_sarif_file(output_dir)
        if found and found != sarif_path:
            os.rename(found, sarif_path)

    return sarif_path, result


def run_trivy_sca(target_path, output_dir):
    """Run Trivy for dependency/vulnerability scanning (SCA)."""
    sarif_path = os.path.join(output_dir, "trivy_sca.sarif")
    trivy_bin = find_tool("trivy")
    cmd = [
        f'"{trivy_bin}"', "fs",
        "--scanners", "vuln",
        "--format", "sarif",
        "--output", f'"{sarif_path}"',
        f'"{str(target_path)}"'
    ]
    result = run_command(cmd, "Trivy Dependency (SCA) Scan")
    return sarif_path, result


def run_semgrep_sast(target_path, output_dir):
    """Run Semgrep for SAST scanning."""
    sarif_path = os.path.join(output_dir, "semgrep_sast.sarif")

    # use chcp 65001 to switch cmd.exe
    # to UTF-8 code page so semgrep can write emoji without crashing.
    # Then redirect SARIF stdout to file directly in the shell.
    cmd_str = (
        f'chcp 65001 >NUL & '
        f'semgrep scan --config auto --sarif '
        f'"{str(target_path)}" '
        f'> "{sarif_path}" '
        f'2>NUL'
    )
    print(f"[*] Running: Semgrep SAST Scan")
    print(f"    Command: semgrep scan --config auto --sarif \"{target_path}\"")

    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["NO_COLOR"] = "1"
    # Override any system-level SEMGREP_SEND_METRICS=off (blocks --config auto)
    env["SEMGREP_SEND_METRICS"] = "auto"

    try:
        proc = subprocess.run(
            cmd_str,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=300,
            shell=True,
            env=env
        )
        result = {
            "success": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout": "",
            "stderr": ""
        }
    except subprocess.TimeoutExpired:
        result = {"success": False, "returncode": -1, "stdout": "", "stderr": "Command timed out"}
    except Exception as e:
        result = {"success": False, "returncode": -1, "stdout": "", "stderr": str(e)}

    return sarif_path, result


def aggregate_results(all_findings):
    """Aggregate findings by category and determine pass/fail."""
    categories = {
        "secrets": [],
        "dependencies": [],
        "sast": []
    }

    for finding in all_findings:
        tool = finding["tool"].lower()
        if "secret" in tool or "secret" in finding.get("rule_id", "").lower():
            categories["secrets"].append(finding)
        elif "trivy" in tool:
            categories["dependencies"].append(finding)
        elif "checkov" in tool:
            categories["secrets"].append(finding)
        elif "semgrep" in tool:
            categories["sast"].append(finding)
        else:
            categories["sast"].append(finding)

    return categories


def determine_pass_fail(categories):
    """Determine pass/fail based on critical severity findings."""
    failed_categories = []

    for category, findings in categories.items():
        critical_findings = [f for f in findings if f["severity"] == "critical"]
        if critical_findings:
            failed_categories.append(category)

    overall_pass = len(failed_categories) == 0
    return overall_pass, failed_categories


def main():
    parser = argparse.ArgumentParser(
        description="Multi-Scanner Orchestrator - Runs security tools and aggregates results"
    )
    parser.add_argument(
        "--path", "-p",
        required=True,
        help="Path to the application/code to scan"
    )
    parser.add_argument(
        "--format", "-f",
        choices=["json", "text"],
        default="json",
        help="Output format (default: json)"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file path (default: stdout)"
    )

    args = parser.parse_args()
    target_path = Path(args.path).resolve()

    if not target_path.exists():
        print(f"[!] Error: Path '{target_path}' does not exist.", file=sys.stderr)
        sys.exit(1)

    print(f"\n{'='*60}")
    print(f"  Multi-Scanner Orchestrator")
    print(f"  Target: {target_path}")
    print(f"  Time: {datetime.now().isoformat()}")
    print(f"{'='*60}\n")

    # Create temp directory for SARIF outputs
    with tempfile.TemporaryDirectory() as output_dir:
        all_findings = []
        scan_results = {}

        # 1. Run Checkov Secrets Scan
        sarif_path, result = run_checkov_secrets(target_path, output_dir)
        scan_results["checkov_secrets"] = {
            "tool": "checkov",
            "category": "secrets",
            "success": result["success"],
            "returncode": result["returncode"]
        }
        secrets_findings = parse_sarif(sarif_path)
        for f in secrets_findings:
            f["_category"] = "secrets"
        all_findings.extend(secrets_findings)
        print(f"    Found {len(secrets_findings)} finding(s)\n")

        # 2. Run Trivy Dependency/SCA Scan
        sarif_path, result = run_trivy_sca(target_path, output_dir)
        scan_results["trivy_sca"] = {
            "tool": "trivy",
            "category": "dependencies",
            "success": result["success"],
            "returncode": result["returncode"]
        }
        sca_findings = parse_sarif(sarif_path)
        for f in sca_findings:
            f["_category"] = "dependencies"
        all_findings.extend(sca_findings)
        print(f"    Found {len(sca_findings)} finding(s)\n")

        # 3. Run Semgrep SAST Scan
        sarif_path, result = run_semgrep_sast(target_path, output_dir)
        scan_results["semgrep_sast"] = {
            "tool": "semgrep",
            "category": "sast",
            "success": result["success"],
            "returncode": result["returncode"]
        }
        sast_findings = parse_sarif(sarif_path)
        for f in sast_findings:
            f["_category"] = "sast"
        all_findings.extend(sast_findings)
        print(f"    Found {len(sast_findings)} finding(s)\n")

    # Aggregate results
    categories = {
        "secrets": [f for f in all_findings if f.get("_category") == "secrets"],
        "dependencies": [f for f in all_findings if f.get("_category") == "dependencies"],
        "sast": [f for f in all_findings if f.get("_category") == "sast"]
    }

    # Determine pass/fail
    overall_pass, failed_categories = determine_pass_fail(categories)

    # Build output
    output = {
        "scan_metadata": {
            "target": str(target_path),
            "timestamp": datetime.now().isoformat(),
            "tools": ["checkov", "trivy", "semgrep"]
        },
        "summary": {
            "overall_result": "PASS" if overall_pass else "FAIL",
            "failed_categories": failed_categories,
            "total_findings": len(all_findings),
            "findings_by_category": {
                "secrets": len(categories["secrets"]),
                "dependencies": len(categories["dependencies"]),
                "sast": len(categories["sast"])
            },
            "findings_by_severity": {
                "critical": len([f for f in all_findings if f["severity"] == "critical"]),
                "high": len([f for f in all_findings if f["severity"] == "high"]),
                "medium": len([f for f in all_findings if f["severity"] == "medium"]),
                "low": len([f for f in all_findings if f["severity"] == "low"])
            }
        },
        "scan_results": scan_results,
        "findings": {
            "secrets": [_clean_finding(f) for f in categories["secrets"]],
            "dependencies": [_clean_finding(f) for f in categories["dependencies"]],
            "sast": [_clean_finding(f) for f in categories["sast"]]
        }
    }

    # Output results
    if args.format == "json":
        json_output = json.dumps(output, indent=2)
        if args.output:
            with open(args.output, "w") as f:
                f.write(json_output)
            print(f"\n[*] Results written to: {args.output}")
        else:
            print(f"\n{'='*60}")
            print("  RESULTS")
            print(f"{'='*60}")
            print(json_output)
    else:
        _print_text_output(output)

    # Print summary
    print(f"\n{'='*60}")
    status = "✅ PASS" if overall_pass else "❌ FAIL"
    print(f"  Overall Result: {status}")
    if failed_categories:
        print(f"  Failed Categories: {', '.join(failed_categories)}")
    print(f"  Total Findings: {len(all_findings)}")
    print(f"{'='*60}\n")

    # Exit with appropriate code
    sys.exit(0 if overall_pass else 1)


def _clean_finding(finding):
    """Remove internal keys from finding for output."""
    clean = {k: v for k, v in finding.items() if not k.startswith("_")}
    return clean


def _print_text_output(output):
    """Print results in text format."""
    print(f"\n{'='*60}")
    print(f"  SECURITY SCAN RESULTS")
    print(f"{'='*60}")
    print(f"\n  Result: {output['summary']['overall_result']}")
    print(f"  Total Findings: {output['summary']['total_findings']}")
    print(f"\n  By Category:")
    for cat, count in output["summary"]["findings_by_category"].items():
        print(f"    - {cat}: {count}")
    print(f"\n  By Severity:")
    for sev, count in output["summary"]["findings_by_severity"].items():
        print(f"    - {sev}: {count}")

    if output["summary"]["failed_categories"]:
        print(f"\n  ❌ Failed Categories: {', '.join(output['summary']['failed_categories'])}")

    for category, findings in output["findings"].items():
        if findings:
            print(f"\n  --- {category.upper()} ---")
            for f in findings[:10]:  # Limit output
                print(f"    [{f['severity'].upper()}] {f['rule_id']}: {f['message'][:80]}")
                for loc in f.get("locations", []):
                    print(f"      -> {loc['file']}:{loc['line']}")


if __name__ == "__main__":
    main()
