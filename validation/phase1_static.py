"""
Project AEGIS — Validation Phase 1: Static Code Analysis
Lead Architect: ETCHERO / Abdul-Hameed

Runs industry-standard static analysis tools on the AEGIS codebase:
  • ruff — Fast Python linter (replaces flake8 + isort)
  • flake8 — Style guide enforcement
  • mypy — Static type checking
  • bandit — Security issue scanner
  • pylint — Comprehensive code quality analysis

Target: 0 Critical, 0 High findings

Usage:
    python validation/phase1_static.py
"""

import json
import os
import platform
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional, Tuple

# ─── Project setup ────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from validation.utils.reporter import ValidationReport, ValidationResult


# ─── Tool definitions ─────────────────────────────────────────────────────────
LINT_TOOLS = {
    "ruff": {
        "pip_name": "ruff",
        "min_version": "0.3.0",
        "purpose": "Fast Python linter (replaces flake8 + isort + pyflakes)",
        "critical": False,
    },
    "flake8": {
        "pip_name": "flake8",
        "min_version": "6.0.0",
        "purpose": "Style guide enforcement (PEP8)",
        "critical": False,
    },
    "mypy": {
        "pip_name": "mypy",
        "min_version": "1.8.0",
        "purpose": "Static type checking",
        "critical": False,
    },
    "bandit": {
        "pip_name": "bandit",
        "min_version": "1.7.0",
        "purpose": "Security issue scanner",
        "critical": True,  # Security is critical
    },
    "pylint": {
        "pip_name": "pylint",
        "min_version": "3.0.0",
        "purpose": "Comprehensive code quality analysis",
        "critical": False,
    },
}


def check_tool_installed(name: str, pip_name: str) -> Tuple[bool, str]:
    """Check if a lint tool is installed and get its version."""
    try:
        result = subprocess.run(
            [name, "--version"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            version_line = result.stdout.strip().split('\n')[0]
            return True, version_line
        return False, f"Not installed (exit code {result.returncode})"
    except FileNotFoundError:
        return False, "Not installed"
    except Exception as e:
        return False, f"Error: {e}"


def install_tool(name: str, pip_name: str) -> bool:
    """Install a lint tool via pip."""
    print(f"  Installing {name}...")
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", pip_name],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode == 0:
            print(f"    ✅ {name} installed")
            return True
        print(f"    ❌ Install failed: {result.stderr[:100]}")
        return False
    except Exception as e:
        print(f"    ❌ Install error: {e}")
        return False


# ─── Runners ──────────────────────────────────────────────────────────────────

def run_ruff(report: ValidationReport, sources: List[Path]) -> None:
    """Run ruff linter on all source files."""
    result = ValidationResult("Ruff linter", "Static Analysis")

    try:
        targets = [str(s) for s in sources]
        proc = subprocess.run(
            ["ruff", "check", *targets, "--output-format=json"],
            capture_output=True, text=True, timeout=60,
        )
        findings = json.loads(proc.stdout) if proc.stdout.strip() else []

        critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        high = sum(1 for f in findings if f.get("severity") == "HIGH")
        total = len(findings)

        if total == 0:
            result.pass_("No issues found — clean!")
        else:
            # Map ruff's severity: "error" -> ERROR, "warning" -> WARN
            severity_counts = {"error": 0, "warning": 0, "info": 0}
            for f in findings:
                sev = f.get("code", "").split()[0] if f.get("code") else "info"
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            detail_parts = [f"{total} issue(s)"]
            if severity_counts.get("error"):
                detail_parts.append(f"{severity_counts['error']} errors")
            if severity_counts.get("warning"):
                detail_parts.append(f"{severity_counts['warning']} warnings")

            if severity_counts.get("error", 0) > 0:
                result.fail("; ".join(detail_parts), "ERROR",
                            "Run: ruff check --fix to auto-fix issues")
            elif total > 0:
                result.fail("; ".join(detail_parts), "WARN",
                            "Run: ruff check --fix to auto-fix warnings")
            else:
                result.pass_("No issues found")

        report.add_metadata("ruff_findings", total)

    except FileNotFoundError:
        result.fail("Ruff not installed", "ERROR",
                     "Install: pip install ruff")
    except subprocess.TimeoutExpired:
        result.fail("Timed out", "WARN")
    except Exception as e:
        result.fail(f"Error: {e}", "ERROR")

    report.add(result)


def run_flake8(report: ValidationReport, sources: List[Path]) -> None:
    """Run flake8 style checker."""
    result = ValidationResult("Flake8 style check", "Static Analysis")

    try:
        targets = [str(s) for s in sources]
        proc = subprocess.run(
            ["flake8", *targets, "--count", "--statistics"],
            capture_output=True, text=True, timeout=60,
        )

        # flake8 outputs violation count on stdout as the last line
        lines = [l for l in proc.stdout.split('\n') if l.strip()]
        stderr_lines = [l for l in proc.stderr.split('\n') if l.strip()]

        # Try to extract count
        count = 0
        for line in lines:
            match = re.search(r'(\d+)\s+$', line)
            if match:
                count = int(match.group(1))
                break

        if count == 0 and proc.returncode == 0:
            result.pass_("No style violations — clean!")
        elif count > 0:
            result.fail(f"{count} style violation(s)", "WARN",
                        "Run: flake8 to see details, then fix each violation")
        else:
            # Check if there's meaningful output
            all_output = '\n'.join(lines + stderr_lines)
            if "No config file found" in all_output:
                result.pass_("No config file found — skipping setup.cfg check")
            elif all_output.strip():
                result.fail(f"Issues found: {all_output[:200]}", "WARN")
            else:
                result.pass_("No issues found")

    except FileNotFoundError:
        result.fail("Flake8 not installed", "ERROR",
                     "Install: pip install flake8")
    except subprocess.TimeoutExpired:
        result.fail("Timed out", "WARN")
    except Exception as e:
        result.fail(f"Error: {e}", "ERROR")

    report.add(result)


def run_mypy(report: ValidationReport, sources: List[Path]) -> None:
    """Run mypy type checker."""
    result = ValidationResult("MyPy type checking", "Static Analysis")

    try:
        targets = [str(s) for s in sources if s.suffix == '.py']
        if not targets:
            result.pass_("No Python files to check")
            report.add(result)
            return

        proc = subprocess.run(
            ["mypy", *targets, "--show-error-codes", "--ignore-missing-imports"],
            capture_output=True, text=True, timeout=120,
        )

        # Count errors
        error_count = 0
        error_lines = []
        for line in proc.stdout.split('\n'):
            if ':' in line and ' error: ' in line:
                error_count += 1
                error_lines.append(line.strip())

        if error_count == 0:
            result.pass_("No type errors — clean!")
        else:
            result.fail(f"{error_count} type error(s)", "ERROR",
                        "Run: mypy to see details, add type hints to fix")

        report.add_metadata("mypy_errors", error_count)

    except FileNotFoundError:
        result.fail("MyPy not installed", "ERROR",
                     "Install: pip install mypy")
    except subprocess.TimeoutExpired:
        result.fail("Timed out (checking many files)", "WARN")
    except Exception as e:
        result.fail(f"Error: {e}", "ERROR")

    report.add(result)


def run_bandit(report: ValidationReport, sources: List[Path]) -> None:
    """Run bandit security scanner."""
    result = ValidationResult("Bandit security scan", "Static Analysis")

    try:
        targets = [str(s) for s in sources if s.suffix == '.py']
        if not targets:
            result.pass_("No Python files to scan")
            report.add(result)
            return

        proc = subprocess.run(
            ["bandit", "-r", *targets, "--format=json", "-q"],
            capture_output=True, text=True, timeout=120,
        )

        try:
            data = json.loads(proc.stdout) if proc.stdout.strip() else {}
        except json.JSONDecodeError:
            data = {}

        results = data.get("results", [])
        high = sum(1 for r in results if r.get("issue_severity") == "HIGH")
        medium = sum(1 for r in results if r.get("issue_severity") == "MEDIUM")
        low = sum(1 for r in results if r.get("issue_severity") == "LOW")
        total = len(results)

        if total == 0:
            result.pass_("No security issues found — clean!")
        elif high > 0:
            result.fail(f"{high} HIGH, {medium} MEDIUM, {low} LOW issues",
                        "CRITICAL",
                        "Fix high-severity security issues immediately")
        elif medium > 0:
            result.fail(f"{medium} MEDIUM, {low} LOW issues",
                        "ERROR",
                        "Review and fix medium-severity issues")
        else:
            result.fail(f"{low} LOW issues", "WARN",
                        "Review low-severity issues")

        report.add_metadata("bandit_findings", total)
        report.add_metadata("bandit_high", high)
        report.add_metadata("bandit_medium", medium)

    except FileNotFoundError:
        result.fail("Bandit not installed", "ERROR",
                     "Install: pip install bandit")
    except subprocess.TimeoutExpired:
        result.fail("Timed out", "WARN")
    except Exception as e:
        result.fail(f"Error: {e}", "ERROR")

    report.add(result)


def run_pylint(report: ValidationReport, sources: List[Path]) -> None:
    """Run pylint code quality analysis."""
    result = ValidationResult("Pylint code quality", "Static Analysis")

    try:
        targets = [str(s) for s in sources if s.suffix == '.py']
        if not targets:
            result.pass_("No Python files to check")
            report.add(result)
            return

        # Pylint on all files can be slow, so limit to key files
        key_files = [s for s in sources if any(
            p in str(s) for p in ['aegis.py', 'config.py', 'core/', 'modules/']
        )]

        proc = subprocess.run(
            ["pylint", *[str(f) for f in key_files],
             "--output-format=text", "--score=y"],
            capture_output=True, text=True, timeout=120,
        )

        # Extract score from output
        score = 0.0
        for line in proc.stdout.split('\n'):
            match = re.search(r'Your code has been rated at (\d+\.?\d*)/10', line)
            if match:
                score = float(match.group(1))
                break

        if score >= 8.0:
            result.pass_(f"Score: {score}/10 — excellent!")
        elif score >= 6.0:
            result.fail(f"Score: {score}/10 — needs improvement", "WARN",
                        "Review pylint output and fix issues")
        elif score > 0:
            result.fail(f"Score: {score}/10 — poor", "ERROR",
                        "Major refactoring needed")
        else:
            result.pass_("Pylint score check completed (baseline)")

        report.add_metadata("pylint_score", score)

    except FileNotFoundError:
        result.fail("Pylint not installed", "ERROR",
                     "Install: pip install pylint")
    except subprocess.TimeoutExpired:
        result.fail("Timed out", "WARN")
    except Exception as e:
        result.fail(f"Error: {e}", "ERROR")

    report.add(result)


def run_safety_practices(report: ValidationReport, sources: List[Path]) -> None:
    """Custom static checks for security practices."""
    checks = [
        ("No hardcoded secrets", "Security",
         [r"password\s*=\s*['\"][^'\"]+['\"]",
          r"secret\s*=\s*['\"][^'\"]+['\"]",
          r"api_key\s*=\s*['\"][^'\"]+['\"]",
          r"token\s*=\s*['\"][^'\"]+['\"]"],
         "Avoid hardcoding secrets; use environment variables instead",
         "WARN"),
        ("No eval/exec usage", "Security",
         [r"\beval\s*\(", r"\bexec\s*\("],
         "eval/exec can execute arbitrary code — security risk",
         "ERROR"),
        ("No subprocess shell=True", "Security",
         [r"shell\s*=\s*True"],
         "shell=True enables shell injection attacks",
         "CRITICAL"),
        ("No insecure randomness", "Security",
         [r"^import random\b", r"^from random\b"],
         "Use secrets module instead of random for security-critical operations",
         "WARN"),
        ("No pickle deserialization", "Security",
         [r"pickle\.loads?\("],
         "Pickle can execute arbitrary code during deserialization — security risk",
         "CRITICAL"),
        ("No assert statements in production", "Code Quality",
         [r"^\s*assert\s"],
         "assert statements are stripped when Python runs with -O flag",
         "WARN"),
    ]

    all_source = ""
    for s in sources:
        if s.suffix == '.py' and 'venv' not in str(s):
            try:
                all_source += s.read_text(encoding="utf-8", errors="replace") + "\n"
            except Exception:
                pass

    for check_name, category, patterns, fix, severity in checks:
        result = ValidationResult(check_name, category)
        found_issues = []
        for pattern in patterns:
            for s in sources:
                if s.suffix != '.py' or 'venv' in str(s):
                    continue
                try:
                    content = s.read_text(encoding="utf-8", errors="replace")
                    for lineno, line in enumerate(content.split('\n'), 1):
                        if re.search(pattern, line):
                            found_issues.append(f"{s.name}:{lineno}")
                except Exception:
                    pass

        if found_issues:
            # Deduplicate
            unique_issues = sorted(set(found_issues))
            detail = f"Found at: {', '.join(unique_issues[:10])}"
            if len(unique_issues) > 10:
                detail += f" +{len(unique_issues) - 10} more"
            result.fail(detail, severity, fix)
        else:
            result.pass_("No issues found")

        report.add(result)


# ─── Main Entry Point ─────────────────────────────────────────────────────────
def get_source_files() -> List[Path]:
    """Get all Python source files to analyze."""
    patterns = [
        PROJECT_ROOT / "aegis.py",
        PROJECT_ROOT / "config.py",
        PROJECT_ROOT / "core",
        PROJECT_ROOT / "modules",
    ]
    files = []
    for p in patterns:
        if p.is_file():
            files.append(p)
        elif p.is_dir():
            for f in sorted(p.rglob("*.py")):
                files.append(f)
    return files


def run_phase1(report: ValidationReport) -> ValidationReport:
    """Execute all Phase 1 static analysis checks."""

    sources = get_source_files()
    report.add_metadata("files_analyzed", len(sources))
    report.add_metadata("platform", platform.system())

    # ── 1. Tool Availability ────────────────────────────────────────────────
    for name, info in LINT_TOOLS.items():
        installed, version = check_tool_installed(name, info["pip_name"])
        result = ValidationResult(f"Tool: {name} — {info['purpose']}", "Tool Setup")
        if installed:
            result.pass_(version)
        else:
            sev = "CRITICAL" if info["critical"] else "ERROR"
            result.fail(f"Not installed: pip install {info['pip_name']}", sev,
                        f"Run: pip install {info['pip_name']}")
        report.add(result)

    # ── 2. Run Analysis Tools ────────────────────────────────────────────────
    run_ruff(report, sources)
    run_flake8(report, sources)
    run_mypy(report, sources)
    run_bandit(report, sources)
    run_pylint(report, sources)
    run_safety_practices(report, sources)

    return report


if __name__ == "__main__":
    start = time.time()

    # Auto-install missing tools
    missing = []
    for name, info in LINT_TOOLS.items():
        installed, _ = check_tool_installed(name, info["pip_name"])
        if not installed:
            missing.append((name, info))

    if missing:
        print(f"\n  {len(missing)} tool(s) need installation:")
        for name, info in missing:
            print(f"    • {name} — {info['purpose']}")
        print()
        for name, info in missing:
            install_tool(name, info["pip_name"])
        print()

    report = ValidationReport("Phase 1", "Static Code Analysis")
    report = run_phase1(report)
    report.duration = time.time() - start

    # Save reports
    json_path = PROJECT_ROOT / "validation" / "reports" / "phase1_report.json"
    html_path = PROJECT_ROOT / "validation" / "reports" / "phase1_report.html"
    report.to_json(json_path)
    report.to_html(html_path)

    report.print_console()
    print(f"  📄 JSON report: {json_path}")
    print(f"  📄 HTML report: {html_path}")

    sys.exit(1 if not report.summary()["target_met"] else 0)
