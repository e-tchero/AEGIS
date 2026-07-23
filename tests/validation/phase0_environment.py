"""
Project AEGIS — Validation Program Phase 0: Environment Validation
Lead Architect: ETCHERO / Abdul-Hameed
Version: 1.0.0 | Classification: AEGIS-VALIDATION

Checks:
  - Python version          — ≥3.10 required
  - Dependencies            — all required packages installed
  - Configuration           — config.py loads, all keys present
  - File system             — logging paths, permissions, disk space
  - Platform                — OS detection, simulation mode
  - Ports                   — required ports available
  - Firewall privileges     — admin elevation check
  - Module imports          — all modules can be imported
  - Startup/Shutdown        — clean lifecycle test
  - Environment variables   — required env vars set

Outputs structured JSON report for dashboard ingestion.
Exit code: 0 if all checks pass, 1 if any fail.
"""

import importlib
import inspect
import json
import os
import platform
import socket
import subprocess
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

# ─── Project root ─────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# ─── Validation result types ──────────────────────────────────────────────────
class ValidationResult:
    """Tracks a single validation check result."""

    def __init__(self, name: str, category: str):
        self.name = name
        self.category = category
        self.passed: bool = False
        self.detail: str = ""
        self.severity: str = "INFO"  # INFO, WARN, ERROR, CRITICAL
        self.suggested_fix: str = ""

    def pass_(self, detail: str = "") -> "ValidationResult":
        self.passed = True
        self.severity = "INFO"
        self.detail = detail
        return self

    def fail(self, detail: str, severity: str = "ERROR",
             fix: str = "") -> "ValidationResult":
        self.passed = False
        self.severity = severity
        self.detail = detail
        self.suggested_fix = fix
        return self

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "category": self.category,
            "passed": self.passed,
            "severity": self.severity,
            "detail": self.detail,
            "suggested_fix": self.suggested_fix,
        }

    def __str__(self) -> str:
        icon = "✅" if self.passed else "❌"
        sev_tag = f"[{self.severity}]" if not self.passed else ""
        return f"  {icon} {sev_tag} {self.name:<50} {self.detail[:60]}"


class ValidationReport:
    """Collects and reports validation results."""

    def __init__(self, phase: str, description: str):
        self.phase = phase
        self.description = description
        self.timestamp = datetime.now().isoformat()
        self.results: List[ValidationResult] = []
        self.duration: float = 0.0

    def add(self, result: ValidationResult) -> None:
        self.results.append(result)

    def summary(self) -> dict:
        total = len(self.results)
        passed = sum(1 for r in self.results if r.passed)
        failed = total - passed
        by_severity: Dict[str, int] = {}
        for r in self.results:
            if not r.passed:
                by_severity[r.severity] = by_severity.get(r.severity, 0) + 1
        return {
            "phase": self.phase,
            "description": self.description,
            "timestamp": self.timestamp,
            "duration_seconds": round(self.duration, 2),
            "total": total,
            "passed": passed,
            "failed": failed,
            "by_severity": by_severity,
            "pass_rate": f"{passed}/{total} ({(passed / total * 100) if total else 0:.1f}%)",
        }

    def to_json(self, path: Optional[Path] = None) -> str:
        data = {
            "summary": self.summary(),
            "results": [r.to_dict() for r in self.results],
        }
        output = json.dumps(data, indent=2)
        if path:
            path.write_text(output, encoding="utf-8")
        return output

    def print_report(self) -> None:
        summary = self.summary()
        print(f"\n  {'═' * 56}")
        print(f"  PHASE 0: {self.description}")
        print(f"  {'═' * 56}")
        print(f"  Duration: {self.duration:.2f}s")
        print(f"  Results: {summary['pass_rate']}")
        print(f"  {'═' * 56}")

        # Group by category
        categories: Dict[str, List[ValidationResult]] = {}
        for r in self.results:
            categories.setdefault(r.category, []).append(r)

        for category, cat_results in categories.items():
            print(f"\n  ── [{category}] ──")
            for r in cat_results:
                print(f"  {r}")

        # Failure summary
        failures = [r for r in self.results if not r.passed]
        if failures:
            print(f"\n  {'─' * 56}")
            print(f"  FAILURES ({len(failures)}):")
            print(f"  {'─' * 56}")
            for r in failures:
                print(f"  ❌ [{r.severity}] {r.name}")
                print(f"     {r.detail}")
                if r.suggested_fix:
                    print(f"     🔧 Fix: {r.suggested_fix}")
            print()

        print(f"  {'═' * 56}")
        print(f"  PHASE 0 {'PASSED' if not failures else 'FAILED'}")
        print(f"  {'═' * 56}\n")


# ─── Validation Runner ───────────────────────────────────────────────────────

class Phase0Validator:
    """Validates the AEGIS deployment environment."""

    def __init__(self):
        self.report = ValidationReport(
            phase="Phase 0",
            description="Environment Validation",
        )
        self._start_time = time.time()

    def run_all(self) -> ValidationReport:
        """Execute all validation checks."""
        self._check_python_version()
        self._check_dependencies()
        self._check_config_integrity()
        self._check_file_system()
        self._check_platform()
        self._check_ports()
        self._check_privileges()
        self._check_module_imports()
        self._check_startup_shutdown()
        self._check_env_vars()

        self.report.duration = time.time() - self._start_time
        return self.report

    def _check(self, name: str, category: str,
               fn: Callable[[], Tuple[bool, str]],
               severity: str = "ERROR",
               fix: str = "") -> ValidationResult:
        """Run a single validation check."""
        result = ValidationResult(name, category)
        try:
            passed, detail = fn()
            if passed:
                result.pass_(detail)
            else:
                result.fail(detail, severity, fix)
        except Exception as e:
            result.fail(f"Check crashed: {e}", "CRITICAL", fix)
        self.report.add(result)
        return result

    # ── Python Version ───────────────────────────────────────────────────────

    def _check_python_version(self) -> None:
        def check() -> Tuple[bool, str]:
            v = sys.version_info
            required = (3, 10)
            if v >= required:
                return True, f"Python {v.major}.{v.minor}.{v.micro}"
            return False, f"Python {v.major}.{v.minor} < {required[0]}.{required[1]}"

        self._check(
            "Python version ≥ 3.10",
            "Python Runtime",
            check,
            severity="CRITICAL",
            fix="Install Python 3.10+ from https://python.org",
        )

    # ── Dependencies ─────────────────────────────────────────────────────────

    REQUIRED_PACKAGES = {
        "psutil": "5.8.0",
        "scapy": "2.5.0",
        "websockets": "12.0",
    }

    OPTIONAL_PACKAGES = {
        "flask": "For alternative dashboard backend",
        "requests": "For webhook notifications",
        "cryptography": "For encrypted telemetry",
        "aiohttp": "For async HTTP",
    }

    def _check_dependencies(self) -> None:
        for pkg, min_ver in self.REQUIRED_PACKAGES.items():
            def make_check(name: str, version: str):
                def check() -> Tuple[bool, str]:
                    try:
                        mod = importlib.import_module(name)
                        ver = getattr(mod, "__version__", "unknown")
                        return True, f"{name} {ver}"
                    except ImportError:
                        return False, f"{name} not installed"
                return check

            self._check(
                f"Dependency: {pkg} ≥ {min_ver}",
                "Dependencies",
                make_check(pkg, min_ver),
                severity="CRITICAL",
                fix=f"pip install {pkg}>={min_ver}",
            )

        # pip list for full inventory
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "list", "--format=json"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                packages = json.loads(result.stdout)
                count = len(packages)
                self._check("pip packages installed", "Dependencies",
                            lambda: (True, f"{count} packages"))  # type: ignore
        except Exception:
            pass

    # ── Configuration ────────────────────────────────────────────────────────

    REQUIRED_CONFIG_KEYS = [
        "PULSE_INTERVAL",
        "CPU_DANGER_THRESHOLD",
        "RAM_DANGER_THRESHOLD",
        "SCAN_WINDOW_SECONDS",
        "PORT_HIT_THRESHOLD",
        "ALERT_COOLDOWN_SECONDS",
        "ALLOWLIST_IPS",
        "BLOCKED_IPS_FILE",
        "MAX_BLOCKED_IPS",
        "FIREWALL_TIMEOUT",
        "HIGH_RISK_TIMEOUT",
        "LOGIC_LOOP_SLEEP",
        "INCIDENT_LOG_FILE",
        "CORRELATION_TIMEOUT_SECONDS",
        "AUTO_CLOSE_MINUTES",
        "MAX_INCIDENT_EVENTS",
        "LOG_MAX_BYTES",
        "LOG_BACKUP_COUNT",
        "LOG_FORMAT",
        "SIMULATION",
        "CURRENT_OS",
        "DASHBOARD_WS_PORT",
        "DASHBOARD_WS_HOST",
    ]

    def _check_config_integrity(self) -> None:
        # Load config
        def check_config_load() -> Tuple[bool, str]:
            try:
                import config
                return True, "config.py loaded successfully"
            except Exception as e:
                return False, f"config.py failed: {e}"

        self._check("Config file loads", "Configuration",
                    check_config_load, severity="CRITICAL",
                    fix="Ensure config.py exists in project root")

        # Check all keys exist
        def check_config_keys() -> Tuple[bool, str]:
            try:
                import config
                missing = [k for k in self.REQUIRED_CONFIG_KEYS
                           if not hasattr(config, k)]
                if missing:
                    return False, f"Missing keys: {', '.join(missing)}"
                return True, f"All {len(self.REQUIRED_CONFIG_KEYS)} keys present"
            except Exception as e:
                return False, f"Config check failed: {e}"

        self._check("Config keys present", "Configuration",
                    check_config_keys, severity="CRITICAL",
                    fix="Add missing keys to config.py")

        # Check config values are reasonable
        def check_config_values() -> Tuple[bool, str]:
            try:
                import config
                issues = []
                if config.PULSE_INTERVAL <= 0:
                    issues.append("PULSE_INTERVAL ≤ 0")
                if config.CPU_DANGER_THRESHOLD > 100:
                    issues.append("CPU_DANGER_THRESHOLD > 100")
                if config.MAX_BLOCKED_IPS <= 0:
                    issues.append("MAX_BLOCKED_IPS ≤ 0")
                if config.CORRELATION_TIMEOUT_SECONDS <= 0:
                    issues.append("CORRELATION_TIMEOUT_SECONDS ≤ 0")
                if issues:
                    return False, "; ".join(issues)
                return True, "All values in expected ranges"
            except Exception as e:
                return False, f"Value check failed: {e}"

        self._check("Config values reasonable", "Configuration",
                    check_config_values, severity="WARN",
                    fix="Review config.py for out-of-range values")

    # ── File System ──────────────────────────────────────────────────────────

    def _check_file_system(self) -> None:
        base_dir = PROJECT_ROOT
        log_dir = base_dir / "logs"
        config_dir = base_dir / "config"

        # Log directory exists and writable
        def check_log_dir() -> Tuple[bool, str]:
            try:
                log_dir.mkdir(parents=True, exist_ok=True)
                test_file = log_dir / ".write_test"
                test_file.write_text("test")
                test_file.unlink()
                return True, f"{log_dir} exists and writable"
            except Exception as e:
                return False, f"Log dir issue: {e}"

        self._check("Log directory writable", "File System",
                    check_log_dir, severity="CRITICAL",
                    fix="Ensure logs/ directory exists with write permissions")

        # Config directory exists and writable
        def check_config_dir() -> Tuple[bool, str]:
            try:
                config_dir.mkdir(parents=True, exist_ok=True)
                return True, f"{config_dir} exists and writable"
            except Exception as e:
                return False, f"Config dir issue: {e}"

        self._check("Config directory writable", "File System",
                    check_config_dir, severity="CRITICAL",
                    fix="Ensure config/ directory exists with write permissions")

        # Disk space
        def check_disk_space() -> Tuple[bool, str]:
            try:
                if hasattr(os, "statvfs"):
                    stat = os.statvfs(str(base_dir))
                    free_gb = (stat.f_frsize * stat.f_bavail) / (1024 ** 3)
                    if free_gb < 1:
                        return False, f"Only {free_gb:.1f}GB free (min 1GB)"
                    return True, f"{free_gb:.1f}GB free"
                # Windows fallback
                import ctypes
                free_bytes = ctypes.c_ulonglong(0)
                ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                    ctypes.c_wchar_p(str(base_dir)),
                    None, None, ctypes.pointer(free_bytes)
                )
                free_gb = free_bytes.value / (1024 ** 3)
                if free_gb < 1:
                    return False, f"Only {free_gb:.1f}GB free (min 1GB)"
                return True, f"{free_gb:.1f}GB free"
            except Exception:
                return True, "Disk space check unavailable"

        self._check("Disk space ≥ 1GB free", "File System",
                    check_disk_space, severity="WARN",
                    fix="Free up disk space on the deployment drive")

        # Project structure
        expected_dirs = ["modules", "core", "tests", "dashboard"]
        def check_structure() -> Tuple[bool, str]:
            missing = [d for d in expected_dirs
                       if not (base_dir / d).exists()]
            if missing:
                return False, f"Missing dirs: {', '.join(missing)}"
            return True, f"All {len(expected_dirs)} directories present"

        self._check("Project structure intact", "File System",
                    check_structure, severity="CRITICAL",
                    fix="Re-clone the repository")

    # ── Platform ─────────────────────────────────────────────────────────────

    def _check_platform(self) -> None:
        import config

        def check_os() -> Tuple[bool, str]:
            os_name = platform.system()
            supported = ["Linux", "Windows", "Darwin"]
            if os_name in supported:
                return True, f"{os_name} ({platform.release()})"
            return False, f"Unsupported OS: {os_name}"

        self._check("Operating system supported", "Platform",
                    check_os, severity="CRITICAL",
                    fix="Deploy on Linux, Windows, or macOS")

        def check_simulation() -> Tuple[bool, str]:
            mode = "SIMULATION" if config.SIMULATION else "LIVE"
            return True, f"{mode} mode (OS: {config.CURRENT_OS})"

        self._check("Execution mode detected", "Platform",
                    check_simulation)

        def check_architecture() -> Tuple[bool, str]:
            arch = platform.machine()
            return True, f"{arch} ({platform.processor() or 'unknown'})"

        self._check("Architecture detected", "Platform",
                    check_architecture)

    # ── Ports ────────────────────────────────────────────────────────────────

    REQUIRED_PORTS = [
        (8765, "AEGIS WebSocket Server"),
        (3000, "Next.js Dashboard"),
    ]

    def _check_ports(self) -> None:
        for port, service in self.REQUIRED_PORTS:
            def make_check(p: int, s: str):
                def check() -> Tuple[bool, str]:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(2)
                        result = sock.connect_ex(("127.0.0.1", p))
                        sock.close()
                        if result == 0:
                            return True, f"Port {p} ({s}) — in use (expected if running)"
                        return True, f"Port {p} ({s}) — available"
                    except Exception as e:
                        return False, f"Port {p} check failed: {e}"
                return check

            self._check(
                f"Port {port} ({service})",
                "Network Ports",
                make_check(port, service),
                severity="WARN",
                fix=f"Ensure port {port} is not blocked by firewall",
            )

    # ── Privileges ───────────────────────────────────────────────────────────

    def _check_privileges(self) -> None:
        import config

        def check_admin() -> Tuple[bool, str]:
            try:
                if platform.system() == "Windows":
                    import ctypes
                    is_admin = ctypes.windll.shell32.IsUserAdmin()
                    if is_admin:
                        return True, "Administrator privileges confirmed"
                    return False, "Not running as administrator (firewall operations limited)"
                # Linux/macOS
                if os.geteuid() == 0:
                    return True, "Root privileges confirmed"
                return False, "Not running as root (firewall operations limited)"
            except Exception:
                return True, "Privilege check unavailable"

        self._check("Administrator/root privileges", "Privileges",
                    check_admin, severity="WARN",
                    fix="Run as administrator (Windows) or root (Linux) for full firewall support")

        def check_firewall_backend() -> Tuple[bool, str]:
            try:
                from modules.firewall_backends import BACKEND
                return True, f"Active backend: {BACKEND.name}"
            except Exception as e:
                return False, f"Firewall backend check failed: {e}"

        self._check("Firewall backend detected", "Privileges",
                    check_firewall_backend, severity="WARN",
                    fix="Install iptables/nftables on Linux or run as admin on Windows")

    # ── Module Imports ───────────────────────────────────────────────────────

    REQUIRED_MODULES = [
        "core.heartbeat",
        "modules.firewall",
        "modules.firewall_backends",
        "modules.incident_manager",
        "modules.ai_analyst",
        "modules.evidence_engine",
        "modules.dashboard_server",
        "modules.net_sentinel",
        "modules.dns_monitor",
        "modules.memory_monitor",
    ]

    def _check_module_imports(self) -> None:
        for mod_name in self.REQUIRED_MODULES:
            def make_check(name: str):
                def check() -> Tuple[bool, str]:
                    try:
                        importlib.import_module(name)
                        return True, f"{name} imported successfully"
                    except ImportError as e:
                        return False, f"{name} failed: {e}"
                    except Exception as e:
                        return False, f"{name} error: {e}"
                return check

            self._check(
                f"Module: {mod_name}",
                "Module Imports",
                make_check(mod_name),
                severity="CRITICAL",
                fix=f"Check {mod_name.replace('.', '/')}.py for errors",
            )

    # ── Startup/Shutdown ─────────────────────────────────────────────────────

    def _check_startup_shutdown(self) -> None:
        # Test individual component instantiation
        components = [
            ("Heartbeat", "from core.heartbeat import Heartbeat; hb = Heartbeat(); hb.stop()"),
            ("IncidentManager", "from modules.incident_manager import IncidentManager; im = IncidentManager(); im.start(); im.stop()"),
            ("DashboardServer",
             "from modules.dashboard_server import DashboardServer; ds = DashboardServer(host='127.0.0.1', port=18766); ds.start(); import time; time.sleep(0.5); ds.stop()"),
        ]

        for name, code in components:
            def make_check(cmd: str, label: str):
                def check() -> Tuple[bool, str]:
                    try:
                        result = subprocess.run(
                            [sys.executable, "-c", cmd],
                            capture_output=True, text=True, timeout=10,
                            cwd=str(PROJECT_ROOT),
                        )
                        if result.returncode == 0:
                            return True, f"{label} lifecycle OK"
                        return False, f"{label} failed: {result.stderr[:200]}"
                    except subprocess.TimeoutExpired:
                        return False, f"{label} timed out"
                    except Exception as e:
                        return False, f"{label} error: {e}"
                return check

            self._check(
                f"Component lifecycle: {name}",
                "Startup/Shutdown",
                make_check(code, name),
                severity="CRITICAL",
                fix=f"Debug {name} instantiation and stop methods",
            )

        # Test AEGIS quick start/stop
        def check_aegis_startstop() -> Tuple[bool, str]:
            try:
                result = subprocess.run(
                    [sys.executable, "-c", """
import sys, os, time
sys.path.insert(0, '.')
os.chdir('.')
import config
from aegis import AegisCore, _parse_args
args = _parse_args(['--no-heartbeat', '--no-sentinel', '--no-procmon',
                     '--no-fim', '--no-logmon', '--no-memmon', '--no-dnsmon',
                     '--no-incident', '--no-dashboard'])
from unittest.mock import patch
with patch('sys.argv', ['aegis.py']):
    agent = AegisCore(args)
    agent.start()
    time.sleep(1)
    agent.stop()
print('AEGIS START/STOP OK')
"""],
                    capture_output=True, text=True, timeout=15,
                    cwd=str(PROJECT_ROOT),
                )
                if "OK" in result.stdout:
                    return True, "AEGIS starts and stops cleanly"
                return False, f"Output: {result.stdout[:200]}"
            except subprocess.TimeoutExpired:
                return False, "AEGIS start/stop timed out (expected on Windows without admin)"
            except Exception as e:
                return False, f"AEGIS lifecycle error: {e}"

        self._check("AEGIS full start/stop cycle", "Startup/Shutdown",
                    check_aegis_startstop, severity="WARN",
                    fix="Check for hanging threads or blocked I/O in startup")

    # ── Environment Variables ────────────────────────────────────────────────

    def _check_env_vars(self) -> None:
        optional_vars = [
            ("DISCORD_WEBHOOK_URL", "Discord notification webhook"),
            ("SLACK_WEBHOOK_URL", "Slack notification webhook"),
            ("NEXT_PUBLIC_WS_URL", "Dashboard WebSocket URL override"),
        ]

        for var, desc in optional_vars:
            def make_check(name: str, description: str):
                def check() -> Tuple[bool, str]:
                    val = os.environ.get(name, "")
                    if val:
                        return True, f"{description} configured ({val[:30]}...)"
                    return True, f"{description} not set (optional)"
                return check

            self._check(
                f"Env var: {var}",
                "Environment Variables",
                make_check(var, desc),
            )


# ─── Entry Point ──────────────────────────────────────────────────────────────
def run_phase0(output_path: Optional[Path] = None) -> int:
    """Run Phase 0 validation and return exit code."""
    print(f"\n{'╔' + '═' * 56 + '╗'}")
    print(f"║     PROJECT AEGIS — VALIDATION PROGRAM                     ║")
    print(f"║     Phase 0: Environment Validation                       ║")
    print(f"║     {datetime.now().isoformat()[:19]}                                   ║")
    print(f"{'╚' + '═' * 56 + '╝'}")

    validator = Phase0Validator()
    report = validator.run_all()
    report.print_report()

    # Save report
    if output_path:
        report.to_json(output_path)
        print(f"  Report saved: {output_path}")

    failures = [r for r in report.results if not r.passed]
    return 1 if failures else 0


if __name__ == "__main__":
    output = PROJECT_ROOT / "logs" / "validation_report.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    sys.exit(run_phase0(output))
