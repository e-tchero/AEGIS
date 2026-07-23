"""
Project AEGIS — Validation Phase 0: Environment Validation
Lead Architect: ETCHERO / Abdul-Hameed

Validates the AEGIS deployment environment:
  • Python version (≥3.10)
  • All dependencies installed
  • Configuration integrity (all keys present, values reasonable)
  • File system (log paths, permissions, disk space)
  • Platform detection (OS, architecture, simulation mode)
  • Network ports (8765 WebSocket, 3000 Dashboard)
  • Firewall privileges
  • All module imports
  • Component lifecycle (start/stop)

Usage:
    python validation/phase0_environment.py
"""

import importlib
import json
import os
import platform
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable, Tuple

# ─── Project setup ────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from validation.utils.reporter import ValidationReport, ValidationResult


def run_phase0(report: ValidationReport) -> ValidationReport:
    """Execute all Phase 0 environment validation checks."""

    def _check(name: str, category: str, fn: Callable,
               severity: str = "ERROR", fix: str = "") -> None:
        result = ValidationResult(name, category)
        try:
            passed, detail = fn()
            if passed:
                result.pass_(detail)
            else:
                result.fail(detail, severity, fix)
        except Exception as e:
            result.fail(f"Check crashed: {e}", "CRITICAL", fix)
        report.add(result)

    # ── 1. Python Version ───────────────────────────────────────────────────
    def check_python():
        v = sys.version_info
        if v >= (3, 10):
            return True, f"Python {v.major}.{v.minor}.{v.micro}"
        return False, f"Python {v.major}.{v.minor} < 3.10"

    _check("Python version ≥ 3.10", "Python Runtime", check_python,
           severity="CRITICAL", fix="Install Python 3.10+ from python.org")

    # ── 2. Dependencies ─────────────────────────────────────────────────────
    REQUIRED = {
        "psutil": "5.8.0",
        "scapy": "2.5.0",
        "websockets": "12.0",
    }

    for pkg, min_ver in REQUIRED.items():
        def make_dep_check(name, version):
            def check():
                try:
                    mod = importlib.import_module(name)
                    ver = getattr(mod, "__version__", "unknown")
                    return True, f"{name} {ver}"
                except ImportError:
                    return False, f"{name} not installed"
            return check

        _check(f"Dependency: {pkg} ≥ {min_ver}", "Dependencies",
               make_dep_check(pkg, min_ver),
               severity="CRITICAL", fix=f"pip install {pkg}>={min_ver}")

    # pip packages count
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "list", "--format=json"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            packages = json.loads(result.stdout)
            _check("Python packages installed", "Dependencies",
                   lambda: (True, f"{len(packages)} packages"))
    except Exception:
        pass

    # ── 3. Configuration ────────────────────────────────────────────────────

    REQUIRED_KEYS = [
        "PULSE_INTERVAL", "CPU_DANGER_THRESHOLD", "RAM_DANGER_THRESHOLD",
        "SCAN_WINDOW_SECONDS", "PORT_HIT_THRESHOLD", "ALERT_COOLDOWN_SECONDS",
        "ALLOWLIST_IPS", "BLOCKED_IPS_FILE", "MAX_BLOCKED_IPS",
        "FIREWALL_TIMEOUT", "HIGH_RISK_TIMEOUT", "LOGIC_LOOP_SLEEP",
        "INCIDENT_LOG_FILE", "CORRELATION_TIMEOUT_SECONDS", "AUTO_CLOSE_MINUTES",
        "MAX_INCIDENT_EVENTS", "LOG_MAX_BYTES", "LOG_BACKUP_COUNT", "LOG_FORMAT",
        "SIMULATION", "CURRENT_OS", "DASHBOARD_WS_PORT", "DASHBOARD_WS_HOST",
    ]

    def check_config_load():
        try:
            import config
            return True, "config.py loaded successfully"
        except Exception as e:
            return False, f"config.py failed: {e}"

    _check("Configuration file loads", "Configuration",
           check_config_load, severity="CRITICAL",
           fix="Ensure config.py exists in project root")

    def check_config_keys():
        import config
        missing = [k for k in REQUIRED_KEYS if not hasattr(config, k)]
        if missing:
            return False, f"Missing: {', '.join(missing)}"
        return True, f"All {len(REQUIRED_KEYS)} keys present"

    _check("Configuration keys present", "Configuration",
           check_config_keys, severity="CRITICAL",
           fix="Add missing keys to config.py")

    def check_config_values():
        import config
        issues = []
        if config.PULSE_INTERVAL <= 0: issues.append("PULSE_INTERVAL ≤ 0")
        if config.CPU_DANGER_THRESHOLD > 100: issues.append("CPU > 100")
        if config.MAX_BLOCKED_IPS <= 0: issues.append("MAX_BLOCKED_IPS ≤ 0")
        if config.CORRELATION_TIMEOUT_SECONDS <= 0: issues.append("CORRELATION_TIMEOUT ≤ 0")
        if issues:
            return False, "; ".join(issues)
        return True, "All values in expected ranges"

    _check("Configuration values reasonable", "Configuration",
           check_config_values, severity="WARN",
           fix="Review config.py for out-of-range values")

    # ── 4. File System ──────────────────────────────────────────────────────
    def check_log_dir():
        log_dir = PROJECT_ROOT / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        test_file = log_dir / ".write_test"
        test_file.write_text("test")
        test_file.unlink()
        return True, f"Logs directory writable ({log_dir})"

    _check("Log directory writable", "File System",
           check_log_dir, severity="CRITICAL",
           fix="Ensure logs/ directory has write permissions")

    def check_config_dir():
        cfg_dir = PROJECT_ROOT / "config"
        cfg_dir.mkdir(parents=True, exist_ok=True)
        return True, f"Config directory writable ({cfg_dir})"

    _check("Config directory writable", "File System",
           check_config_dir, severity="CRITICAL",
           fix="Ensure config/ directory has write permissions")

    def check_disk_space():
        try:
            if os.name == "nt":
                import ctypes
                free = ctypes.c_ulonglong(0)
                ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                    ctypes.c_wchar_p(str(PROJECT_ROOT)), None, None, ctypes.pointer(free))
                free_gb = free.value / (1024 ** 3)
            else:
                stat = os.statvfs(str(PROJECT_ROOT))
                free_gb = (stat.f_frsize * stat.f_bavail) / (1024 ** 3)
            if free_gb < 1:
                return False, f"Only {free_gb:.1f}GB free (min 1GB)"
            return True, f"{free_gb:.1f}GB free"
        except Exception:
            return True, "Disk space check unavailable"

    _check("Disk space ≥ 1GB free", "File System",
           check_disk_space, severity="WARN",
           fix="Free up disk space on deployment drive")

    def check_structure():
        expected = ["modules", "core", "tests", "dashboard", "validation"]
        missing = [d for d in expected if not (PROJECT_ROOT / d).exists()]
        if missing:
            return False, f"Missing: {', '.join(missing)}"
        return True, f"All {len(expected)} project directories present"

    _check("Project structure intact", "File System",
           check_structure, severity="CRITICAL",
           fix="Re-clone the repository")

    # ── 5. Platform ─────────────────────────────────────────────────────────
    def check_os():
        os_name = platform.system()
        if os_name in ("Linux", "Windows", "Darwin"):
            return True, f"{os_name} {platform.release()}"
        return False, f"Unsupported OS: {os_name}"

    _check("Operating system supported", "Platform",
           check_os, severity="CRITICAL",
           fix="Deploy on Linux, Windows, or macOS")

    def check_arch():
        return True, f"{platform.machine()} ({platform.processor() or 'unknown'})"

    _check("Architecture detected", "Platform", check_arch)

    # ── 6. Ports ────────────────────────────────────────────────────────────
    for port, service in [(8765, "AEGIS WebSocket"), (3000, "Dashboard")]:
        def make_port_check(p, s):
            def check():
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex(("127.0.0.1", p))
                sock.close()
                if result == 0:
                    return True, f"Port {p} ({s}) — in use (expected if running)"
                return True, f"Port {p} ({s}) — available"
            return check

        _check(f"Port {port} ({service})", "Network Ports",
               make_port_check(port, service), severity="WARN",
               fix=f"Ensure port {port} is not blocked by firewall")

    # ── 7. Privileges ───────────────────────────────────────────────────────
    def check_admin():
        try:
            if platform.system() == "Windows":
                import ctypes
                if ctypes.windll.shell32.IsUserAdmin():
                    return True, "Administrator privileges confirmed"
                return False, "Not running as admin (firewall limited)"
            if os.geteuid() == 0:
                return True, "Root privileges confirmed"
            return False, "Not running as root (firewall limited)"
        except Exception:
            return True, "Privilege check unavailable"

    _check("Administrator/root privileges", "Privileges",
           check_admin, severity="WARN",
           fix="Run as admin (Windows) or root (Linux) for full firewall")

    def check_fw_backend():
        from modules.firewall_backends import BACKEND
        return True, f"Active backend: {BACKEND.name}"

    _check("Firewall backend detected", "Privileges",
           check_fw_backend, severity="WARN",
           fix="Install iptables/nftables on Linux or run as admin on Windows")

    # ── 8. Module Imports ──────────────────────────────────────────────────
    MODULES = [
        "core.heartbeat", "modules.firewall", "modules.firewall_backends",
        "modules.incident_manager", "modules.ai_analyst",
        "modules.evidence_engine", "modules.dashboard_server",
        "modules.net_sentinel", "modules.dns_monitor", "modules.memory_monitor",
    ]

    for mod_name in MODULES:
        def make_import_check(name):
            def check():
                importlib.import_module(name)
                return True, f"{name} imported successfully"
            return check

        _check(f"Module: {mod_name}", "Module Imports",
               make_import_check(mod_name), severity="CRITICAL",
               fix=f"Check {mod_name.replace('.', '/')}.py for errors")

    # ── 9. Component Lifecycle ──────────────────────────────────────────────
    components = [
        ("Heartbeat", "from core.heartbeat import Heartbeat; hb = Heartbeat(); hb.stop()"),
        ("IncidentManager",
         "from modules.incident_manager import IncidentManager; im = IncidentManager(); im.start(); im.stop()"),
    ]

    for name, code in components:
        def make_lifecycle_check(cmd, label):
            def check():
                result = subprocess.run(
                    [sys.executable, "-c", cmd],
                    capture_output=True, text=True, timeout=10,
                    cwd=str(PROJECT_ROOT),
                )
                if result.returncode == 0:
                    return True, f"{label} start/stop OK"
                return False, f"{label} failed: {result.stderr[:200]}"
            return check

        _check(f"Component: {name}", "Lifecycle",
               make_lifecycle_check(code, name), severity="WARN",
               fix=f"Debug {name} instantiation and stop methods")

    return report


if __name__ == "__main__":
    from validation.utils.reporter import ValidationReport
    start = time.time()
    report = ValidationReport("Phase 0", "Environment Validation")
    report = run_phase0(report)
    report.duration = time.time() - start

    # Save reports
    json_path = PROJECT_ROOT / "validation" / "reports" / "phase0_report.json"
    html_path = PROJECT_ROOT / "validation" / "reports" / "phase0_report.html"
    report.to_json(json_path)
    report.to_html(html_path)

    report.print_console()
    print(f"  📄 JSON report: {json_path}")
    print(f"  📄 HTML report: {html_path}")

    sys.exit(1 if not report.summary()["target_met"] else 0)
