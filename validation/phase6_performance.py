"""
Project AEGIS -- Validation Phase 6: Performance Testing
Lead Architect: ETCHERO / Abdul-Hameed

Measures system resource utilization under three conditions:
  1. Idle (system baseline)
  2. Post-import (all modules loaded)
  3. Post-start (core components instantiated)

Targets:
  - CPU usage (process):        < 5% at idle
  - RAM usage (process RSS):    < 200 MB
  - Thread count:               < 50
  - Open sockets / handles:     < 100

Usage:
    python validation/phase6_performance.py
"""

import importlib
import os
import platform
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from validation.utils.reporter import ValidationReport, ValidationResult


def get_process_usage() -> Dict[str, float]:
    """Get current process resource usage."""
    import psutil
    proc = psutil.Process()
    cpu = proc.cpu_percent(interval=0.5)
    mem = proc.memory_info()
    threads = proc.num_threads()

    # Connections may raise AccessDenied on Windows without admin
    try:
        connections = len(proc.net_connections())
    except (psutil.AccessDenied, psutil.NoSuchProcess, Exception):
        connections = -1

    # Open files may raise AccessDenied on some platforms
    try:
        open_files = len(proc.open_files())
    except (psutil.AccessDenied, psutil.NoSuchProcess, Exception):
        open_files = -1

    return {
        "cpu_percent": cpu,
        "rss_mb": mem.rss / (1024 * 1024),
        "vms_mb": mem.vms / (1024 * 1024),
        "threads": threads,
        "connections": connections,
        "open_files": open_files,
        "num_fds": proc.num_fds() if hasattr(proc, "num_fds") else 0,
    }


def get_system_usage() -> Dict[str, float]:
    """Get system-wide resource usage."""
    import psutil
    return {
        "cpu_percent": psutil.cpu_percent(interval=0.5),
        "ram_percent": psutil.virtual_memory().percent,
        "ram_available_gb": psutil.virtual_memory().available / (1024**3),
    }


class ResourceSnapshot:
    """A snapshot of resource usage at a point in time."""

    def __init__(self, label: str):
        self.label = label
        self.timestamp = time.time()
        self.process = get_process_usage()
        self.system = get_system_usage()

    def __str__(self) -> str:
        return (
            f"  [{self.label}]"
            f" CPU: {self.process['cpu_percent']:.1f}%"
            f" | RAM: {self.process['rss_mb']:.1f}MB"
            f" | Threads: {self.process['threads']}"
            f" | Connections: {self.process['connections']}"
            f" | Files: {self.process['open_files']}"
        )

    def diff_from(self, other: "ResourceSnapshot") -> Dict[str, float]:
        """Return the difference from another snapshot."""
        return {
            "cpu_percent": self.process["cpu_percent"] - other.process["cpu_percent"],
            "rss_mb": self.process["rss_mb"] - other.process["rss_mb"],
            "vms_mb": self.process["vms_mb"] - other.process["vms_mb"],
            "threads": self.process["threads"] - other.process["threads"],
            "connections": self.process["connections"] - other.process["connections"],
            "open_files": self.process["open_files"] - other.process["open_files"],
        }


def run_phase6(report: ValidationReport) -> ValidationReport:
    """Execute all Phase 6 performance validation checks."""

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

    # ═══════════════════════════════════════════════════════════════════════════
    # 1. BASELINE MEASUREMENT — Idle System
    # ═══════════════════════════════════════════════════════════════════════════
    print("\n  [PHASE 6] Measuring baseline system resources...")
    baseline_proc = get_process_usage()
    baseline_sys = get_system_usage()

    baseline = ResourceSnapshot("Baseline")
    report.add_metadata("baseline_cpu", f"{baseline.process['cpu_percent']:.1f}%")
    report.add_metadata("baseline_ram_mb", f"{baseline.process['rss_mb']:.1f}")
    report.add_metadata("baseline_threads", str(baseline.process['threads']))

    # ═══════════════════════════════════════════════════════════════════════════
    # 2. MODULE IMPORT MEASUREMENT
    # ═══════════════════════════════════════════════════════════════════════════
    print("  [PHASE 6] Measuring module import overhead...")

    MODULES = [
        "config",
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
        "modules.process_monitor",
        "modules.login_monitor",
        "modules.file_monitor",
    ]

    for mod_name in MODULES:
        try:
            importlib.import_module(mod_name)
        except Exception as e:
            print(f"    Warning: {mod_name} import failed: {e}")

    post_import = ResourceSnapshot("Post-Import")
    import_delta = post_import.diff_from(baseline)

    report.add_metadata("post_import_cpu", f"{post_import.process['cpu_percent']:.1f}%")
    report.add_metadata("post_import_ram_mb", f"{post_import.process['rss_mb']:.1f}")
    report.add_metadata("import_delta_ram_mb", f"{import_delta['rss_mb']:.1f}")

    # ═══════════════════════════════════════════════════════════════════════════
    # 3. COMPONENT INSTANTIATION
    # ═══════════════════════════════════════════════════════════════════════════
    print("  [PHASE 6] Measuring component instantiation...")

    # Start lightweight components (skip scapy-dependent ones)
    components = {}

    try:
        from core.heartbeat import Heartbeat
        hb = Heartbeat()
        components["heartbeat"] = hb
        print("    Heartbeat instantiated")
    except Exception as e:
        print(f"    Heartbeat failed: {e}")

    try:
        from modules.incident_manager import IncidentManager
        im = IncidentManager()
        im.start()
        components["incident_manager"] = im
        print("    IncidentManager started")
    except Exception as e:
        print(f"    IncidentManager failed: {e}")

    try:
        from modules.dashboard_server import DashboardServer
        ds = DashboardServer()
        ds.start()
        components["dashboard"] = ds
        print("    DashboardServer started")
    except Exception as e:
        print(f"    DashboardServer failed: {e}")

    try:
        from modules.dns_monitor import DnsMonitor
        dm = DnsMonitor()
        dm.start()
        components["dns_monitor"] = dm
        print("    DnsMonitor started")
    except Exception as e:
        print(f"    DnsMonitor failed: {e}")

    try:
        from modules.file_monitor import FileMonitor
        fm = FileMonitor()
        fm.start()
        components["file_monitor"] = fm
        print("    FileMonitor started")
    except Exception as e:
        print(f"    FileMonitor failed: {e}")

    # Give components a moment to settle
    time.sleep(1)

    post_start = ResourceSnapshot("Post-Start")
    start_delta = post_start.diff_from(baseline)

    report.add_metadata("post_start_cpu", f"{post_start.process['cpu_percent']:.1f}%")
    report.add_metadata("post_start_ram_mb", f"{post_start.process['rss_mb']:.1f}")
    report.add_metadata("start_delta_ram_mb", f"{start_delta['rss_mb']:.1f}")

    # ═══════════════════════════════════════════════════════════════════════════
    # 4. SUSTAINED MEASUREMENT (5 samples over time)
    # ═══════════════════════════════════════════════════════════════════════════
    print("  [PHASE 6] Measuring sustained resource usage (5 samples)...")
    samples = []
    for i in range(5):
        time.sleep(0.5)
        snap = ResourceSnapshot(f"Sample {i+1}")
        samples.append(snap)
        print(f"    Sample {i+1}: CPU={snap.process['cpu_percent']:.1f}%"
              f" RAM={snap.process['rss_mb']:.1f}MB"
              f" Threads={snap.process['threads']}")

    # Calculate averages
    avg_cpu = sum(s.process["cpu_percent"] for s in samples) / len(samples)
    avg_ram = sum(s.process["rss_mb"] for s in samples) / len(samples)
    avg_threads = sum(s.process["threads"] for s in samples) / len(samples)
    avg_connections = sum(s.process["connections"] for s in samples) / len(samples)
    avg_files = sum(s.process["open_files"] for s in samples) / len(samples)
    max_ram = max(s.process["rss_mb"] for s in samples)
    max_cpu = max(s.process["cpu_percent"] for s in samples)

    report.add_metadata("avg_cpu", f"{avg_cpu:.1f}%")
    report.add_metadata("avg_ram_mb", f"{avg_ram:.1f}")
    report.add_metadata("max_ram_mb", f"{max_ram:.1f}")
    report.add_metadata("avg_threads", f"{avg_threads:.1f}")
    report.add_metadata("avg_connections", f"{avg_connections:.1f}")
    report.add_metadata("avg_open_files", f"{avg_files:.1f}")
    report.add_metadata("samples_taken", str(len(samples)))

    # ═══════════════════════════════════════════════════════════════════════════
    # 5. STOP COMPONENTS
    # ═══════════════════════════════════════════════════════════════════════════
    print("  [PHASE 6] Stopping components...")
    for name, component in components.items():
        try:
            if hasattr(component, "stop"):
                component.stop()
            print(f"    {name} stopped")
        except Exception as e:
            print(f"    {name} stop failed: {e}")

    post_stop = ResourceSnapshot("Post-Stop")
    report.add_metadata("post_stop_ram_mb", f"{post_stop.process['rss_mb']:.1f}")

    # ═══════════════════════════════════════════════════════════════════════════
    # 6. PERFORMANCE ASSERTIONS
    # ═══════════════════════════════════════════════════════════════════════════

    # --- CPU ---
    def check_cpu_baseline():
        cpu = baseline.process["cpu_percent"]
        if cpu < 5.0:
            return True, f"{cpu:.1f}% (target: < 5%)"
        return False, f"{cpu:.1f}% (exceeds target of 5%)"

    _check("CPU usage (baseline) < 5%", "CPU",
           check_cpu_baseline, severity="WARN",
           fix="Close other applications during AEGIS deployment")

    def check_cpu_post_import():
        cpu = post_import.process["cpu_percent"]
        if cpu < 10.0:
            return True, f"{cpu:.1f}% (target: < 10%)"
        return False, f"{cpu:.1f}% (exceeds target of 10%)"

    _check("CPU usage (post-import) < 10%", "CPU",
           check_cpu_post_import, severity="WARN")

    def check_cpu_post_start():
        cpu = post_start.process["cpu_percent"]
        if cpu < 15.0:
            return True, f"{cpu:.1f}% (target: < 15%)"
        return False, f"{cpu:.1f}% (exceeds target of 15%)"

    _check("CPU usage (post-start) < 15%", "CPU",
           check_cpu_post_start, severity="WARN")

    def check_cpu_sustained():
        if avg_cpu < 10.0:
            return True, f"Avg {avg_cpu:.1f}% across {len(samples)} samples (target: < 10%)"
        return False, f"Avg {avg_cpu:.1f}% (exceeds target of 10%)"

    _check("CPU usage (sustained average) < 10%", "CPU",
           check_cpu_sustained, severity="ERROR",
           fix="Investigate high CPU in AEGIS threads")

    # --- RAM ---
    def check_ram_baseline():
        ram = baseline.process["rss_mb"]
        if ram < 200:
            return True, f"{ram:.1f} MB (target: < 200 MB)"
        return False, f"{ram:.1f} MB (exceeds target of 200 MB)"

    _check("RAM usage (baseline) < 200 MB", "Memory",
           check_ram_baseline, severity="CRITICAL",
           fix="Reduce system memory load before running AEGIS")

    def check_ram_post_import():
        ram = import_delta["rss_mb"]
        if ram < 100:
            return True, f"+{ram:.1f} MB additional (target: < 100 MB increase)"
        return False, f"+{ram:.1f} MB (exceeds target of 100 MB increase)"

    _check("RAM increase (post-import) < 100 MB", "Memory",
           check_ram_post_import, severity="ERROR",
           fix="Check for memory-heavy imports or circular dependencies")

    def check_ram_post_start():
        ram = post_start.process["rss_mb"]
        if ram < 200:
            return True, f"{ram:.1f} MB (target: < 200 MB)"
        return False, f"{ram:.1f} MB (exceeds target of 200 MB)"

    _check("RAM usage (post-start) < 200 MB", "Memory",
           check_ram_post_start, severity="CRITICAL",
           fix="Profile memory usage in AEGIS core components")

    def check_ram_max():
        if max_ram < 250:
            return True, f"Peak {max_ram:.1f} MB (target: < 250 MB)"
        return False, f"Peak {max_ram:.1f} MB (exceeds target of 250 MB)"

    _check("RAM peak usage < 250 MB", "Memory",
           check_ram_max, severity="WARN")

    # --- Threads ---
    def check_threads_baseline():
        t = baseline.process["threads"]
        if t < 30:
            return True, f"{t} threads (target: < 30)"
        return False, f"{t} threads (exceeds target of 30)"

    _check("Thread count (baseline) < 30", "Threads",
           check_threads_baseline, severity="WARN")

    def check_threads_post_start():
        t = post_start.process["threads"]
        if t < 50:
            return True, f"{t} threads (target: < 50)"
        return False, f"{t} threads (exceeds target of 50)"

    _check("Thread count (post-start) < 50", "Threads",
           check_threads_post_start, severity="ERROR",
           fix="Review threading model for leaked or excessive threads")

    def check_threads_sustained():
        if avg_threads < 50:
            return True, f"Avg {avg_threads:.0f} threads (target: < 50)"
        return False, f"Avg {avg_threads:.0f} threads (exceeds target of 50)"

    _check("Thread count (sustained) < 50", "Threads",
           check_threads_sustained, severity="WARN")

    # --- Network Connections ---
    def check_connections():
        if avg_connections < 20:
            return True, f"Avg {avg_connections:.0f} connections (target: < 20)"
        return False, f"Avg {avg_connections:.0f} connections (exceeds target of 20)"

    _check("Network connections < 20", "Network",
           check_connections, severity="WARN")

    # --- Open Files ---
    def check_open_files():
        if avg_files < 50:
            return True, f"Avg {avg_files:.0f} open files (target: < 50)"
        return False, f"Avg {avg_files:.0f} open files (exceeds target of 50)"

    _check("Open file handles < 50", "File System",
           check_open_files, severity="WARN")

    # --- Stability (no drift across samples) ---
    def check_ram_drift():
        ram_values = [s.process["rss_mb"] for s in samples]
        drift = max(ram_values) - min(ram_values)
        if drift < 10:
            return True, f"RAM drift {drift:.1f} MB across samples (target: < 10 MB)"
        return False, f"RAM drift {drift:.1f} MB (exceeds target of 10 MB)"

    _check("RAM stability (drift < 10 MB)", "Stability",
           check_ram_drift, severity="ERROR",
           fix="Investigate potential memory leak in running components")

    def check_cpu_drift():
        cpu_values = [s.process["cpu_percent"] for s in samples]
        drift = max(cpu_values) - min(cpu_values)
        if drift < 5:
            return True, f"CPU drift {drift:.1f}% (target: < 5%)"
        return False, f"CPU drift {drift:.1f}% (exceeds target of 5%)"

    _check("CPU stability (drift < 5%)", "Stability",
           check_cpu_drift, severity="WARN")

    # --- psutil import (required for performance monitoring) ---
    def check_psutil():
        try:
            import psutil
            return True, f"psutil {psutil.__version__} available"
        except ImportError:
            return False, "psutil not installed"

    _check("psutil available for metrics", "Environment",
           check_psutil, severity="CRITICAL",
           fix="pip install psutil")

    # ── Component lifecycle ──
    def check_components_clean_stop():
        ram_after = post_stop.process["rss_mb"]
        if ram_after <= max_ram * 1.1:
            return True, f"RAM after stop: {ram_after:.1f} MB (not significantly above peak)"
        return False, f"RAM after stop: {ram_after:.1f} MB (potential resource leak)"

    _check("Components stop cleanly (no leaks)", "Lifecycle",
           check_components_clean_stop, severity="WARN",
           fix="Ensure all component stop() methods clean up resources")

    return report


if __name__ == "__main__":
    import time
    start = time.time()
    report = ValidationReport("Phase 6", "Performance Testing")
    report = run_phase6(report)
    report.duration = time.time() - start

    json_path = PROJECT_ROOT / "validation" / "reports" / "phase6_report.json"
    html_path = PROJECT_ROOT / "validation" / "reports" / "phase6_report.html"
    report.to_json(json_path)
    report.to_html(html_path)

    report.print_console()
    print(f"  JSON report: {json_path}")
    print(f"  HTML report: {html_path}")

    sys.exit(1 if not report.summary()["target_met"] else 0)
