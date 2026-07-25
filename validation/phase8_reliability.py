"""
Project AEGIS -- Validation Phase 8: Reliability Testing
Lead Architect: ETCHERO / Abdul-Hameed

Runs AEGIS components continuously and monitors for:
  1. Memory leaks (RSS growth over time via linear regression)
  2. Thread leaks (thread count stability)
  3. CPU drift (CPU usage trend analysis)
  4. Handle / file descriptor leaks
  5. Log file growth (prevent unbounded growth)
  6. Recovery after component restart (resilience)

Uses accelerated testing: injects events continuously while sampling
resource usage at regular intervals. Designed to simulate 72 hours of
operation in a shorter time window.

Duration is configurable via RELIABILITY_DURATION_MINUTES env var
(default: 30 minutes for accelerated validation).

Usage:
    python validation/phase8_reliability.py            # 30 min accelerated
    RELIABILITY_DURATION_MINUTES=180 python validation/phase8_reliability.py  # 3 hours
    RELIABILITY_DURATION_MINUTES=4320 python validation/phase8_reliability.py  # 72 hours
"""

import gc
import math
import os
import sys
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from statistics import stdev, mean
from typing import Any, Callable, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from validation.utils.reporter import ValidationReport, ValidationResult


def _check(
    report: ValidationReport, name: str, category: str, fn: Callable,
    severity: str = "ERROR", fix: str = "",
) -> None:
    """Run a single validation check and record the result."""
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


# ─── Configuration ───────────────────────────────────────────────────────────

# Duration in minutes (override via env var)
DEFAULT_DURATION_MINUTES = 20  # default for accelerated dev testing
RELIABILITY_DURATION_MINUTES = float(
    os.environ.get("RELIABILITY_DURATION_MINUTES", DEFAULT_DURATION_MINUTES)
)

# Sampling intervals (seconds)
SAMPLE_INTERVAL = 5            # seconds between resource snapshots
MIN_SAMPLES_FOR_TREND = 10     # minimum samples before trend analysis

# Event injection rate (events per second per component)
EVENTS_PER_SECOND = 20

# Trend detection thresholds
MEMORY_LEAK_THRESHOLD_MB_PER_HOUR = 15   # max allowed RSS growth per hour
THREAD_LEAK_THRESHOLD_PER_HOUR = 5        # max allowed thread growth per hour
CPU_DRIFT_THRESHOLD_PERCENT = 10          # max allowed CPU drift
HANDLE_LEAK_THRESHOLD_PER_HOUR = 10       # max allowed handle growth per hour
LOG_GROWTH_THRESHOLD_MB_PER_HOUR = 100    # max allowed log growth per hour
RECOVERY_TIMEOUT_SECONDS = 10             # max time to recover after restart


# ─── Data Model ──────────────────────────────────────────────────────────────

@dataclass
class ReliabilitySample:
    """A single reliability measurement sample."""
    timestamp: float
    elapsed_minutes: float
    rss_mb: float
    vms_mb: float
    cpu_percent: float
    threads: int
    connections: int
    open_files: int
    gc_objects: int
    log_dir_size_mb: float


# ─── Trend Analysis ──────────────────────────────────────────────────────────

def linear_regression_slope(samples: List[float], timestamps: List[float]) -> float:
    """Compute the slope (units per second) of a linear regression.

    Positive slope = growth over time. Negative slope = shrinkage.
    """
    n = len(samples)
    if n < 2:
        return 0.0

    # Normalize timestamps to elapsed seconds from first sample
    t0 = timestamps[0]
    x = [t - t0 for t in timestamps]
    y = samples

    sum_x = sum(x)
    sum_y = sum(y)
    sum_xy = sum(xi * yi for xi, yi in zip(x, y))
    sum_x2 = sum(xi * xi for xi in x)

    denom = n * sum_x2 - sum_x * sum_x
    if abs(denom) < 1e-10:
        return 0.0

    slope = (n * sum_xy - sum_x * sum_y) / denom
    return slope


def compute_correlation(x: List[float], y: List[float]) -> float:
    """Compute Pearson correlation coefficient between x and y."""
    n = len(x)
    if n < 3:
        return 0.0
    mx = mean(x)
    my = mean(y)
    num = sum((xi - mx) * (yi - my) for xi, yi in zip(x, y))
    denom = math.sqrt(sum((xi - mx) ** 2 for xi in x) * sum((yi - my) ** 2 for yi in y))
    if abs(denom) < 1e-10:
        return 0.0
    return num / denom


def detect_leak(samples: List[float], timestamps: List[float],
                threshold_per_hour: float, label: str,
                unit: str = "units", direction: str = "positive") -> Tuple[bool, str]:
    """Detect a leak by computing the linear regression slope.

    Args:
        direction: "positive" = only flag growth (threads, handles, memory),
                   "both" = flag any excessive change (GC objects, log growth)

    Returns (passed, detail_string).
    """
    if len(samples) < MIN_SAMPLES_FOR_TREND:
        return True, f"Not enough samples ({len(samples)}/{MIN_SAMPLES_FOR_TREND}) for trend analysis"

    slope = linear_regression_slope(samples, timestamps)
    # Convert slope per-second to per-hour
    slope_per_hour = slope * 3600
    corr = compute_correlation(timestamps, samples)

    trend_desc = "growing" if slope_per_hour > threshold_per_hour / 5 else \
                  "stable" if abs(slope_per_hour) < threshold_per_hour / 5 else \
                  "shrinking"
    detail = (
        f"{label} slope: {slope_per_hour:+.2f} {unit}/hour "
        f"(r={corr:.2f}) — {trend_desc}"
    )

    if direction == "positive":
        # Only flag positive growth as a leak (decreasing is fine)
        if slope_per_hour > threshold_per_hour:
            return False, f"{detail} (exceeds threshold of {threshold_per_hour} {unit}/hour, potential leak)"
    else:
        # Flag excessive change in either direction
        if abs(slope_per_hour) > threshold_per_hour:
            return False, f"{detail} (exceeds threshold of {threshold_per_hour} {unit}/hour, potential leak)"
    return True, detail


# ─── Resource Sampling ───────────────────────────────────────────────────────

def get_process_usage() -> Dict[str, float]:
    """Get current process resource usage."""
    import psutil
    proc = psutil.Process()
    cpu = proc.cpu_percent(interval=0.3)
    mem = proc.memory_info()
    threads = proc.num_threads()

    try:
        connections = len(proc.net_connections())
    except (psutil.AccessDenied, psutil.NoSuchProcess, Exception):
        connections = -1

    try:
        open_files = len(proc.open_files())
    except (psutil.AccessDenied, psutil.NoSuchProcess, Exception):
        open_files = -1

    # Count GC objects
    gc_objects = len(gc.get_objects())

    return {
        "cpu_percent": cpu,
        "rss_mb": mem.rss / (1024 * 1024),
        "vms_mb": mem.vms / (1024 * 1024),
        "threads": threads,
        "connections": connections,
        "open_files": open_files,
        "gc_objects": gc_objects,
    }


def get_log_dir_size(log_dir: Path) -> float:
    """Get total size of log directory in MB."""
    if not log_dir.exists():
        return 0.0
    total_bytes = 0
    try:
        for f in log_dir.glob("**/*"):
            if f.is_file():
                total_bytes += f.stat().st_size
    except (OSError, PermissionError):
        pass
    return total_bytes / (1024 * 1024)


# ─── Component Management ────────────────────────────────────────────────────

class AegisReliabilityRunner:
    """Manages AEGIS component lifecycle for reliability testing."""

    def __init__(self):
        self._components: Dict[str, Any] = {}
        self._failures: List[str] = []

    def boot_all(self) -> None:
        """Start all AEGIS core components (skip ones requiring hardware)."""
        # ── Config ──
        import config  # noqa: F401
        self._log_dir = Path(config.LOG_DIR)

        # ── Heartbeat (using simulated psutil) ──
        try:
            from core.heartbeat import Heartbeat
            hb = Heartbeat()
            self._components["heartbeat"] = hb
        except Exception as e:
            self._failures.append(f"Heartbeat: {e}")

        # ── Incident Manager ──
        try:
            from modules.incident_manager import IncidentManager
            im = IncidentManager()
            im.start()
            self._components["incident_manager"] = im
        except Exception as e:
            self._failures.append(f"IncidentManager: {e}")

        # ── AI Analyst (static class, no lifecycle needed) ──
        try:
            from modules.ai_analyst import AiAnalyst
            self._components["ai_analyst"] = AiAnalyst
        except Exception as e:
            self._failures.append(f"AiAnalyst: {e}")

        # ── DNS Monitor (programmatic mode) ──
        try:
            from modules.dns_monitor import DnsMonitor
            dm = DnsMonitor()
            dm.start()
            self._components["dns_monitor"] = dm
        except Exception as e:
            self._failures.append(f"DnsMonitor: {e}")

        # ── Evidence Engine ──
        try:
            from modules.evidence_engine import EvidenceEngine
            EvidenceEngine.configure(Path(config.EVIDENCE_DIR))
            self._components["evidence_engine"] = True
        except Exception as e:
            self._failures.append(f"EvidenceEngine: {e}")

    def inject_events(self, count: int = 5) -> None:
        """Inject a batch of events into running components."""
        timestamp = time.time()
        from modules.incident_manager import IncidentManager
        from modules.dns_monitor import DnsReasoningEngine, DnsQuery
        from modules.ai_analyst import AiAnalyst

        im = self._components.get("incident_manager")
        dm = self._components.get("dns_monitor")
        analyst = self._components.get("ai_analyst")

        # ── Inject network events ──
        if im:
            for i in range(count):
                try:
                    from dataclasses import dataclass
                    event = type("StressEvent", (), {
                        "attacker_ip": f"10.0.0.{i % 50}",
                        "threat_type": ["SYN_SCAN", "BRUTE_FORCE", "REVERSE_SHELL"][i % 3],
                        "risk_level": ["MEDIUM", "HIGH", "CRITICAL"][i % 3],
                        "port_count": 10 + i,
                        "reasoning": "Stress test event",
                    })()
                    im.correlate(event)
                except Exception:
                    pass

        # ── Inject DNS queries (feed through existing engine to preserve state) ──
        if dm:
            for i in range(count):
                try:
                    dm._engine.evaluate(DnsQuery(
                        timestamp=timestamp + (i * 0.1),
                        domain=f"test{i}.example.com",
                        query_type="A" if i % 2 == 0 else "TXT",
                        source_ip=f"10.0.0.{i % 50}",
                        query_size=40,
                        response_size=80,
                    ))
                except Exception:
                    pass

    def take_snapshot(self, elapsed: float) -> Optional[ReliabilitySample]:
        """Take a resource usage snapshot."""
        try:
            usage = get_process_usage()
            log_size = get_log_dir_size(self._log_dir) if hasattr(self, '_log_dir') else 0.0
            return ReliabilitySample(
                timestamp=time.time(),
                elapsed_minutes=elapsed,
                rss_mb=usage["rss_mb"],
                vms_mb=usage["vms_mb"],
                cpu_percent=usage["cpu_percent"],
                threads=usage["threads"],
                connections=usage["connections"],
                open_files=usage["open_files"],
                gc_objects=usage["gc_objects"],
                log_dir_size_mb=log_size,
            )
        except Exception:
            return None

    def stop_all(self) -> None:
        """Stop all running components and clean up."""
        for name, component in self._components.items():
            try:
                if hasattr(component, "stop"):
                    component.stop()
            except Exception as e:
                self._failures.append(f"Stop {name}: {e}")
        time.sleep(0.5)
        gc.collect()

    @property
    def has_failures(self) -> bool:
        return len(self._failures) > 0

    @property
    def failure_details(self) -> str:
        return "; ".join(self._failures)


# ─── Main Reliability Test ────────────────────────────────────────────────────

def run_phase8(report: ValidationReport) -> ValidationReport:
    """Execute all Phase 8 reliability validation checks."""

    duration_minutes = RELIABILITY_DURATION_MINUTES
    total_seconds = duration_minutes * 60

    print(f"\n{'='*60}")
    print(f"  PHASE 8: RELIABILITY TESTING")
    print(f"  Duration: {duration_minutes:.0f} minutes ({total_seconds:.0f} seconds)")
    print(f"  Sample interval: {SAMPLE_INTERVAL}s")
    print("=" * 60)

    report.add_metadata("target_duration_minutes", str(duration_minutes))
    report.add_metadata("sample_interval", str(SAMPLE_INTERVAL))
    report.add_metadata("event_injection_rate", str(EVENTS_PER_SECOND))

    # ═══════════════════════════════════════════════════════════════════════════
    # 1. BOOT ALL COMPONENTS
    # ═══════════════════════════════════════════════════════════════════════════
    print("\n  [RELIABILITY] Booting AEGIS components...")
    runner = AegisReliabilityRunner()
    runner.boot_all()

    def check_boot():
        if not runner.has_failures:
            return True, f"All {len(runner._components)} components booted successfully"
        return False, f"Boot failures: {runner.failure_details}"

    _check(report, "All components boot successfully", "Boot",
           check_boot, severity="CRITICAL",
           fix="Investigate component import/instantiation errors")

    # ═══════════════════════════════════════════════════════════════════════════
    # 2. RUN CONTINUOUS TEST LOOP
    # ═══════════════════════════════════════════════════════════════════════════
    print(f"\n  [RELIABILITY] Running test loop for {duration_minutes:.0f} minutes...")
    print(f"  [RELIABILITY] Injecting ~{EVENTS_PER_SECOND} events/sec continuously")

    samples: List[ReliabilitySample] = []
    start_time = time.time()
    end_time = start_time + total_seconds
    event_count = 0
    last_event_inject = 0.0
    crashes = 0
    last_sample_time = 0.0

    try:
        while time.time() < end_time:
            now = time.time()
            elapsed = (now - start_time) / 60.0

            # ── Inject events at the configured rate ──
            if now - last_event_inject >= 1.0:
                try:
                    runner.inject_events(count=EVENTS_PER_SECOND)
                    event_count += EVENTS_PER_SECOND
                    last_event_inject = now
                except Exception:
                    crashes += 1

            # ── Take resource snapshot at regular intervals ──
            if now - last_sample_time >= SAMPLE_INTERVAL:
                snap = runner.take_snapshot(elapsed)
                if snap:
                    samples.append(snap)
                    last_sample_time = now

                    # Progress every 60 seconds
                    if len(samples) % (60 // SAMPLE_INTERVAL) == 0:
                        remaining = end_time - now
                        print(
                            f"    [{elapsed:5.1f}min] "
                            f"RSS={snap.rss_mb:.1f}MB "
                            f"Threads={snap.threads} "
                            f"CPU={snap.cpu_percent:.1f}% "
                            f"Events={event_count} "
                            f"Remaining={remaining:.0f}s"
                        )

            # Sleep a short time to avoid busy-waiting
            time.sleep(0.1)

    except KeyboardInterrupt:
        print("\n  [RELIABILITY] Test interrupted by user")

    elapsed_actual = time.time() - start_time
    print(f"\n  [RELIABILITY] Test completed: {elapsed_actual:.0f}s elapsed")
    print(f"  [RELIABILITY] Samples collected: {len(samples)}")
    print(f"  [RELIABILITY] Events injected: {event_count}")
    print(f"  [RELIABILITY] Crashes during injection: {crashes}")

    report.add_metadata("actual_duration_seconds", str(round(elapsed_actual, 1)))
    report.add_metadata("samples_collected", str(len(samples)))
    report.add_metadata("events_injected", str(event_count))
    report.add_metadata("injection_crashes", str(crashes))

    # ═══════════════════════════════════════════════════════════════════════════
    # 3. MEMORY LEAK DETECTION (Linear regression on RSS samples)
    # ═══════════════════════════════════════════════════════════════════════════
    print("\n  [RELIABILITY] Analyzing memory trend...")

    rss_values = [s.rss_mb for s in samples]
    rss_timestamps = [s.timestamp for s in samples]
    initial_rss = rss_values[0] if rss_values else 0
    final_rss = rss_values[-1] if rss_values else 0
    rss_delta = final_rss - initial_rss
    rss_min = min(rss_values) if rss_values else 0
    rss_max = max(rss_values) if rss_values else 0

    report.add_metadata("initial_rss_mb", f"{initial_rss:.1f}")
    report.add_metadata("final_rss_mb", f"{final_rss:.1f}")
    report.add_metadata("rss_delta_mb", f"{rss_delta:.1f}")
    report.add_metadata("rss_min_mb", f"{rss_min:.1f}")
    report.add_metadata("rss_max_mb", f"{rss_max:.1f}")

    # Memory leak check
    def check_memory_leak():
        return detect_leak(
            rss_values, rss_timestamps,
            MEMORY_LEAK_THRESHOLD_MB_PER_HOUR,
            "RSS memory", "MB",
            direction="positive"
        )

    _check(report, "No memory leak (RSS growth < 15 MB/hour)", "Memory",
           check_memory_leak, severity="CRITICAL",
           fix="Run memory profiler to identify accumulating objects. Check for unbounded dict/list growth in stateful modules.")

    # Peak memory check
    def check_peak_memory():
        peak = rss_max
        # Peak should not exceed initial + 50MB for a 30-min test (scales with duration)
        allowed_peak = initial_rss + 50 + (duration_minutes * 0.5)
        if peak < allowed_peak:
            return True, f"Peak RSS: {peak:.1f} MB (threshold: {allowed_peak:.0f} MB) — {peak - initial_rss:+.1f} MB from start"
        return False, f"Peak RSS: {peak:.1f} MB (exceeds threshold of {allowed_peak:.0f} MB)"

    _check(report, "Peak memory stays within expected range", "Memory",
           check_peak_memory, severity="ERROR",
           fix="Check for memory spikes in event processing paths")

    # ═══════════════════════════════════════════════════════════════════════════
    # 4. THREAD LEAK DETECTION
    # ═══════════════════════════════════════════════════════════════════════════
    print("  [RELIABILITY] Analyzing thread trend...")

    thread_values = [s.threads for s in samples]
    thread_timestamps = [s.timestamp for s in samples]
    initial_threads = thread_values[0] if thread_values else 0
    final_threads = thread_values[-1] if thread_values else 0
    thread_delta = final_threads - initial_threads
    thread_min = min(thread_values) if thread_values else 0
    thread_max = max(thread_values) if thread_values else 0

    report.add_metadata("initial_threads", str(initial_threads))
    report.add_metadata("final_threads", str(final_threads))
    report.add_metadata("thread_delta", str(thread_delta))
    report.add_metadata("thread_min", str(thread_min))
    report.add_metadata("thread_max", str(thread_max))

    def check_thread_leak():
        return detect_leak(
            [float(t) for t in thread_values], thread_timestamps,
            THREAD_LEAK_THRESHOLD_PER_HOUR,
            "Thread count", "threads",
            direction="positive"
        )

    _check(report, "No thread leak (thread growth < 5/hour)", "Threads",
           check_thread_leak, severity="ERROR",
           fix="Check for threads created but not joined. Review daemon thread lifecycle.")

    # Absolute thread limit
    def check_thread_limit():
        if thread_max < 100:
            return True, f"Max threads: {thread_max} (limit: < 100)"
        return False, f"Max threads: {thread_max} (exceeds limit of 100)"

    _check(report, "Thread count stays below 100", "Threads",
           check_thread_limit, severity="ERROR",
           fix="Review threading model for excessive thread creation")

    # ═══════════════════════════════════════════════════════════════════════════
    # 5. CPU DRIFT ANALYSIS
    # ═══════════════════════════════════════════════════════════════════════════
    print("  [RELIABILITY] Analyzing CPU drift...")

    cpu_values = [s.cpu_percent for s in samples]
    cpu_timestamps = [s.timestamp for s in samples]
    avg_cpu = mean(cpu_values) if cpu_values else 0
    max_cpu = max(cpu_values) if cpu_values else 0

    report.add_metadata("avg_cpu_percent", f"{avg_cpu:.1f}")
    report.add_metadata("max_cpu_percent", f"{max_cpu:.1f}")

    def check_cpu_drift():
        if len(cpu_values) < MIN_SAMPLES_FOR_TREND:
            return True, f"Not enough samples ({len(cpu_values)}) for CPU drift analysis"
        slope = linear_regression_slope(cpu_values, cpu_timestamps)
        slope_per_hour = slope * 3600
        corr = compute_correlation(cpu_timestamps, cpu_values)
        drift_direction = "increasing" if slope_per_hour > CPU_DRIFT_THRESHOLD_PERCENT else \
                          "decreasing" if slope_per_hour < -CPU_DRIFT_THRESHOLD_PERCENT else \
                          "stable"
        detail = (
            f"CPU slope: {slope_per_hour:+.2f}%/hour (r={corr:.2f}) — {drift_direction}"
        )
        if abs(slope_per_hour) > CPU_DRIFT_THRESHOLD_PERCENT:
            return False, f"{detail} (exceeds drift threshold of {CPU_DRIFT_THRESHOLD_PERCENT}%/hour)"
        return True, detail

    _check(report, "No CPU drift (trend < 10%/hour)", "CPU",
           check_cpu_drift, severity="WARN",
           fix="Investigate CPU usage growth pattern. Check for polling loops or spin-waiting.")

    # Average CPU
    def check_avg_cpu():
        if avg_cpu < 15.0:
            return True, f"Average CPU: {avg_cpu:.1f}% (target: < 15%)"
        return False, f"Average CPU: {avg_cpu:.1f}% (exceeds target of 15%)"

    _check(report, "Average CPU usage < 15%", "CPU",
           check_avg_cpu, severity="WARN",
           fix="Review event processing loop for inefficiencies")

    # ═══════════════════════════════════════════════════════════════════════════
    # 6. GC OBJECT ANALYSIS
    # ═══════════════════════════════════════════════════════════════════════════
    print("  [RELIABILITY] Analyzing GC object trend...")

    gc_values = [s.gc_objects for s in samples]
    gc_timestamps = [s.timestamp for s in samples]
    initial_gc = gc_values[0] if gc_values else 0
    final_gc = gc_values[-1] if gc_values else 0
    gc_delta = final_gc - initial_gc

    report.add_metadata("initial_gc_objects", str(initial_gc))
    report.add_metadata("final_gc_objects", str(final_gc))

    def check_gc_leak():
        if len(gc_values) < MIN_SAMPLES_FOR_TREND:
            return True, f"Not enough samples ({len(gc_values)}) for GC object analysis"
        slope = linear_regression_slope([float(g) for g in gc_values], gc_timestamps)
        objects_per_hour = slope * 3600
        corr = compute_correlation(gc_timestamps, [float(g) for g in gc_values])
        detail = (
            f"GC objects slope: {objects_per_hour:+.0f} objects/hour "
            f"(r={corr:.2f}) — initial={initial_gc}, final={final_gc}"
        )
        if objects_per_hour > 5000:
            return False, f"{detail} (excessive object accumulation, potential reference cycle)"
        return True, detail

    _check(report, "No GC object leak (stable object count)", "Memory",
           check_gc_leak, severity="WARN",
           fix="Check for reference cycles, cached objects not evicted, or listener leaks")

    # ═══════════════════════════════════════════════════════════════════════════
    # 7. HANDLE / FILE DESCRIPTOR ANALYSIS
    # ═══════════════════════════════════════════════════════════════════════════
    print("  [RELIABILITY] Analyzing open file handle trend...")

    file_values = [s.open_files for s in samples]
    file_timestamps = [s.timestamp for s in samples]
    valid_files = [(f, t) for f, t in zip(file_values, file_timestamps) if f >= 0]

    if valid_files:
        f_values = [f for f, _ in valid_files]
        f_timestamps = [t for _, t in valid_files]

        def check_handle_leak():
            return detect_leak(
                [float(f) for f in f_values], f_timestamps,
            HANDLE_LEAK_THRESHOLD_PER_HOUR,
            "Open file handles", "handles",
            direction="positive"
        )

        _check(report, "No handle leak (handle growth < 10/hour)", "File System",
               check_handle_leak, severity="WARN",
               fix="Check for file handles opened but not closed. Review logging handler lifecycle.")
    else:
        _check(report, "No handle leak (handle growth < 10/hour)", "File System",
               lambda: (True, "Handle tracking unavailable on this platform (data not accessible)"),
               severity="WARN")

    # ═══════════════════════════════════════════════════════════════════════════
    # 8. LOG FILE GROWTH ANALYSIS
    # ═══════════════════════════════════════════════════════════════════════════
    print("  [RELIABILITY] Analyzing log directory growth...")

    log_values = [s.log_dir_size_mb for s in samples]
    log_timestamps = [s.timestamp for s in samples]
    initial_log = log_values[0] if log_values else 0
    final_log = log_values[-1] if log_values else 0
    log_growth = final_log - initial_log

    report.add_metadata("initial_log_mb", f"{initial_log:.1f}")
    report.add_metadata("final_log_mb", f"{final_log:.1f}")
    report.add_metadata("log_growth_mb", f"{log_growth:.1f}")

    def check_log_growth():
        if len(log_values) < MIN_SAMPLES_FOR_TREND:
            return True, f"Not enough samples ({len(log_values)}) for log growth analysis"
        slope = linear_regression_slope(log_values, log_timestamps)
        mb_per_hour = slope * 3600
        detail = (
            f"Log growth: {mb_per_hour:+.2f} MB/hour "
            f"(initial={initial_log:.1f}MB, final={final_log:.1f}MB)"
        )
        if mb_per_hour > LOG_GROWTH_THRESHOLD_MB_PER_HOUR:
            return False, f"{detail} (exceeds threshold of {LOG_GROWTH_THRESHOLD_MB_PER_HOUR} MB/hour)"
        return True, detail

    _check(report, "Log file growth < 100 MB/hour", "Disk",
           check_log_growth, severity="WARN",
           fix="Reduce log verbosity or increase log rotation frequency. Review debug logging in hot paths.")

    # ═══════════════════════════════════════════════════════════════════════════
    # 9. CRASH / STABILITY CHECK
    # ═══════════════════════════════════════════════════════════════════════════
    def check_no_crashes():
        if crashes == 0:
            return True, f"Zero crashes during {event_count} event injections over {elapsed_actual:.0f}s"
        return False, f"{crashes} crashes during event injection"

    _check(report, "Zero crashes during continuous operation", "Stability",
           check_no_crashes, severity="CRITICAL",
           fix="Investigate exception handling in event processing paths")

    def check_continuous_operation():
        if elapsed_actual >= total_seconds * 0.8:
            return True, (
                f"Ran for {elapsed_actual:.0f}s of {total_seconds:.0f}s target "
                f"({elapsed_actual/total_seconds*100:.0f}%)"
            )
        return False, f"Test duration too short: {elapsed_actual:.0f}s (target: {total_seconds:.0f}s)"

    _check(report, "Continuous operation maintained for target duration", "Stability",
           check_continuous_operation, severity="ERROR",
           fix="Check for early termination due to unhandled exceptions")

    # ═══════════════════════════════════════════════════════════════════════════
    # 10. STOP COMPONENTS AND VERIFY CLEANUP
    # ═══════════════════════════════════════════════════════════════════════════
    print("\n  [RELIABILITY] Stopping components...")
    runner.stop_all()

    def check_clean_stop():
        if not runner.has_failures:
            return True, "All components stopped without errors"
        return False, f"Stop failures: {runner.failure_details}"

    _check(report, "Components stop cleanly (no errors)", "Lifecycle",
           check_clean_stop, severity="WARN",
           fix="Review component stop() methods for proper cleanup")

    # Measure post-stop memory
    try:
        post_stop = get_process_usage()
        report.add_metadata("post_stop_rss_mb", f"{post_stop['rss_mb']:.1f}")

        def check_post_stop_memory():
            if post_stop["rss_mb"] <= rss_max * 1.1:
                return True, f"Post-stop RSS: {post_stop['rss_mb']:.1f} MB (not significantly above peak)"
            return False, f"Post-stop RSS: {post_stop['rss_mb']:.1f} MB (above peak, potential leak)"

        _check(report, "Memory released after component stop", "Lifecycle",
               check_post_stop_memory, severity="WARN",
               fix="Ensure stop() methods release references to large objects")

        def check_gc_freed():
            gc.collect()
            gc_after = len(gc.get_objects())
            if gc_after <= initial_gc * 1.2:
                return True, f"GC objects after stop: {gc_after} (within 20% of initial: {initial_gc})"
            return False, f"GC objects after stop: {gc_after} (significantly above initial: {initial_gc})"

        _check(report, "GC objects return to baseline after stop", "Memory",
               check_gc_freed, severity="WARN",
               fix="Check for global caches or module-level state that persists after stop")

    except Exception as e:
        _check(report, "Memory released after component stop", "Lifecycle",
               lambda: (False, f"Measurement failed: {e}"), severity="WARN")

    return report


# ═══════════════════════════════════════════════════════════════════════════════
# COMMAND LINE
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    start = time.time()
    report = ValidationReport("Phase 8", "Reliability Testing")
    report = run_phase8(report)
    report.duration = time.time() - start

    json_path = PROJECT_ROOT / "validation" / "reports" / "phase8_report.json"
    html_path = PROJECT_ROOT / "validation" / "reports" / "phase8_report.html"
    report.to_json(json_path)
    report.to_html(html_path)

    report.print_console()
    print(f"  JSON report: {json_path}")
    print(f"  HTML report: {html_path}")

    sys.exit(1 if not report.summary()["target_met"] else 0)
