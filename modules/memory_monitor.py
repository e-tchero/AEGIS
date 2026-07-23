"""
Project AEGIS — Memory Intelligence Module
Lead Architect: ETCHERO / Abdul-Hameed
Version: 1.0.0 | Classification: AEGIS-MEMINTEL
Role: Monitors process memory for signs of in-memory attacks.
      Detects DLL injection, reflective loading, RWX memory regions,
      process hollowing, and anomalous memory permissions.

      Uses psutil memory_maps() to inspect per-process memory regions
      and flag suspicious patterns.
"""

import json
import logging
import threading
import time
import traceback
from dataclasses import dataclass, asdict, field
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from threading import Event
from typing import Callable, Dict, List, Optional

import psutil

# ─── CONFIG ───────────────────────────────────────────────────────────────────
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config import (  # noqa: E402
    MEMORY_POLL_INTERVAL,
    MEMORY_LOG_FILE,
    MEMORY_RWX_THRESHOLD,
    SUSPICIOUS_PERMISSIONS,
    MEMORY_MAP_COUNT_THRESHOLD,
    SUSPICIOUS_INJECTION_MODULES,
    KNOWN_LEGITIMATE_MODULES,
    RWX_ALLOWED_PROCESSES,
    LOG_MAX_BYTES,
    LOG_BACKUP_COUNT,
    LOG_FORMAT,
)

# ─── LOGGER ───────────────────────────────────────────────────────────────────
_logger = logging.getLogger("aegis.memintel")
if not _logger.handlers:
    _handler = RotatingFileHandler(
        str(MEMORY_LOG_FILE),
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT,
        encoding="utf-8",
    )
    _handler.setFormatter(logging.Formatter(LOG_FORMAT))
    _logger.addHandler(_handler)
_logger.setLevel(logging.INFO)
_logger.propagate = False


# ─── DATA MODELS ──────────────────────────────────────────────────────────────
@dataclass
class MemoryRegion:
    """A memory region from a process's address space."""
    path: str           # Backing file path (empty if anonymous)
    perms: str          # Permissions string (rwx, r-x, rwxp, etc.)
    rss: int            # Resident set size in bytes
    is_anonymous: bool  # True if no backing file
    is_executable: bool  # True if executable permission set
    is_writable: bool   # True if write permission set
    is_private: bool    # True if private mapping (not shared)


@dataclass
class MemoryThreat:
    """A memory-based threat alert."""
    timestamp: str
    threat_type: str     # RWX_MEMORY, DLL_INJECTION, PROCESS_HOLLOWING, REFLECTIVE_LOAD, HIGH_MAP_COUNT
    risk_level: str      # CRITICAL, HIGH, MEDIUM, LOW
    pid: int
    process_name: str
    suspicious_count: int
    reasoning: str
    action_taken: str
    evidence: Dict = field(default_factory=dict)


# ─── MEMORY ANALYZER ──────────────────────────────────────────────────────────
class MemoryAnalyzer:
    """Analyzes process memory maps for suspicious patterns."""

    def __init__(self):
        self._previous_map_counts: Dict[int, int] = {}  # pid -> map count

    def analyze_process(self, proc: psutil.Process) -> Optional[MemoryThreat]:
        """Run all detection checks on a single process.

        Checks in priority order:
        1. RWX memory regions (shellcode / injected code)
        2. DLL injection (suspicious modules)
        3. Reflective loading (anonymous executable memory)
        4. Process hollowing (image mismatch)
        5. High memory map count (injection indicator)
        """
        pid = proc.pid
        try:
            name = proc.name() or "unknown"
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

        # Known JIT processes are allowed RWX memory
        name_lower = name.lower()
        is_jit_allowed = any(jit in name_lower for jit in RWX_ALLOWED_PROCESSES)

        try:
            maps = proc.memory_maps(grouped=False)
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            return None

        if not maps:
            return None

        # Parse all memory regions
        regions = self._parse_regions(maps)
        map_count = len(regions)

        # ── Check 1: RWX memory regions ──
        rwx_regions = [r for r in regions if r.perms in SUSPICIOUS_PERMISSIONS]
        if rwx_regions:
            if not is_jit_allowed or len(rwx_regions) > MEMORY_RWX_THRESHOLD:
                return self._create_rwx_threat(pid, name, rwx_regions, map_count)

        # ── Check 2: DLL injection (suspicious modules) ──
        suspicious_modules = self._find_suspicious_modules(regions)
        if suspicious_modules:
            return self._create_injection_threat(pid, name, suspicious_modules, map_count)

        # ── Check 3: Reflective loading (anon-exec regions) ──
        anon_exec = [r for r in regions if r.is_anonymous and r.is_executable and r.rss > 4096]
        if anon_exec and not is_jit_allowed:
            # Count significant anonymous executable regions (>4KB)
            if len(anon_exec) >= 2:
                return self._create_reflective_threat(pid, name, anon_exec, map_count)

        # ── Check 4: Process hollowing ──
        hollowing = self._check_hollowing(regions, name)
        if hollowing:
            return self._create_hollowing_threat(pid, name, hollowing, map_count)

        # ── Check 5: High memory map count ──
        prev_count = self._previous_map_counts.get(pid, 0)
        self._previous_map_counts[pid] = map_count

        if map_count > MEMORY_MAP_COUNT_THRESHOLD and prev_count > 0:
            # Flag if map count is consistently high (not a transient spike)
            if prev_count > MEMORY_MAP_COUNT_THRESHOLD:
                return self._create_high_map_threat(pid, name, map_count)

        return None

    # ── Region Parsing ───────────────────────────────────────────────────────

    @staticmethod
    def _parse_regions(maps: List) -> List[MemoryRegion]:
        """Parse psutil memory maps into MemoryRegion objects."""
        regions = []
        for m in maps:
            path = m.path or ""
            perms = (m.perms or "---").lower().strip()

            regions.append(MemoryRegion(
                path=path,
                perms=perms,
                rss=m.rss or 0,
                is_anonymous=not bool(path),
                is_executable="x" in perms,
                is_writable="w" in perms,
                is_private="p" in perms,
            ))
        return regions

    # ── Suspicious Module Detection ─────────────────────────────────────────

    @staticmethod
    def _find_suspicious_modules(regions: List[MemoryRegion]) -> List[Dict]:
        """Find suspicious modules loaded into process memory.

        Looks for:
        - Modules loaded from temp/suspicious directories
        - Modules with suspicious names
        - Modules that are NOT in the known legitimate list
        - Modules with suspicious permission combinations
        """
        suspicious = []

        for region in regions:
            path_lower = region.path.lower()

            if not region.path or region.is_anonymous:
                continue

            path_parts = path_lower.replace("\\", "/").split("/")
            module_name = path_parts[-1] if path_parts else ""

            # Skip known legitimate system modules
            if any(legit in path_lower for legit in KNOWN_LEGITIMATE_MODULES):
                continue

            # Check for suspicious paths
            for sus_path in SUSPICIOUS_INJECTION_MODULES:
                if sus_path and sus_path in path_lower:
                    suspicious.append({
                        "path": region.path,
                        "matched_pattern": sus_path,
                        "perms": region.perms,
                        "rss": region.rss,
                        "reason": f"Loaded from suspicious path: {region.path}",
                    })
                    break

            # Check for writable + executable (not normal for DLLs)
            if region.is_writable and region.is_executable and module_name.endswith(".dll"):
                suspicious.append({
                    "path": region.path,
                    "matched_pattern": "wx_module",
                    "perms": region.perms,
                    "rss": region.rss,
                    "reason": f"Injected-module with write+exec permissions in '{module_name}'",
                })

        return suspicious

    # ── Process Hollowing Detection ─────────────────────────────────────────

    @staticmethod
    def _check_hollowing(regions: List[MemoryRegion], process_name: str) -> Optional[Dict]:
        """Detect process hollowing by checking memory characteristics.

        Signs of hollowing:
        - No executable regions backed by the original image file
        - Executable regions backed by anonymous memory or temp files
        - Image base not where it should be (crude heuristic)
        """

        # Build list of executable regions with their backing files
        exec_files = set()
        for r in regions:
            if r.is_executable and r.path:
                exec_files.add(r.path.lower())

        # If a process has executable regions but none from its own image file,
        # it may be hollowed (e.g., svchost.exe with no c:\windows\... backing)
        if not exec_files and any(r.is_executable for r in regions):
            # Executable regions exist but none from files
            return {
                "indicator": "no_file_backed_executable_regions",
                "exec_region_count": sum(1 for r in regions if r.is_executable),
                "exec_regions_anonymous": sum(
                    1 for r in regions if r.is_executable and r.is_anonymous
                ),
            }

        # Check if the process image is loaded from a non-standard location
        exe_regions_from_temp = [
            r for r in regions
            if r.is_executable and r.path
            and any(t in r.path.lower() for t in ["/temp/", "/tmp/", "\\temp\\", "\\tmp\\"])  # nosec B108
        ]
        if exe_regions_from_temp:
            return {
                "indicator": "executable_code_in_temp",
                "matched_regions": [r.path for r in exe_regions_from_temp[:5]],
                "count": len(exe_regions_from_temp),
            }

        return None

    # ── Threat Builders ──────────────────────────────────────────────────────

    @staticmethod
    def _create_rwx_threat(pid: int, name: str, rwx_regions: List[MemoryRegion],
                           map_count: int) -> MemoryThreat:
        """Build threat for RWX memory regions (most severe)."""
        total_rwx_rss = sum(r.rss for r in rwx_regions)
        rwx_paths = [r.path for r in rwx_regions[:10] if r.path]

        reasoning = (
            f"Process '{name}' (PID {pid}) has {len(rwx_regions)} RWX memory regions "
            f"totaling {total_rwx_rss // 1024}KB. RWX (Read-Write-Execute) memory is "
            f"extremely rare in normal operation and strongly indicates injected "
            f"shellcode or malicious code execution."
        )
        if rwx_paths:
            reasoning += f" Suspicious regions: {', '.join(rwx_paths[:5])}."

        return MemoryThreat(
            timestamp=datetime.now().isoformat(),
            threat_type="RWX_MEMORY",
            risk_level="CRITICAL",
            pid=pid,
            process_name=name,
            suspicious_count=len(rwx_regions),
            reasoning=reasoning,
            action_taken="FLAG_FOR_AUTOBLOCK",
            evidence={
                "rwx_count": len(rwx_regions),
                "total_rwx_kb": total_rwx_rss // 1024,
                "rwx_permissions": list(set(r.perms for r in rwx_regions)),
                "rwx_regions": [
                    {"path": r.path or "(anon)", "perms": r.perms, "rss_kb": r.rss // 1024}
                    for r in rwx_regions[:20]
                ],
                "total_map_count": map_count,
            },
        )

    @staticmethod
    def _create_injection_threat(
        pid: int, name: str,
        suspicious_modules: List[Dict],
        map_count: int,
    ) -> MemoryThreat:
        """Build threat for DLL injection."""
        module_names = [m["path"].split("/")[-1].split("\\")[-1]
                        for m in suspicious_modules[:5]]
        reasoning = (
            f"DLL injection detected in '{name}' (PID {pid}): "
            f"found {len(suspicious_modules)} suspicious modules loaded. "
            f"Suspicious modules: {', '.join(module_names)}. "
            f"These modules are not in the known legitimate list and are loaded "
            f"from non-standard paths."
        )

        return MemoryThreat(
            timestamp=datetime.now().isoformat(),
            threat_type="DLL_INJECTION",
            risk_level="HIGH",
            pid=pid,
            process_name=name,
            suspicious_count=len(suspicious_modules),
            reasoning=reasoning,
            action_taken="ALERT_AND_MONITOR",
            evidence={
                "suspicious_modules": suspicious_modules[:20],
                "count": len(suspicious_modules),
                "total_map_count": map_count,
            },
        )

    @staticmethod
    def _create_reflective_threat(
        pid: int, name: str,
        anon_exec: List[MemoryRegion],
        map_count: int,
    ) -> MemoryThreat:
        """Build threat for reflective DLL loading."""
        total_anon_rss = sum(r.rss for r in anon_exec)
        reasoning = (
            f"Reflective DLL loading suspected in '{name}' (PID {pid}): "
            f"{len(anon_exec)} anonymous executable memory regions detected "
            f"({total_anon_rss // 1024}KB total). These regions have execute "
            f"permissions but no backing file, indicating code loaded directly "
            f"into memory (reflective / memory-only loading)."
        )

        return MemoryThreat(
            timestamp=datetime.now().isoformat(),
            threat_type="REFLECTIVE_LOAD",
            risk_level="HIGH",
            pid=pid,
            process_name=name,
            suspicious_count=len(anon_exec),
            reasoning=reasoning,
            action_taken="ALERT_AND_MONITOR",
            evidence={
                "anon_exec_count": len(anon_exec),
                "total_anon_exec_kb": total_anon_rss // 1024,
                "region_sizes_kb": [r.rss // 1024 for r in anon_exec[:20]],
                "total_map_count": map_count,
            },
        )

    @staticmethod
    def _create_hollowing_threat(
        pid: int, name: str,
        hollowing: Dict,
        map_count: int,
    ) -> MemoryThreat:
        """Build threat for process hollowing."""
        indicator = hollowing.get("indicator", "unknown")
        reasoning = (
            f"Process hollowing suspected in '{name}' (PID {pid}): "
            f"{indicator}. The process's memory characteristics suggest its "
            f"original code has been replaced. This is a common technique used "
            f"by malware to evade detection by masquerading as a legitimate process."
        )

        return MemoryThreat(
            timestamp=datetime.now().isoformat(),
            threat_type="PROCESS_HOLLOWING",
            risk_level="CRITICAL",
            pid=pid,
            process_name=name,
            suspicious_count=hollowing.get("count", 1),
            reasoning=reasoning,
            action_taken="FLAG_FOR_AUTOBLOCK",
            evidence={
                "indicator": indicator,
                "details": hollowing,
                "total_map_count": map_count,
            },
        )

    @staticmethod
    def _create_high_map_threat(pid: int, name: str, map_count: int) -> MemoryThreat:
        """Build threat for high memory map count."""
        reasoning = (
            f"Excessive memory maps detected in '{name}' (PID {pid}): "
            f"{map_count} memory regions mapped. This exceeds the threshold of "
            f"{MEMORY_MAP_COUNT_THRESHOLD}. High memory map counts often indicate "
            f"DLL injection or reflective loading attacks."
        )

        return MemoryThreat(
            timestamp=datetime.now().isoformat(),
            threat_type="HIGH_MAP_COUNT",
            risk_level="MEDIUM",
            pid=pid,
            process_name=name,
            suspicious_count=map_count,
            reasoning=reasoning,
            action_taken="LOG_AND_WATCH",
            evidence={
                "map_count": map_count,
                "threshold": MEMORY_MAP_COUNT_THRESHOLD,
                "all_module_paths": [],
            },
        )


# ─── MEMORY MONITOR ──────────────────────────────────────────────────────────
class MemoryMonitor:
    """Monitors process memory for signs of in-memory attacks.

    Runs periodic scans of all running processes, analyzing their
    memory maps for RWX regions, injected DLLs, reflective loading,
    process hollowing, and other memory-based attack indicators.
    """

    def __init__(self, on_threat: Optional[Callable[[MemoryThreat], None]] = None):
        self.on_threat: Callable[[MemoryThreat], None] = on_threat or self._default_handler
        self._analyzer = MemoryAnalyzer()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = Event()

    def _scan(self) -> None:
        """Run one full memory scan cycle on all processes."""
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                threat = self._analyzer.analyze_process(proc)
                if threat:
                    _logger.warning(json.dumps(asdict(threat)))
                    self.on_threat(threat)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as e:
                _logger.debug(f"Memory scan error for PID {proc.pid}: {e}")

    def _run_loop(self) -> None:
        """Main monitoring loop."""
        while not self._stop_event.is_set():
            try:
                self._scan()
            except Exception as e:
                _logger.error(f"Memory scan crashed: {e}\n{traceback.format_exc()}")

            if self._stop_event.wait(MEMORY_POLL_INTERVAL):
                break

    def start(self) -> None:
        """Start the memory monitor in a background thread."""
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop, daemon=True, name="AEGIS-MemIntel"
        )
        self._thread.start()
        _logger.info("Memory Monitor started.")

        # Brief scan indicator
        has_rwx = False
        try:
            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    maps = proc.memory_maps(grouped=False)
                    for m in maps:
                        perms = (m.perms or "").lower().strip()
                        if perms in SUSPICIOUS_PERMISSIONS:
                            has_rwx = True
                            break
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue
                if has_rwx:
                    break
        except Exception:
            _logger.debug("Initial RWX scan failed")

        status = "⚠ RWX memory detected on this system!" if has_rwx else "memory appears normal"
        print(f"  [AEGIS] Memory Monitor online — {status}\n")

    def stop(self) -> None:
        """Stop the memory monitor."""
        self._running = False
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            try:
                self._thread.join(timeout=2.0)
            except Exception:
                _logger.debug("Memory monitor thread join failed")
        _logger.info("Memory Monitor stopped.")
        print("  [MEMINTEL] Memory monitor stopped.")

    @staticmethod
    def _default_handler(threat: MemoryThreat) -> None:
        border = "═" * 56
        print(f"\n  ╔{border}╗")
        print("  ║  AEGIS MEMINTEL — MEMORY THREAT DETECTED              ║")
        print(f"  ╠{border}╣")
        print(f"  ║  Type      : {threat.threat_type:<40}║")
        print(f"  ║  Process   : {threat.process_name:<40}║")
        print(f"  ║  PID       : {threat.pid:<40}║")
        print(f"  ║  Findings  : {threat.suspicious_count:<40}║")
        print(f"  ║  Risk      : {threat.risk_level:<40}║")
        print(f"  ║  Action    : {threat.action_taken:<40}║")
        print(f"  ╚{border}╝")
        print(f"  → {threat.reasoning}\n")

        # Show evidence details
        if threat.evidence:
            rwx_regions = threat.evidence.get("rwx_regions", [])
            if rwx_regions:
                print("  📋 RWX Regions:\n")
                for reg in rwx_regions[:10]:
                    path = reg.get("path", "(anon)")
                    perms = reg.get("perms", "")
                    rss_kb = reg.get("rss_kb", 0)
                    print(f"      {path:<50} {perms:>5} {rss_kb:>8}KB")

            sus_modules = threat.evidence.get("suspicious_modules", [])
            if sus_modules:
                print("  📋 Suspicious Modules:\n")
                for mod in sus_modules[:10]:
                    path = mod.get("path", "")
                    perms = mod.get("perms", "")
                    reason = mod.get("reason", "")
                    print(f"      {path:<50} {perms:>5}")
                    print(f"      {'':>6}→ {reason}")

        print()


# ─── STANDALONE MODE ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n  AEGIS MEMORY INTELLIGENCE — STANDALONE v1.0\n")
    print("  Scanning all processes for memory-based threats...\n")

    monitor = MemoryMonitor()
    monitor.start()

    # Run an immediate scan
    time.sleep(2)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        monitor.stop()
