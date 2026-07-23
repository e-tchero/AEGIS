"""
Project AEGIS — Process Monitor Module
Lead Architect: ETCHERO / Abdul-Hameed
Version: 1.0.0 | Classification: AEGIS-PROCMON
Role: Monitors running processes for suspicious behavior.
      Detects reverse shells, crypto miners, privilege escalation,
      persistence mechanisms, and anomalous process chains.
"""

import logging
import threading
import time
import traceback
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from threading import Event
from typing import Callable, Dict, List, Optional, Set

import psutil

# ─── CONFIG ───────────────────────────────────────────────────────────────────
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config import (  # noqa: E402
    PROCESS_POLL_INTERVAL,
    PROCESS_LOG_FILE,
    SUSPICIOUS_PROCESS_NAMES,
    KNOWN_GOOD_CHAINS,
    MINER_CPU_THRESHOLD,
    MINER_CPU_SAMPLES,
    SUSPICIOUS_DIRECTORIES,
    LOLBINS,
    SUSPICIOUS_CMDLINE_SUBSTRINGS,
    LOG_MAX_BYTES,
    LOG_BACKUP_COUNT,
    LOG_FORMAT,
)

# ─── LOGGER ───────────────────────────────────────────────────────────────────
_logger = logging.getLogger("aegis.procmon")
if not _logger.handlers:
    _handler = RotatingFileHandler(
        str(PROCESS_LOG_FILE),
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
class ProcessSnapshot:
    pid: int
    name: str
    cmdline: str
    parent_pid: int
    parent_name: str
    username: str
    create_time: float
    cpu_percent: float
    memory_percent: float
    num_connections: int
    connection_ports: List[int]
    exe: str
    cwd: str


@dataclass
class ProcessThreat:
    timestamp: str
    threat_type: str       # REVERSE_SHELL, CRYPTO_MINER, PRIVILEGE_ESC, PERSISTENCE, SUSPICIOUS_CHAIN
    risk_level: str        # CRITICAL, HIGH, MEDIUM, LOW
    pid: int
    process_name: str
    cmdline: str
    parent_name: str
    parent_pid: int
    username: str
    reasoning: str
    action_taken: str
    evidence: Dict = field(default_factory=dict)


# ─── REASONING ENGINE ─────────────────────────────────────────────────────────
class ProcessReasoningEngine:
    """Analyzes process snapshots and flags suspicious behavior."""

    def __init__(self):
        self._cpu_history: Dict[int, List[float]] = defaultdict(list)
        self._suspicious_name_lower = [n.lower() for n in SUSPICIOUS_PROCESS_NAMES]

    def _is_in_suspicious_dir(self, exe: str, cwd: str) -> bool:
        """Check if the executable or working directory is in a suspicious location."""
        for d in SUSPICIOUS_DIRECTORIES:
            if d in exe.lower() or d in cwd.lower():
                return True
        return False

    def _has_network_connections(self, proc_info: Dict) -> bool:
        """Check if a process has active network connections."""
        try:
            proc = psutil.Process(proc_info["pid"])
            conns = proc.connections(kind="inet")
            return len(conns) > 0
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False

    def _is_suspicious_chain(self, parent_name: str, child_name: str) -> bool:
        """Check if parent->child chain is suspicious.

        E.g., word.exe spawning powershell.exe is suspicious.
        """
        key = (parent_name.lower(), child_name.lower())
        if key in KNOWN_GOOD_CHAINS:
            return False
        # If the child is a known scripting shell and parent isn't cmd/explorer
        child_lower = child_name.lower()
        scripting_shells = [
            "powershell", "cmd.exe", "wscript", "cscript",
            "mshta", "bash", "sh", "python",
        ]
        is_scripting = any(s in child_lower for s in scripting_shells)
        parent_lower = parent_name.lower()
        parent_is_normal = any(s in parent_lower for s in ["explorer", "cmd.exe", "svchost", "services", "winlogon"])
        return is_scripting and not parent_is_normal

    def _check_reverse_shell(
        self, pid: int, info: Dict,
        snapshot: Dict[int, ProcessSnapshot],
    ) -> Optional[ProcessThreat]:
        """Detect potential reverse shells: scripting processes with remote connections."""
        name = info["name"].lower()
        is_scripting = any(s in name for s in ["powershell", "cmd.exe", "bash", "sh", "python", "nc", "ncat", "socat"])
        if not is_scripting:
            return None

        # Use snapshot data as a fast gate - skip if no connections
        num_connections = info.get("num_connections", 0)
        if num_connections == 0:
            return None

        # Fetch detailed connection info for scripting processes with connections
        try:
            proc = psutil.Process(pid)
            conns = proc.connections(kind="inet")
            # Filter for established outbound connections to non-local IPs
            outbound = [c for c in conns if c.status == "ESTABLISHED" and c.raddr and c.raddr.ip]
            if not outbound:
                return None

            # Check if it's running from a suspicious directory
            try:
                exe = proc.exe() or ""
                cwd = proc.cwd() or ""
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                exe = ""
                cwd = ""

            ports = [c.raddr.port for c in outbound if c.raddr]
            remote_ips = list(set(c.raddr.ip for c in outbound if c.raddr))

            reasoning = (
                f"Process '{info['name']}' (PID {pid}) has {len(outbound)} established "
                f"outbound connections to {', '.join(remote_ips[:5])}. "
                f"This pattern matches reverse shell behavior."
            )
            if self._is_in_suspicious_dir(exe, cwd):
                reasoning += f" Process running from suspicious directory: {exe or cwd}."

            return ProcessThreat(
                timestamp=datetime.now().isoformat(),
                threat_type="REVERSE_SHELL",
                risk_level="CRITICAL",
                pid=pid,
                process_name=info["name"],
                cmdline=info.get("cmdline", ""),
                parent_name=info.get("parent_name", ""),
                parent_pid=info.get("parent_pid", 0),
                username=info.get("username", ""),
                reasoning=reasoning,
                action_taken="FLAG_FOR_AUTOBLOCK",
                evidence={
                    "remote_ips": remote_ips,
                    "ports": ports,
                    "connection_count": len(outbound),
                    "exe": exe,
                    "cwd": cwd,
                },
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

    def _check_crypto_miner(self, pid: int, info: Dict) -> Optional[ProcessThreat]:
        """Detect crypto miners based on sustained high CPU usage."""
        cpu = info.get("cpu_percent", 0)
        if cpu < MINER_CPU_THRESHOLD:
            self._cpu_history[pid] = []
            return None

        self._cpu_history[pid].append(cpu)
        # Keep only recent samples
        self._cpu_history[pid] = self._cpu_history[pid][-MINER_CPU_SAMPLES:]

        if len(self._cpu_history[pid]) >= MINER_CPU_SAMPLES:
            avg_cpu = sum(self._cpu_history[pid]) / len(self._cpu_history[pid])
            if avg_cpu >= MINER_CPU_THRESHOLD:
                name = info["name"]
                reasoning = (
                    f"Process '{name}' (PID {pid}) sustained CPU at {avg_cpu:.1f}% "
                    f"over {MINER_CPU_SAMPLES} samples. This sustained high usage "
                    f"is consistent with cryptocurrency mining."
                )

                return ProcessThreat(
                    timestamp=datetime.now().isoformat(),
                    threat_type="CRYPTO_MINER",
                    risk_level="HIGH",
                    pid=pid,
                    process_name=name,
                    cmdline=info.get("cmdline", ""),
                    parent_name=info.get("parent_name", ""),
                    parent_pid=info.get("parent_pid", 0),
                    username=info.get("username", ""),
                    reasoning=reasoning,
                    action_taken="ALERT_AND_MONITOR",
                    evidence={"avg_cpu": round(avg_cpu, 1), "samples": len(self._cpu_history[pid])},
                )

        return None

    def _check_suspicious_chain(self, pid: int, info: Dict) -> Optional[ProcessThreat]:
        """Detect suspicious parent-child process relationships."""
        parent_name = info.get("parent_name", "")
        child_name = info["name"]
        if not self._is_suspicious_chain(parent_name, child_name):
            return None

        reasoning = (
            f"Suspicious process chain: '{parent_name}' (PPID {info.get('parent_pid', 0)}) "
            f"spawned '{child_name}' (PID {pid}). This is unusual and may indicate "
            f"a code execution attack (e.g., macro -> shell)."
        )

        return ProcessThreat(
            timestamp=datetime.now().isoformat(),
            threat_type="SUSPICIOUS_CHAIN",
            risk_level="MEDIUM",
            pid=pid,
            process_name=child_name,
            cmdline=info.get("cmdline", ""),
            parent_name=parent_name,
            parent_pid=info.get("parent_pid", 0),
            username=info.get("username", ""),
            reasoning=reasoning,
            action_taken="LOG_AND_WATCH",
            evidence={"parent_name": parent_name, "parent_pid": info.get("parent_pid", 0)},
        )

    def _check_privilege_escalation(self, pid: int, info: Dict) -> Optional[ProcessThreat]:
        """Detect potential privilege escalation."""
        cmdline = (info.get("cmdline") or "").lower()

        # Detect sudo/su usage on Linux
        if "sudo" in cmdline or "su " in cmdline or "runas" in cmdline:
            reasoning = (
                f"Privilege escalation detected: '{info['name']}' (PID {pid}) "
                f"executed with elevated privileges. Command: {cmdline[:100]}"
            )
            return ProcessThreat(
                timestamp=datetime.now().isoformat(),
                threat_type="PRIVILEGE_ESC",
                risk_level="HIGH",
                pid=pid,
                process_name=info["name"],
                cmdline=info.get("cmdline", ""),
                parent_name=info.get("parent_name", ""),
                parent_pid=info.get("parent_pid", 0),
                username=info.get("username", ""),
                reasoning=reasoning,
                action_taken="ALERT_AND_MONITOR",
                evidence={"cmdline": cmdline[:200]},
            )

        return None

    def _check_persistence(self, pid: int, info: Dict) -> Optional[ProcessThreat]:
        """Detect potential persistence mechanisms being installed."""
        cmdline = (info.get("cmdline") or "").lower()
        name = info["name"].lower()

        persistence_indicators = [
            "schtasks", "at.exe", "sc.exe", "reg.exe", "regedit",
            "systemctl enable", "crontab", "update-rc.d",
            "mkdir startup", "copy", "move", "symlink",
            "registry", "run", "runonce", "startup",
        ]

        matched = [i for i in persistence_indicators if i in cmdline or i in name]
        if matched:
            reasoning = (
                f"Persistence mechanism detected: '{info['name']}' (PID {pid}) "
                f"triggered indicators: {', '.join(matched[:3])}. "
                f"Command: {cmdline[:100]}"
            )
            return ProcessThreat(
                timestamp=datetime.now().isoformat(),
                threat_type="PERSISTENCE",
                risk_level="HIGH",
                pid=pid,
                process_name=info["name"],
                cmdline=info.get("cmdline", ""),
                parent_name=info.get("parent_name", ""),
                parent_pid=info.get("parent_pid", 0),
                username=info.get("username", ""),
                reasoning=reasoning,
                action_taken="ALERT_AND_MONITOR",
                evidence={"matched_indicators": matched, "cmdline": cmdline[:200]},
            )

        return None

    def _check_suspicious_cmdline(self, pid: int, info: Dict) -> Optional[ProcessThreat]:
        """Detect suspicious command-line patterns (Priority 4).

        Detects:
        - Base64-encoded PowerShell commands
        - Hidden execution flags (WindowStyle Hidden, ExecutionPolicy Bypass)
        - Remote download & execute patterns (curl|bash, iex (iwr ...))
        - LOLBin abuse (regsvr32, mshta, certutil used for execution)
        - Suspicious PowerShell parameter combinations
        """
        cmdline = (info.get("cmdline") or "").lower()
        name = info["name"].lower()

        if not cmdline:
            return None

        matched_groups: List[Dict[str, str]] = []  # type: ignore[valid-type]

        # Check each pattern group against the command line
        for group_name, group_config in SUSPICIOUS_CMDLINE_SUBSTRINGS.items():
            patterns = group_config.get("patterns", [])
            for pattern in patterns:
                if pattern in cmdline:
                    matched_groups.append({
                        "group": str(group_name),
                        "risk": str(group_config.get("risk", "MEDIUM")),
                        "description": str(group_config.get("description", "")),
                        "matched_pattern": str(pattern),
                    })
                    break  # Only one match per group

        # Check for LOLBins being used in a suspicious context
        for lolbin in LOLBINS:
            if lolbin in name or lolbin in cmdline:
                # Only flag if also has suspicious flags/args
                lolbin_flags = ["http://", "https://", "javascript:", "/s ", "/i ", "/q ", "/quiet",
                                "-urlcache", "-decode",    "//nologo", "/transfer"]  # noqa: E501
                matched_flags = [f for f in lolbin_flags if f in cmdline]
                if matched_flags:
                    matched_groups.append({
                        "group": "lolbin_abuse",
                        "risk": "HIGH",
                        "description": f"LOLBin '{lolbin}' used with suspicious flag: {', '.join(matched_flags)}",
                        "matched_pattern": str(lolbin),
                    })
                    break

        if not matched_groups:
            return None

        # Determine highest risk level
        risk_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        max_risk = max(matched_groups, key=lambda g: risk_order.get(g["risk"], 0))  # type: ignore[call-overload, arg-type]  # noqa: E501
        highest_risk = str(max_risk["risk"])

        # De-duplicate groups by name
        seen: Set[str] = set()
        unique_groups: List[Dict[str, str]] = []
        for g in matched_groups:
            if str(g["group"]) not in seen:
                seen.add(str(g["group"]))
                unique_groups.append(g)

        # Build reasoning
        group_names = [str(g["group"]).replace("_", " ").title() for g in unique_groups]
        matched_patterns = [str(g["matched_pattern"]) for g in unique_groups]

        reasoning = (
            f"Suspicious command line detected in '{info['name']}' (PID {pid}): "
            f"{', '.join(group_names)}. "
            f"Matched patterns: {', '.join(matched_patterns[:5])}. "
            f"Command: {cmdline[:200]}"
        )

        action_map = {
            "CRITICAL": "FLAG_FOR_AUTOBLOCK",
            "HIGH": "ALERT_AND_MONITOR",
            "MEDIUM": "LOG_AND_WATCH",
            "LOW": "LOG",
        }

        return ProcessThreat(
            timestamp=datetime.now().isoformat(),
            threat_type="SUSPICIOUS_CMDLINE",
            risk_level=highest_risk,
            pid=pid,
            process_name=info["name"],
            cmdline=info.get("cmdline", ""),
            parent_name=info.get("parent_name", ""),
            parent_pid=info.get("parent_pid", 0),
            username=info.get("username", ""),
            reasoning=reasoning,
            action_taken=action_map.get(highest_risk, "LOG"),
            evidence={
                "matched_groups": unique_groups,
                "matched_count": len(unique_groups),
                "highest_risk": highest_risk,
                "cmdline": cmdline[:500],
            },
        )

    def evaluate_process(self, pid: int, info: Dict, snapshot: Dict[int, ProcessSnapshot]) -> Optional[ProcessThreat]:
        """Run all detection checks on a single process."""
        # Priority order: most severe first
        checks = [
            self._check_reverse_shell,
            self._check_crypto_miner,
            self._check_suspicious_cmdline,  # Priority 4: command line detection
            self._check_privilege_escalation,
            self._check_persistence,
            self._check_suspicious_chain,
        ]

        for check in checks:
            try:
                result = check(pid, info, snapshot)  # type: ignore[call-arg,operator]
                if result:
                    return result
            except Exception as e:
                _logger.debug(f"Check {check.__name__} failed for PID {pid}: {e}")

        return None

    def cleanup_history(self, active_pids: Set[int]) -> None:
        """Remove CPU history for processes that no longer exist."""
        stale = [pid for pid in self._cpu_history if pid not in active_pids]
        for pid in stale:
            del self._cpu_history[pid]


# ─── EVIDENCE ENGINE IMPORT (late import to avoid cycles) ──────────────────────
def _capture_evidence(pid: int, threat: ProcessThreat) -> ProcessThreat:
    """Attach forensic evidence to a threat using the Evidence Engine."""
    try:
        from modules.evidence_engine import EvidenceEngine
        evidence_id = EvidenceEngine.generate_threat_id()
        package = EvidenceEngine.capture_process_evidence(
            pid=pid,
            threat_type=threat.threat_type,
            threat_id=evidence_id,
        )
        # Merge evidence package data into threat's evidence dict
        threat.evidence["forensic"] = {
            "threat_id": evidence_id,
            "process_tree": [{"pid": n.pid, "name": n.name, "cmdline": n.cmdline[:200]} for n in package.process_tree],
            "binary_hash": package.binary_hash,
            "command_line": package.command_line[:500],
            "environment_keys": list(package.environment.keys())[:30],
            "working_directory": package.working_directory,
            "open_files": package.open_files[:30],
            "connections": [
                {
                    "local": f"{c.local_addr}:{c.local_port}",
                    "remote": f"{c.remote_addr}:{c.remote_port}",
                    "status": c.status,
                } for c in package.connections
            ],
            "memory_regions": len(package.memory_maps),
        }
        threat.evidence["evidence_package"] = package  # Full package for persistence
    except Exception as e:
        _logger.debug(f"Evidence capture failed for PID {pid}: {e}")
    return threat


# ─── PROCESS MONITOR ──────────────────────────────────────────────────────────
class ProcessMonitor:
    """Monitors system processes for suspicious behavior."""

    def __init__(self, on_threat: Optional[Callable[[ProcessThreat], None]] = None):
        self.on_threat: Callable[[ProcessThreat], None] = on_threat or self._default_handler
        self.engine = ProcessReasoningEngine()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = Event()
        self._previous_snapshot: Dict[int, ProcessSnapshot] = {}

    def _take_snapshot(self) -> Dict[int, ProcessSnapshot]:
        """Capture a snapshot of all running processes."""
        snapshot = {}
        for proc in psutil.process_iter(["pid", "name", "cmdline", "ppid", "username", "create_time",
                                         "cpu_percent", "memory_percent", "exe", "cwd"]):
            try:
                info = proc.info
                pid = info["pid"]
                ppid = info["ppid"] or 0
                parent_name = ""
                if ppid and psutil.pid_exists(ppid):
                    try:
                        parent_name = psutil.Process(ppid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                connections = 0
                connection_ports = []
                try:
                    conns = proc.connections(kind="inet")
                    connections = len(conns)
                    connection_ports = list(set(c.raddr.port for c in conns if c.raddr))
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

                snapshot[pid] = ProcessSnapshot(
                    pid=pid,
                    name=info["name"] or "",
                    cmdline=" ".join(info["cmdline"] or [""]),
                    parent_pid=ppid,
                    parent_name=parent_name,
                    username=info["username"] or "",
                    create_time=info["create_time"] or 0,
                    cpu_percent=info["cpu_percent"] or 0,
                    memory_percent=info["memory_percent"] or 0,
                    num_connections=connections,
                    connection_ports=connection_ports,
                    exe=info["exe"] or "",
                    cwd=info["cwd"] or "",
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, TypeError):
                continue

        return snapshot

    def _scan(self) -> None:
        """Run one full scan cycle."""
        try:
            snapshot = self._take_snapshot()
            active_pids = set(snapshot.keys())

            for pid, proc_info in snapshot.items():
                try:
                    threat = self.engine.evaluate_process(
                        pid,
                        {
                            "name": proc_info.name,
                            "cmdline": proc_info.cmdline,
                            "parent_name": proc_info.parent_name,
                            "parent_pid": proc_info.parent_pid,
                            "username": proc_info.username,
                            "cpu_percent": proc_info.cpu_percent,
                            "num_connections": proc_info.num_connections,
                            "exe": proc_info.exe,
                            "cwd": proc_info.cwd,
                        },
                        snapshot,
                    )
                    if threat:
                        threat = _capture_evidence(pid, threat)
                        self.on_threat(threat)
                except Exception as e:
                    _logger.debug(f"Process scan error for PID {pid}: {e}")

            self.engine.cleanup_history(active_pids)
            self._previous_snapshot = snapshot

        except Exception as e:
            _logger.error(f"Process scan failed: {e}\n{traceback.format_exc()}")

    def _run_loop(self) -> None:
        """Main monitoring loop."""
        print(f"  [PROCMON] Process monitor active. Scanning every {PROCESS_POLL_INTERVAL}s.\n")
        while not self._stop_event.is_set():
            try:
                self._scan()
            except Exception as e:
                _logger.error(f"Process scan crashed: {e}\n{traceback.format_exc()}")
            if self._stop_event.wait(PROCESS_POLL_INTERVAL):
                break

    def start(self) -> None:
        """Start the process monitor in a background thread."""
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="AEGIS-ProcMon")
        self._thread.start()  # type: ignore[union-attr]
        _logger.info("Process monitor started.")
        print("  [AEGIS] Process Monitor online.\n")

    def stop(self) -> None:
        """Stop the process monitor."""
        self._running = False
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        _logger.info("Process monitor stopped.")
        print("  [PROCMON] Process monitor stopped.")

    @staticmethod
    def _default_handler(threat: ProcessThreat) -> None:
        border = "═" * 56
        print(f"\n  ╔{border}╗")
        print("  ║  AEGIS PROCMON — PROCESS THREAT DETECTED              ║")
        print(f"  ╠{border}╣")
        print(f"  ║  Type      : {threat.threat_type:<40}║")
        print(f"  ║  Process   : {threat.process_name:<40}║")
        print(f"  ║  PID       : {threat.pid:<40}║")
        print(f"  ║  Risk      : {threat.risk_level:<40}║")
        print(f"  ║  Action    : {threat.action_taken:<40}║")
        print(f"  ╚{border}╝")
        print(f"  → {threat.reasoning}")

        # Display process tree if forensic evidence was captured
        if threat.evidence:
            forensics = threat.evidence.get("forensic", {})
            if forensics:
                raw_tree = forensics.get("process_tree", [])
                if raw_tree:
                    try:
                        from modules.evidence_engine import EvidenceEngine
                        nodes = EvidenceEngine.dicts_to_process_nodes(raw_tree)
                        print("\n  Process Tree (ancestral chain):")
                        for line in EvidenceEngine.render_process_tree(nodes, target_pid=threat.pid).split("\n"):
                            print(f"  {line}")
                    except Exception:
                        _logger.debug("Process tree rendering failed")

        print()


if __name__ == "__main__":
    print("\n  AEGIS PROCESS MONITOR — STANDALONE\n")

    monitor = ProcessMonitor()
    monitor.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        monitor.stop()
