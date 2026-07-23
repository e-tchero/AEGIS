"""
Project AEGIS — Incident Manager
Lead Architect: ETCHERO / Abdul-Hameed
Version: 1.0.0 | Classification: AEGIS-INCIDENT
Role: Correlates related alerts into single incidents.
      Groups by source IP, process lineage, and time windows.
      Transforms noise into a coherent attack narrative.

      Instead of 5 separate alerts:
        Port Scan → SSH Brute Force → Privilege Escalation → Persistence → Reverse Shell

      Produces 1 incident:
        INCIDENT #AEGIS-2026-0715-003
        09:14 — Port Scan
        09:15 — SSH Brute Force
        09:16 — Privilege Escalation
        09:17 — Persistence
        09:18 — Reverse Shell
"""

import logging
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from threading import Lock
from typing import Any, Callable, Dict, List, Optional, Set

# ─── CONFIG ───────────────────────────────────────────────────────────────────
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config import (  # noqa: E402
    INCIDENT_LOG_FILE,
    CORRELATION_TIMEOUT_SECONDS,
    AUTO_CLOSE_MINUTES,
    MAX_INCIDENT_EVENTS,
    LOG_MAX_BYTES,
    LOG_BACKUP_COUNT,
    LOG_FORMAT,
)

# ─── LOGGER ───────────────────────────────────────────────────────────────────
_logger = logging.getLogger("aegis.incident")
if not _logger.handlers:
    _handler = RotatingFileHandler(
        str(INCIDENT_LOG_FILE),
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
class IncidentEvent:
    """A single event that's part of an incident."""
    timestamp: str
    threat_type: str
    risk_level: str
    source: str          # "network", "process", "file", "login"
    summary: str         # One-line human-readable summary
    evidence_file: Optional[str] = None
    detail: str = ""     # Extended description
    process_tree: str = ""  # Visual process tree (for process events)

    def __hash__(self) -> int:
        return hash((self.timestamp, self.threat_type, self.summary[:50]))


@dataclass
class Incident:
    """A correlated group of related alerts."""
    incident_id: str
    created_at: str
    updated_at: str
    status: str           # OPEN, CLOSED
    risk_level: str       # Highest of all contained events
    threat_types: List[str] = field(default_factory=list)
    source_ips: Set[str] = field(default_factory=set)
    process_names: Set[str] = field(default_factory=set)
    file_paths: Set[str] = field(default_factory=set)
    user_names: Set[str] = field(default_factory=set)
    events: List[IncidentEvent] = field(default_factory=list)
    event_count: int = 0
    last_event_time: float = 0.0

    @property
    def timeline(self) -> str:
        """Generate a compact timeline string."""
        if not self.events:
            return "No events"
        lines = []
        for ev in self.events[:15]:  # Show last 15 events max
            time_str = ev.timestamp[-8:] if len(ev.timestamp) >= 8 else ev.timestamp
            lines.append(f"  {time_str} — [{ev.source.upper()}] {ev.summary}")
        if len(self.events) > 15:
            lines.append(f"  ... and {len(self.events) - 15} more events")
        return "\n".join(lines)


# ─── INCIDENT MANAGER ─────────────────────────────────────────────────────────
class IncidentManager:
    """Correlates alerts into incidents based on IP, process, and time."""

    def __init__(self, on_new_incident: Optional[Callable[[Incident], None]] = None):
        self.on_new_incident: Callable[[Incident], None] = on_new_incident or self._default_handler

        # Active incidents: incident_id -> Incident
        self._incidents: Dict[str, Incident] = {}
        self._lock = Lock()

        # Correlation indexes
        # IP -> set of incident_ids
        self._ip_index: Dict[str, Set[str]] = defaultdict(set)
        # Process name -> set of incident_ids
        self._proc_index: Dict[str, Set[str]] = defaultdict(set)
        # PID -> set of incident_ids (finer-grained)
        self._pid_index: Dict[int, Set[str]] = defaultdict(set)

        # Running count for human-readable IDs
        self._incident_counter = 0

        # Background thread for auto-closing stale incidents
        self._running = False
        self._stop_event = threading.Event()
        self._housekeeping_thread: Optional[threading.Thread] = None

    # ── Correlation Key Extraction ───────────────────────────────────────────

    @staticmethod
    def _get_correlation_keys(snap: Any) -> Dict[str, Any]:
        """Extract correlation keys from any threat object.

        Returns a dict with keys: ips, pids, process_names, file_paths, usernames, source
        """
        keys: Dict[str, Any] = {
            "ips": set(),
            "pids": set(),
            "process_names": set(),
            "file_paths": set(),
            "usernames": set(),
            "source": "unknown",
        }

        # Network threats
        if hasattr(snap, "attacker_ip") and snap.attacker_ip:
            keys["ips"].add(snap.attacker_ip)
            keys["source"] = "network"

        # Login threats
        if hasattr(snap, "source_ip") and snap.source_ip:
            keys["ips"].add(snap.source_ip)
            keys["source"] = "login"
        if hasattr(snap, "username") and snap.username:
            keys["usernames"].add(snap.username)

        # Process threats
        if hasattr(snap, "pid") and snap.pid:
            keys["pids"].add(snap.pid)
            keys["source"] = "process"
        if hasattr(snap, "process_name") and snap.process_name:
            keys["process_names"].add(snap.process_name)
        if hasattr(snap, "parent_pid") and snap.parent_pid:
            keys["pids"].add(snap.parent_pid)
        if hasattr(snap, "parent_name") and snap.parent_name:
            keys["process_names"].add(snap.parent_name)

        # File threats
        if hasattr(snap, "file_path") and snap.file_path:
            keys["file_paths"].add(snap.file_path)
            keys["source"] = "file"

        return keys

    # ── Correlation Logic ────────────────────────────────────────────────────

    def _find_existing_incident(self, keys: Dict[str, Any], now: float) -> Optional[str]:
        """Find an existing open incident that this threat should join.

        Priority order:
        1. Same IP address
        2. Same PID
        3. Same process name
        4. Time-based (any open incident within correlation window)
        """
        # 1. IP-based correlation (strongest signal)
        for ip in keys.get("ips", set()):
            if ip in self._ip_index:
                for inc_id in list(self._ip_index[ip]):
                    inc = self._incidents.get(inc_id)
                    if inc and inc.status == "OPEN":
                        # Check time window
                        if now - inc.last_event_time <= CORRELATION_TIMEOUT_SECONDS:
                            return inc_id
                        # Outside time window — keep open but don't auto-join

        # 2. PID-based correlation
        for pid in keys.get("pids", set()):
            if pid in self._pid_index:
                for inc_id in list(self._pid_index[pid]):
                    inc = self._incidents.get(inc_id)
                    if inc and inc.status == "OPEN":
                        if now - inc.last_event_time <= CORRELATION_TIMEOUT_SECONDS:
                            return inc_id

        # 3. Process name correlation
        for pname in keys.get("process_names", set()):
            if pname in self._proc_index:
                for inc_id in list(self._proc_index[pname]):
                    inc = self._incidents.get(inc_id)
                    if inc and inc.status == "OPEN":
                        if now - inc.last_event_time <= CORRELATION_TIMEOUT_SECONDS:
                            return inc_id

        # 4. Time-based correlation (fallback)
        for inc_id, inc in list(self._incidents.items()):
            if inc.status == "OPEN":
                if now - inc.last_event_time <= CORRELATION_TIMEOUT_SECONDS:
                    return inc_id

        return None

    # ── Incident Creation ────────────────────────────────────────────────────

    def _generate_incident_id(self) -> str:
        """Generate a human-readable incident ID."""
        self._incident_counter += 1
        date_str = datetime.now().strftime("%Y%m%d")
        return f"AEGIS-{date_str}-{self._incident_counter:04d}"

    def _create_incident(self, snap: Any, keys: Dict[str, Any], now: float) -> Incident:
        """Create a new incident for a threat."""
        inc_id = self._generate_incident_id()
        ts = datetime.now().isoformat()

        risk = getattr(snap, "risk_level", "LOW")
        threat_type = getattr(snap, "threat_type", "UNKNOWN")

        incident = Incident(
            incident_id=inc_id,
            created_at=ts,
            updated_at=ts,
            status="OPEN",
            risk_level=risk,
            threat_types=[threat_type],
            source_ips=keys.get("ips", set()),
            process_names=keys.get("process_names", set()),
            file_paths=keys.get("file_paths", set()),
            user_names=keys.get("usernames", set()),
            last_event_time=now,
        )

        # Add indexes
        for ip in incident.source_ips:
            self._ip_index[ip].add(inc_id)
        for pname in incident.process_names:
            self._proc_index[pname].add(inc_id)
        for pid in keys.get("pids", set()):
            self._pid_index[pid].add(inc_id)

        self._incidents[inc_id] = incident

        _logger.info(f"INCIDENT CREATED | {inc_id} | {risk} | {threat_type}")
        return incident

    # ── Event Addition ───────────────────────────────────────────────────────

    def _build_summary(self, snap: Any) -> str:
        """Build a one-line summary from any threat type."""
        threat_type = getattr(snap, "threat_type", "UNKNOWN")

        if hasattr(snap, "attacker_ip") and snap.attacker_ip:
            return f"{threat_type} from {snap.attacker_ip}"
        if hasattr(snap, "source_ip") and snap.source_ip:
            return f"{threat_type} from {snap.source_ip} (user: {getattr(snap, 'username', '?')})"
        if hasattr(snap, "process_name") and snap.process_name:
            cmd = (getattr(snap, "cmdline", "") or "")[:60]
            return f"{threat_type} — {snap.process_name} (PID {snap.pid}) {cmd}"
        if hasattr(snap, "file_path") and snap.file_path:
            return f"{threat_type} — {snap.file_path}"
        return threat_type

    def _add_event_to_incident(self, inc: Incident, snap: Any, keys: Dict[str, Any],
                               evidence_file: Optional[str], now: float) -> None:
        """Add an event to an existing incident."""
        ts = datetime.now().isoformat()
        threat_type = getattr(snap, "threat_type", "UNKNOWN")
        risk = getattr(snap, "risk_level", "LOW")
        source = keys.get("source", "unknown")
        summary = self._build_summary(snap)
        reasoning = getattr(snap, "reasoning", "")

        # Extract and render process tree from forensic evidence (Priority 3)
        process_tree_str = ""
        if source == "process":
            try:
                evidence_dict = getattr(snap, "evidence", {})
                if isinstance(evidence_dict, dict):
                    forensics = evidence_dict.get("forensic", {})
                    raw_tree = forensics.get("process_tree", [])
                    if raw_tree:
                        # Late import to avoid cycles
                        from modules.evidence_engine import EvidenceEngine
                        nodes = EvidenceEngine.dicts_to_process_nodes(raw_tree)
                        pid = getattr(snap, "pid", 0)
                        process_tree_str = EvidenceEngine.render_process_tree(nodes, target_pid=pid)
            except Exception:
                _logger.debug("Process tree rendering failed")

        event = IncidentEvent(
            timestamp=ts,
            threat_type=threat_type,
            risk_level=risk,
            source=source,
            summary=summary,
            evidence_file=evidence_file,
            detail=reasoning,
            process_tree=process_tree_str,
        )

        inc.events.append(event)
        inc.event_count += 1
        inc.updated_at = ts
        inc.last_event_time = now

        # Update risk level (highest wins)
        risk_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        if risk_order.get(risk, 0) > risk_order.get(inc.risk_level, 0):
            inc.risk_level = risk

        # Update threat types
        if threat_type not in inc.threat_types:
            inc.threat_types.append(threat_type)

        # Update IPs
        for ip in keys.get("ips", set()):
            if ip not in inc.source_ips:
                inc.source_ips.add(ip)
                self._ip_index[ip].add(inc.incident_id)

        # Update process names
        for pname in keys.get("process_names", set()):
            if pname not in inc.process_names:
                inc.process_names.add(pname)
                self._proc_index[pname].add(inc.incident_id)

        # Update file paths
        for fp in keys.get("file_paths", set()):
            inc.file_paths.add(fp)

        # Update usernames
        for un in keys.get("usernames", set()):
            inc.user_names.add(un)

        # Enforce max events (trim oldest if needed)
        if inc.event_count > MAX_INCIDENT_EVENTS:
            overflow = inc.event_count - MAX_INCIDENT_EVENTS
            inc.events = inc.events[overflow:]
            inc.event_count = len(inc.events)

        _logger.info(f"INCIDENT UPDATED | {inc.incident_id} | +{threat_type} | events={inc.event_count}")

    # ── Main Correlation Entry Point ─────────────────────────────────────────

    def correlate(self, snap: Any, evidence_file: Optional[str] = None) -> Optional[Incident]:
        """Process a threat and correlate it into an incident.

        Returns the Incident it was added to (or a new one).
        """
        now = time.time()
        keys = self._get_correlation_keys(snap)

        with self._lock:
            # Try to find an existing incident
            existing_id = self._find_existing_incident(keys, now)

            if existing_id and existing_id in self._incidents:
                inc = self._incidents[existing_id]
                self._add_event_to_incident(inc, snap, keys, evidence_file, now)
                return inc

            # No match — create new incident
            inc = self._create_incident(snap, keys, now)
            self._add_event_to_incident(inc, snap, keys, evidence_file, now)
            return inc

    # ── Auto-Close ──────────────────────────────────────────────────────────

    def _auto_close_stale(self) -> None:
        """Close incidents that haven't received events within the auto-close window."""
        now = time.time()
        cutoff = now - (AUTO_CLOSE_MINUTES * 60)
        closed = []

        with self._lock:
            for inc_id, inc in list(self._incidents.items()):
                if inc.status == "OPEN" and inc.last_event_time < cutoff:
                    inc.status = "CLOSED"
                    inc.updated_at = datetime.now().isoformat()
                    closed.append(inc_id)

        for inc_id in closed:
            inc = self._incidents[inc_id]
            _logger.info(f"INCIDENT CLOSED | {inc_id} | auto-close | events={inc.event_count}")

    def _housekeeping_loop(self) -> None:
        """Background loop for auto-closing stale incidents."""
        while not self._stop_event.is_set():
            try:
                self._auto_close_stale()
            except Exception as e:
                _logger.warning(f"Incident housekeeping error: {e}")
            self._stop_event.wait(30)  # Check every 30 seconds

    def start(self) -> None:
        """Start the incident manager's housekeeping thread."""
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self._housekeeping_thread = threading.Thread(
            target=self._housekeeping_loop, daemon=True, name="AEGIS-Incident-HK"
        )
        self._housekeeping_thread.start()
        _logger.info("Incident manager started.")

    def stop(self) -> None:
        """Stop the incident manager."""
        self._running = False
        self._stop_event.set()
        if self._housekeeping_thread and self._housekeeping_thread.is_alive():
            self._housekeeping_thread.join(timeout=2.0)
        _logger.info("Incident manager stopped.")

    # ── Incident Queries ─────────────────────────────────────────────────────

    def get_open_incidents(self) -> List[Incident]:
        """Return all open incidents, most recent first."""
        with self._lock:
            incidents = [inc for inc in self._incidents.values() if inc.status == "OPEN"]
            incidents.sort(key=lambda i: i.last_event_time, reverse=True)
            return list(incidents)

    def get_closed_incidents(self, limit: int = 50) -> List[Incident]:
        """Return most recently closed incidents."""
        with self._lock:
            incidents = [inc for inc in self._incidents.values() if inc.status == "CLOSED"]
            incidents.sort(key=lambda i: i.last_event_time, reverse=True)
            return incidents[:limit]

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """Get a specific incident by ID."""
        with self._lock:
            return self._incidents.get(incident_id)

    def get_all_incidents(self) -> List[Incident]:
        """Return all incidents, most recent first."""
        with self._lock:
            incidents = sorted(
                self._incidents.values(),
                key=lambda i: i.last_event_time,
                reverse=True,
            )
            return list(incidents)

    def get_open_count(self) -> int:
        """Count of open incidents."""
        return sum(1 for inc in self._incidents.values() if inc.status == "OPEN")

    # ── Display ──────────────────────────────────────────────────────────────

    @staticmethod
    def display_incident(inc: Incident) -> None:
        """Print a formatted incident report to stdout."""
        # Risk color
        risk_colors = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
        color = risk_colors.get(inc.risk_level, "⚪")

        print(f"\n  {'═'*56}")
        print(f"  {color} INCIDENT {inc.incident_id}")
        print(f"  {'═'*56}")
        print(f"  Status    : {inc.status}")
        print(f"  Risk      : {inc.risk_level}")
        print(f"  Types     : {', '.join(inc.threat_types[:5])}")
        if inc.source_ips:
            print(f"  Sources   : {', '.join(list(inc.source_ips)[:3])}")
        if inc.process_names:
            print(f"  Processes : {', '.join(list(inc.process_names)[:3])}")
        print(f"  Events    : {inc.event_count}")
        print(f"  Created   : {inc.created_at[:19]}")
        print(f"  Updated   : {inc.updated_at[:19]}")

        # Show process trees from events (Priority 3 — ancestral chain)
        for ev in inc.events:
            if ev.process_tree:
                print(f"  {'─'*56}")
                print(f"  Process Tree ({ev.threat_type}):")
                for line in ev.process_tree.split("\n"):
                    print(f"  {line}")
                break  # Show just the first tree to keep reports compact

        print(f"  {'─'*56}")
        print("  Timeline:")
        print(f"{inc.timeline}")
        print(f"  {'═'*56}\n")

    @staticmethod
    def _default_handler(inc: Incident) -> None:
        IncidentManager.display_incident(inc)


# ─── STANDALONE ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n  AEGIS INCIDENT MANAGER — STANDALONE\n")

    manager = IncidentManager()
    manager.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        manager.stop()
