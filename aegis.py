"""
Project AEGIS — Master Orchestrator
Lead Architect: ETCHERO / Abdul-Hameed
Version: 1.3.0 | Classification: AEGIS-CORE-BRAIN

Role: Boots all modules. Runs the central logic loop.
      Responds to ThreatSnapshots with tiered autonomous actions.
      Cross-platform: full power on Linux, simulation on Windows.

Phase 1 (v1.2.0):
  - Process Monitor: reverse shells, crypto miners, privilege escalation
  - File Integrity Monitor: hash-based file change detection
  - Login Monitor: brute force detection, auth log analysis

Priority 2 — Incident Manager (v1.3.0):
  - Correlates related alerts into single incidents by IP, process, time
  - Auto-blocks critical sources, displays incident timelines
  - Dramatically reduces alert fatigue
"""

import argparse
import json as _json
import logging
import platform
import sys
import threading
import time
import traceback
import urllib.request
from datetime import datetime

from pathlib import Path
from typing import Any, Optional

# ─── CONFIG ───────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))
from config import (  # noqa: E402,E501
    SafeRotatingFileHandler,
    SIMULATION,
    CURRENT_OS,
    MODE_LABEL,
    HIGH_RISK_TIMEOUT,
    LOGIC_LOOP_SLEEP,
    AEGIS_LOG_FILE,
    LOG_MAX_BYTES,
    LOG_BACKUP_COUNT,
    LOG_FORMAT,
    NOTIFY_ON_LEVELS,
    DISCORD_WEBHOOK_URL,
    SLACK_WEBHOOK_URL,
)

# ─── LOGGER SETUP ─────────────────────────────────────────────────────────────
_logger = logging.getLogger("aegis.master")
if not _logger.handlers:
    _handler = SafeRotatingFileHandler(
        str(AEGIS_LOG_FILE),
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT,
        encoding="utf-8",
    )
    _handler.setFormatter(logging.Formatter(LOG_FORMAT))
    _logger.addHandler(_handler)
_logger.setLevel(logging.INFO)
_logger.propagate = False

# ─── LOCAL IMPORTS ────────────────────────────────────────────────────────────
from core.heartbeat import Heartbeat  # noqa: E402
from modules.firewall import (  # noqa: E402
    block_ip,
    dump_block_list,
    is_blocked,
    set_lockdown,
    is_lockdown_active,
)

# Evidence Engine
from modules.evidence_engine import EvidenceEngine, EvidencePackage  # noqa: E402

# Incident Manager
from modules.incident_manager import IncidentManager, Incident  # noqa: E402

# AI Analyst
from modules.ai_analyst import AiAnalyst  # noqa: E402

# Dashboard Server (Priority 9)
from modules.dashboard_server import DashboardServer  # noqa: E402


# ─── CLI ──────────────────────────────────────────────────────────────────────
def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="aegis",
        description="Project AEGIS — Autonomous Security Operations Agent",  # noqa: E501
        epilog="Built by ETCHERO. Stay dangerous.",  # noqa: E501
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-i", "--interface",
        help="Network interface to sniff on (e.g., eth0, wlan0). Default: auto-detect.",
        default=None,
    )
    parser.add_argument(
        "--no-heartbeat",
        action="store_true",
        help="Disable the system health heartbeat monitor.",
    )
    parser.add_argument(
        "--no-sentinel",
        action="store_true",
        help="Disable the network sniffer/sentinel.",
    )
    parser.add_argument(
        "--no-procmon",
        action="store_true",
        help="Disable the process monitor.",
    )
    parser.add_argument(
        "--no-fim",
        action="store_true",
        help="Disable the file integrity monitor.",
    )
    parser.add_argument(
        "--no-logmon",
        action="store_true",
        help="Disable the login monitor.",
    )
    parser.add_argument(
        "--no-memmon",
        action="store_true",
        help="Disable the memory monitor.",
    )
    parser.add_argument(
        "--no-dnsmon",
        action="store_true",
        help="Disable the DNS monitor.",
    )
    parser.add_argument(
        "--no-incident",
        action="store_true",
        help="Disable incident correlation (show raw alerts instead).",
    )
    parser.add_argument(
        "--no-dashboard",
        action="store_true",
        help="Disable the WebSocket dashboard server.",
    )
    parser.add_argument(
        "--lockdown",
        action="store_true",
        help="Start in lockdown mode (block all inbound traffic immediately).",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Set the console log verbosity. Default: INFO.",
    )
    parser.add_argument(
        "--persist",
        action="store_true",
        default=True,
        help="Persist blocked IPs to disk (default: on).",
    )
    return parser.parse_args()


# ─── NOTIFICATIONS ────────────────────────────────────────────────────────────
def _send_notification(snap: Any, severity: str) -> None:
    """Send a notification via configured channels (Slack, Discord)."""
    if severity not in NOTIFY_ON_LEVELS:
        return

    # Build a message from whatever threat type we have
    threat_type = getattr(snap, "threat_type", "UNKNOWN")
    detail = ""
    if hasattr(snap, "attacker_ip") and snap.attacker_ip:
        detail = f"from {snap.attacker_ip}"
    elif hasattr(snap, "source_ip") and snap.source_ip:
        detail = f"from {snap.source_ip}"
    elif hasattr(snap, "process_name") and snap.process_name:
        detail = f"process: {snap.process_name} (PID {snap.pid})"
    elif hasattr(snap, "file_path") and snap.file_path:
        detail = f"file: {snap.file_path}"

    message = f"[AEGIS] {severity} | {threat_type} {detail}"

    if SLACK_WEBHOOK_URL:
        try:
            payload = _json.dumps({"text": message}).encode()
            req = urllib.request.Request(
                SLACK_WEBHOOK_URL,
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            urllib.request.urlopen(req, timeout=5)  # nosec B310
        except Exception as e:
            _logger.warning(f"Slack notification failed: {e}")

    if DISCORD_WEBHOOK_URL:
        try:
            payload = _json.dumps({"content": message}).encode()
            req = urllib.request.Request(
                DISCORD_WEBHOOK_URL,
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            urllib.request.urlopen(req, timeout=5)  # nosec B310
        except Exception as e:
            _logger.warning(f"Discord notification failed: {e}")


# ─── THREAT TYPE DISPATCH ─────────────────────────────────────────────────────
def _get_threat_source(snap: Any) -> str:
    """Determine which module generated this threat based on its attributes."""
    if hasattr(snap, "attacker_ip") and hasattr(snap, "port_count"):
        return "network"
    if hasattr(snap, "pid") and hasattr(snap, "suspicious_count"):
        return "memory"
    if hasattr(snap, "pid") and hasattr(snap, "process_name"):
        return "process"
    if hasattr(snap, "file_path") and hasattr(snap, "old_hash"):
        return "file"
    if hasattr(snap, "source_ip") and hasattr(snap, "attempt_count"):
        return "login"
    if hasattr(snap, "domain") and hasattr(snap, "query_count"):
        return "dns"
    if hasattr(snap, "pid") and hasattr(snap, "suspicious_count"):
        return "memory"
    return "unknown"


# ─── AEGIS CORE ───────────────────────────────────────────────────────────────
class AegisCore:
    """Master orchestrator that boots modules and manages the threat response loop."""

    def __init__(self, args: argparse.Namespace):
        self._args = args
        self._lock = threading.Lock()
        self._threat_queue: list = []
        self._running = False

        # Heartbeat
        self._heartbeat: Optional[Heartbeat] = None
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._heartbeat_stop = threading.Event()

        # Sentinel (network)
        self._sentinel: Optional[object] = None

        # Phase 1 — Endpoint Visibility
        self._procmon: Optional[object] = None
        self._fim: Optional[object] = None
        self._logmon: Optional[object] = None

        # Priority 5 — Memory Monitor
        self._memmon: Optional[object] = None

        # Priority 6 — DNS Monitor
        self._dnsmon: Optional[object] = None

        # Priority 9 — Dashboard Server
        self._dashboard: Optional[DashboardServer] = None

        # Priority 2 — Incident Manager
        self._incident_manager: Optional[IncidentManager] = None
        self._seen_incidents: set = set()  # Track which incidents we've displayed

        self._print_banner()

    def _print_banner(self) -> None:
        os_line = f"OS: {CURRENT_OS} | MODE: {MODE_LABEL}"
        print(
            "\n"
            "╔══════════════════════════════════════════════════════╗\n"
            "║            PROJECT AEGIS — MASTER v1.2              ║\n"
            "║      Autonomous Security Operations Agent            ║\n"
            f"║  {os_line:<52}║\n"
            "║      ETCHERO | Lead Architect                        ║\n"
            "╚══════════════════════════════════════════════════════╝\n"
        )
        if SIMULATION:
            print(
                "  ⚠  SIMULATION MODE ACTIVE\n"
                "  All firewall actions will be LOGGED but NOT executed.\n"
                "  Deploy on Linux / Parrot OS for live threat response.\n"
            )

    # ── Boot Methods ──────────────────────────────────────────────────────────

    def _boot_heartbeat(self) -> None:
        if self._args.no_heartbeat:
            print("  [AEGIS] Heartbeat disabled via --no-heartbeat.\n")
            return

        self._heartbeat = Heartbeat(stop_event=self._heartbeat_stop)
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat.run, daemon=True, name="AEGIS-Heartbeat"
        )
        self._heartbeat_thread.start()
        _logger.info("Heartbeat thread started.")
        print("  [AEGIS] Heartbeat thread online.\n")

    def _boot_sentinel(self) -> None:
        if self._args.no_sentinel:
            print("  [AEGIS] Sentinel disabled via --no-sentinel.\n")
            return

        try:
            from modules.net_sentinel import NetSentinel
            self._sentinel = NetSentinel(
                interface=self._args.interface,
                on_threat=self._on_threat_received,
            )
            self._sentinel.start()
            _logger.info("NetSentinel thread started.")
            print("  [AEGIS] Net Sentinel eyes online.\n")

        except ImportError as e:
            msg = f"Scapy not installed. Sniffer unavailable. ({e})"
            print(f"  [AEGIS] WARNING: {msg}")
            _logger.warning(msg)

        except OSError as e:
            estr = str(e)
            if "Npcap" in estr or "WinPcap" in estr:
                msg = (
                    "Npcap not found. Install from https://npcap.com to enable "
                    "packet sniffing on Windows. Sniffer unavailable on this host."
                )
            else:
                msg = f"Sniffer unavailable on this host. Reason: {e}"
            print(f"  [AEGIS] WARNING: {msg}")
            _logger.warning(msg)

        except Exception as e:
            msg = f"Sniffer unavailable. Unexpected error: {e}\n{traceback.format_exc()}"
            print("  [AEGIS] WARNING: Sniffer unavailable.")
            _logger.warning(msg)

    def _boot_procmon(self) -> None:
        """Boot the Process Monitor (Phase 1)."""
        if self._args.no_procmon:
            print("  [AEGIS] Process Monitor disabled via --no-procmon.\n")
            return

        try:
            from modules.process_monitor import ProcessMonitor
            self._procmon = ProcessMonitor(on_threat=self._on_threat_received)
            self._procmon.start()
            _logger.info("Process Monitor started.")
        except ImportError as e:
            print(f"  [AEGIS] WARNING: Process Monitor unavailable — psutil issue? ({e})")
            _logger.warning(f"Process Monitor import failed: {e}")
        except Exception as e:
            print(f"  [AEGIS] WARNING: Process Monitor failed: {e}")
            _logger.warning(f"Process Monitor boot error: {e}")

    def _boot_fim(self) -> None:
        """Boot the File Integrity Monitor (Phase 1)."""
        if self._args.no_fim:
            print("  [AEGIS] File Integrity Monitor disabled via --no-fim.\n")
            return

        try:
            from modules.file_monitor import FileMonitor
            self._fim = FileMonitor(on_threat=self._on_threat_received)
            self._fim.start()
            _logger.info("File Integrity Monitor started.")
        except Exception as e:
            print(f"  [AEGIS] WARNING: File Integrity Monitor failed: {e}")
            _logger.warning(f"FIM boot error: {e}")

    def _boot_logmon(self) -> None:
        """Boot the Login Monitor (Phase 1)."""
        if self._args.no_logmon:
            print("  [AEGIS] Login Monitor disabled via --no-logmon.\n")
            return

        try:
            from modules.login_monitor import LoginMonitor
            self._logmon = LoginMonitor(on_threat=self._on_threat_received)
            self._logmon.start()
            _logger.info("Login Monitor started.")
        except Exception as e:
            print(f"  [AEGIS] WARNING: Login Monitor failed: {e}")
            _logger.warning(f"Login Monitor boot error: {e}")

    # ── DNS Monitor ───────────────────────────────────────────────────────────

    def _boot_dnsmon(self) -> None:
        """Boot the DNS Monitor (Priority 6)."""
        if self._args.no_dnsmon:
            print("  [AEGIS] DNS Monitor disabled via --no-dnsmon.\n")
            return

        try:
            from modules.dns_monitor import DnsMonitor
            self._dnsmon = DnsMonitor(on_threat=self._on_threat_received)
            self._dnsmon.start()
            _logger.info("DNS Monitor started.")
        except Exception as e:
            print(f"  [AEGIS] WARNING: DNS Monitor failed: {e}")
            _logger.warning(f"DNS Monitor boot error: {e}")

    # ── Memory Monitor ─────────────────────────────────────────────────────────

    def _boot_memmon(self) -> None:
        """Boot the Memory Monitor (Priority 5)."""
        if self._args.no_memmon:
            print("  [AEGIS] Memory Monitor disabled via --no-memmon.\n")
            return

        try:
            from modules.memory_monitor import MemoryMonitor
            self._memmon = MemoryMonitor(on_threat=self._on_threat_received)
            self._memmon.start()
            _logger.info("Memory Monitor started.")
        except Exception as e:
            print(f"  [AEGIS] WARNING: Memory Monitor failed: {e}")
            _logger.warning(f"Memory Monitor boot error: {e}")

    # ── Dashboard Server ───────────────────────────────────────────────────────

    def _boot_dashboard(self) -> None:
        """Boot the WebSocket dashboard server (Priority 9)."""
        if self._args.no_dashboard:
            print("  [AEGIS] Dashboard server disabled via --no-dashboard.\n")
            return

        try:
            self._dashboard = DashboardServer()
            self._dashboard.start()
            _logger.info("Dashboard server started.")
            print("  [AEGIS] Dashboard server online → ws://localhost:8765")
            print("  [AEGIS] Start the Next.js dashboard: cd dashboard && npm run dev\n")
        except Exception as e:
            print(f"  [AEGIS] WARNING: Dashboard server failed: {e}")
            _logger.warning(f"Dashboard server boot error: {e}")

    # ── Incident Manager ──────────────────────────────────────────────────────

    def _boot_incident_manager(self) -> None:
        """Boot the Incident Manager (Priority 2)."""
        if self._args.no_incident:
            print("  [AEGIS] Incident correlation disabled via --no-incident.\n")
            return

        try:
            self._incident_manager = IncidentManager()
            self._incident_manager.start()
            _logger.info("Incident Manager started.")
            print("  [AEGIS] Incident Manager online — correlating events into incidents.\n")
        except Exception as e:
            print(f"  [AEGIS] WARNING: Incident Manager failed: {e}")
            _logger.warning(f"Incident Manager boot error: {e}")

    # ── Threat Handling ───────────────────────────────────────────────────────

    def _on_threat_received(self, snapshot: Any) -> None:
        with self._lock:
            self._threat_queue.append(snapshot)

    def _handle_threat(self, snap: Any) -> None:
        source = _get_threat_source(snap)
        lvl = snap.risk_level if hasattr(snap, "risk_level") else "LOW"

        _logger.warning(
            f"THREAT | {source} | {lvl} | {getattr(snap, 'threat_type', 'UNKNOWN')}"
        )

        # Persist forensic evidence to disk before handling
        evidence_file = self._persist_evidence(snap)

        # Send notifications for high-severity threats
        if lvl in NOTIFY_ON_LEVELS:
            try:
                _send_notification(snap, lvl)
            except Exception as e:
                _logger.warning(f"Notification failed: {e}")

        # Correlate through Incident Manager (if enabled)
        if self._incident_manager:
            incident = self._incident_manager.correlate(snap, evidence_file)
            if incident:
                self._handle_incident(incident, snap)
            # Dashboard push is handled inside _handle_incident for new incidents
            # to avoid duplicate AI analyst computation
        else:
            # Legacy mode: dispatch directly
            self._dispatch_threat(snap, source)

    def _handle_incident(self, inc: Incident, snap: Any) -> None:
        """Handle an incident — display if new, auto-respond if needed."""
        # Cap _seen_incidents to prevent unbounded memory growth
        if len(self._seen_incidents) > 1000:
            self._seen_incidents.clear()

        if not inc or not inc.incident_id:
            return

        is_new = inc.incident_id not in self._seen_incidents

        if is_new:
            # First event in this incident — display the full report
            self._seen_incidents.add(inc.incident_id)
            IncidentManager.display_incident(inc)
            # Generate and display AI Analyst assessment (compute once, share)
            assessment = None
            try:
                assessment = AiAnalyst.analyze_incident(inc)
                if assessment:
                    assessment.display()
            except Exception as e:
                _logger.debug(f"AI Analyst assessment failed: {e}")

            # Push update to dashboard (reuse the same assessment object)
            if self._dashboard:
                try:
                    self._dashboard.push_incident_update(inc, assessment)
                except Exception:
                    _logger.debug("Dashboard push failed")
        elif inc.event_count <= 3:
            # Early events in an incident — show a condensed update
            last_event = inc.events[-1] if inc.events else None
            if last_event:
                print(f"  ── INCIDENT {inc.incident_id} +{last_event.threat_type} ({inc.event_count} events) ──")
        else:
            # Just log silently
            _logger.info(f"INCIDENT {inc.incident_id} | event {inc.event_count} | {getattr(snap, 'threat_type', '?')}")

        # Auto-response actions based on incident risk level
        if inc.risk_level == "CRITICAL":
            self._auto_respond_critical(snap)

    def _auto_respond_critical(self, snap: Any) -> None:
        """Automatic response actions for critical incidents."""
        tag = "[SIM]" if SIMULATION else "[LIVE]"

        # Network threats: block IP
        if hasattr(snap, "attacker_ip") and snap.attacker_ip:
            if not is_blocked(snap.attacker_ip):
                block_ip(snap.attacker_ip)
                print(f"  {tag} AUTO-BLOCK: {snap.attacker_ip}")

        # Login threats: block source IP
        if hasattr(snap, "source_ip") and snap.source_ip and snap.source_ip != "local":
            if not is_blocked(snap.source_ip):
                block_ip(snap.source_ip)
                print(f"  {tag} AUTO-BLOCK: {snap.source_ip}")

        # Process threats (reverse shell): block remote IPs
        if hasattr(snap, "evidence") and isinstance(snap.evidence, dict):
            remote_ips = snap.evidence.get("remote_ips", [])
            for ip in remote_ips:
                if ip and not is_blocked(ip):
                    block_ip(ip)
                    print(f"  {tag} AUTO-BLOCK: {ip}")

    def _dispatch_threat(self, snap: Any, source: str) -> None:
        """Direct dispatch without incident correlation (legacy mode)."""
        if source == "network":
            self._handle_network_threat(snap)
        elif source == "process":
            self._handle_process_threat(snap)
        elif source == "file":
            self._handle_file_threat(snap)
        elif source == "login":
            self._handle_login_threat(snap)
        elif source == "dns":
            self._handle_dns_threat(snap)
        elif source == "memory":
            self._handle_memory_threat(snap)
        else:
            self._handle_unknown_threat(snap)

    # ── Evidence Persistence ──────────────────────────────────────────────────

    @staticmethod
    def _persist_evidence(snap: Any) -> Optional[str]:
        """Persist forensic evidence to disk from the threat's evidence package."""
        try:
            # Check if the threat has a pre-built evidence package (from process_monitor)
            evidence_package = None
            if hasattr(snap, "evidence") and isinstance(snap.evidence, dict):
                evidence_package = snap.evidence.get("evidence_package")

            if evidence_package is not None:
                filepath = EvidenceEngine.persist(evidence_package)
                if filepath:
                    _logger.info(f"Evidence saved: {filepath}")
                return filepath

            # For threats without pre-built packages, build a lightweight one
            threat_id = EvidenceEngine.generate_threat_id()
            package = EvidencePackage(
                captured_at=datetime.now().isoformat(),
                threat_type=getattr(snap, "threat_type", "UNKNOWN"),
                threat_id=threat_id,
                system_info={"hostname": platform.node()},
                raw={
                    "risk_level": getattr(snap, "risk_level", "N/A"),
                    "reasoning": getattr(snap, "reasoning", ""),
                    "action_taken": getattr(snap, "action_taken", ""),
                },
            )
            # Add source-specific context
            if hasattr(snap, "attacker_ip"):
                package.raw["source_ip"] = snap.attacker_ip
            if hasattr(snap, "source_ip"):
                package.raw["source_ip"] = snap.source_ip
            if hasattr(snap, "file_path"):
                package.file_path = snap.file_path
                import os as _os
                if _os.path.exists(snap.file_path):
                    package.file_hash = EvidenceEngine.hash_binary(snap.file_path)

            filepath = EvidenceEngine.persist(package)
            if filepath:
                _logger.info(f"Evidence saved: {filepath}")
            return filepath

        except Exception as e:
            _logger.warning(f"Evidence persistence failed: {e}")
            return None

    # ── Network Threat Responses ──────────────────────────────────────────────

    def _handle_network_threat(self, snap: Any) -> None:
        lvl = snap.risk_level
        if lvl == "CRITICAL":
            self._critical_response(snap)
        elif lvl == "HIGH":
            self._high_response(snap)
        elif lvl == "MEDIUM":
            self._medium_response(snap)
        else:
            self._low_response(snap)

    def _critical_response(self, snap: Any) -> None:
        ip = snap.attacker_ip
        print(f"\n  {'═'*54}")
        print(f"  [CRITICAL] THREAT DETECTED — AUTO-BLOCKING {ip}")
        print(f"  Reasoning: {snap.reasoning}")
        print(f"  {'═'*54}")
        success = block_ip(ip)
        action = "BLOCKED" if success else "BLOCK_FAILED"
        tag = "[SIM]" if SIMULATION else "[LIVE]"
        print(f"  {tag} ACTION: {action} → {ip}\n")
        _logger.warning(f"AUTO_BLOCK | {action} | {ip}")

    def _high_response(self, snap: Any) -> None:
        ip = snap.attacker_ip
        print(f"\n  {'─'*54}")
        print(f"  [HIGH RISK] SEMI-AUTO ALERT — Attacker: {ip}")
        print(f"  Ports hit: {snap.port_count} | Type: {snap.threat_type}")
        print(f"  Reasoning: {snap.reasoning}")
        print(f"  Auto-blocking in {HIGH_RISK_TIMEOUT}s... Press ENTER to skip.")
        print(f"  {'─'*54}")

        user_cancelled = threading.Event()

        def wait_for_input() -> None:
            try:
                input()
                user_cancelled.set()
            except Exception:
                _logger.debug("User input thread interrupted")

        input_thread = threading.Thread(target=wait_for_input, daemon=True)
        input_thread.start()
        input_thread.join(timeout=HIGH_RISK_TIMEOUT)

        if user_cancelled.is_set():
            print(f"  [AEGIS] Operator cancelled block for {ip}. Watching.")
            _logger.info(f"SEMI_AUTO_CANCELLED | {ip}")
        else:
            success = block_ip(ip)
            action = "AUTO_BLOCKED_TIMEOUT" if success else "BLOCK_FAILED"
            tag = "[SIM]" if SIMULATION else "[LIVE]"
            print(f"  {tag} ACTION: {action} → {ip}\n")
            _logger.warning(f"SEMI_AUTO_BLOCK | {action} | {ip}")

    @staticmethod
    def _medium_response(snap: Any) -> None:
        print(f"\n  [MEDIUM] Port scan from {snap.attacker_ip} — {snap.port_count} ports")
        print("  → Logging. Watching for escalation.")
        _logger.info(f"MEDIUM_WATCH | {snap.attacker_ip} | {snap.port_count} ports")

    @staticmethod
    def _low_response(snap: Any) -> None:
        print(f"  [LOW] Minor probe from {snap.attacker_ip}. Logged.")
        _logger.info(f"LOW_PROBE | {snap.attacker_ip}")

    # ── Process Threat Response ───────────────────────────────────────────────

    def _handle_process_threat(self, snap: Any) -> None:
        print(f"\n  {'─'*54}")
        print(f"  [{snap.risk_level}] PROCESS THREAT — {snap.threat_type}")
        print(f"  Reasoning: {snap.reasoning}")

        # Display forensic evidence with full process tree
        if hasattr(snap, "evidence") and isinstance(snap.evidence, dict):
            forensics = snap.evidence.get("forensic", {})
            if forensics:
                # ── Ancestral Process Tree ────────────────────────────────────
                raw_tree = forensics.get("process_tree", [])
                if raw_tree:
                    from modules.evidence_engine import EvidenceEngine
                    nodes = EvidenceEngine.dicts_to_process_nodes(raw_tree)
                    print("\n  📋 Process Tree (ancestral chain):")
                    print("  ──────────────────────────────────────────────────────")
                    for line in EvidenceEngine.render_process_tree(nodes, target_pid=snap.pid).split("\n"):
                        print(f"  {line}")
                    print("  ──────────────────────────────────────────────────────")

                # Binary hash
                if forensics.get("binary_hash"):
                    print(f"  📦 SHA-256: {forensics['binary_hash'][:32]}...")

                # Command line (full, not truncated)
                if forensics.get("command_line"):
                    cmd = forensics["command_line"]
                    print(f"  💻 Cmdline: {cmd[:200]}{'...' if len(cmd) > 200 else ''}")

                # Network connections
                if forensics.get("connections"):
                    print(f"  🔗 Connections ({len(forensics['connections'])}):")
                    for conn in forensics["connections"][:5]:
                        print(f"      {conn['local']} → {conn['remote']} ({conn['status']})")

                # Open files
                if forensics.get("open_files"):
                    files = forensics["open_files"]
                    print(f"  📂 Open files: {len(files)} handles")
                    for f in files[:3]:
                        print(f"      {f}")

        print(f"  {'─'*54}")

        # For reverse shells with attacker IPs, attempt auto-block
        if snap.risk_level == "CRITICAL" and hasattr(snap, "evidence"):
            remote_ips = snap.evidence.get("remote_ips", [])
            for ip in remote_ips:
                if ip and not is_blocked(ip):
                    block_ip(ip)
                    tag = "[SIM]" if SIMULATION else "[LIVE]"
                    print(f"  {tag} AUTO-BLOCK remote IP: {ip}")
                    _logger.warning(f"PROCMON_AUTO_BLOCK | {ip}")

    # ── File Threat Response ──────────────────────────────────────────────────

    @staticmethod
    def _handle_file_threat(snap: Any) -> None:
        print(f"\n  {'─'*54}")
        print(f"  [{snap.risk_level}] FILE INTEGRITY — {snap.threat_type}")
        print(f"  File: {snap.file_path}")
        print(f"  Reasoning: {snap.reasoning}")
        print(f"  {'─'*54}")

    # ── Login Threat Response ─────────────────────────────────────────────────

    def _handle_login_threat(self, snap: Any) -> None:
        print(f"\n  {'─'*54}")
        print(f"  [{snap.risk_level}] LOGIN THREAT — {snap.threat_type}")
        print(f"  Source: {snap.source_ip} | User: {snap.username}")
        print(f"  Attempts: {snap.attempt_count}")
        print(f"  Reasoning: {snap.reasoning}")
        print(f"  {'─'*54}")

        # Auto-block brute force sources
        if snap.risk_level == "CRITICAL" and snap.source_ip and snap.source_ip != "local":
            if not is_blocked(snap.source_ip):
                success = block_ip(snap.source_ip)
                tag = "[SIM]" if SIMULATION else "[LIVE]"
                print(f"  {tag} AUTO-BLOCK source IP: {snap.source_ip} ({'OK' if success else 'FAILED'})")
                action = "BLOCKED" if success else "BLOCK_FAILED"
                _logger.warning(f"LOGMON_AUTO_BLOCK | {action} | {snap.source_ip}")

    # ── Memory Threat Response ─────────────────────────────────────────────────

    @staticmethod
    def _handle_memory_threat(snap: Any) -> None:
        print(f"\n  {'─'*54}")
        print(f"  [{snap.risk_level}] MEMORY THREAT — {snap.threat_type}")
        print(f"  Process: {snap.process_name} (PID {snap.pid})")
        print(f"  Findings: {snap.suspicious_count} suspicious indicators")
        print(f"  Reasoning: {snap.reasoning}")
        if hasattr(snap, "evidence") and isinstance(snap.evidence, dict):
            rwx_regions = snap.evidence.get("rwx_regions", [])
            if rwx_regions:
                print(f"  ⚡ RWX Regions: {len(rwx_regions)}")
            sus_modules = snap.evidence.get("suspicious_modules", [])
            if sus_modules:
                print(f"  📦 Suspicious Modules: {len(sus_modules)}")
            if "total_rwx_kb" in snap.evidence:
                print(f"  💾 Total RWX: {snap.evidence['total_rwx_kb']}KB")
        print(f"  {'─'*54}")

    # ── DNS Threat Response ───────────────────────────────────────────────────

    @staticmethod
    def _handle_dns_threat(snap: Any) -> None:
        print(f"\n  {'─'*54}")
        print(f"  [{snap.risk_level}] DNS THREAT — {snap.threat_type}")
        print(f"  Domain: {snap.domain} | Queries: {snap.query_count}")
        print(f"  Reasoning: {snap.reasoning}")
        if hasattr(snap, "evidence") and isinstance(snap.evidence, dict):
            if "entropy" in snap.evidence:
                print(f"  📊 Entropy: {snap.evidence['entropy']} bits/char")
            if "avg_response_size" in snap.evidence:
                print(f"  📦 Avg response: {snap.evidence['avg_response_size']:.0f}B")
            if "avg_interval" in snap.evidence:
                print(f"  ⏱ Interval: {snap.evidence['avg_interval']}s")
        print(f"  {'─'*54}")

    # ── Unknown Threat Response ───────────────────────────────────────────────

    @staticmethod
    def _handle_unknown_threat(snap: Any) -> None:
        print("\n  [?] Unknown threat type received.")
        print(f"  Attributes: {[a for a in dir(snap) if not a.startswith('_')]}")
        print("  This may indicate a misconfigured module.\n")
        _logger.warning(f"UNKNOWN_THREAT_TYPE | {type(snap).__name__}")

    # ── Logic Loop ────────────────────────────────────────────────────────────

    def _logic_loop(self) -> None:
        while self._running:
            with self._lock:
                pending = list(self._threat_queue)
                self._threat_queue.clear()

            for snap in pending:
                self._handle_threat(snap)

            time.sleep(LOGIC_LOOP_SLEEP)

    def start(self) -> None:
        """Start all AEGIS modules and begin the threat response loop."""
        self._running = True
        print("  [AEGIS] Booting modules...\n")
        self._boot_heartbeat()
        self._boot_sentinel()
        self._boot_procmon()
        self._boot_fim()
        self._boot_logmon()
        self._boot_memmon()
        self._boot_dnsmon()
        self._boot_dashboard()
        self._boot_incident_manager()

        # Lockdown mode
        if self._args.lockdown:
            set_lockdown(True)

        print("  [AEGIS] All modules online. Logic loop active.")
        print("  [AEGIS] Press Ctrl+C to shut down.\n")
        _logger.info(f"AEGIS started | OS={CURRENT_OS} | MODE={MODE_LABEL}")

        try:
            self._logic_loop()
        except KeyboardInterrupt:
            self.stop()
        except Exception as e:
            _logger.critical(f"Unhandled exception in logic loop: {e}\n{traceback.format_exc()}")
            print(f"\n  [AEGIS] FATAL ERROR: {e}")
            print("  [AEGIS] See logs for full traceback.")
            self.stop()
            sys.exit(1)

    def stop(self) -> None:
        """Gracefully shut down all modules."""
        self._running = False
        print("\n\n  [AEGIS] Shutdown signal received.")
        print("  [AEGIS] Standing down all modules...")

        if is_lockdown_active():
            set_lockdown(False)

        # Stop modules in reverse order
        for name, module in [
            ("Dashboard Server", self._dashboard),
            ("Incident Manager", self._incident_manager),
            ("DNS Monitor", self._dnsmon),
            ("Memory Monitor", self._memmon),
            ("Login Monitor", self._logmon),
            ("File Monitor", self._fim),
            ("Process Monitor", self._procmon),
            ("Sentinel", self._sentinel),
            ("Heartbeat", self._heartbeat),
        ]:
            if module:
                try:
                    stop_method = getattr(module, "stop", None)
                    if stop_method:
                        stop_method()
                except Exception as e:
                    _logger.warning(f"{name} stop error: {e}")

        # Join heartbeat thread
        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            try:
                self._heartbeat_thread.join(timeout=2.0)
            except Exception:
                _logger.debug("Heartbeat thread join timed out")

        dump_block_list()
        _logger.info("AEGIS shutdown cleanly.")
        print("  [AEGIS] Agent offline. Stay dangerous, ETCHERO.\n")


# Global reference for dashboard server to access orchestrator state
_AEGIS_INSTANCE: Optional[AegisCore] = None


# ─── ENTRY POINT ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    args = _parse_args()
    logging.getLogger().setLevel(getattr(logging, args.log_level))
    agent = AegisCore(args)
    _AEGIS_INSTANCE = agent
    agent.start()
