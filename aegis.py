"""
Project AEGIS — Master Orchestrator
Lead Architect: ETCHERO / Abdul-Hameed
Version: 1.0.0 | Classification: AEGIS-CORE-BRAIN
Role: Boots all modules. Runs the central logic loop.
      Responds to ThreatSnapshots with tiered autonomous actions.
      Cross-platform: full power on Linux, simulation on Windows.
"""

import platform
import time
import threading
import logging
import sys
from pathlib import Path
from datetime import datetime

# ─── PATHS ───────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent
LOG_DIR  = BASE_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
AEGIS_LOG = LOG_DIR / "aegis_master.log"

logging.basicConfig(
    filename=str(AEGIS_LOG),
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

# ─── LOCAL IMPORTS ────────────────────────────────────────────────────────────
sys.path.insert(0, str(BASE_DIR))
from core.heartbeat   import Heartbeat
from modules.firewall import block_ip, is_blocked, dump_block_list, SIMULATION, CURRENT_OS

# ─── OS / MODE ────────────────────────────────────────────────────────────────
IS_WINDOWS    = CURRENT_OS == "Windows"
MODE_LABEL    = "SIMULATION" if SIMULATION else "LIVE"
HIGH_RISK_TIMEOUT = 5


# ─── AEGIS CORE ───────────────────────────────────────────────────────────────
class AegisCore:
    def __init__(self):
        self._lock         = threading.Lock()
        self._threat_queue = []
        self._running      = False
        self._heartbeat    = None
        self._heartbeat_thread = None
        self._heartbeat_stop   = threading.Event()
        self._sentinel     = None
        self._print_banner()

    def _print_banner(self):
        os_line = f"OS: {CURRENT_OS} | MODE: {MODE_LABEL}"
        print(
            "\n"
            "╔══════════════════════════════════════════════════════╗\n"
            "║            PROJECT AEGIS — MASTER v1.0              ║\n"
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

    def _boot_heartbeat(self):
        self._heartbeat = Heartbeat(stop_event=self._heartbeat_stop)
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat.run, daemon=True, name="AEGIS-Heartbeat"
        )
        self._heartbeat_thread.start()
        logging.info("Heartbeat thread started.")
        print("  [AEGIS] Heartbeat thread online.\n")

    def _boot_sentinel(self):
        try:
            from modules.net_sentinel import NetSentinel
            self._sentinel = NetSentinel(on_threat=self._on_threat_received)
            self._sentinel.start()
            logging.info("NetSentinel thread started.")
            print("  [AEGIS] Net Sentinel eyes online.\n")

        except ImportError:
            msg = "Scapy not installed. Sniffer unavailable on this host."
            print(f"  [AEGIS] WARNING: {msg}")
            logging.warning(msg)

        except OSError as e:
            if "Npcap" in str(e) or "WinPcap" in str(e):
                msg = (
                    "Npcap not found. Install from https://npcap.com to enable "
                    "packet sniffing on Windows. Sniffer unavailable on this host."
                )
            else:
                msg = f"Sniffer unavailable on this host. Reason: {e}"
            print(f"  [AEGIS] WARNING: {msg}")
            logging.warning(msg)

        except Exception as e:
            msg = f"Sniffer unavailable on this host. Unexpected error: {e}"
            print(f"  [AEGIS] WARNING: {msg}")
            logging.warning(msg)

    def _on_threat_received(self, snapshot):
        with self._lock:
            self._threat_queue.append(snapshot)

    def _handle_threat(self, snap):
        ip  = snap.attacker_ip
        lvl = snap.risk_level
        logging.warning(
            f"THREAT | {lvl} | {ip} | {snap.port_count} ports | {snap.threat_type}"
        )

        if lvl == "CRITICAL":
            self._critical_response(snap)
        elif lvl == "HIGH":
            self._high_response(snap)
        elif lvl == "MEDIUM":
            self._medium_response(snap)
        else:
            self._low_response(snap)

    def _critical_response(self, snap):
        ip = snap.attacker_ip
        print(f"\n  {'═'*54}")
        print(f"  [CRITICAL] THREAT DETECTED — AUTO-BLOCKING {ip}")
        print(f"  Reasoning: {snap.reasoning}")
        print(f"  {'═'*54}")
        success = block_ip(ip)
        action  = "BLOCKED" if success else "BLOCK_FAILED"
        tag     = "[SIM]" if SIMULATION else "[LIVE]"
        print(f"  {tag} ACTION: {action} → {ip}\n")
        logging.warning(f"AUTO_BLOCK | {action} | {ip}")

    def _high_response(self, snap):
        ip = snap.attacker_ip
        print(f"\n  {'─'*54}")
        print(f"  [HIGH RISK] SEMI-AUTO ALERT — Attacker: {ip}")
        print(f"  Ports hit: {snap.port_count} | Type: {snap.threat_type}")
        print(f"  Reasoning: {snap.reasoning}")
        print(f"  Auto-blocking in {HIGH_RISK_TIMEOUT}s... Press ENTER to skip.")
        print(f"  {'─'*54}")

        user_cancelled = threading.Event()

        def wait_for_input():
            try:
                input()
                user_cancelled.set()
            except Exception:
                pass

        input_thread = threading.Thread(target=wait_for_input, daemon=True)
        input_thread.start()
        input_thread.join(timeout=HIGH_RISK_TIMEOUT)

        if user_cancelled.is_set():
            print(f"  [AEGIS] Operator cancelled block for {ip}. Watching.")
            logging.info(f"SEMI_AUTO_CANCELLED | {ip}")
        else:
            success = block_ip(ip)
            action  = "AUTO_BLOCKED_TIMEOUT" if success else "BLOCK_FAILED"
            tag     = "[SIM]" if SIMULATION else "[LIVE]"
            print(f"  {tag} ACTION: {action} → {ip}\n")
            logging.warning(f"SEMI_AUTO_BLOCK | {action} | {ip}")

    def _medium_response(self, snap):
        print(f"\n  [MEDIUM] Port scan from {snap.attacker_ip} — {snap.port_count} ports")
        print(f"  → Logging. Watching for escalation.")
        logging.info(f"MEDIUM_WATCH | {snap.attacker_ip} | {snap.port_count} ports")

    def _low_response(self, snap):
        print(f"  [LOW] Minor probe from {snap.attacker_ip}. Logged.")
        logging.info(f"LOW_PROBE | {snap.attacker_ip}")

    def _logic_loop(self):
        while self._running:
            with self._lock:
                pending = list(self._threat_queue)
                self._threat_queue.clear()

            for snap in pending:
                self._handle_threat(snap)

            time.sleep(0.5)

    def start(self):
        self._running = True
        print("  [AEGIS] Booting modules...\n")
        self._boot_heartbeat()
        self._boot_sentinel()
        print("  [AEGIS] All modules online. Logic loop active.")
        print("  [AEGIS] Press Ctrl+C to shut down.\n")
        logging.info(f"AEGIS started | OS={CURRENT_OS} | MODE={MODE_LABEL}")

        try:
            self._logic_loop()
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        self._running = False
        print("\n\n  [AEGIS] Shutdown signal received.")
        print("  [AEGIS] Standing down all modules...")
        if self._sentinel:
            self._sentinel.stop()
        if self._heartbeat:
            try:
                self._heartbeat.stop()
            except Exception:
                pass
        if self._heartbeat_thread:
            try:
                self._heartbeat_thread.join(timeout=2.0)
            except Exception:
                pass
        dump_block_list()
        logging.info("AEGIS shutdown cleanly.")
        print("  [AEGIS] Agent offline. Stay dangerous, ETCHERO.\n")


# ─── ENTRY POINT ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    agent = AegisCore()
    agent.start()
