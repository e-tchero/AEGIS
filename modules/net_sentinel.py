"""
Project AEGIS — Net Sentinel Module
Lead Architect: ETCHERO / Abdul-Hameed
Version: 1.1.0 | Classification: AEGIS-EYES

Role: Passive network sniffer. Detects SYN scans, FIN scans, Xmas scans,
      NULL scans, UDP sweeps, and other probes targeting the system.

Improvements in v1.1:
  - Uses centralized config.py
  - Detects FIN, Xmas, NULL, and UDP scans (not just SYN)
  - Removed duplicate iptables_block_ip() — routes through firewall module
  - Rotating file logs
  - Full type hints
  - Better cooldown logic with configurable duration
"""

import json
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from threading import Lock
from typing import Callable, Dict, List, Optional, Set, Tuple

from scapy.all import AsyncSniffer, IP, TCP, UDP  # type: ignore[import-untyped,attr-defined]

# ─── CONFIG ───────────────────────────────────────────────────────────────────
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config import (  # noqa: E402
    SCAN_WINDOW_SECONDS,
    PORT_HIT_THRESHOLD,
    ALERT_COOLDOWN_SECONDS,
    SENTINEL_LOG_FILE,
    LOG_MAX_BYTES,
    LOG_BACKUP_COUNT,
    LOG_FORMAT,
)

# ─── LOGGER SETUP ─────────────────────────────────────────────────────────────
_logger = logging.getLogger("aegis.sentinel")
if not _logger.handlers:
    _handler = RotatingFileHandler(
        str(SENTINEL_LOG_FILE),
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT,
        encoding="utf-8",
    )
    _handler.setFormatter(logging.Formatter(LOG_FORMAT))
    _logger.addHandler(_handler)
_logger.setLevel(logging.INFO)
_logger.propagate = False


# ─── DATA MODEL ──────────────────────────────────────────────────────────────
@dataclass
class ThreatSnapshot:
    timestamp: str
    attacker_ip: str
    ports_hit: List[int]
    port_count: int
    risk_level: str
    threat_type: str
    reasoning: str
    action_taken: str
    iptables_ready: bool = True


# ─── SCAN DETECTION ───────────────────────────────────────────────────────────
def _check_tcp_flags(pkt, syn_only: bool = False) -> Optional[str]:
    """Classify a TCP packet into a scan type or return None.

    Args:
        pkt: A Scapy packet with TCP layer.
        syn_only: If True, only detect SYN scans (legacy mode).

    Returns:
        A scan type string (e.g. "SYN_SCAN", "FIN_SCAN") or None.
    """
    flags = pkt[TCP].flags
    flag_bits = int(flags)

    if syn_only:
        # Original behavior: detect bare SYN (no ACK)
        is_syn = bool(flag_bits & 0x02) and not bool(flag_bits & 0x10)
        return "SYN_SCAN" if is_syn else None

    # ── FIN scan: only FIN flag set ──
    if flag_bits == 0x01:
        return "FIN_SCAN"

    # ── Xmas scan: FIN + PSH + URG (0x29) ──
    if flag_bits == 0x29:
        return "XMAS_SCAN"

    # ── Null scan: no flags set ──
    if flag_bits == 0x00:
        return "NULL_SCAN"

    # ── SYN scan (no ACK) — the standard stealth scan ──
    is_syn = bool(flag_bits & 0x02) and not bool(flag_bits & 0x10)
    if is_syn:
        return "SYN_SCAN"

    # ── SYN-ACK from scanner? Some scanners use connect() scan — less common ──
    # We ignore SYN-ACKs (bit 0x12) since those are usually local responses.

    return None


# ─── REASONING ENGINE ─────────────────────────────────────────────────────────
class SentinelReasoning:
    """Evaluates port scan intensity and produces a risk level with reasoning."""

    THRESHOLDS: Dict[str, Tuple[int, str, str]] = {
        "CRITICAL": (50, "FLAG_FOR_AUTOBLOCK",
                     "Matches aggressive Nmap -sS full scan. Immediate block recommended."),
        "HIGH": (25, "ALERT_AND_MONITOR",
                 "Consistent with targeted service discovery — Nmap -F, masscan."),
        "MEDIUM": (PORT_HIT_THRESHOLD, "LOG_AND_WATCH",
                   "Matches slow-scan or script-kiddie probe."),
    }

    @classmethod
    def evaluate(cls, ip: str, ports: List[int], scan_type: str) -> Tuple[str, str, str]:
        count = len(ports)

        for level, (threshold, action, template) in sorted(
            cls.THRESHOLDS.items(), key=lambda x: -x[1][0]
        ):
            if count >= threshold:
                if level == "CRITICAL":
                    reasoning = (
                        f"{ip} hit {count} unique ports ({scan_type}) in {SCAN_WINDOW_SECONDS}s. "
                        f"{template}"
                    )
                elif level == "HIGH":
                    reasoning = (
                        f"{ip} hit {count} ports ({scan_type}) — {template} "
                        f"Likely recon before exploitation."
                    )
                else:
                    reasoning = (
                        f"{ip} triggered {count} {scan_type} packets to distinct ports "
                        f"in {SCAN_WINDOW_SECONDS}s. {template}"
                    )
                return level, reasoning, action

        return ("LOW",
                f"{ip} — {count} port hits ({scan_type}). Below threshold. Noise or single-service probe.",
                "PASSIVE_LOG")


# ─── SENTINEL CORE ────────────────────────────────────────────────────────────
class NetSentinel:
    """Passive network sniffer that detects port scans and raises threat alerts."""

    def __init__(
        self,
        interface: Optional[str] = None,
        on_threat: Optional[Callable[[ThreatSnapshot], None]] = None,
    ):
        self.interface = interface
        self.on_threat: Callable[[ThreatSnapshot], None] = on_threat or self._default_handler
        self.reasoner = SentinelReasoning()
        self._lock = Lock()

        # IP -> list of timestamps (all scan types)
        self._ip_tracker: Dict[str, List[float]] = defaultdict(list)
        # IP -> {port: last_seen_ts} (across all scan types)
        self._port_tracker: Dict[str, Dict[int, float]] = defaultdict(dict)
        # IP -> {port: set of scan types detected}
        self._scan_type_tracker: Dict[str, Dict[int, Set[str]]] = defaultdict(lambda: defaultdict(set))

        self._threats: List[ThreatSnapshot] = []
        self._running = False
        self._sniffer: Optional[AsyncSniffer] = None

    # ── Throttling ──────────────────────────────────────────────────────────

    def _is_on_cooldown(self, ip: str, now: float) -> bool:
        """Check if *any* threat for this IP is still in cooldown."""
        for snap in reversed(self._threats):
            if snap.attacker_ip == ip:
                try:
                    last_time = datetime.fromisoformat(snap.timestamp).timestamp()
                    if now - last_time < ALERT_COOLDOWN_SECONDS:
                        return True
                except (ValueError, TypeError):
                    pass
                break  # only the most recent threat for this IP matters
        return False

    # ── Housekeeping ────────────────────────────────────────────────────────

    def _purge_old(self, ip: str, now: float) -> None:
        """Remove entries older than the scan window for a given IP."""
        self._ip_tracker[ip] = [t for t in self._ip_tracker[ip] if now - t <= SCAN_WINDOW_SECONDS]
        self._port_tracker[ip] = {
            p: ts for p, ts in self._port_tracker[ip].items()
            if now - ts <= SCAN_WINDOW_SECONDS
        }
        # Clean up scan type tracker too
        stale_ports = [
            p for p, ts in self._port_tracker[ip].items()
            if now - ts > SCAN_WINDOW_SECONDS
        ]
        for p in stale_ports:
            self._scan_type_tracker[ip].pop(p, None)

    # ── Packet Processing ───────────────────────────────────────────────────

    def _process_packet(self, pkt) -> None:
        if not pkt.haslayer(IP):
            return

        src_ip = pkt[IP].src
        now = time.time()

        # ── TCP scan detection ──
        detected_type: Optional[str] = None
        dst_port: Optional[int] = None

        if pkt.haslayer(TCP):
            detected_type = _check_tcp_flags(pkt)
            dst_port = pkt[TCP].dport

        # ── UDP scan detection ──
        if pkt.haslayer(UDP) and not detected_type:
            detected_type = "UDP_SCAN"
            dst_port = pkt[UDP].dport

        if detected_type is None or dst_port is None:
            return

        with self._lock:
            self._ip_tracker[src_ip].append(now)
            self._port_tracker[src_ip][dst_port] = now
            self._scan_type_tracker[src_ip][dst_port].add(detected_type)
            self._purge_old(src_ip, now)

            port_count = len(self._port_tracker[src_ip])

            # Determine the primary scan type
            all_types: Set[str] = set()
            for port_scans in self._scan_type_tracker[src_ip].values():
                all_types.update(port_scans)
            primary_type = self._dominant_scan_type(all_types)

            if port_count >= PORT_HIT_THRESHOLD:
                if self._is_on_cooldown(src_ip, now):
                    return

                ports_list = sorted(self._port_tracker[src_ip].keys())
                risk, reasoning, action = self.reasoner.evaluate(src_ip, ports_list, primary_type)

                snapshot = ThreatSnapshot(
                    timestamp=datetime.now().isoformat(),
                    attacker_ip=src_ip,
                    ports_hit=ports_list[-50:],
                    port_count=port_count,
                    risk_level=risk,
                    threat_type=primary_type,
                    reasoning=reasoning,
                    action_taken=action,
                    iptables_ready=True,
                )

                self._threats.append(snapshot)
                _logger.warning(json.dumps(asdict(snapshot)))
                self.on_threat(snapshot)

                # Reset trackers for this IP after alert
                self._ip_tracker[src_ip] = []
                self._port_tracker[src_ip] = {}
                self._scan_type_tracker[src_ip] = defaultdict(set)

    @staticmethod
    def _dominant_scan_type(types: Set[str]) -> str:
        """Pick the most relevant scan type for display."""
        priority = ["SYN_SCAN", "FIN_SCAN", "XMAS_SCAN", "NULL_SCAN", "UDP_SCAN"]
        for t in priority:
            if t in types:
                return t
        return "MIXED"

    # ── Lifecycle ───────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start the sniffer thread."""
        if self._running:
            return
        self._running = True
        self._sniffer = AsyncSniffer(
            iface=self.interface,
            filter="tcp or udp",
            prn=self._process_packet,
            store=False,
        )
        self._sniffer.start()
        print(f"  [SENTINEL] Sniffing started. Interface: {self.interface or 'auto'}.")
        _logger.info(f"Sniffing started on interface {self.interface or 'auto'}")

    def stop(self) -> None:
        """Stop the sniffer and clean up."""
        self._running = False
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                _logger.debug("Sniffer stop failed")
            self._sniffer = None
        print("  [SENTINEL] Sniffing stopped.")
        _logger.info("Sniffing stopped")

    # ── Data Access ─────────────────────────────────────────────────────────

    def get_threats(self) -> List[ThreatSnapshot]:
        """Return a list of all threats detected this session."""
        return list(self._threats)

    def get_latest_threat(self) -> Optional[ThreatSnapshot]:
        """Return the most recent threat, or None."""
        return self._threats[-1] if self._threats else None

    # ── Default Handler ─────────────────────────────────────────────────────

    @staticmethod
    def _default_handler(snap: ThreatSnapshot) -> None:
        border = "═" * 56
        print(f"\n  ╔{border}╗")
        print("  ║  AEGIS SENTINEL — THREAT DETECTED                    ║")
        print(f"  ╠{border}╣")
        print(f"  ║  IP         : {snap.attacker_ip:<40}║")
        print(f"  ║  Risk       : {snap.risk_level:<40}║")
        print(f"  ║  Scan Type  : {snap.threat_type:<40}║")
        print(f"  ║  Ports Hit  : {snap.port_count:<40}║")
        print(f"  ║  Action     : {snap.action_taken:<40}║")
        print(f"  ╚{border}╝\n")


# ─── STANDALONE MODE ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n  AEGIS NET SENTINEL — STANDALONE v1.1\n")

    # Route blocking through the firewall module
    from modules.firewall import block_ip  # noqa: E402

    def on_threat(snap: ThreatSnapshot) -> None:
        if snap.action_taken == "FLAG_FOR_AUTOBLOCK":
            block_ip(snap.attacker_ip)

    sentinel = NetSentinel(on_threat=on_threat)
    sentinel.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        sentinel.stop()
        print(f"\n  Threats this session: {len(sentinel.get_threats())}")
