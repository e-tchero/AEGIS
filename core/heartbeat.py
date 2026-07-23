"""
Project AEGIS — Heartbeat Module
Lead Architect: ETCHERO / Abdul-Hameed
Version: 1.1.0 | Classification: AEGIS-CORE

Role: Monitors system health (CPU, RAM, Network, Connections)
      and produces a health score with AI-style reasoning.

Improvements in v1.1:
  - Uses centralized config.py
  - Rotating file logs (5 MB cap, 3 backups)
  - Graceful handling if psutil is missing
  - Full type hints
"""

import json
import logging
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from threading import Event
from typing import Optional, Tuple

# ─── CONFIG ───────────────────────────────────────────────────────────────────
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config import (  # noqa: E402
    PULSE_INTERVAL,
    CPU_DANGER_THRESHOLD,
    CPU_ELEVATED_THRESHOLD,
    RAM_DANGER_THRESHOLD,
    RAM_ELEVATED_THRESHOLD,
    NET_SPIKE_THRESHOLD,
    NET_FLOOD_THRESHOLD,
    HEALTH_LOG_FILE,
    LOG_MAX_BYTES,
    LOG_BACKUP_COUNT,
    LOG_FORMAT,
)

# ─── GRACEFUL PSUTIL IMPORT ───────────────────────────────────────────────────
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    psutil = None  # type: ignore[assignment]

# ─── LOGGER SETUP ─────────────────────────────────────────────────────────────
_logger = logging.getLogger("aegis.heartbeat")
if not _logger.handlers:
    _handler = RotatingFileHandler(
        str(HEALTH_LOG_FILE),
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
class SystemSnapshot:
    timestamp: str
    cpu_percent: float
    ram_percent: float
    ram_used_gb: float
    ram_total_gb: float
    net_sent_mbps: float
    net_recv_mbps: float
    active_connections: int
    health_score: float
    status: str
    reasoning: str


# ─── REASONING ENGINE ─────────────────────────────────────────────────────────
class ReasoningEngine:
    """Evaluates system metrics and produces a health score with explainable reasoning."""

    @staticmethod
    def evaluate(cpu: float, ram: float, net_sent: float, net_recv: float) -> Tuple[float, str, str]:
        flags: list[str] = []
        deductions: float = 0.0
        reasoning_parts: list[str] = []

        if cpu > CPU_DANGER_THRESHOLD:
            deductions += 30
            flags.append("CPU_CRITICAL")
            reasoning_parts.append(
                f"CPU at {cpu:.1f}% — exceeds {CPU_DANGER_THRESHOLD}% threshold. "
                f"Possible cause: runaway process, crypto-miner, or DoS stress."
            )
        elif cpu > CPU_ELEVATED_THRESHOLD:
            deductions += 10
            flags.append("CPU_ELEVATED")
            reasoning_parts.append(f"CPU at {cpu:.1f}% — elevated but not critical. Monitoring.")

        if ram > RAM_DANGER_THRESHOLD:
            deductions += 25
            flags.append("RAM_CRITICAL")
            reasoning_parts.append(
                f"RAM at {ram:.1f}% — near exhaustion. "
                f"Risk: OOM kill events or swap thrashing."
            )
        elif ram > RAM_ELEVATED_THRESHOLD:
            deductions += 8
            flags.append("RAM_ELEVATED")
            reasoning_parts.append(f"RAM at {ram:.1f}% — above comfortable range.")

        if net_sent > NET_SPIKE_THRESHOLD:
            deductions += 20
            flags.append("NET_EXFIL_RISK")
            reasoning_parts.append(
                f"Outbound traffic spike: {net_sent:.2f} MB/s. "
                f"Possible data exfiltration or botnet C2 communication."
            )
        if net_recv > NET_FLOOD_THRESHOLD:
            deductions += 15
            flags.append("NET_FLOOD_RISK")
            reasoning_parts.append(
                f"Inbound flood: {net_recv:.2f} MB/s. Possible DDoS reflection."
            )

        health_score = max(0.0, 100.0 - deductions)

        if health_score >= 85:
            status = "NOMINAL"
        elif health_score >= 60:
            status = "DEGRADED"
        elif health_score >= 35:
            status = "COMPROMISED"
        else:
            status = "CRITICAL"

        reasoning = (
            " | ".join(reasoning_parts)
            if reasoning_parts
            else "All subsystems within normal operating parameters. No anomalies detected."
        )

        return health_score, status, reasoning


# ─── HEARTBEAT CLASS ──────────────────────────────────────────────────────────
class Heartbeat:
    """Periodically samples system metrics and evaluates health."""

    def __init__(self, stop_event: Optional[Event] = None):
        if not PSUTIL_AVAILABLE:
            print("\n  [AEGIS] WARNING: psutil is not installed. Heartbeat cannot monitor system health.")
            print("  [AEGIS] Install it with: pip install psutil\n")
            self._disabled = True
            self._stop_event = stop_event or Event()
            return

        self._disabled = False
        self.engine = ReasoningEngine()
        self._prev_net = psutil.net_io_counters()  # type: ignore[union-attr]
        self._prev_time = time.time()
        self._stop_event = stop_event or Event()
        print(self._banner())

    def _banner(self) -> str:
        return (
            "\n"
            "╔══════════════════════════════════════════════╗\n"
            "║         PROJECT AEGIS — HEARTBEAT v1.1       ║\n"
            "║    Autonomous Security Operations Agent      ║\n"
            "║         ETCHERO | Lead Architect             ║\n"
            "╚══════════════════════════════════════════════╝\n"
        )

    def _get_net_speed(self) -> Tuple[float, float]:
        if self._disabled:
            return 0.0, 0.0
        current_net = psutil.net_io_counters()  # type: ignore[union-attr]
        current_time = time.time()
        elapsed = current_time - self._prev_time
        if elapsed <= 0:
            return 0.0, 0.0
        sent_mbps = (current_net.bytes_sent - self._prev_net.bytes_sent) / elapsed / 1_000_000
        recv_mbps = (current_net.bytes_recv - self._prev_net.bytes_recv) / elapsed / 1_000_000
        self._prev_net = current_net
        self._prev_time = current_time
        return round(sent_mbps, 4), round(recv_mbps, 4)

    def pulse(self) -> Optional[SystemSnapshot]:
        """Take a system snapshot, evaluate health, and return the result."""
        if self._disabled:
            return None

        cpu = psutil.cpu_percent(interval=1)  # type: ignore[union-attr]
        ram = psutil.virtual_memory()  # type: ignore[union-attr]
        net_sent, net_recv = self._get_net_speed()
        try:
            connections = len(psutil.net_connections(kind="inet"))  # type: ignore[union-attr]
        except Exception:  # safe: _disabled guard ensures psutil is loaded
            connections = -1

        health_score, status, reasoning = self.engine.evaluate(
            cpu, ram.percent, net_sent, net_recv  # type: ignore[union-attr]
        )

        snapshot = SystemSnapshot(
            timestamp=datetime.now().isoformat(),
            cpu_percent=cpu,
            ram_percent=ram.percent,  # type: ignore[union-attr]
            ram_used_gb=round(ram.used / 1e9, 2),  # type: ignore[union-attr]
            ram_total_gb=round(ram.total / 1e9, 2),  # type: ignore[union-attr]
            net_sent_mbps=net_sent,
            net_recv_mbps=net_recv,
            active_connections=connections,
            health_score=round(health_score, 1),
            status=status,
            reasoning=reasoning,
        )

        self._display(snapshot)
        _logger.info(json.dumps(asdict(snapshot)))
        return snapshot

    def _display(self, s: SystemSnapshot) -> None:
        bar_len = 20
        score_filled = int((s.health_score / 100) * bar_len)
        bar = "█" * score_filled + "░" * (bar_len - score_filled)
        print(f"\n{'─'*54}")
        print(f"  🕐  {s.timestamp}")
        print(f"  🏥  STATUS     : {s.status}")
        print(f"  📊  SCORE      : [{bar}] {s.health_score}/100")
        print(f"  🖥️  CPU        : {s.cpu_percent}%")
        print(f"  🧠  RAM        : {s.ram_percent}% ({s.ram_used_gb}GB / {s.ram_total_gb}GB)")
        print(f"  📡  NET ↑      : {s.net_sent_mbps} MB/s")
        print(f"  📡  NET ↓      : {s.net_recv_mbps} MB/s")
        print(f"  🔗  CONNS      : {s.active_connections}")
        print("\n  🧠  REASONING  :")
        print(f"  → {s.reasoning}")
        print(f"{'─'*54}")

    def run(self) -> None:
        """Run the heartbeat loop until stopped."""
        if self._disabled:
            print("  [AEGIS] Heartbeat disabled (psutil not available).")
            return
        print(f"  [AEGIS] Heartbeat active. Pulse every {PULSE_INTERVAL}s. Ctrl+C to stop.\n")
        try:
            while not self._stop_event.is_set():
                self.pulse()
                if self._stop_event.wait(PULSE_INTERVAL):
                    break
        except KeyboardInterrupt:
            print("\n  [AEGIS] Heartbeat stopped.")

    def stop(self) -> None:
        """Signal the heartbeat loop to stop."""
        self._stop_event.set()


if __name__ == "__main__":
    agent = Heartbeat()
    agent.run()
