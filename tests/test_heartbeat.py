"""Tests for the AEGIS Heartbeat / ReasoningEngine module."""

import sys
from pathlib import Path
from typing import Tuple

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from core.heartbeat import ReasoningEngine, SystemSnapshot, Heartbeat
from config import (
    CPU_DANGER_THRESHOLD,
    CPU_ELEVATED_THRESHOLD,
    RAM_DANGER_THRESHOLD,
    RAM_ELEVATED_THRESHOLD,
    NET_SPIKE_THRESHOLD,
    NET_FLOOD_THRESHOLD,
)


# ─── REASONING ENGINE ─────────────────────────────────────────────────────────

class TestReasoningEngine:
    """Tests for the Heartbeat ReasoningEngine.evaluate() method."""

    def setup_method(self):
        self.engine = ReasoningEngine()

    def evaluate(self, cpu: float, ram: float, net_sent: float, net_recv: float) -> Tuple[float, str, str]:
        return self.engine.evaluate(cpu, ram, net_sent, net_recv)

    def test_all_normal(self):
        score, status, reasoning = self.evaluate(30, 40, 5, 10)
        assert score >= 85
        assert status == "NOMINAL"
        assert "No anomalies" in reasoning

    def test_cpu_critical(self):
        score, status, reasoning = self.evaluate(
            CPU_DANGER_THRESHOLD + 5, 40, 5, 10
        )
        assert score <= 70  # -30 deduction
        assert f"{CPU_DANGER_THRESHOLD}% threshold" in reasoning
        assert status in ("DEGRADED", "COMPROMISED")

    def test_cpu_elevated_not_critical(self):
        score, status, reasoning = self.evaluate(
            CPU_ELEVATED_THRESHOLD + 5, 40, 5, 10
        )
        assert score >= 80  # -10 at most
        assert "elevated but not critical" in reasoning.lower()

    def test_ram_critical(self):
        score, status, reasoning = self.evaluate(
            30, RAM_DANGER_THRESHOLD + 5, 5, 10
        )
        assert score <= 75  # -25 deduction
        assert "near exhaustion" in reasoning

    def test_ram_elevated_not_critical(self):
        score, status, reasoning = self.evaluate(
            30, RAM_ELEVATED_THRESHOLD + 5, 5, 10
        )
        assert "above comfortable range" in reasoning
        assert "near exhaustion" not in reasoning

    def test_net_exfil_risk(self):
        score, status, reasoning = self.evaluate(
            30, 40, NET_SPIKE_THRESHOLD + 10, 10
        )
        assert score <= 80  # -20 deduction
        assert any(w in reasoning.lower() for w in ["exfil", "spike", "C2"])

    def test_net_flood_risk(self):
        score, status, reasoning = self.evaluate(
            30, 40, 5, NET_FLOOD_THRESHOLD + 10
        )
        assert "Inbound flood" in reasoning

    def test_combined_high_risk(self):
        score, status, reasoning = self.evaluate(
            CPU_DANGER_THRESHOLD + 5,   # -30
            RAM_DANGER_THRESHOLD + 5,   # -25
            NET_SPIKE_THRESHOLD + 10,   # -20
            10,
        )
        assert score <= 45
        assert status in ("COMPROMISED", "CRITICAL")

    def test_all_critical(self):
        score, status, reasoning = self.evaluate(
            CPU_DANGER_THRESHOLD + 10,
            RAM_DANGER_THRESHOLD + 10,
            NET_SPIKE_THRESHOLD + 20,
            NET_FLOOD_THRESHOLD + 20,
        )
        assert score <= 25  # -30 -25 -20 -15 = 10 max
        assert status == "CRITICAL"

    def test_boundary_nominal(self):
        score, status, reasoning = self.evaluate(40, 50, 10, 20)
        assert status == "NOMINAL"
        assert score >= 85

    def test_health_score_no_negative(self):
        """Health score should never be negative."""
        score, status, reasoning = self.evaluate(100, 100, 200, 300)
        assert score >= 0

    def test_zero_metrics(self):
        """Zero metrics should produce NOMINAL status."""
        score, status, reasoning = self.evaluate(0, 0, 0, 0)
        assert status == "NOMINAL"
        assert score >= 85


class TestSystemSnapshot:
    """Tests for the SystemSnapshot data model."""

    def test_creation(self):
        snap = SystemSnapshot(
            timestamp="2025-01-01T00:00:00",
            cpu_percent=45.0,
            ram_percent=60.0,
            ram_used_gb=8.0,
            ram_total_gb=16.0,
            net_sent_mbps=1.5,
            net_recv_mbps=2.0,
            active_connections=42,
            health_score=90.0,
            status="NOMINAL",
            reasoning="All normal",
        )
        assert snap.cpu_percent == 45.0
        assert snap.health_score == 90.0
        assert snap.status == "NOMINAL"
        assert snap.active_connections == 42


class TestHeartbeat:
    """Tests for Heartbeat class behavior."""

    def test_instantiation_no_crash(self):
        """Heartbeat creation should not crash even with disabled state."""
        from threading import Event
        hb = Heartbeat(stop_event=Event())
        assert hb is not None
        if hb._disabled:
            assert hb._disabled is True

    def test_pulse_returns_none_if_disabled(self):
        """If psutil unavailable, pulse should return None."""
        from threading import Event
        hb = Heartbeat(stop_event=Event())
        if hb._disabled:
            result = hb.pulse()
            assert result is None

    def test_stop_sets_event(self):
        from threading import Event
        e = Event()
        hb = Heartbeat(stop_event=e)
        hb.stop()
        assert e.is_set()


class TestReasoningEngineEdgeCases:
    """Edge case tests for the ReasoningEngine."""

    def test_exactly_at_threshold(self):
        """Metrics exactly at threshold should trigger warning."""
        score, status, reasoning = ReasoningEngine.evaluate(85, 75, 50, 100)
        assert score <= 90  # Some deduction should apply

    def test_just_below_threshold(self):
        score, status, reasoning = ReasoningEngine.evaluate(59, 74, 49, 99)
        assert status == "NOMINAL"

    def test_very_high_cpu_low_ram(self):
        score, status, reasoning = ReasoningEngine.evaluate(99, 10, 1, 1)
        assert score <= 70
        assert "CPU" in reasoning

    def test_very_high_ram_low_cpu(self):
        score, status, reasoning = ReasoningEngine.evaluate(10, 98, 1, 1)
        assert score <= 75
        assert "RAM" in reasoning
