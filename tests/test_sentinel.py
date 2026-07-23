"""Unit tests for the AEGIS Net Sentinel module."""

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from scapy.all import IP, TCP, UDP  # type: ignore[import-untyped]

from modules.net_sentinel import (
    SentinelReasoning,
    ThreatSnapshot,
    _check_tcp_flags,
    NetSentinel,
)


# ─── SCAN DETECTION HELPERS ───────────────────────────────────────────────────

class MockFlags:
    """Minimal mock for Scapy TCP flags field."""
    def __init__(self, value: int):
        self.value = value

    def __int__(self) -> int:
        return self.value

    def __and__(self, other) -> int:
        return self.value & other

    def __bool__(self) -> bool:
        return bool(self.value)


class MockTCP:
    """Minimal Scapy-like TCP layer for testing flag detection."""
    def __init__(self, flags_value: int, dport: int = 80):
        self.flags = MockFlags(flags_value)
        self.dport = dport


class MockUDP:
    def __init__(self, dport: int = 53):
        self.dport = dport


class MockIP:
    def __init__(self, src: str = "1.2.3.4", dst: str = "10.0.0.1"):
        self.src = src
        self.dst = dst


class MockPacket:
    """Mimics a Scapy packet for testing."""

    def __init__(self, src: str, tcp_flags: int = 0, dport: int = 80,
                 has_tcp: bool = True, has_udp: bool = False, has_ip: bool = True):
        self._layers: Dict[type, Any] = {}
        self._has_tcp = has_tcp
        self._has_udp = has_udp
        self._has_ip = has_ip

        self._ip = MockIP(src=src)
        if has_tcp:
            self._tcp = MockTCP(flags_value=tcp_flags, dport=dport)
        self._udp = MockUDP(dport=dport) if has_udp else None

    def haslayer(self, layer) -> bool:
        if layer == IP:
            return self._has_ip
        if layer == TCP:
            return self._has_tcp
        if layer == UDP:
            return self._has_udp
        return False

    def __getitem__(self, layer):
        if layer == IP:
            return self._ip
        if layer == TCP and self._has_tcp:
            return self._tcp
        if layer == UDP and self._has_udp:
            return self._udp
        raise KeyError(layer)


# ─── TCP FLAG DETECTION ──────────────────────────────────────────────────────

class TestCheckTCPFlags:
    """Test scan type classification from TCP flags."""

    def test_syn_scan(self):
        pkt = MockPacket(src="1.2.3.4", tcp_flags=0x02)
        assert _check_tcp_flags(pkt) == "SYN_SCAN"

    def test_fin_scan(self):
        pkt = MockPacket(src="1.2.3.4", tcp_flags=0x01)
        assert _check_tcp_flags(pkt) == "FIN_SCAN"

    def test_xmas_scan(self):
        pkt = MockPacket(src="1.2.3.4", tcp_flags=0x29)
        assert _check_tcp_flags(pkt) == "XMAS_SCAN"

    def test_null_scan(self):
        pkt = MockPacket(src="1.2.3.4", tcp_flags=0x00)
        assert _check_tcp_flags(pkt) == "NULL_SCAN"

    def test_ack_not_scan(self):
        pkt = MockPacket(src="1.2.3.4", tcp_flags=0x10)
        assert _check_tcp_flags(pkt) is None

    def test_syn_ack_not_scan(self):
        pkt = MockPacket(src="1.2.3.4", tcp_flags=0x12)
        assert _check_tcp_flags(pkt) is None

    def test_rst_not_scan(self):
        pkt = MockPacket(src="1.2.3.4", tcp_flags=0x04)
        assert _check_tcp_flags(pkt) is None

    def test_psh_ack_not_scan(self):
        pkt = MockPacket(src="1.2.3.4", tcp_flags=0x18)
        assert _check_tcp_flags(pkt) is None

    def test_urg_not_scan(self):
        pkt = MockPacket(src="1.2.3.4", tcp_flags=0x20)
        assert _check_tcp_flags(pkt) is None

    def test_syn_scan_syn_only_mode(self):
        pkt = MockPacket(src="1.2.3.4", tcp_flags=0x02)
        assert _check_tcp_flags(pkt, syn_only=True) == "SYN_SCAN"

    def test_fin_not_detected_syn_only(self):
        pkt = MockPacket(src="1.2.3.4", tcp_flags=0x01)
        assert _check_tcp_flags(pkt, syn_only=True) is None


# ─── REASONING ENGINE ─────────────────────────────────────────────────────────

class TestSentinelReasoning:
    """Test risk level evaluation based on port counts."""

    def setup_method(self):
        self.reasoner = SentinelReasoning()

    def test_low_below_threshold(self):
        ports = list(range(1, 5))  # 4 ports — below threshold
        risk, reasoning, action = self.reasoner.evaluate("1.2.3.4", ports, "SYN_SCAN")
        assert risk == "LOW"
        assert action == "PASSIVE_LOG"

    def test_medium_at_threshold(self):
        ports = list(range(1, 11))  # 10 ports — at threshold
        risk, reasoning, action = self.reasoner.evaluate("1.2.3.4", ports, "SYN_SCAN")
        assert risk == "MEDIUM"
        assert action == "LOG_AND_WATCH"

    def test_high_at_25(self):
        ports = list(range(1, 26))  # 25 ports
        risk, reasoning, action = self.reasoner.evaluate("1.2.3.4", ports, "SYN_SCAN")
        assert risk == "HIGH"
        assert action == "ALERT_AND_MONITOR"

    def test_critical_at_50(self):
        ports = list(range(1, 51))  # 50 ports
        risk, reasoning, action = self.reasoner.evaluate("1.2.3.4", ports, "SYN_SCAN")
        assert risk == "CRITICAL"
        assert action == "FLAG_FOR_AUTOBLOCK"

    def test_reasoning_contains_scan_type(self):
        ports = list(range(1, 15))
        risk, reasoning, action = self.reasoner.evaluate("1.2.3.4", ports, "FIN_SCAN")
        assert "FIN_SCAN" in reasoning

    def test_reasoning_contains_ip(self):
        ports = list(range(1, 15))
        risk, reasoning, action = self.reasoner.evaluate("10.0.0.99", ports, "SYN_SCAN")
        assert "10.0.0.99" in reasoning

    def test_exactly_10_ports(self):
        ports = list(range(1, 11))
        risk, reasoning, action = self.reasoner.evaluate("1.2.3.4", ports, "SYN_SCAN")
        assert risk in ("MEDIUM", "HIGH")

    def test_exactly_1_port(self):
        risk, reasoning, action = self.reasoner.evaluate("1.2.3.4", [80], "SYN_SCAN")
        assert risk == "LOW"

    def test_fin_scan_label_in_reasoning(self):
        ports = list(range(1, 15))
        risk, reasoning, action = self.reasoner.evaluate("1.2.3.4", ports, "NULL_SCAN")
        assert "NULL_SCAN" in reasoning


# ─── DOMINANT SCAN TYPE ──────────────────────────────────────────────────────

class TestDominantScanType:
    def test_syn_preferred(self):
        types = {"UDP_SCAN", "SYN_SCAN", "NULL_SCAN"}
        assert NetSentinel._dominant_scan_type(types) == "SYN_SCAN"

    def test_fin_when_no_syn(self):
        types = {"FIN_SCAN", "XMAS_SCAN"}
        assert NetSentinel._dominant_scan_type(types) == "FIN_SCAN"

    def test_udp_only(self):
        assert NetSentinel._dominant_scan_type({"UDP_SCAN"}) == "UDP_SCAN"

    def test_empty_set_returns_mixed(self):
        assert NetSentinel._dominant_scan_type(set()) == "MIXED"

    def test_all_types(self):
        types = {"SYN_SCAN", "FIN_SCAN", "XMAS_SCAN", "NULL_SCAN", "UDP_SCAN"}
        assert NetSentinel._dominant_scan_type(types) == "SYN_SCAN"

    def test_single_null(self):
        assert NetSentinel._dominant_scan_type({"NULL_SCAN"}) == "NULL_SCAN"

    def test_single_xmas(self):
        assert NetSentinel._dominant_scan_type({"XMAS_SCAN"}) == "XMAS_SCAN"


# ─── THREAT SNAPSHOT ──────────────────────────────────────────────────────────

class TestThreatSnapshot:
    def test_creation(self):
        snap = ThreatSnapshot(
            timestamp="2025-01-01T00:00:00",
            attacker_ip="1.2.3.4",
            ports_hit=[22, 80, 443],
            port_count=3,
            risk_level="MEDIUM",
            threat_type="SYN_SCAN",
            reasoning="Port scan detected",
            action_taken="LOG_AND_WATCH",
        )
        assert snap.attacker_ip == "1.2.3.4"
        assert snap.port_count == 3
        assert snap.threat_type == "SYN_SCAN"

    def test_minimal_threat(self):
        snap = ThreatSnapshot(
            timestamp="2025-01-01T00:00:00",
            attacker_ip="1.2.3.4",
            ports_hit=[80],
            port_count=1,
            risk_level="LOW",
            threat_type="SYN_SCAN",
            reasoning="Minimal",
            action_taken="PASSIVE_LOG",
        )
        assert snap.risk_level == "LOW"


# ─── NET SENTINEL ─────────────────────────────────────────────────────────────

class TestNetSentinel:
    def test_instantiation(self):
        sentinel = NetSentinel()
        assert sentinel is not None
        assert not sentinel._running

    def test_start_stop(self):
        sentinel = NetSentinel()
        sentinel.start()
        assert sentinel._running
        sentinel.stop()
        assert not sentinel._running

    def test_with_callback(self):
        results = []
        sentinel = NetSentinel(on_threat=lambda t: results.append(t))
        assert sentinel is not None

    def test_get_threats_empty(self):
        sentinel = NetSentinel()
        assert sentinel.get_threats() == []

    def test_get_latest_threat_empty(self):
        sentinel = NetSentinel()
        assert sentinel.get_latest_threat() is None

    def test_default_handler_no_crash(self):
        snap = ThreatSnapshot(
            timestamp="2025-01-01T00:00:00",
            attacker_ip="1.2.3.4",
            ports_hit=[22, 80, 443],
            port_count=3,
            risk_level="MEDIUM",
            threat_type="SYN_SCAN",
            reasoning="Test",
            action_taken="LOG_AND_WATCH",
        )
        NetSentinel._default_handler(snap)
        assert True  # Should not raise

    def test_is_on_cooldown_no_threats(self):
        sentinel = NetSentinel()
        result = sentinel._is_on_cooldown("1.2.3.4", 1000.0)
        assert result is False


class TestNetSentinelScanTypes:
    """Test that NetSentinel can handle all scan types."""

    def test_syn_scan_threat(self):
        sentinel = NetSentinel()
        # SYN scan packet
        import time
        from datetime import datetime as dt

        # Manually test the scan type labels
        assert _check_tcp_flags(MockPacket(src="1.2.3.4", tcp_flags=0x02)) == "SYN_SCAN"
        assert _check_tcp_flags(MockPacket(src="1.2.3.4", tcp_flags=0x01)) == "FIN_SCAN"
        assert _check_tcp_flags(MockPacket(src="1.2.3.4", tcp_flags=0x29)) == "XMAS_SCAN"
        assert _check_tcp_flags(MockPacket(src="1.2.3.4", tcp_flags=0x00)) == "NULL_SCAN"


class TestThresholdConstants:
    """Test the threshold constants used by SentinelReasoning."""

    def test_thresholds_decreasing(self):
        import modules.net_sentinel as ns
        thresholds = []
        for level, (threshold, action, template) in sorted(
            ns.SentinelReasoning.THRESHOLDS.items(),
            key=lambda x: -x[1][0]
        ):
            thresholds.append(threshold)
        # Each threshold should be larger than the next
        assert thresholds[0] > thresholds[1] > thresholds[2]
