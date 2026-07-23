"""Coverage booster for net_sentinel.py.

Covers uncovered paths:
- _check_tcp_flags with syn_only=True and various flag combinations
- SentinelReasoning.evaluate with different port counts
- NetSentinel._dominant_scan_type
- NetSentinel._purge_old cleanup
- NetSentinel._is_on_cooldown edge cases
- NetSentinel._process_packet with TCP and UDP
- NetSentinel lifecycle (start/stop)
- NetSentinel.get_latest_threat
"""

import time
from unittest.mock import patch, MagicMock, PropertyMock
from datetime import datetime

import pytest


# ═══════════════════════════════════════════════════════════════════════════════
# TCP FLAG DETECTION
# ═══════════════════════════════════════════════════════════════════════════════


class MockPacket:
    """Minimal mock Scapy packet."""

    def __init__(self, has_ip=True, has_tcp=True, has_udp=False, tcp_flags=0x02, dport=80):
        self._has_ip = has_ip
        self._has_tcp = has_tcp
        self._has_udp = has_udp
        self._tcp_flags = tcp_flags
        self._dport = dport
        self._src = "10.0.0.5"
        self._sport = 54321

    def haslayer(self, layer):
        name = str(layer.__name__) if hasattr(layer, '__name__') else str(layer)
        if 'IP' in name:
            return self._has_ip
        if 'TCP' in name:
            return self._has_tcp
        if 'UDP' in name:
            return self._has_udp
        return False

    def __getitem__(self, layer):
        name = str(layer if isinstance(layer, str) else layer.__name__)
        if 'IP' in name:
            return MagicMock(src=self._src)
        if 'TCP' in name:
            mock = MagicMock()
            mock.flags = self._tcp_flags
            mock.dport = self._dport
            mock.sport = self._sport
            return mock
        if 'UDP' in name:
            mock = MagicMock()
            mock.dport = self._dport
            mock.sport = self._sport
            return mock
        raise KeyError(layer)


class TestCheckTcpFlags:
    """Tests for _check_tcp_flags function."""

    def test_syn_scan_detected(self):
        """SYN flag only (0x02) should be detected as SYN_SCAN."""
        from modules.net_sentinel import _check_tcp_flags
        pkt = MockPacket(tcp_flags=0x02)  # SYN
        result = _check_tcp_flags(pkt)
        assert result == "SYN_SCAN"

    def test_syn_scan_with_ack_ignored(self):
        """SYN-ACK (0x12) should NOT be detected as a scan."""
        from modules.net_sentinel import _check_tcp_flags
        pkt = MockPacket(tcp_flags=0x12)  # SYN-ACK
        result = _check_tcp_flags(pkt)
        assert result is None

    def test_ack_alone_ignored(self):
        """ACK (0x10) alone should NOT be detected."""
        from modules.net_sentinel import _check_tcp_flags
        pkt = MockPacket(tcp_flags=0x10)  # ACK
        result = _check_tcp_flags(pkt)
        assert result is None

    def test_fin_scan_detected(self):
        """FIN only (0x01) should be detected as FIN_SCAN."""
        from modules.net_sentinel import _check_tcp_flags
        pkt = MockPacket(tcp_flags=0x01)
        result = _check_tcp_flags(pkt)
        assert result == "FIN_SCAN"

    def test_xmas_scan_detected(self):
        """FIN+PSH+URG (0x29) should be detected as XMAS_SCAN."""
        from modules.net_sentinel import _check_tcp_flags
        pkt = MockPacket(tcp_flags=0x29)
        result = _check_tcp_flags(pkt)
        assert result == "XMAS_SCAN"

    def test_null_scan_detected(self):
        """No flags (0x00) should be detected as NULL_SCAN."""
        from modules.net_sentinel import _check_tcp_flags
        pkt = MockPacket(tcp_flags=0x00)
        result = _check_tcp_flags(pkt)
        assert result == "NULL_SCAN"

    def test_syn_only_mode_true(self):
        """With syn_only=True, only SYN should be detected."""
        from modules.net_sentinel import _check_tcp_flags
        syn_pkt = MockPacket(tcp_flags=0x02)
        fin_pkt = MockPacket(tcp_flags=0x01)
        assert _check_tcp_flags(syn_pkt, syn_only=True) == "SYN_SCAN"
        assert _check_tcp_flags(fin_pkt, syn_only=True) is None

    def test_fin_scan_with_other_flags(self):
        """FIN+SYN (0x03) should be treated as SYN_SCAN (SYN has priority)."""
        from modules.net_sentinel import _check_tcp_flags
        pkt = MockPacket(tcp_flags=0x03)  # FIN+SYN
        result = _check_tcp_flags(pkt)
        # SYN flag is set, no ACK -> returns SYN_SCAN
        assert result == "SYN_SCAN"


# ═══════════════════════════════════════════════════════════════════════════════
# SENTINEL REASONING
# ═══════════════════════════════════════════════════════════════════════════════


class TestSentinelReasoning:
    """Tests for SentinelReasoning.evaluate."""

    def test_critical_threshold(self):
        """50+ ports should be CRITICAL."""
        from modules.net_sentinel import SentinelReasoning
        level, _, action = SentinelReasoning.evaluate("10.0.0.5", list(range(60)), "SYN_SCAN")
        assert level == "CRITICAL"
        assert action == "FLAG_FOR_AUTOBLOCK"

    def test_high_threshold(self):
        """25-49 ports should be HIGH."""
        from modules.net_sentinel import SentinelReasoning
        level, _, action = SentinelReasoning.evaluate("10.0.0.5", list(range(30)), "SYN_SCAN")
        assert level == "HIGH"
        assert action == "ALERT_AND_MONITOR"

    def test_medium_threshold(self):
        """10-24 ports should be MEDIUM."""
        from modules.net_sentinel import SentinelReasoning
        # PORT_HIT_THRESHOLD is typically 10
        level, _, action = SentinelReasoning.evaluate("10.0.0.5", list(range(15)), "SYN_SCAN")
        assert level == "MEDIUM"
        assert action == "LOG_AND_WATCH"

    def test_low_below_threshold(self):
        """Below threshold should be LOW."""
        from modules.net_sentinel import SentinelReasoning
        level, reason, action = SentinelReasoning.evaluate("10.0.0.5", [22, 80], "SYN_SCAN")
        assert level == "LOW"
        assert action == "PASSIVE_LOG"
        assert "Below threshold" in reason

    def test_fin_scan_reasoning(self):
        """FIN scan should be mentioned in reasoning."""
        from modules.net_sentinel import SentinelReasoning
        _, reason, _ = SentinelReasoning.evaluate("10.0.0.5", list(range(15)), "FIN_SCAN")
        assert "FIN_SCAN" in reason


# ═══════════════════════════════════════════════════════════════════════════════
# NET SENTINEL CORE
# ═══════════════════════════════════════════════════════════════════════════════


class TestNetSentinelCore:
    """Tests for NetSentinel core methods."""

    @pytest.fixture
    def sentinel(self):
        from modules.net_sentinel import NetSentinel
        return NetSentinel()

    def test_dominant_scan_type_priority(self):
        """_dominant_scan_type should pick the highest priority type."""
        from modules.net_sentinel import NetSentinel
        result = NetSentinel._dominant_scan_type(
            {"NULL_SCAN", "FIN_SCAN", "UDP_SCAN"}
        )
        assert result == "FIN_SCAN"  # Priority: SYN > FIN > XMAS > NULL > UDP

    def test_dominant_scan_type_syn(self):
        """SYN_SCAN should take priority."""
        from modules.net_sentinel import NetSentinel
        result = NetSentinel._dominant_scan_type(
            {"UDP_SCAN", "SYN_SCAN", "NULL_SCAN"}
        )
        assert result == "SYN_SCAN"

    def test_dominant_scan_type_mixed(self):
        """When no known types, return MIXED."""
        from modules.net_sentinel import NetSentinel
        result = NetSentinel._dominant_scan_type({"UNKNOWN_TYPE"})
        assert result == "MIXED"

    def test_is_on_cooldown_no_threats(self, sentinel):
        """No threats means no cooldown."""
        assert sentinel._is_on_cooldown("10.0.0.5", time.time()) is False

    def test_is_on_cooldown_active(self, sentinel):
        """Recent threat should trigger cooldown."""
        from modules.net_sentinel import ThreatSnapshot
        sentinel._threats.append(ThreatSnapshot(
            timestamp=datetime.now().isoformat(),
            attacker_ip="10.0.0.5",
            ports_hit=[22],
            port_count=1,
            risk_level="LOW",
            threat_type="SYN_SCAN",
            reasoning="test",
            action_taken="LOG",
        ))
        assert sentinel._is_on_cooldown("10.0.0.5", time.time()) is True

    def test_is_on_cooldown_expired(self, sentinel):
        """Old threat should not trigger cooldown."""
        from modules.net_sentinel import ThreatSnapshot
        old_time = datetime.now().timestamp() - 99999
        # Need to create a threat with an old ISO timestamp
        sentinel._threats.append(ThreatSnapshot(
            timestamp=datetime.fromtimestamp(old_time).isoformat(),
            attacker_ip="10.0.0.5",
            ports_hit=[22],
            port_count=1,
            risk_level="LOW",
            threat_type="SYN_SCAN",
            reasoning="test",
            action_taken="LOG",
        ))
        assert sentinel._is_on_cooldown("10.0.0.5", time.time()) is False

    def test_is_on_cooldown_invalid_timestamp(self, sentinel):
        """Invalid timestamp should be handled."""
        from modules.net_sentinel import ThreatSnapshot
        sentinel._threats.append(ThreatSnapshot(
            timestamp="not-a-timestamp",
            attacker_ip="10.0.0.5",
            ports_hit=[22],
            port_count=1,
            risk_level="LOW",
            threat_type="SYN_SCAN",
            reasoning="test",
            action_taken="LOG",
        ))
        # Should not raise, should return False
        assert sentinel._is_on_cooldown("10.0.0.5", time.time()) is False

    def test_purge_old_removes_stale(self, sentinel):
        """_purge_old should clean up entries outside SCAN_WINDOW_SECONDS."""
        now = time.time()
        old = now - 99999
        sentinel._ip_tracker["10.0.0.5"] = [old, now]
        sentinel._port_tracker["10.0.0.5"] = {22: old, 80: now}
        sentinel._scan_type_tracker["10.0.0.5"][22].add("SYN_SCAN")
        sentinel._scan_type_tracker["10.0.0.5"][80].add("SYN_SCAN")
        sentinel._purge_old("10.0.0.5", now)
        assert len(sentinel._ip_tracker["10.0.0.5"]) == 1
        assert 22 not in sentinel._port_tracker["10.0.0.5"]
        assert 80 in sentinel._port_tracker["10.0.0.5"]

    def test_get_latest_threat_empty(self, sentinel):
        """No threats means get_latest_threat returns None."""
        assert sentinel.get_latest_threat() is None

    def test_get_latest_threat_with_data(self, sentinel):
        """With threats, should return the most recent."""
        from modules.net_sentinel import ThreatSnapshot
        t1 = ThreatSnapshot(timestamp="2026-01-01T00:00:00", attacker_ip="1.2.3.4",
                            ports_hit=[22], port_count=1, risk_level="LOW",
                            threat_type="SYN_SCAN", reasoning="a", action_taken="LOG")
        t2 = ThreatSnapshot(timestamp="2026-01-01T00:01:00", attacker_ip="5.6.7.8",
                            ports_hit=[80], port_count=1, risk_level="HIGH",
                            threat_type="SYN_SCAN", reasoning="b", action_taken="BLOCK")
        sentinel._threats = [t1, t2]
        latest = sentinel.get_latest_threat()
        assert latest.attacker_ip == "5.6.7.8"

    def test_default_handler_prints(self, capsys):
        """_default_handler should print formatted output."""
        from modules.net_sentinel import NetSentinel, ThreatSnapshot
        snap = ThreatSnapshot(
            timestamp="2026-01-01T00:00:00",
            attacker_ip="10.0.0.5",
            ports_hit=[22, 80, 443],
            port_count=3,
            risk_level="HIGH",
            threat_type="SYN_SCAN",
            reasoning="Test reasoning",
            action_taken="FLAG_FOR_AUTOBLOCK",
        )
        NetSentinel._default_handler(snap)
        captured = capsys.readouterr()
        assert "SYN_SCAN" in captured.out
        assert "10.0.0.5" in captured.out
        assert "HIGH" in captured.out

    def test_process_packet_no_ip(self, sentinel):
        """Packets without IP layer should be ignored."""
        pkt = MockPacket(has_ip=False)
        sentinel._process_packet(pkt)
        assert len(sentinel._ip_tracker) == 0

    def test_process_packet_no_tcp_or_udp(self, sentinel):
        """Packets without TCP or UDP should be ignored."""
        pkt = MockPacket(has_tcp=False, has_udp=False)
        sentinel._process_packet(pkt)
        assert len(sentinel._ip_tracker) == 0

    def test_process_packet_udp_scan(self, sentinel):
        """UDP packets should be detected as UDP_SCAN."""
        pkt = MockPacket(has_tcp=False, has_udp=True)
        sentinel._process_packet(pkt)
        # Should be tracked even if below threshold
        assert len(sentinel._ip_tracker) > 0

    def test_start_stop(self, sentinel):
        """Start and stop the sentinel."""
        with patch("modules.net_sentinel.AsyncSniffer") as mock_sniffer_cls:
            mock_sniffer = MagicMock()
            mock_sniffer_cls.return_value = mock_sniffer
            sentinel.start()
            assert sentinel._running is True
            assert sentinel._sniffer is not None
            sentinel.stop()
            assert sentinel._running is False
            mock_sniffer.stop.assert_called_once()

    def test_start_twice(self, sentinel):
        """Starting twice should be a no-op."""
        with patch("modules.net_sentinel.AsyncSniffer") as mock_sniffer_cls:
            sentinel.start()
            sniffer_id = id(sentinel._sniffer)
            sentinel.start()
            assert id(sentinel._sniffer) == sniffer_id
            sentinel.stop()

    def test_stop_without_start(self, sentinel):
        """Stop should not raise when not started."""
        sentinel.stop()

    def test_stop_sniffer_stop_fails(self, sentinel):
        """Sniffer stop failure should be caught."""
        sentinel._sniffer = MagicMock()
        sentinel._sniffer.stop.side_effect = RuntimeError("stop error")
        sentinel.stop()  # Should not raise
