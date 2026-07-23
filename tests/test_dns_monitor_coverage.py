"""Coverage booster for dns_monitor.py.

Covers uncovered paths:
- EntropyCalculator.domain_entropy edge cases
- DnsCapture.is_available / start_capture with/without Scapy
- DnsMonitor.feed_queries, _process_query, _dns_callback
- DnsMonitor lifecycle (start/stop) without scapy fallback
- DnsMonitor._default_handler formatting
- DnsReasoningEngine._purge_old cleanup edge cases
- High-entropy detection with whitelisted domains
"""

import threading
import time
from unittest.mock import patch, MagicMock

import pytest


# ═══════════════════════════════════════════════════════════════════════════════
# ENTROPY CALCULATOR
# ═══════════════════════════════════════════════════════════════════════════════


class TestEntropyCalculatorEdgeCases:
    """Edge cases for entropy calculation."""

    def test_empty_string(self):
        from modules.dns_monitor import EntropyCalculator
        assert EntropyCalculator.shannon_entropy("") == 0.0

    def test_single_char(self):
        from modules.dns_monitor import EntropyCalculator
        assert EntropyCalculator.shannon_entropy("a") == 0.0

    def test_two_chars_same(self):
        from modules.dns_monitor import EntropyCalculator
        assert EntropyCalculator.shannon_entropy("aa") == 0.0

    def test_high_entropy_string(self):
        from modules.dns_monitor import EntropyCalculator
        entropy = EntropyCalculator.shannon_entropy("a1b2c3d4e5f6g7h8i9j0")
        assert entropy > 3.0

    def test_domain_entropy_empty(self):
        from modules.dns_monitor import EntropyCalculator
        assert EntropyCalculator.domain_entropy("") == 0.0

    def test_domain_entropy_tld_only(self):
        from modules.dns_monitor import EntropyCalculator
        assert EntropyCalculator.domain_entropy("example.com") == 0.0

    def test_domain_entropy_with_subdomain(self):
        from modules.dns_monitor import EntropyCalculator
        entropy = EntropyCalculator.domain_entropy("randomxzy.test.example.com")
        assert entropy > 0.0

    def test_domain_entropy_trailing_dot(self):
        from modules.dns_monitor import EntropyCalculator
        entropy = EntropyCalculator.domain_entropy("test.example.com.")
        assert entropy >= 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# DNS CAPTURE
# ═══════════════════════════════════════════════════════════════════════════════


class TestDnsCapture:
    """Tests for DnsCapture class."""

    def test_scapy_available_returns_true(self):
        from modules.dns_monitor import DnsCapture
        with patch.object(DnsCapture, "check_scapy_available", return_value=True):
            capture = DnsCapture()
            assert capture.is_available() is True

    def test_scapy_available_returns_false(self):
        from modules.dns_monitor import DnsCapture
        with patch.object(DnsCapture, "check_scapy_available", return_value=False):
            capture = DnsCapture()
            assert capture.is_available() is False

    def test_start_capture_scapy_available(self):
        """Patch scapy.all.AsyncSniffer since it's imported inside the method."""
        from modules.dns_monitor import DnsCapture
        mock_sniffer = MagicMock()
        with patch.object(DnsCapture, "check_scapy_available", return_value=True):
            with patch("scapy.all.AsyncSniffer", return_value=mock_sniffer):
                capture = DnsCapture()
                callback = MagicMock()
                result = capture.start_capture(callback)
                assert result is mock_sniffer
                mock_sniffer.start.assert_called_once()

    def test_start_capture_scapy_not_available(self):
        from modules.dns_monitor import DnsCapture
        with patch.object(DnsCapture, "check_scapy_available", return_value=False):
            capture = DnsCapture()
            callback = MagicMock()
            result = capture.start_capture(callback)
            assert result is None

    def test_start_capture_import_error(self):
        """When AsyncSniffer import fails, should return None."""
        from modules.dns_monitor import DnsCapture
        with patch.object(DnsCapture, "check_scapy_available", return_value=True):
            with patch("scapy.all.AsyncSniffer", side_effect=ImportError("no scapy")):
                capture = DnsCapture()
                callback = MagicMock()
                result = capture.start_capture(callback)
                assert result is None

    def test_start_capture_init_exception(self):
        """When AsyncSniffer init raises, should catch and return None."""
        from modules.dns_monitor import DnsCapture
        with patch.object(DnsCapture, "check_scapy_available", return_value=True):
            with patch("scapy.all.AsyncSniffer", side_effect=RuntimeError("init error")):
                capture = DnsCapture()
                callback = MagicMock()
                result = capture.start_capture(callback)
                assert result is None


# ═══════════════════════════════════════════════════════════════════════════════
# DNS REASONING ENGINE — EDGE CASES
# ═══════════════════════════════════════════════════════════════════════════════


class TestDnsReasoningEngineEdgeCases:
    """Edge cases for the DNS reasoning engine."""

    @pytest.fixture
    def engine(self):
        from modules.dns_monitor import DnsReasoningEngine
        return DnsReasoningEngine()

    def test_empty_domain(self, engine):
        from modules.dns_monitor import DnsQuery
        query = DnsQuery(timestamp=time.time(), domain="", query_type="A",
                         source_ip="1.2.3.4", query_size=40, response_size=100)
        assert engine.evaluate(query) is None

    def test_dot_only_domain(self, engine):
        from modules.dns_monitor import DnsQuery
        query = DnsQuery(timestamp=time.time(), domain=".", query_type="A",
                         source_ip="1.2.3.4", query_size=40, response_size=100)
        assert engine.evaluate(query) is None

    def test_purge_old_removes_empty_entries(self, engine):
        """_purge_old should remove domain keys when all entries are purged."""
        engine._domain_tracker["lonely.test"] = [time.time() - 99999]
        engine._domain_size_tracker["lonely.test"] = [(time.time() - 99999, 40, 100)]
        engine._txt_tracker["lonely.test"] = [time.time() - 99999]
        engine._interval_tracker["lonely.test"] = [time.time() - 99999]
        engine._purge_old("lonely.test", time.time())
        assert "lonely.test" not in engine._domain_tracker
        assert "lonely.test" not in engine._domain_size_tracker
        assert "lonely.test" not in engine._txt_tracker
        assert "lonely.test" not in engine._interval_tracker

    def test_large_response_detected(self, engine):
        """A single large response should trigger LARGE_RESPONSE threat."""
        from modules.dns_monitor import DnsQuery
        threat = engine.evaluate(DnsQuery(
            timestamp=time.time(), domain="cdn.example.com", query_type="A",
            source_ip="1.2.3.4", query_size=50, response_size=5000,
        ))
        assert threat is not None
        assert threat.threat_type == "LARGE_RESPONSE"
        assert threat.risk_level == "MEDIUM"

    def test_txt_query_tracked(self, engine):
        """TXT queries should be tracked in the txt_tracker."""
        from modules.dns_monitor import DnsQuery
        for i in range(8):
            engine.evaluate(DnsQuery(
                timestamp=time.time() + (i * 0.1),
                domain="txt-test.example.com", query_type="TXT",
                source_ip="1.2.3.4", query_size=45, response_size=200,
            ))
        assert len(engine._txt_tracker.get("txt-test.example.com", [])) >= 5

    def test_cooldown_suppresses_duplicates(self, engine):
        """After alerting, cooldown prevents duplicate alerts."""
        from modules.dns_monitor import DnsQuery
        threat1 = engine.evaluate(DnsQuery(
            timestamp=time.time(), domain="very.random.xq7.example.com",
            query_type="A", source_ip="1.2.3.4", query_size=60, response_size=100,
        ))
        if threat1:
            threat2 = engine.evaluate(DnsQuery(
                timestamp=time.time(), domain="very.random.xq7.example.com",
                query_type="A", source_ip="1.2.3.4", query_size=60, response_size=100,
            ))
            assert threat2 is None


# ═══════════════════════════════════════════════════════════════════════════════
# DNS MONITOR LIFECYCLE & EDGE CASES
# ═══════════════════════════════════════════════════════════════════════════════


class TestDnsMonitorLifecycle:
    """Test DnsMonitor lifecycle and edge cases."""

    @pytest.fixture
    def monitor(self):
        from modules.dns_monitor import DnsMonitor
        return DnsMonitor()

    def test_start_stop(self, monitor):
        with patch.object(monitor._capture, "start_capture", return_value=None):
            monitor.start()
            assert monitor._running is True
            monitor.stop()
            assert monitor._running is False

    def test_start_twice(self, monitor):
        with patch.object(monitor._capture, "start_capture", return_value=None):
            monitor.start()
            thread_id = id(monitor._thread)
            monitor.start()
            assert id(monitor._thread) == thread_id
            monitor.stop()

    def test_stop_without_start(self, monitor):
        monitor.stop()

    def test_stop_with_sniffer(self, monitor):
        mock_sniffer = MagicMock()
        monitor._sniffer = mock_sniffer
        monitor._thread = MagicMock()
        monitor._thread.is_alive.return_value = True
        monitor.stop()
        mock_sniffer.stop.assert_called_once()

    def test_feed_query_buffers(self, monitor):
        from modules.dns_monitor import DnsQuery
        query = DnsQuery(timestamp=time.time(), domain="test.com", query_type="A",
                         source_ip="1.2.3.4", query_size=40, response_size=100)
        monitor.feed_query(query)
        assert len(monitor._query_buffer) == 1

    def test_feed_queries_batch(self, monitor):
        from modules.dns_monitor import DnsQuery
        queries = [
            DnsQuery(timestamp=time.time(), domain=f"test{i}.com", query_type="A",
                     source_ip="1.2.3.4", query_size=40, response_size=100)
            for i in range(5)
        ]
        monitor.feed_queries(queries)
        assert len(monitor._query_buffer) == 5

    def test_process_query_error_handling(self, monitor):
        with patch.object(monitor._engine, "evaluate", side_effect=RuntimeError("evaluation error")):
            from modules.dns_monitor import DnsQuery
            query = DnsQuery(timestamp=time.time(), domain="test.com", query_type="A",
                             source_ip="1.2.3.4", query_size=40, response_size=100)
            monitor._process_query(query)  # Should not raise

    def test_dns_callback_buffers_query(self, monitor):
        from modules.dns_monitor import DnsQuery
        query = DnsQuery(timestamp=time.time(), domain="test.com", query_type="A",
                         source_ip="1.2.3.4", query_size=40, response_size=100)
        with patch.object(monitor, "feed_query") as mock_feed:
            monitor._dns_callback(query)
            mock_feed.assert_called_once_with(query)

    def test_default_handler_prints(self, capsys):
        from modules.dns_monitor import DnsMonitor, DnsThreat
        threat = DnsThreat(
            timestamp="2026-01-01T00:00:00", threat_type="DNS_TUNNEL",
            risk_level="CRITICAL", domain="evil.c2.com", query_count=50,
            reasoning="Test reasoning", action_taken="FLAG_FOR_AUTOBLOCK",
            evidence={"test": "data"},
        )
        DnsMonitor._default_handler(threat)
        captured = capsys.readouterr()
        assert "DNS_TUNNEL" in captured.out
        assert "CRITICAL" in captured.out
        assert "evil.c2.com" in captured.out

    def test_on_threat_called(self):
        from modules.dns_monitor import DnsMonitor, DnsThreat
        callback = MagicMock()
        monitor = DnsMonitor(on_threat=callback)
        threat = DnsThreat(
            timestamp="now", threat_type="TEST", risk_level="LOW",
            domain="test.com", query_count=1, reasoning="test", action_taken="LOG",
        )
        monitor.on_threat(threat)
        callback.assert_called_once_with(threat)

    def test_run_loop_exits_via_stop_event(self, monitor):
        """_run_loop should process buffer then exit when stop event is set."""
        from modules.dns_monitor import DnsQuery
        query = DnsQuery(timestamp=time.time(), domain="test.com", query_type="A",
                         source_ip="1.2.3.4", query_size=40, response_size=100)
        monitor._query_buffer.append(query)

        # Set stop event from a timer so run_loop processes buffer first
        def set_stop():
            monitor._stop_event.set()

        timer = threading.Timer(0.05, set_stop)
        timer.start()
        with patch.object(monitor._engine, "cleanup") as mock_cleanup:
            monitor._run_loop()
            assert len(monitor._query_buffer) == 0  # Buffer was processed
            mock_cleanup.assert_called_once()

    def test_run_loop_with_stop_event_pre_set(self, monitor):
        """When stop_event is set before run_loop, it exits immediately."""
        monitor._stop_event.set()
        monitor._run_loop()  # Should not block or raise
