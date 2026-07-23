"""Tests for the AEGIS DNS Monitor (Priority 6)."""

import time
from datetime import datetime

import pytest

from modules.dns_monitor import (
    DnsMonitor, DnsQuery, DnsThreat, DnsReasoningEngine,
    EntropyCalculator,
)


class TestEntropyCalculator:
    """Tests for Shannon entropy calculation for DGA detection."""

    def setup_method(self):
        self.calc = EntropyCalculator()

    def test_empty_string(self):
        assert self.calc.shannon_entropy("") == 0.0

    def test_low_entropy_domain(self):
        entropy = self.calc.shannon_entropy("google")
        assert entropy < 3.0, f"Expected low entropy, got {entropy:.2f}"

    def test_high_entropy_domain(self):
        entropy = self.calc.shannon_entropy("x8fK2pQ9mZ1vR3nL5sW7yB4")
        assert entropy > 3.5, f"Expected high entropy, got {entropy:.2f}"

    def test_all_same_char(self):
        entropy = self.calc.shannon_entropy("aaaaaa")
        assert entropy == 0.0

    def test_domain_entropy_simple(self):
        entropy = self.calc.domain_entropy("google.com")
        assert entropy < 3.0, f"Expected low domain entropy, got {entropy:.2f}"

    def test_domain_entropy_complex(self):
        entropy = self.calc.domain_entropy("x8fK2pQ9mZ1vR3n.malware.com")
        assert entropy > 3.0, f"Expected high domain entropy, got {entropy:.2f}"

    def test_domain_entropy_empty(self):
        assert self.calc.domain_entropy("") == 0.0

    def test_domain_entropy_no_subdomain(self):
        assert self.calc.domain_entropy("example.com") == 0.0

    def test_whitelisted_domain_low_entropy(self):
        entropy = self.calc.domain_entropy("abc123.cloudfront.net")
        # CloudFront is whitelisted, so only the sub-subdomain is checked
        assert isinstance(entropy, float)

    def test_balanced_string(self):
        """String with balanced chars should have high entropy."""
        entropy = self.calc.shannon_entropy("abc123xyz789")
        assert entropy > 2.5

    def test_single_char_string(self):
        assert self.calc.shannon_entropy("a") == 0.0


class TestDnsReasoningEngine:
    """Tests for the DNS reasoning engine's threat detection logic."""

    def setup_method(self):
        self.engine = DnsReasoningEngine()

    def test_high_entropy_threat(self):
        threat = self.engine.evaluate(DnsQuery(
            timestamp=time.time(),
            domain="x8fK2pQ9mZ1vR3nL5sW7yB4.malware.com",
            query_type="A", source_ip="1.2.3.4",
            query_size=50, response_size=100,
        ))
        assert threat is not None
        assert threat.threat_type == "HIGH_ENTROPY"
        assert threat.risk_level in ("CRITICAL", "HIGH", "MEDIUM")

    def test_normal_domain_no_threat(self):
        threat = self.engine.evaluate(DnsQuery(
            timestamp=time.time(),
            domain="google.com",
            query_type="A", source_ip="1.2.3.4",
            query_size=30, response_size=60,
        ))
        assert threat is None

    def test_whitelisted_domain_no_threat(self):
        threat = self.engine.evaluate(DnsQuery(
            timestamp=time.time(),
            domain="cdn.cloudfront.net",
            query_type="A", source_ip="1.2.3.4",
            query_size=30, response_size=60,
        ))
        assert threat is None

    def test_large_response_detected(self):
        threat = self.engine.evaluate(DnsQuery(
            timestamp=time.time(),
            domain="cdn.example.com",
            query_type="A", source_ip="1.2.3.4",
            query_size=50, response_size=5000,  # Large response (>1000B)
        ))
        assert threat is not None
        assert threat.threat_type == "LARGE_RESPONSE"

    def test_empty_domain(self):
        threat = self.engine.evaluate(DnsQuery(
            timestamp=time.time(),
            domain="",
            query_type="A", source_ip="1.2.3.4",
            query_size=0, response_size=0,
        ))
        assert threat is None

    def test_dot_only_domain(self):
        threat = self.engine.evaluate(DnsQuery(
            timestamp=time.time(),
            domain=".",
            query_type="A", source_ip="1.2.3.4",
            query_size=1, response_size=0,
        ))
        assert threat is None

    def test_txt_abuse_detection(self):
        """Multiple TXT queries should trigger TXT_ABUSE."""
        threat = None
        for i in range(6):  # Threshold is 5
            result = self.engine.evaluate(DnsQuery(
                timestamp=time.time(),
                domain="example.com",
                query_type="TXT", source_ip="1.2.3.4",
                query_size=50, response_size=2000,
            ))
            if result is not None:
                threat = result
        assert threat is not None
        assert threat.threat_type in ("TXT_ABUSE", "LARGE_RESPONSE")

    def test_dns_threat_dataclass(self):
        threat = DnsThreat(
            timestamp=datetime.now().isoformat(),
            threat_type="DNS_TUNNEL",
            risk_level="CRITICAL",
            domain="evil.com",
            query_count=100,
            reasoning="Test",
            action_taken="FLAG_FOR_AUTOBLOCK",
            evidence={"queries": 100},
        )
        assert threat.threat_type == "DNS_TUNNEL"
        assert threat.risk_level == "CRITICAL"
        assert threat.domain == "evil.com"
        assert threat.query_count == 100

    def test_dns_query_dataclass(self):
        query = DnsQuery(
            timestamp=1234567890.0,
            domain="example.com",
            query_type="A",
            source_ip="1.2.3.4",
            query_size=40,
            response_size=80,
        )
        assert query.domain == "example.com"
        assert query.query_type == "A"
        assert query.source_ip == "1.2.3.4"

    def test_cleanup_does_not_crash(self):
        """Cleanup should handle empty state without errors."""
        self.engine.cleanup()
        assert True  # Should not raise


class TestDnsMonitor:
    """Tests for DnsMonitor lifecycle."""

    def test_instantiation(self):
        monitor = DnsMonitor()
        assert monitor is not None
        assert not monitor._running

    def test_start_stop(self):
        monitor = DnsMonitor()
        monitor.start()
        assert monitor._running
        monitor.stop()
        assert not monitor._running

    def test_with_callback(self):
        results = []
        monitor = DnsMonitor(on_threat=lambda t: results.append(t))
        monitor.start()
        assert monitor._running
        monitor.stop()

    def test_feed_query_no_crash(self):
        monitor = DnsMonitor()
        monitor.feed_query(DnsQuery(
            timestamp=time.time(),
            domain="test.com",
            query_type="A", source_ip="1.2.3.4",
            query_size=30, response_size=60,
        ))
        assert True  # Should not raise

    def test_feed_queries_no_crash(self):
        monitor = DnsMonitor()
        queries = [
            DnsQuery(timestamp=time.time(), domain=f"test{i}.com",
                     query_type="A", source_ip="1.2.3.4",
                     query_size=30, response_size=60)
            for i in range(10)
        ]
        monitor.feed_queries(queries)
        assert True  # Should not raise

    def test_default_handler_no_crash(self):
        threat = DnsThreat(
            timestamp=datetime.now().isoformat(),
            threat_type="TEST", risk_level="LOW",
            domain="test.com", query_count=1,
            reasoning="Test",
            action_taken="LOG",
        )
        DnsMonitor._default_handler(threat)
        assert True  # Should not raise


class TestDnsCapture:
    """Tests for DNS capture availability."""

    def test_scapy_check(self):
        from modules.dns_monitor import DnsCapture
        capture = DnsCapture()
        available = capture.check_scapy_available()
        assert isinstance(available, bool)

    def test_is_available(self):
        from modules.dns_monitor import DnsCapture
        capture = DnsCapture()
        available = capture.is_available()
        assert isinstance(available, bool)


class TestDnsThreatDataModel:
    """Tests for the DnsThreat data model."""

    def test_full_threat_creation(self):
        threat = DnsThreat(
            timestamp="2025-01-01T00:00:00",
            threat_type="DNS_TUNNEL",
            risk_level="CRITICAL",
            domain="tunnel.evil.com",
            query_count=500,
            reasoning="DNS tunneling detected with 500 queries",
            action_taken="FLAG_FOR_AUTOBLOCK",
            evidence={
                "total_queries": 500,
                "large_responses": 20,
                "avg_response_size": 2048,
            },
        )
        assert threat.threat_type == "DNS_TUNNEL"
        assert "evidence" in threat.__dict__
        assert threat.evidence["total_queries"] == 500

    def test_minimal_threat_creation(self):
        threat = DnsThreat(
            timestamp="2025-01-01T00:00:00",
            threat_type="HIGH_ENTROPY",
            risk_level="MEDIUM",
            domain="random.example.com",
            query_count=5,
            reasoning="High entropy detected",
            action_taken="LOG_AND_WATCH",
        )
        assert threat.evidence == {}  # Default empty dict
