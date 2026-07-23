"""Tests for the AEGIS Login Monitor."""

import time
from datetime import datetime

import pytest

from modules.login_monitor import (
    LoginMonitor, LoginAttempt, LoginThreat,
    LoginReasoningEngine, AuthLogParser,
)


class TestLoginAttempt:
    """Tests for the LoginAttempt data model."""

    def test_creation(self):
        attempt = LoginAttempt(
            timestamp=time.time(),
            username="admin", source_ip="10.0.0.5",
            success=False,
            log_line="Failed password for admin from 10.0.0.5",
        )
        assert attempt.username == "admin"
        assert attempt.source_ip == "10.0.0.5"
        assert attempt.success is False

    def test_successful_attempt(self):
        attempt = LoginAttempt(
            timestamp=time.time(),
            username="john", source_ip="192.168.1.100",
            success=True,
            log_line="Accepted password for john from 192.168.1.100",
        )
        assert attempt.success is True


class TestLoginThreat:
    """Tests for the LoginThreat data model."""

    def test_creation(self):
        threat = LoginThreat(
            timestamp=datetime.now().isoformat(),
            threat_type="BRUTE_FORCE", risk_level="HIGH",
            source_ip="10.0.0.5", username="admin",
            attempt_count=15,
            reasoning="Brute force detected",
            action_taken="FLAG_FOR_AUTOBLOCK",
            evidence={"failed_count": 15},
        )
        assert threat.threat_type == "BRUTE_FORCE"
        assert threat.attempt_count == 15


class TestLoginReasoningEngine:
    """Tests for the login reasoning engine."""

    def setup_method(self):
        self.engine = LoginReasoningEngine()

    def test_single_failed_attempt_no_threat(self):
        attempt = LoginAttempt(
            timestamp=time.time(), username="admin",
            source_ip="10.0.0.5", success=False,
            log_line="Failed password for admin",
        )
        threats = self.engine.evaluate([attempt])
        assert len(threats) == 0

    def test_brute_force_detected_at_threshold(self):
        """When count reaches/exceeds BRUTE_FORCE_THRESHOLD (5), should alert."""
        threats = []
        for i in range(5):  # Exactly at threshold
            attempt = LoginAttempt(
                timestamp=time.time(),
                username=f"user{i}", source_ip="10.0.0.5",
                success=False, log_line=f"Failed password for user{i}",
            )
            threats = self.engine.evaluate([attempt])
        # At the 5th attempt (count=5, threshold=5), alert fires ONCE
        assert len(threats) == 1
        assert threats[0].threat_type == "BRUTE_FORCE"

    def test_successful_attempt_no_brute_force(self):
        """Successful login should not trigger brute force."""
        attempt = LoginAttempt(
            timestamp=time.time(), username="admin",
            source_ip="10.0.0.5", success=True,
            log_line="Accepted password for admin",
        )
        threats = self.engine.evaluate([attempt])
        assert len(threats) == 0

    def test_different_ips_separate_tracking(self):
        """Failed attempts from different IPs are tracked independently."""
        # Send 5 from IP_A (should trigger at attempt 5)
        ip_a_threats = []
        for i in range(5):
            result = self.engine.evaluate([
                LoginAttempt(time.time(), f"user{i}", "10.0.0.5", False, "fail")
            ])
            if result:
                ip_a_threats.extend(result)
        # IP_A should have triggered
        assert len(ip_a_threats) >= 1

        # Send 5 from IP_B (separate tracking, should also trigger)
        ip_b_threats = []
        for i in range(5):
            result = self.engine.evaluate([
                LoginAttempt(time.time(), f"user{i}", "10.0.0.99", False, "fail")
            ])
            if result:
                ip_b_threats.extend(result)
        # IP_B should also trigger (different tracking)
        assert len(ip_b_threats) >= 1

        # Verify they're tracking different IPs
        if ip_a_threats:
            assert ip_a_threats[0].source_ip == "10.0.0.5"
        if ip_b_threats:
            assert ip_b_threats[0].source_ip == "10.0.0.99"

        # IP_A would trigger again only after cooldown, but the test verifies
        # that tracking is separate

    def test_new_admin_detection(self):
        threat = self.engine.check_new_admin("newadmin")
        assert threat is not None
        assert threat.threat_type == "NEW_ADMIN"

    def test_duplicate_admin_no_alert(self):
        threat1 = self.engine.check_new_admin("existing_admin")
        threat2 = self.engine.check_new_admin("existing_admin")
        assert threat1 is not None
        assert threat2 is None

    def test_empty_attempts_list(self):
        threats = self.engine.evaluate([])
        assert threats == []


class TestAuthLogParser:
    """Tests for the auth log parser."""

    def test_instantiation(self):
        parser = AuthLogParser()
        assert parser is not None

    def test_linux_failed_pattern_matches(self):
        parser = AuthLogParser()
        pattern = parser.LINUX_FAILED_PATTERNS[0]
        line = "Jan 15 10:30:45 server sshd[1234]: Failed password for admin from 10.0.0.5 port 22 ssh2"
        match = pattern.search(line)
        assert match is not None
        assert match.group(1) == "admin"
        assert match.group(2) == "10.0.0.5"

    def test_linux_invalid_user_pattern(self):
        parser = AuthLogParser()
        pattern = parser.LINUX_FAILED_PATTERNS[1]
        line = "Jan 15 10:30:45 server sshd[1234]: Failed password for invalid user test from 192.168.1.100 port 22"
        match = pattern.search(line)
        assert match is not None
        assert match.group(1) == "test"
        assert match.group(2) == "192.168.1.100"

    def test_linux_success_pattern_matches(self):
        parser = AuthLogParser()
        pattern = parser.LINUX_SUCCESS_PATTERNS[0]
        line = "Jan 15 10:30:45 server sshd[1234]: Accepted password for john from 192.168.1.100 port 22 ssh2"
        match = pattern.search(line)
        assert match is not None
        assert match.group(1) == "john"
        assert match.group(2) == "192.168.1.100"

    def test_parse_logs_returns_list(self):
        parser = AuthLogParser()
        attempts = parser.parse_logs()
        assert isinstance(attempts, list)

    def test_parse_windows_event_success(self):
        event = {"EventId": "4624", "Target User Name": "john",
                 "Source Network Address": "192.168.1.100"}
        attempt = AuthLogParser._parse_windows_event(event)
        assert attempt is not None
        assert attempt.success is True
        assert attempt.username == "john"

    def test_parse_windows_event_failure(self):
        event = {"EventId": "4625", "Account Name": "admin",
                 "IpAddress": "10.0.0.5"}
        attempt = AuthLogParser._parse_windows_event(event)
        assert attempt is not None
        assert attempt.success is False
        assert attempt.username == "admin"


class TestLoginMonitor:
    """Tests for LoginMonitor lifecycle."""

    def test_instantiation(self):
        monitor = LoginMonitor()
        assert monitor is not None
        assert not monitor._running

    def test_start_stop(self):
        monitor = LoginMonitor()
        monitor.start()
        assert monitor._running
        monitor.stop()
        assert not monitor._running

    def test_with_callback(self):
        results = []
        monitor = LoginMonitor(on_threat=lambda t: results.append(t))
        assert monitor is not None

    def test_default_handler_no_crash(self):
        threat = LoginThreat(
            timestamp=datetime.now().isoformat(),
            threat_type="BRUTE_FORCE", risk_level="HIGH",
            source_ip="10.0.0.5", username="admin",
            attempt_count=15,
            reasoning="Brute force detected",
            action_taken="FLAG_FOR_AUTOBLOCK",
        )
        LoginMonitor._default_handler(threat)
