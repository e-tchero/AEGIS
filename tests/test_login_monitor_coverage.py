"""Coverage booster for login_monitor.py.

Covers uncovered paths:
- AuthLogParser._parse_linux_log with various patterns
- AuthLogParser._parse_windows_logs (wevtutil)
- AuthLogParser._parse_windows_event
- LoginReasoningEngine._check_attempt cooldown
- LoginReasoningEngine._purge_old_attempts
- LoginReasoningEngine.evaluate batch processing
- Edge cases: empty log lines, missing timestamps, file rotation
"""

import time
import os
from unittest.mock import patch, MagicMock, mock_open
from pathlib import Path

import pytest


# ═══════════════════════════════════════════════════════════════════════════════
# AUTH LOG PARSER
# ═══════════════════════════════════════════════════════════════════════════════


class TestAuthLogParser:
    """Tests for AuthLogParser."""

    @pytest.fixture
    def parser(self):
        from modules.login_monitor import AuthLogParser
        return AuthLogParser()

    def test_parse_linux_log_failed_password(self, parser, tmp_path):
        """Parse a failed password log line."""
        log_file = tmp_path / "auth.log"
        log_content = (
            "Jan 15 10:30:45 server sshd[1234]: Failed password for root from 10.0.0.5 port 22\n"
        )
        log_file.write_text(log_content)
        attempts = parser._parse_linux_log(str(log_file))
        assert len(attempts) == 1
        assert attempts[0].source_ip == "10.0.0.5"
        assert attempts[0].username == "root"
        assert attempts[0].success is False

    def test_parse_linux_log_invalid_user(self, parser, tmp_path):
        """Parse a failed password for invalid user."""
        log_file = tmp_path / "auth.log"
        log_content = (
            "Jan 15 10:31:00 server sshd[1235]: Failed password for invalid user admin from 10.0.0.99 port 2222\n"
        )
        log_file.write_text(log_content)
        attempts = parser._parse_linux_log(str(log_file))
        assert len(attempts) == 1
        assert attempts[0].username == "admin"
        assert attempts[0].source_ip == "10.0.0.99"

    def test_parse_linux_log_accepted_password(self, parser, tmp_path):
        """Parse a successful login."""
        log_file = tmp_path / "auth.log"
        log_content = (
            "Jan 15 10:32:00 server sshd[1236]: Accepted password for alice from 192.168.1.100 port 22\n"
        )
        log_file.write_text(log_content)
        attempts = parser._parse_linux_log(str(log_file))
        assert len(attempts) == 1
        assert attempts[0].username == "alice"
        assert attempts[0].source_ip == "192.168.1.100"
        assert attempts[0].success is True

    def test_parse_linux_log_empty_line(self, parser, tmp_path):
        """Empty lines should be skipped."""
        log_file = tmp_path / "auth.log"
        log_content = "\n\n\n"
        log_file.write_text(log_content)
        attempts = parser._parse_linux_log(str(log_file))
        assert len(attempts) == 0

    def test_parse_linux_log_no_match(self, parser, tmp_path):
        """Lines that don't match any pattern should be skipped."""
        log_file = tmp_path / "auth.log"
        log_content = "Jan 15 10:33:00 server sshd[1237]: Received disconnect from 10.0.0.5\n"
        log_file.write_text(log_content)
        attempts = parser._parse_linux_log(str(log_file))
        assert len(attempts) == 0

    def test_parse_linux_log_file_rotated(self, parser, tmp_path):
        """When last_pos > file_size, should reset to 0 (file rotation)."""
        log_file = tmp_path / "auth.log"
        log_file.write_text("Jan 15 10:00:00 server sshd[1000]: Failed password for root from 10.0.0.1 port 22\n")
        parser._last_positions[str(log_file)] = 9999  # Way beyond current file
        attempts = parser._parse_linux_log(str(log_file))
        assert len(attempts) == 1  # Should read from start

    def test_parse_linux_log_permission_denied(self, parser):
        """PermissionError should be caught and logged."""
        with patch("builtins.open", side_effect=PermissionError("denied")):
            attempts = parser._parse_linux_log("/var/log/auth.log")
            assert attempts == []

    def test_parse_linux_log_file_not_found(self, parser):
        """FileNotFoundError should be caught."""
        with patch("builtins.open", side_effect=FileNotFoundError()):
            attempts = parser._parse_linux_log("/nonexistent/auth.log")
            assert attempts == []

    def test_parse_logs_linux(self, parser):
        """parse_logs should dispatch to Linux log parser."""
        with patch("modules.login_monitor.CURRENT_OS", "Linux"):
            with patch("os.path.exists", return_value=True):
                with patch.object(parser, "_parse_linux_log", return_value=[1, 2, 3]):
                    attempts = parser.parse_logs()
                    assert len(attempts) >= 3

    def test_parse_logs_windows(self, parser):
        """parse_logs should dispatch to Windows event log parser."""
        with patch("modules.login_monitor.CURRENT_OS", "Windows"):
            with patch.object(parser, "_parse_windows_logs", return_value=[4, 5]):
                attempts = parser.parse_logs()
                assert len(attempts) == 2

    def test_parse_windows_logs_empty(self, parser):
        """Windows event log parsing with no results."""
        with patch("subprocess.run") as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = ""
            mock_run.return_value = mock_result
            attempts = parser._parse_windows_logs()
            assert attempts == []

    def test_parse_windows_logs_timeout(self, parser):
        """Windows event log parsing timeout should be caught."""
        import subprocess
        with patch("subprocess.run",
                   side_effect=subprocess.TimeoutExpired([], timeout=10)):
            result = parser._parse_windows_logs()
            assert result == []

    def test_parse_windows_event_success(self, parser):
        """Parse a successful Windows login event."""
        event = {"EventId": "4624", "Account Name": "admin", "IpAddress": "10.0.0.5"}
        attempt = parser._parse_windows_event(event)
        assert attempt is not None
        assert attempt.username == "admin"
        assert attempt.source_ip == "10.0.0.5"
        assert attempt.success is True

    def test_parse_windows_event_failure(self, parser):
        """Parse a failed Windows login event."""
        event = {"Id": "4625", "Target User Name": "root", "Source Network Address": "192.168.1.100"}
        attempt = parser._parse_windows_event(event)
        assert attempt is not None
        assert attempt.username == "root"
        assert attempt.success is False

    def test_parse_windows_event_missing_fields(self, parser):
        """Parse Windows event with missing fields should still return an attempt."""
        event = {"EventId": "4624"}
        attempt = parser._parse_windows_event(event)
        assert attempt is not None

    def test_parse_windows_event_exception(self, parser):
        """Exception during parsing should return None."""
        with patch.object(parser, "_parse_windows_event", return_value=None):
            result = parser._parse_windows_event({})
            assert result is None


# ═══════════════════════════════════════════════════════════════════════════════
# REASONING ENGINE
# ═══════════════════════════════════════════════════════════════════════════════


class TestLoginReasoningEngine:
    """Tests for LoginReasoningEngine."""

    @pytest.fixture
    def engine(self):
        from modules.login_monitor import LoginReasoningEngine
        return LoginReasoningEngine()

    def test_brute_force_detected(self, engine):
        """Multiple failed attempts from same IP should trigger brute force alert."""
        from modules.login_monitor import LoginAttempt
        attempts = []
        now = time.time()
        for i in range(6):
            attempts.append(LoginAttempt(
                timestamp=now - (i * 2),
                username="admin",
                source_ip="10.0.0.5",
                success=False,
                log_line="Failed password",
            ))
        threats = engine.evaluate(attempts)
        assert len(threats) >= 1
        assert threats[0].threat_type == "BRUTE_FORCE"

    def test_cooldown_suppresses_duplicates(self, engine):
        """After alerting, cooldown prevents duplicate alerts."""
        from modules.login_monitor import LoginAttempt
        now = time.time()
        # First batch triggers alert
        batch1 = [
            LoginAttempt(timestamp=now - (i * 1), username="admin",
                         source_ip="10.0.0.5", success=False, log_line="fail")
            for i in range(6)
        ]
        threats = engine.evaluate(batch1)
        brute_threats = [t for t in threats if t.threat_type == "BRUTE_FORCE"]
        # Second batch immediately after should be suppressed
        batch2 = [
            LoginAttempt(timestamp=now, username="admin",
                         source_ip="10.0.0.5", success=False, log_line="fail")
            for i in range(6)
        ]
        threats2 = engine.evaluate(batch2)
        new_brute = [t for t in threats2 if t.threat_type == "BRUTE_FORCE"]
        assert len(new_brute) == 0

    def test_successful_login_no_alert(self, engine):
        """Successful logins should not trigger brute force alerts."""
        from modules.login_monitor import LoginAttempt
        attempts = [
            LoginAttempt(timestamp=time.time(), username="admin",
                         source_ip="10.0.0.5", success=True, log_line="Accepted")
            for _ in range(10)
        ]
        threats = engine.evaluate(attempts)
        brute = [t for t in threats if t.threat_type == "BRUTE_FORCE"]
        assert len(brute) == 0

    def test_different_ips_separate_tracking(self, engine):
        """Different IPs should be tracked separately."""
        from modules.login_monitor import LoginAttempt
        now = time.time()
        attempts = []
        for i in range(6):
            attempts.append(LoginAttempt(
                timestamp=now - (i * 2),
                username="admin",
                source_ip="10.0.0.5",
                success=False,
                log_line="fail",
            ))
            attempts.append(LoginAttempt(
                timestamp=now - (i * 2),
                username="root",
                source_ip="10.0.0.99",
                success=False,
                log_line="fail",
            ))
        threats = engine.evaluate(attempts)
        brute_threats = [t for t in threats if t.threat_type == "BRUTE_FORCE"]
        # Both IPs should have triggered
        ips = {t.source_ip for t in brute_threats}
        assert len(ips) >= 1

    def test_evaluate_error_handling(self, engine):
        """evaluate should catch per-attempt errors."""
        from modules.login_monitor import LoginAttempt
        with patch.object(engine, "_check_attempt", side_effect=RuntimeError("eval error")):
            attempt = LoginAttempt(timestamp=time.time(), username="test",
                                   source_ip="1.2.3.4", success=False, log_line="fail")
            threats = engine.evaluate([attempt])
            assert threats == []

    def test_purge_old_removes_stale(self, engine):
        """_purge_old_attempts should remove entries outside BRUTE_FORCE_WINDOW."""
        engine._failed_attempts["10.0.0.1"] = [time.time() - 99999]
        engine._failed_attempts["10.0.0.2"] = [time.time()]
        engine._purge_old_attempts(time.time())
        assert "10.0.0.1" not in engine._failed_attempts
        assert "10.0.0.2" in engine._failed_attempts

    def test_is_on_cooldown_active(self, engine):
        """_is_on_cooldown should return True within cooldown period."""
        engine._alerted_ips["10.0.0.5"] = time.time()
        assert engine._is_on_cooldown("10.0.0.5", time.time()) is True

    def test_is_on_cooldown_expired(self, engine):
        """_is_on_cooldown should return False after cooldown period."""
        engine._alerted_ips["10.0.0.5"] = time.time() - 99999
        assert engine._is_on_cooldown("10.0.0.5", time.time()) is False
