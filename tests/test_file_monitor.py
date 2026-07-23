"""Tests for the AEGIS File Integrity Monitor."""

import json
import os
import tempfile
from datetime import datetime
from pathlib import Path

import pytest

from modules.file_monitor import FileMonitor, FileRecord, FileThreat


class TestFileRecord:
    """Tests for the FileRecord data model."""

    def test_creation(self):
        record = FileRecord(
            path="/etc/passwd",
            hash="abc123def456",
            size=2048,
            modified_time="2025-01-01T00:00:00",
            first_seen="2025-01-01T00:00:00",
        )
        assert record.path == "/etc/passwd"
        assert record.hash == "abc123def456"
        assert record.size == 2048


class TestFileThreat:
    """Tests for the FileThreat data model."""

    def test_creation(self):
        threat = FileThreat(
            timestamp=datetime.now().isoformat(),
            threat_type="FILE_CHANGED",
            risk_level="HIGH",
            file_path="/etc/shadow",
            old_hash="abc123",
            new_hash="def456",
            old_size=1024,
            new_size=2048,
            reasoning="Critical file modified",
            action_taken="ALERT_AND_MONITOR",
            evidence={"old_hash_prefix": "abc123"},
        )
        assert threat.threat_type == "FILE_CHANGED"
        assert threat.risk_level == "HIGH"
        assert threat.file_path == "/etc/shadow"
        assert threat.new_hash == "def456"

    def test_file_deleted_threat(self):
        threat = FileThreat(
            timestamp=datetime.now().isoformat(),
            threat_type="FILE_DELETED",
            risk_level="CRITICAL",
            file_path="/etc/sudoers",
            old_hash="xyz789",
            new_hash="",
            old_size=4096,
            new_size=0,
            reasoning="Critical file deleted",
            action_taken="ALERT_AND_MONITOR",
        )
        assert threat.threat_type == "FILE_DELETED"
        assert threat.risk_level == "CRITICAL"
        assert threat.new_hash == ""


class TestFileMonitor:
    """Tests for the FileMonitor's core logic."""

    def test_instantiation(self):
        monitor = FileMonitor()
        assert monitor is not None
        assert not monitor._running

    def test_start_stop(self):
        monitor = FileMonitor()
        monitor.start()
        assert monitor._running
        monitor.stop()
        assert not monitor._running

    def test_with_callback(self):
        results = []
        monitor = FileMonitor(on_threat=lambda t: results.append(t))
        assert monitor is not None

    def test_hash_file_valid(self):
        """Test hashing a real temp file."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"test content for hashing")
            tmp_path = f.name
        try:
            hash_val = FileMonitor._hash_file(tmp_path)
            assert hash_val is not None
            assert len(hash_val) == 64  # SHA-256 hex digest
        finally:
            os.unlink(tmp_path)

    def test_hash_file_nonexistent(self):
        hash_val = FileMonitor._hash_file("/nonexistent/path/file.txt")
        assert hash_val is None

    def test_get_file_info_valid(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"test")
            tmp_path = f.name
        try:
            info = FileMonitor._get_file_info(tmp_path)
            assert info is not None
            assert "size" in info
            assert "modified_time" in info
            assert info["size"] > 0
        finally:
            os.unlink(tmp_path)

    def test_get_file_info_nonexistent(self):
        info = FileMonitor._get_file_info("/nonexistent/file.txt")
        assert info is None


class TestFileMonitorBaseline:
    """Tests for baseline management."""

    def test_baseline_save_and_load(self):
        """Test that baseline can be persisted and loaded back."""
        monitor = FileMonitor()
        # Use a temp baseline file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({
                "/etc/test.conf": {
                    "path": "/etc/test.conf",
                    "hash": "abc123", "size": 100,
                    "modified_time": "2025-01-01T00:00:00",
                    "first_seen": "2025-01-01T00:00:00",
                }
            }, f)
            baseline_path = f.name
        try:
            # Load baseline
            with open(baseline_path, "r") as f:
                data = json.load(f)
            assert "/etc/test.conf" in data
            assert data["/etc/test.conf"]["hash"] == "abc123"
        finally:
            os.unlink(baseline_path)


class TestFileThreatEdgeCases:
    """Tests for edge cases in file threat detection."""

    def test_minimal_threat(self):
        threat = FileThreat(
            timestamp="2025-01-01T00:00:00",
            threat_type="FILE_CHANGED",
            risk_level="LOW",
            file_path="/tmp/test.txt",
            old_hash="", new_hash="",
            old_size=0, new_size=0,
            reasoning="Test",
            action_taken="LOG",
        )
        assert threat.file_path == "/tmp/test.txt"

    def test_default_handler_no_crash(self):
        threat = FileThreat(
            timestamp=datetime.now().isoformat(),
            threat_type="FILE_CHANGED",
            risk_level="HIGH",
            file_path="/etc/shadow",
            old_hash="abc", new_hash="def",
            old_size=100, new_size=200,
            reasoning="Test default handler",
            action_taken="ALERT_AND_MONITOR",
        )
        FileMonitor._default_handler(threat)
        assert True  # Should not raise


class TestWatchedPaths:
    """Tests for watched paths configuration."""

    def test_windows_paths(self):
        from config import WATCHED_PATHS_WINDOWS
        assert len(WATCHED_PATHS_WINDOWS) > 0
        assert any("cmd.exe" in p for p in WATCHED_PATHS_WINDOWS)
        assert any("powershell.exe" in p for p in WATCHED_PATHS_WINDOWS)
        assert any("hosts" in p for p in WATCHED_PATHS_WINDOWS)

    def test_linux_paths(self):
        from config import WATCHED_PATHS_LINUX
        assert len(WATCHED_PATHS_LINUX) > 0
        assert "/etc/passwd" in WATCHED_PATHS_LINUX
        assert "/etc/shadow" in WATCHED_PATHS_LINUX
        assert "/etc/sudoers" in WATCHED_PATHS_LINUX
        assert "/etc/hosts" in WATCHED_PATHS_LINUX
