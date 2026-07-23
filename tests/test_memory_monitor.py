"""Tests for the AEGIS Memory Intelligence Module (Priority 5)."""

from datetime import datetime
from pathlib import Path

import pytest

from modules.memory_monitor import (
    MemoryMonitor, MemoryThreat, MemoryRegion, MemoryAnalyzer,
    SUSPICIOUS_PERMISSIONS,
)


class TestSuspiciousPermissions:
    """Tests for suspicious memory permission detection."""

    def test_rwx_is_suspicious(self):
        assert "rwx" in SUSPICIOUS_PERMISSIONS

    def test_rwxp_is_suspicious(self):
        assert "rwxp" in SUSPICIOUS_PERMISSIONS

    def test_rw_is_not_suspicious(self):
        assert "rw-" not in SUSPICIOUS_PERMISSIONS
        assert "rw" not in SUSPICIOUS_PERMISSIONS

    def test_rx_is_not_suspicious(self):
        assert "r-x" not in SUSPICIOUS_PERMISSIONS
        assert "r--" not in SUSPICIOUS_PERMISSIONS


class TestMemoryRegion:
    """Tests for the MemoryRegion data model."""

    def test_rwx_region_creation(self):
        region = MemoryRegion(
            path="", perms="rwx", rss=65536,
            is_anonymous=True, is_executable=True,
            is_writable=True, is_private=True,
        )
        assert region.perms == "rwx"
        assert region.is_anonymous is True
        assert region.is_executable is True
        assert region.is_writable is True

    def test_normal_region_creation(self):
        region = MemoryRegion(
            path="/usr/lib/libc.so", perms="r-x", rss=4096,
            is_anonymous=False, is_executable=True,
            is_writable=False, is_private=True,
        )
        assert region.path == "/usr/lib/libc.so"
        assert region.is_anonymous is False
        assert region.is_writable is False

    def test_anonymous_region(self):
        region = MemoryRegion(
            path="", perms="rwx", rss=131072,
            is_anonymous=True, is_executable=False,
            is_writable=False, is_private=True,
        )
        assert region.is_anonymous is True

    def test_region_permission_combinations(self):
        region = MemoryRegion(
            path="test.dll", perms="rwxp", rss=8192,
            is_anonymous=False, is_executable=True,
            is_writable=True, is_private=True,
        )
        assert region.is_writable and region.is_executable


class TestMemoryThreat:
    """Tests for the MemoryThreat data model."""

    def test_creation(self):
        threat = MemoryThreat(
            timestamp=datetime.now().isoformat(),
            threat_type="RWX_MEMORY",
            risk_level="CRITICAL",
            pid=1234,
            process_name="test.exe",
            suspicious_count=3,
            reasoning="RWX memory regions detected",
            action_taken="FLAG_FOR_AUTOBLOCK",
            evidence={"rwx_count": 3, "rwx_regions": []},
        )
        assert threat.threat_type == "RWX_MEMORY"
        assert threat.risk_level == "CRITICAL"
        assert threat.pid == 1234
        assert threat.suspicious_count == 3

    def test_dll_injection_threat(self):
        threat = MemoryThreat(
            timestamp=datetime.now().isoformat(),
            threat_type="DLL_INJECTION",
            risk_level="HIGH",
            pid=5678,
            process_name="svchost.exe",
            suspicious_count=2,
            reasoning="Suspicious modules loaded",
            action_taken="ALERT_AND_MONITOR",
            evidence={"suspicious_modules": [{"path": "/tmp/malware.dll"}]},
        )
        assert threat.threat_type == "DLL_INJECTION"
        assert threat.pid == 5678
        assert len(threat.evidence["suspicious_modules"]) == 1

    def test_process_hollowing_threat(self):
        threat = MemoryThreat(
            timestamp=datetime.now().isoformat(),
            threat_type="PROCESS_HOLLOWING",
            risk_level="CRITICAL",
            pid=9012,
            process_name="svchost.exe",
            suspicious_count=1,
            reasoning="Process hollowing suspected",
            action_taken="FLAG_FOR_AUTOBLOCK",
            evidence={"indicator": "no_file_backed_executable_regions"},
        )
        assert threat.threat_type == "PROCESS_HOLLOWING"
        assert threat.evidence["indicator"] == "no_file_backed_executable_regions"

    def test_minimal_threat(self):
        threat = MemoryThreat(
            timestamp="2025-01-01T00:00:00",
            threat_type="HIGH_MAP_COUNT",
            risk_level="MEDIUM",
            pid=1,
            process_name="init",
            suspicious_count=600,
            reasoning="High map count",
            action_taken="LOG_AND_WATCH",
        )
        assert threat.evidence == {}


class TestMemoryAnalyzer:
    """Tests for the MemoryAnalyzer's detection logic."""

    def setup_method(self):
        self.analyzer = MemoryAnalyzer()

    def test_find_suspicious_modules_anonymous_only(self):
        """Anonymous (no path) regions should not be flagged as injection modules."""
        suspicious = self.analyzer._find_suspicious_modules([
            MemoryRegion(path="", perms="r-x", rss=4096,
                         is_anonymous=True, is_executable=True,
                         is_writable=False, is_private=True),
        ])
        assert len(suspicious) == 0

    def test_find_suspicious_modules_temp_path(self):
        suspicious = self.analyzer._find_suspicious_modules([
            MemoryRegion(path="/tmp/malware.dll", perms="r-x", rss=4096,
                         is_anonymous=False, is_executable=True,
                         is_writable=False, is_private=True),
        ])
        assert len(suspicious) >= 1

    def test_known_legitimate_not_suspicious(self):
        suspicious = self.analyzer._find_suspicious_modules([
            MemoryRegion(path="C:\\Windows\\System32\\ntdll.dll", perms="r-x", rss=4096,
                         is_anonymous=False, is_executable=True,
                         is_writable=False, is_private=True),
        ])
        assert len(suspicious) == 0  # ntdll.dll is in KNOWN_LEGITIMATE_MODULES

    def test_find_suspicious_modules_with_rwx(self):
        regions = [
            MemoryRegion(path="/usr/lib/libc.so", perms="r-x", rss=4096,
                         is_anonymous=False, is_executable=True,
                         is_writable=False, is_private=True),
            MemoryRegion(path="/tmp/shellcode.dll", perms="rwx", rss=65536,
                         is_anonymous=False, is_executable=True,
                         is_writable=True, is_private=True),
        ]
        suspicious = self.analyzer._find_suspicious_modules(regions)
        assert len(suspicious) >= 1

    def test_check_hollowing_no_exec_regions(self):
        result = MemoryAnalyzer._check_hollowing([
            MemoryRegion(path="", perms="rw-", rss=4096,
                         is_anonymous=True, is_executable=False,
                         is_writable=True, is_private=True),
        ], "svchost.exe")
        assert result is None  # No executable regions at all

    def test_check_hollowing_anon_exec_regions(self):
        result = MemoryAnalyzer._check_hollowing([
            MemoryRegion(path="", perms="r-x", rss=65536,
                         is_anonymous=True, is_executable=True,
                         is_writable=False, is_private=True),
            MemoryRegion(path="", perms="rwx", rss=131072,
                         is_anonymous=True, is_executable=True,
                         is_writable=True, is_private=True),
        ], "svchost.exe")
        assert result is not None
        assert result["indicator"] == "no_file_backed_executable_regions"

    def test_check_hollowing_temp_regions(self):
        result = MemoryAnalyzer._check_hollowing([
            MemoryRegion(path="/tmp/evil.exe", perms="r-x", rss=65536,
                         is_anonymous=False, is_executable=True,
                         is_writable=False, is_private=True),
        ], "evil.exe")
        assert result is not None
        assert "temp" in result["indicator"].lower() or "temp" in str(result.get("matched_regions", []))

    def test_parse_regions(self):
        class MockMap:
            def __init__(self, path, perms, rss):
                self.path = path
                self.perms = perms
                self.rss = rss

        maps = [MockMap("", "rwx", 65536), MockMap("/lib/lib.so", "r-x", 4096)]
        regions = MemoryAnalyzer._parse_regions(maps)
        assert len(regions) == 2
        assert regions[0].perms == "rwx"
        assert regions[1].path == "/lib/lib.so"

    def test_parse_regions_empty(self):
        regions = MemoryAnalyzer._parse_regions([])
        assert regions == []


class TestMemoryMonitor:
    """Tests for MemoryMonitor lifecycle."""

    def test_instantiation(self):
        monitor = MemoryMonitor()
        assert monitor is not None
        assert not monitor._running

    def test_start_stop(self):
        monitor = MemoryMonitor()
        monitor.start()
        assert monitor._running
        monitor.stop()
        assert not monitor._running

    def test_with_callback(self):
        results = []
        monitor = MemoryMonitor(on_threat=lambda t: results.append(t))
        assert monitor is not None

    def test_default_handler_no_crash(self):
        threat = MemoryThreat(
            timestamp=datetime.now().isoformat(),
            threat_type="RWX_MEMORY", risk_level="CRITICAL",
            pid=1234, process_name="test.exe",
            suspicious_count=3,
            reasoning="RWX memory detected",
            action_taken="FLAG_FOR_AUTOBLOCK",
            evidence={
                "rwx_regions": [
                    {"path": "/tmp/evil.exe", "perms": "rwx", "rss_kb": 64}
                ]
            },
        )
        MemoryMonitor._default_handler(threat)
        assert True  # Should not raise

    def test_default_handler_empty_evidence(self):
        threat = MemoryThreat(
            timestamp=datetime.now().isoformat(),
            threat_type="RWX_MEMORY", risk_level="CRITICAL",
            pid=1234, process_name="test.exe",
            suspicious_count=3,
            reasoning="RWX memory detected",
            action_taken="FLAG_FOR_AUTOBLOCK",
        )
        MemoryMonitor._default_handler(threat)
        assert True  # Should not raise


class TestMemoryThreatBuilders:
    """Tests for the static threat builder methods."""

    def test_rwx_threat_builder(self):
        regions = [
            MemoryRegion(path="", perms="rwx", rss=65536,
                         is_anonymous=True, is_executable=True,
                         is_writable=True, is_private=True),
        ]
        threat = MemoryAnalyzer._create_rwx_threat(
            1234, "test.exe", regions, 100
        )
        assert threat.threat_type == "RWX_MEMORY"
        assert threat.pid == 1234
        assert threat.risk_level == "CRITICAL"
        assert threat.action_taken == "FLAG_FOR_AUTOBLOCK"

    def test_injection_threat_builder(self):
        mods = [{"path": "/tmp/malware.dll", "matched_pattern": "tmp", "perms": "rwx", "rss": 65536, "reason": "test"}]
        threat = MemoryAnalyzer._create_injection_threat(
            5678, "svchost.exe", mods, 200
        )
        assert threat.threat_type == "DLL_INJECTION"
        assert threat.pid == 5678
        assert threat.risk_level == "HIGH"

    def test_reflective_threat_builder(self):
        regions = [
            MemoryRegion(path="", perms="r-x", rss=65536,
                         is_anonymous=True, is_executable=True,
                         is_writable=False, is_private=True),
        ]
        threat = MemoryAnalyzer._create_reflective_threat(
            9012, "test.exe", regions, 150
        )
        assert threat.threat_type == "REFLECTIVE_LOAD"
        assert threat.pid == 9012
        assert threat.risk_level == "HIGH"

    def test_hollowing_threat_builder(self):
        hollowing = {"indicator": "no_file_backed_executable_regions", "exec_region_count": 3, "exec_regions_anonymous": 3}
        threat = MemoryAnalyzer._create_hollowing_threat(
            3456, "svchost.exe", hollowing, 300
        )
        assert threat.threat_type == "PROCESS_HOLLOWING"
        assert threat.pid == 3456
        assert threat.risk_level == "CRITICAL"

    def test_high_map_threat_builder(self):
        threat = MemoryAnalyzer._create_high_map_threat(
            7890, "test.exe", 600
        )
        assert threat.threat_type == "HIGH_MAP_COUNT"
        assert threat.pid == 7890
        assert threat.risk_level == "MEDIUM"
        assert threat.action_taken == "LOG_AND_WATCH"


class TestJitExceptions:
    """Tests for JIT process exceptions (RWX allowed for JIT)."""

    @pytest.mark.parametrize("process_name", [
        "python3.10", "node.exe", "java", "dotnet",
        "chrome.exe", "firefox.exe",
    ])
    def test_jit_processes_in_allowlist(self, process_name):
        from config import RWX_ALLOWED_PROCESSES
        name_lower = process_name.lower()
        is_allowed = any(jit in name_lower for jit in RWX_ALLOWED_PROCESSES)
        assert is_allowed, f"{process_name} should be in RWX_ALLOWED_PROCESSES"
