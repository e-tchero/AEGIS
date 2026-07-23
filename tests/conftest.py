"""
Project AEGIS — Shared Test Fixtures and Utilities
"""

import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import pytest

# ─── Project path setup ───────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# ═══════════════════════════════════════════════════════════════════════════════
# MOCK THREAT DATACLASSES
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class MockNetworkThreat:
    """Simulates a network scan threat for incident correlation tests."""
    attacker_ip: str = "10.0.0.5"
    threat_type: str = "SYN_SCAN"
    risk_level: str = "MEDIUM"
    port_count: int = 25
    reasoning: str = "Port scan detected"


@dataclass
class MockProcessThreat:
    """Simulates a process-level threat for incident correlation tests."""
    pid: int = 1234
    process_name: str = "powershell.exe"
    threat_type: str = "REVERSE_SHELL"
    risk_level: str = "CRITICAL"
    cmdline: str = "powershell -enc SQBFAFgA"
    parent_pid: int = 888
    parent_name: str = "explorer.exe"
    username: str = "admin"
    reasoning: str = "Reverse shell detected"
    evidence: Dict = field(default_factory=dict)
    num_connections: int = 3


@dataclass
class MockMemoryThreat:
    """Simulates a memory-based threat."""
    pid: int = 5678
    process_name: str = "svchost.exe"
    threat_type: str = "RWX_MEMORY"
    risk_level: str = "CRITICAL"
    suspicious_count: int = 3
    reasoning: str = "RWX memory regions detected"


@dataclass
class MockDnsThreat:
    """Simulates a DNS-level threat."""
    domain: str = "malware.evil.c2.com"
    threat_type: str = "DNS_TUNNEL"
    risk_level: str = "HIGH"
    query_count: int = 100
    reasoning: str = "DNS tunneling detected"


@dataclass
class MockLoginThreat:
    """Simulates a login-level threat."""
    source_ip: str = "10.0.0.5"
    username: str = "admin"
    threat_type: str = "BRUTE_FORCE"
    risk_level: str = "HIGH"
    attempt_count: int = 15
    reasoning: str = "Brute force detected"


@dataclass
class MockFileThreat:
    """Simulates a file integrity threat."""
    file_path: str = "/etc/shadow"
    threat_type: str = "FILE_CHANGED"
    risk_level: str = "HIGH"
    old_hash: str = "abc123"
    new_hash: str = "def456"
    old_size: int = 1024
    new_size: int = 2048
    reasoning: str = "Critical file modified"


@dataclass
class MockCustomThreat:
    """Generic threat with all possible correlation fields."""
    attacker_ip: Optional[str] = "10.0.0.5"
    source_ip: Optional[str] = None
    pid: Optional[int] = None
    process_name: Optional[str] = None
    parent_pid: Optional[int] = None
    parent_name: Optional[str] = None
    file_path: Optional[str] = None
    username: Optional[str] = None
    threat_type: str = "UNKNOWN"
    risk_level: str = "LOW"
    reasoning: str = ""


# ═══════════════════════════════════════════════════════════════════════════════
# SHARED FIXTURES
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def sample_network_threat() -> MockNetworkThreat:
    return MockNetworkThreat()


@pytest.fixture
def sample_process_threat() -> MockProcessThreat:
    return MockProcessThreat()


@pytest.fixture
def sample_login_threat() -> MockLoginThreat:
    return MockLoginThreat()


@pytest.fixture
def sample_file_threat() -> MockFileThreat:
    return MockFileThreat()


@pytest.fixture
def sample_memory_threat() -> MockMemoryThreat:
    return MockMemoryThreat()


@pytest.fixture
def sample_dns_threat() -> MockDnsThreat:
    return MockDnsThreat()
