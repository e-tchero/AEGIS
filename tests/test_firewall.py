"""Unit tests for the AEGIS Firewall module."""

import json
import sys
import threading
from pathlib import Path
from typing import List

import pytest

# Ensure the project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from modules.firewall import (
    is_valid_ip,
    is_blocked,
    block_ip,
    unblock_ip,
    get_blocked,
    block_count,
    clear_blocked,
    set_lockdown,
    is_lockdown_active,
    get_backend_info,
    dump_block_list,
    _blocked_ips,
    _lock,
    _save_blocked_ips,
    _load_blocked_ips,
    _sync_in_memory_from_backend,
)


# ─── FIXTURES ─────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def reset_state():
    """Reset the global blocked IP set before each test."""
    with _lock:
        _blocked_ips.clear()
    yield
    with _lock:
        _blocked_ips.clear()


# ─── IP VALIDATION ────────────────────────────────────────────────────────────

class TestIsValidIP:
    def test_valid_public_ipv4(self):
        assert is_valid_ip("8.8.8.8") is True

    def test_valid_public_ipv6(self):
        assert is_valid_ip("2001:db8::1") is True

    def test_loopback_rejected(self):
        assert is_valid_ip("127.0.0.1") is False
        assert is_valid_ip("::1") is False

    def test_unspecified_rejected(self):
        assert is_valid_ip("0.0.0.0") is False
        assert is_valid_ip("::") is False

    def test_link_local_rejected(self):
        assert is_valid_ip("169.254.1.1") is False

    def test_multicast_rejected(self):
        assert is_valid_ip("224.0.0.1") is False

    def test_invalid_format(self):
        assert is_valid_ip("not-an-ip") is False
        assert is_valid_ip("999.999.999.999") is False
        assert is_valid_ip("") is False

    def test_private_ip_valid(self):
        """Private IPs should be valid for blocking (if not in allowlist)."""
        assert is_valid_ip("10.0.0.5") is True
        assert is_valid_ip("192.168.1.1") is True
        assert is_valid_ip("172.16.0.1") is True

    def test_allowlist_localhost(self):
        assert is_valid_ip("localhost") is False


# ─── BLOCK / UNBLOCK ─────────────────────────────────────────────────────────

class TestBlockUnblock:
    def test_block_valid_ip(self):
        assert block_ip("1.2.3.4") is True
        assert is_blocked("1.2.3.4") is True

    def test_block_invalid_ip(self):
        assert block_ip("invalid") is False
        assert is_blocked("invalid") is False

    def test_block_loopback(self):
        assert block_ip("127.0.0.1") is False
        assert is_blocked("127.0.0.1") is False

    def test_block_duplicate(self):
        assert block_ip("1.2.3.4") is True
        assert block_ip("1.2.3.4") is True  # Should succeed (idempotent)

    def test_unblock_existing(self):
        block_ip("1.2.3.4")
        assert unblock_ip("1.2.3.4") is True
        assert is_blocked("1.2.3.4") is False

    def test_unblock_nonexistent(self):
        assert unblock_ip("1.2.3.4") is False

    def test_get_blocked_order(self):
        block_ip("3.3.3.3")
        block_ip("1.1.1.1")
        block_ip("2.2.2.2")
        assert get_blocked() == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]

    def test_block_count(self):
        assert block_count() == 0
        block_ip("1.1.1.1")
        assert block_count() == 1
        block_ip("2.2.2.2")
        assert block_count() == 2

    def test_clear_blocked(self):
        block_ip("1.1.1.1")
        block_ip("2.2.2.2")
        cleared = clear_blocked()
        assert cleared == 2
        assert block_count() == 0

    def test_block_ipv6(self):
        assert block_ip("2001:db8::1") is True
        assert is_blocked("2001:db8::1") is True

    def test_clear_empty(self):
        cleared = clear_blocked()
        assert cleared == 0


# ─── LOCKDOWN ─────────────────────────────────────────────────────────────────

class TestLockdown:
    def test_lockdown_toggle(self):
        set_lockdown(True)
        set_lockdown(False)

    def test_is_lockdown_active(self):
        assert is_lockdown_active() is False
        set_lockdown(True)
        assert is_lockdown_active() is True
        set_lockdown(False)
        assert is_lockdown_active() is False


# ─── BACKEND INFO ─────────────────────────────────────────────────────────────

class TestBackendInfo:
    def test_get_backend_info(self):
        info = get_backend_info()
        assert isinstance(info, str)
        assert info in ("simulation", "iptables", "nftables", "netsh", "pf")

    def test_dump_block_list_no_crash(self):
        dump_block_list()
        block_ip("1.2.3.4")
        dump_block_list()


# ─── THREAD SAFETY ────────────────────────────────────────────────────────────

class TestThreadSafety:
    def test_concurrent_block(self):
        errors: List[Exception] = []

        def block_ip_safe(ip: str):
            try:
                block_ip(ip)
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=block_ip_safe, args=(f"10.0.0.{i}",))
            for i in range(50)
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Thread errors occurred: {errors}"
        assert block_count() == 50

    def test_concurrent_unblock(self):
        for i in range(20):
            block_ip(f"10.0.0.{i}")

        errors: List[Exception] = []

        def unblock_safe(ip: str):
            try:
                unblock_ip(ip)
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=unblock_safe, args=(f"10.0.0.{i}",))
            for i in range(20)
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Thread errors occurred: {errors}"
        assert block_count() == 0

    def test_concurrent_mixed_operations(self):
        errors: List[Exception] = []

        def worker():
            for i in range(10):
                try:
                    block_ip("10.0.0.1")
                    unblock_ip("10.0.0.1")
                except Exception as e:
                    errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors


# ─── PERSISTENCE ──────────────────────────────────────────────────────────────

class TestPersistence:
    def test_save_and_load_blocklist(self):
        # The persistence module requires specific files to exist
        block_ip("1.2.3.4")
        block_ip("5.6.7.8")
        # save happens automatically on block
        assert block_count() == 2
        import os
        from config import BLOCKED_IPS_FILE
        if BLOCKED_IPS_FILE.exists():
            assert BLOCKED_IPS_FILE.stat().st_size > 0

    def test_is_blocked_multiple(self):
        ips = ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
        for ip in ips:
            block_ip(ip)
        for ip in ips:
            assert is_blocked(ip)
        assert is_blocked("9.9.9.9") is False
