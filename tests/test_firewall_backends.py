"""Tests for the AEGIS Firewall Backend Abstraction Layer."""

import pytest

from modules.firewall_backends import (
    FirewallBackend,
    IptablesBackend,
    NftablesBackend,
    NetshBackend,
    PfBackend,
    SimulationBackend,
    detect_best_backend,
    BACKEND,
)


class TestFirewallBackendBase:
    """Tests for the abstract base class."""

    def test_abstract_cannot_instantiate(self):
        with pytest.raises(TypeError):
            FirewallBackend()  # type: ignore[abstract]

    def test_base_has_abstract_methods(self):
        assert hasattr(FirewallBackend, "block")
        assert hasattr(FirewallBackend, "unblock")
        assert hasattr(FirewallBackend, "set_lockdown")
        assert hasattr(FirewallBackend, "is_available")
        assert hasattr(FirewallBackend, "get_backend_rules")


@pytest.fixture
def sim_backend():
    """Create a fresh SimulationBackend for each test."""
    backend = SimulationBackend()
    backend.clear_blocked()
    return backend


class TestSimulationBackend:
    """Tests for the SimulationBackend (always available fallback)."""

    def test_name(self, sim_backend):
        assert sim_backend.name == "simulation"

    def test_is_available(self, sim_backend):
        assert sim_backend.is_available() is True

    def test_block(self, sim_backend):
        assert sim_backend.block("1.2.3.4") is True
        assert sim_backend.is_blocked("1.2.3.4") is True

    def test_block_multiple(self, sim_backend):
        assert sim_backend.block("1.1.1.1") is True
        assert sim_backend.block("2.2.2.2") is True
        assert sim_backend.block("3.3.3.3") is True
        assert sim_backend.blocked_count == 3

    def test_unblock(self, sim_backend):
        sim_backend.block("1.2.3.4")
        assert sim_backend.unblock("1.2.3.4") is True
        assert sim_backend.is_blocked("1.2.3.4") is False

    def test_unblock_nonexistent(self, sim_backend):
        assert sim_backend.unblock("9.9.9.9") is True
        assert sim_backend.is_blocked("9.9.9.9") is False

    def test_set_lockdown(self, sim_backend):
        assert sim_backend.set_lockdown(True) is True
        assert sim_backend.set_lockdown(False) is True

    def test_get_blocked_list(self, sim_backend):
        sim_backend.block("3.3.3.3")
        sim_backend.block("1.1.1.1")
        sim_backend.block("2.2.2.2")
        blocked = sim_backend.get_blocked()
        assert blocked == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]

    def test_clear_blocked(self, sim_backend):
        sim_backend.block("1.2.3.4")
        sim_backend.clear_blocked()
        assert sim_backend.blocked_count == 0

    def test_get_backend_rules(self, sim_backend):
        sim_backend.block("1.2.3.4")
        rules = sim_backend.get_backend_rules()
        assert len(rules) == 1
        assert "1.2.3.4" in rules[0]

    def test_blocked_count(self, sim_backend):
        assert sim_backend.blocked_count == 0
        sim_backend.block("1.2.3.4")
        assert sim_backend.blocked_count == 1

    def test_add_remove_blocked(self, sim_backend):
        sim_backend.add_blocked("1.2.3.4")
        assert sim_backend.is_blocked("1.2.3.4") is True
        sim_backend.remove_blocked("1.2.3.4")
        assert sim_backend.is_blocked("1.2.3.4") is False


class TestIptablesBackend:
    def test_name(self):
        backend = IptablesBackend()
        assert backend.name == "iptables"

    def test_is_available(self):
        backend = IptablesBackend()
        result = backend.is_available()
        assert isinstance(result, bool)


class TestNftablesBackend:
    def test_name(self):
        backend = NftablesBackend()
        assert backend.name == "nftables"

    def test_is_available(self):
        backend = NftablesBackend()
        result = backend.is_available()
        assert isinstance(result, bool)


class TestNetshBackend:
    def test_name(self):
        backend = NetshBackend()
        assert backend.name == "netsh"

    def test_is_available(self):
        backend = NetshBackend()
        result = backend.is_available()
        assert isinstance(result, bool)


class TestPfBackend:
    def test_name(self):
        backend = PfBackend()
        assert backend.name == "pf"

    def test_is_available(self):
        backend = PfBackend()
        result = backend.is_available()
        assert isinstance(result, bool)


class TestAutoDetection:
    def test_detect_best_backend_returns_backend(self):
        backend = detect_best_backend()
        assert backend is not None
        assert hasattr(backend, "block")
        assert hasattr(backend, "name")

    def test_detect_best_backend_with_preferred(self):
        backend = detect_best_backend("simulation")
        assert backend.name == "simulation"

    def test_detect_best_backend_with_invalid_preferred(self):
        backend = detect_best_backend("nonexistent_backend")
        assert backend is not None
        assert backend.name in ("simulation", "iptables", "nftables", "netsh", "pf")

    def test_global_backend_is_instantiated(self):
        assert BACKEND is not None
        assert hasattr(BACKEND, "name")
        assert BACKEND.name in ("simulation", "iptables", "nftables", "netsh", "pf")

    def test_backend_has_required_methods(self):
        for method in ["block", "unblock", "set_lockdown", "is_available",
                       "is_blocked", "get_blocked", "get_backend_rules"]:
            assert hasattr(BACKEND, method), f"BACKEND missing {method}"
