"""Tests for firewall_backends.py — Coverage booster for platform-specific backends.

Covers all backends (Iptables, Nftables, Netsh, Pf) by mocking subprocess.run
to simulate both success and failure paths. Also tests detect_best_backend()
with preferred and auto-detection modes.

Uses @patch decorators INSTEAD of sys.modules replacement to avoid
breaking RotatingFileHandler imports in other modules.
"""

import builtins
import subprocess
import shutil
from unittest.mock import patch, MagicMock

import pytest
import sys


# ─── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def reset_backend_state():
    """Reset shared class-level state between tests."""
    from modules.firewall_backends import FirewallBackend

    FirewallBackend._blocked.clear()
    yield
    FirewallBackend._blocked.clear()


# ═══════════════════════════════════════════════════════════════════════════════
# IPTABLES BACKEND
# ═══════════════════════════════════════════════════════════════════════════════


class TestIptablesBackend:
    """Tests for the IptablesBackend class (Linux legacy)."""

    @pytest.fixture
    def backend(self):
        from modules.firewall_backends import IptablesBackend

        return IptablesBackend(binary="iptables")

    def test_init_defaults(self):
        from modules.firewall_backends import IptablesBackend

        b = IptablesBackend()
        assert b._binary == "iptables"
        assert b._label == "[IPTABLES]"

    def test_init_custom_binary(self):
        from modules.firewall_backends import IptablesBackend

        b = IptablesBackend(binary="ip6tables")
        assert b._binary == "ip6tables"

    def test_name(self, backend):
        assert backend.name == "iptables"

    def test_block_success(self, backend):
        with patch.object(backend, "_run", return_value=True) as mock_run:
            result = backend.block("10.0.0.1")
            assert result is True
            mock_run.assert_called_once_with(["-A", "INPUT", "-s", "10.0.0.1", "-j", "DROP"])
            assert backend.is_blocked("10.0.0.1") is True

    def test_block_failure(self, backend):
        with patch.object(backend, "_run", return_value=False):
            result = backend.block("10.0.0.1")
            assert result is False
            assert backend.is_blocked("10.0.0.1") is False

    def test_unblock_success(self, backend):
        backend.add_blocked("10.0.0.1")
        with patch.object(backend, "_run", return_value=True) as mock_run:
            result = backend.unblock("10.0.0.1")
            assert result is True
            mock_run.assert_called_once_with(["-D", "INPUT", "-s", "10.0.0.1", "-j", "DROP"])
            assert backend.is_blocked("10.0.0.1") is False

    def test_unblock_not_blocked(self, backend):
        with patch.object(backend, "_run", return_value=True):
            result = backend.unblock("1.2.3.4")
            assert result is True

    def test_set_lockdown_active(self, backend):
        with patch.object(backend, "_run", return_value=True) as mock_run:
            result = backend.set_lockdown(True)
            assert result is True
            mock_run.assert_called_once_with(["-P", "INPUT", "DROP"])

    def test_set_lockdown_deactivate(self, backend):
        with patch.object(backend, "_run", return_value=True) as mock_run:
            result = backend.set_lockdown(False)
            assert result is True
            mock_run.assert_called_once_with(["-P", "INPUT", "ACCEPT"])

    def test_set_lockdown_failure(self, backend):
        with patch.object(backend, "_run", return_value=False):
            assert backend.set_lockdown(True) is False

    @patch("modules.firewall_backends.CURRENT_OS", "Linux")
    def test_is_available_linux_with_binary(self, backend):
        with patch.object(shutil, "which", return_value="/sbin/iptables"):
            assert backend.is_available() is True

    @patch("modules.firewall_backends.CURRENT_OS", "Windows")
    def test_is_available_wrong_os(self, backend):
        assert backend.is_available() is False

    @patch("modules.firewall_backends.CURRENT_OS", "Linux")
    def test_is_available_no_binary(self, backend):
        with patch.object(shutil, "which", return_value=None):
            assert backend.is_available() is False

    def test_get_backend_rules_success(self, backend):
        mock_result = MagicMock()
        mock_result.stdout = "Chain INPUT (policy ACCEPT)\ntarget prot opt source\n"
        mock_result.returncode = 0
        with patch.object(subprocess, "run", return_value=mock_result):
            rules = backend.get_backend_rules()
            assert len(rules) == 2
            assert "Chain INPUT" in rules[0]

    def test_get_backend_rules_exception(self, backend):
        with patch.object(subprocess, "run", side_effect=Exception("boom")):
            rules = backend.get_backend_rules()
            assert rules == []

    def test_run_calledprocesserror(self, backend):
        with patch.object(
            subprocess, "run", side_effect=subprocess.CalledProcessError(1, [], stderr="Permission denied\n")
        ):
            assert backend._run(["-L"]) is False

    def test_run_timeoutexpired(self, backend):
        with patch.object(subprocess, "run", side_effect=subprocess.TimeoutExpired([], timeout=5)):
            assert backend._run(["-L"]) is False

    def test_run_filenotfound(self, backend):
        with patch.object(subprocess, "run", side_effect=FileNotFoundError()):
            assert backend._run(["-L"]) is False

    def test_run_permissionerror(self, backend):
        with patch.object(subprocess, "run", side_effect=PermissionError()):
            assert backend._run(["-L"]) is False


# ═══════════════════════════════════════════════════════════════════════════════
# NFTABLES BACKEND
# ═══════════════════════════════════════════════════════════════════════════════


class TestNftablesBackend:
    """Tests for the NftablesBackend class (Linux modern)."""

    @pytest.fixture
    def backend(self):
        from modules.firewall_backends import NftablesBackend

        return NftablesBackend()

    def test_name(self, backend):
        assert backend.name == "nftables"

    @patch("modules.firewall_backends.CURRENT_OS", "Linux")
    def test_is_available_linux_success(self, backend):
        mock_result = MagicMock()
        mock_result.returncode = 0
        with patch.object(shutil, "which", return_value="/sbin/nft"):
            with patch.object(subprocess, "run", return_value=mock_result):
                assert backend.is_available() is True

    @patch("modules.firewall_backends.CURRENT_OS", "Windows")
    def test_is_available_wrong_os(self, backend):
        assert backend.is_available() is False

    @patch("modules.firewall_backends.CURRENT_OS", "Linux")
    def test_is_available_no_binary(self, backend):
        with patch.object(shutil, "which", return_value=None):
            assert backend.is_available() is False

    @patch("modules.firewall_backends.CURRENT_OS", "Linux")
    def test_is_available_nft_check_fails(self, backend):
        with patch.object(shutil, "which", return_value="/sbin/nft"):
            with patch.object(subprocess, "run", side_effect=Exception("nft error")):
                assert backend.is_available() is False

    def test_block_success(self, backend):
        with patch.object(backend, "_ensure_table", return_value=True):
            with patch.object(backend, "_run", return_value=True) as mock_run:
                result = backend.block("10.0.0.1")
                assert result is True
                mock_run.assert_called_once_with(
                    [
                        "add",
                        "rule",
                        "inet",
                        "aegis_block",
                        "aegis_input",
                        "ip saddr 10.0.0.1 drop",
                    ]
                )
                assert backend.is_blocked("10.0.0.1") is True

    def test_block_ensure_table_fails(self, backend):
        with patch.object(backend, "_ensure_table", return_value=False):
            result = backend.block("10.0.0.1")
            assert result is False

    def test_unblock_success(self, backend):
        backend.add_blocked("10.0.0.1")
        with patch.object(backend, "_ensure_table", return_value=True):
            with patch.object(backend, "_find_rule_handle", return_value="42"):
                with patch.object(backend, "_run", return_value=True) as mock_run:
                    result = backend.unblock("10.0.0.1")
                    assert result is True
                    mock_run.assert_called_once_with(
                        [
                            "delete",
                            "rule",
                            "inet",
                            "aegis_block",
                            "aegis_input",
                            "handle 42",
                        ]
                    )
                    assert backend.is_blocked("10.0.0.1") is False

    def test_unblock_rule_not_found(self, backend):
        with patch.object(backend, "_ensure_table", return_value=True):
            with patch.object(backend, "_find_rule_handle", return_value=None):
                result = backend.unblock("10.0.0.1")
                assert result is False

    def test_unblock_ensure_table_fails(self, backend):
        with patch.object(backend, "_ensure_table", return_value=False):
            result = backend.unblock("10.0.0.1")
            assert result is False

    def test_ensure_table_exists(self, backend):
        """_ensure_table returns True if table already exists."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        with patch.object(subprocess, "run", return_value=mock_result):
            assert backend._ensure_table() is True

    def test_ensure_table_creates(self, backend):
        """_ensure_table creates table + chain if they don't exist."""
        mock_result_fail = MagicMock()
        mock_result_fail.returncode = 1
        with patch.object(backend, "_run", return_value=True) as mock_run:
            with patch.object(subprocess, "run", return_value=mock_result_fail):
                result = backend._ensure_table()
                assert result is True
                assert mock_run.call_count == 2  # add table + add chain

    def test_find_rule_handle_found(self, backend):
        mock_result = MagicMock()
        mock_result.stdout = (
            "table inet aegis_block {\n"
            "  chain aegis_input {\n"
            "    ip saddr 10.0.0.1 drop # handle 42\n"
            "  }\n"
            "}\n"
        )
        with patch.object(subprocess, "run", return_value=mock_result):
            handle = backend._find_rule_handle("10.0.0.1")
            assert handle == "42"

    def test_find_rule_handle_not_found(self, backend):
        mock_result = MagicMock()
        mock_result.stdout = "table inet aegis_block { chain aegis_input { } }\n"
        with patch.object(subprocess, "run", return_value=mock_result):
            handle = backend._find_rule_handle("10.0.0.1")
            assert handle is None

    def test_find_rule_handle_exception(self, backend):
        with patch.object(subprocess, "run", side_effect=Exception("boom")):
            handle = backend._find_rule_handle("10.0.0.1")
            assert handle is None

    def test_set_lockdown_active(self, backend):
        with patch.object(backend, "_ensure_table", return_value=True):
            with patch.object(backend, "_run", return_value=True) as mock_run:
                result = backend.set_lockdown(True)
                assert result is True
                mock_run.assert_called_once_with(
                    [
                        "add",
                        "rule",
                        "inet",
                        "aegis_block",
                        "aegis_input",
                        "drop",
                    ]
                )

    def test_set_lockdown_deactivate_with_handle(self, backend):
        mock_result = MagicMock()
        mock_result.stdout = (
            "table inet aegis_block {\n"
            "  chain aegis_input {\n"
            "    drop # handle 99\n"
            "  }\n"
            "}\n"
        )
        with patch.object(backend, "_ensure_table", return_value=True):
            with patch.object(subprocess, "run", return_value=mock_result):
                with patch.object(backend, "_run", return_value=True):
                    result = backend.set_lockdown(False)
                    assert result is True

    def test_set_lockdown_deactivate_no_handle(self, backend):
        """When no handle found, should still return True."""
        mock_result = MagicMock()
        mock_result.stdout = "table inet aegis_block { chain aegis_input { } }\n"
        with patch.object(backend, "_ensure_table", return_value=True):
            with patch.object(subprocess, "run", return_value=mock_result):
                result = backend.set_lockdown(False)
                assert result is True

    def test_set_lockdown_ensure_table_fails(self, backend):
        with patch.object(backend, "_ensure_table", return_value=False):
            assert backend.set_lockdown(True) is False

    def test_get_backend_rules_success(self, backend):
        mock_result = MagicMock()
        mock_result.stdout = "table inet aegis_block {\n  chain aegis_input {\n  }\n}\n"
        with patch.object(subprocess, "run", return_value=mock_result):
            rules = backend.get_backend_rules()
            # 4 lines: table, chain, }, }
            assert len(rules) == 4

    def test_get_backend_rules_exception(self, backend):
        with patch.object(subprocess, "run", side_effect=Exception("boom")):
            rules = backend.get_backend_rules()
            assert rules == []

    def test_run_calledprocesserror(self, backend):
        with patch.object(
            subprocess, "run", side_effect=subprocess.CalledProcessError(1, [], stderr="Error: No such file\n")
        ):
            assert backend._run(["list", "tables"]) is False

    def test_run_timeout(self, backend):
        with patch.object(subprocess, "run", side_effect=subprocess.TimeoutExpired([], timeout=3)):
            assert backend._run(["list", "tables"]) is False

    def test_run_filenotfound(self, backend):
        with patch.object(subprocess, "run", side_effect=FileNotFoundError()):
            assert backend._run(["list", "tables"]) is False

    def test_run_permissionerror(self, backend):
        with patch.object(subprocess, "run", side_effect=PermissionError()):
            assert backend._run(["list", "tables"]) is False


# ═══════════════════════════════════════════════════════════════════════════════
# NETSH BACKEND (Windows)
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.skipif(sys.platform != "win32", reason="Netsh is Windows-only")
class TestNetshBackend:
    """Tests for the NetshBackend class (Windows)."""

    @pytest.fixture
    def backend(self):
        from modules.firewall_backends import NetshBackend

        return NetshBackend()

    def test_name(self, backend):
        assert backend.name == "netsh"

    def test_block_success(self, backend):
        with patch.object(backend, "_run", return_value=True) as mock_run:
            result = backend.block("192.168.1.100")
            assert result is True
            assert mock_run.called
            args = mock_run.call_args[0][0]
            assert "add" in args and "rule" in args
            assert "remoteip=192.168.1.100" in args
            assert backend.is_blocked("192.168.1.100") is True

    def test_unblock_success(self, backend):
        backend.add_blocked("192.168.1.100")
        with patch.object(backend, "_run", return_value=True) as mock_run:
            result = backend.unblock("192.168.1.100")
            assert result is True
            args = mock_run.call_args[0][0]
            assert "delete" in args
            assert "name=AEGIS_BLOCK_192.168.1.100" in args

    def test_set_lockdown_active(self, backend):
        with patch.object(backend, "_run", return_value=True) as mock_run:
            result = backend.set_lockdown(True)
            assert result is True
            args = mock_run.call_args[0][0]
            assert "blockinbound,allowoutbound" in " ".join(args)

    def test_set_lockdown_deactivate(self, backend):
        with patch.object(backend, "_run", return_value=True) as mock_run:
            result = backend.set_lockdown(False)
            assert result is True
            args = mock_run.call_args[0][0]
            assert "notconfigured" in " ".join(args)

    def test_set_lockdown_failure(self, backend):
        with patch.object(backend, "_run", return_value=False):
            assert backend.set_lockdown(True) is False

    @patch("modules.firewall_backends.CURRENT_OS", "Windows")
    def test_is_available_windows_admin(self, backend):
        with patch.object(shutil, "which", return_value="C:\\Windows\\System32\\netsh.exe"):
            with patch("ctypes.windll.shell32.IsUserAnAdmin", return_value=True):
                mock_result = MagicMock()
                mock_result.returncode = 0
                with patch.object(subprocess, "run", return_value=mock_result):
                    assert backend.is_available() is True

    @patch("modules.firewall_backends.CURRENT_OS", "Linux")
    def test_is_available_wrong_os(self, backend):
        assert backend.is_available() is False

    @patch("modules.firewall_backends.CURRENT_OS", "Windows")
    def test_is_available_no_netsh(self, backend):
        with patch.object(shutil, "which", return_value=None):
            assert backend.is_available() is False

    @patch("modules.firewall_backends.CURRENT_OS", "Windows")
    def test_is_available_not_admin(self, backend):
        with patch.object(shutil, "which", return_value="netsh.exe"):
            with patch("ctypes.windll.shell32.IsUserAnAdmin", return_value=False):
                assert backend.is_available() is False

    @patch("modules.firewall_backends.CURRENT_OS", "Windows")
    def test_is_available_ctypes_import_error(self, backend):
        with patch.object(shutil, "which", return_value="netsh.exe"):
            orig_import = builtins.__import__

            def mock_import(name, *args, **kwargs):
                if name == "ctypes":
                    raise ImportError("no ctypes")
                return orig_import(name, *args, **kwargs)

            with patch("builtins.__import__", side_effect=mock_import):
                assert backend.is_available() is False

    @patch("modules.firewall_backends.CURRENT_OS", "Windows")
    def test_is_available_subprocess_fails(self, backend):
        with patch.object(shutil, "which", return_value="netsh.exe"):
            with patch("ctypes.windll.shell32.IsUserAnAdmin", return_value=True):
                with patch.object(subprocess, "run", side_effect=subprocess.TimeoutExpired([], timeout=5)):
                    assert backend.is_available() is False

    def test_get_backend_rules_success(self, backend):
        mock_result = MagicMock()
        mock_result.stdout = "Rule Name: AEGIS_BLOCK_10.0.0.1\nEnabled: Yes\n"
        with patch.object(subprocess, "run", return_value=mock_result):
            rules = backend.get_backend_rules()
            assert len(rules) == 2

    def test_get_backend_rules_exception(self, backend):
        with patch.object(subprocess, "run", side_effect=Exception("boom")):
            rules = backend.get_backend_rules()
            assert rules == []

    def test_run_calledprocesserror(self, backend):
        error = subprocess.CalledProcessError(1, [], stderr="Access denied\n")
        with patch.object(subprocess, "run", side_effect=error):
            assert backend._run(["add", "rule", "name=test"]) is False

    def test_run_filenotfound(self, backend):
        with patch.object(subprocess, "run", side_effect=FileNotFoundError()):
            assert backend._run(["add", "rule"]) is False

    def test_run_timeout(self, backend):
        with patch.object(subprocess, "run", side_effect=subprocess.TimeoutExpired([], timeout=5)):
            assert backend._run(["add", "rule"]) is False

    def test_block_failure(self, backend):
        with patch.object(backend, "_run", return_value=False):
            result = backend.block("10.0.0.1")
            assert result is False

    def test_unblock_not_blocked(self, backend):
        with patch.object(backend, "_run", return_value=True):
            result = backend.unblock("10.0.0.99")
            assert result is True


# ═══════════════════════════════════════════════════════════════════════════════
# PF BACKEND (macOS/BSD)
# ═══════════════════════════════════════════════════════════════════════════════


class TestPfBackend:
    """Tests for the PfBackend class (macOS/BSD)."""

    @pytest.fixture
    def backend(self):
        from modules.firewall_backends import PfBackend

        return PfBackend()

    def test_name(self, backend):
        assert backend.name == "pf"

    @patch("modules.firewall_backends.CURRENT_OS", "Darwin")
    def test_is_available_darwin(self, backend):
        with patch.object(shutil, "which", return_value="/sbin/pfctl"):
            assert backend.is_available() is True

    @patch("modules.firewall_backends.CURRENT_OS", "Linux")
    def test_is_available_wrong_os(self, backend):
        assert backend.is_available() is False

    @patch("modules.firewall_backends.CURRENT_OS", "Darwin")
    def test_is_available_no_pfctl(self, backend):
        with patch.object(shutil, "which", return_value=None):
            assert backend.is_available() is False

    def test_block_success(self, backend):
        with patch.object(backend, "_ensure_anchor", return_value=True):
            with patch("tempfile.NamedTemporaryFile") as mock_temp:
                mock_file = MagicMock()
                mock_file.name = "/tmp/aegis_test.pf"
                mock_temp.return_value.__enter__.return_value = mock_file
                with patch.object(backend, "_run", return_value=True) as mock_run:
                    with patch("os.unlink"):
                        result = backend.block("10.0.0.1")
                        assert result is True
                        assert mock_run.called
                        args = mock_run.call_args[0][0]
                        assert "pfctl" in args
                        assert "aegis" in args

    def test_block_ensure_anchor_fails(self, backend):
        with patch.object(backend, "_ensure_anchor", return_value=False):
            assert backend.block("10.0.0.1") is False

    def test_block_exception(self, backend):
        with patch.object(backend, "_ensure_anchor", return_value=True):
            with patch("tempfile.NamedTemporaryFile", side_effect=Exception("disk full")):
                result = backend.block("10.0.0.1")
                assert result is False

    def test_unblock_success(self, backend):
        backend.add_blocked("10.0.0.1")
        backend.add_blocked("10.0.0.2")
        with patch.object(backend, "_ensure_anchor", return_value=True):
            with patch("tempfile.NamedTemporaryFile") as mock_temp:
                mock_file = MagicMock()
                mock_file.name = "/tmp/aegis_unblock.pf"
                mock_temp.return_value.__enter__.return_value = mock_file
                with patch.object(backend, "_run", return_value=True):
                    with patch("os.unlink"):
                        result = backend.unblock("10.0.0.1")
                        assert result is True
                        assert backend.is_blocked("10.0.0.1") is False
                        assert backend.is_blocked("10.0.0.2") is True

    def test_unblock_ensure_anchor_fails(self, backend):
        with patch.object(backend, "_ensure_anchor", return_value=False):
            assert backend.unblock("10.0.0.1") is False

    def test_unblock_exception(self, backend):
        backend.add_blocked("10.0.0.1")
        with patch.object(backend, "_ensure_anchor", return_value=True):
            with patch.object(backend, "_run", side_effect=Exception("pfctl error")):
                result = backend.unblock("10.0.0.1")
                assert result is False

    def test_set_lockdown_active(self, backend):
        with patch.object(backend, "_ensure_anchor", return_value=True):
            with patch("tempfile.NamedTemporaryFile") as mock_temp:
                mock_file = MagicMock()
                mock_file.name = "/tmp/aegis_lockdown.pf"
                mock_temp.return_value.__enter__.return_value = mock_file
                with patch.object(backend, "_run", return_value=True):
                    with patch("os.unlink"):
                        result = backend.set_lockdown(True)
                        assert result is True
                        assert "block in all" in mock_file.write.call_args[0][0]

    def test_set_lockdown_deactivate(self, backend):
        with patch.object(backend, "_ensure_anchor", return_value=True):
            with patch.object(backend, "_run", return_value=True) as mock_run:
                result = backend.set_lockdown(False)
                assert result is True
                args = mock_run.call_args[0][0]
                assert "-F" in args
                assert "all" in args

    def test_set_lockdown_ensure_anchor_fails(self, backend):
        with patch.object(backend, "_ensure_anchor", return_value=False):
            assert backend.set_lockdown(True) is False
            assert backend.set_lockdown(False) is False

    def test_set_lockdown_active_exception(self, backend):
        with patch.object(backend, "_ensure_anchor", return_value=True):
            with patch("tempfile.NamedTemporaryFile", side_effect=Exception("error")):
                assert backend.set_lockdown(True) is False

    def test_ensure_anchor_exists(self, backend):
        mock_result = MagicMock()
        mock_result.stdout = "aegis/aegis\ncom.apple/*\n"
        with patch.object(subprocess, "run", return_value=mock_result):
            assert backend._ensure_anchor() is True

    def test_ensure_anchor_creates(self, backend):
        mock_result_empty = MagicMock()
        mock_result_empty.stdout = "com.apple/*\n"
        with patch.object(subprocess, "run", return_value=mock_result_empty):
            with patch.object(backend, "_run", return_value=True):
                assert backend._ensure_anchor() is True

    def test_ensure_anchor_exception(self, backend):
        with patch.object(subprocess, "run", side_effect=Exception("pfctl error")):
            assert backend._ensure_anchor() is False

    def test_get_backend_rules_success(self, backend):
        mock_result = MagicMock()
        mock_result.stdout = "block in from 10.0.0.1 to any\n"
        with patch.object(subprocess, "run", return_value=mock_result):
            rules = backend.get_backend_rules()
            assert len(rules) == 1

    def test_get_backend_rules_exception(self, backend):
        with patch.object(subprocess, "run", side_effect=Exception("boom")):
            rules = backend.get_backend_rules()
            assert rules == []

    def test_run_calledprocesserror(self, backend):
        with patch.object(
            subprocess, "run", side_effect=subprocess.CalledProcessError(1, [], stderr="permission denied")
        ):
            assert backend._run(["pfctl", "-s", "info"]) is False

    def test_run_generic_exception(self, backend):
        with patch.object(subprocess, "run", side_effect=OSError("no such file")):
            assert backend._run(["pfctl"]) is False


# ═══════════════════════════════════════════════════════════════════════════════
# SIMULATION BACKEND
# ═══════════════════════════════════════════════════════════════════════════════


class TestSimulationBackendExtended:
    """Extended tests for SimulationBackend beyond existing tests."""

    @pytest.fixture
    def backend(self):
        from modules.firewall_backends import SimulationBackend

        return SimulationBackend()

    def test_block_prints_and_logs(self, backend, capsys):
        with patch("modules.firewall_backends._logger") as mock_logger:
            result = backend.block("10.0.0.1")
            assert result is True
            assert backend.is_blocked("10.0.0.1") is True
            mock_logger.info.assert_called_once()
            captured = capsys.readouterr()
            assert "Would block" in captured.out

    def test_unblock_prints_and_logs(self, backend, capsys):
        backend.add_blocked("10.0.0.1")
        with patch("modules.firewall_backends._logger") as mock_logger:
            result = backend.unblock("10.0.0.1")
            assert result is True
            mock_logger.info.assert_called_once()
            captured = capsys.readouterr()
            assert "Would unblock" in captured.out

    def test_set_lockdown_active(self, backend, capsys):
        with patch("modules.firewall_backends._logger") as mock_logger:
            result = backend.set_lockdown(True)
            assert result is True
            mock_logger.info.assert_called_once()
            captured = capsys.readouterr()
            assert "ACTIVATE" in captured.out

    def test_set_lockdown_deactivate(self, backend, capsys):
        with patch("modules.firewall_backends._logger") as mock_logger:
            result = backend.set_lockdown(False)
            assert result is True
            mock_logger.info.assert_called_once()
            captured = capsys.readouterr()
            assert "DEACTIVATE" in captured.out

    def test_get_backend_rules_with_blocked(self, backend):
        backend.add_blocked("10.0.0.1")
        backend.add_blocked("10.0.0.2")
        rules = backend.get_backend_rules()
        assert len(rules) == 2
        assert "[SIM]" in rules[0]

    def test_is_available(self, backend):
        assert backend.is_available() is True

    def test_blocked_count_property(self, backend):
        assert backend.blocked_count == 0
        backend.add_blocked("10.0.0.1")
        assert backend.blocked_count == 1

    def test_clear_blocked(self, backend):
        backend.add_blocked("10.0.0.1")
        backend.add_blocked("10.0.0.2")
        backend.clear_blocked()
        assert backend.blocked_count == 0

    def test_get_blocked_sorted(self, backend):
        backend.add_blocked("10.0.0.5")
        backend.add_blocked("10.0.0.1")
        blocked = backend.get_blocked()
        assert blocked == ["10.0.0.1", "10.0.0.5"]


# ═══════════════════════════════════════════════════════════════════════════════
# AUTO-DETECTION
# ═══════════════════════════════════════════════════════════════════════════════


class TestDetectBestBackend:
    """Tests for the detect_best_backend() auto-detection logic."""

    def test_preferred_nftables_available(self):
        from modules.firewall_backends import detect_best_backend, NftablesBackend

        with patch.object(NftablesBackend, "is_available", return_value=True):
            backend = detect_best_backend(preferred="nftables")
            assert isinstance(backend, NftablesBackend)

    def test_preferred_nftables_unavailable_fallsback(self):
        from modules.firewall_backends import detect_best_backend, IptablesBackend

        with patch.object(IptablesBackend, "is_available", return_value=True):
            with patch("modules.firewall_backends.NftablesBackend.is_available", return_value=False):
                backend = detect_best_backend(preferred="nftables")
                assert isinstance(backend, IptablesBackend)

    def test_preferred_simulation(self):
        from modules.firewall_backends import detect_best_backend, SimulationBackend

        backend = detect_best_backend(preferred="simulation")
        assert isinstance(backend, SimulationBackend)

    def test_preferred_unknown_ignored(self):
        from modules.firewall_backends import detect_best_backend, SimulationBackend, IptablesBackend

        with patch.object(IptablesBackend, "is_available", return_value=False):
            with patch("modules.firewall_backends.NftablesBackend.is_available", return_value=False):
                with patch("modules.firewall_backends.NetshBackend.is_available", return_value=False):
                    with patch("modules.firewall_backends.PfBackend.is_available", return_value=False):
                        backend = detect_best_backend(preferred="nonexistent")
                        assert isinstance(backend, SimulationBackend)

    def test_auto_detect_nftables(self):
        from modules.firewall_backends import detect_best_backend, NftablesBackend

        with patch.object(NftablesBackend, "is_available", return_value=True):
            backend = detect_best_backend()
            assert isinstance(backend, NftablesBackend)

    def test_auto_detect_iptables(self):
        from modules.firewall_backends import detect_best_backend, IptablesBackend

        with patch.object(IptablesBackend, "is_available", return_value=True):
            with patch("modules.firewall_backends.NftablesBackend.is_available", return_value=False):
                backend = detect_best_backend()
                assert isinstance(backend, IptablesBackend)

    def test_auto_detect_netsh(self):
        from modules.firewall_backends import detect_best_backend, NetshBackend

        with patch.object(NetshBackend, "is_available", return_value=True):
            with patch("modules.firewall_backends.NftablesBackend.is_available", return_value=False):
                with patch("modules.firewall_backends.IptablesBackend.is_available", return_value=False):
                    backend = detect_best_backend()
                    assert isinstance(backend, NetshBackend)

    def test_auto_detect_pf(self):
        from modules.firewall_backends import detect_best_backend, PfBackend

        with patch.object(PfBackend, "is_available", return_value=True):
            with patch("modules.firewall_backends.NftablesBackend.is_available", return_value=False):
                with patch("modules.firewall_backends.IptablesBackend.is_available", return_value=False):
                    with patch("modules.firewall_backends.NetshBackend.is_available", return_value=False):
                        backend = detect_best_backend()
                        assert isinstance(backend, PfBackend)

    def test_auto_detect_simulation_fallback(self):
        from modules.firewall_backends import detect_best_backend, SimulationBackend

        with patch("modules.firewall_backends.NftablesBackend.is_available", return_value=False):
            with patch("modules.firewall_backends.IptablesBackend.is_available", return_value=False):
                with patch("modules.firewall_backends.NetshBackend.is_available", return_value=False):
                    with patch("modules.firewall_backends.PfBackend.is_available", return_value=False):
                        backend = detect_best_backend()
                        assert isinstance(backend, SimulationBackend)

    def test_detect_best_backend_prints_and_logs(self, capsys):
        from modules.firewall_backends import detect_best_backend, SimulationBackend

        with patch("modules.firewall_backends.NftablesBackend.is_available", return_value=False):
            with patch("modules.firewall_backends.IptablesBackend.is_available", return_value=False):
                with patch("modules.firewall_backends.NetshBackend.is_available", return_value=False):
                    with patch("modules.firewall_backends.PfBackend.is_available", return_value=False):
                        backend = detect_best_backend()
                        assert isinstance(backend, SimulationBackend)
                        captured = capsys.readouterr()
                        assert "simulation" in captured.out.lower()
