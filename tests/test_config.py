"""Tests for the AEGIS central configuration module.

Verifies that all configuration constants are valid, consistent,
and have sensible ranges.
"""

import pytest

import config as cfg


class TestPaths:
    def test_base_dir_exists(self):
        assert cfg.BASE_DIR.exists()
        assert cfg.BASE_DIR.is_dir()

    def test_log_dir_created(self):
        assert cfg.LOG_DIR.exists()
        assert cfg.LOG_DIR.is_dir()

    def test_config_dir_created(self):
        assert cfg.CONFIG_DIR.exists()
        assert cfg.CONFIG_DIR.is_dir()


class TestMode:
    def test_current_os_is_string(self):
        assert isinstance(cfg.CURRENT_OS, str)
        assert len(cfg.CURRENT_OS) > 0

    def test_simulation_is_bool(self):
        assert isinstance(cfg.SIMULATION, bool)

    def test_mode_label_is_string(self):
        assert isinstance(cfg.MODE_LABEL, str)
        assert cfg.MODE_LABEL in ("SIMULATION", "LIVE")


class TestHeartbeatConfig:
    def test_pulse_interval_positive(self):
        assert cfg.PULSE_INTERVAL > 0

    def test_cpu_thresholds_ordered(self):
        assert cfg.CPU_ELEVATED_THRESHOLD < cfg.CPU_DANGER_THRESHOLD

    def test_ram_thresholds_ordered(self):
        assert cfg.RAM_ELEVATED_THRESHOLD < cfg.RAM_DANGER_THRESHOLD

    def test_net_thresholds_positive(self):
        assert cfg.NET_SPIKE_THRESHOLD > 0
        assert cfg.NET_FLOOD_THRESHOLD > 0
        assert cfg.NET_FLOOD_THRESHOLD > cfg.NET_SPIKE_THRESHOLD


class TestFirewallConfig:
    def test_allowlist_contains_localhost(self):
        assert "127.0.0.1" in cfg.ALLOWLIST_IPS
        assert "localhost" in cfg.ALLOWLIST_IPS

    def test_max_blocked_ips_positive(self):
        assert cfg.MAX_BLOCKED_IPS > 0

    def test_firewall_timeout_positive(self):
        assert cfg.FIREWALL_TIMEOUT > 0


class TestIncidentManagerConfig:
    def test_correlation_timeout_positive(self):
        assert cfg.CORRELATION_TIMEOUT_SECONDS > 0

    def test_auto_close_minutes_positive(self):
        assert cfg.AUTO_CLOSE_MINUTES > 0

    def test_max_incident_events_positive(self):
        assert cfg.MAX_INCIDENT_EVENTS > 0


class TestProcessMonitorConfig:
    def test_poll_interval_positive(self):
        assert cfg.PROCESS_POLL_INTERVAL > 0

    def test_miner_threshold_valid(self):
        assert 0 < cfg.MINER_CPU_THRESHOLD <= 100

    def test_suspicious_process_names(self):
        assert len(cfg.SUSPICIOUS_PROCESS_NAMES) > 0
        assert "powershell" in cfg.SUSPICIOUS_PROCESS_NAMES

    def test_known_good_chains(self):
        assert len(cfg.KNOWN_GOOD_CHAINS) > 0
        assert ("explorer.exe", "cmd.exe") in cfg.KNOWN_GOOD_CHAINS

    def test_lolbins(self):
        assert len(cfg.LOLBINS) > 0
        assert "regsvr32" in cfg.LOLBINS

    def test_suspicious_cmdline_structure(self):
        assert len(cfg.SUSPICIOUS_CMDLINE_SUBSTRINGS) > 0
        for group_name, group_cfg in cfg.SUSPICIOUS_CMDLINE_SUBSTRINGS.items():
            assert "patterns" in group_cfg
            assert "risk" in group_cfg
            assert len(group_cfg["patterns"]) > 0


class TestDnsMonitorConfig:
    def test_entropy_threshold_valid(self):
        assert 2.0 <= cfg.DNS_ENTROPY_THRESHOLD <= 5.0

    def test_beaconing_thresholds_positive(self):
        assert cfg.DNS_BEACON_QUERY_THRESHOLD > 0
        assert cfg.DNS_BEACON_WINDOW > 0

    def test_txt_thresholds_positive(self):
        assert cfg.DNS_TXT_QUERY_THRESHOLD > 0
        assert cfg.DNS_TXT_WINDOW > 0

    def test_tunnel_thresholds_positive(self):
        assert cfg.DNS_TUNNEL_QUERY_THRESHOLD > 0
        assert cfg.DNS_TUNNEL_WINDOW > 0

    def test_large_response_threshold_positive(self):
        assert cfg.DNS_LARGE_RESPONSE_THRESHOLD > 0

    def test_entropy_whitelist(self):
        assert len(cfg.DNS_ENTROPY_WHITELIST) > 0
        assert ".cloudfront.net" in cfg.DNS_ENTROPY_WHITELIST


class TestMemoryMonitorConfig:
    def test_poll_interval_positive(self):
        assert cfg.MEMORY_POLL_INTERVAL > 0

    def test_suspicious_permissions(self):
        assert "rwx" in cfg.SUSPICIOUS_PERMISSIONS
        assert "rwxp" in cfg.SUSPICIOUS_PERMISSIONS

    def test_known_legitimate_modules(self):
        assert len(cfg.KNOWN_LEGITIMATE_MODULES) > 0
        assert "ntdll.dll" in cfg.KNOWN_LEGITIMATE_MODULES

    def test_rwx_allowed_processes(self):
        assert len(cfg.RWX_ALLOWED_PROCESSES) > 0
        assert "python" in cfg.RWX_ALLOWED_PROCESSES


class TestDashboardConfig:
    def test_ws_port_valid(self):
        assert 1024 <= cfg.DASHBOARD_WS_PORT <= 65535

    def test_dashboard_poll_interval_positive(self):
        assert cfg.DASHBOARD_POLL_INTERVAL > 0


class TestLoggingConfig:
    def test_log_max_bytes_positive(self):
        assert cfg.LOG_MAX_BYTES > 0

    def test_log_backup_count_positive(self):
        assert cfg.LOG_BACKUP_COUNT > 0

    def test_log_format_contains_placeholders(self):
        assert "%(asctime)s" in cfg.LOG_FORMAT
        assert "%(message)s" in cfg.LOG_FORMAT


class TestScanPatterns:
    def test_all_scan_types_defined(self):
        for scan_type in ("SYN_SCAN", "FIN_SCAN", "XMAS_SCAN", "NULL_SCAN", "UDP_SCAN"):
            assert scan_type in cfg.SCAN_PATTERNS

    def test_scan_patterns_have_description(self):
        for scan_type, pattern in cfg.SCAN_PATTERNS.items():
            assert "description" in pattern

    def test_scan_patterns_have_threshold(self):
        for scan_type, pattern in cfg.SCAN_PATTERNS.items():
            assert pattern.get("threshold", 0) > 0


class TestNotifications:
    def test_notify_on_levels(self):
        assert "CRITICAL" in cfg.NOTIFY_ON_LEVELS
        assert "HIGH" in cfg.NOTIFY_ON_LEVELS
