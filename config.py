"""
Project AEGIS — Centralized Configuration
Lead Architect: ETCHERO / Abdul-Hameed
Version: 1.1.0 | Classification: AEGIS-CONFIG

All tunable parameters live here — no more hardcoded values in modules.
"""

import os
import platform
import shutil
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path

# ─── PATHS ───────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent
LOG_DIR  = BASE_DIR / "logs"
CONFIG_DIR = BASE_DIR / "config"
CONFIG_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)

# ─── OS / MODE ────────────────────────────────────────────────────────────────
CURRENT_OS = platform.system()
SIMULATION = CURRENT_OS != "Linux"
MODE_LABEL = "SIMULATION" if SIMULATION else "LIVE"

# ─── HEARTBEAT CONFIG ─────────────────────────────────────────────────────────
PULSE_INTERVAL = 10          # seconds between health checks
CPU_DANGER_THRESHOLD = 85    # percent
CPU_ELEVATED_THRESHOLD = 60  # percent
RAM_DANGER_THRESHOLD = 90    # percent
RAM_ELEVATED_THRESHOLD = 75  # percent
NET_SPIKE_THRESHOLD = 50     # MB/s — outbound exfil suspicion
NET_FLOOD_THRESHOLD = 100    # MB/s — inbound DDoS suspicion
HEALTH_LOG_FILE = LOG_DIR / "aegis_health.log"

# ─── SENTINEL CONFIG ──────────────────────────────────────────────────────────
SCAN_WINDOW_SECONDS = 5      # sliding window for port tracking
PORT_HIT_THRESHOLD  = 10     # min distinct ports to trigger alert
ALERT_COOLDOWN_SECONDS = 15  # silence period per IP after alert
SENTINEL_LOG_FILE = LOG_DIR / "sentinel.log"
SNIFFER_FILTER = "tcp or udp"

# ─── FIREWALL CONFIG ──────────────────────────────────────────────────────────
# IPs/ranges that must never be blocked
ALLOWLIST_IPS: set = {
    "127.0.0.1",
    "::1",
    "0.0.0.0",  # nosec B104
    "localhost",
}

BLOCKED_IPS_FILE = CONFIG_DIR / "blocked_ips.json"
MAX_BLOCKED_IPS = 5000        # safety cap

FIREWALL_LOG_FILE = LOG_DIR / "firewall.log"
FIREWALL_BACKEND_LOG_FILE = LOG_DIR / "firewall_backend.log"

FIREWALL_TIMEOUT = 8          # seconds for firewall commands
FIREWALL_BACKEND = None       # Set to "iptables", "nftables", "netsh", "pf", or "simulation" to override auto-detect

# ─── AEGIS CORE CONFIG ────────────────────────────────────────────────────────
HIGH_RISK_TIMEOUT = 5         # seconds before auto-blocking HIGH risk
AEGIS_LOG_FILE = LOG_DIR / "aegis_master.log"
LOGIC_LOOP_SLEEP = 0.5        # seconds between threat queue polls

# ─── INCIDENT MANAGER CONFIG ──────────────────────────────────────────────────
INCIDENT_LOG_FILE = LOG_DIR / "incidents.log"
CORRELATION_TIMEOUT_SECONDS = 300  # time window for correlating related events (5 min)
AUTO_CLOSE_MINUTES = 30            # close incidents after inactivity
MAX_INCIDENT_EVENTS = 100          # max events per incident before trimming

# ─── EVIDENCE ENGINE CONFIG ───────────────────────────────────────────────────
EVIDENCE_DIR = LOG_DIR / "evidence"
EVIDENCE_MAX_FILES = 1000          # max evidence JSON files to keep on disk

# ─── LOGGING CONFIG ───────────────────────────────────────────────────────────
LOG_MAX_BYTES = 5 * 1024 * 1024   # 5 MB per log file
LOG_BACKUP_COUNT = 3              # keep 3 rotated backups
LOG_FORMAT = "%(asctime)s | %(levelname)s | %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# ─── DETECTION PATTERNS ───────────────────────────────────────────────────────
# Packets that are NOT caught by the generic SYN flag check
SCAN_PATTERNS = {
    "SYN_SCAN": {
        "description": "Standard TCP SYN scan (stealth scan)",
        "tcp_flags_check": "syn and not ack",
        "threshold": PORT_HIT_THRESHOLD,
    },
    "FIN_SCAN": {
        "description": "TCP FIN scan — bypasses some firewalls",
        "tcp_flags_check": "fin and not syn and not rst and not ack",
        "threshold": PORT_HIT_THRESHOLD,
    },
    "XMAS_SCAN": {
        "description": "TCP Xmas scan (FIN+PSH+URG) — evades stateless filters",
        "tcp_flags_check": "fin and psh and urg",
        "threshold": PORT_HIT_THRESHOLD // 2,  # more suspicious, lower threshold
    },
    "NULL_SCAN": {
        "description": "TCP Null scan — no flags set, evades some IDS",
        "tcp_flags_check": "not syn and not ack and not fin and not rst and not psh and not urg",
        "threshold": PORT_HIT_THRESHOLD // 2,
    },
    "UDP_SCAN": {
        "description": "UDP port scan — slower but detects UDP services",
        "protocol": "udp",
        "threshold": PORT_HIT_THRESHOLD,
    },
}

# ─── PROCESS MONITOR CONFIG ───────────────────────────────────────────────────
PROCESS_POLL_INTERVAL = 5        # seconds between process scans
PROCESS_LOG_FILE = LOG_DIR / "process_monitor.log"

# Suspicious process name patterns (case-insensitive substring match)
SUSPICIOUS_PROCESS_NAMES = [
    "powershell", "cmd.exe", "wscript", "cscript", "mshta",
    "regsvr32", "rundll32", "certutil", "bitsadmin",
    "schtasks", "at.exe", "sc.exe", "wmic", "xcopy",
    "nc.exe", "ncat", "netcat", "socat",
]

# Known good parent->child process chains (e.g., explorer.exe spawning cmd.exe is OK)
# Format: {(parent_name_lower, child_name_lower)}
KNOWN_GOOD_CHAINS = {
    ("explorer.exe", "cmd.exe"),
    ("explorer.exe", "powershell.exe"),
    ("cmd.exe", "powershell.exe"),
    ("svchost.exe", "cmd.exe"),
    ("services.exe", "svchost.exe"),
    ("winlogon.exe", "logonui.exe"),
}

# Processes that should NEVER have network connections
NO_NET_PROCESSES = [
    "notepad.exe", "calc.exe", "mspaint.exe", "wordpad.exe",
]

# CPU threshold for crypto miner suspicion (sustained %)
MINER_CPU_THRESHOLD = 50
MINER_CPU_SAMPLES = 3            # consecutive samples above threshold to confirm

# Temp directories that are suspicious for executable running
SUSPICIOUS_DIRECTORIES = [
    "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",  # nosec B108
    "/tmp/", "/dev/shm/", "/var/tmp/",  # nosec B108
]

# ─── FILE MONITOR CONFIG ──────────────────────────────────────────────────────
FILE_MONITOR_INTERVAL = 60       # seconds between integrity scans
FILE_LOG_FILE = LOG_DIR / "file_monitor.log"
FILE_BASELINE_FILE = CONFIG_DIR / "file_baseline.json"

# Critical paths to monitor per platform
WATCHED_PATHS_WINDOWS = [
    # System32 core binaries
    "C:\\Windows\\System32\\cmd.exe",
    "C:\\Windows\\System32\\powershell.exe",
    "C:\\Windows\\System32\\svchost.exe",
    # Startup
    "C:\\Windows\\System32\\GroupPolicy\\Machine\\Registry.pol",
    # Hosts file
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
]

WATCHED_PATHS_LINUX = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/hosts",
    "/etc/crontab",
    "/etc/ssh/sshd_config",
    "/bin/bash",
    "/bin/sh",
    "/usr/bin/sudo",
    "/usr/bin/ssh",
]

# ─── LOGIN MONITOR CONFIG ─────────────────────────────────────────────────────
LOGIN_POLL_INTERVAL = 10         # seconds between log checks
LOGIN_LOG_FILE = LOG_DIR / "login_monitor.log"

# Linux auth log paths to watch
LINUX_AUTH_LOGS = [
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/syslog",
]

# Thresholds
BRUTE_FORCE_THRESHOLD = 5        # failed attempts before alerting
BRUTE_FORCE_WINDOW = 300         # seconds window for brute force detection (5 min)
LOGIN_COOLDOWN_SECONDS = 60      # silence period per IP after login alert

# ─── COMMAND LINE DETECTION CONFIG (Priority 4) ─────────────────────────────
# Suspicious command-line patterns for detecting malicious execution
# Each entry maps a pattern name to its detection rules

# LOLBins (Living Off the Land Binaries) commonly abused by attackers
LOLBINS = [
    "regsvr32", "rundll32", "certutil", "mshta", "bitsadmin",
    "cscript", "wscript", "wmic", "msiexec", "reg.exe",
    "sc.exe", "schtasks", "at.exe", "bcdedit",
]

# PowerShell flags that indicate hidden or encoded execution
HIDDEN_EXECUTION_FLAGS = [
    "-windowstyle hidden", "-w hidden", "-window hidden",
    "-executionpolicy bypass", "-ep bypass",
    "-noprofile", "-noni", "-noninteractive",
    "-encodedcommand", "-enc",
    "-command", "-c",
]

# Suspicious command-line substrings (case-insensitive match)
SUSPICIOUS_CMDLINE_SUBSTRINGS = {
    "encoded_powershell": {
        "patterns": ["-enc ", "-encodedcommand ", "-e ", "-ec ", "base64"],
        "risk": "HIGH",
        "description": "Base64-encoded PowerShell command (often used to obfuscate malicious intent)",
    },
    "hidden_execution": {
        "patterns": [
            "-windowstyle hidden", "-w hidden",
            "-executionpolicy bypass", "-ep bypass",
        ],
        "risk": "MEDIUM",
        "description": "Hidden or bypass execution — common in malware droppers",
    },
    "remote_download": {
        "patterns": [
            "curl | bash", "curl | sh", "wget | bash", "wget | sh",
            "invoke-webrequest", "iwr ", "invoke-restmethod", "irm ",
            "webclient.download", "system.net.webclient",
            "invoke-expression", "iex ",
            "start-bitstransfer", "bitsadmin /transfer",
        ],
        "risk": "CRITICAL",
        "description": "Remote download and execute pattern — common in malware loaders",
    },
    "suspicious_powershell": {
        "patterns": [
            "-noprofile -command", "-nop -command",
            "-windowstyle hidden -command",
            "frombase64string", "compress", "decompress",
        ],
        "risk": "HIGH",
        "description": "Suspicious PowerShell invocation with obfuscation indicators",
    },
    "lolbin_redirect": {
        "patterns": [
            "regsvr32 /s", "regsvr32 /i",
            "rundll32 javascript:", "rundll32 http://",
            "mshta http://", "mshta https://",
            "certutil -urlcache", "certutil -decode",
            "cscript //nologo", "msiexec /q", "msiexec /quiet",
        ],
        "risk": "HIGH",
        "description": "LOLBin used for script execution or download — bypasses application whitelisting",
    },
}

# ─── AI ANALYST CONFIG (Priority 7) ──────────────────────────────────────────
AI_LOG_FILE = LOG_DIR / "ai_analyst.log"

# ─── MEMORY MONITOR CONFIG (Priority 5) ──────────────────────────────────────
MEMORY_POLL_INTERVAL = 10         # seconds between memory scans
MEMORY_LOG_FILE = LOG_DIR / "memory_monitor.log"

# RWX memory threshold: max allowed RWX regions before flagging
# Legitimate processes may have 1-2 RWX regions (JIT compilers)
MEMORY_RWX_THRESHOLD = 3

# Suspicious memory permission patterns
# rwx = Read-Write-Execute (highly suspicious for shellcode)
# rwxp = Read-Write-Execute-Private (even more suspicious)
SUSPICIOUS_PERMISSIONS = {"rwx", "rwxp", "rwxk"}

# Max number of memory maps for a process before flagging (injection indicator)
MEMORY_MAP_COUNT_THRESHOLD = 500

# Suspicious DLL/module names commonly used in injection
SUSPICIOUS_INJECTION_MODULES = [
    # Known injected DLLs
    "mimilib.dll", "mimikatz", "pwh.dll",
    "hook.dll", "inject.dll", "reflective.dll",
    # Loaded from suspicious paths
    "/temp/", "/tmp/", "\\temp\\", "\\tmp\\",  # nosec B108
    "/appdata/", "\\appdata\\",  # nosec B108
    "/users/", "/home/",
]

# Known legitimate modules/binaries (never flag these)
KNOWN_LEGITIMATE_MODULES = [
    # Windows system DLLs
    "ntdll.dll", "kernel32.dll", "kernelbase.dll",
    "user32.dll", "gdi32.dll", "advapi32.dll",
    "ole32.dll", "oleaut32.dll", "combase.dll",
    "winhttp.dll", "ws2_32.dll", "dnsapi.dll",
    "bcrypt.dll", "sechost.dll", "rpcrt4.dll",
    "msvcrt.dll", "ucrtbase.dll", "vcruntime",
    "shlwapi.dll", "shell32.dll", "shcore.dll",
    "imm32.dll", "comctl32.dll", "uxtheme.dll",
    "clbcatq.dll", "crypt32.dll", "wintrust.dll",
    # Linux
    "libc.so", "libc-", "ld-linux", "ld-musl",
    "libpthread", "libm.so", "libdl.so",
    "libssl.so", "libcrypto.so",
]

# Processes by name that are allowed to have RWX memory (e.g., JIT compilers)
RWX_ALLOWED_PROCESSES = [
    # JIT compilers
    "python", "python3", "node.exe", "node",
    "java.exe", "java", "javaw.exe",
    "dotnet.exe", "dotnet",
    "chrome.exe", "msedge.exe", "firefox.exe",
]

# ─── DNS MONITOR CONFIG (Priority 6) ───────────────────────────────────────
DNS_LOG_FILE = LOG_DIR / "dns_monitor.log"
DNS_POLL_INTERVAL = 3         # seconds between DNS traffic checks

# Entropy threshold for DGA/tunneling detection (Shannon entropy per character)
# Legitimate domains typically < 3.5, DGA/tunneling often > 4.0
DNS_ENTROPY_THRESHOLD = 3.8

# Query size thresholds for tunneling detection (bytes)
DNS_QUERY_SIZE_THRESHOLD = 255     # Standard DNS max is ~255 bytes
DNS_RESPONSE_SIZE_THRESHOLD = 512   # Standard DNS UDP max is 512 bytes

# Beaconing detection: query frequency threshold per domain
# If a domain receives > N queries within the window, flag as beaconing
DNS_BEACON_QUERY_THRESHOLD = 10
DNS_BEACON_WINDOW = 60             # seconds window for beaconing detection

# TXT abuse detection
DNS_TXT_QUERY_THRESHOLD = 5        # TXT queries within window before alerting
DNS_TXT_WINDOW = 300                # seconds window for TXT tracking

# Tunneling detection
DNS_TUNNEL_QUERY_THRESHOLD = 20    # total queries to single domain within window
DNS_TUNNEL_WINDOW = 60             # seconds window

# Alert cooldown per domain to reduce noise
DNS_ALERT_COOLDOWN = 120           # seconds

# Large DNS responses (possible exfil via DNS tunneling)
DNS_LARGE_RESPONSE_THRESHOLD = 1000  # bytes

# High-entropy domain suffix whitelist (CDN, cloud providers with random subdomains)
DNS_ENTROPY_WHITELIST = [
    ".akamaihd.net", ".cloudfront.net", ".azureedge.net",
    ".s3.amazonaws.com", ".r2.dev", ".fastly.net",
    ".trafficmanager.net", ".azure.com", ".microsoft.com",
    ".google.com", ".youtube.com", ".googlevideo.com",
]

# ─── DASHBOARD SERVER CONFIG (Priority 9) ─────────────────────────────────────
DASHBOARD_WS_HOST = "0.0.0.0"        # nosec B104 — Bind address for WebSocket server
DASHBOARD_WS_PORT = 8765              # WebSocket port
DASHBOARD_LOG_FILE = LOG_DIR / "dashboard.log"
DASHBOARD_POLL_INTERVAL = 3           # seconds between state broadcasts
DASHBOARD_LOG_MAX_BYTES = 5 * 1024 * 1024
DASHBOARD_LOG_BACKUP_COUNT = 3

# ─── SAFE ROTATING FILE HANDLER ─────────────────────────────────────────────
class SafeRotatingFileHandler(RotatingFileHandler):
    """RotatingFileHandler that gracefully handles Windows PermissionError
    during log rotation by retrying with backoff and falling back to
    copytruncate-style rotation on Windows.
    """

    MAX_RETRIES = 3
    RETRY_DELAY = 0.2  # seconds

    def doRollover(self):
        """Override doRollover with retry logic for Windows file locks."""
        for attempt in range(self.MAX_RETRIES):
            try:
                super().doRollover()
                return
            except PermissionError:
                if attempt < self.MAX_RETRIES - 1:
                    time.sleep(self.RETRY_DELAY * (attempt + 1))
                else:
                    self._copytruncate_rollover()

    def _copytruncate_rollover(self):
        """Fallback rotation strategy: copy file and truncate original.
        Works on Windows because it does not require renaming an open file.
        """
        try:
            self.close()
            base_filename = self.baseFilename
            for i in range(self.backupCount - 1, 0, -1):
                src = f"{base_filename}.{i}"
                dst = f"{base_filename}.{i + 1}"
                if os.path.exists(src):
                    if os.path.exists(dst):
                        os.remove(dst)
                    shutil.copy2(src, dst)
            if os.path.exists(base_filename):
                dst = f"{base_filename}.1"
                if os.path.exists(dst):
                    os.remove(dst)
                shutil.copy2(base_filename, dst)
            with open(base_filename, "w"):
                pass
            self.stream = open(base_filename, "a", encoding=self.encoding)
        except Exception:
            if self.stream:
                self.stream.close()
            self.stream = open(self.baseFilename, "a", encoding=self.encoding)

# ─── NOTIFICATIONS ────────────────────────────────────────────────────────────
NOTIFY_ON_LEVELS = {"CRITICAL", "HIGH"}  # which threat levels trigger notifications
DISCORD_WEBHOOK_URL = ""   # set via env or config override
SLACK_WEBHOOK_URL = ""     # set via env or config override
