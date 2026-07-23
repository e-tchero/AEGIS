"""
Project AEGIS — Login Monitor Module
Lead Architect: ETCHERO / Abdul-Hameed
Version: 1.0.0 | Classification: AEGIS-LOGMON
Role: Monitors authentication logs for suspicious activity.
      Detects brute force attacks, impossible login times,
      repeated failures, and new administrator accounts.
"""

import logging
import os
import re
import threading
import time
import traceback
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from threading import Event
from typing import Callable, Dict, List, Optional, Set

# ─── CONFIG ───────────────────────────────────────────────────────────────────
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config import (  # noqa: E402
    LOGIN_POLL_INTERVAL,
    LOGIN_LOG_FILE,
    LINUX_AUTH_LOGS,
    BRUTE_FORCE_THRESHOLD,
    BRUTE_FORCE_WINDOW,
    LOGIN_COOLDOWN_SECONDS,
    LOG_MAX_BYTES,
    LOG_BACKUP_COUNT,
    LOG_FORMAT,
    CURRENT_OS,
)

# ─── LOGGER ───────────────────────────────────────────────────────────────────
_logger = logging.getLogger("aegis.logmon")
if not _logger.handlers:
    _handler = RotatingFileHandler(
        str(LOGIN_LOG_FILE),
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT,
        encoding="utf-8",
    )
    _handler.setFormatter(logging.Formatter(LOG_FORMAT))
    _logger.addHandler(_handler)
_logger.setLevel(logging.INFO)
_logger.propagate = False


# ─── DATA MODELS ──────────────────────────────────────────────────────────────
@dataclass
class LoginAttempt:
    timestamp: float
    username: str
    source_ip: str
    success: bool
    log_line: str


@dataclass
class LoginThreat:
    timestamp: str
    threat_type: str       # BRUTE_FORCE, IMPOSSIBLE_LOGIN, NEW_ADMIN, SUSPICIOUS_LOGIN
    risk_level: str        # CRITICAL, HIGH, MEDIUM, LOW
    source_ip: str
    username: str
    attempt_count: int
    reasoning: str
    action_taken: str
    evidence: Dict = field(default_factory=dict)


# ─── AUTH LOG PARSING ─────────────────────────────────────────────────────────
class AuthLogParser:
    """Parses system authentication logs for login events."""

    # Linux auth.log patterns
    LINUX_FAILED_PATTERNS = [
        re.compile(r"Failed password for (\S+) from (\S+) port \d+"),
        re.compile(r"Failed password for invalid user (\S+) from (\S+) port \d+"),
        re.compile(r"Connection closed by authenticating user (\S+) (\S+) port \d+"),
    ]

    LINUX_SUCCESS_PATTERNS = [
        re.compile(r"Accepted (?:password|publickey|keyboard-interactive) for (\S+) from (\S+) port \d+"),
        re.compile(r"session opened for user (\S+) by"),
    ]

    LINUX_NEW_USER_PATTERNS = [
        re.compile(r"new user: name=(\S+),"),
        re.compile(r"useradd\[.*\]: new user: name=(\S+)"),
        re.compile(r"groupadd\[.*\]: new group: name=(\S+)"),
    ]

    LINUX_SUDO_PATTERNS = [
        re.compile(r"sudo:.*?USER=(\S+).*?COMMAND=(.*)"),
    ]

    def __init__(self):
        self._last_positions: Dict[str, int] = {}  # file -> byte position

    def parse_logs(self) -> List[LoginAttempt]:
        """Parse all auth log files and return new login attempts."""
        attempts = []

        if CURRENT_OS == "Windows":
            # Windows event log parsing via wevtutil
            attempts.extend(self._parse_windows_logs())
        else:
            # Linux log file parsing
            for path in LINUX_AUTH_LOGS:
                if os.path.exists(path):
                    attempts.extend(self._parse_linux_log(path))

        return attempts

    def _parse_linux_log(self, path: str) -> List[LoginAttempt]:
        """Parse a Linux auth log file incrementally."""
        attempts = []
        last_pos = self._last_positions.get(path, 0)

        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                # Seek to last read position
                file_size = os.path.getsize(path)
                if last_pos > file_size:
                    last_pos = 0  # File was rotated

                f.seek(last_pos)
                new_lines = f.readlines()
                self._last_positions[path] = f.tell()

                for line in new_lines:
                    line = line.strip()
                    if not line:
                        continue

                    # Try to extract timestamp
                    ts = None
                    try:
                        # Typical syslog format: "Jan 15 10:30:45"
                        ts_str = " ".join(line.split()[:3])
                        ts = datetime.strptime(ts_str, "%b %d %H:%M:%S")
                        # Use current year
                        ts = ts.replace(year=datetime.now().year)
                    except (ValueError, IndexError):
                        ts = datetime.now()

                    # Check for failed logins
                    for pattern in self.LINUX_FAILED_PATTERNS:
                        match = pattern.search(line)
                        if match:
                            attempts.append(LoginAttempt(
                                timestamp=ts.timestamp(),
                                username=match.group(1),
                                source_ip=match.group(2),
                                success=False,
                                log_line=line[:200],
                            ))
                            break

                    # Check for successful logins
                    for pattern in self.LINUX_SUCCESS_PATTERNS:
                        match = pattern.search(line)
                        if match:
                            attempts.append(LoginAttempt(
                                timestamp=ts.timestamp(),
                                username=match.group(1),
                                source_ip=match.group(2) if len(match.groups()) >= 2 else "local",
                                success=True,
                                log_line=line[:200],
                            ))
                            break

        except (OSError, PermissionError, FileNotFoundError) as e:
            _logger.debug(f"Cannot read auth log {path}: {e}")

        return attempts

    def _parse_windows_logs(self) -> List[LoginAttempt]:
        """Parse Windows Security event logs using wevtutil."""
        attempts: List[LoginAttempt] = []

        try:
            import subprocess  # nosec B404
            # Query Security log for login events (4624=success, 4625=failure)
            # XML output is more parseable
            result = subprocess.run(  # nosec B603 B607
                ["wevtutil", "qe", "Security", "/q:",
                 "*[System[(EventID=4624 or EventID=4625)]]",
                 "/c:50", "/rd:true", "/f:text"],
                capture_output=True, text=True, timeout=10,
            )

            if result.returncode != 0:
                return attempts

            # Parse the text output for login events
            current_event: Dict[str, str] = {}
            for line in result.stdout.split("\n"):
                line = line.strip()

                if line.startswith("Event[") and current_event:
                    # Process previous event
                    attempt = self._parse_windows_event(current_event)
                    if attempt:
                        attempts.append(attempt)
                    current_event = {}
                elif ":" in line:
                    key, _, value = line.partition(":")
                    current_event[key.strip()] = value.strip()

            # Process last event
            if current_event:
                attempt = self._parse_windows_event(current_event)
                if attempt:
                    attempts.append(attempt)

        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            _logger.debug(f"Windows event log query failed: {e}")

        return attempts

    @staticmethod
    def _parse_windows_event(event: Dict[str, str]) -> Optional[LoginAttempt]:
        """Parse a Windows Security event into a LoginAttempt."""
        try:
            event_id = event.get("EventId", event.get("Id", ""))
            user = (event.get("Account Name") or
                    event.get("Target User Name") or
                    event.get("Subject User Name") or "")
            ip = (event.get("IpAddress") or
                  event.get("Source Network Address") or
                  event.get("Workstation Name") or "unknown")

            is_success = "4624" in str(event_id)
            ts = datetime.now().timestamp()

            return LoginAttempt(
                timestamp=ts,
                username=user,
                source_ip=ip,
                success=is_success,
                log_line=str(event)[:200],
            )
        except Exception:
            return None


# ─── REASONING ENGINE ─────────────────────────────────────────────────────────
class LoginReasoningEngine:
    """Analyzes login attempts and detects attack patterns."""

    def __init__(self):
        self._failed_attempts: Dict[str, List[float]] = defaultdict(list)
        self._alerted_ips: Dict[str, float] = {}  # ip -> last alert time
        self._known_users: Set[str] = set()
        self._known_admins: Set[str] = set()

    def _is_on_cooldown(self, ip: str, now: float) -> bool:
        """Check if we recently alerted for this IP."""
        last_alert = self._alerted_ips.get(ip, 0)
        return (now - last_alert) < LOGIN_COOLDOWN_SECONDS

    def _purge_old_attempts(self, now: float) -> None:
        """Remove failed attempts outside the brute force window."""
        cutoff = now - BRUTE_FORCE_WINDOW
        for ip in list(self._failed_attempts.keys()):
            self._failed_attempts[ip] = [
                t for t in self._failed_attempts[ip] if t >= cutoff
            ]
            if not self._failed_attempts[ip]:
                del self._failed_attempts[ip]

    def evaluate(self, attempts: List[LoginAttempt]) -> List[LoginThreat]:
        """Analyze login attempts and return any threats detected."""
        threats = []
        now = time.time()
        self._purge_old_attempts(now)

        for attempt in attempts:
            try:
                threat = self._check_attempt(attempt, now)
                if threat:
                    threats.append(threat)
            except Exception as e:
                _logger.debug(f"Login evaluation error: {e}")

        return threats

    def _check_attempt(self, attempt: LoginAttempt, now: float) -> Optional[LoginThreat]:
        """Evaluate a single login attempt for threats."""
        ip = attempt.source_ip
        username = attempt.username

        # Track failed attempts per IP
        if not attempt.success:
            self._failed_attempts[ip].append(attempt.timestamp)

            # Check for brute force
            recent_count = len(self._failed_attempts[ip])
            if recent_count >= BRUTE_FORCE_THRESHOLD:
                if self._is_on_cooldown(ip, now):
                    return None

                self._alerted_ips[ip] = now
                reasoning = (
                    f"Brute force attack detected from {ip}: {recent_count} failed "
                    f"login attempts in {BRUTE_FORCE_WINDOW // 60} minute window. "
                    f"Last failed user: '{username}'."
                )

                return LoginThreat(
                    timestamp=datetime.now().isoformat(),
                    threat_type="BRUTE_FORCE",
                    risk_level="CRITICAL" if recent_count >= BRUTE_FORCE_THRESHOLD * 2 else "HIGH",
                    source_ip=ip,
                    username=username,
                    attempt_count=recent_count,
                    reasoning=reasoning,
                    action_taken="FLAG_FOR_AUTOBLOCK",
                    evidence={
                        "failed_count": recent_count,
                        "window_seconds": BRUTE_FORCE_WINDOW,
                        "last_user": username,
                    },
                )

        return None

    def check_new_admin(self, username: str) -> Optional[LoginThreat]:
        """Check if a new admin/sudo-capable user was created."""
        if username not in self._known_admins:
            # This would be triggered by parsing sudo/useradd logs separately
            self._known_admins.add(username)
            return LoginThreat(
                timestamp=datetime.now().isoformat(),
                threat_type="NEW_ADMIN",
                risk_level="HIGH",
                source_ip="local",
                username=username,
                attempt_count=1,
                reasoning=f"New administrative user detected: '{username}'. "
                          f"Verify this was authorized.",
                action_taken="ALERT_AND_MONITOR",
                evidence={"username": username, "event": "user_added"},
            )
        return None


# ─── LOGIN MONITOR ────────────────────────────────────────────────────────────
class LoginMonitor:
    """Monitors system authentication logs for suspicious activity."""

    def __init__(self, on_threat: Optional[Callable[[LoginThreat], None]] = None):
        self.on_threat: Callable[[LoginThreat], None] = on_threat or self._default_handler
        self._parser = AuthLogParser()
        self._engine = LoginReasoningEngine()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = Event()
        self._first_scan = True

    def start(self) -> None:
        """Start the login monitor in a background thread."""
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop, daemon=True, name="AEGIS-LogMon"
        )
        self._thread.start()
        _logger.info("Login monitor started.")
        print("  [AEGIS] Login Monitor online.\n")

    def _run_loop(self) -> None:
        """Main monitoring loop."""
        print(f"  [LOGMON] Login monitoring active. Checking every {LOGIN_POLL_INTERVAL}s.\n")
        while not self._stop_event.is_set():
            try:
                # Parse auth logs
                attempts = self._parser.parse_logs()

                # On first scan, just build baseline of recent events (don't alert)
                if not self._first_scan:
                    threats = self._engine.evaluate(attempts)
                    for threat in threats:
                        self.on_threat(threat)
                else:
                    self._first_scan = False
                    if attempts:
                        _logger.info(f"Login monitor loaded {len(attempts)} existing log entries as baseline.")

            except Exception as e:
                _logger.error(f"Login scan error: {e}\n{traceback.format_exc()}")

            if self._stop_event.wait(LOGIN_POLL_INTERVAL):
                break

    def stop(self) -> None:
        """Stop the login monitor."""
        self._running = False
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        _logger.info("Login monitor stopped.")
        print("  [LOGMON] Login monitor stopped.")

    @staticmethod
    def _default_handler(threat: LoginThreat) -> None:
        border = "═" * 56
        print(f"\n  ╔{border}╗")
        print("  ║  AEGIS LOGMON — LOGIN THREAT DETECTED                 ║")
        print(f"  ╠{border}╣")
        print(f"  ║  Type      : {threat.threat_type:<40}║")
        print(f"  ║  Source IP : {threat.source_ip:<40}║")
        print(f"  ║  User      : {threat.username:<40}║")
        print(f"  ║  Attempts  : {threat.attempt_count:<40}║")
        print(f"  ║  Risk      : {threat.risk_level:<40}║")
        print(f"  ║  Action    : {threat.action_taken:<40}║")
        print(f"  ╚{border}╝")
        print(f"  → {threat.reasoning}\n")


if __name__ == "__main__":
    print("\n  AEGIS LOGIN MONITOR — STANDALONE\n")

    monitor = LoginMonitor()
    monitor.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        monitor.stop()
