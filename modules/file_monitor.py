"""
Project AEGIS — File Integrity Monitor Module
Lead Architect: ETCHERO / Abdul-Hameed
Version: 1.0.0 | Classification: AEGIS-FIM
Role: Monitors critical system files for unauthorized changes.
      Uses SHA-256 hashing for baseline comparison.
      Watches Windows System32, Linux /etc, startup items, and more.
"""

import hashlib
import json
import logging
import os
import threading
import time
from dataclasses import dataclass, asdict, field
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from threading import Event
from typing import Callable, Dict, List, Optional

# ─── CONFIG ───────────────────────────────────────────────────────────────────
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config import (  # noqa: E402
    FILE_MONITOR_INTERVAL,
    FILE_LOG_FILE,
    FILE_BASELINE_FILE,
    WATCHED_PATHS_WINDOWS,
    WATCHED_PATHS_LINUX,
    LOG_MAX_BYTES,
    LOG_BACKUP_COUNT,
    LOG_FORMAT,
    CURRENT_OS,
)

# ─── LOGGER ───────────────────────────────────────────────────────────────────
_logger = logging.getLogger("aegis.fim")
if not _logger.handlers:
    _handler = RotatingFileHandler(
        str(FILE_LOG_FILE),
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
class FileRecord:
    path: str
    hash: str
    size: int
    modified_time: str
    first_seen: str


@dataclass
class FileThreat:
    timestamp: str
    threat_type: str       # FILE_CHANGED, FILE_DELETED, FILE_CREATED, HASH_MISMATCH
    risk_level: str        # CRITICAL, HIGH, MEDIUM, LOW
    file_path: str
    old_hash: str
    new_hash: str
    old_size: int
    new_size: int
    reasoning: str
    action_taken: str
    evidence: Dict = field(default_factory=dict)


# ─── FILE MONITOR ─────────────────────────────────────────────────────────────
class FileMonitor:
    """Monitors critical system files for integrity violations."""

    def __init__(self, on_threat: Optional[Callable[[FileThreat], None]] = None):
        self.on_threat: Callable[[FileThreat], None] = on_threat or self._default_handler
        self._baseline: Dict[str, FileRecord] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = Event()

        # Determine watched paths based on OS
        if CURRENT_OS == "Windows":
            self._watched_paths = WATCHED_PATHS_WINDOWS
        else:
            self._watched_paths = WATCHED_PATHS_LINUX

    # ── Hashing ────────────────────────────────────────────────────────────────

    @staticmethod
    def _hash_file(path: str) -> Optional[str]:
        """Compute SHA-256 hash of a file. Returns hex digest or None on error."""
        try:
            h = hashlib.sha256()
            with open(path, "rb", buffering=65536) as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    h.update(chunk)
            return h.hexdigest()
        except (OSError, PermissionError, FileNotFoundError):
            return None

    @staticmethod
    def _get_file_info(path: str) -> Optional[Dict]:
        """Get file metadata."""
        try:
            stat = os.stat(path)
            return {
                "size": stat.st_size,
                "modified_time": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            }
        except (OSError, FileNotFoundError):
            return None

    # ── Baseline Management ───────────────────────────────────────────────────

    def _load_baseline(self) -> Dict[str, FileRecord]:
        """Load the baseline file hash database from disk."""
        if not FILE_BASELINE_FILE.exists():
            _logger.info("No file baseline found — will create on first scan.")
            return {}
        try:
            data = json.loads(FILE_BASELINE_FILE.read_text(encoding="utf-8"))
            records = {}
            for path, record in data.items():
                records[path] = FileRecord(**record)
            _logger.info(f"Loaded baseline with {len(records)} file records.")
            return records
        except (json.JSONDecodeError, OSError, TypeError) as e:
            _logger.warning(f"Failed to load baseline: {e}. Starting fresh.")
            return {}

    def _save_baseline(self) -> None:
        """Save the current baseline to disk."""
        try:
            FILE_BASELINE_FILE.parent.mkdir(parents=True, exist_ok=True)
            data = {path: asdict(rec) for path, rec in self._baseline.items()}
            FILE_BASELINE_FILE.write_text(
                json.dumps(data, indent=2, default=str),
                encoding="utf-8",
            )
            _logger.info(f"Saved baseline with {len(self._baseline)} file records.")
        except OSError as e:
            _logger.error(f"Failed to save baseline: {e}")

    # ── Scanning ──────────────────────────────────────────────────────────────

    def _scan_file(self, path: str, now: str) -> Optional[FileThreat]:
        """Check a single file for integrity violations."""
        info = self._get_file_info(path)
        current_hash = self._hash_file(path) if info else None

        # File doesn't exist
        if info is None or current_hash is None:
            if path in self._baseline:
                # File was deleted
                old = self._baseline[path]
                del self._baseline[path]
                reasoning = f"Monitored file DELETED: {path}. Previously tracked with hash {old.hash[:16]}... "
                return FileThreat(
                    timestamp=now,
                    threat_type="FILE_DELETED",
                    risk_level="CRITICAL",
                    file_path=path,
                    old_hash=old.hash,
                    new_hash="",
                    old_size=old.size,
                    new_size=0,
                    reasoning=reasoning,
                    action_taken="ALERT_AND_MONITOR",
                    evidence={"previous_hash": old.hash[:16], "previous_size": old.size},
                )
            return None  # Never tracked before and doesn't exist now — skip

        # New file — add to baseline
        if path not in self._baseline:
            self._baseline[path] = FileRecord(
                path=path,
                hash=current_hash,
                size=info["size"],
                modified_time=info["modified_time"],
                first_seen=now,
            )
            return None

        # Existing file — check integrity
        baseline = self._baseline[path]
        if baseline.hash == current_hash:
            return None  # No change

        # Hash mismatch — file was modified
        reasoning = (
            f"File INTEGRITY VIOLATION: {path}\n"
            f"  Old hash: {baseline.hash[:16]}...\n"
            f"  New hash: {current_hash[:16]}...\n"
            f"  Old size: {baseline.size} bytes → New size: {info['size']} bytes\n"
            f"  Possible causes: unauthorized modification, malware patching, or system update."
        )

        # Update baseline
        self._baseline[path] = FileRecord(
            path=path,
            hash=current_hash,
            size=info["size"],
            modified_time=info["modified_time"],
            first_seen=baseline.first_seen,
        )

        return FileThreat(
            timestamp=now,
            threat_type="FILE_CHANGED",
            risk_level="HIGH",
            file_path=path,
            old_hash=baseline.hash,
            new_hash=current_hash,
            old_size=baseline.size,
            new_size=info["size"],
            reasoning=reasoning,
            action_taken="ALERT_AND_MONITOR",
            evidence={
                "old_hash_prefix": baseline.hash[:16],
                "new_hash_prefix": current_hash[:16],
                "size_delta": info["size"] - baseline.size,
                "modified_time": info["modified_time"],
            },
        )

    def _scan_all(self) -> List[FileThreat]:
        """Scan all watched paths and return any threats detected.

        Note: _scan_file() already handles FILE_DELETED for paths in _watched_paths.
        This loop also checks for files in baseline that were removed from the
        watched paths list (edge case where config changed between runs).
        """
        now = datetime.now().isoformat()
        threats = []

        # Scan all currently watched paths
        for path in self._watched_paths:
            try:
                threat = self._scan_file(path, now)
                if threat:
                    threats.append(threat)
            except Exception as e:
                _logger.error(f"Error scanning {path}: {e}")

        # Edge case: files in baseline that are no longer in _watched_paths
        # (e.g., config changed) — check if they still exist
        watched_set = set(self._watched_paths)
        for path in list(self._baseline.keys()):
            if path not in watched_set:
                if not os.path.exists(path):
                    threats.append(FileThreat(
                        timestamp=now,
                        threat_type="FILE_DELETED",
                        risk_level="CRITICAL",
                        file_path=path,
                        old_hash=self._baseline[path].hash,
                        new_hash="",
                        old_size=self._baseline[path].size,
                        new_size=0,
                        reasoning=f"Monitored file DELETED: {path}.",
                        action_taken="ALERT_AND_MONITOR",
                        evidence={"previous_hash": self._baseline[path].hash[:16]},
                    ))
                    del self._baseline[path]

        return threats

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start the file integrity monitor in a background thread."""
        if self._running:
            return
        self._baseline = self._load_baseline()
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop, daemon=True, name="AEGIS-FIM"
        )
        self._thread.start()
        _logger.info("File integrity monitor started.")
        print(f"  [AEGIS] File Integrity Monitor online. Watching {len(self._watched_paths)} paths.\n")

    def _run_loop(self) -> None:
        """Main monitoring loop."""
        print(f"  [FIM] File integrity scan active. Scanning every {FILE_MONITOR_INTERVAL}s.\n")
        while not self._stop_event.is_set():
            threats = self._scan_all()
            for threat in threats:
                self.on_threat(threat)
            self._save_baseline()
            if self._stop_event.wait(FILE_MONITOR_INTERVAL):
                break

    def stop(self) -> None:
        """Stop the file integrity monitor."""
        self._running = False
        self._stop_event.set()
        self._save_baseline()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        _logger.info("File integrity monitor stopped.")
        print("  [FIM] File integrity monitor stopped.")

    @staticmethod
    def _default_handler(threat: FileThreat) -> None:
        border = "═" * 56
        print(f"\n  ╔{border}╗")
        print("  ║  AEGIS FIM — FILE INTEGRITY ALERT                     ║")
        print(f"  ╠{border}╣")
        print(f"  ║  Event     : {threat.threat_type:<40}║")
        print(f"  ║  File      : {Path(threat.file_path).name:<40}║")
        print(f"  ║  Risk      : {threat.risk_level:<40}║")
        print(f"  ║  Action    : {threat.action_taken:<40}║")
        print(f"  ╚{border}╝")
        print(f"  → {threat.reasoning}\n")


if __name__ == "__main__":
    print("\n  AEGIS FILE INTEGRITY MONITOR — STANDALONE\n")

    monitor = FileMonitor()
    monitor.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        monitor.stop()
