"""
Project AEGIS — Firewall Module (Multi-Platform)
Lead Architect: ETCHERO / Abdul-Hameed
Version: 1.2.0 | Classification: AEGIS-FIREWALL

Role: Cross-platform IP blocking abstraction.
      Supports iptables, nftables, Windows netsh advfirewall,
      macOS pf, and simulation mode.

      Auto-detects the best available backend at runtime.
      Full public API backward compatibility with v1.1.

Priority 8 — Multi-platform Backend:
  - Platform abstraction layer in modules/firewall_backends.py
  - Auto-detection: nftables → iptables → netsh → pf → simulation
  - Config override via FIREWALL_BACKEND in config.py
"""

import ipaddress
import json
import logging
import platform
import threading

from pathlib import Path
from typing import List, Set

# ─── CONFIG ───────────────────────────────────────────────────────────────────
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config import (  # noqa: E402
    SafeRotatingFileHandler,
    SIMULATION,
    ALLOWLIST_IPS,
    BLOCKED_IPS_FILE,
    MAX_BLOCKED_IPS,
    FIREWALL_LOG_FILE,
    LOG_MAX_BYTES,
    LOG_BACKUP_COUNT,
    LOG_FORMAT,
)

# ─── BACKEND IMPORT ───────────────────────────────────────────────────────────
from modules.firewall_backends import BACKEND, FirewallBackend  # noqa: E402

# ─── LOGGER SETUP ─────────────────────────────────────────────────────────────
_logger = logging.getLogger("aegis.firewall")
if not _logger.handlers:
    _handler = SafeRotatingFileHandler(
        str(FIREWALL_LOG_FILE),
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT,
        encoding="utf-8",
    )
    _handler.setFormatter(logging.Formatter(LOG_FORMAT))
    _logger.addHandler(_handler)
_logger.setLevel(logging.INFO)
_logger.propagate = False

# ─── CONSTANTS ────────────────────────────────────────────────────────────────
CURRENT_OS: str = platform.system()
SIM_LABEL: str = "[SIM]" if SIMULATION else "[LIVE]"

# ─── STATE ────────────────────────────────────────────────────────────────────
_blocked_ips: Set[str] = set()
_lock: threading.Lock = threading.Lock()
_lockdown_active: bool = False
_active_backend: FirewallBackend = BACKEND


# ─── IP VALIDATION ────────────────────────────────────────────────────────────
def is_valid_ip(ip: str) -> bool:
    """Validate an IP address string and check against allowlist.

    Returns True only if the IP is valid AND not in the allowlist.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        _logger.warning(f"Invalid IP address format: {ip}")
        return False

    # Check allowlist — never block these
    if ip in ALLOWLIST_IPS or str(addr) in ALLOWLIST_IPS:
        _logger.info(f"Skipping allowlisted IP: {ip}")
        return False

    # Prevent blocking link-local, multicast, broadcast, etc.
    if addr.is_loopback:
        _logger.warning(f"Refusing to block loopback address: {ip}")
        return False
    if addr.is_link_local:
        _logger.warning(f"Refusing to block link-local address: {ip}")
        return False
    if addr.is_multicast:
        _logger.warning(f"Refusing to block multicast address: {ip}")
        return False
    if addr.is_unspecified:
        _logger.warning(f"Refusing to block unspecified address: {ip}")
        return False
    if addr.is_reserved:
        _logger.warning(f"Refusing to block reserved address: {ip}")
        return False

    return True


# ─── PERSISTENCE ──────────────────────────────────────────────────────────────
def _load_blocked_ips() -> Set[str]:
    """Load previously blocked IPs from disk."""
    if not BLOCKED_IPS_FILE.exists():
        return set()
    try:
        data = json.loads(BLOCKED_IPS_FILE.read_text(encoding="utf-8"))
        valid = {ip for ip in data if is_valid_ip(ip)}
        _logger.info(f"Loaded {len(valid)} blocked IPs from {BLOCKED_IPS_FILE.name}")
        return valid
    except (json.JSONDecodeError, OSError) as e:
        _logger.error(f"Failed to load blocked IPs: {e}")
        return set()


def _save_blocked_ips() -> None:
    """Persist blocked IP set to disk."""
    try:
        BLOCKED_IPS_FILE.parent.mkdir(parents=True, exist_ok=True)
        BLOCKED_IPS_FILE.write_text(
            json.dumps(sorted(_blocked_ips), indent=2),
            encoding="utf-8",
        )
    except OSError as e:
        _logger.error(f"Failed to save blocked IPs: {e}")


def _sync_in_memory_from_backend() -> None:
    """Sync the in-memory block list and re-create firewall rules on restart.

    On first load, persisted IPs are re-applied to the active backend so that
    firewall rules survive AEGIS restarts (iptables rules are ephemeral).
    """
    global _blocked_ips  # noqa: PLW0603
    with _lock:
        persisted = _load_blocked_ips()
        backend_blocked = set(_active_backend.get_blocked())
        _blocked_ips = persisted | backend_blocked

    # Re-create firewall rules for IPs that are persisted but not in the backend
    for ip in persisted:
        if ip not in backend_blocked and not _active_backend.is_blocked(ip):
            _active_backend.block(ip)  # Actually create the firewall rule


# ─── CORE OPERATIONS ──────────────────────────────────────────────────────────
def block_ip(ip: str) -> bool:
    """Block an IP address using the active firewall backend.

    Supports iptables, nftables, Windows netsh, macOS pf, and simulation.
    Returns True on success, False on failure.
    """
    # Validate
    if not is_valid_ip(ip):
        print(f"  [FIREWALL] REJECTED invalid/allowlisted IP: {ip}")
        return False

    with _lock:
        if ip in _blocked_ips:
            print(f"  [FIREWALL] {ip} already blocked. Skipping.")
            return True

        # Safety cap
        if len(_blocked_ips) >= MAX_BLOCKED_IPS:
            _logger.error(f"Block list full ({MAX_BLOCKED_IPS} IPs). Cannot block {ip}.")
            print(f"  [FIREWALL] ERROR: Block list at capacity ({MAX_BLOCKED_IPS}).")
            return False

    # Delegate to backend (releases/re-acquires lock internally)
    success = _active_backend.block(ip)

    if success:
        with _lock:
            _blocked_ips.add(ip)
            _save_blocked_ips()
            backend_name = _active_backend.name
            msg = f"BLOCKED {ip} via {backend_name}"
            print(f"  [FIREWALL] {msg}")
            _logger.warning(msg)
    else:
        print(f"  [FIREWALL] ERROR: Failed to block {ip}")

    return success


def unblock_ip(ip: str) -> bool:
    """Unblock an IP address using the active firewall backend."""
    with _lock:
        if ip not in _blocked_ips:
            print(f"  [FIREWALL] {ip} not in block list.")
            return False

    success = _active_backend.unblock(ip)

    if success:
        with _lock:
            _blocked_ips.discard(ip)
            _save_blocked_ips()
            msg = f"UNBLOCKED {ip}"
            print(f"  [FIREWALL] {msg}")
            _logger.info(msg)
    else:
        print(f"  [FIREWALL] ERROR: Failed to unblock {ip}")

    return success


def get_blocked() -> List[str]:
    """Return a sorted list of all currently blocked IPs."""
    with _lock:
        return sorted(_blocked_ips)


def is_blocked(ip: str) -> bool:
    """Check if an IP is currently blocked."""
    with _lock:
        return ip in _blocked_ips


def block_count() -> int:
    """Return the number of currently blocked IPs."""
    with _lock:
        return len(_blocked_ips)


def dump_block_list() -> None:
    """Print the current block list to stdout with backend info."""
    with _lock:
        if not _blocked_ips:
            print("  [FIREWALL] Block list is empty.")
            return
        backend_name = _active_backend.name
        print(f"\n  [FIREWALL] Active block list ({len(_blocked_ips)} IPs):")
        print(f"  [FIREWALL] Backend: {backend_name}")
        for ip in sorted(_blocked_ips):
            live_label = f"(via {backend_name})" if backend_name != "simulation" else "(simulated)"
            print(f"    → {ip}  {live_label}")


def set_lockdown(active: bool) -> None:
    """Toggle lockdown mode using the active firewall backend.

    In lockdown mode, all non-allowlisted inbound traffic is blocked.
    """
    global _lockdown_active  # noqa: PLW0603

    success = _active_backend.set_lockdown(active)
    if success:
        _lockdown_active = active
        backend_name = _active_backend.name
        status = "ACTIVATED" if active else "DEACTIVATED"
        print(f"  [FIREWALL] Lockdown {status} via {backend_name}")
        _logger.warning(f"LOCKDOWN_{status} via {backend_name}")
    else:
        print(f"  [FIREWALL] ERROR: Failed to set lockdown via {_active_backend.name}")
        _logger.error("Lockdown failed")


def is_lockdown_active() -> bool:
    """Check whether lockdown mode is currently active."""
    return _lockdown_active


def clear_blocked() -> int:
    """Unblock every IP in the block list. Returns count of cleared IPs."""
    with _lock:
        ips = list(_blocked_ips)
        count = len(ips)
    # Release lock before unblocking (backends also acquire locks)
    for ip in ips:
        unblock_ip(ip)
    with _lock:
        _blocked_ips.clear()
        _save_blocked_ips()
    _logger.info(f"Cleared all {count} blocked IPs")
    return count


def get_backend_info() -> str:
    """Return the name of the active firewall backend."""
    return _active_backend.name


# ─── INIT ─────────────────────────────────────────────────────────────────────
# Sync persisted IPs with the backend on import
_sync_in_memory_from_backend()
