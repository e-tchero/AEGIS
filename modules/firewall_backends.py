"""
Project AEGIS — Firewall Backend Abstraction Layer
Lead Architect: ETCHERO / Abdul-Hameed
Version: 1.0.0 | Classification: AEGIS-BACKEND
Role: Provides a unified interface for IP blocking across platforms.
      Supports iptables, nftables, Windows netsh advfirewall,
      macOS pf, and simulation mode.

      Auto-detects the best available backend at runtime.
      New backends can be registered without changing the core.
"""

import abc
import logging
import os
import shutil
import subprocess  # nosec B404
import threading

from pathlib import Path
from typing import List, Optional, Set, Type

# ─── CONFIG ───────────────────────────────────────────────────────────────────
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config import (  # noqa: E402
    SafeRotatingFileHandler,
    FIREWALL_BACKEND,
    FIREWALL_TIMEOUT,
    FIREWALL_BACKEND_LOG_FILE,
    LOG_MAX_BYTES,
    LOG_BACKUP_COUNT,
    LOG_FORMAT,
    CURRENT_OS,
)

# ─── LOGGER SETUP ─────────────────────────────────────────────────────────────
_logger = logging.getLogger("aegis.firewall.backend")
if not _logger.handlers:
    _handler = SafeRotatingFileHandler(
        str(FIREWALL_BACKEND_LOG_FILE),
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT,
        encoding="utf-8",
    )
    _handler.setFormatter(logging.Formatter(LOG_FORMAT))
    _logger.addHandler(_handler)
_logger.setLevel(logging.INFO)
_logger.propagate = False


# ─── BACKEND INTERFACE ────────────────────────────────────────────────────────

class FirewallBackend(abc.ABC):
    """Abstract base class for all firewall backends."""

    name: str = "abstract"
    _blocked: Set[str] = set()
    _lock: threading.Lock = threading.Lock()

    @abc.abstractmethod
    def block(self, ip: str) -> bool:
        """Block an IP address. Returns True on success."""
        ...

    @abc.abstractmethod
    def unblock(self, ip: str) -> bool:
        """Unblock an IP address. Returns True on success."""
        ...

    @abc.abstractmethod
    def set_lockdown(self, active: bool) -> bool:
        """Toggle lockdown mode (block all inbound). Returns True on success."""
        ...

    @abc.abstractmethod
    def is_available(self) -> bool:
        """Check if this backend can be used on the current system."""
        ...

    @abc.abstractmethod
    def get_backend_rules(self) -> List[str]:
        """Return current rules from the system firewall for this backend."""
        ...

    def get_blocked(self) -> List[str]:
        """Return sorted list of blocked IPs maintained by this backend."""
        with self._lock:
            return sorted(self._blocked)

    def add_blocked(self, ip: str) -> None:
        """Track a blocked IP in memory."""
        with self._lock:
            self._blocked.add(ip)

    def remove_blocked(self, ip: str) -> None:
        """Remove an IP from the in-memory block list."""
        with self._lock:
            self._blocked.discard(ip)

    def clear_blocked(self) -> None:
        """Clear the in-memory block list."""
        with self._lock:
            self._blocked.clear()

    @property
    def blocked_count(self) -> int:
        with self._lock:
            return len(self._blocked)

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            return ip in self._blocked


# ─── IPTABLES BACKEND (Linux legacy) ──────────────────────────────────────────

class IptablesBackend(FirewallBackend):
    """Backend using iptables (Linux legacy firewalling)."""

    name = "iptables"

    def __init__(self, binary: str = "iptables"):
        self._binary = binary
        self._sudo = "sudo"
        self._label = "[IPTABLES]"

    def _run(self, args: List[str], timeout: int = FIREWALL_TIMEOUT) -> bool:
        cmd = [self._sudo, self._binary] + args
        try:
            subprocess.run(  # nosec B603
                cmd, check=True, capture_output=True, text=True, timeout=timeout,
            )
            return True
        except subprocess.CalledProcessError as e:
            _logger.error(f"{self._label} command failed: {' '.join(cmd)} — {e.stderr.strip()}")
            return False
        except subprocess.TimeoutExpired:
            _logger.error(f"{self._label} timed out after {timeout}s")
            return False
        except FileNotFoundError:
            _logger.error(f"{self._label} binary not found: {self._binary}")
            return False
        except PermissionError:
            _logger.error(f"{self._label} permission denied — is sudo configured?")
            return False

    def is_available(self) -> bool:
        if CURRENT_OS != "Linux":
            return False
        binary_path = shutil.which(self._binary)
        return binary_path is not None

    def block(self, ip: str) -> bool:
        if self._run(["-A", "INPUT", "-s", ip, "-j", "DROP"]):
            self.add_blocked(ip)
            _logger.info(f"{self._label} BLOCKED {ip}")
            return True
        return False

    def unblock(self, ip: str) -> bool:
        if self._run(["-D", "INPUT", "-s", ip, "-j", "DROP"]):
            self.remove_blocked(ip)
            _logger.info(f"{self._label} UNBLOCKED {ip}")
            return True
        return False

    def set_lockdown(self, active: bool) -> bool:
        target = "DROP" if active else "ACCEPT"
        if self._run(["-P", "INPUT", target]):
            status = "ACTIVATED" if active else "DEACTIVATED"
            _logger.warning(f"{self._label} LOCKDOWN_{status}")
            return True
        return False

    def get_backend_rules(self) -> List[str]:
        try:
            result = subprocess.run(  # nosec B603
                [self._sudo, self._binary, "-L", "INPUT", "-n"],
                capture_output=True, text=True, timeout=FIREWALL_TIMEOUT,
            )
            return result.stdout.strip().split("\n") if result.stdout else []
        except Exception:
            return []


# ─── NFTABLES BACKEND (Linux modern) ──────────────────────────────────────────

class NftablesBackend(FirewallBackend):
    """Backend using nftables (Linux modern firewalling)."""

    name = "nftables"

    def __init__(self):
        self._sudo = "sudo"
        self._label = "[NFTABLES]"
        self._table = "aegis_block"
        self._chain = "aegis_input"

    def _run(self, args: List[str], timeout: int = FIREWALL_TIMEOUT) -> bool:
        cmd = [self._sudo, "nft"] + args
        try:
            subprocess.run(  # nosec B603
                cmd, check=True, capture_output=True, text=True, timeout=timeout,
            )
            return True
        except subprocess.CalledProcessError as e:
            _logger.error(f"{self._label} command failed — {e.stderr.strip()}")
            return False
        except subprocess.TimeoutExpired:
            _logger.error(f"{self._label} timed out")
            return False
        except FileNotFoundError:
            _logger.error(f"{self._label} binary not found: nft")
            return False
        except PermissionError:
            _logger.error(f"{self._label} permission denied")
            return False

    def is_available(self) -> bool:
        if CURRENT_OS != "Linux":
            return False
        nft_path = shutil.which("nft")
        if not nft_path:
            return False
        # Check if nftables is the active firewall backend
        try:
            result = subprocess.run(
                [self._sudo, "nft", "list", "tables"],  # nosec B603
                capture_output=True, text=True, timeout=3,
            )
            return result.returncode == 0
        except Exception:
            _logger.debug("Failed to list nft tables")
            return False

    def _ensure_table(self) -> bool:
        """Create the AEGIS nftables table and chain if they don't exist."""
        # Check if table exists
        check = subprocess.run(  # nosec B603
            [self._sudo, "nft", "list", "table", "inet", self._table],
            capture_output=True, timeout=3,
        )
        if check.returncode == 0:
            return True
        # Create table and chain
        return self._run([
            "add", "table", "inet", self._table,
        ]) and self._run([
            "add", "chain", "inet", self._table, self._chain,
            "{ type filter hook input priority 0; policy accept; }",
        ])

    def block(self, ip: str) -> bool:
        if not self._ensure_table():
            return False
        rule = f"ip saddr {ip} drop"
        if self._run(["add", "rule", "inet", self._table, self._chain, rule]):
            self.add_blocked(ip)
            _logger.info(f"{self._label} BLOCKED {ip}")
            return True
        return False

    def unblock(self, ip: str) -> bool:
        if not self._ensure_table():
            return False
        handle = self._find_rule_handle(ip)
        if handle is None:
            _logger.warning(f"{self._label} rule not found for {ip}")
            return False
        if self._run(["delete", "rule", "inet", self._table, self._chain, f"handle {handle}"]):
            self.remove_blocked(ip)
            _logger.info(f"{self._label} UNBLOCKED {ip}")
            return True
        return False

    def _find_rule_handle(self, ip: str) -> Optional[str]:
        """Find the nftables rule handle for a given IP."""
        try:
            result = subprocess.run(  # nosec B603
                [self._sudo, "nft", "-a", "list", "chain", "inet", self._table, self._chain],
                capture_output=True, text=True, timeout=FIREWALL_TIMEOUT,
            )
            for line in result.stdout.split("\n"):
                if ip in line and "drop" in line.lower():
                    parts = line.split("handle")
                    if len(parts) > 1:
                        return parts[-1].strip()
            return None
        except Exception:
            _logger.debug("Failed to find rule handle for %s", ip)
            return None

    def set_lockdown(self, active: bool) -> bool:
        if not self._ensure_table():
            return False
        if active:
            return self._run([
                "add", "rule", "inet", self._table, self._chain,
                "drop",  # Default drop
            ])
        else:
            # Remove the default drop rule
            try:
                result = subprocess.run(  # nosec B603
                    [self._sudo, "nft", "-a", "list", "chain", "inet", self._table, self._chain],
                    capture_output=True, text=True, timeout=FIREWALL_TIMEOUT,
                )
                for line in result.stdout.split("\n"):
                    if "drop" in line.lower() and "saddr" not in line.lower():
                        parts = line.split("handle")
                        if len(parts) > 1:
                            handle = parts[-1].strip()
                            self._run(["delete", "rule", "inet", self._table, self._chain,
                                       f"handle {handle}"])
                            break
            except Exception:
                _logger.debug("Failed to clear lockdown rules")
            return True

    def get_backend_rules(self) -> List[str]:
        try:
            result = subprocess.run(  # nosec B603
                [self._sudo, "nft", "list", "chain", "inet", self._table, self._chain],
                capture_output=True, text=True, timeout=FIREWALL_TIMEOUT,
            )
            return result.stdout.strip().split("\n") if result.stdout else []
        except Exception:
            _logger.debug("Failed to get nftables rules")
            return []


# ─── NETSH BACKEND (Windows) ──────────────────────────────────────────────────

class NetshBackend(FirewallBackend):
    """Backend using netsh advfirewall (Windows Firewall)."""

    name = "netsh"

    def __init__(self):
        self._label = "[NETSH]"
        self._rule_prefix = "AEGIS_BLOCK_"

    def _run(self, args: List[str], timeout: int = FIREWALL_TIMEOUT) -> bool:
        cmd = ["netsh", "advfirewall", "firewall"] + args
        try:
            subprocess.run(  # nosec B603
                cmd, check=True, capture_output=True, text=True, timeout=timeout,
            )
            return True
        except subprocess.CalledProcessError as e:
            _logger.error(f"{self._label} command failed — {e.stderr or e.stdout}")
            return False
        except FileNotFoundError:
            _logger.error(f"{self._label} netsh not found on this system")
            return False
        except subprocess.TimeoutExpired:
            _logger.error(f"{self._label} timed out")
            return False

    def is_available(self) -> bool:
        if CURRENT_OS != "Windows":
            return False
        if not shutil.which("netsh"):
            return False
        # Check if running with admin privileges (required for firewall changes)
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if not is_admin:
                _logger.info("netsh available but not running as admin — falling back to simulation")
                return False
            # Verify netsh advfirewall is functional
            result = subprocess.run(  # nosec B603 B607
                ["netsh", "advfirewall", "show", "allprofiles"],
                capture_output=True, text=True, timeout=5,
            )
            return result.returncode == 0
        except (ImportError, AttributeError):
            return False
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            _logger.debug(f"netsh availability check failed: {e}")
            return False

    def block(self, ip: str) -> bool:
        rule_name = f"{self._rule_prefix}{ip}"
        cmd = [
            "add", "rule",
            f"name={rule_name}",
            "dir=in",
            "action=block",
            f"remoteip={ip}",
            "protocol=any",
        ]
        if self._run(cmd):
            self.add_blocked(ip)
            _logger.info(f"{self._label} BLOCKED {ip} (rule: {rule_name})")
            return True
        return False

    def unblock(self, ip: str) -> bool:
        rule_name = f"{self._rule_prefix}{ip}"
        if self._run(["delete", "rule", f"name={rule_name}"]):
            self.remove_blocked(ip)
            _logger.info(f"{self._label} UNBLOCKED {ip}")
            return True
        return False

    def set_lockdown(self, active: bool) -> bool:
        profile = "all"
        cmd = ["set", f"{profile}profile", "firewallpolicy",
               "blockinbound,allowoutbound" if active else "notconfigured"]
        if self._run(cmd):
            status = "ACTIVATED" if active else "DEACTIVATED"
            _logger.warning(f"{self._label} LOCKDOWN_{status}")
            return True
        return False

    def get_backend_rules(self) -> List[str]:
        try:
            result = subprocess.run(  # nosec B603 B607
                ["netsh", "advfirewall", "firewall", "show", "rule",
                 f"name={self._rule_prefix}all", "verbose"],
                capture_output=True, text=True, timeout=FIREWALL_TIMEOUT,
            )
            return result.stdout.strip().split("\n") if result.stdout else []
        except Exception:
            _logger.debug("Failed to get backend rules")
            return []


# ─── PF BACKEND (macOS/BSD) ──────────────────────────────────────────────────

class PfBackend(FirewallBackend):
    """Backend using pfctl (macOS/BSD Packet Filter)."""

    name = "pf"

    def __init__(self):
        self._sudo = "sudo"
        self._label = "[PF]"
        self._anchor = "aegis"

    def _run(self, cmd: List[str], timeout: int = FIREWALL_TIMEOUT) -> bool:
        try:
            subprocess.run(  # nosec B603
                cmd, check=True, capture_output=True, text=True, timeout=timeout,
            )
            return True
        except subprocess.CalledProcessError as e:
            _logger.error(f"{self._label} command failed — {e.stderr.strip()}")
            return False
        except Exception as e:
            _logger.error(f"{self._label} error: {e}")
            return False

    def is_available(self) -> bool:
        if CURRENT_OS != "Darwin":
            return False
        pfctl_path = shutil.which("pfctl")
        return pfctl_path is not None

    def _ensure_anchor(self) -> bool:
        """Create the AEGIS anchor in pf."""
        # Add the anchor to pf.conf if not present
        try:
            result = subprocess.run(
                [self._sudo, "pfctl", "-s", "anchors"],  # nosec B603
                capture_output=True, text=True, timeout=3,
            )
            if f"aegis/{self._anchor}" in result.stdout:
                return True
            # Create anchor
            return self._run([self._sudo, "pfctl", "-A", self._anchor])
        except Exception:
            _logger.debug("Failed to ensure pf anchor")
            return False

    def block(self, ip: str) -> bool:
        if not self._ensure_anchor():
            return False
        # Add block rule to the anchor via temporary file
        from tempfile import NamedTemporaryFile
        rule = f"block in from {ip} to any\n"
        try:
            with NamedTemporaryFile(mode="w", suffix=".pf", delete=False) as f:
                f.write(rule)
                tmp_path = f.name
            ok = self._run([self._sudo, "pfctl", "-a", self._anchor, "-f", tmp_path])
            os.unlink(tmp_path)
            if ok:
                self.add_blocked(ip)
                _logger.info(f"{self._label} BLOCKED {ip}")
                return True
        except Exception as e:
            _logger.error(f"{self._label} block failed for {ip}: {e}")
        return False

    def unblock(self, ip: str) -> bool:
        if not self._ensure_anchor():
            return False
        # Reload anchor with all blocked IPs EXCEPT this one
        remaining = [bip for bip in list(self._blocked) if bip != ip]
        from tempfile import NamedTemporaryFile
        try:
            with NamedTemporaryFile(mode="w", suffix=".pf", delete=False) as f:
                for rip in remaining:
                    f.write(f"block in from {rip} to any\n")
                tmp_path = f.name
            ok = self._run([self._sudo, "pfctl", "-a", self._anchor, "-f", tmp_path])
            os.unlink(tmp_path)
            if ok:
                self.remove_blocked(ip)
                _logger.info(f"{self._label} UNBLOCKED {ip}")
                return True
        except Exception as e:
            _logger.error(f"{self._label} unblock failed for {ip}: {e}")
        return False

    def set_lockdown(self, active: bool) -> bool:
        if not self._ensure_anchor():
            return False
        if active:
            # Add a block-all rule to the AEGIS anchor (non-destructive)
            from tempfile import NamedTemporaryFile
            rule = "block in all\n"
            try:
                with NamedTemporaryFile(mode="w", suffix=".pf", delete=False) as f:
                    f.write(rule)
                    tmp_path = f.name
                ok = self._run([self._sudo, "pfctl", "-a", self._anchor, "-f", tmp_path])
                os.unlink(tmp_path)
                if ok:
                    status = "ACTIVATED"
                    _logger.warning(f"{self._label} LOCKDOWN_{status}")
                    return True
            except Exception as e:
                _logger.error(f"{self._label} lockdown failed: {e}")
            return False
        else:
            # Clear AEGIS anchor rules
            return self._run([self._sudo, "pfctl", "-a", self._anchor, "-F", "all"])

    def get_backend_rules(self) -> List[str]:
        try:
            result = subprocess.run(
                [self._sudo, "pfctl", "-a", self._anchor, "-s", "rules"],  # nosec B603
                capture_output=True, text=True, timeout=FIREWALL_TIMEOUT,
            )
            return result.stdout.strip().split("\n") if result.stdout else []
        except Exception:
            _logger.debug("Failed to get pf rules")
            return []


# ─── SIMULATION BACKEND (cross-platform fallback) ────────────────────────────

class SimulationBackend(FirewallBackend):
    """Simulation backend for environments without firewall access.

    Logs all actions but does not execute them. Safe for development,
    testing, and environments where the user does not have root/admin.
    """

    name = "simulation"

    def __init__(self):
        self._sim_note = "[SIM]"

    def is_available(self) -> bool:
        return True  # Always available as fallback

    def block(self, ip: str) -> bool:
        self.add_blocked(ip)
        _logger.info(f"{self._sim_note} SIMULATED BLOCK {ip}")
        print(f"  {self._sim_note} Would block {ip}")
        return True

    def unblock(self, ip: str) -> bool:
        self.remove_blocked(ip)
        _logger.info(f"{self._sim_note} SIMULATED UNBLOCK {ip}")
        print(f"  {self._sim_note} Would unblock {ip}")
        return True

    def set_lockdown(self, active: bool) -> bool:
        status = "ACTIVATE" if active else "DEACTIVATE"
        _logger.info(f"{self._sim_note} SIMULATED LOCKDOWN {status}")
        print(f"  {self._sim_note} Would {status} lockdown mode")
        return True

    def get_backend_rules(self) -> List[str]:
        return [f"[SIM] Would block: {ip}" for ip in sorted(self._blocked)]


# ─── AUTO-DETECTION ───────────────────────────────────────────────────────────

def detect_best_backend(preferred: Optional[str] = None) -> FirewallBackend:
    """Auto-detect the best available firewall backend for this system.

    Detection priority:
    1. User-configured backend (from config)
    2. nftables (if available on Linux)
    3. iptables (if available on Linux)
    4. netsh (if on Windows)
    5. pf (if on macOS)
    6. Simulation (always available fallback)
    """
    backends: List[Type[FirewallBackend]] = [
        NftablesBackend,
        IptablesBackend,
        NetshBackend,
        PfBackend,
    ]

    # If user explicitly configured a backend, try it first
    if preferred:
        preferred_map = {
            "nftables": NftablesBackend,
            "iptables": IptablesBackend,
            "netsh": NetshBackend,
            "pf": PfBackend,
            "simulation": SimulationBackend,
        }
        backend_cls = preferred_map.get(preferred.lower())
        if backend_cls:
            instance = backend_cls()
            if instance.is_available():
                _logger.info(f"Backend selected (preferred): {instance.name}")
                print(f"  [FIREWALL] Using preferred backend: {instance.name}")
                return instance
            _logger.warning(f"Preferred backend '{preferred}' unavailable, falling back...")
            print(f"  [FIREWALL] WARNING: Preferred backend '{preferred}' unavailable."
                  f" Auto-detecting...")

    # Auto-detect
    for backend_cls in backends:
        instance = backend_cls()
        if instance.is_available():
            _logger.info(f"Backend auto-detected: {instance.name}")
            print(f"  [FIREWALL] Backend: {instance.name}")
            return instance

    # Fallback to simulation
    sim = SimulationBackend()
    _logger.info("No native firewall backend available — using simulation mode.")
    print("  [FIREWALL] No native firewall backend detected.")
    print("  [FIREWALL] Using simulation mode — IPs logged but NOT blocked.")
    return sim


# ─── INIT ─────────────────────────────────────────────────────────────────────
# A backend instance is created on import
# The config FIREWALL_BACKEND can override auto-detection
BACKEND: FirewallBackend = detect_best_backend(FIREWALL_BACKEND)
