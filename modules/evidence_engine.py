"""
Project AEGIS — Evidence Engine
Lead Architect: ETCHERO / Abdul-Hameed
Version: 1.0.0 | Classification: AEGIS-EVIDENCE
Role: Captures forensic-grade evidence for every threat.
      Every alert becomes a complete artifact package:

      Process Threats:
        - Process tree (ancestral chain PID → root)
        - Binary SHA-256 hash
        - Full command line
        - Environment variables
        - Working directory
        - Open file handles
        - Network connections (local + remote)

      File Threats:
        - Full file metadata (permissions, owner, timestamps)
        - SHA-256 hash
        - Directory listing

      Login Threats:
        - Recent auth log entries
        - Source IP geolocation stub
"""

import hashlib
import json
import logging
import os
from dataclasses import dataclass, asdict, field
from datetime import datetime

from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil

# ─── CONFIG ───────────────────────────────────────────────────────────────────
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config import (  # noqa: E402
    SafeRotatingFileHandler,
    LOG_DIR,
    EVIDENCE_DIR,
    LOG_MAX_BYTES,
    LOG_BACKUP_COUNT,
    LOG_FORMAT,
)

# ─── LOGGER ───────────────────────────────────────────────────────────────────
_logger = logging.getLogger("aegis.evidence")
if not _logger.handlers:
    _handler = SafeRotatingFileHandler(
        str(LOG_DIR / "evidence_engine.log"),
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT,
        encoding="utf-8",
    )
    _handler.setFormatter(logging.Formatter(LOG_FORMAT))
    _logger.addHandler(_handler)
_logger.setLevel(logging.INFO)
_logger.propagate = False


# ─── DATA MODEL ───────────────────────────────────────────────────────────────
@dataclass
class ProcessNode:
    """A single node in a process tree chain."""
    pid: int
    name: str
    cmdline: str
    exe: str
    create_time: float
    username: str
    cpu_percent: float
    memory_percent: float


@dataclass
class ConnectionRecord:
    """A network connection record."""
    fd: int
    family: str
    type: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    status: str


@dataclass
class EvidencePackage:
    """Complete forensic evidence package for any threat."""
    # Metadata
    captured_at: str
    threat_type: str
    threat_id: str

    # Process context (for process / network threats)
    process_tree: List[ProcessNode] = field(default_factory=list)
    binary_hash: Optional[str] = None
    command_line: str = ""
    environment: Dict[str, str] = field(default_factory=dict)
    working_directory: str = ""
    open_files: List[str] = field(default_factory=list)
    connections: List[ConnectionRecord] = field(default_factory=list)
    memory_maps: List[Dict] = field(default_factory=list)

    # File context (for file threats)
    file_path: str = ""
    file_hash: Optional[str] = None
    file_size: int = 0
    file_permissions: str = ""
    file_owner: str = ""
    file_modified: str = ""
    file_context: Dict[str, Any] = field(default_factory=dict)

    # System context
    system_info: Dict[str, Any] = field(default_factory=dict)

    # Raw evidence payload
    raw: Dict[str, Any] = field(default_factory=dict)


# ─── EVIDENCE ENGINE ──────────────────────────────────────────────────────────
class EvidenceEngine:
    """Centralized forensic evidence capture engine."""

    EVIDENCE_DIR: Path = LOG_DIR / "evidence"
    MAX_EVIDENCE_FILES: int = 1000

    @classmethod
    def configure(cls, evidence_dir: Path, max_files: int = 1000) -> None:
        """Configure evidence storage.

        Validates that the provided path is a real directory and does not
        contain path traversal components.
        """
        evidence_str = str(evidence_dir)
        if ".." in evidence_str.split(os.sep):
            _logger.error(f"Path traversal attempt blocked in evidence_dir: {evidence_dir}")
            raise ValueError(f"Invalid evidence directory path: {evidence_dir}")
        cls.EVIDENCE_DIR = evidence_dir
        cls.MAX_EVIDENCE_FILES = max_files
        cls.EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
        _logger.info(f"Evidence engine configured: dir={evidence_dir}, max_files={max_files}")

    # ── Process Tree ──────────────────────────────────────────────────────────

    @classmethod
    def capture_process_tree(cls, pid: int) -> List[ProcessNode]:
        """Build ancestral process tree from PID to root (init/explorer).

        Returns oldest ancestor first, target process last.
        Example:
            [explorer.exe (PID 1000), powershell.exe (PID 2000), nc.exe (PID 3000)]
        """
        tree: List[ProcessNode] = []
        seen: set = set()
        current_pid = pid

        while current_pid > 0 and current_pid not in seen:
            seen.add(current_pid)
            try:
                proc = psutil.Process(current_pid)
                try:
                    username = proc.username()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    username = "UNKNOWN"

                tree.append(ProcessNode(
                    pid=current_pid,
                    name=proc.name(),
                    cmdline=" ".join(proc.cmdline() or []),
                    exe=proc.exe(),
                    create_time=proc.create_time(),
                    username=username,
                    cpu_percent=proc.cpu_percent(interval=0),
                    memory_percent=proc.memory_percent(),
                ))
                current_pid = proc.ppid()
            except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError):
                break

        # Reverse so root comes first
        tree.reverse()
        return tree

    # ── Binary Hashing ────────────────────────────────────────────────────────

    @classmethod
    def hash_binary(cls, exe_path: Optional[str]) -> Optional[str]:
        """Compute SHA-256 hash of a binary file."""
        if not exe_path or not os.path.isfile(exe_path):
            return None
        try:
            h = hashlib.sha256()
            with open(exe_path, "rb", buffering=65536) as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    h.update(chunk)
            return h.hexdigest()
        except (OSError, PermissionError, FileNotFoundError):
            return None

    # ── Process Context ──────────────────────────────────────────────────────

    @classmethod
    def _get_environment(cls, pid: int) -> Dict[str, str]:
        """Get environment variables for a process (sanitized)."""
        try:
            proc = psutil.Process(pid)
            env = proc.environ()
            # Sanitize: truncate long values, exclude sensitive keys
            sanitized = {}
            sensitive_keys = {"PASSWORD", "SECRET", "TOKEN", "KEY", "AUTH", "CREDENTIAL"}
            for k, v in env.items():
                if any(s in k.upper() for s in sensitive_keys):
                    sanitized[k] = "***REDACTED***"
                else:
                    sanitized[k] = str(v)[:500]
            return sanitized
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
            return {}

    @classmethod
    def _get_open_files(cls, pid: int) -> List[str]:
        """Get list of open file handles for a process."""
        try:
            proc = psutil.Process(pid)
            files = proc.open_files()
            return [f.path for f in files[:100]]  # Cap at 100 files
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            return []

    @classmethod
    def _get_connections(cls, pid: int) -> List[ConnectionRecord]:
        """Get all network connections for a process."""
        try:
            proc = psutil.Process(pid)
            conns = proc.connections(kind="inet")
            records = []
            for c in conns:
                laddr = c.laddr
                raddr = c.raddr
                records.append(ConnectionRecord(
                    fd=c.fd,
                    family=str(c.family),
                    type=str(c.type),
                    local_addr=laddr.ip if laddr else "",
                    local_port=laddr.port if laddr else 0,
                    remote_addr=raddr.ip if raddr else "",
                    remote_port=raddr.port if raddr else 0,
                    status=c.status,
                ))
            return records
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            return []

    @classmethod
    def _get_memory_maps(cls, pid: int) -> List[Dict]:
        """Get memory maps for a process (high-value for injection detection)."""
        try:
            proc = psutil.Process(pid)
            maps = []
            for m in proc.memory_maps(grouped=False)[:50]:  # Cap at 50
                maps.append({
                    "path": m.path,
                    "rss": m.rss,
                    "perms": m.perms,
                })
            return maps
        except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError):
            return []

    # ── Process Tree Rendering ────────────────────────────────────────────────

    @staticmethod
    def dicts_to_process_nodes(raw_tree: List[Dict[str, Any]]) -> List[ProcessNode]:
        """Convert raw dict data (from serialized evidence) back to ProcessNode objects.

        This is used when displaying process trees from persisted evidence or
        from the forensic dict stored on a threat object.
        """
        nodes = []
        for n in raw_tree:
            nodes.append(ProcessNode(
                pid=n.get("pid", 0),
                name=n.get("name", "?"),
                cmdline=n.get("cmdline", ""),
                exe=n.get("exe", ""),
                create_time=n.get("create_time", 0),
                username=n.get("username", ""),
                cpu_percent=n.get("cpu_percent", 0),
                memory_percent=n.get("memory_percent", 0),
            ))
        return nodes

    @staticmethod
    def render_process_tree(process_tree: List[ProcessNode], target_pid: Optional[int] = None) -> str:
        """Render a process tree as a visual ancestral chain.

        Args:
            process_tree: List of ProcessNodes from oldest ancestor to target process.
            target_pid: If provided, marks the target PID with a threat indicator.

        Returns:
            A multi-line string showing the process tree with tree-drawing characters.

        Example output:
            explorer.exe (PID 1234)
            └── powershell.exe (PID 5678) — C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
                └── python.exe (PID 9012) — C:\\Python39\\python.exe -c "import socket..."
                    └── nc.exe (PID 1111) ◄─ THREAT
        """
        if not process_tree:
            return "  (no process tree available)"

        lines: List[str] = []
        depth = 0
        for i, node in enumerate(process_tree):
            is_target = (node.pid == target_pid) if target_pid is not None else (i == len(process_tree) - 1)
            is_last = (i == len(process_tree) - 1)

            # Build prefix with tree-drawing characters
            if depth == 0:
                prefix = ""
            elif is_last:
                prefix = "    " * (depth - 1) + "└── "
            else:
                prefix = "    " * (depth - 1) + "├── "

            # Build node label
            cmd_preview = f" — {node.cmdline[:80]}" if node.cmdline else ""
            threat_marker = " ◄─ THREAT" if is_target else ""

            line = f"{prefix}{node.name} (PID {node.pid}){cmd_preview}{threat_marker}"
            lines.append(line)
            depth += 1

        return "\n".join(lines)

    @staticmethod
    def render_process_tree_compact(process_tree: List[ProcessNode]) -> str:
        """Render a process tree as a compact one-line chain for use in summaries.

        Example:
            explorer.exe(1234) → powershell.exe(5678) → python.exe(9012) → nc.exe(1111)
        """
        if not process_tree:
            return ""
        nodes = [f"{n.name}({n.pid})" for n in process_tree]
        return " → ".join(nodes)

    # ── File Context ──────────────────────────────────────────────────────────

    @classmethod
    def capture_file_context(cls, file_path: str) -> Dict[str, Any]:
        """Capture forensic context for a file."""
        context: Dict[str, Any] = {}
        try:
            stat = os.stat(file_path)
            context = {
                "path": file_path,
                "size": stat.st_size,
                "permissions": oct(stat.st_mode),
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                "hash": cls.hash_binary(file_path),
            }
            # Try to get owner
            try:
                import pwd  # type: ignore[import-untyped]
                context["owner"] = pwd.getpwuid(stat.st_uid).pw_name  # type: ignore[attr-defined]
            except (ImportError, KeyError):
                context["owner"] = str(stat.st_uid)
        except (OSError, FileNotFoundError):
            _logger.debug("Could not capture file context for %s", file_path)
        return context

    # ── System Context ───────────────────────────────────────────────────────

    @classmethod
    def _capture_system_info(cls) -> Dict[str, Any]:
        """Capture general system context."""
        info = {
            "hostname": "",
            "boot_time": "",
            "total_cpu_count": 0,
            "total_ram_gb": 0,
        }
        try:
            import platform
            info["hostname"] = platform.node()
            info["boot_time"] = datetime.fromtimestamp(psutil.boot_time()).isoformat()
            info["total_cpu_count"] = psutil.cpu_count()
            info["total_ram_gb"] = round(psutil.virtual_memory().total / 1e9, 2)
        except Exception:
            _logger.debug("Could not capture system info")
        return info

    # ── Full Capture ─────────────────────────────────────────────────────────

    @classmethod
    def capture_process_evidence(cls, pid: int, threat_type: str, threat_id: str) -> EvidencePackage:
        """Capture full forensic evidence for a process-based threat.

        This is the main entry point for process threats (reverse shell,
        crypto miner, privilege escalation, etc.).
        """
        package = EvidencePackage(
            captured_at=datetime.now().isoformat(),
            threat_type=threat_type,
            threat_id=threat_id,
            system_info=cls._capture_system_info(),
        )

        try:
            if not psutil.pid_exists(pid):
                _logger.warning(f"Cannot capture evidence: PID {pid} no longer exists")
                return package

            proc = psutil.Process(pid)

            # Process tree
            package.process_tree = cls.capture_process_tree(pid)

            # Binary hash
            try:
                exe = proc.exe()
                package.binary_hash = cls.hash_binary(exe)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            # Command line
            try:
                package.command_line = " ".join(proc.cmdline() or [])
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            # Environment
            package.environment = cls._get_environment(pid)

            # Working directory
            try:
                package.working_directory = proc.cwd()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            # Open files
            package.open_files = cls._get_open_files(pid)

            # Network connections
            package.connections = cls._get_connections(pid)

            # Memory maps
            package.memory_maps = cls._get_memory_maps(pid)

            # Raw dump for extensibility
            package.raw = {
                "pid": pid,
                "name": proc.name(),
                "status": proc.status(),
                "num_threads": proc.num_threads(),
                "create_time": proc.create_time(),
            }

        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            _logger.warning(f"Evidence capture failed for PID {pid}: {e}")

        return package

    @classmethod
    def capture_file_evidence(cls, file_path: str, threat_type: str, threat_id: str) -> EvidencePackage:
        """Capture full forensic evidence for a file-based threat."""
        package = EvidencePackage(
            captured_at=datetime.now().isoformat(),
            threat_type=threat_type,
            threat_id=threat_id,
            system_info=cls._capture_system_info(),
            file_context=cls.capture_file_context(file_path),
        )
        return package

    # ── Persistence ──────────────────────────────────────────────────────────

    @classmethod
    def persist(cls, package: EvidencePackage) -> Optional[str]:
        """Write evidence package to disk. Returns the file path or None."""
        try:
            cls.EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

            # Generate a unique filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            safe_type = package.threat_type.lower().replace(" ", "_").replace("/", "_")
            filename = f"{timestamp}_{safe_type}_{package.threat_id}.json"
            filepath = cls.EVIDENCE_DIR / filename

            # Defense-in-depth: verify resolved path is within EVIDENCE_DIR
            try:
                resolved = filepath.resolve()
                evidence_resolved = cls.EVIDENCE_DIR.resolve()
                if evidence_resolved not in resolved.parents and resolved != evidence_resolved:
                    _logger.error(f"Path traversal blocked: {filename} resolves outside EVIDENCE_DIR")
                    return None
            except (OSError, RuntimeError) as e:
                _logger.error(f"Path resolution failed for {filename}: {e}")
                return None

            # Write evidence
            filepath.write_text(
                json.dumps(asdict(package), indent=2, default=str),
                encoding="utf-8",
            )

            _logger.info(f"Evidence persisted: {filepath} ({len(str(asdict(package)))} bytes)")

            # Prune old evidence files if over limit
            cls._prune_old()

            return str(filepath)

        except OSError as e:
            _logger.error(f"Failed to persist evidence: {e}")
            return None

    @classmethod
    def _prune_old(cls) -> None:
        """Remove oldest evidence files if over the max limit."""
        try:
            files = sorted(cls.EVIDENCE_DIR.glob("*.json"), key=os.path.getmtime)
            while len(files) > cls.MAX_EVIDENCE_FILES:
                oldest = files.pop(0)
                oldest.unlink()
                _logger.debug(f"Pruned old evidence: {oldest}")
        except OSError as e:
            _logger.warning(f"Evidence pruning failed: {e}")

    # ── Threat ID Generation ─────────────────────────────────────────────────

    @staticmethod
    def generate_threat_id() -> str:
        """Generate a unique threat/incident ID."""
        import uuid
        return uuid.uuid4().hex[:12]


# ─── INIT ─────────────────────────────────────────────────────────────────────
# Auto-configure on import
EvidenceEngine.configure(EVIDENCE_DIR)  # EVIDENCE_DIR imported from config
