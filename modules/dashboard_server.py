"""
Project AEGIS — Dashboard WebSocket Server
Lead Architect: ETCHERO / Abdul-Hameed
Version: 1.0.0 | Classification: AEGIS-DASHBOARD
Role: Real-time WebSocket server that bridges AEGIS data to the Next.js dashboard.
      Broadcasts health metrics, incidents, blocked IPs, and AI assessments.

      Priority 9 — Central Dashboard:
      - WebSocket JSON protocol over port 8765 (configurable)
      - Periodic full-state broadcasts every 3 seconds
      - Event-driven updates when new incidents are created
      - Command channel for dashboard-to-AEGIS operations (block/unblock IP)

      Protocol:
        Server → Client (broadcast):
        {
          "type": "state_update",
          "data": {
            "health": { ... },
            "incidents": [ ... ],
            "blocked_ips": [...],
            "assessments": { "incident_id": { ... } }
          }
        }

        Client → Server (command):
        {
          "type": "command",
          "command": "block_ip" | "unblock_ip" | "lockdown_on" | "lockdown_off",
          "params": { "ip": "1.2.3.4" }
        }
"""

import asyncio
import json
import logging
import threading
import time
from dataclasses import asdict
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

# ─── CONFIG ───────────────────────────────────────────────────────────────────
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config import (  # noqa: E402
    DASHBOARD_WS_HOST,
    DASHBOARD_WS_PORT,
    DASHBOARD_LOG_FILE,
    DASHBOARD_POLL_INTERVAL,
    DASHBOARD_LOG_MAX_BYTES,
    DASHBOARD_LOG_BACKUP_COUNT,
    LOG_FORMAT,
)

# ─── LOGGER ───────────────────────────────────────────────────────────────────
_logger = logging.getLogger("aegis.dashboard")
if not _logger.handlers:
    _handler = RotatingFileHandler(
        str(DASHBOARD_LOG_FILE) if DASHBOARD_LOG_FILE else "logs/dashboard.log",
        maxBytes=DASHBOARD_LOG_MAX_BYTES or 5 * 1024 * 1024,
        backupCount=DASHBOARD_LOG_BACKUP_COUNT or 3,
        encoding="utf-8",
    )
    _handler.setFormatter(logging.Formatter(LOG_FORMAT))
    _logger.addHandler(_handler)
_logger.setLevel(logging.INFO)
_logger.propagate = False


# ─── WEBSOCKET SERVER ─────────────────────────────────────────────────────────
class DashboardServer:
    """WebSocket server that broadcasts AEGIS state to connected dashboard clients.

    Runs in its own thread with an asyncio event loop.
    """

    def __init__(self, host: str = DASHBOARD_WS_HOST, port: int = DASHBOARD_WS_PORT):
        self._host = host
        self._port = port
        self._clients: Set[Any] = set()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None

        # Cache for latest state (protected by lock)
        self._state_lock = threading.Lock()
        self._last_health: dict = {}
        self._last_incidents: List[dict] = []
        self._last_blocked_ips: List[str] = []
        self._last_assessments: Dict[str, Any] = {}
        self._known_incident_ids: Set[str] = set()

        # Callback for receiving incident updates from orchestrator
        self._pending_incidents: List[Any] = []
        self._pending_lock = threading.Lock()

        # Single shared heartbeat instance (created once, not per poll)
        self._heartbeat_instance: Any = None
        self._heartbeat_created = False

        # Polling interval
        self._poll_interval = DASHBOARD_POLL_INTERVAL

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start the WebSocket server in a background thread."""
        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(
            target=self._run_loop,
            daemon=True,
            name="AEGIS-Dashboard-WS",
        )
        self._thread.start()
        _logger.info(f"Dashboard server starting on ws://{self._host}:{self._port}")
        print(f"  [AEGIS] Dashboard server starting on ws://{self._host}:{self._port}")

    def stop(self) -> None:
        """Stop the WebSocket server."""
        self._running = False
        if self._loop and self._loop.is_running():
            try:
                self._loop.call_soon_threadsafe(self._loop.stop)
            except Exception:
                _logger.debug("Dashboard loop stop failed")
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        _logger.info("Dashboard server stopped.")
        print("  [AEGIS] Dashboard server stopped.")

    def _run_loop(self) -> None:
        """Run the asyncio event loop in the background thread."""
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._serve())
        except Exception as e:
            _logger.error(f"Dashboard server error: {e}")
        finally:
            self._loop.close()

    async def _serve(self) -> None:
        """Start the WebSocket server and polling task."""
        import websockets

        print(f"  [AEGIS] Dashboard WebSocket ready → ws://{self._host}:{self._port}")
        print("  [AEGIS] Open the dashboard in your browser to connect.\n")

        async with websockets.serve(
            self._handle_client,
            self._host,
            self._port,
            ping_interval=20,
            ping_timeout=10,
        ):
            # Run the polling loop alongside the server
            await self._polling_loop()

    async def _polling_loop(self) -> None:
        """Periodically gather and broadcast AEGIS state."""
        while self._running:
            try:
                await self._gather_and_broadcast()
            except Exception as e:
                _logger.debug(f"Dashboard poll error: {e}")
            await asyncio.sleep(self._poll_interval)

    # ── State Gathering ──────────────────────────────────────────────────────

    async def _gather_and_broadcast(self) -> None:
        """Gather latest AEGIS state and broadcast to all clients."""
        state = await self._gather_state()
        if state:
            msg = json.dumps({"type": "state_update", "data": state})
            # Cache the state
            self._last_health = state.get("health", {})
            self._last_incidents = state.get("incidents", [])
            self._last_blocked_ips = state.get("blocked_ips", [])
            self._last_assessments = state.get("assessments", {})

            if self._clients:
                await self._broadcast(msg)

    async def _gather_state(self) -> Optional[dict]:
        """Gather all AEGIS state from modules."""
        try:
            state = {
                "health": await self._get_health_state(),
                "incidents": await self._get_incidents_state(),
                "blocked_ips": await self._get_blocked_ips_state(),
                "assessments": self._last_assessments,
                "timestamp": datetime.now().isoformat(),
            }
            return state
        except Exception as e:
            _logger.warning(f"State gathering error: {e}")
            return None

    async def _get_health_state(self) -> dict:
        """Gather health metrics using a shared heartbeat instance."""
        try:
            from core.heartbeat import Heartbeat

            # Create heartbeat once, reuse for all polls
            if not self._heartbeat_created:
                self._heartbeat_instance = Heartbeat()
                self._heartbeat_created = True

            hb = self._heartbeat_instance
            snap = hb.pulse()
            if snap:
                return asdict(snap)
        except Exception as e:
            _logger.debug(f"Health state error: {e}")

        # Fallback: return cached or empty
        with self._state_lock:
            if self._last_health:
                return self._last_health
        return {
            "status": "UNKNOWN",
            "health_score": 0,
            "cpu_percent": 0,
            "ram_percent": 0,
            "active_connections": 0,
            "timestamp": datetime.now().isoformat(),
        }

    async def _get_incidents_state(self) -> List[dict]:
        """Gather incidents from the incident manager."""
        try:

            # Try to get the global AEGIS instance (set by orchestrator on boot)
            try:
                import aegis as aegis_mod
                core_instance = getattr(aegis_mod, '_AEGIS_INSTANCE', None)
                if core_instance and core_instance._incident_manager:
                    im = core_instance._incident_manager
                    all_inc = im.get_all_incidents()
                    incidents = [self._incident_to_dict(inc) for inc in all_inc[:50]]
                    return incidents
            except (ImportError, AttributeError):
                pass

            # Fallback: return cached incidents
            with self._state_lock:
                return list(self._last_incidents)
        except Exception as e:
            _logger.debug(f"Incidents state error: {e}")
            with self._state_lock:
                return list(self._last_incidents)

    @staticmethod
    def _incident_to_dict(inc: Any) -> dict:
        """Convert an Incident dataclass to a JSON-serializable dict."""
        if hasattr(inc, "incident_id"):
            # It's an Incident object
            return {
                "incident_id": getattr(inc, "incident_id", ""),
                "created_at": getattr(inc, "created_at", ""),
                "updated_at": getattr(inc, "updated_at", ""),
                "status": getattr(inc, "status", ""),
                "risk_level": getattr(inc, "risk_level", ""),
                "threat_types": list(getattr(inc, "threat_types", [])),
                "source_ips": list(getattr(inc, "source_ips", set())),
                "process_names": list(getattr(inc, "process_names", set())),
                "event_count": getattr(inc, "event_count", 0),
                "last_event_time": getattr(inc, "last_event_time", 0.0),
                "timeline": getattr(inc, "timeline", ""),
                # Convert events if present
                "events": [
                    {
                        "timestamp": getattr(ev, "timestamp", ""),
                        "threat_type": getattr(ev, "threat_type", ""),
                        "risk_level": getattr(ev, "risk_level", ""),
                        "source": getattr(ev, "source", ""),
                        "summary": getattr(ev, "summary", ""),
                        "detail": getattr(ev, "detail", "")[:200] if getattr(ev, "detail", "") else "",
                    }
                    for ev in getattr(inc, "events", [])[-10:]  # Last 10 events
                ],
            }
        return {}

    async def _get_blocked_ips_state(self) -> List[str]:
        """Gather blocked IPs from the firewall module."""
        try:
            from modules.firewall import get_blocked
            return get_blocked()[:100]  # Max 100 IPs for dashboard
        except Exception as e:
            _logger.debug(f"Blocked IPs state error: {e}")
            return self._last_blocked_ips

    # ── Client Handling ──────────────────────────────────────────────────────

    async def _handle_client(self, websocket: Any, path: str = "/") -> None:
        """Handle a single WebSocket client connection."""
        self._clients.add(websocket)
        client_addr = websocket.remote_address
        _logger.info(f"Dashboard client connected: {client_addr}")
        print(f"  [AEGIS] Dashboard client connected: {client_addr}")

        # Send current state immediately on connect
        try:
            state = await self._gather_state()
            if state:
                await websocket.send(
                    json.dumps({"type": "state_update", "data": state})
                )
        except Exception:
            _logger.debug("Initial state send failed")

        try:
            async for message in websocket:
                await self._handle_message(websocket, message)
        except Exception as e:
            _logger.debug(f"Client {client_addr} disconnected: {e}")
        finally:
            self._clients.discard(websocket)
            _logger.info(f"Dashboard client disconnected: {client_addr}")
            print(f"  [AEGIS] Dashboard client disconnected: {client_addr}")

    async def _handle_message(self, websocket: Any, message: str) -> None:
        """Handle an incoming command from a dashboard client."""
        try:
            data = json.loads(message)
        except json.JSONDecodeError:
            return

        if not isinstance(data, dict) or data.get("type") != "command":
            return

        command = data.get("command", "")
        params = data.get("params", {})

        _logger.info(f"Dashboard command: {command} {params}")

        if command == "block_ip":
            ip = params.get("ip", "")
            if ip:
                try:
                    from modules.firewall import block_ip
                    result = block_ip(ip)
                    await websocket.send(
                        json.dumps({"type": "command_result", "command": command, "success": result})
                    )
                except Exception as e:
                    await websocket.send(
                        json.dumps({"type": "command_result", "command": command, "success": False, "error": str(e)})
                    )

        elif command == "unblock_ip":
            ip = params.get("ip", "")
            if ip:
                try:
                    from modules.firewall import unblock_ip
                    result = unblock_ip(ip)
                    await websocket.send(
                        json.dumps({"type": "command_result", "command": command, "success": result})
                    )
                except Exception as e:
                    await websocket.send(
                        json.dumps({"type": "command_result", "command": command, "success": False, "error": str(e)})
                    )

        elif command == "lockdown_on":
            try:
                from modules.firewall import set_lockdown
                set_lockdown(True)
                await websocket.send(
                    json.dumps({"type": "command_result", "command": command, "success": True})
                )
            except Exception as e:
                await websocket.send(
                    json.dumps({"type": "command_result", "command": command, "success": False, "error": str(e)})
                )

        elif command == "lockdown_off":
            try:
                from modules.firewall import set_lockdown
                set_lockdown(False)
                await websocket.send(
                    json.dumps({"type": "command_result", "command": command, "success": True})
                )
            except Exception as e:
                await websocket.send(
                    json.dumps({"type": "command_result", "command": command, "success": False, "error": str(e)})
                )

        else:
            await websocket.send(
                json.dumps({"type": "command_result", "command": command, "success": False, "error": "Unknown command"})
            )

    async def _broadcast(self, message: str) -> None:
        """Send a message to all connected clients."""
        if not self._clients:
            return
        disconnected = set()
        for client in self._clients:
            try:
                await client.send(message)
            except Exception:
                _logger.debug("Broadcast send failed")
                disconnected.add(client)
        self._clients -= disconnected

    # ── External API for Orchestrator ─────────────────────────────────────────

    def push_incident_update(self, incident: Any, assessment: Any = None) -> None:
        """Push an incident update to all clients (called from orchestrator)."""
        inc_dict = self._incident_to_dict(incident)
        assessments = {}
        if assessment:
            try:
                from modules.ai_analyst import AnalystAssessment
                if isinstance(assessment, AnalystAssessment):
                    assessments[incident.incident_id] = {
                        "risk_level": assessment.risk_level,
                        "confidence": assessment.confidence,
                        "executive_summary": assessment.executive_summary,
                        "kill_chain": assessment.kill_chain,
                        "mitre_techniques": [
                            {
                                "technique_id": t.technique_id,
                                "technique_name": t.technique_name,
                                "kill_chain_stage": t.kill_chain_stage,
                            }
                            for t in assessment.mitre_techniques
                        ],
                        "recommended_actions": assessment.recommended_actions[:5],
                        "key_indicators": {k: v[:3] for k, v in assessment.key_indicators.items()},
                    }
            except Exception:
                _logger.debug("Assessment serialization failed")

        payload = json.dumps({
            "type": "incident_update",
            "data": {
                "incident": inc_dict,
                "assessment": assessments.get(incident.incident_id),
            }
        })

        if self._loop and self._loop.is_running():
            asyncio.run_coroutine_threadsafe(self._broadcast(payload), self._loop)


# ─── STANDALONE ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n  AEGIS DASHBOARD SERVER — STANDALONE\n")
    server = DashboardServer()
    server.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.stop()
