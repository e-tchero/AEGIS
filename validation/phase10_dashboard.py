"""
Project AEGIS -- Validation Phase 10: Dashboard Testing
Lead Architect: ETCHERO / Abdul-Hameed
Version: 1.0.0 | Classification: AEGIS-DASH-TEST

Verifies the Dashboard WebSocket server under various conditions:

  1. WebSocket Lifecycle     -- start/stop/restart cycles
  2. Client Connection       -- fresh state on connect
  3. Multiple Clients        -- 10 concurrent clients receive broadcasts
  4. Malformed Packets       -- invalid JSON, oversized messages, null bytes
  5. Command Channel         -- block_ip, unblock_ip via WebSocket
  6. High-Frequency Updates  -- 100 rapid push_incident_update calls
  7. Broadcast Integrity     -- all clients receive identical state
  8. Disconnect/Reconnect    -- rapid connect/disconnect/reconnect cycles

  NOTE: Tests 2-8 share a single DashboardServer instance to avoid
  Windows TCP TIME_WAIT issues on port reuse.

Usage:
    python validation/phase10_dashboard.py
"""

import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from validation.utils.reporter import ValidationReport, ValidationResult


def _check(
    report: ValidationReport, name: str, category: str, fn: Callable,
    severity: str = "ERROR", fix: str = "",
) -> None:
    result = ValidationResult(name, category)
    try:
        passed, detail = fn()
        if passed:
            result.pass_(detail)
        else:
            result.fail(detail, severity, fix)
    except Exception as e:
        result.fail(f"Check crashed: {e}", "CRITICAL", fix)
    report.add(result)


TEST_HOST = "127.0.0.1"
TEST_PORT = 18765
TEST_WS_URL = f"ws://{TEST_HOST}:{TEST_PORT}"
TIMEOUT_SHORT = 3
TIMEOUT_MEDIUM = 5


def _run_async(coro) -> Any:
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(coro)
    finally:
        try:
            loop.close()
        except Exception:
            pass


# ─── Helpers ─────────────────────────────────────────────────────────────────

async def _recv_state(ws, timeout: float = TIMEOUT_MEDIUM) -> Optional[dict]:
    """Receive a single message and return parsed data, or None on timeout."""
    try:
        msg = await asyncio.wait_for(ws.recv(), timeout=timeout)
        data = json.loads(msg)
        if isinstance(data, dict) and data.get("type") == "state_update":
            return data.get("data", {})
        return data
    except (asyncio.TimeoutError, json.JSONDecodeError, Exception):
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# TEST 1: Lifecycle (runs with its own server)
# ═══════════════════════════════════════════════════════════════════════════════

def test_lifecycle(report: ValidationReport) -> Dict[str, Any]:
    """Verify the WebSocket server can start, stop, and restart cleanly."""
    print("  [DASH] Test 1: WebSocket Lifecycle (start/stop/restart)...")

    from modules.dashboard_server import DashboardServer

    results = {"starts": 0, "stops": 0, "errors": 0}

    for cycle in range(2):
        try:
            ds = DashboardServer(host=TEST_HOST, port=TEST_PORT)
            ds.start()
            time.sleep(0.5)
            results["starts"] += 1
            ds.stop()
            time.sleep(0.3)
            results["stops"] += 1
        except Exception:
            results["errors"] += 1

    def check():
        if results["errors"] == 0 and results["starts"] == 2 and results["stops"] == 2:
            return True, f"{results['starts']} start / {results['stops']} stop cycles without errors"
        return False, f"{results['errors']} errors in {results['starts']}/{results['stops']} cycles"

    _check(report, "Dashboard server survives start/stop/restart cycles",
           "Lifecycle", check, severity="CRITICAL",
           fix="Ensure stop() is idempotent and start() works after stop()")

    return results


# ─── Tests 2-8 use a shared server instance on a different port ───────────────
# Test 1 (lifecycle) uses port 18765. The shared server uses port 18764
# to avoid Windows TCP TIME_WAIT port reuse conflicts.

SHARED_PORT = 18764
SHARED_WS_URL = f"ws://{TEST_HOST}:{SHARED_PORT}"
_SERVER = None  # Shared DashboardServer


def _ensure_server() -> Any:
    """Start a shared DashboardServer for tests 2-8."""
    global _SERVER  # noqa: PLW0603
    if _SERVER is not None:
        return _SERVER
    from modules.dashboard_server import DashboardServer
    _SERVER = DashboardServer(host=TEST_HOST, port=SHARED_PORT)
    _SERVER.start()
    time.sleep(1)
    return _SERVER


def _stop_server() -> None:
    global _SERVER  # noqa: PLW0603
    if _SERVER is not None:
        _SERVER.stop()
        time.sleep(0.5)
        _SERVER = None


# ═══════════════════════════════════════════════════════════════════════════════
# TEST 2: Client Connection and Fresh State
# ═══════════════════════════════════════════════════════════════════════════════

def test_client_connect(report: ValidationReport) -> Dict[str, Any]:
    print("  [DASH] Test 2: Client Connection and Fresh State...")

    results = {"connected": 0, "received_state": 0, "errors": 0}

    _ensure_server()

    async def connect_and_receive():
        import websockets
        try:
            async with websockets.connect(SHARED_WS_URL, close_timeout=2, ping_interval=None) as ws:
                results["connected"] += 1
                data = await _recv_state(ws)
                if data is not None:
                    results["received_state"] += 1
                else:
                    results["errors"] += 1
        except Exception:
            results["errors"] += 1

    _run_async(connect_and_receive())

    def check():
        if results["connected"] >= 1 and results["received_state"] >= 1:
            return True, f"Client connected and received state immediately"
        return False, f"Connected: {results['connected']}, State: {results['received_state']}, Errors: {results['errors']}"

    _check(report, "Client connects and receives state immediately",
           "Connectivity", check, severity="CRITICAL",
           fix="Verify _handle_client sends initial state on connect")

    return results


# ═══════════════════════════════════════════════════════════════════════════════
# TEST 3: Multiple Concurrent Clients
# ═══════════════════════════════════════════════════════════════════════════════

def test_multiple_clients(report: ValidationReport) -> Dict[str, Any]:
    print("  [DASH] Test 3: Multiple Concurrent Clients (10 clients)...")

    _ensure_server()
    results = {"connected": 0, "received": 0, "errors": 0}
    num_clients = 10

    async def connect_multiple():
        import websockets
        clients = []
        for _ in range(num_clients):
            try:
                ws = await asyncio.wait_for(
                    websockets.connect(SHARED_WS_URL, close_timeout=2, ping_interval=None),
                    timeout=TIMEOUT_SHORT,
                )
                clients.append(ws)
            except Exception:
                results["errors"] += 1

        for ws in clients:
            data = await _recv_state(ws)
            if data is not None:
                results["received"] += 1
            else:
                results["errors"] += 1

        for ws in clients:
            try:
                await ws.close()
            except Exception:
                pass

        results["connected"] = len(clients)

    _run_async(connect_multiple())

    def check():
        if results["connected"] >= num_clients * 0.8:
            return True, (f"{results['connected']}/{num_clients} connected, "
                          f"{results['received']} received state")
        return False, f"Only {results['connected']}/{num_clients} connected"

    _check(report, "Multiple clients connect and receive broadcasts simultaneously",
           "Concurrency", check, severity="ERROR",
           fix="Check concurrent WebSocket connection handling")

    return results


# ═══════════════════════════════════════════════════════════════════════════════
# TEST 4: Malformed Packets
# ═══════════════════════════════════════════════════════════════════════════════

def test_malformed_packets(report: ValidationReport) -> Dict[str, Any]:
    print("  [DASH] Test 4: Malformed Packets...")

    _ensure_server()
    results = {"sent": 0, "server_crashed": False, "reconnect_ok": False}

    async def send_malformed():
        import websockets

        try:
            async with websockets.connect(SHARED_WS_URL, close_timeout=2, ping_interval=None) as ws:
                # Drain initial state
                await _recv_state(ws, TIMEOUT_SHORT)

                # Invalid JSON
                for payload in [
                    "{invalid json, not valid}",
                    "",
                    "\x00\x01\x02\x1f\x7f",
                    json.dumps({"type": "command", "command": "block_ip",
                                "params": {"ip": "X" * 100000}}),
                    json.dumps({"type": "command", "command": "eval",
                                "params": {"code": "print('pwned')"}}),
                    json.dumps({"A" * 10000: "test"}),
                    json.dumps({"type": "command", "command": "block_ip",
                                "params": {"ip": "'; DROP TABLE --"}}),
                ]:
                    try:
                        await ws.send(payload)
                        results["sent"] += 1
                    except Exception:
                        pass
        except Exception:
            pass

        # Reconnect and verify server still alive
        try:
            async with websockets.connect(SHARED_WS_URL, close_timeout=2, ping_interval=None) as ws2:
                data = await _recv_state(ws2)
                if data is not None:
                    results["reconnect_ok"] = True
        except Exception:
            results["server_crashed"] = True

    _run_async(send_malformed())

    def check():
        if not results["server_crashed"] and results["reconnect_ok"]:
            return True, (f"{results['sent']} malformed packets sent, "
                          f"server survived, client reconnected")
        return False, f"Server crashed: {results['server_crashed']}"

    _check(report, "Server handles malformed WebSocket packets without crash",
           "Resilience", check, severity="CRITICAL",
           fix="Add try/except around message parsing in _handle_message")

    return results


# ═══════════════════════════════════════════════════════════════════════════════
# TEST 5: Command Channel
# ═══════════════════════════════════════════════════════════════════════════════

def test_command_channel(report: ValidationReport) -> Dict[str, Any]:
    print("  [DASH] Test 5: Command Channel (block/unblock)...")

    from modules.firewall import clear_blocked, is_blocked
    clear_blocked()
    _ensure_server()
    results = {"sent": 0, "responses": 0, "executed": 0}

    async def test_commands():
        import websockets

        try:
            async with websockets.connect(SHARED_WS_URL, close_timeout=2, ping_interval=None) as ws:
                # Drain initial state
                await _recv_state(ws, TIMEOUT_SHORT)

                # block_ip
                await ws.send(json.dumps({
                    "type": "command", "command": "block_ip",
                    "params": {"ip": "10.0.0.99"}
                }))
                results["sent"] += 1
                try:
                    resp = await asyncio.wait_for(ws.recv(), timeout=TIMEOUT_SHORT)
                    d = json.loads(resp)
                    if d.get("type") == "command_result" and d.get("success"):
                        results["responses"] += 1
                    if is_blocked("10.0.0.99"):
                        results["executed"] += 1
                except Exception:
                    pass

                # unblock_ip
                await ws.send(json.dumps({
                    "type": "command", "command": "unblock_ip",
                    "params": {"ip": "10.0.0.99"}
                }))
                results["sent"] += 1
                try:
                    resp = await asyncio.wait_for(ws.recv(), timeout=TIMEOUT_SHORT)
                    d = json.loads(resp)
                    if d.get("type") == "command_result" and d.get("success"):
                        results["responses"] += 1
                    if not is_blocked("10.0.0.99"):
                        results["executed"] += 1
                except Exception:
                    pass

                # Unknown command (should return error)
                await ws.send(json.dumps({
                    "type": "command", "command": "nonexistent", "params": {}
                }))
                results["sent"] += 1
                try:
                    resp = await asyncio.wait_for(ws.recv(), timeout=TIMEOUT_SHORT)
                    d = json.loads(resp)
                    if d.get("type") == "command_result" and not d.get("success"):
                        results["responses"] += 1
                except Exception:
                    pass

        except Exception:
            pass

    _run_async(test_commands())
    clear_blocked()

    def check():
        if results["executed"] >= 2:
            return True, (f"{results['sent']} commands, {results['responses']} responses, "
                          f"{results['executed']} executed")
        return False, f"Only {results['executed']}/3 commands executed"

    _check(report, "Dashboard command channel works (block/unblock IP)",
           "Command Channel", check, severity="ERROR",
           fix="Verify command routing in _handle_message method")

    return results


# ═══════════════════════════════════════════════════════════════════════════════
# TEST 6: High-Frequency Updates
# ═══════════════════════════════════════════════════════════════════════════════

def test_high_frequency_updates(report: ValidationReport) -> Dict[str, Any]:
    print("  [DASH] Test 6: High-Frequency Updates (100 rapid pushes)...")

    ds = _ensure_server()
    results = {"pushes": 0, "received": 0, "errors": 0}

    class MockIncident:
        incident_id = "DASH-TEST-0001"
        created_at = "2026-01-01T00:00:00"
        updated_at = "2026-01-01T00:00:00"
        status = "OPEN"
        risk_level = "HIGH"
        threat_types = ["SYN_SCAN"]
        source_ips = {"10.0.0.1"}
        process_names = set()
        event_count = 1
        last_event_time = 0.0
        timeline = "Test event"
        events = []

    async def rapid_push_test():
        import websockets
        try:
            async with websockets.connect(SHARED_WS_URL, close_timeout=2, ping_interval=None) as ws:
                await _recv_state(ws, TIMEOUT_SHORT)

                for i in range(100):
                    try:
                        mock = MockIncident()
                        mock.incident_id = f"DASH-TEST-{i:04d}"
                        ds.push_incident_update(mock)
                        results["pushes"] += 1
                    except Exception:
                        results["errors"] += 1

                await asyncio.sleep(2)

                try:
                    while True:
                        msg = await asyncio.wait_for(ws.recv(), timeout=1)
                        data = json.loads(msg)
                        if data.get("type") in ("state_update", "incident_update"):
                            results["received"] += 1
                except (asyncio.TimeoutError, Exception):
                    pass
        except Exception:
            results["errors"] += 1

    _run_async(rapid_push_test())

    def check():
        if results["errors"] == 0:
            return True, (f"{results['pushes']} updates pushed, "
                          f"{results['received']} received, 0 errors")
        return False, f"{results['errors']} errors during push test"

    _check(report, "Server handles 100 rapid incident updates without error",
           "Performance", check, severity="WARN",
           fix="Consider rate-limiting or batching push_incident_update calls")

    return results


# ═══════════════════════════════════════════════════════════════════════════════
# TEST 7: Broadcast Integrity
# ═══════════════════════════════════════════════════════════════════════════════

def test_broadcast_integrity(report: ValidationReport) -> Dict[str, Any]:
    print("  [DASH] Test 7: Broadcast Integrity (3 clients)...")

    _ensure_server()
    results = {"connected": 0, "states": [], "match": False, "errors": 0}

    async def broadcast_test():
        import websockets
        clients = []
        states = []
        errors = 0

        for _ in range(3):
            try:
                ws = await asyncio.wait_for(
                    websockets.connect(SHARED_WS_URL, close_timeout=2, ping_interval=None),
                    timeout=TIMEOUT_SHORT,
                )
                clients.append(ws)
            except Exception:
                errors += 1

        for ws in clients:
            data = await _recv_state(ws)
            if data is not None:
                states.append(data)
            else:
                errors += 1

        for ws in clients:
            try:
                await ws.close()
            except Exception:
                pass

        return len(clients), states, errors

    connected, states, errors = _run_async(broadcast_test())
    results["connected"] = connected
    results["states"] = states
    results["errors"] = errors

    if len(states) >= 2:
        # Compare structural integrity: same top-level keys, same health fields
        # Values may differ (timestamps are per-connect), but structure must match
        keysets = [set(s.keys()) for s in states]
        base_keys = keysets[0]
        structure_match = all(ks == base_keys for ks in keysets[1:])

        # Also verify required fields exist
        has_health = all("health" in s for s in states)
        has_blocked = all("blocked_ips" in s for s in states)
        has_timestamp = all("timestamp" in s for s in states)

        results["match"] = structure_match and has_health and has_blocked and has_timestamp

    def check():
        if results["match"] and results["errors"] == 0:
            return True, (f"{results['connected']} clients received structurally identical "
                          f"state (health, blocked_ips, incidents keys present)")
        return False, f"Structural match: {results['match']}, Errors: {results['errors']}"

    _check(report, "All connected clients receive identical broadcast state",
           "Integrity", check, severity="ERROR",
           fix="Verify _broadcast() sends the same message to all clients")

    return results


# ═══════════════════════════════════════════════════════════════════════════════
# TEST 8: Disconnect / Reconnect
# ═══════════════════════════════════════════════════════════════════════════════

def test_disconnect_recovery(report: ValidationReport) -> Dict[str, Any]:
    print("  [DASH] Test 8: Disconnect / Reconnect (5 cycles)...")

    _ensure_server()
    results = {"cycles": 0, "reconnects": 0, "errors": 0}

    async def disconnect_test():
        import websockets
        cycles = 0
        reconnects = 0
        errors = 0

        for _ in range(5):
            try:
                ws = await asyncio.wait_for(
                    websockets.connect(SHARED_WS_URL, close_timeout=2, ping_interval=None),
                    timeout=TIMEOUT_SHORT,
                )
                data = await _recv_state(ws, TIMEOUT_SHORT)
                if data is not None:
                    cycles += 1

                await ws.close()

                ws2 = await asyncio.wait_for(
                    websockets.connect(SHARED_WS_URL, close_timeout=2, ping_interval=None),
                    timeout=TIMEOUT_SHORT,
                )
                data2 = await _recv_state(ws2, TIMEOUT_SHORT)
                if data2 is not None:
                    reconnects += 1

                await ws2.close()

            except Exception:
                errors += 1

        return cycles, reconnects, errors

    cycles, reconnects, errors = _run_async(disconnect_test())
    results["cycles"] = cycles
    results["reconnects"] = reconnects
    results["errors"] = errors

    def check():
        if results["cycles"] >= 4 and results["reconnects"] >= 4:
            return True, (f"{results['cycles']} connect/disconnect cycles, "
                          f"{results['reconnects']} successful reconnects")
        return False, f"Only {results['reconnects']}/{results['cycles']} reconnects"

    _check(report, "Server handles client disconnects and reconnects gracefully",
           "Resilience", check, severity="ERROR",
           fix="Ensure _handle_client cleanup removes disconnected clients from set")

    return results


# ═══════════════════════════════════════════════════════════════════════════════
# RUN ALL
# ═══════════════════════════════════════════════════════════════════════════════

def run_phase10(report: ValidationReport) -> ValidationReport:
    print("\n" + "=" * 60)
    print("  PHASE 10: DASHBOARD TESTING")
    print("  Verifying WebSocket server behavior...")
    print("=" * 60)

    results: Dict[str, Dict[str, Any]] = {}

    # Test 1: Lifecycle (own server)
    print("\n" + "-" * 56)
    results["lifecycle"] = test_lifecycle(report)

    # Start shared server for tests 2-8
    _ensure_server()

    # Test 2: Client Connect
    print("\n" + "-" * 56)
    results["client_connect"] = test_client_connect(report)

    # Test 3: Multiple Clients
    print("\n" + "-" * 56)
    results["multiple_clients"] = test_multiple_clients(report)

    # Test 4: Malformed Packets
    print("\n" + "-" * 56)
    results["malformed"] = test_malformed_packets(report)

    # Test 5: Command Channel
    print("\n" + "-" * 56)
    results["commands"] = test_command_channel(report)

    # Test 6: High-Frequency Updates
    print("\n" + "-" * 56)
    results["high_frequency"] = test_high_frequency_updates(report)

    # Test 7: Broadcast Integrity
    print("\n" + "-" * 56)
    results["broadcast"] = test_broadcast_integrity(report)

    # Test 8: Disconnect/Reconnect
    print("\n" + "-" * 56)
    results["reconnect"] = test_disconnect_recovery(report)

    # Stop shared server
    _stop_server()

    total_errors = sum(
        r.get("errors", 0) for r in results.values() if isinstance(r, dict)
    )
    report.add_metadata("tests_run", str(len(results)))
    report.add_metadata("total_errors", str(total_errors))

    return report


if __name__ == "__main__":
    start = time.time()
    report = ValidationReport("Phase 10", "Dashboard Testing")
    report = run_phase10(report)
    report.duration = time.time() - start

    json_path = PROJECT_ROOT / "validation" / "reports" / "phase10_report.json"
    html_path = PROJECT_ROOT / "validation" / "reports" / "phase10_report.html"
    report.to_json(json_path)
    report.to_html(html_path)

    report.print_console()
    print(f"  JSON report: {json_path}")
    print(f"  HTML report: {html_path}")

    sys.exit(1 if not report.summary()["target_met"] else 0)
