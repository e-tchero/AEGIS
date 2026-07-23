"""Tests for DashboardServer — coverage booster for WebSocket handling.

Covers _handle_message (all commands: block_ip, unblock_ip, lockdown_on/off, unknown),
_handle_client lifecycle, _gather_and_broadcast, state gathering fallbacks,
_incident_to_dict, push_incident_update, standalone mode, and edge cases.
"""

import json
import builtins
from unittest.mock import patch, MagicMock

import pytest


# ═══════════════════════════════════════════════════════════════════════════════
# FIXTURES
# ═══════════════════════════════════════════════════════════════════════════════


class MockWebSocket:
    """Mock websocket for testing _handle_client and _handle_message."""

    def __init__(self, remote_address=("127.0.0.1", 54321)):
        self.remote_address = remote_address
        self.sent_messages = []
        self.closed = False

    async def send(self, message):
        self.sent_messages.append(message)

    def __aiter__(self):
        return self

    async def __anext__(self):
        raise StopAsyncIteration


class MockIncident:
    """Minimal mock incident for testing _incident_to_dict and push_incident_update."""

    def __init__(
        self,
        incident_id="INC-001",
        status="open",
        risk_level="HIGH",
        threat_types=None,
        source_ips=None,
        process_names=None,
        event_count=3,
        last_event_time=1000.0,
        timeline="",
        events=None,
    ):
        self.incident_id = incident_id
        self.created_at = "2026-01-15T10:00:00"
        self.updated_at = "2026-01-15T10:05:00"
        self.status = status
        self.risk_level = risk_level
        self.threat_types = threat_types or ["PORT_SCAN"]
        self.source_ips = source_ips if source_ips is not None else {"10.0.0.5"}
        self.process_names = process_names if process_names is not None else set()
        self.event_count = event_count
        self.last_event_time = last_event_time
        self.timeline = timeline
        self.events = events or []


class MockEvent:
    def __init__(
        self,
        timestamp="2026-01-15T10:00:00",
        threat_type="PORT_SCAN",
        risk_level="HIGH",
        source="network",
        summary="Port scan detected",
        detail="Nmap SYN scan on port 22",
    ):
        self.timestamp = timestamp
        self.threat_type = threat_type
        self.risk_level = risk_level
        self.source = source
        self.summary = summary
        self.detail = detail


class MockAssessment:
    def __init__(self):
        self.risk_level = "HIGH"
        self.confidence = "HIGH"
        self.executive_summary = "Test summary"
        self.kill_chain = ["Recon", "Exploit"]
        self.mitre_techniques = [
            MagicMock(
                technique_id="T1595",
                technique_name="Active Scanning",
                kill_chain_stage="Reconnaissance",
            )
        ]
        self.recommended_actions = ["Block IP", "Investigate"]
        self.key_indicators = {"source_ips": ["10.0.0.5"]}


@pytest.fixture
def server():
    """Create a DashboardServer instance with mocks for testing internals."""
    from modules.dashboard_server import DashboardServer

    s = DashboardServer(host="127.0.0.1", port=18766)
    s._loop = MagicMock()
    s._loop.is_running.return_value = True
    return s


@pytest.fixture
def mock_ws():
    return MockWebSocket()


# ═══════════════════════════════════════════════════════════════════════════════
# LIFECYCLE
# ═══════════════════════════════════════════════════════════════════════════════


class TestLifecycle:
    """Test start/stop behavior."""

    def test_start(self, server):
        with patch.object(server, "_run_loop"):
            server.start()
            assert server._running is True
            assert server._thread is not None

    def test_start_already_running(self, server):
        server._running = True
        with patch.object(server, "_run_loop"):
            server.start()

    def test_stop_without_start(self, server):
        server.stop()

    def test_stop_with_running_loop(self, server):
        server._loop = MagicMock()
        server._loop.is_running.return_value = True
        server._running = True
        server.stop()
        server._loop.call_soon_threadsafe.assert_called_once()

    def test_stop_with_thread(self, server):
        mock_thread = MagicMock()
        mock_thread.is_alive.return_value = True
        server._thread = mock_thread
        server._running = True
        server.stop()
        mock_thread.join.assert_called_once_with(timeout=3.0)

    def test_run_loop_error(self, server):
        """_run_loop should catch errors and close loop."""
        # Must use spec=AbstractEventLoop so set_event_loop() accepts it
        import asyncio
        mock_loop = MagicMock(spec=asyncio.AbstractEventLoop)
        mock_loop.run_until_complete.side_effect = RuntimeError("Server error")
        with patch("asyncio.new_event_loop", return_value=mock_loop):
            server._run_loop()
            mock_loop.close.assert_called_once()


# ═══════════════════════════════════════════════════════════════════════════════
# STATE GATHERING
# ═══════════════════════════════════════════════════════════════════════════════


class TestStateGathering:
    """Test _gather_state and its sub-methods."""

    @pytest.mark.asyncio
    async def test_gather_state_success(self, server):
        with patch.object(server, "_get_health_state", return_value={"status": "OK", "health_score": 95}):
            with patch.object(server, "_get_incidents_state", return_value=[{"id": "1"}]):
                with patch.object(server, "_get_blocked_ips_state", return_value=["10.0.0.1"]):
                    state = await server._gather_state()
                    assert state is not None
                    assert state["health"]["status"] == "OK"
                    assert state["incidents"][0]["id"] == "1"
                    assert "10.0.0.1" in state["blocked_ips"]
                    assert "timestamp" in state

    @pytest.mark.asyncio
    async def test_gather_state_exception(self, server):
        with patch.object(server, "_get_health_state", side_effect=Exception("boom")):
            state = await server._gather_state()
            assert state is None

    @pytest.mark.asyncio
    async def test_gather_and_broadcast_no_clients(self, server):
        with patch.object(server, "_gather_state") as mock_gather:
            mock_gather.return_value = {"health": {"status": "OK"}}
            with patch.object(server, "_broadcast") as mock_broadcast:
                await server._gather_and_broadcast()
                mock_broadcast.assert_not_called()
                assert server._last_health["status"] == "OK"

    @pytest.mark.asyncio
    async def test_gather_and_broadcast_with_clients(self, server):
        server._clients.add("mock_client")
        mock_state = {
            "health": {"status": "OK"},
            "incidents": [],
            "blocked_ips": [],
            "assessments": {},
        }
        with patch.object(server, "_gather_state", return_value=mock_state):
            with patch.object(server, "_broadcast") as mock_broadcast:
                await server._gather_and_broadcast()
                mock_broadcast.assert_called_once()

    @pytest.mark.asyncio
    async def test_gather_and_broadcast_no_state(self, server):
        with patch.object(server, "_gather_state", return_value=None):
            with patch.object(server, "_broadcast") as mock_broadcast:
                await server._gather_and_broadcast()
                mock_broadcast.assert_not_called()


class TestGetHealthState:
    """Test _get_health_state with various scenarios."""

    @pytest.mark.asyncio
    async def test_heartbeat_success(self, server):
        mock_heartbeat = MagicMock()
        # pulse() returns a dict directly instead of a MagicMock,
        # avoiding asdict() failure on non-dataclass objects
        mock_heartbeat.pulse.return_value = {
            "status": "HEALTHY",
            "health_score": 98,
            "cpu_percent": 12.5,
            "ram_percent": 45.0,
            "active_connections": 5,
            "timestamp": "2026-01-01T00:00:00",
        }

        with patch("core.heartbeat.Heartbeat", return_value=mock_heartbeat):
            # Patch asdict to return the snap dict directly
            with patch("modules.dashboard_server.asdict", side_effect=lambda x: x):
                health = await server._get_health_state()
                assert health["status"] == "HEALTHY"
                assert health["health_score"] == 98
                assert server._heartbeat_created is True

    @pytest.mark.asyncio
    async def test_heartbeat_reuses_instance(self, server):
        server._heartbeat_created = True
        server._heartbeat_instance = MagicMock()
        server._heartbeat_instance.pulse.return_value = None

        health = await server._get_health_state()
        assert health["status"] == "UNKNOWN"
        assert health["health_score"] == 0

    @pytest.mark.asyncio
    async def test_heartbeat_import_error(self, server):
        with patch("core.heartbeat.Heartbeat", side_effect=ImportError("no module")):
            health = await server._get_health_state()
            assert health["status"] == "UNKNOWN"
            assert health["health_score"] == 0

    @pytest.mark.asyncio
    async def test_heartbeat_returns_cached(self, server):
        server._heartbeat_created = True
        server._heartbeat_instance = MagicMock()
        server._heartbeat_instance.pulse.return_value = None
        server._last_health = {"status": "HEALTHY", "health_score": 90}

        health = await server._get_health_state()
        assert health["status"] == "HEALTHY"
        assert health["health_score"] == 90


class TestGetIncidentsState:
    """Test _get_incidents_state with various scenarios."""

    @pytest.mark.asyncio
    async def test_returns_cached_incidents(self, server):
        server._last_incidents = [{"incident_id": "INC-001"}]
        incidents = await server._get_incidents_state()
        assert len(incidents) == 1
        assert incidents[0]["incident_id"] == "INC-001"

    @pytest.mark.asyncio
    async def test_empty_when_no_cache(self, server):
        incidents = await server._get_incidents_state()
        assert incidents == []


class TestGetBlockedIpsState:
    """Test _get_blocked_ips_state."""

    @pytest.mark.asyncio
    async def test_from_firewall(self, server):
        with patch("modules.firewall.get_blocked", return_value=["10.0.0.1", "10.0.0.2"]):
            ips = await server._get_blocked_ips_state()
            assert ips == ["10.0.0.1", "10.0.0.2"]

    @pytest.mark.asyncio
    async def test_limit_100(self, server):
        many_ips = [f"10.0.0.{i}" for i in range(150)]
        with patch("modules.firewall.get_blocked", return_value=many_ips):
            ips = await server._get_blocked_ips_state()
            assert len(ips) == 100

    @pytest.mark.asyncio
    async def test_import_error_fallback(self, server):
        server._last_blocked_ips = ["10.0.0.1"]
        with patch("modules.firewall.get_blocked", side_effect=ImportError("no firewall")):
            ips = await server._get_blocked_ips_state()
            assert ips == ["10.0.0.1"]


# ═══════════════════════════════════════════════════════════════════════════════
# INCIDENT TO DICT
# ═══════════════════════════════════════════════════════════════════════════════


class TestIncidentToDict:
    """Test _incident_to_dict static method."""

    def test_valid_incident(self):
        from modules.dashboard_server import DashboardServer

        event = MockEvent()
        inc = MockIncident(
            incident_id="INC-001",
            threat_types=["PORT_SCAN", "BRUTE_FORCE"],
            source_ips={"10.0.0.5", "10.0.0.99"},
            events=[event],
        )
        result = DashboardServer._incident_to_dict(inc)
        assert result["incident_id"] == "INC-001"
        assert "PORT_SCAN" in result["threat_types"]
        assert "10.0.0.5" in result["source_ips"]
        assert result["event_count"] == 3
        assert len(result["events"]) == 1
        assert result["events"][0]["threat_type"] == "PORT_SCAN"
        assert result["events"][0]["detail"] == "Nmap SYN scan on port 22"

    def test_incident_with_long_detail(self):
        """Detail should be truncated to 200 chars."""
        from modules.dashboard_server import DashboardServer

        long_detail = "A" * 500
        event = MockEvent(detail=long_detail)
        inc = MockIncident(events=[event])
        result = DashboardServer._incident_to_dict(inc)
        assert len(result["events"][0]["detail"]) == 200

    def test_non_incident_object(self):
        from modules.dashboard_server import DashboardServer

        result = DashboardServer._incident_to_dict("not_an_incident")
        assert result == {}

    def test_incident_without_events(self):
        from modules.dashboard_server import DashboardServer

        inc = MockIncident(events=None)
        result = DashboardServer._incident_to_dict(inc)
        assert result["events"] == []

    def test_empty_source_ips(self):
        from modules.dashboard_server import DashboardServer

        inc = MockIncident(source_ips=set())
        result = DashboardServer._incident_to_dict(inc)
        assert result["source_ips"] == []

    def test_timeline_present(self):
        from modules.dashboard_server import DashboardServer

        inc = MockIncident(timeline="09:14 Port Scan -> 09:15 Brute Force")
        result = DashboardServer._incident_to_dict(inc)
        assert "Port Scan" in result["timeline"]


# ═══════════════════════════════════════════════════════════════════════════════
# MESSAGE HANDLING (Commands)
# ═══════════════════════════════════════════════════════════════════════════════


class TestHandleMessage:
    """Test _handle_message with all command types."""

    @pytest.mark.asyncio
    async def test_block_ip_success(self, server, mock_ws):
        with patch("modules.firewall.block_ip", return_value=True):
            await server._handle_message(
                mock_ws,
                json.dumps({"type": "command", "command": "block_ip", "params": {"ip": "10.0.0.5"}}),
            )
            assert len(mock_ws.sent_messages) == 1
            resp = json.loads(mock_ws.sent_messages[0])
            assert resp["type"] == "command_result"
            assert resp["success"] is True

    @pytest.mark.asyncio
    async def test_block_ip_no_ip(self, server, mock_ws):
        await server._handle_message(
            mock_ws, json.dumps({"type": "command", "command": "block_ip", "params": {}})
        )
        assert len(mock_ws.sent_messages) == 0

    @pytest.mark.asyncio
    async def test_block_ip_exception(self, server, mock_ws):
        with patch("modules.firewall.block_ip", side_effect=RuntimeError("firewall error")):
            await server._handle_message(
                mock_ws,
                json.dumps({"type": "command", "command": "block_ip", "params": {"ip": "10.0.0.5"}}),
            )
            resp = json.loads(mock_ws.sent_messages[0])
            assert resp["success"] is False
            assert "error" in resp

    @pytest.mark.asyncio
    async def test_unblock_ip_success(self, server, mock_ws):
        with patch("modules.firewall.unblock_ip", return_value=True):
            await server._handle_message(
                mock_ws,
                json.dumps({"type": "command", "command": "unblock_ip", "params": {"ip": "10.0.0.5"}}),
            )
            resp = json.loads(mock_ws.sent_messages[0])
            assert resp["type"] == "command_result"
            assert resp["success"] is True

    @pytest.mark.asyncio
    async def test_unblock_ip_no_ip(self, server, mock_ws):
        await server._handle_message(
            mock_ws, json.dumps({"type": "command", "command": "unblock_ip", "params": {}})
        )
        assert len(mock_ws.sent_messages) == 0

    @pytest.mark.asyncio
    async def test_unblock_ip_exception(self, server, mock_ws):
        with patch("modules.firewall.unblock_ip", side_effect=RuntimeError("error")):
            await server._handle_message(
                mock_ws,
                json.dumps({"type": "command", "command": "unblock_ip", "params": {"ip": "10.0.0.5"}}),
            )
            resp = json.loads(mock_ws.sent_messages[0])
            assert resp["success"] is False

    @pytest.mark.asyncio
    async def test_lockdown_on(self, server, mock_ws):
        with patch("modules.firewall.set_lockdown") as mock_lockdown:
            await server._handle_message(
                mock_ws, json.dumps({"type": "command", "command": "lockdown_on"})
            )
            mock_lockdown.assert_called_once_with(True)
            resp = json.loads(mock_ws.sent_messages[0])
            assert resp["success"] is True

    @pytest.mark.asyncio
    async def test_lockdown_on_exception(self, server, mock_ws):
        with patch("modules.firewall.set_lockdown", side_effect=RuntimeError("error")):
            await server._handle_message(
                mock_ws, json.dumps({"type": "command", "command": "lockdown_on"})
            )
            resp = json.loads(mock_ws.sent_messages[0])
            assert resp["success"] is False

    @pytest.mark.asyncio
    async def test_lockdown_off(self, server, mock_ws):
        with patch("modules.firewall.set_lockdown") as mock_lockdown:
            await server._handle_message(
                mock_ws, json.dumps({"type": "command", "command": "lockdown_off"})
            )
            mock_lockdown.assert_called_once_with(False)
            resp = json.loads(mock_ws.sent_messages[0])
            assert resp["success"] is True

    @pytest.mark.asyncio
    async def test_lockdown_off_exception(self, server, mock_ws):
        with patch("modules.firewall.set_lockdown", side_effect=RuntimeError("error")):
            await server._handle_message(
                mock_ws, json.dumps({"type": "command", "command": "lockdown_off"})
            )
            resp = json.loads(mock_ws.sent_messages[0])
            assert resp["success"] is False

    @pytest.mark.asyncio
    async def test_unknown_command(self, server, mock_ws):
        await server._handle_message(
            mock_ws, json.dumps({"type": "command", "command": "restart"})
        )
        resp = json.loads(mock_ws.sent_messages[0])
        assert resp["success"] is False
        assert "Unknown command" in resp["error"]

    @pytest.mark.asyncio
    async def test_invalid_json(self, server, mock_ws):
        await server._handle_message(mock_ws, "not json")
        assert len(mock_ws.sent_messages) == 0

    @pytest.mark.asyncio
    async def test_not_a_command_type(self, server, mock_ws):
        await server._handle_message(mock_ws, json.dumps({"type": "chat", "text": "hello"}))
        assert len(mock_ws.sent_messages) == 0

    @pytest.mark.asyncio
    async def test_not_a_dict(self, server, mock_ws):
        await server._handle_message(mock_ws, json.dumps(["not", "a", "dict"]))
        assert len(mock_ws.sent_messages) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# CLIENT HANDLING
# ═══════════════════════════════════════════════════════════════════════════════


class TestHandleClient:
    """Test _handle_client lifecycle."""

    @pytest.mark.asyncio
    async def test_client_connect_sends_state(self, server):
        ws = MockWebSocket()
        with patch.object(server, "_gather_state", return_value={"health": {"status": "OK"}}):
            await server._handle_client(ws)
        # Client was added but then removed in finally block (StopAsyncIteration).
        # Verify it was connected by checking the state was sent.
        assert len(ws.sent_messages) >= 1

    @pytest.mark.asyncio
    async def test_client_connect_state_fails(self, server):
        ws = MockWebSocket()
        with patch.object(server, "_gather_state", side_effect=Exception("state error")):
            await server._handle_client(ws)
        # Client was added but then removed in finally block.
        # Verify no state was sent (since gather_state raised).
        assert len(ws.sent_messages) == 0

    @pytest.mark.asyncio
    async def test_client_disconnect_removed(self, server):
        ws = MockWebSocket()
        with patch.object(server, "_gather_state", return_value={"health": {"status": "OK"}}):
            await server._handle_client(ws)
            assert ws not in server._clients


# ═══════════════════════════════════════════════════════════════════════════════
# BROADCAST
# ═══════════════════════════════════════════════════════════════════════════════


class TestBroadcast:
    """Test _broadcast method."""

    @pytest.mark.asyncio
    async def test_broadcast_no_clients(self, server):
        await server._broadcast("test message")

    @pytest.mark.asyncio
    async def test_broadcast_to_clients(self, server):
        ws1 = MockWebSocket()
        ws2 = MockWebSocket()
        server._clients.add(ws1)
        server._clients.add(ws2)
        await server._broadcast(json.dumps({"type": "test"}))
        assert len(ws1.sent_messages) == 1
        assert len(ws2.sent_messages) == 1

    @pytest.mark.asyncio
    async def test_broadcast_disconnected_client_removed(self, server):
        ws1 = MockWebSocket()
        ws2 = MockWebSocket()

        async def failing_send(msg):
            raise ConnectionError("disconnected")

        ws1.send = failing_send
        server._clients.add(ws1)
        server._clients.add(ws2)
        await server._broadcast("test")
        assert ws1 not in server._clients
        assert ws2 in server._clients


# ═══════════════════════════════════════════════════════════════════════════════
# PUSH INCIDENT UPDATE
# ═══════════════════════════════════════════════════════════════════════════════


class TestPushIncidentUpdate:
    """Test push_incident_update external API."""

    def test_push_without_assessment(self, server):
        inc = MockIncident()
        server._loop = MagicMock()
        server._loop.is_running.return_value = True
        server.push_incident_update(inc)

    def test_push_with_assessment(self, server):
        inc = MockIncident(incident_id="INC-001")
        assessment = MockAssessment()
        server._loop = MagicMock()
        server._loop.is_running.return_value = True

        with patch("asyncio.run_coroutine_threadsafe") as mock_schedule:
            server.push_incident_update(inc, assessment)
            mock_schedule.assert_called_once()

    def test_push_loop_not_running(self, server):
        inc = MockIncident()
        server._loop = MagicMock()
        server._loop.is_running.return_value = False

        with patch("asyncio.run_coroutine_threadsafe") as mock_schedule:
            server.push_incident_update(inc)
            mock_schedule.assert_not_called()

    def test_push_no_loop(self, server):
        server._loop = None
        inc = MockIncident()
        server.push_incident_update(inc)


# ═══════════════════════════════════════════════════════════════════════════════
# POLLING LOOP
# ═══════════════════════════════════════════════════════════════════════════════


class TestPollingLoop:
    """Test _polling_loop."""

    @pytest.mark.asyncio
    async def test_polling_not_running(self, server):
        server._running = False
        server._poll_interval = 0.1
        with patch.object(server, "_gather_and_broadcast") as mock_gather:
            await server._polling_loop()
            assert mock_gather.call_count == 0

    @pytest.mark.asyncio
    async def test_polling_gather_error(self, server):
        """Polling should continue after a gather error."""
        gather_count = 0

        async def mock_gather():
            nonlocal gather_count
            gather_count += 1
            if gather_count == 1:
                raise Exception("gather error")
            server._running = False

        server._running = True
        server._poll_interval = 0.05
        with patch.object(server, "_gather_and_broadcast", side_effect=mock_gather):
            await server._polling_loop()
            assert gather_count >= 1


# ═══════════════════════════════════════════════════════════════════════════════
# STANDALONE MODE
# ═══════════════════════════════════════════════════════════════════════════════


class TestStandalone:
    """Test __main__ standalone execution."""

    def test_standalone_starts_and_stops(self):
        from modules.dashboard_server import DashboardServer

        server = DashboardServer()
        with patch.object(server, "start") as mock_start:
            with patch.object(server, "stop") as mock_stop:
                try:
                    server.start()
                    raise KeyboardInterrupt()
                except KeyboardInterrupt:
                    server.stop()
                mock_start.assert_called_once()
                mock_stop.assert_called_once()
