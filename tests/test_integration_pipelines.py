"""
Project AEGIS — Phase 3: Integration Pipeline Tests
====================================================
Verifies complete end-to-end pipelines across AEGIS modules:

  Pipeline 1: Port Scan → Incident → AI Assessment → Firewall Block → Dashboard
  Pipeline 2: Process Threat → Incident → AI Assessment → Firewall Block → Dashboard
  Pipeline 3: DNS Threat → Incident → AI Assessment → Firewall Block → Dashboard
  Pipeline 4: Login Threat → Incident → AI Assessment → Firewall Block → Dashboard
  Pipeline 5: File Threat → Incident → AI Assessment → Dashboard

Each pipeline validates:
  - Detection creates a correlated incident
  - Incident generates a valid AI assessment with MITRE mappings
  - Firewall can block the attacker IP
  - Dashboard server accepts and pushes the update

Usage:
    pytest tests/test_integration_pipelines.py -v
"""

import json
import time
from datetime import datetime

import pytest

from modules.incident_manager import IncidentManager, Incident, IncidentEvent
from modules.ai_analyst import AiAnalyst, AnalystAssessment
from modules.firewall import (
    block_ip, unblock_ip, is_blocked, block_count,
    clear_blocked, get_blocked,
)


# ═══════════════════════════════════════════════════════════════════════════════
# SHARED FIXTURES
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def incident_manager():
    """Create and start an IncidentManager for testing."""
    im = IncidentManager()
    im.start()
    yield im
    im.stop()


@pytest.fixture(autouse=True)
def reset_firewall():
    """Reset firewall state before each pipeline test."""
    clear_blocked()
    yield
    clear_blocked()


# ═══════════════════════════════════════════════════════════════════════════════
# HELPER: VERIFY A COMPLETE ASSESSMENT
# ═══════════════════════════════════════════════════════════════════════════════

def verify_assessment(
    assessment: AnalystAssessment,
    *,
    expected_incident_id: str,
    expected_risk: str = None,
    expect_mitre: bool = True,
    expect_recommendations: bool = True,
    expect_indicators: bool = True,
) -> None:
    """Assert that an assessment is complete and well-formed."""
    assert assessment is not None, "Assessment should not be None"
    assert assessment.incident_id == expected_incident_id, \
        f"Expected ID {expected_incident_id}, got {assessment.incident_id}"
    assert assessment.risk_level in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    assert assessment.confidence in ("HIGH", "MEDIUM", "LOW")
    assert isinstance(assessment.executive_summary, str) and len(assessment.executive_summary) > 20
    assert isinstance(assessment.narrative, str) and len(assessment.narrative) > 20
    assert isinstance(assessment.kill_chain, list) and len(assessment.kill_chain) > 0
    assert isinstance(assessment.generated_at, str) and len(assessment.generated_at) > 10

    if expected_risk:
        assert assessment.risk_level == expected_risk, \
            f"Expected risk {expected_risk}, got {assessment.risk_level}"

    if expect_mitre:
        assert len(assessment.mitre_techniques) > 0, "Should have MITRE techniques"
        for tech in assessment.mitre_techniques:
            assert tech.technique_id.startswith("T"), \
                f"Invalid technique ID: {tech.technique_id}"
            assert tech.technique_name, "Technique name should not be empty"
            assert tech.kill_chain_stage, "Kill chain stage should not be empty"

    if expect_recommendations:
        assert len(assessment.recommended_actions) > 0, "Should have recommendations"

    if expect_indicators:
        assert len(assessment.key_indicators) > 0, "Should have key indicators"

    # Verify the assessment can be displayed without errors
    assessment.display()


def verify_incident(
    incident: Incident,
    *,
    expected_types: list = None,
    expected_ips: set = None,
    min_events: int = 1,
) -> None:
    """Assert that an incident is well-formed."""
    assert incident is not None, "Incident should not be None"
    assert incident.incident_id.startswith("AEGIS-"), \
        f"Invalid incident ID: {incident.incident_id}"
    assert incident.status == "OPEN"
    assert incident.event_count >= min_events, \
        f"Expected >= {min_events} events, got {incident.event_count}"
    assert isinstance(incident.timeline, str) and "No events" not in incident.timeline

    if expected_types:
        for t in expected_types:
            assert t in incident.threat_types, \
                f"Missing threat type {t} in {incident.threat_types}"

    if expected_ips:
        for ip in expected_ips:
            assert ip in incident.source_ips, \
                f"Missing IP {ip} in {incident.source_ips}"


# ═══════════════════════════════════════════════════════════════════════════════
# PIPELINE 1: Network Scan → Incident → Assessment → Firewall Block → Dashboard
# ═══════════════════════════════════════════════════════════════════════════════

class TestPipelineNetworkScan:
    """End-to-end: network scan detection through incident, assessment, and firewall."""

    ATTACKER_IP = "10.0.0.5"

    def test_pipeline_network_scan_to_incident(self, incident_manager):
        """Pipeline Step 1-2: Network threat → correlated incident."""
        from tests.conftest import MockNetworkThreat
        inc = incident_manager.correlate(MockNetworkThreat(
            attacker_ip=self.ATTACKER_IP,
            threat_type="SYN_SCAN",
            risk_level="MEDIUM",
            port_count=25,
            reasoning="SYN scan detected 25 ports",
        ))
        verify_incident(inc, expected_types=["SYN_SCAN"],
                        expected_ips={self.ATTACKER_IP})

    def test_pipeline_network_scan_to_assessment(self, incident_manager):
        """Pipeline Step 1-3: Network threat → incident → AI assessment."""
        from tests.conftest import MockNetworkThreat
        inc = incident_manager.correlate(MockNetworkThreat(
            attacker_ip=self.ATTACKER_IP, threat_type="SYN_SCAN",
        ))
        assert inc is not None
        assessment = AiAnalyst.analyze_incident(inc)
        verify_assessment(assessment, expected_incident_id=inc.incident_id,
                          expected_risk="MEDIUM")

    def test_pipeline_network_scan_to_firewall(self):
        """Pipeline Step 1-4: Block attacker IP via firewall."""
        assert block_ip(self.ATTACKER_IP) is True
        assert is_blocked(self.ATTACKER_IP) is True
        blocked_list = get_blocked()
        assert self.ATTACKER_IP in blocked_list

    def test_pipeline_network_full_e2e(self, incident_manager):
        """Full Pipeline 1: SYN scan → incident → assessment → firewall block."""
        # Step 1: Generate threat
        from tests.conftest import MockNetworkThreat
        threat = MockNetworkThreat(
            attacker_ip=self.ATTACKER_IP, threat_type="SYN_SCAN",
            risk_level="MEDIUM", port_count=50,
        )

        # Step 2: Correlate into incident
        inc = incident_manager.correlate(threat)
        verify_incident(inc, expected_types=["SYN_SCAN"],
                        expected_ips={self.ATTACKER_IP})

        # Step 3: Generate AI assessment
        assessment = AiAnalyst.analyze_incident(inc)
        verify_assessment(assessment, expected_incident_id=inc.incident_id)

        # Step 4: Block the attacker
        assert block_ip(self.ATTACKER_IP) is True
        assert is_blocked(self.ATTACKER_IP) is True

    def test_pipeline_network_multi_stage(self, incident_manager):
        """Multi-stage network attack: SYN + FIN + NULL → single incident."""
        from tests.conftest import MockNetworkThreat
        stages = ["SYN_SCAN", "FIN_SCAN", "NULL_SCAN"]
        first_inc = None
        for stage in stages:
            inc = incident_manager.correlate(MockNetworkThreat(
                attacker_ip=self.ATTACKER_IP, threat_type=stage,
                risk_level="MEDIUM", port_count=15,
            ))
            if first_inc is None:
                first_inc = inc

        # All stages should merge into one incident (same IP + time window)
        assert first_inc is not None
        for stage in stages:
            assert stage in first_inc.threat_types, \
                f"Missing {stage} in merged incident"

        # Generate assessment covering all stages
        assessment = AiAnalyst.analyze_incident(first_inc)
        verify_assessment(assessment, expected_incident_id=first_inc.incident_id)

        # Block the attacker
        assert block_ip(self.ATTACKER_IP) is True


# ═══════════════════════════════════════════════════════════════════════════════
# PIPELINE 2: Process Threat → Incident → Assessment → Firewall
# ═══════════════════════════════════════════════════════════════════════════════

class TestPipelineProcessThreat:
    """End-to-end: process-level threat through full pipeline."""

    def test_pipeline_process_to_incident(self, incident_manager):
        """Process threat → correlated incident."""
        from tests.conftest import MockProcessThreat
        inc = incident_manager.correlate(MockProcessThreat(
            pid=1234, process_name="powershell.exe",
            threat_type="REVERSE_SHELL", risk_level="CRITICAL",
            cmdline="powershell -enc SQBFAFgA",
            parent_pid=888, parent_name="explorer.exe",
        ))
        verify_incident(inc, expected_types=["REVERSE_SHELL"],
                        min_events=1)

    def test_pipeline_process_to_assessment(self, incident_manager):
        """Process threat → incident → MITRE-backed assessment."""
        from tests.conftest import MockProcessThreat
        inc = incident_manager.correlate(MockProcessThreat(
            pid=1234, process_name="powershell.exe",
            threat_type="REVERSE_SHELL", risk_level="CRITICAL",
        ))
        assert inc is not None
        assessment = AiAnalyst.analyze_incident(inc)
        verify_assessment(assessment, expected_incident_id=inc.incident_id)
        # Verify REVERSE_SHELL maps to T1059 (Command and Scripting Interpreter)
        tech_ids = {t.technique_id for t in assessment.mitre_techniques}
        assert "T1059" in tech_ids, f"Expected T1059 in {tech_ids}"

    def test_pipeline_process_suspicious_cmdline(self, incident_manager):
        """Suspicious command line → incident → assessment."""
        from tests.conftest import MockProcessThreat
        inc = incident_manager.correlate(MockProcessThreat(
            pid=5678, process_name="powershell.exe",
            threat_type="SUSPICIOUS_CMDLINE", risk_level="HIGH",
            cmdline="powershell -enc SQBFAFgA",
        ))
        assert inc is not None
        assert "SUSPICIOUS_CMDLINE" in inc.threat_types
        assessment = AiAnalyst.analyze_incident(inc)
        verify_assessment(assessment, expected_incident_id=inc.incident_id)


# ═══════════════════════════════════════════════════════════════════════════════
# PIPELINE 3: DNS Threat → Incident → Assessment → Firewall
# ═══════════════════════════════════════════════════════════════════════════════

class TestPipelineDnsThreat:
    """End-to-end: DNS-level threat through full pipeline."""

    def test_pipeline_dns_to_incident(self, incident_manager):
        """DNS threat → correlated incident."""
        from tests.conftest import MockDnsThreat
        inc = incident_manager.correlate(MockDnsThreat(
            domain="malware.evil.c2.com",
            threat_type="DNS_TUNNEL", risk_level="CRITICAL",
        ))
        verify_incident(inc, expected_types=["DNS_TUNNEL"])

    def test_pipeline_dns_to_assessment(self, incident_manager):
        """DNS threat → incident → assessment with MITRE T1572."""
        from tests.conftest import MockDnsThreat
        inc = incident_manager.correlate(MockDnsThreat(
            domain="malware.evil.c2.com",
            threat_type="DNS_TUNNEL", risk_level="CRITICAL",
        ))
        assert inc is not None
        assessment = AiAnalyst.analyze_incident(inc)
        # DNS threats may not have source IPs, so skip indicator assertion
        verify_assessment(assessment, expected_incident_id=inc.incident_id,
                          expect_indicators=False)
        # DNS tunneling maps to T1572 (Protocol Tunneling)
        tech_ids = {t.technique_id for t in assessment.mitre_techniques}
        assert "T1572" in tech_ids or any(t.startswith("T1572") for t in tech_ids), \
            f"Expected T1572 in {tech_ids}"

    def test_pipeline_dns_beaconing_to_assessment(self, incident_manager):
        """DNS beaconing → incident → assessment."""
        from tests.conftest import MockDnsThreat
        inc = incident_manager.correlate(MockDnsThreat(
            domain="beacon.malicious.com",
            threat_type="BEACONING", risk_level="HIGH",
        ))
        assert inc is not None
        assessment = AiAnalyst.analyze_incident(inc)
        # DNS threats may not populate source IPs/process names, so skip indicators
        verify_assessment(assessment, expected_incident_id=inc.incident_id,
                          expect_indicators=False)
        tech_ids = {t.technique_id for t in assessment.mitre_techniques}
        assert "T1071" in tech_ids or any(t.startswith("T1071") for t in tech_ids), \
            f"Expected T1071 in {tech_ids}"


# ═══════════════════════════════════════════════════════════════════════════════
# PIPELINE 4: Login Threat → Incident → Assessment → Firewall Block
# ═══════════════════════════════════════════════════════════════════════════════

class TestPipelineLoginThreat:
    """End-to-end: login-level threat through full pipeline."""

    ATTACKER_IP = "10.0.0.50"

    def test_pipeline_login_to_incident(self, incident_manager):
        """Login brute force → correlated incident."""
        from tests.conftest import MockLoginThreat
        inc = incident_manager.correlate(MockLoginThreat(
            source_ip=self.ATTACKER_IP, username="admin",
            threat_type="BRUTE_FORCE", risk_level="HIGH",
        ))
        verify_incident(inc, expected_types=["BRUTE_FORCE"],
                        expected_ips={self.ATTACKER_IP})

    def test_pipeline_login_to_assessment(self, incident_manager):
        """Login brute force → incident → assessment with MITRE T1110."""
        from tests.conftest import MockLoginThreat
        inc = incident_manager.correlate(MockLoginThreat(
            source_ip=self.ATTACKER_IP, username="admin",
            threat_type="BRUTE_FORCE", risk_level="HIGH",
        ))
        assert inc is not None
        assessment = AiAnalyst.analyze_incident(inc)
        verify_assessment(assessment, expected_incident_id=inc.incident_id)
        # Brute force maps to T1110 (or sub-techniques T1110.001, T1110.003)
        tech_ids = {t.technique_id for t in assessment.mitre_techniques}
        assert "T1110" in tech_ids or any(t.startswith("T1110") for t in tech_ids), \
            f"Expected T1110 in {tech_ids}"

    def test_pipeline_login_to_firewall(self):
        """Block attacker IP after login attack."""
        assert block_ip(self.ATTACKER_IP) is True
        assert is_blocked(self.ATTACKER_IP) is True

    def test_pipeline_login_full_e2e(self, incident_manager):
        """Full Pipeline 4: brute force → incident → assessment → block."""
        from tests.conftest import MockLoginThreat

        # Step 1-2: Correlate
        inc = incident_manager.correlate(MockLoginThreat(
            source_ip=self.ATTACKER_IP, username="admin",
            threat_type="BRUTE_FORCE", risk_level="HIGH",
            attempt_count=15,
        ))
        verify_incident(inc, expected_types=["BRUTE_FORCE"],
                        expected_ips={self.ATTACKER_IP})

        # Step 3: Assess
        assessment = AiAnalyst.analyze_incident(inc)
        verify_assessment(assessment, expected_incident_id=inc.incident_id)

        # Step 4: Block
        assert block_ip(self.ATTACKER_IP) is True

        # Step 5: Verify
        blocked = get_blocked()
        assert self.ATTACKER_IP in blocked


# ═══════════════════════════════════════════════════════════════════════════════
# PIPELINE 5: File Threat → Incident → Assessment → Dashboard
# ═══════════════════════════════════════════════════════════════════════════════

class TestPipelineFileThreat:
    """End-to-end: file integrity threat through full pipeline."""

    def test_pipeline_file_to_incident(self, incident_manager):
        """File integrity threat → correlated incident."""
        from tests.conftest import MockFileThreat
        inc = incident_manager.correlate(MockFileThreat(
            file_path="/etc/passwd",
            threat_type="FILE_CHANGED", risk_level="HIGH",
        ))
        verify_incident(inc, expected_types=["FILE_CHANGED"])
        assert "/etc/passwd" in inc.file_paths

    def test_pipeline_file_deleted_to_assessment(self, incident_manager):
        """File deletion → incident → assessment with MITRE T1070."""
        from tests.conftest import MockFileThreat
        inc = incident_manager.correlate(MockFileThreat(
            file_path="/etc/shadow",
            threat_type="FILE_DELETED", risk_level="HIGH",
        ))
        assert inc is not None
        assessment = AiAnalyst.analyze_incident(inc)
        verify_assessment(assessment, expected_incident_id=inc.incident_id)
        # File deletion maps to T1070.004
        tech_ids = {t.technique_id for t in assessment.mitre_techniques}
        assert "T1070" in tech_ids or "T1070.004" in tech_ids, \
            f"Expected T1070 in {tech_ids}"


# ═══════════════════════════════════════════════════════════════════════════════
# CROSS-PIPELINE: Complex Multi-Stage Attack
# ═══════════════════════════════════════════════════════════════════════════════

class TestPipelineComplexAttack:
    """Complex multi-stage attack spanning network + login + process."""

    ATTACKER_IP = "192.168.1.100"

    def test_pipeline_complex_multi_stage(self, incident_manager):
        """Full attack chain: recon → brute force → reverse shell → block.

        This is the most realistic scenario — a real attacker would
        follow this exact pattern.
        """
        from tests.conftest import MockNetworkThreat, MockLoginThreat, MockProcessThreat

        threats = [
            # Stage 1: Reconnaissance (network scan)
            MockNetworkThreat(attacker_ip=self.ATTACKER_IP, threat_type="SYN_SCAN",
                              risk_level="MEDIUM", port_count=30),
            # Stage 2: Credential attack (brute force SSH)
            MockLoginThreat(source_ip=self.ATTACKER_IP, username="root",
                            threat_type="BRUTE_FORCE", risk_level="HIGH"),
            # Stage 3: Execution (reverse shell via PowerShell)
            MockProcessThreat(pid=1234, process_name="powershell.exe",
                              threat_type="REVERSE_SHELL", risk_level="CRITICAL"),
        ]

        first_inc = None
        for threat in threats:
            inc = incident_manager.correlate(threat)
            if first_inc is None:
                first_inc = inc

        # All stages should merge into one incident (same source IP + time window)
        assert first_inc is not None
        verify_incident(first_inc, min_events=3)

        # All threat types should be captured
        for expected in ["SYN_SCAN", "BRUTE_FORCE", "REVERSE_SHELL"]:
            assert expected in first_inc.threat_types, \
                f"Missing {expected} in merged incident"

        # The risk should be CRITICAL (highest across all events)
        assert first_inc.risk_level == "CRITICAL", \
            f"Expected CRITICAL risk, got {first_inc.risk_level}"

        # Source IP should be tracked
        assert self.ATTACKER_IP in first_inc.source_ips

        # Generate comprehensive AI assessment
        assessment = AiAnalyst.analyze_incident(first_inc)
        verify_assessment(assessment, expected_incident_id=first_inc.incident_id)

        # The assessment should cover all kill chain stages
        stages = set(assessment.kill_chain)
        assert "Reconnaissance" in stages, f"Missing Reconnaissance in {stages}"
        assert "Execution" in stages, f"Missing Execution in {stages}"

        # The confidence should be HIGH for a 3-stage attack
        assert assessment.confidence in ("HIGH", "MEDIUM"), \
            f"Expected HIGH/MEDIUM confidence, got {assessment.confidence}"

        # Firewall should block the attacker
        assert block_ip(self.ATTACKER_IP) is True
        assert is_blocked(self.ATTACKER_IP) is True

        # Verify assessment display
        assessment.display()


# ═══════════════════════════════════════════════════════════════════════════════
# DASHBOARD SERVER INTEGRATION
# ═══════════════════════════════════════════════════════════════════════════════

class TestPipelineDashboardIntegration:
    """Tests that the Dashboard server can receive and broadcast pipeline results."""

    def test_dashboard_push_incident_no_crash(self):
        """Dashboard server accepts incident push without error."""
        from modules.dashboard_server import DashboardServer

        server = DashboardServer(host="127.0.0.1", port=18765)
        try:
            server.start()
            time.sleep(0.5)
            assert server._running

            now_ts = datetime.now().isoformat()
            incident = Incident(
                incident_id="AEGIS-INTEG-TEST-0001",
                created_at=now_ts, updated_at=now_ts,
                status="OPEN", risk_level="CRITICAL",
                threat_types=["SYN_SCAN", "REVERSE_SHELL"],
                source_ips={"192.168.1.100"},
                event_count=2, last_event_time=time.time(),
            )
            incident.events = [
                IncidentEvent(timestamp=now_ts, threat_type="SYN_SCAN",
                              risk_level="MEDIUM", source="network",
                              summary="SYN_SCAN from 192.168.1.100",
                              detail="30 ports scanned"),
                IncidentEvent(timestamp=now_ts, threat_type="REVERSE_SHELL",
                              risk_level="CRITICAL", source="process",
                              summary="REVERSE_SHELL — powershell.exe",
                              detail="Outbound C2 connection"),
            ]

            # Push without assessment
            server.push_incident_update(incident)
            time.sleep(0.2)

            # Push with assessment
            assessment = AiAnalyst.analyze_incident(incident)
            server.push_incident_update(incident, assessment)
            time.sleep(0.2)

        finally:
            server.stop()

    def test_dashboard_full_pipeline_push(self, incident_manager):
        """Full pipeline: incident → assessment → dashboard push."""
        from modules.dashboard_server import DashboardServer
        from tests.conftest import MockNetworkThreat, MockLoginThreat, MockProcessThreat

        # Create incident from a multi-stage attack
        threats = [
            MockNetworkThreat(attacker_ip="10.0.0.99", threat_type="SYN_SCAN"),
            MockLoginThreat(source_ip="10.0.0.99", username="admin",
                            threat_type="BRUTE_FORCE"),
            MockProcessThreat(pid=9999, process_name="powershell.exe",
                              threat_type="REVERSE_SHELL", risk_level="CRITICAL"),
        ]

        inc = None
        for threat in threats:
            inc = incident_manager.correlate(threat)

        assert inc is not None
        assessment = AiAnalyst.analyze_incident(inc)

        # Start dashboard and push
        server = DashboardServer(host="127.0.0.1", port=18766)
        try:
            server.start()
            time.sleep(0.3)
            server.push_incident_update(inc)
            time.sleep(0.2)
            if assessment:
                server.push_incident_update(inc, assessment)
                time.sleep(0.2)
        finally:
            server.stop()


# ═══════════════════════════════════════════════════════════════════════════════
# EDGE CASES & ERROR HANDLING
# ═══════════════════════════════════════════════════════════════════════════════

class TestPipelineEdgeCases:
    """Edge cases for the integration pipelines."""

    def test_empty_incident_no_assessment(self):
        """An incident with no events should produce no assessment."""
        empty = Incident(
            incident_id="AEGIS-EMPTY-0001",
            created_at=datetime.now().isoformat(),
            updated_at=datetime.now().isoformat(),
            status="OPEN", risk_level="LOW",
            event_count=0, last_event_time=0,
        )
        assessment = AiAnalyst.analyze_incident(empty)
        assert assessment is None, "Empty incident should return None"

    def test_firewall_blocks_before_assessment(self, incident_manager):
        """Firewall block should work independently of incident pipeline."""
        from tests.conftest import MockNetworkThreat

        # Block first
        assert block_ip("10.0.0.77") is True

        # Then correlate (should still work)
        inc = incident_manager.correlate(MockNetworkThreat(attacker_ip="10.0.0.77"))
        assert inc is not None
        assert "10.0.0.77" in inc.source_ips

    def test_unblock_after_assessment(self, incident_manager):
        """Unblock an IP after the full pipeline completes."""
        from tests.conftest import MockNetworkThreat

        inc = incident_manager.correlate(
            MockNetworkThreat(attacker_ip="10.0.0.88", threat_type="SYN_SCAN")
        )
        assert inc is not None

        assessment = AiAnalyst.analyze_incident(inc)
        assert assessment is not None

        # Block
        assert block_ip("10.0.0.88") is True
        assert is_blocked("10.0.0.88") is True

        # Unblock
        assert unblock_ip("10.0.0.88") is True
        assert is_blocked("10.0.0.88") is False
