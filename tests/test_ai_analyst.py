"""Tests for the AEGIS AI Security Analyst (Priority 7)."""

import time
from datetime import datetime

import pytest

from modules.ai_analyst import (
    AiAnalyst, AnalystAssessment, MitreTechnique,
    MITRE_MAPPING, KILL_CHAIN_STAGES, RESPONSE_ACTIONS,
)
from modules.incident_manager import Incident, IncidentEvent


class TestMitreMapping:
    """Tests for MITRE ATT&CK mapping coverage."""

    def test_all_module_threats_mapped(self):
        """Every threat type used by AEGIS modules must have a MITRE mapping."""
        module_threats = {
            "SYN_SCAN", "FIN_SCAN", "XMAS_SCAN", "NULL_SCAN", "UDP_SCAN",
            "REVERSE_SHELL", "SUSPICIOUS_CMDLINE", "SUSPICIOUS_CHAIN",
            "PERSISTENCE", "PRIVILEGE_ESC", "CRYPTO_MINER",
            "RWX_MEMORY", "DLL_INJECTION", "REFLECTIVE_LOAD", "PROCESS_HOLLOWING",
            "HIGH_MAP_COUNT",
            "DNS_TUNNEL", "HIGH_ENTROPY", "BEACONING", "TXT_ABUSE", "LARGE_RESPONSE",
            "BRUTE_FORCE", "NEW_ADMIN", "SUSPICIOUS_LOGIN",
            "FILE_CHANGED", "FILE_DELETED",
        }
        missing = module_threats - set(MITRE_MAPPING.keys())
        assert not missing, f"Threat types missing MITRE mappings: {missing}"

    def test_mitre_mapping_structure(self):
        """Each MITRE mapping contains a list of (technique_id, name, description) tuples."""
        for threat_type, mappings in MITRE_MAPPING.items():
            assert isinstance(mappings, list), f"{threat_type} should be a list"
            assert len(mappings) > 0, f"{threat_type} has empty mappings"
            for mapping in mappings:
                assert isinstance(mapping, tuple), f"{threat_type} mapping should be tuple"
                assert len(mapping) == 3, f"{threat_type} mapping should have 3 elements"
                tech_id, tech_name, desc = mapping
                assert isinstance(tech_id, str) and tech_id.startswith("T"), \
                    f"{threat_type} has invalid technique_id: {tech_id}"
                assert isinstance(tech_name, str) and len(tech_name) > 0

    def test_response_actions_structure(self):
        """All threat types should have response playbooks."""
        for threat_type, actions in RESPONSE_ACTIONS.items():
            assert isinstance(actions, list), f"{threat_type} actions should be list"
            assert len(actions) >= 1, f"{threat_type} has no actions"

    def test_kill_chain_stages_structure(self):
        """MITRE technique IDs map to kill chain stages."""
        for tech_id, stage in KILL_CHAIN_STAGES.items():
            assert isinstance(tech_id, str) and tech_id.startswith("T"), \
                f"Invalid technique ID: {tech_id}"
            assert isinstance(stage, str) and len(stage) > 0

    def test_technique_ids_in_kill_chain_are_mapped(self):
        """All technique IDs from MITRE_MAPPING should have kill chain entries."""
        all_tech_ids = set()
        for mappings in MITRE_MAPPING.values():
            for tech_id, _, _ in mappings:
                all_tech_ids.add(tech_id)
        missing = all_tech_ids - set(KILL_CHAIN_STAGES.keys())
        assert not missing, f"Technique IDs missing kill chain mapping: {missing}"


class TestAnalystAssessment:
    """Tests for the AnalystAssessment data model."""

    def test_assessment_creation(self):
        assessment = AnalystAssessment(
            incident_id="AEGIS-TEST-0001",
            risk_level="CRITICAL",
            confidence="HIGH",
            executive_summary="Test summary",
            narrative="Test narrative",
            generated_at=datetime.now().isoformat(),
            mitre_techniques=[
                MitreTechnique(
                    technique_id="T1595",
                    technique_name="Active Scanning",
                    kill_chain_stage="Reconnaissance",
                    description="Port scan detected",
                    source="SYN_SCAN",
                )
            ],
            kill_chain=["Reconnaissance", "Exploitation"],
            recommended_actions=["Isolate host", "Block IP"],
            key_indicators={"Source IPs": ["10.0.0.5"]},
        )
        assert assessment.incident_id == "AEGIS-TEST-0001"
        assert assessment.risk_level == "CRITICAL"
        assert assessment.confidence == "HIGH"
        assert len(assessment.mitre_techniques) == 1

    def test_assessment_empty_lists(self):
        assessment = AnalystAssessment(
            incident_id="AEGIS-TEST-0002",
            risk_level="LOW",
            confidence="LOW",
            executive_summary="",
            narrative="",
            generated_at=datetime.now().isoformat(),
            mitre_techniques=[],
            kill_chain=[],
            recommended_actions=[],
            key_indicators={},
        )
        assert assessment.incident_id == "AEGIS-TEST-0002"
        assert len(assessment.mitre_techniques) == 0

    def test_mitre_technique_creation(self):
        tech = MitreTechnique(
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            kill_chain_stage="Execution",
            description="PowerShell execution detected",
            source="REVERSE_SHELL",
        )
        assert tech.technique_id == "T1059"
        assert tech.technique_name == "Command and Scripting Interpreter"

    def test_assessment_display_no_crash(self):
        assessment = AnalystAssessment(
            incident_id="AEGIS-TEST-DISPLAY",
            risk_level="HIGH",
            confidence="MEDIUM",
            executive_summary="Display test",
            narrative="This is a test narrative",
            generated_at=datetime.now().isoformat(),
            mitre_techniques=[
                MitreTechnique(
                    technique_id="T1110", technique_name="Brute Force",
                    kill_chain_stage="Credential Access",
                    description="Failed login attempts", source="BRUTE_FORCE",
                ),
            ],
            kill_chain=["Reconnaissance", "Credential Access"],
            recommended_actions=["Block IP", "Alert admin"],
            key_indicators={"Source IPs": ["10.0.0.5"]},
        )
        assessment.display()


class TestAiAnalyst:
    """Tests for the main AI Analyst analysis pipeline."""

    @staticmethod
    def _create_incident(risk="CRITICAL", threat_types=None, event_count=4, source_ips=None):
        if threat_types is None:
            threat_types = ["SYN_SCAN", "BRUTE_FORCE", "PRIVILEGE_ESC", "REVERSE_SHELL"]
        if source_ips is None:
            source_ips = {"192.168.1.100"}
        now_ts = datetime.now().isoformat()
        incident = Incident(
            incident_id="AEGIS-TEST-0001",
            created_at=now_ts,
            updated_at=now_ts,
            status="OPEN",
            risk_level=risk,
            threat_types=threat_types,
            source_ips=source_ips,
            process_names={"powershell.exe"},
            event_count=event_count,
            last_event_time=time.time(),
        )
        event_data = [
            ("SYN_SCAN", "MEDIUM", "network"),
            ("BRUTE_FORCE", "HIGH", "login"),
            ("PRIVILEGE_ESC", "HIGH", "process"),
            ("REVERSE_SHELL", "CRITICAL", "process"),
        ][:max(event_count, 1)]
        incident.events = [
            IncidentEvent(
                timestamp=now_ts, threat_type=t, risk_level=r,
                source=s, summary=f"{t} detected", detail="Test detail"
            )
            for t, r, s in event_data
        ]
        return incident

    def test_analyze_incident_returns_assessment(self):
        incident = self._create_incident()
        assessment = AiAnalyst.analyze_incident(incident)
        assert assessment is not None
        assert isinstance(assessment, AnalystAssessment)

    def test_assessment_has_incident_id(self):
        incident = self._create_incident()
        assessment = AiAnalyst.analyze_incident(incident)
        assert assessment is not None
        assert assessment.incident_id == "AEGIS-TEST-0001"

    def test_assessment_has_risk_level(self):
        incident = self._create_incident(risk="CRITICAL")
        assessment = AiAnalyst.analyze_incident(incident)
        assert assessment is not None
        assert assessment.risk_level == "CRITICAL"

    def test_assessment_has_confidence(self):
        incident = self._create_incident(event_count=4)
        assessment = AiAnalyst.analyze_incident(incident)
        assert assessment is not None
        assert assessment.confidence in ("HIGH", "MEDIUM", "LOW")

    def test_assessment_has_executive_summary(self):
        incident = self._create_incident()
        assessment = AiAnalyst.analyze_incident(incident)
        assert assessment is not None
        assert isinstance(assessment.executive_summary, str)
        assert len(assessment.executive_summary) > 20

    def test_assessment_has_narrative(self):
        incident = self._create_incident()
        assessment = AiAnalyst.analyze_incident(incident)
        assert assessment is not None
        assert isinstance(assessment.narrative, str)
        assert len(assessment.narrative) > 20

    def test_assessment_has_mitre_techniques(self):
        incident = self._create_incident()
        assessment = AiAnalyst.analyze_incident(incident)
        assert assessment is not None
        assert len(assessment.mitre_techniques) > 0

    def test_assessment_includes_relevant_mitre_ids(self):
        incident = self._create_incident(
            threat_types=["SYN_SCAN", "BRUTE_FORCE"]
        )
        assessment = AiAnalyst.analyze_incident(incident)
        assert assessment is not None
        tech_ids = {t.technique_id for t in assessment.mitre_techniques}
        assert "T1595" in tech_ids or "T1595.001" in tech_ids

    def test_assessment_has_kill_chain(self):
        incident = self._create_incident()
        assessment = AiAnalyst.analyze_incident(incident)
        assert assessment is not None
        assert len(assessment.kill_chain) > 0

    def test_assessment_has_recommendations(self):
        incident = self._create_incident()
        assessment = AiAnalyst.analyze_incident(incident)
        assert assessment is not None
        assert len(assessment.recommended_actions) > 0

    def test_assessment_has_key_indicators(self):
        incident = self._create_incident()
        assessment = AiAnalyst.analyze_incident(incident)
        assert assessment is not None
        assert len(assessment.key_indicators) > 0

    def test_single_event_low_confidence(self):
        incident = self._create_incident(risk="LOW", threat_types=["SYN_SCAN"], event_count=1)
        assessment = AiAnalyst.analyze_incident(incident)
        assert assessment is not None
        assert assessment.confidence == "LOW"

    def test_multi_event_high_confidence(self):
        incident = self._create_incident(event_count=8)
        assessment = AiAnalyst.analyze_incident(incident)
        assert assessment is not None
        assert assessment.confidence in ("HIGH", "MEDIUM")

    def test_empty_incident_returns_none(self):
        empty = Incident(
            incident_id="AEGIS-TEST-EMPTY",
            created_at=datetime.now().isoformat(),
            updated_at=datetime.now().isoformat(),
            status="OPEN", risk_level="LOW",
            event_count=0, last_event_time=0,
        )
        assessment = AiAnalyst.analyze_incident(empty)
        assert assessment is None

    def test_crypto_miner_recognition(self):
        incident = self._create_incident(
            risk="HIGH",
            threat_types=["CRYPTO_MINER"],
            event_count=2,
        )
        assessment = AiAnalyst.analyze_incident(incident)
        assert assessment is not None
        tech_ids = {t.technique_id for t in assessment.mitre_techniques}
        assert "T1496" in tech_ids

    def test_dns_tunnel_recognition(self):
        incident = self._create_incident(
            risk="CRITICAL",
            threat_types=["DNS_TUNNEL"],
            event_count=2,
        )
        assessment = AiAnalyst.analyze_incident(incident)
        assert assessment is not None
        tech_ids = {t.technique_id for t in assessment.mitre_techniques}
        assert "T1572" in tech_ids

    def test_rwx_memory_recognition(self):
        incident = self._create_incident(
            risk="CRITICAL",
            threat_types=["RWX_MEMORY"],
            event_count=2,
        )
        assessment = AiAnalyst.analyze_incident(incident)
        assert assessment is not None
        tech_ids = {t.technique_id for t in assessment.mitre_techniques}
        assert "T1055" in tech_ids

    def test_syn_scan_correctly_analyzed(self):
        incident = self._create_incident(
            risk="MEDIUM",
            threat_types=["SYN_SCAN"],
            event_count=1,
        )
        assessment = AiAnalyst.analyze_incident(incident)
        assert assessment is not None
        tech_ids = {t.technique_id for t in assessment.mitre_techniques}
        assert "T1595" in tech_ids or "T1595.001" in tech_ids

    def test_reverse_shell_correctly_analyzed(self):
        incident = self._create_incident(
            risk="CRITICAL",
            threat_types=["REVERSE_SHELL"],
            event_count=2,
        )
        assessment = AiAnalyst.analyze_incident(incident)
        assert assessment is not None
        tech_ids = {t.technique_id for t in assessment.mitre_techniques}
        assert "T1059" in tech_ids
