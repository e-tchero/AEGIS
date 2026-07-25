"""
Project AEGIS — AI Security Analyst
Lead Architect: ETCHERO / Abdul-Hameed
Version: 1.0.0 | Classification: AEGIS-ANALYST
Role: Takes correlated incidents from the Incident Manager and produces
      natural-language assessments with MITRE ATT&CK mappings, confidence
      levels, and recommended response actions.

      No LLM required — uses template-based analysis to map detected
      threat patterns to known MITRE techniques and response playbooks.

      Instead of:
        Port Scan (LOW)
        SSH Brute Force (HIGH)
        Privilege Escalation (HIGH)

      Produces:
        AEGIS ASSESSMENT — INCIDENT AEGIS-20260715-0003
        Confidence: HIGH
        Likely MITRE: T1595 (Active Scanning) → T1110 (Brute Force) → T1548 (Priv Esc)
        Narrative: An external host performed reconnaissance, then launched
        a credential brute force, followed by privilege escalation attempts.
        Recommended: Block source IP, audit user accounts, enable MFA.
"""

import logging
from dataclasses import dataclass
from datetime import datetime

from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


# ─── CONFIG ───────────────────────────────────────────────────────────────────
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config import (  # noqa: E402
    SafeRotatingFileHandler,
    AI_LOG_FILE,
    LOG_MAX_BYTES,
    LOG_BACKUP_COUNT,
    LOG_FORMAT,
)

# ─── LOGGER ───────────────────────────────────────────────────────────────────
_logger = logging.getLogger("aegis.analyst")
if not _logger.handlers:
    _handler = SafeRotatingFileHandler(
        str(AI_LOG_FILE),
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT,
        encoding="utf-8",
    )
    _handler.setFormatter(logging.Formatter(LOG_FORMAT))
    _logger.addHandler(_handler)
_logger.setLevel(logging.INFO)
_logger.propagate = False


# ─── MITRE ATT&CK MAPPING ─────────────────────────────────────────────────────

# Maps AEGIS threat types to MITRE ATT&CK techniques
# Format: threat_type -> list of (technique_id, technique_name, description)
MITRE_MAPPING: Dict[str, List[Tuple[str, str, str]]] = {
    # ── Network Reconnaissance ──
    "SYN_SCAN": [
        ("T1595.001", "Active Scanning: Scanning IP Blocks",
         "Standard TCP SYN scan used to identify open ports and running services."),
    ],
    "FIN_SCAN": [
        ("T1595.001", "Active Scanning: Scanning IP Blocks",
         "FIN scan — evades some firewalls by sending only FIN flag."),
    ],
    "XMAS_SCAN": [
        ("T1595.001", "Active Scanning: Scanning IP Blocks",
         "Xmas scan (FIN+PSH+URG) — evades stateless packet filters."),
    ],
    "NULL_SCAN": [
        ("T1595.001", "Active Scanning: Scanning IP Blocks",
         "Null scan — no TCP flags set, evades some IDS/IPS systems."),
    ],
    "UDP_SCAN": [
        ("T1595.001", "Active Scanning: Scanning IP Blocks",
         "UDP port scan — detects UDP services, slower but quieter than TCP."),
    ],

    # ── Execution ──
    "REVERSE_SHELL": [
        ("T1059", "Command and Scripting Interpreter",
         "Process established outbound connections, consistent with reverse shell behavior."),
        ("T1071.001", "Application Layer Protocol: Web Protocols",
         "Using standard application layer protocols for C2 communications."),
        ("T1059.001", "Command and Scripting Interpreter: PowerShell",
         "PowerShell or scripting engine used to establish reverse shell connection."),
    ],
    "SUSPICIOUS_CMDLINE": [
        ("T1059", "Command and Scripting Interpreter",
         "Suspicious command-line arguments detected, indicating script execution."),
        ("T1204.002", "User Execution: Malicious File",
         "Command-line patterns match known malware loader behavior."),
    ],
    "SUSPICIOUS_CHAIN": [
        ("T1204.002", "User Execution: Malicious File",
         "Unusual parent-child process chain suggests code execution attack."),
        ("T1059", "Command and Scripting Interpreter",
         "Scripting engine spawned from non-standard parent process."),
    ],

    # ── Persistence ──
    "PERSISTENCE": [
        ("T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys",
         "Persistence mechanism detected via registry, scheduled tasks, or startup folders."),
        ("T1053.005", "Scheduled Task/Job: Scheduled Task",
         "Potential persistence via scheduled task creation."),
    ],

    # ── Privilege Escalation ──
    "PRIVILEGE_ESC": [
        ("T1548.001", "Abuse Elevation Control Mechanism: Setuid and Setgid",
         "Privilege escalation attempt via sudo/su/runas elevation."),
        ("T1068", "Exploitation for Privilege Escalation",
         "Process attempting to gain elevated privileges."),
    ],

    # ── Defense Evasion ──
    "RWX_MEMORY": [
        ("T1055", "Process Injection",
         "RWX (Read-Write-Execute) memory regions detected — strongly indicates injected code."),
    ],
    "DLL_INJECTION": [
        ("T1055.001", "Process Injection: DLL Injection",
         "Suspicious DLLs loaded from non-standard paths, indicating injection."),
    ],
    "REFLECTIVE_LOAD": [
        ("T1055.001", "Process Injection: DLL Injection",
         "Anonymous executable memory indicates reflective (memory-only) DLL loading."),
        ("T1620", "Reflective Code Loading",
         "Code loaded directly into memory without touching disk."),
    ],
    "PROCESS_HOLLOWING": [
        ("T1055.012", "Process Injection: Process Hollowing",
         "Process memory characteristics suggest original code has been replaced."),
    ],
    "HIGH_MAP_COUNT": [
        ("T1055", "Process Injection",
         "Excessive memory maps may indicate injection or reflective loading."),
    ],

    # ── Credential Access ──
    "BRUTE_FORCE": [
        ("T1110.003", "Brute Force: Password Spraying",
         "Multiple failed login attempts from a single source IP within a short window."),
        ("T1110.001", "Brute Force: Password Guessing",
         "Repeated authentication failures against multiple user accounts."),
    ],
    "NEW_ADMIN": [
        ("T1098", "Account Manipulation",
         "New administrative user account created, potential persistence mechanism."),
    ],

    # ── Exfiltration / C2 ──
    "DNS_TUNNEL": [
        ("T1572", "Protocol Tunneling",
         "DNS protocol used for tunneling data — common technique for C2 and exfiltration."),
        ("T1048", "Exfiltration Over Alternative Protocol",
         "Large DNS responses suggest data exfiltration via DNS tunneling."),
    ],
    "HIGH_ENTROPY": [
        ("T1568", "Dynamic Resolution",
         "High-entropy domain names consistent with DGA (Domain Generation Algorithm)."),
        ("T1571", "Non-Standard Port",
         "Random-appearing subdomains may indicate DNS tunneling or DGA C2."),
    ],
    "BEACONING": [
        ("T1071", "Application Layer Protocol",
         "Regular DNS query intervals consistent with C2 beaconing behavior."),
        ("T1573", "Encrypted Channel",
         "Periodic communications to same domain suggests beaconing to C2 server."),
    ],
    "TXT_ABUSE": [
        ("T1572", "Protocol Tunneling",
         "Excessive TXT record queries — commonly used for DNS tunneling data transfer."),
    ],
    "LARGE_RESPONSE": [
        ("T1048", "Exfiltration Over Alternative Protocol",
         "Unusually large DNS response may indicate data exfiltration."),
    ],

    # ── Resource Hijacking ──
    "CRYPTO_MINER": [
        ("T1496", "Resource Hijacking",
         "Sustained high CPU usage consistent with cryptocurrency mining."),
    ],

    # ── Credential Access ──
    "SUSPICIOUS_LOGIN": [
        ("T1078", "Valid Accounts",
         "Suspicious login activity detected from unusual location or time."),
    ],

    # ── Impact / Defense Evasion ──
    "FILE_CHANGED": [
        ("T1070", "Indicator Removal",
         "Critical system file modification detected — may indicate tampering."),
    ],
    "FILE_DELETED": [
        ("T1070.004", "Indicator Removal: File Deletion",
         "Critical system file deleted — potential evidence destruction."),
    ],
}

# ─── KILL CHAIN STAGES ───────────────────────────────────────────────────────

# Maps MITRE techniques to the Lockheed Martin Cyber Kill Chain
KILL_CHAIN_STAGES = {
    "T1595": "Reconnaissance",
    "T1595.001": "Reconnaissance",
    "T1059": "Execution",
    "T1059.001": "Execution",
    "T1204": "Execution",
    "T1204.002": "Execution",
    "T1547": "Persistence",
    "T1547.001": "Persistence",
    "T1053": "Persistence",
    "T1053.005": "Persistence",
    "T1548": "Privilege Escalation",
    "T1548.001": "Privilege Escalation",
    "T1068": "Privilege Escalation",
    "T1055": "Defense Evasion",
    "T1055.001": "Defense Evasion",
    "T1055.012": "Defense Evasion",
    "T1620": "Defense Evasion",
    "T1110": "Credential Access",
    "T1110.001": "Credential Access",
    "T1110.003": "Credential Access",
    "T1098": "Persistence",
    "T1572": "Command & Control",
    "T1071": "Command & Control",
    "T1071.001": "Command & Control",
    "T1571": "Command & Control",
    "T1573": "Command & Control",
    "T1568": "Command & Control",
    "T1048": "Exfiltration",
    "T1496": "Impact",
    "T1078": "Credential Access",
    "T1070": "Defense Evasion",
    "T1070.004": "Defense Evasion",
}

# ─── RESPONSE PLAYBOOKS ───────────────────────────────────────────────────────

# Maps threat types to recommended response actions
RESPONSE_ACTIONS: Dict[str, List[str]] = {
    "REVERSE_SHELL": [
        "Immediately block the remote IP address via firewall.",
        "Kill the suspicious process and investigate the parent process chain.",
        "Capture a full memory dump for forensic analysis.",
        "Review the process tree to determine the initial infection vector.",
        "Check for persistence mechanisms installed by the attacker.",
    ],
    "CRYPTO_MINER": [
        "Identify and terminate the resource-intensive process.",
        "Review process ancestry to determine how the miner was deployed.",
        "Check for persistence mechanisms (scheduled tasks, cron jobs).",
        "Verify if crypto miner wallet addresses are in known threat intel feeds.",
        "Remove any associated files and monitor for re-infection.",
    ],
    "SUSPICIOUS_CMDLINE": [
        "Review the full command line and its purpose.",
        "Trace the parent process to determine the initial execution vector.",
        "Check for encoded or obfuscated payloads in the command.",
        "Verify if the command matches known malware signatures.",
        "Capture environment variables and process memory for analysis.",
    ],
    "PRIVILEGE_ESC": [
        "Audit sudoers file and user privilege assignments.",
        "Review recent user account modifications.",
        "Check for recently installed SUID binaries on Linux.",
        "Verify if vulnerable services are running with elevated privileges.",
        "Apply principle of least privilege where possible.",
    ],
    "PERSISTENCE": [
        "Remove the identified persistence mechanism.",
        "Audit all scheduled tasks, cron jobs, and startup items.",
        "Review registry run keys and startup folders on Windows.",
        "Check for unauthorized services or daemons.",
        "Monitor for re-creation of the persistence mechanism.",
    ],
    "SUSPICIOUS_CHAIN": [
        "Review the full process tree to understand the attack chain.",
        "Identify the initial process that started the chain.",
        "Check for macro-enabled documents or phishing attachments.",
        "Block the parent application from spawning scripting engines.",
    ],
    "BRUTE_FORCE": [
        "Block the source IP address at the firewall.",
        "Enable account lockout policies or reduce lockout thresholds.",
        "Require multi-factor authentication for remote access.",
        "Audit user accounts for compromised credentials.",
        "Review authentication logs for successful logins from the attacker IP.",
    ],
    "DNS_TUNNEL": [
        "Block or sinkhole the suspicious domain.",
        "Review DNS logs for data exfiltration indicators.",
        "Implement DNS traffic filtering and monitoring.",
        "Restrict DNS query types allowed (block TXT, NULL, etc. if not needed).",
        "Deploy DNS over HTTPS (DoH) inspection if possible.",
    ],
    "HIGH_ENTROPY": [
        "Investigate the high-entropy domain for malicious activity.",
        "Check if the domain is in known DGA or blocklist feeds.",
        "Block the domain if confirmed malicious.",
        "Review DNS logs for related suspicious domains.",
    ],
    "BEACONING": [
        "Block or sinkhole the beaconing domain.",
        "Review network logs for C2 traffic patterns.",
        "Isolate the affected host for forensic analysis.",
        "Deploy network-level threat detection for the identified domain.",
    ],
    "TXT_ABUSE": [
        "Restrict TXT query access to authorized DNS servers only.",
        "Review DNS logs for data exfiltration volume.",
        "Consider blocking TXT queries to external domains.",
    ],
    "RWX_MEMORY": [
        "Isolate the affected process immediately — injected code confirmed.",
        "Capture a full memory dump before terminating the process.",
        "Review the process parent chain for the injection vector.",
        "Scan for persistence mechanisms related to the injected code.",
        "Deploy endpoint detection rules for RWX memory monitoring.",
    ],
    "DLL_INJECTION": [
        "Terminate the compromised process.",
        "Scan for the injected DLL on disk and remove it.",
        "Review the process ancestry for the injection source.",
        "Check other processes for the same injected module.",
        "Update application whitelisting rules.",
    ],
    "REFLECTIVE_LOAD": [
        "Isolate the host immediately — memory-only malware is highly evasive.",
        "Capture full memory dump for forensic analysis.",
        "Scan for related persistence mechanisms.",
        "Review network connections from the affected process.",
    ],
    "PROCESS_HOLLOWING": [
        "Isolate the affected host immediately.",
        "Capture a memory dump before terminating the process.",
        "Review the process ancestry for the hollowing source.",
        "Check for indicators of compromise across the environment.",
    ],
    "HIGH_MAP_COUNT": [
        "Review the specific modules loaded in the process.",
        "Check for unsigned or suspicious DLLs.",
        "Compare memory maps against known baselines.",
        "Monitor for escalation to RWX memory or injection.",
    ],
    "SYN_SCAN": [
        "Block the scanning IP at the firewall.",
        "Monitor for follow-up exploitation attempts.",
        "Verify no services are exposed unnecessarily.",
    ],
    "FIN_SCAN": [
        "Block the scanning IP — FIN scans are more aggressive than SYN scans.",
        "Review firewall logs for related probes.",
    ],
    "XMAS_SCAN": [
        "Block the scanning IP — Xmas scans are associated with advanced attackers.",
        "Increase monitoring for more targeted probing.",
    ],
    "NULL_SCAN": [
        "Block the scanning IP — NULL scans evade basic filtering.",
        "Review IDS/IPS logs for related activity.",
    ],
    "UDP_SCAN": [
        "Block the scanning IP at the firewall.",
        "Review which UDP services are exposed.",
    ],
    "FILE_CHANGED": [
        "Review the file modification for unauthorized changes.",
        "Restore the file from a known-good backup if needed.",
        "Audit who or what modified the file.",
        "Implement file integrity monitoring on critical paths.",
    ],
    "FILE_DELETED": [
        "Restore the deleted file from a known-good source.",
        "Audit system logs for the deletion event.",
        "Investigate the cause of deletion (cleanup vs. malicious).",
    ],
    "NEW_ADMIN": [
        "Verify if the admin account creation was authorized.",
        "Disable unauthorized accounts immediately.",
        "Audit all administrator accounts on the system.",
        "Review logs for related privilege escalation activity.",
    ],
    "LARGE_RESPONSE": [
        "Review DNS query and response data for exfiltration indicators.",
        "Check if large responses originate from known C2 domains.",
        "Monitor outbound DNS traffic volume for anomalies.",
    ],
}

# ─── ASSESSMENT DATA MODEL ────────────────────────────────────────────────────


@dataclass
class MitreTechnique:
    """A mapped MITRE ATT&CK technique with context."""
    technique_id: str
    technique_name: str
    kill_chain_stage: str
    description: str
    source: str  # Which threat type generated this mapping


@dataclass
class AnalystAssessment:
    """Full AI-generated assessment for an incident."""
    incident_id: str
    generated_at: str
    risk_level: str
    confidence: str          # LOW, MEDIUM, HIGH
    executive_summary: str
    narrative: str
    kill_chain: List[str]     # Stages affected (e.g., Reconnaissance → Execution)
    mitre_techniques: List[MitreTechnique]
    recommended_actions: List[str]
    key_indicators: Dict[str, List[str]]

    def display(self) -> None:
        """Print the formatted assessment to stdout."""
        risk_colors = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
        risk_icon = risk_colors.get(self.risk_level, "⚪")

        print(f"\n  {'═'*56}")
        print(f"  {risk_icon} AEGIS ASSESSMENT — INCIDENT {self.incident_id}")
        print(f"  {'═'*56}")

        # Header
        print(f"  Generated : {self.generated_at[:19]}")
        print(f"  Risk      : {self.risk_level}")
        print(f"  Confidence: {self.confidence}")
        print()

        # Executive summary
        print(f"  {risk_icon} Executive Summary:")
        print(f"  {'─'*50}")
        print(f"  {self.executive_summary}")
        print()

        # Kill chain
        if self.kill_chain:
            stages = " → ".join(self.kill_chain)
            print(f"  🎯 Kill Chain: {stages}")
            print()

        # MITRE techniques
        if self.mitre_techniques:
            print("  📋 MITRE ATT&CK Mapping:")
            print(f"  {'─'*50}")
            for tech in self.mitre_techniques:
                print(f"  • {tech.technique_id} — {tech.technique_name}")
                print(f"    ({tech.kill_chain_stage}): {tech.description[:120]}...")
            print()

        # Narrative
        print("  📝 Assessment:")
        print(f"  {'─'*50}")
        for line in self.narrative.split("\\n"):
            print(f"  {line}")
        print()

        # Key indicators
        if self.key_indicators:
            print("  🔑 Key Indicators:")
            print(f"  {'─'*50}")
            for label, items in self.key_indicators.items():
                if items:
                    print(f"  {label}: {', '.join(list(items)[:5])}")
            print()

        # Recommendations
        if self.recommended_actions:
            print("  ✅ Recommended Actions:")
            print(f"  {'─'*50}")
            for i, action in enumerate(self.recommended_actions, 1):
                print(f"  {i}. {action}")
            print()

        print(f"  {'═'*56}\n")


# ─── AI ANALYST ───────────────────────────────────────────────────────────────
class AiAnalyst:
    """Template-based security analyst that produces MITRE-backed assessments."""

    # Risk-level mapping for confidence scoring
    RISK_WEIGHTS = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

    @classmethod
    def analyze_incident(cls, incident) -> Optional[AnalystAssessment]:
        """Analyze an incident and produce a full assessment.

        Args:
            incident: An Incident object from the Incident Manager.

        Returns:
            An AnalystAssessment or None if the incident has no events.
        """
        if not incident or not incident.events:
            return None

        threat_types = incident.threat_types
        risk = incident.risk_level

        # ── Gather MITRE techniques ──
        mitre_techniques: List[MitreTechnique] = []
        seen_techniques: Set[str] = set()
        kill_chain_order: List[str] = []
        seen_stages: Set[str] = set()

        for ttype in threat_types:
            mappings = MITRE_MAPPING.get(ttype, [])
            for tech_id, tech_name, desc in mappings:
                if tech_id not in seen_techniques:
                    seen_techniques.add(tech_id)
                    stage = KILL_CHAIN_STAGES.get(tech_id, "Unknown")
                    mitre_techniques.append(MitreTechnique(
                        technique_id=tech_id,
                        technique_name=tech_name,
                        kill_chain_stage=stage,
                        description=desc,
                        source=ttype,
                    ))
                    if stage not in seen_stages:
                        seen_stages.add(stage)
                        kill_chain_order.append(stage)

        # Sort kill chain by standard order
        stage_priority = [
            "Reconnaissance", "Weaponization", "Delivery",
            "Exploitation", "Installation", "Command & Control",
            "Execution", "Persistence", "Privilege Escalation",
            "Defense Evasion", "Credential Access", "Discovery",
            "Lateral Movement", "Collection", "Exfiltration", "Impact",
        ]
        kill_chain_order.sort(key=lambda s: stage_priority.index(s) if s in stage_priority else 99)

        # ── Build narrative ──
        narrative = cls._build_narrative(incident, threat_types, kill_chain_order)

        # ── Build executive summary ──
        exec_summary = cls._build_executive_summary(incident, threat_types, kill_chain_order)

        # ── Confidence score ──
        confidence = cls._calculate_confidence(incident, mitre_techniques)

        # ── Recommended actions ──
        actions = cls._build_recommendations(threat_types)

        # ── Key indicators ──
        indicators = cls._extract_indicators(incident)

        return AnalystAssessment(
            incident_id=incident.incident_id,
            generated_at=datetime.now().isoformat(),
            risk_level=risk,
            confidence=confidence,
            executive_summary=exec_summary,
            narrative=narrative,
            kill_chain=kill_chain_order,
            mitre_techniques=mitre_techniques,
            recommended_actions=actions,
            key_indicators=indicators,
        )

    @classmethod
    def _build_executive_summary(cls, incident, threat_types: List[str],
                                 kill_chain: List[str]) -> str:
        """Build a one-paragraph executive summary of the incident."""
        stage_str = " → ".join(kill_chain) if kill_chain else "Unknown"

        if len(threat_types) == 1:
            return (
                f"A single {threat_types[0]} event was detected involving "
                f"{cls._format_indicators(incident)}. "
                f"The activity maps to the {stage_str} stage of the cyber kill chain. "
                f"Risk level: {incident.risk_level}."
            )

        # Multi-event incident
        return (
            f"An incident containing {incident.event_count} correlated security events "
            f"({', '.join(threat_types[:5])}) was detected. "
            f"The attack chain spans: {stage_str}. "
            f"{cls._format_indicators(incident)} involved. "
            f"Overall risk level: {incident.risk_level}. "
            f"Immediate investigation and response recommended."
        )

    @classmethod
    def _build_narrative(cls, incident, threat_types: List[str],
                         kill_chain: List[str]) -> str:
        """Build a narrative description of the incident.

        Provides a human-readable account of what happened, in what order,
        and what the indicators suggest about the attacker's intent.
        """
        parts = []

        # Opening statement
        if len(threat_types) == 1:
            parts.append(f"A {threat_types[0]} event was detected.")
        else:
            parts.append(
                f"A multi-stage security incident involving "
                f"{', '.join(threat_types[:5])} was detected."
            )

        # Timeline from events
        if incident.events:
            timeline_events = incident.events[:5]
            timeline = "; ".join(
                f"{e.threat_type} ({e.risk_level})" for e in timeline_events
            )
            parts.append(f"Timeline: {timeline}.")

        # Kill chain context
        if kill_chain:
            parts.append(
                f"The attack spans the following kill chain stages: "
                f"{' -> '.join(kill_chain)}."
            )

        # Indicators
        if incident.source_ips:
            ips = ', '.join(list(incident.source_ips)[:3])
            parts.append(f"Source IPs involved: {ips}.")
        if incident.process_names:
            procs = ', '.join(list(incident.process_names)[:3])
            parts.append(f"Processes involved: {procs}.")

        # Risk context
        parts.append(
            f"Overall risk level is {incident.risk_level}. "
            f"Immediate investigation is {'recommended' if incident.risk_level in ('HIGH', 'CRITICAL') else 'advised'}."
        )

        return " ".join(parts)

    @classmethod
    def _calculate_confidence(cls, incident, techniques: List[MitreTechnique]) -> str:
        """Calculate confidence level based on available evidence.

        Factors:
        - Number of correlated events (more = higher confidence)
        - Number of distinct threat types (more = broader attack = higher confidence)
        - Highest risk level (critical/high = more evidence of real attack)
        - Number of MITRE technique mappings (more = better characterized)
        - Presence of multiple kill chain stages (indicates coordinated attack)
        """
        score = 0.0

        # Event count (max 40 points)
        score += min(incident.event_count * 10, 40)

        # Distinct threat types (max 20 points)
        score += min(len(incident.threat_types) * 5, 20)

        # Risk level (max 20 points)
        risk_order = {"CRITICAL": 20, "HIGH": 15, "MEDIUM": 10, "LOW": 5}
        score += risk_order.get(incident.risk_level, 0)

        # Kill chain stages (max 10 points)
        stages = set(t.kill_chain_stage for t in techniques)
        score += min(len(stages) * 3, 10)

        # Attack sophistication (max 10 points)
        has_defense_evasion = any("Defense Evasion" in t.kill_chain_stage for t in techniques)
        has_c2 = any("Command & Control" in t.kill_chain_stage for t in techniques)
        if has_defense_evasion:
            score += 5
        if has_c2:
            score += 5

        # Thresholds
        if score >= 70:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        else:
            return "LOW"

    @classmethod
    def _build_recommendations(cls, threat_types: List[str]) -> List[str]:
        """Build a consolidated list of recommended actions."""
        all_actions: List[str] = []
        seen: Set[str] = set()

        for ttype in threat_types:
            actions = RESPONSE_ACTIONS.get(ttype, [])
            for action in actions:
                if action not in seen:
                    seen.add(action)
                    all_actions.append(action)

        # Limit to top recommendations
        return all_actions[:10]

    @classmethod
    def _extract_indicators(cls, incident) -> Dict[str, List[str]]:
        """Extract key indicators from the incident data."""
        indicators: Dict[str, List[str]] = {}

        if incident.source_ips:
            indicators["Source IPs"] = sorted(incident.source_ips)

        if incident.process_names:
            indicators["Processes"] = sorted(incident.process_names)

        if incident.file_paths:
            indicators["Files"] = sorted(incident.file_paths)

        if incident.user_names:
            indicators["Users"] = sorted(incident.user_names)

        # Extract domains from event summaries
        domains = set()
        for ev in incident.events:
            if "domain" in ev.detail.lower():
                # Try to extract domain from summary
                lines = ev.detail.split("\n")
                for line in lines:
                    if "domain" in line.lower():
                        import re
                        found = re.findall(r"['\"]([^'\"]+\.\w+)['\"]", line)
                        domains.update(found)
        if domains:
            indicators["Domains"] = sorted(domains)

        return indicators

    @staticmethod
    def _format_indicators(incident) -> str:
        """Format indicators for inclusion in narrative/executive summary."""
        parts = []
        if incident.source_ips:
            ips = list(incident.source_ips)[:2]
            parts.append(f"source{'s' if len(ips)>1 else ''} {', '.join(ips)}")
        if incident.process_names:
            procs = list(incident.process_names)[:2]
            parts.append(f"process{'es' if len(procs)>1 else ''} {', '.join(procs)}")
        if not parts:
            return "multiple indicators"
        return "; ".join(parts)


# ─── STANDALONE ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import time
    print("\n  AEGIS AI SECURITY ANALYST — STANDALONE v1.0\n")

    # Standalone demo: create a sample incident and analyze it
    from modules.incident_manager import Incident, IncidentEvent

    sample_incident = Incident(
        incident_id="AEGIS-DEMO-0001",
        created_at=datetime.now().isoformat(),
        updated_at=datetime.now().isoformat(),
        status="OPEN",
        risk_level="HIGH",
        threat_types=["SYN_SCAN", "BRUTE_FORCE", "PRIVILEGE_ESC"],
        source_ips={"192.168.1.100", "10.0.0.50"},
        process_names={"sshd.exe", "cmd.exe"},
        event_count=3,
        last_event_time=time.time(),
    )

    sample_incident.events = [
        IncidentEvent(
            timestamp=datetime.now().isoformat(),
            threat_type="SYN_SCAN",
            risk_level="MEDIUM",
            source="network",
            summary="SYN_SCAN from 192.168.1.100",
            detail="Port scan detected against 25 ports",
        ),
        IncidentEvent(
            timestamp=datetime.now().isoformat(),
            threat_type="BRUTE_FORCE",
            risk_level="HIGH",
            source="login",
            summary="BRUTE_FORCE from 10.0.0.50 (user: admin)",
            detail="8 failed login attempts in 5 minute window",
        ),
        IncidentEvent(
            timestamp=datetime.now().isoformat(),
            threat_type="PRIVILEGE_ESC",
            risk_level="HIGH",
            source="process",
            summary="PRIVILEGE_ESC — cmd.exe (PID 1234)",
            detail="sudo usage detected",
        ),
    ]

    assessment = AiAnalyst.analyze_incident(sample_incident)
    if assessment:
        assessment.display()
