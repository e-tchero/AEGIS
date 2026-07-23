# PROJECT AEGIS — Autonomous SecOps Agent
**Lead Architect:** ETCHERO / Abdul-Hameed  
**Version:** 1.0.0  
**Classification:** AEGIS-CORE

---

## What is AEGIS?
A modular, autonomous security operations agent for Linux (Parrot OS) and Windows.
It monitors system health, detects network intrusions, and blocks threats in real time.

---

## Structure
```
AEGIS/
├── aegis.py               ← Master orchestrator (THE BRAIN)
├── core/
│   └── heartbeat.py       ← System health monitor
├── modules/
│   ├── net_sentinel.py    ← Scapy SYN scan detector
│   └── firewall.py        ← iptables abstraction (Linux live / Windows sim)
├── logs/                  ← All agent logs (auto-created)
├── requirements.txt
├── install.sh             ← Linux setup
└── install.bat            ← Windows setup
```

---

## Quick Start

### Linux / Parrot OS
```bash
chmod +x install.sh
./install.sh
sudo venv/bin/python aegis.py
```

### Windows (Simulation Mode)
```
install.bat
venv\Scripts\python aegis.py
```

---

## Requirements
| Package  | Purpose                         | Required On        |
|----------|---------------------------------|--------------------|
| psutil   | CPU / RAM / Network monitoring  | Linux + Windows    |
| scapy    | Packet sniffing (SYN detection) | Linux (+ Npcap on Windows) |

### System Requirements
| Tool     | Purpose                    | Platform |
|----------|----------------------------|----------|
| iptables | Kernel-level IP blocking   | Linux    |
| Npcap    | Packet capture driver      | Windows  |
| sudo     | Root access for raw sockets| Linux    |

---

## Threat Response Tiers
| Risk     | Action                                   |
|----------|------------------------------------------|
| CRITICAL | Immediate auto-block via iptables        |
| HIGH     | 5s countdown — operator can cancel       |
| MEDIUM   | Log and watch                            |
| LOW      | Passive log only                         |

---

## Test a Scan (Parrot OS)
```bash
# In a second terminal — scan yourself
nmap -sS 127.0.0.1
# AEGIS should fire within 5 seconds
```

---

*Built by ETCHERO. Stay dangerous.*
