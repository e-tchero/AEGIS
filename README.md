# Project AEGIS - Security Operations Platform

AEGIS is an endpoint security platform focused on continuous monitoring, threat detection, evidence collection, incident analysis, and defensive response. Its direction is to help turn individual security signals into understandable, evidence-backed incidents that administrators and security analysts can investigate and act on.

## Why the Name AEGIS?

**Aegis** comes from Greek mythology, where the Aegis is a protective shield associated with Zeus and Athena. The word has come to represent protection, defence, and safeguarding.

That meaning reflects AEGIS's purpose as an endpoint defence platform: maintain visibility across a system, identify suspicious activity, preserve the evidence needed to understand it, connect related events into incidents, and support an appropriate response. Detection is only the beginning; the goal is to make security events explainable and actionable.

AEGIS is a name with a meaning, not an acronym. Its guiding idea is simple: **protection through visibility, evidence, and informed response.**

---

## Two Ways to Run

### Option 1: AEGIS.exe (Recommended - No Setup Required)

The standalone executable bundles Python, all dependencies, and the entire application into a single portable file.

| Feature | Detail |
|---------|--------|
| Python required? | No |
| Dependencies needed? | No |
| Portable? | Yes - copy to any Windows PC and run |
| How to run | Double-click `AEGIS.exe` |
| Fresh Windows PC? | Works immediately - no setup |

Best for: Regular users, fresh machines, USB deployment, distribution

### Option 2: Python Source (Developer Mode)

Run from source if you want to modify or extend AEGIS.

Requirements:
- Windows 10/11 x64
- Python 3.10+ (Download from python.org)
- Git (to clone the repo)

```
git clone https://github.com/YOUR_USERNAME/aegis.git
cd aegis
pip install -r requirements.txt
python aegis.py
```

Best for: Developers, contributors, custom modifications

---

## How to Use AEGIS

### Terminal Mode
```
AEGIS.exe
```
Runs in the command window - shows live logs of all security events.

### GUI Mode (System Tray)
```
AEGIS.exe --gui
```
Runs in the system tray (bottom-right icons). Features:
- Tray icon - right-click for quick actions
- Web dashboard at http://localhost:8765
- Live metrics: CPU, memory, threats blocked
- Real-time incident alerts
- Auto-starts and runs silently

### Common Commands
```
AEGIS.exe --help              Show all options
AEGIS.exe --gui               GUI mode with tray icon + dashboard
AEGIS.exe --gui --no-sentinel GUI mode without network monitoring
AEGIS.exe --terminal          Classic terminal mode
```

---

## Delivery Options

| Option | File | Description | Best For |
|--------|------|-------------|----------|
| Portable .exe | `AEGIS.exe` | Standalone executable - no Python needed | USB drives, fresh PCs, quick deployment |
| Windows Installer | `AEGIS_Setup_v1.0.0.exe` | Inno Setup installer - adds startup shortcut, installs to Program Files | Permanent installation, enterprise rollout |
| Python Source | `aegis.py` | Full source code - modify and extend | Developers, contributors |

---

## Core Security Modules

| Module | What It Does |
|--------|-------------|
| Firewall Manager | Blocks malicious IPs automatically via Windows Firewall |
| Process Monitor | Watches for suspicious running processes |
| File Integrity Monitor | Detects unauthorized file changes |
| Login Monitor | Tracks failed login attempts (brute force detection) |
| DNS Monitor | Spots connections to malicious domains |
| Memory Monitor | Detects memory-based attacks (Mimikatz, etc.) |
| Network Sentinel | Real-time packet analysis |
| AI Analyst | GPT-powered threat assessment and recommendations |
| Evidence Engine | Collects forensic evidence during incidents |
| Incident Manager | Tracks and correlates security events |

---

## Web Dashboard

AEGIS includes a full-featured dark-mode web dashboard built with React + Vite:

- Live WebSocket connection to the AEGIS backend
- 6 metric cards: System Health, CPU, Memory, Threats Blocked, Incidents, Blocked IPs
- Incident timeline with expandable cards, severity badges, event logs, IP tags
- Blocked IPs panel with search and one-click unblock
- AI Assessment panel with confidence bars, Kill Chain stages, MITRE ATT&CK mapping
- Glassmorphism design with semi-transparent cards, cyan/teal accents, grid background

To run the dashboard standalone:
```
cd dashboard
npm install
npm run dev
```
Opens at http://localhost:3000

---

## Validation and Testing

AEGIS includes a comprehensive validation suite (11 phases):

```
python validation/run_all.py
python validation/utils/generate_master_report.py
```

Phases cover:
- [x] Environment and dependencies
- [x] Static code analysis
- [x] Unit tests
- [x] Integration tests
- [x] Performance benchmarks
- [x] Stress testing
- [x] Reliability (24h soak)
- [x] Security audit
- [x] Dashboard coverage
- [x] Production readiness

---

## Project Structure

```
aegis/
 +-- aegis.py                    Main entry point
 +-- AEGIS.exe                   Standalone executable (built)
 +-- config/
 |   +-- file_baseline.json
 +-- modules/
 |   +-- firewall.py
 |   +-- process_monitor.py
 |   +-- file_monitor.py
 |   +-- login_monitor.py
 |   +-- dns_monitor.py
 |   +-- memory_monitor.py
 |   +-- net_sentinel.py
 |   +-- ai_analyst.py
 |   +-- evidence_engine.py
 |   +-- incident_manager.py
 |   +-- dashboard_server.py
 |   +-- firewall_backends.py
 +-- dashboard/
 |   +-- src/
 |   |   +-- App.tsx
 |   |   +-- components/
 |   |   +-- hooks/
 |   +-- index.html
 +-- tests/
 +-- validation/
 +-- requirements.txt
 +-- README.md
```

---

## Building from Source

To build your own AEGIS.exe:

```
pip install pyinstaller
pyinstaller AEGIS.spec
```

Or build directly:
```
pyinstaller --onefile --windowed --icon=AEGIS_LOGO.ico aegis.py
```

To generate the Windows installer (requires Inno Setup):
```
ISCC installer.iss
```

---

## Troubleshooting

### AEGIS opens and closes immediately (terminal flashes)

You are double-clicking the Python file. This opens a terminal, runs the script, and closes before you can see errors.

Fix: Open Command Prompt (or PowerShell) first, navigate to the folder, then run:
```
python aegis.py
```
You will see the actual error message.

### "Python is not recognized"

Python is not installed or not in your system PATH.

Fix: Reinstall Python and check the box "Add Python to PATH" during installation.

### The .exe says "DLL not found" or "Failed to execute script"

The executable was built for a different Windows version or is corrupted.

Fix: Rebuild from source using `pyinstaller AEGIS.spec` on the target machine.

### Web dashboard shows "Connection failed"

AEGIS must be running with the dashboard server enabled.

Fix:
1. Start AEGIS with `AEGIS.exe --gui` (or `python aegis.py --gui` from source)
2. Wait 5 seconds for the server to start
3. Open your browser to http://localhost:8765

Note: The React/Vite dashboard (port 3000) is for development. For everyday use, the auto-started dashboard on port 8765 is all you need.

### How do I verify AEGIS is working?

Run with verbose logging:
```
AEGIS.exe --gui --verbose
```
You will see live log output showing all modules initializing and any errors.

---

## License

MIT License - see LICENSE file for details.

---

## Acknowledgments

Built with:
- PyInstaller - Python bundling
- React + Vite - Web dashboard
- Tailwind CSS - Dashboard styling
- Inno Setup - Windows installer

---

Project AEGIS - Know your system is guarded.
