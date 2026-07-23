# AEGIS Security Platform — Validation Suite

> **Investor-Ready Verification Program**
>
> This directory contains the official AEGIS Validation Program — a structured,
> automated verification suite that proves the platform's security, stability,
> and production readiness. Each phase produces polished HTML + JSON reports.

---

## Quick Start

```bash
# From the AEGIS project root:

# Run all validation phases
python validation/run_all.py

# Run specific phases only
python validation/run_all.py --phases 0      # Environment only
python validation/run_all.py --phases 0 1    # Environment + Static Analysis

# Generate reports and open in browser
python validation/run_all.py --serve
```

**Reports are saved to:** `validation/reports/`

---

## Validation Phases

| Phase | Name | Description | Status |
|-------|------|-------------|--------|
| **0** | **Environment Validation** | Python version, dependencies, config integrity, file system, platform, ports, privileges, module imports, lifecycle | ✅ Built |
| **1** | **Static Code Analysis** | ruff, flake8, mypy, bandit, pylint — 0 Critical, 0 High target | ✅ Built |
| **2** | **Unit Verification** | 200+ unit tests, 95%+ coverage across all modules | 🔧 Planned |
| **3** | **Integration Testing** | End-to-end pipeline: detection → incident → AI → firewall → dashboard | 🔧 Planned |
| **4** | **Functional Testing** | Every detection scenario: SYN scan, reverse shell, DLL injection, etc. | 🔧 Planned |
| **5** | **Adversarial Testing** | Metasploit, Atomic Red Team, Caldera attack simulations | 🔧 Planned |
| **6** | **Performance Testing** | CPU < 5% idle, RAM < 200MB resource targets | 🔧 Planned |
| **7** | **Stress Testing** | 10,000+ events, 100,000 packets, 100 simultaneous attacks | 🔧 Planned |
| **8** | **Reliability Testing** | 72-hour continuous run with memory/thread/handle leak monitoring | 🔧 Planned |
| **9** | **Security Audit** | Attack surface analysis, spoofing, DoS, WebSocket abuse testing | 🔧 Planned |
| **10** | **Long Duration Burn-In** | 7-day continuous operation with daily health snapshots | 🔧 Planned |
| **11** | **Production Readiness Review** | Final sign-off checklist with all acceptance criteria | 🔧 Planned |

---

## Report Format

Each phase generates two report formats:

### 📊 HTML Report — Investor Ready
Professionally styled, dark-themed HTML with:
- Circular pass-rate visualization
- Color-coded pass/fail indicators
- Severity tagging (INFO / WARN / ERROR / CRITICAL)
- Suggested fix guidance for each failure
- Environment metadata

### 📋 JSON Report — Machine Readable
Structured data for CI/CD pipelines and programmatic analysis.

---

## Target Metrics

| Metric | Target | Status |
|--------|--------|--------|
| Unit test pass rate | **100%** | ✅ 47/47 |
| Test coverage | **≥ 95%** | 🔧 Phase 2 |
| Static analysis (Critical/High) | **0** | 🔧 Phase 1 |
| Detection rate (known attacks) | **≥ 95%** | 🔧 Phase 5 |
| False positive rate | **< 2%** | 🔧 Phase 5 |
| False negative rate | **< 5%** | 🔧 Phase 5 |
| Memory leak after 72h | **None** | 🔧 Phase 8 |
| Unexpected crashes | **0** | 🔧 Phase 7 |
| Dashboard uptime | **100%** | 🔧 Phase 9 |
| WebSocket message loss | **0** | 🔧 Phase 9 |
| Recovery after failure | **< 10 seconds** | 🔧 Phase 8 |

---

## Architecture

```
validation/
├── README.md              ← This file (investor overview)
├── run_all.py             ← Master runner (run all phases)
├── phase0_environment.py  ← Phase 0 checks
├── phase1_static.py       ← Phase 1 static analysis
├── utils/
│   └── reporter.py        ← Report generator (HTML + JSON)
└── reports/               ← Generated report output
    ├── phase0_report.html
    ├── phase0_report.json
    ├── phase1_report.html
    ├── phase1_report.json
    ├── master_report.html  ← Consolidated report
    └── master_report.json
```

---

## Requirements

- **Python 3.10+**
- **Linting tools** (auto-installed by Phase 1):
  - `ruff` — Fast Python linter
  - `flake8` — Style guide enforcement
  - `mypy` — Static type checking
  - `bandit` — Security scanner
  - `pylint` — Code quality analysis

```bash
# Install all linting tools manually:
pip install ruff flake8 mypy bandit pylint
```

---

## Lead Architect

**ETCHERO / Abdul-Hameed** — Project AEGIS

*"Many products can detect events; far fewer can explain, correlate,
  and recommend responses in a way that reduces the workload on
  administrators."*
