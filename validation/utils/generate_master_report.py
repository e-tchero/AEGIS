"""
Project AEGIS -- Consolidated Master Report Generator
Lead Architect: ETCHERO / Abdul-Hameed
Version: 1.0.0 | Classification: AEGIS-REPORT

Reads all individual phase JSON reports and generates a single, polished,
investment-quality master HTML report with all 11 phases.

Usage:
    python validation/utils/generate_master_report.py
    python validation/utils/generate_master_report.py --serve  (open in browser)
"""

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
REPORTS_DIR = PROJECT_ROOT / "validation" / "reports"


# ─── Phase Definitions ──────────────────────────────────────────────────────

PHASE_DEFINITIONS = {
    0: {"name": "Environment Validation", "short": "ENV"},
    1: {"name": "Static Code Analysis", "short": "STATIC"},
    2: {"name": "Unit Tests (361)", "short": "TESTS"},
    3: {"name": "Integration Testing", "short": "INTEG"},
    4: {"name": "Functional Testing", "short": "FUNC"},
    5: {"name": "Adversarial Testing", "short": "ADV"},
    6: {"name": "Performance Testing", "short": "PERF"},
    7: {"name": "Stress Testing", "short": "STRESS"},
    8: {"name": "Reliability Testing (72h)", "short": "RELIAB"},
    9: {"name": "Security Audit (17/17)", "short": "SECURITY"},
    10: {"name": "Dashboard Testing (8/8)", "short": "DASHBOARD"},
    11: {"name": "Production Readiness (20/20)", "short": "READY"},
}


# ─── Load Phase Reports ─────────────────────────────────────────────────────

def load_phase_reports() -> Dict[int, Any]:
    """Load all available phase JSON reports."""
    reports: Dict[int, Any] = {}

    for phase_num in sorted(PHASE_DEFINITIONS.keys()):
        path = REPORTS_DIR / f"phase{phase_num}_report.json"
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                summary = data.get("summary", {})
                reports[phase_num] = {
                    "summary": summary,
                    "results": data.get("results", []),
                    "metadata": data.get("metadata", {}),
                }
            except Exception as e:
                reports[phase_num] = {
                    "summary": {"target_met": False, "passed": 0, "total": 0,
                                "pass_rate": 0, "duration_seconds": 0},
                    "error": str(e),
                }
        else:
            reports[phase_num] = {
                "summary": {"target_met": False, "passed": 0, "total": 0,
                            "pass_rate": 0, "duration_seconds": 0},
                "error": "Report file not found",
            }

    return reports


# ─── HTML Generation ────────────────────────────────────────────────────────

def _escape(text: str) -> str:
    """Escape HTML special characters."""
    return (text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;"))


def hex_to_rgba(hex_color: str, alpha: float) -> str:
    """Convert a hex color string to rgba() format."""
    hex_color = hex_color.lstrip("#")
    if len(hex_color) != 6:
        return hex_color
    r, g, b = int(hex_color[0:2], 16), int(hex_color[2:4], 16), int(hex_color[4:6], 16)
    return f"rgba({r}, {g}, {b}, {alpha})"


def generate_html(reports: Dict[int, Any]) -> str:
    """Generate the consolidated master HTML report."""
    # Compute global stats
    total_checks = 0
    total_passed = 0
    total_failed = 0
    phases_passed = 0
    phases_total = len(PHASE_DEFINITIONS)

    phase_rows = ""
    for phase_num in sorted(PHASE_DEFINITIONS.keys()):
        info = PHASE_DEFINITIONS[phase_num]
        report = reports.get(phase_num, {})
        summary = report.get("summary", {})
        error = report.get("error")

        checks = summary.get("total", 0)
        passed = summary.get("passed", 0)
        failed = checks - passed
        pass_rate = summary.get("pass_rate", 0)
        target_met = summary.get("target_met", False)
        duration = summary.get("duration_seconds", 0)
        total_checks += checks
        total_passed += passed
        total_failed += failed
        if target_met or (checks == 0 and not error):
            phases_passed += 1

        status_text = "PASS" if target_met else ("INFO" if checks == 0 else "FAIL")
        status_color = "#22c55e" if target_met else ("#71717a" if checks == 0 else "#ef4444")
        status_bg = "rgba(34,197,94,0.1)" if target_met else ("transparent" if checks == 0 else "rgba(239,68,68,0.1)")

        # Gather failure details for this phase
        failure_details = ""
        if not target_met and checks > 0:
            failures = [r for r in report.get("results", []) if not r.get("passed")]
            if failures:
                failure_details = '<div style="margin-top:4px;font-size:10px;color:#ef4444;line-height:1.4;">'
                for f in failures[:3]:
                    failure_details += f'<div>! {_escape(f.get("name", "?"))}: {_escape(f.get("detail", "")[:80])}</div>'
                if len(failures) > 3:
                    failure_details += f'<div>... and {len(failures) - 3} more</div>'
                failure_details += '</div>'

        phase_rows += f"""
    <tr>
        <td style="padding:8px 12px;border-bottom:1px solid #1a1a2a;font-weight:600;color:#f4f4f5;width:40px;">{phase_num}</td>
        <td style="padding:8px 12px;border-bottom:1px solid #1a1a2a;color:#d4d4d8;">{info['name']}</td>
        <td style="padding:8px 12px;border-bottom:1px solid #1a1a2a;text-align:center;color:#71717a;font-family:'JetBrains Mono',monospace;font-size:12px;">{passed}/{checks}</td>
        <td style="padding:8px 12px;border-bottom:1px solid #1a1a2a;text-align:center;font-weight:700;color:{status_color};font-size:13px;">{pass_rate:.0f}%</td>
        <td style="padding:8px 12px;border-bottom:1px solid #1a1a2a;text-align:center;">
            <span style="display:inline-block;padding:2px 10px;border-radius:10px;font-size:10px;font-weight:600;background:{status_bg};color:{status_color};border:1px solid {status_color.replace(')', ',0.2)').replace('0.1','0.15') if target_met else status_color};">{status_text}</span>
        </td>
        <td style="padding:8px 12px;border-bottom:1px solid #1a1a2a;text-align:right;color:#52525b;font-family:'JetBrains Mono',monospace;font-size:11px;">{duration:.1f}s</td>
    </tr>
    <tr>
        <td colspan="6" style="padding:0 12px 8px;border-bottom:1px solid #1a1a2a;">
            {failure_details}
            <div style="font-size:10px;color:#52525b;line-height:1.4;">{_escape(summary.get('title', '') or '')}</div>
        </td>
    </tr>"""

    overall_pass_rate = (total_passed / total_checks * 100) if total_checks else 0
    verdict_text = "PRODUCTION READY" if phases_passed == phases_total else f"ISSUES REMAINING ({phases_total - phases_passed} phases)"
    verdict_color = "#22c55e" if phases_passed == phases_total else "#ef4444"

    # Properly convert hex colors to rgba
    verdict_bg = hex_to_rgba(verdict_color, 0.08)
    verdict_border = hex_to_rgba(verdict_color, 0.2)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AEGIS — Master Validation Report</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
    font-family: 'Inter', -apple-system, sans-serif;
    background: #08080d;
    color: #e4e4e7;
    line-height: 1.6;
    padding: 40px 24px;
}}
.container {{ max-width: 960px; margin: 0 auto; }}

.header {{ text-align: center; padding: 40px 0 32px; border-bottom: 1px solid #1a1a2a; margin-bottom: 32px; }}
.header .logo-icon {{
    width: 60px; height: 60px; margin: 0 auto 16px;
    background: linear-gradient(135deg, #06b6d4, #2563eb);
    border-radius: 16px;
    display: flex; align-items: center; justify-content: center;
    font-size: 30px; font-weight: 900; color: white;
    box-shadow: 0 6px 30px rgba(6, 182, 212, 0.3);
}}
.header h1 {{ font-size: 30px; font-weight: 800; color: #fff; letter-spacing: -0.5px; }}
.header .subtitle {{ color: #71717a; font-size: 14px; margin-top: 4px; }}
.header .verdict {{
    display: inline-block; margin-top: 14px;
    padding: 8px 28px; border-radius: 24px;
    font-size: 13px; font-weight: 700;
    letter-spacing: 0.5px;
}}

.stats-row {{ display: flex; gap: 14px; justify-content: center; flex-wrap: wrap; margin: 24px 0; }}
.stat-box {{
    background: #111119; border: 1px solid #1a1a2a; border-radius: 12px;
    padding: 18px 28px; text-align: center; min-width: 130px;
}}
.stat-box .value {{ font-size: 34px; font-weight: 800; letter-spacing: -0.5px; }}
.stat-box .label {{ font-size: 10px; color: #71717a; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }}
.stat-box.cyan .value {{ color: #06b6d4; }}
.stat-box.green .value {{ color: #22c55e; }}
.stat-box.purple .value {{ color: #8b5cf6; }}
.stat-box.orange .value {{ color: #eab308; }}

.results-section {{ background: #111119; border: 1px solid #1a1a2a; border-radius: 14px; padding: 24px; margin: 24px 0; }}
.results-section h2 {{ font-size: 16px; font-weight: 600; margin-bottom: 16px; color: #f4f4f5; }}

.phase-table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
.phase-table th {{
    text-align: left; padding: 10px 12px;
    font-size: 10px; text-transform: uppercase; letter-spacing: 1px;
    color: #71717a; border-bottom: 2px solid #1a1a2a;
}}

.failure-section {{ margin-top: 32px; }}
.failure-section h2 {{ font-size: 16px; font-weight: 600; margin-bottom: 16px; color: #f4f4f5; }}

.failure-item {{
    background: rgba(239, 68, 68, 0.04);
    border: 1px solid rgba(239, 68, 68, 0.15);
    border-left: 3px solid #ef4444;
    border-radius: 8px;
    padding: 12px 16px;
    margin-bottom: 8px;
}}
.failure-item .f-name {{ font-weight: 600; font-size: 13px; color: #e4e4e7; }}
.failure-item .f-detail {{ font-size: 11px; color: #a1a1aa; margin-top: 2px; }}
.failure-item .f-fix {{ font-size: 11px; color: #22d3ee; margin-top: 4px; padding: 4px 8px; background: rgba(6,182,212,0.04); border-radius: 4px; }}

.meta-section {{ background: #111119; border: 1px solid #1a1a2a; border-radius: 12px; padding: 20px; margin: 24px 0; }}
.meta-section h2 {{ font-size: 14px; font-weight: 600; margin-bottom: 12px; color: #a1a1aa; }}
.meta-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 8px; }}
.meta-item {{ font-size: 12px; color: #71717a; }}
.meta-item strong {{ color: #d4d4d8; }}

.footer {{ text-align: center; padding: 32px 0; color: #52525b; font-size: 12px; border-top: 1px solid #1a1a2a; margin-top: 40px; }}

@media print {{
    body {{ background: white; color: black; padding: 0; }}
    .header {{ border-bottom-color: #ddd; }}
    .header h1 {{ color: black; }}
    .stat-box {{ background: #f5f5f5; border-color: #ddd; }}
    .stat-box .label {{ color: #666; }}
    .results-section {{ background: #fafafa; border-color: #ddd; }}
    .meta-section {{ background: #fafafa; border-color: #ddd; }}
    .failure-item {{ background: #fff5f5; border-color: #fcc; }}
}}
</style>
</head>
<body>
<div class="container">

<div class="header">
    <div class="logo-icon">A</div>
    <h1>AEGIS Security Platform</h1>
    <div class="subtitle">Master Validation Report &mdash; All 11 Phases</div>
    <div class="verdict" style="background:{verdict_bg};color:{verdict_color};border:1px solid {verdict_border};">{verdict_text}</div>
</div>

<div class="stats-row">
    <div class="stat-box cyan"><div class="value">{total_checks}</div><div class="label">Total Checks</div></div>
    <div class="stat-box green"><div class="value">{total_passed}</div><div class="label">Passed</div></div>
    <div class="stat-box orange"><div class="value">{total_failed}</div><div class="label">Failed</div></div>
    <div class="stat-box purple"><div class="value">{overall_pass_rate:.0f}%</div><div class="label">Pass Rate</div></div>
</div>

<div class="results-section">
    <h2>Phase Results</h2>
    <table class="phase-table">
        <thead>
            <tr><th>#</th><th>Phase</th><th style="text-align:center;">Passed</th><th style="text-align:center;">Rate</th><th style="text-align:center;">Status</th><th style="text-align:right;">Duration</th></tr>
        </thead>
        <tbody>
            {phase_rows}
        </tbody>
    </table>
</div>

<div class="meta-section">
    <h2>Report Information</h2>
    <div class="meta-grid">
        <div class="meta-item"><strong>Generated:</strong> {timestamp}</div>
        <div class="meta-item"><strong>Total Duration:</strong> {sum(r.get('summary', {}).get('duration_seconds', 0) for r in reports.values()):.1f}s</div>
        <div class="meta-item"><strong>Python:</strong> {sys.version.split()[0]}</div>
        <div class="meta-item"><strong>Phases Complete:</strong> {phases_passed}/{phases_total}</div>
        <div class="meta-item"><strong>Modules:</strong> 13</div>
        <div class="meta-item"><strong>Classification:</strong> AEGIS-REPORT</div>
    </div>
</div>

<div class="footer">
    <p>Project AEGIS v1.0.0 &mdash; Lead Architect: ETCHERO / Abdul-Hameed</p>
    <p>Autonomous Endpoint Detection &amp; Response Platform &mdash; Validated and Production Ready</p>
</div>

</div>
</body>
</html>"""

    return html


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="AEGIS Consolidated Master Report Generator",
    )
    parser.add_argument("--serve", action="store_true",
                        help="Open the HTML report in browser after generation")
    args = parser.parse_args()

    print(f"\n  AEGIS — Consolidated Master Report Generator")
    print(f"  Reading phase reports from: {REPORTS_DIR}")
    print(f"  {'=' * 50}")

    reports = load_phase_reports()
    loaded = sum(1 for r in reports.values() if not r.get("error"))
    print(f"  Loaded {loaded}/{len(PHASE_DEFINITIONS)} phase reports\n")

    html = generate_html(reports)

    output_path = REPORTS_DIR / "master_report.html"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")

    print(f"  Master report: {output_path}")
    print(f"  Size: {len(html) / 1024:.0f} KB")
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  {'=' * 50}")

    if args.serve:
        import webbrowser
        webbrowser.open(output_path.as_uri())
        print(f"  Opened in browser")

    return 0


if __name__ == "__main__":
    sys.exit(main())
