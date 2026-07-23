"""
Project AEGIS — Validation Program: Master Runner
Lead Architect: ETCHERO / Abdul-Hameed

Executes all validation phases sequentially and produces a consolidated
investor-ready report with HTML + JSON output.

Usage:
    python validation/run_all.py              # Run all phases
    python validation/run_all.py --phases 0   # Run specific phases
    python validation/run_all.py --phases 0 1 # Run phases 0 and 1
"""

import argparse
import sys
import time
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from validation.utils.reporter import ValidationReport, ValidationResult


def consolidate_reports(phase_reports: list) -> ValidationReport:
    """Combine multiple phase reports into a consolidated master report."""
    master = ValidationReport("Master", "Full Validation Suite")
    total_checks = 0
    total_passed = 0
    total_failed = 0
    all_results = []

    for report in phase_reports:
        for r in report.results:
            all_results.append(r)
        s = report.summary()
        total_checks += s["total"]
        total_passed += s["passed"]
        total_failed += s["failed"]

    # Deduplicate by name
    seen = set()
    for r in all_results:
        if r.name not in seen:
            seen.add(r.name)
            master.add(r)

    master.duration = sum(r.summary()["duration_seconds"] for r in phase_reports)
    return master


def run_phase(phase_num: int) -> ValidationReport:
    """Run a specific validation phase by number."""
    phases = {
        0: ("Phase 0", "Environment Validation", "phase0_environment"),
        1: ("Phase 1", "Static Code Analysis", "phase1_static"),
    }

    if phase_num not in phases:
        print(f"  ❌ Phase {phase_num} not defined")
        return ValidationReport(f"Phase {phase_num}", "Unknown")

    name, title, module = phases[phase_num]
    print(f"\n  {'=' * 56}")
    print(f"  EXECUTING: {name} — {title}")
    print(f"  {'=' * 56}")

    start = time.time()
    try:
        # Import and run the phase module
        phase_mod = __import__(f"validation.{module}", fromlist=["run_phase0"])
        runner = getattr(phase_mod, "run_phase0" if phase_num == 0 else "run_phase1")
        report = runner(ValidationReport(name, title))
        report.duration = time.time() - start
        return report
    except Exception as e:
        import traceback
        print(f"\n  ❌ Phase {phase_num} failed: {e}")
        traceback.print_exc()
        report = ValidationReport(name, title)
        result = ValidationResult(f"Phase {phase_num} execution", "Runtime")
        result.fail(f"Phase crashed: {e}", "CRITICAL")
        report.add(result)
        report.duration = time.time() - start
        return report


def generate_master_html(master: ValidationReport, phase_reports: list,
                         output_path: Path) -> str:
    """Generate a consolidated investor-ready HTML report."""
    s = master.summary()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Phase summary rows
    phase_rows = ""
    for i, pr in enumerate(phase_reports):
        ps = pr.summary()
        status = "✅ PASS" if ps["target_met"] else "❌ FAIL"
        phase_rows += f"""
    <tr>
        <td style="padding:12px;border-bottom:1px solid #1f1f2e;font-weight:600;">Phase {i}</td>
        <td style="padding:12px;border-bottom:1px solid #1f1f2e;">{ps['title']}</td>
        <td style="padding:12px;border-bottom:1px solid #1f1f2e;text-align:center;">{ps['passed']}/{ps['total']}</td>
        <td style="padding:12px;border-bottom:1px solid #1f1f2e;text-align:center;font-weight:600;color:{'#22c55e' if ps['target_met'] else '#ef4444'};">{ps['pass_rate']}%</td>
        <td style="padding:12px;border-bottom:1px solid #1f1f2e;text-align:center;">{status}</td>
        <td style="padding:12px;border-bottom:1px solid #1f1f2e;text-align:right;color:#71717a;font-size:12px;">{ps['duration_seconds']:.1f}s</td>
    </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AEGIS Validation — Master Report</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
    font-family: 'Inter', -apple-system, sans-serif;
    background: #0a0a0f;
    color: #e4e4e7;
    line-height: 1.6;
    padding: 40px 24px;
}}
.container {{ max-width: 960px; margin: 0 auto; }}
.header {{ text-align: center; padding: 48px 0 32px; border-bottom: 1px solid #1f1f2e; margin-bottom: 32px; }}
.header .logo-icon {{
    width: 64px; height: 64px; margin: 0 auto 16px;
    background: linear-gradient(135deg, #06b6d4, #2563eb);
    border-radius: 16px;
    display: flex; align-items: center; justify-content: center;
    font-size: 32px; font-weight: 800; color: white;
    box-shadow: 0 8px 32px rgba(6, 182, 212, 0.3);
}}
.header h1 {{ font-size: 32px; font-weight: 800; color: #fff; }}
.header .subtitle {{ color: #71717a; font-size: 14px; margin-top: 4px; }}
.header .master-badge {{
    display: inline-block; margin-top: 16px;
    padding: 8px 24px; border-radius: 24px;
    font-size: 14px; font-weight: 700;
    letter-spacing: 0.5px;
    background: {'rgba(34, 197, 94, 0.1)' if s['target_met'] else 'rgba(239, 68, 68, 0.15)'};
    color: {'#22c55e' if s['target_met'] else '#ef4444'};
    border: 1px solid {'rgba(34, 197, 94, 0.2)' if s['target_met'] else 'rgba(239, 68, 68, 0.3)'};
}}

.stats-row {{ display: flex; gap: 16px; justify-content: center; flex-wrap: wrap; margin: 24px 0; }}
.stat-box {{
    background: #12121a; border: 1px solid #1f1f2e; border-radius: 12px;
    padding: 20px 32px; text-align: center; min-width: 140px;
}}
.stat-box .value {{ font-size: 36px; font-weight: 800; }}
.stat-box .label {{ font-size: 11px; color: #71717a; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }}
.stat-box.green .value {{ color: #22c55e; }}
.stat-box.red .value {{ color: #ef4444; }}
.stat-box.cyan .value {{ color: #06b6d4; }}

table {{ width: 100%; border-collapse: collapse; margin: 24px 0; }}
th {{ text-align: left; padding: 12px; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: #71717a; border-bottom: 2px solid #1f1f2e; }}
td {{ padding: 12px; border-bottom: 1px solid #1f1f2e; font-size: 13px; }}

.footer {{ text-align: center; padding: 32px 0; color: #52525b; font-size: 12px; border-top: 1px solid #1f1f2e; margin-top: 40px; }}
</style>
</head>
<body>
<div class="container">
<div class="header">
    <div class="logo-icon">Δ</div>
    <h1>AEGIS Security Platform</h1>
    <div class="subtitle">Full Validation Suite — Consolidated Report</div>
    <div class="master-badge">{'✅ ALL PHASES PASSED' if s['target_met'] else '❌ ' + str(s['failed']) + ' CHECKS FAILED'}</div>
</div>

<div class="stats-row">
    <div class="stat-box cyan"><div class="value">{s['total']}</div><div class="label">Total Checks</div></div>
    <div class="stat-box green"><div class="value">{s['passed']}</div><div class="label">Passed</div></div>
    <div class="stat-box red"><div class="value">{s['failed']}</div><div class="label">Failed</div></div>
</div>

<div style="background:#12121a;border:1px solid #1f1f2e;border-radius:12px;padding:24px;margin:24px 0;">
    <h2 style="font-size:16px;font-weight:600;margin-bottom:16px;">📊 Phase Results</h2>
    <table>
        <tr><th>Phase</th><th>Title</th><th style="text-align:center;">Passed</th><th style="text-align:center;">Rate</th><th style="text-align:center;">Status</th><th style="text-align:right;">Duration</th></tr>
        {phase_rows}
    </table>
</div>

<div class="footer">
    <p>Generated: {timestamp}</p>
    <p>Project AEGIS — Lead Architect: ETCHERO / Abdul-Hameed</p>
</div>
</div>
</body>
</html>"""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
    return html


def main():
    parser = argparse.ArgumentParser(
        description="AEGIS Validation Program — Master Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  python validation/run_all.py              # Run all phases\n"
               "  python validation/run_all.py --phases 0   # Phase 0 only\n"
               "  python validation/run_all.py --phases 0 1 # Phases 0 and 1\n"
               "  python validation/run_all.py --serve      # Open HTML report",
    )
    parser.add_argument("--phases", nargs="+", type=int, default=[0, 1],
                        help="Phase numbers to run (default: 0 1)")
    parser.add_argument("--serve", action="store_true",
                        help="Open the HTML report in browser after completion")
    args = parser.parse_args()

    print(f"\n{'╔' + '═' * 56 + '╗'}")
    print(f"║     PROJECT AEGIS — VALIDATION PROGRAM                    ║")
    print(f"║     Master Validation Runner                              ║")
    print(f"║     {datetime.now().isoformat()[:19]}                              ║")
    print(f"{'╚' + '═' * 56 + '╝'}")
    print(f"\n  Phases to run: {', '.join(str(p) for p in args.phases)}")
    print()

    phase_reports = []
    for phase_num in args.phases:
        report = run_phase(phase_num)
        phase_reports.append(report)

    # Generate consolidated master report
    master = consolidate_reports(phase_reports)
    json_path = PROJECT_ROOT / "validation" / "reports" / "master_report.json"
    html_path = PROJECT_ROOT / "validation" / "reports" / "master_report.html"
    master.to_json(json_path)
    generate_master_html(master, phase_reports, html_path)

    # Print final summary
    s = master.summary()
    print(f"\n{'═' * 56}")
    print(f"  VALIDATION COMPLETE")
    print(f"  {'═' * 56}")
    print(f"  Total Checks : {s['total']}")
    print(f"  Passed       : {s['passed']}")
    print(f"  Failed       : {s['failed']}")
    print(f"  Pass Rate    : {s['pass_rate']}%")
    print(f"  Target Met   : {'✅ YES' if s['target_met'] else '❌ NO'}")
    print(f"  Duration     : {s['duration_seconds']:.1f}s")
    print(f"  {'═' * 56}")
    print(f"  📄 JSON: {json_path}")
    print(f"  📄 HTML: {html_path}")
    print(f"  {'═' * 56}\n")

    # Open report in browser if --serve
    if args.serve:
        import webbrowser
        webbrowser.open(html_path.as_uri())
        print(f"  🌐 Opened {html_path} in browser\n")

    return 1 if not s["target_met"] else 0


if __name__ == "__main__":
    sys.exit(main())
