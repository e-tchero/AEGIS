"""
Project AEGIS — Validation Report Generator
Lead Architect: ETCHERO / Abdul-Hameed
Version: 1.0.0 | Classification: AEGIS-VALIDATION

Professional report generator with HTML + JSON output for investor demos.
Produces clean, branded validation reports suitable for funder presentations.
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class ValidationResult:
    """A single validation check with pass/fail, severity, and fix guidance."""

    def __init__(self, name: str, category: str):
        self.name = name
        self.category = category
        self.passed: bool = False
        self.detail: str = ""
        self.severity: str = "INFO"  # INFO, WARN, ERROR, CRITICAL
        self.suggested_fix: str = ""

    def pass_(self, detail: str = "") -> "ValidationResult":
        self.passed = True
        self.severity = "INFO"
        self.detail = detail
        return self

    def fail(self, detail: str, severity: str = "ERROR",
             fix: str = "") -> "ValidationResult":
        self.passed = False
        self.severity = severity
        self.detail = detail
        self.suggested_fix = fix
        return self

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "category": self.category,
            "passed": self.passed,
            "severity": self.severity,
            "detail": self.detail,
            "suggested_fix": self.suggested_fix,
        }


class ValidationReport:
    """Collects results and generates polished reports."""

    def __init__(self, phase: str, title: str):
        self.phase = phase
        self.title = title
        self.timestamp = datetime.now().isoformat()
        self.results: List[ValidationResult] = []
        self.metadata: Dict[str, Any] = {}
        self.duration: float = 0.0

    def add(self, result: ValidationResult) -> None:
        self.results.append(result)

    def add_metadata(self, key: str, value: Any) -> None:
        self.metadata[key] = value

    def summary(self) -> dict:
        total = len(self.results)
        passed = sum(1 for r in self.results if r.passed)
        failed = total - passed
        by_severity: Dict[str, int] = {}
        for r in self.results:
            by_severity[r.severity] = by_severity.get(r.severity, 0) + 1
        pass_rate = (passed / total * 100) if total else 0
        return {
            "phase": self.phase,
            "title": self.title,
            "timestamp": self.timestamp,
            "duration_seconds": round(self.duration, 2),
            "total": total,
            "passed": passed,
            "failed": failed,
            "pass_rate": round(pass_rate, 1),
            "pass_rate_display": f"{passed}/{total} ({pass_rate:.1f}%)",
            "by_severity": by_severity,
            "target_met": pass_rate == 100.0,
        }

    def to_json(self, path: Optional[Path] = None) -> str:
        data = {
            "summary": self.summary(),
            "metadata": self.metadata,
            "results": [r.to_dict() for r in self.results],
        }
        output = json.dumps(data, indent=2)
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(output, encoding="utf-8")
        return output

    def to_html(self, path: Optional[Path] = None) -> str:
        """Generate a polished, branded HTML report for investor demos."""
        s = self.summary()

        # Build parts with simple string operations to avoid f-string nesting issues
        pass_rate = f"{s['pass_rate']:.0f}"
        total = s['total']
        passed = s['passed']
        failed = s['failed']
        target_met = s['target_met']
        ok_color = "#22c55e"
        fail_color = "#ef4444"
        badge_color = ok_color if target_met else fail_color
        badge_bg = "rgba(34, 197, 94, 0.1)" if target_met else "rgba(239, 68, 68, 0.15)"
        badge_border = "rgba(34, 197, 94, 0.2)" if target_met else "rgba(239, 68, 68, 0.3)"
        badge_text = "ALL CHECKS PASSED" if target_met else str(failed) + " CHECKS FAILED"
        gradient_color = ok_color if target_met else fail_color

        parts = []
        parts.append('<!DOCTYPE html>')
        parts.append('<html lang="en">')
        parts.append('<head>')
        parts.append('<meta charset="UTF-8">')
        parts.append('<meta name="viewport" content="width=device-width, initial-scale=1.0">')
        parts.append('<title>AEGIS Validation &mdash; ' + self.phase + '</title>')
        parts.append('<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&amp;family=JetBrains+Mono:wght@400;500&amp;display=swap" rel="stylesheet">')
        parts.append('<style>')
        parts.append(self._css_styles())
        parts.append('</style>')
        parts.append('</head>')
        parts.append('<body>')
        parts.append('<div class="container">')

        # Header
        parts.append('<div class="header">')
        parts.append('<div class="logo">')
        parts.append('<div class="logo-icon">&Delta;</div>')
        parts.append('<div>')
        parts.append('<h1>AEGIS Security Platform</h1>')
        parts.append('<div class="subtitle">Validation Report &mdash; ' + self.phase + '</div>')
        parts.append('</div></div>')
        parts.append('<div class="phase-badge" style="background:' + badge_bg + ';color:' + badge_color + ';border:1px solid ' + badge_border + ';">')
        parts.append(badge_text)
        parts.append('</div></div>')

        # Score ring + stats
        parts.append('<div class="score-ring">')
        parts.append('<div class="score-circle" style="background: conic-gradient(' + gradient_color + ' ' + pass_rate + '%, #1f1f2e ' + pass_rate + '%);">')
        parts.append('<div class="score-value" style="color:' + gradient_color + ';">' + pass_rate + '%</div>')
        parts.append('<div class="score-label">Pass Rate</div>')
        parts.append('</div>')
        parts.append('<div class="stats-grid">')
        parts.append('<div class="stat-card total"><div class="stat-value" style="color:#06b6d4;">' + str(total) + '</div><div class="stat-label">Total Checks</div></div>')
        parts.append('<div class="stat-card pass"><div class="stat-value" style="color:' + ok_color + ';">' + str(passed) + '</div><div class="stat-label">Passed</div></div>')
        parts.append('<div class="stat-card fail"><div class="stat-value" style="color:' + fail_color + ';">' + str(failed) + '</div><div class="stat-label">Failed</div></div>')
        parts.append('</div></div>')

        # Check results
        parts.append('<div class="results-section">')
        parts.append('<h2>Check Results</h2>')

        categories: Dict[str, list] = {}
        for r in self.results:
            categories.setdefault(r.category, []).append(r)

        for cat, cat_results in categories.items():
            parts.append('<div style="margin-bottom:20px;">')
            parts.append('<h3 style="font-size:13px;color:#71717a;text-transform:uppercase;margin-bottom:8px;">' + cat + '</h3>')
            for r in cat_results:
                icon = "&#9989;" if r.passed else "&#10060;"
                cls = "passed" if r.passed else "failed"
                fix_html = ''
                if not r.passed and r.suggested_fix:
                    fix_html = '<div class="fix-box">' + r.suggested_fix + '</div>'
                parts.append('<div class="result-item ' + cls + '">')
                parts.append('<div class="icon">' + icon + '</div>')
                parts.append('<div class="content">')
                parts.append('<div class="name">' + self._escape_html(r.name) + '</div>')
                parts.append('<div class="detail">' + self._escape_html(r.detail) + '</div>')
                parts.append(fix_html)
                parts.append('</div>')
                parts.append('<span class="severity severity-' + r.severity + '">' + r.severity + '</span>')
                parts.append('</div>')
            parts.append('</div>')

        # Metadata
        if self.metadata:
            parts.append('<div class="metadata-section">')
            parts.append('<h3>Environment</h3>')
            parts.append('<div class="metadata-grid">')
            for k, v in self.metadata.items():
                parts.append('<div class="metadata-item"><strong>' + self._escape_html(k) + ':</strong> ' + self._escape_html(str(v)) + '</div>')
            parts.append('</div></div>')

        # Footer
        parts.append('<div class="footer">')
        parts.append('<p>Generated: ' + s['timestamp'][:19] + ' | Duration: ' + str(s['duration_seconds']) + 's</p>')
        parts.append('<p>Project AEGIS &mdash; Lead Architect: ETCHERO / Abdul-Hameed</p>')
        parts.append('</div>')

        parts.append('</div></body></html>')

        html = '\n'.join(parts)

        if path:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(html, encoding="utf-8")
        return html

    @staticmethod
    def _css_styles() -> str:
        """Return the CSS styles for the HTML report."""
        return """
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    font-family: 'Inter', -apple-system, sans-serif;
    background: #0a0a0f;
    color: #e4e4e7;
    line-height: 1.6;
    padding: 40px 24px;
}
.container { max-width: 900px; margin: 0 auto; }
.header { text-align: center; padding: 40px 0 32px; border-bottom: 1px solid #1f1f2e; margin-bottom: 32px; }
.header .logo { display: inline-flex; align-items: center; gap: 12px; margin-bottom: 12px; }
.header .logo-icon { width: 48px; height: 48px; background: linear-gradient(135deg, #06b6d4, #2563eb); border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 24px; font-weight: 800; color: white; box-shadow: 0 4px 20px rgba(6,182,212,0.3); }
.header h1 { font-size: 28px; font-weight: 800; color: #fff; }
.header .subtitle { color: #71717a; font-size: 14px; margin-top: 4px; }
.header .phase-badge { display: inline-block; padding: 6px 16px; border-radius: 20px; font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; margin-top: 12px; }
.score-ring { display: flex; align-items: center; justify-content: center; gap: 48px; padding: 32px 0; flex-wrap: wrap; }
.score-circle { width: 140px; height: 140px; border-radius: 50%; display: flex; flex-direction: column; align-items: center; justify-content: center; position: relative; }
.score-circle::before { content: ''; position: absolute; width: 120px; height: 120px; border-radius: 50%; background: #0a0a0f; }
.score-value { position: relative; z-index: 1; font-size: 36px; font-weight: 800; }
.score-label { position: relative; z-index: 1; font-size: 11px; color: #71717a; text-transform: uppercase; letter-spacing: 1px; }
.stats-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }
.stat-card { background: #12121a; border: 1px solid #1f1f2e; border-radius: 12px; padding: 20px 24px; text-align: center; }
.stat-value { font-size: 32px; font-weight: 700; }
.stat-label { font-size: 12px; color: #71717a; text-transform: uppercase; letter-spacing: 0.5px; margin-top: 4px; }
.results-section { margin-top: 32px; }
.results-section h2 { font-size: 18px; font-weight: 600; margin-bottom: 16px; color: #f4f4f5; }
.result-item { background: #12121a; border: 1px solid #1f1f2e; border-radius: 10px; padding: 16px 20px; margin-bottom: 8px; display: flex; align-items: flex-start; gap: 12px; }
.result-item.passed { border-left: 3px solid #22c55e; }
.result-item.failed { border-left: 3px solid #ef4444; }
.result-item .icon { font-size: 18px; margin-top: 1px; }
.result-item .content { flex: 1; }
.result-item .name { font-weight: 600; font-size: 14px; color: #e4e4e7; }
.result-item .detail { font-size: 12px; color: #71717a; margin-top: 2px; }
.result-item .severity { font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; padding: 2px 8px; border-radius: 4px; font-weight: 600; margin-left: auto; }
.severity-CRITICAL { background: rgba(239,68,68,0.15); color: #ef4444; }
.severity-ERROR { background: rgba(251,146,60,0.15); color: #fb923c; }
.severity-WARN { background: rgba(234,179,8,0.15); color: #eab308; }
.fix-box { margin-top: 8px; padding: 8px 12px; background: rgba(6,182,212,0.05); border: 1px solid rgba(6,182,212,0.15); border-radius: 6px; font-size: 12px; color: #22d3ee; }
.metadata-section { margin-top: 32px; padding: 20px; background: #12121a; border: 1px solid #1f1f2e; border-radius: 12px; }
.metadata-section h3 { font-size: 14px; font-weight: 600; margin-bottom: 12px; color: #a1a1aa; }
.metadata-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 8px; }
.metadata-item { font-size: 12px; color: #71717a; }
.metadata-item strong { color: #d4d4d8; }
.footer { text-align: center; padding: 32px 0; color: #52525b; font-size: 12px; border-top: 1px solid #1f1f2e; margin-top: 40px; }
"""

    @staticmethod
    def _escape_html(text: str) -> str:
        """Escape HTML special characters in text."""
        return (text
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&#39;"))

    def print_console(self, show_all: bool = False) -> None:
        """Print a clean console report."""
        s = self.summary()
        print(f"\n  {'═' * 56}")
        print(f"  {self.phase}: {self.title}")
        print(f"  {'═' * 56}")
        print(f"  Duration: {s['duration_seconds']:.2f}s")
        print(f"  Results: {s['pass_rate_display']}")
        print(f"  Target Met: {'✅ YES' if s['target_met'] else '❌ NO'}")

        # Only show failures by default for cleaner output
        failures = [r for r in self.results if not r.passed]
        if failures:
            print(f"\n  {'─' * 56}")
            print(f"  FAILURES ({len(failures)}):")
            for r in failures:
                print(f"  ❌ [{r.severity}] {r.name}")
                print(f"     {r.detail}")
                if r.suggested_fix:
                    print(f"     🔧 {r.suggested_fix}")
        elif show_all:
            print(f"\n  {'─' * 56}")
            print(f"  ALL CHECKS:")
            for r in self.results:
                icon = "✅" if r.passed else "❌"
                print(f"  {icon} {r.name:<50} {r.detail[:50]}")

        print(f"\n  {'═' * 56}")
        status = "PASSED" if s['target_met'] else "FAILED"
        print(f"  {self.phase}: {status}")
        print(f"  {'═' * 56}\n")
