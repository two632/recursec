"""Report generator — produces Markdown, HTML, and JSON reports from scan findings.

Supports:
- Executive summary with risk scoring
- Detailed technical findings with evidence
- Severity breakdown and statistics
- Attack chain visualization
- Remediation guidance
- CVSS scoring
- Timeline of discovery
- Appendices with raw tool output
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

from recursec.analysis.vuln_correlator import CorrelatedFinding
from recursec.core.models import Severity

logger = structlog.get_logger()


class ReportGenerator:
    """Generates security assessment reports."""

    def __init__(self, project_name: str = "RecurSec Assessment") -> None:
        self.project_name = project_name
        self._findings: list[CorrelatedFinding] = []
        self._attack_chains: list[dict[str, Any]] = []
        self._scan_metadata: dict[str, Any] = {}
        self._tool_outputs: dict[str, str] = {}

    def set_findings(self, findings: list[CorrelatedFinding]) -> None:
        self._findings = findings

    def set_attack_chains(self, chains: list[dict[str, Any]]) -> None:
        self._attack_chains = chains

    def set_metadata(self, metadata: dict[str, Any]) -> None:
        self._scan_metadata = metadata

    def add_tool_output(self, tool_name: str, output: str) -> None:
        self._tool_outputs[tool_name] = output

    # ── Markdown Report ────────────────────────────────────

    def generate_markdown(self) -> str:
        """Generate a comprehensive Markdown report."""
        lines: list[str] = []

        # Header
        lines.append(f"# {self.project_name}")
        lines.append(f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append("**Framework:** RecurSec Recursive Multi-Agent Security Framework")
        lines.append("")

        target = self._scan_metadata.get("target", "N/A")
        lines.append(f"**Target:** `{target}`")
        scan_time = self._scan_metadata.get("scan_duration", "N/A")
        lines.append(f"**Scan Duration:** {scan_time}")
        lines.append("")

        # Executive Summary
        lines.append("---")
        lines.append("## Executive Summary")
        lines.append("")
        severity_counts = self._severity_counts()
        total = sum(severity_counts.values())
        lines.append(f"This assessment identified **{total} findings** across the target environment:")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                lines.append(f"| {sev.value.upper()} | {count} |")
        lines.append("")

        risk_score = self._calculate_risk_score()
        risk_level = "CRITICAL" if risk_score >= 8 else "HIGH" if risk_score >= 6 else "MODERATE" if risk_score >= 4 else "LOW"
        lines.append(f"**Overall Risk Score:** {risk_score:.1f}/10 ({risk_level})")
        lines.append("")

        # Key findings summary
        critical_findings = [f for f in self._findings if f.severity == Severity.CRITICAL]
        if critical_findings:
            lines.append("### Critical Findings Requiring Immediate Attention")
            lines.append("")
            for f in critical_findings:
                lines.append(f"- **{f.title}** — {f.description[:150]}")
            lines.append("")

        # Attack Chains
        if self._attack_chains:
            lines.append("---")
            lines.append("## Attack Chains")
            lines.append("")
            lines.append("The following exploitation paths were identified:")
            lines.append("")
            for i, chain in enumerate(self._attack_chains, 1):
                lines.append(f"### Chain {i}: {chain.get('name', 'Unnamed')}")
                lines.append(f"**Impact:** {chain.get('impact', 'N/A')}")
                lines.append(f"**Risk:** {chain.get('risk_score', 'N/A')}/10")
                lines.append("")
                steps = chain.get("steps", [])
                for j, step in enumerate(steps, 1):
                    lines.append(f"{j}. {step.get('description', '')}")
                lines.append("")

        # Detailed Findings
        lines.append("---")
        lines.append("## Detailed Findings")
        lines.append("")

        for i, finding in enumerate(self._findings, 1):
            lines.append(f"### {i}. {finding.title}")
            lines.append("")
            lines.append("| Field | Value |")
            lines.append("|-------|-------|")
            lines.append(f"| **Severity** | {finding.severity.value.upper()} |")
            lines.append(f"| **CVSS** | {finding.cvss_score} |")
            if finding.cve_id:
                lines.append(f"| **CVE** | {finding.cve_id} |")
            if finding.cwe_id:
                lines.append(f"| **CWE** | {finding.cwe_id} |")
            lines.append(f"| **Confidence** | {finding.confidence:.0%} |")
            lines.append(f"| **Validated** | {'Yes' if finding.validated else 'No'} |")
            components = ", ".join(finding.affected_components[:5])
            lines.append(f"| **Components** | {components} |")
            sources = ", ".join(finding.tool_sources[:5])
            lines.append(f"| **Detected By** | {sources} |")
            lines.append("")

            lines.append("**Description:**")
            lines.append("")
            lines.append(finding.description)
            lines.append("")

            if finding.evidence:
                lines.append("**Evidence:**")
                lines.append("")
                for ev in finding.evidence[:3]:
                    lines.append("```")
                    lines.append(ev[:500])
                    lines.append("```")
                lines.append("")

            if finding.remediation:
                lines.append("**Remediation:**")
                lines.append("")
                lines.append(finding.remediation)
                lines.append("")

            lines.append("---")
            lines.append("")

        # Methodology
        lines.append("## Methodology")
        lines.append("")
        lines.append("This assessment was performed using RecurSec, a recursive multi-agent security framework.")
        lines.append("The framework employs multiple specialized AI agents coordinated by an orchestrator,")
        lines.append("with 16 local LLM models providing reasoning, planning, and analysis capabilities.")
        lines.append("")
        lines.append("### Agents Used")
        lines.append("")
        agents = self._scan_metadata.get("agents_used", [])
        if agents:
            for agent in agents:
                lines.append(f"- **{agent.get('role', '')}**: {agent.get('tasks', 0)} tasks")
        lines.append("")

        lines.append("### Tools Used")
        lines.append("")
        tools = self._scan_metadata.get("tools_used", [])
        if tools:
            for tool in tools:
                lines.append(f"- {tool}")
        lines.append("")

        return "\n".join(lines)

    # ── JSON Report ────────────────────────────────────────

    def generate_json(self) -> dict[str, Any]:
        """Generate a machine-readable JSON report."""
        return {
            "report_metadata": {
                "title": self.project_name,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "framework": "RecurSec",
                "version": "0.1.0",
            },
            "scan_metadata": self._scan_metadata,
            "summary": {
                "total_findings": len(self._findings),
                "severity_counts": {k.value: v for k, v in self._severity_counts().items()},
                "risk_score": round(self._calculate_risk_score(), 1),
                "attack_chains": len(self._attack_chains),
            },
            "findings": [f.to_dict() for f in self._findings],
            "attack_chains": self._attack_chains,
        }

    # ── HTML Report ────────────────────────────────────────

    def generate_html(self) -> str:
        """Generate a styled HTML report."""
        severity_counts = self._severity_counts()
        risk_score = self._calculate_risk_score()

        findings_html = ""
        for i, f in enumerate(self._findings, 1):
            sev_class = f.severity.value
            evidence_html = ""
            if f.evidence:
                for ev in f.evidence[:2]:
                    evidence_html += f'<pre class="evidence">{_html_escape(ev[:500])}</pre>'

            findings_html += f"""
            <div class="finding {sev_class}">
                <div class="finding-header">
                    <span class="finding-num">#{i}</span>
                    <span class="severity-badge {sev_class}">{f.severity.value.upper()}</span>
                    <span class="finding-title">{_html_escape(f.title)}</span>
                    <span class="cvss">CVSS {f.cvss_score}</span>
                </div>
                <div class="finding-body">
                    <p>{_html_escape(f.description)}</p>
                    {evidence_html}
                    {'<p class="remediation"><strong>Remediation:</strong> ' + _html_escape(f.remediation) + '</p>' if f.remediation else ''}
                </div>
            </div>
            """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_html_escape(self.project_name)}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0a0a0f;color:#e0e0e0;line-height:1.6}}
.container{{max-width:1000px;margin:0 auto;padding:40px 20px}}
h1{{font-size:28px;margin-bottom:10px;background:linear-gradient(90deg,#ff0044,#ff6600);-webkit-background-clip:text;-webkit-text-fill-color:transparent}}
h2{{font-size:20px;margin:30px 0 15px;border-bottom:1px solid #333;padding-bottom:8px}}
.meta{{color:#888;font-size:14px;margin-bottom:30px}}
.summary-grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:15px;margin:20px 0}}
.summary-card{{background:#111118;border:1px solid #222;border-radius:8px;padding:20px;text-align:center}}
.summary-card .count{{font-size:32px;font-weight:bold}}
.summary-card .label{{font-size:12px;color:#888;text-transform:uppercase;margin-top:5px}}
.critical .count{{color:#ff0044}}.high .count{{color:#ff6600}}.medium .count{{color:#ffaa00}}.low .count{{color:#00aaff}}.info .count{{color:#888}}
.risk-bar{{background:#111118;border:1px solid #222;border-radius:8px;padding:20px;margin:20px 0}}
.risk-score{{font-size:48px;font-weight:bold;color:{'#ff0044' if risk_score >= 8 else '#ff6600' if risk_score >= 6 else '#ffaa00' if risk_score >= 4 else '#00ff44'}}}
.finding{{background:#111118;border:1px solid #222;border-radius:8px;margin:15px 0;overflow:hidden}}
.finding-header{{display:flex;align-items:center;gap:12px;padding:15px;border-bottom:1px solid #222}}
.finding-num{{color:#555;font-weight:bold}}.finding-title{{flex:1;font-weight:bold}}
.severity-badge{{padding:3px 10px;border-radius:3px;font-size:11px;font-weight:bold}}
.severity-badge.critical{{background:#ff004422;color:#ff0044}}.severity-badge.high{{background:#ff660022;color:#ff6600}}
.severity-badge.medium{{background:#ffaa0022;color:#ffaa00}}.severity-badge.low{{background:#00aaff22;color:#00aaff}}
.severity-badge.info{{background:#88888822;color:#888}}
.cvss{{color:#888;font-size:12px}}
.finding-body{{padding:15px}}
.evidence{{background:#050508;border:1px solid #222;border-radius:4px;padding:10px;margin:10px 0;font-size:12px;overflow-x:auto;white-space:pre-wrap;font-family:monospace;color:#aaa}}
.remediation{{background:#001a0022;border-left:3px solid #00aa44;padding:10px;margin-top:10px;border-radius:0 4px 4px 0}}
</style>
</head>
<body>
<div class="container">
<h1>{_html_escape(self.project_name)}</h1>
<div class="meta">Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} | Framework: RecurSec</div>

<h2>Summary</h2>
<div class="summary-grid">
    <div class="summary-card critical"><div class="count">{severity_counts.get(Severity.CRITICAL, 0)}</div><div class="label">Critical</div></div>
    <div class="summary-card high"><div class="count">{severity_counts.get(Severity.HIGH, 0)}</div><div class="label">High</div></div>
    <div class="summary-card medium"><div class="count">{severity_counts.get(Severity.MEDIUM, 0)}</div><div class="label">Medium</div></div>
    <div class="summary-card low"><div class="count">{severity_counts.get(Severity.LOW, 0)}</div><div class="label">Low</div></div>
    <div class="summary-card info"><div class="count">{severity_counts.get(Severity.INFO, 0)}</div><div class="label">Info</div></div>
</div>
<div class="risk-bar">
    <div>Overall Risk Score</div>
    <div class="risk-score">{risk_score:.1f}/10</div>
</div>

<h2>Findings ({len(self._findings)})</h2>
{findings_html}
</div>
</body>
</html>"""

        return html

    # ── Save Reports ───────────────────────────────────────

    def save(self, output_dir: str, formats: list[str] | None = None) -> dict[str, str]:
        """Save reports in specified formats. Returns dict of format -> filepath."""
        formats = formats or ["markdown", "html", "json"]
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        saved: dict[str, str] = {}
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        if "markdown" in formats:
            md_file = output_path / f"report_{timestamp}.md"
            md_file.write_text(self.generate_markdown())
            saved["markdown"] = str(md_file)

        if "html" in formats:
            html_file = output_path / f"report_{timestamp}.html"
            html_file.write_text(self.generate_html())
            saved["html"] = str(html_file)

        if "json" in formats:
            json_file = output_path / f"report_{timestamp}.json"
            json_file.write_text(json.dumps(self.generate_json(), indent=2))
            saved["json"] = str(json_file)

        return saved

    # ── Internal Helpers ───────────────────────────────────

    def _severity_counts(self) -> dict[Severity, int]:
        counts: dict[Severity, int] = {}
        for f in self._findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def _calculate_risk_score(self) -> float:
        """Calculate overall risk score (0-10)."""
        if not self._findings:
            return 0.0

        weights = {Severity.CRITICAL: 10, Severity.HIGH: 7, Severity.MEDIUM: 4, Severity.LOW: 1, Severity.INFO: 0}
        total_weight = sum(weights.get(f.severity, 0) * f.confidence for f in self._findings)
        max_possible = len(self._findings) * 10

        base_score = (total_weight / max_possible) * 10 if max_possible > 0 else 0

        # Boost for attack chains
        if self._attack_chains:
            base_score = min(10.0, base_score + len(self._attack_chains) * 0.5)

        return min(10.0, base_score)


def _html_escape(text: str) -> str:
    """Escape HTML special characters."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )
