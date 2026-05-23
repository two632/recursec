"""Output formatter — formats findings and results for various outputs.

Supports:
1. JSON structured output
2. Markdown reports
3. Terminal-friendly colored output
4. SARIF format (Static Analysis Results Interchange Format)
5. CSV/TSV for spreadsheet import
6. Summary statistics
7. Diff format (changes since last scan)
8. Custom templates
"""

from __future__ import annotations

import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class OutputFormat(str, Enum):
    JSON = "json"
    MARKDOWN = "markdown"
    TERMINAL = "terminal"
    SARIF = "sarif"
    CSV = "csv"
    SUMMARY = "summary"


SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_COLORS = {
    "critical": "\033[91m",   # Red
    "high": "\033[93m",       # Yellow
    "medium": "\033[33m",     # Orange
    "low": "\033[94m",        # Blue
    "info": "\033[90m",       # Gray
}
RESET = "\033[0m"


@dataclass
class FormattedOutput:
    """A formatted output."""
    format_type: OutputFormat = OutputFormat.JSON
    content: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class OutputFormatter:
    """Formats security findings and assessment results.

    Produces structured outputs in multiple formats
    for different consumers (humans, tools, APIs).
    """

    def __init__(self) -> None:
        self._log = logger.bind(component="output_formatter")

    def format_findings(
        self,
        findings: list[dict[str, Any]],
        output_format: OutputFormat = OutputFormat.JSON,
        target: str = "",
        title: str = "",
    ) -> FormattedOutput:
        """Format a list of findings."""
        if output_format == OutputFormat.JSON:
            content = self._format_json(findings, target, title)
        elif output_format == OutputFormat.MARKDOWN:
            content = self._format_markdown(findings, target, title)
        elif output_format == OutputFormat.TERMINAL:
            content = self._format_terminal(findings, target, title)
        elif output_format == OutputFormat.SARIF:
            content = self._format_sarif(findings, target, title)
        elif output_format == OutputFormat.CSV:
            content = self._format_csv(findings)
        elif output_format == OutputFormat.SUMMARY:
            content = self._format_summary(findings, target, title)
        else:
            content = self._format_json(findings, target, title)

        return FormattedOutput(
            format_type=output_format,
            content=content,
            metadata={
                "findings_count": len(findings),
                "target": target,
                "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            },
        )

    # ── JSON ─────────────────────────────────────────────

    def _format_json(
        self,
        findings: list[dict[str, Any]],
        target: str,
        title: str,
    ) -> str:
        report = {
            "title": title or "Security Assessment Report",
            "target": target,
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "summary": self._build_summary(findings),
            "findings": [self._clean_finding(f) for f in findings],
        }
        return json.dumps(report, indent=2, default=str)

    # ── Markdown ─────────────────────────────────────────

    def _format_markdown(
        self,
        findings: list[dict[str, Any]],
        target: str,
        title: str,
    ) -> str:
        lines = []
        lines.append(f"# {title or 'Security Assessment Report'}")
        lines.append(f"\n**Target:** {target}")
        lines.append(f"**Date:** {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}")
        lines.append(f"**Total Findings:** {len(findings)}")

        # Summary
        summary = self._build_summary(findings)
        lines.append("\n## Summary\n")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in SEVERITY_ORDER:
            count = summary["by_severity"].get(sev, 0)
            if count > 0:
                lines.append(f"| {sev.title()} | {count} |")

        # Findings by severity
        sorted_findings = sorted(
            findings,
            key=lambda f: SEVERITY_ORDER.index(
                f.get("severity", "medium").lower()
            ) if f.get("severity", "medium").lower() in SEVERITY_ORDER else 5,
        )

        current_severity = ""
        for finding in sorted_findings:
            severity = finding.get("severity", "medium").lower()
            if severity != current_severity:
                current_severity = severity
                lines.append(f"\n## {severity.title()} Severity\n")

            lines.append(f"### {finding.get('title', 'N/A')}\n")
            lines.append(f"- **Severity:** {severity.title()}")
            if finding.get("target"):
                lines.append(f"- **Target:** {finding['target']}")
            if finding.get("tool"):
                lines.append(f"- **Tool:** {finding['tool']}")
            if finding.get("cve"):
                lines.append(f"- **CVE:** {finding['cve']}")

            desc = finding.get("description", "")
            if desc:
                lines.append(f"\n{desc[:500]}")

            evidence = finding.get("evidence", "")
            if evidence:
                lines.append(f"\n**Evidence:**\n```\n{evidence[:300]}\n```")

            remediation = finding.get("remediation", "")
            if remediation:
                lines.append(f"\n**Remediation:** {remediation[:200]}")

            lines.append("")

        return "\n".join(lines)

    # ── Terminal ─────────────────────────────────────────

    def _format_terminal(
        self,
        findings: list[dict[str, Any]],
        target: str,
        title: str,
    ) -> str:
        lines = []
        lines.append(f"\n{'='*60}")
        lines.append(f"  {title or 'Security Assessment Report'}")
        lines.append(f"  Target: {target}")
        lines.append(f"  Findings: {len(findings)}")
        lines.append(f"{'='*60}\n")

        # Summary bar
        summary = self._build_summary(findings)
        for sev in SEVERITY_ORDER:
            count = summary["by_severity"].get(sev, 0)
            if count > 0:
                color = SEVERITY_COLORS.get(sev, "")
                lines.append(f"  {color}[{sev.upper():>8}]{RESET} {count} finding(s)")

        lines.append("")

        # Findings
        sorted_findings = sorted(
            findings,
            key=lambda f: SEVERITY_ORDER.index(
                f.get("severity", "medium").lower()
            ) if f.get("severity", "medium").lower() in SEVERITY_ORDER else 5,
        )

        for i, finding in enumerate(sorted_findings, 1):
            severity = finding.get("severity", "medium").lower()
            color = SEVERITY_COLORS.get(severity, "")
            lines.append(f"  {color}[{severity.upper():>8}]{RESET} {i}. {finding.get('title', 'N/A')}")
            if finding.get("target"):
                lines.append(f"             Target: {finding['target']}")
            if finding.get("tool"):
                lines.append(f"             Tool: {finding['tool']}")
            lines.append("")

        return "\n".join(lines)

    # ── SARIF ────────────────────────────────────────────

    def _format_sarif(
        self,
        findings: list[dict[str, Any]],
        target: str,
        title: str,
    ) -> str:
        severity_map = {
            "critical": "error", "high": "error",
            "medium": "warning", "low": "note", "info": "none",
        }

        results = []
        for finding in findings:
            severity = finding.get("severity", "medium").lower()
            result = {
                "ruleId": finding.get("type", "security-finding"),
                "level": severity_map.get(severity, "warning"),
                "message": {
                    "text": finding.get("title", ""),
                },
                "locations": [],
            }
            if finding.get("target"):
                result["locations"].append({
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding["target"],
                        },
                    },
                })
            results.append(result)

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "RecurSec",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/recursec/recursec",
                    },
                },
                "results": results,
            }],
        }
        return json.dumps(sarif, indent=2)

    # ── CSV ──────────────────────────────────────────────

    def _format_csv(self, findings: list[dict[str, Any]]) -> str:
        lines = ["severity,title,target,tool,type,cve"]
        for finding in findings:
            row = [
                finding.get("severity", ""),
                finding.get("title", "").replace(",", ";"),
                finding.get("target", ""),
                finding.get("tool", ""),
                finding.get("type", ""),
                finding.get("cve", ""),
            ]
            lines.append(",".join(f'"{v}"' for v in row))
        return "\n".join(lines)

    # ── Summary ──────────────────────────────────────────

    def _format_summary(
        self,
        findings: list[dict[str, Any]],
        target: str,
        title: str,
    ) -> str:
        summary = self._build_summary(findings)
        lines = []
        lines.append(f"Assessment: {title or 'Security Assessment'}")
        lines.append(f"Target: {target}")
        lines.append(f"Total: {len(findings)} findings")
        for sev in SEVERITY_ORDER:
            count = summary["by_severity"].get(sev, 0)
            if count > 0:
                lines.append(f"  {sev.title()}: {count}")
        lines.append(f"Risk: {summary['risk_level']}")
        return "\n".join(lines)

    # ── Utilities ────────────────────────────────────────

    def _build_summary(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        by_severity: dict[str, int] = defaultdict(int)
        by_type: dict[str, int] = defaultdict(int)
        by_tool: dict[str, int] = defaultdict(int)
        targets: set[str] = set()

        for finding in findings:
            sev = finding.get("severity", "medium").lower()
            by_severity[sev] += 1
            by_type[finding.get("type", "other")] += 1
            by_tool[finding.get("tool", "unknown")] += 1
            if finding.get("target"):
                targets.add(finding["target"])

        critical = by_severity.get("critical", 0)
        high = by_severity.get("high", 0)

        if critical > 0:
            risk_level = "critical"
        elif high > 2:
            risk_level = "high"
        elif by_severity.get("medium", 0) > 5:
            risk_level = "medium"
        else:
            risk_level = "low"

        return {
            "total": len(findings),
            "by_severity": dict(by_severity),
            "by_type": dict(by_type),
            "by_tool": dict(by_tool),
            "targets": len(targets),
            "risk_level": risk_level,
        }

    def _clean_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Clean a finding for output."""
        keys = ["title", "severity", "description", "target", "tool",
                "type", "cve", "cwe", "evidence", "remediation",
                "confidence", "validated"]
        return {k: finding.get(k, "") for k in keys if finding.get(k)}
