"""Report generator — produces assessment reports in multiple formats.

Implements:
1. JSON report generation
2. Markdown report generation
3. Executive summary generation
4. Finding detail formatting
5. Risk matrix generation
6. Statistics and metrics
7. Timeline of actions
8. Remediation priority list
"""

from __future__ import annotations

import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class ReportSection:
    """A section of the report."""
    title: str = ""
    content: str = ""
    subsections: list[ReportSection] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title[:40],
            "content_len": len(self.content),
            "subsections": len(self.subsections),
        }


@dataclass
class AssessmentReport:
    """A complete assessment report."""
    report_id: str = ""
    title: str = ""
    target: str = ""
    assessor: str = "RecurSec"
    start_time: float = 0.0
    end_time: float = 0.0
    sections: list[ReportSection] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    @property
    def duration_s(self) -> float:
        return max(0, self.end_time - self.start_time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.report_id, "target": self.target[:40],
            "findings": len(self.findings),
            "sections": len(self.sections),
            "duration_s": round(self.duration_s, 0),
        }


class ReportGenerator:
    """Produces assessment reports in multiple formats.

    Generates JSON and Markdown reports with
    executive summaries, findings, and recommendations.
    """

    def __init__(self, output_dir: str = "data/reports") -> None:
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._report_counter = 0
        self._log = logger.bind(component="report_generator")

    def generate(
        self,
        target: str,
        findings: list[dict[str, Any]],
        metrics: dict[str, Any] | None = None,
        start_time: float = 0.0,
        end_time: float = 0.0,
    ) -> AssessmentReport:
        """Generate a complete assessment report."""
        self._report_counter += 1
        report_id = f"report-{self._report_counter}"

        report = AssessmentReport(
            report_id=report_id,
            title=f"Security Assessment: {target}",
            target=target,
            start_time=start_time or time.time(),
            end_time=end_time or time.time(),
            findings=findings,
            metrics=metrics or {},
        )

        # Build sections
        report.sections = [
            self._executive_summary(report),
            self._findings_section(report),
            self._risk_matrix(report),
            self._remediation_section(report),
            self._metrics_section(report),
        ]

        return report

    def _executive_summary(self, report: AssessmentReport) -> ReportSection:
        """Generate executive summary."""
        severity_counts = self._count_severities(report.findings)
        total = len(report.findings)

        summary_lines = [
            f"Target: {report.target}",
            f"Duration: {report.duration_s:.0f} seconds",
            f"Total Findings: {total}",
            f"Critical: {severity_counts.get('critical', 0)}",
            f"High: {severity_counts.get('high', 0)}",
            f"Medium: {severity_counts.get('medium', 0)}",
            f"Low: {severity_counts.get('low', 0)}",
            f"Info: {severity_counts.get('info', 0)}",
        ]

        risk_level = "Low"
        if severity_counts.get("critical", 0) > 0:
            risk_level = "Critical"
        elif severity_counts.get("high", 0) > 0:
            risk_level = "High"
        elif severity_counts.get("medium", 0) > 0:
            risk_level = "Medium"

        summary_lines.append(f"\nOverall Risk Level: {risk_level}")

        return ReportSection(
            title="Executive Summary",
            content="\n".join(summary_lines),
            data={"severity_counts": severity_counts, "risk_level": risk_level},
        )

    def _findings_section(self, report: AssessmentReport) -> ReportSection:
        """Generate findings detail section."""
        subsections = []

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            report.findings,
            key=lambda f: severity_order.get(f.get("severity", "info"), 4),
        )

        for i, finding in enumerate(sorted_findings):
            content_lines = [
                f"Severity: {finding.get('severity', 'info').upper()}",
                f"Target: {finding.get('target', 'N/A')}",
                f"Description: {finding.get('description', 'N/A')}",
            ]

            if finding.get("evidence"):
                content_lines.append(f"Evidence: {finding['evidence'][:200]}")
            if finding.get("remediation"):
                content_lines.append(f"Remediation: {finding['remediation'][:200]}")
            if finding.get("cve"):
                content_lines.append(f"CVE: {finding['cve']}")
            if finding.get("cwe"):
                content_lines.append(f"CWE: {finding['cwe']}")

            subsections.append(ReportSection(
                title=f"{i + 1}. {finding.get('title', 'Finding')}",
                content="\n".join(content_lines),
            ))

        return ReportSection(
            title="Findings",
            content=f"Total: {len(report.findings)} findings",
            subsections=subsections,
        )

    def _risk_matrix(self, report: AssessmentReport) -> ReportSection:
        """Generate risk matrix."""
        matrix: dict[str, dict[str, int]] = {
            "critical": {"network": 0, "web": 0, "config": 0, "crypto": 0, "other": 0},
            "high": {"network": 0, "web": 0, "config": 0, "crypto": 0, "other": 0},
            "medium": {"network": 0, "web": 0, "config": 0, "crypto": 0, "other": 0},
            "low": {"network": 0, "web": 0, "config": 0, "crypto": 0, "other": 0},
        }

        for finding in report.findings:
            sev = finding.get("severity", "low")
            if sev not in matrix:
                continue

            title = finding.get("title", "").lower()
            if any(w in title for w in ["port", "service", "network", "firewall"]):
                category = "network"
            elif any(w in title for w in ["xss", "sql", "injection", "web", "http"]):
                category = "web"
            elif any(w in title for w in ["config", "default", "misconfiguration"]):
                category = "config"
            elif any(w in title for w in ["ssl", "tls", "cipher", "crypto"]):
                category = "crypto"
            else:
                category = "other"

            matrix[sev][category] += 1

        content_lines = ["Severity | Network | Web | Config | Crypto | Other"]
        content_lines.append("---------|---------|-----|--------|--------|------")
        for sev in ["critical", "high", "medium", "low"]:
            row = matrix[sev]
            content_lines.append(
                f"{sev.upper():8s} | {row['network']:7d} | {row['web']:3d} | "
                f"{row['config']:6d} | {row['crypto']:6d} | {row['other']:5d}"
            )

        return ReportSection(
            title="Risk Matrix",
            content="\n".join(content_lines),
            data={"matrix": matrix},
        )

    def _remediation_section(self, report: AssessmentReport) -> ReportSection:
        """Generate remediation priority list."""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

        sorted_findings = sorted(
            report.findings,
            key=lambda f: severity_order.get(f.get("severity", "info"), 4),
        )

        lines = []
        for i, finding in enumerate(sorted_findings):
            remediation = finding.get("remediation", "No specific remediation provided")
            sev = finding.get("severity", "info").upper()
            lines.append(f"{i + 1}. [{sev}] {finding.get('title', 'Finding')}")
            lines.append(f"   Remediation: {remediation[:150]}")
            lines.append("")

        return ReportSection(
            title="Remediation Priority",
            content="\n".join(lines),
        )

    def _metrics_section(self, report: AssessmentReport) -> ReportSection:
        """Generate metrics section."""
        lines = [
            f"Assessment Duration: {report.duration_s:.0f}s",
            f"Total Findings: {len(report.findings)}",
        ]

        if report.metrics:
            for key, value in report.metrics.items():
                lines.append(f"{key}: {value}")

        return ReportSection(
            title="Assessment Metrics",
            content="\n".join(lines),
            data=report.metrics,
        )

    def save_json(self, report: AssessmentReport) -> str:
        """Save report as JSON."""
        path = self._output_dir / f"{report.report_id}.json"

        data = {
            "id": report.report_id,
            "title": report.title,
            "target": report.target,
            "assessor": report.assessor,
            "duration_s": report.duration_s,
            "findings": report.findings,
            "metrics": report.metrics,
            "severity_counts": self._count_severities(report.findings),
            "sections": [s.to_dict() for s in report.sections],
            "created_at": report.created_at,
        }

        path.write_text(json.dumps(data, indent=2, default=str))
        return str(path)

    def save_markdown(self, report: AssessmentReport) -> str:
        """Save report as Markdown."""
        path = self._output_dir / f"{report.report_id}.md"

        lines = [
            f"# {report.title}",
            "",
            f"**Target:** {report.target}",
            f"**Assessor:** {report.assessor}",
            f"**Date:** {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(report.created_at))}",
            "",
        ]

        for section in report.sections:
            lines.append(f"## {section.title}")
            lines.append("")
            lines.append(section.content)
            lines.append("")

            for sub in section.subsections:
                lines.append(f"### {sub.title}")
                lines.append("")
                lines.append(sub.content)
                lines.append("")

        path.write_text("\n".join(lines))
        return str(path)

    @staticmethod
    def _count_severities(findings: list[dict[str, Any]]) -> dict[str, int]:
        counts: dict[str, int] = defaultdict(int)
        for finding in findings:
            sev = finding.get("severity", "info")
            counts[sev] += 1
        return dict(counts)

    def get_stats(self) -> dict[str, Any]:
        return {
            "reports": self._report_counter,
            "output_dir": str(self._output_dir),
        }
