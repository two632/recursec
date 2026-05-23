"""Report formatter — generates security assessment reports.

Implements:
1. JSON report generation (machine-readable)
2. Markdown report generation (human-readable)
3. Executive summary generation
4. Technical detail sections
5. Finding deduplication
6. Severity-based sorting
7. Remediation prioritization
8. CVSS and CWE inclusion
9. Timeline of events
10. Risk scoring aggregation
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class FindingSummary:
    """Summarized finding for reports."""
    title: str = ""
    severity: str = "info"
    target: str = ""
    description: str = ""
    evidence: str = ""
    tool: str = ""
    cwe: str = ""
    cvss: float = 0.0
    remediation: str = ""
    validated: bool = False
    confidence: float = 0.5

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title, "severity": self.severity,
            "target": self.target, "description": self.description[:200],
            "tool": self.tool, "cwe": self.cwe,
            "cvss": round(self.cvss, 1), "validated": self.validated,
        }


@dataclass
class ReportSection:
    """A section in the report."""
    title: str = ""
    content: str = ""
    subsections: list[ReportSection] = field(default_factory=list)

    def to_markdown(self, level: int = 2) -> str:
        hashes = "#" * level
        parts = [f"{hashes} {self.title}\n\n{self.content}\n"]
        for sub in self.subsections:
            parts.append(sub.to_markdown(level + 1))
        return "\n".join(parts)


@dataclass
class Report:
    """A complete assessment report."""
    title: str = ""
    target: str = ""
    summary: str = ""
    risk_rating: str = ""
    findings: list[FindingSummary] = field(default_factory=list)
    sections: list[ReportSection] = field(default_factory=list)
    timeline: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    generated_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title, "target": self.target,
            "risk": self.risk_rating,
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.summary,
            "metadata": self.metadata,
            "generated_at": self.generated_at,
        }


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class ReportFormatter:
    """Generates security assessment reports.

    Creates JSON and Markdown reports with executive
    summaries, findings, and remediation guidance.
    """

    def __init__(self, output_dir: str = "data/reports") -> None:
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._log = logger.bind(component="report_formatter")

    def generate(
        self,
        target: str,
        findings: list[dict[str, Any]],
        validated: list[dict[str, Any]] | None = None,
        events: list[dict[str, Any]] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Report:
        """Generate a complete report."""
        # Deduplicate findings
        deduped = self._deduplicate(findings)

        # Convert to summaries
        summaries = []
        for finding in deduped:
            summaries.append(FindingSummary(
                title=finding.get("title", "Unknown"),
                severity=finding.get("severity", "info"),
                target=finding.get("target", target),
                description=finding.get("description", ""),
                evidence=finding.get("evidence", ""),
                tool=finding.get("tool", ""),
                cwe=finding.get("cwe", ""),
                cvss=finding.get("cvss", 0.0),
                remediation=finding.get("remediation", ""),
                validated=finding.get("title", "") in {
                    v.get("title", "") for v in (validated or [])
                },
                confidence=finding.get("confidence", 0.5),
            ))

        # Sort by severity
        summaries.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 4))

        # Risk rating
        risk = self._calculate_risk(summaries)

        # Build report
        report = Report(
            title=f"Security Assessment Report: {target}",
            target=target,
            summary=self._executive_summary(summaries, risk),
            risk_rating=risk,
            findings=summaries,
            timeline=events or [],
            metadata=metadata or {},
        )

        # Build sections
        report.sections = self._build_sections(summaries, target)

        return report

    def save_json(self, report: Report, filename: str = "") -> Path:
        """Save report as JSON."""
        fname = filename or f"report-{int(time.time())}.json"
        path = self._output_dir / fname
        path.write_text(json.dumps(report.to_dict(), indent=2, default=str))
        return path

    def save_markdown(self, report: Report, filename: str = "") -> Path:
        """Save report as Markdown."""
        fname = filename or f"report-{int(time.time())}.md"
        path = self._output_dir / fname
        path.write_text(self._to_markdown(report))
        return path

    def _deduplicate(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Remove duplicate findings."""
        seen: set[str] = set()
        deduped = []

        for finding in findings:
            key = f"{finding.get('title', '')}:{finding.get('target', '')}"
            if key not in seen:
                seen.add(key)
                deduped.append(finding)

        return deduped

    def _calculate_risk(self, findings: list[FindingSummary]) -> str:
        """Calculate overall risk rating."""
        critical = sum(1 for f in findings if f.severity == "critical")
        high = sum(1 for f in findings if f.severity == "high")
        medium = sum(1 for f in findings if f.severity == "medium")

        if critical > 0:
            return "critical"
        elif high >= 3:
            return "critical"
        elif high > 0:
            return "high"
        elif medium >= 3:
            return "high"
        elif medium > 0:
            return "medium"
        return "low"

    def _executive_summary(
        self,
        findings: list[FindingSummary],
        risk: str,
    ) -> str:
        """Generate executive summary."""
        total = len(findings)
        by_sev = {}
        for f in findings:
            by_sev.setdefault(f.severity, 0)
            by_sev[f.severity] += 1

        validated = sum(1 for f in findings if f.validated)

        parts = [
            f"The security assessment identified {total} findings.",
        ]

        if by_sev:
            sev_parts = []
            for sev in ["critical", "high", "medium", "low", "info"]:
                count = by_sev.get(sev, 0)
                if count > 0:
                    sev_parts.append(f"{count} {sev}")
            parts.append(f"Severity breakdown: {', '.join(sev_parts)}.")

        parts.append(f"Overall risk rating: {risk.upper()}.")

        if validated:
            parts.append(f"{validated} findings were independently validated.")

        return " ".join(parts)

    def _build_sections(
        self,
        findings: list[FindingSummary],
        target: str,
    ) -> list[ReportSection]:
        """Build report sections."""
        sections = []

        # Scope section
        sections.append(ReportSection(
            title="Scope",
            content=f"Target: {target}\nAssessment type: Automated security assessment",
        ))

        # Findings by severity
        for severity in ["critical", "high", "medium", "low", "info"]:
            sev_findings = [f for f in findings if f.severity == severity]
            if not sev_findings:
                continue

            subsections = []
            for finding in sev_findings:
                content_parts = [finding.description]
                if finding.evidence:
                    content_parts.append(f"\n**Evidence:** {finding.evidence[:200]}")
                if finding.cwe:
                    content_parts.append(f"\n**CWE:** {finding.cwe}")
                if finding.remediation:
                    content_parts.append(f"\n**Remediation:** {finding.remediation}")

                subsections.append(ReportSection(
                    title=finding.title,
                    content="\n".join(content_parts),
                ))

            sections.append(ReportSection(
                title=f"{severity.upper()} Findings ({len(sev_findings)})",
                content="",
                subsections=subsections,
            ))

        # Remediation section
        remediations = [f for f in findings if f.remediation]
        if remediations:
            rem_text = "\n".join(
                f"- **{f.title}**: {f.remediation[:100]}"
                for f in remediations[:20]
            )
            sections.append(ReportSection(
                title="Remediation Summary",
                content=rem_text,
            ))

        return sections

    def _to_markdown(self, report: Report) -> str:
        """Convert report to Markdown."""
        parts = [
            f"# {report.title}\n",
            f"**Risk Rating:** {report.risk_rating.upper()}\n",
            f"**Target:** {report.target}\n",
            f"**Generated:** {time.ctime(report.generated_at)}\n",
            "---\n",
            "## Executive Summary\n",
            f"{report.summary}\n",
        ]

        for section in report.sections:
            parts.append(section.to_markdown(2))

        return "\n".join(parts)

    def get_stats(self) -> dict[str, Any]:
        reports = list(self._output_dir.glob("report-*"))
        return {"reports_generated": len(reports)}
