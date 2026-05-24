"""Report generator — creates security assessment reports.

Basic reporting focused on structured output:
1. Finding summary by severity
2. Attack chain documentation
3. Remediation recommendations
4. Executive summary
5. Technical details per finding
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class ReportSection:
    """A section of the report."""
    title: str = ""
    content: str = ""
    severity: str = ""
    order: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {"title": self.title[:20], "severity": self.severity[:4], "length": len(self.content)}


@dataclass
class SecurityReport:
    """A complete security assessment report."""
    report_id: str = ""
    target: str = ""
    generated_at: float = field(default_factory=time.time)
    executive_summary: str = ""
    sections: list[ReportSection] = field(default_factory=list)
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    attack_chains: list[dict[str, Any]] = field(default_factory=list)
    tools_used: list[str] = field(default_factory=list)
    kbs_used: list[str] = field(default_factory=list)
    duration_s: float = 0.0
    overall_risk: str = "medium"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.report_id[:8],
            "target": self.target[:20],
            "findings": self.total_findings,
            "critical": self.critical_count,
            "high": self.high_count,
            "risk": self.overall_risk[:6],
        }


# Remediation templates per vulnerability type
REMEDIATION_MAP: dict[str, str] = {
    "sqli": "Use parameterized queries/prepared statements. Implement input validation. Use ORM frameworks. Apply least-privilege database accounts.",
    "xss": "Implement context-aware output encoding. Use Content-Security-Policy headers. Sanitize user input. Use modern framework auto-escaping.",
    "ssrf": "Implement URL allowlist validation. Block internal/private IP ranges. Use network-level controls. Disable unnecessary URL schemes.",
    "rce": "Never pass user input to system commands. Use parameterized APIs. Implement strict input validation. Run with least privileges.",
    "idor": "Implement proper authorization checks on every request. Use indirect object references. Validate user ownership of requested resources.",
    "auth_bypass": "Implement multi-layer authentication. Use proven auth frameworks. Enforce session management. Add rate limiting.",
    "csrf": "Implement anti-CSRF tokens. Use SameSite cookie attribute. Verify Origin/Referer headers. Require re-authentication for sensitive actions.",
    "path_traversal": "Canonicalize file paths. Use allowlist for allowed directories. Never use user input in file paths directly.",
    "xxe": "Disable external entity processing. Use JSON instead of XML. If XML needed, use safe parser configuration.",
    "deserialization": "Avoid deserializing untrusted data. Use allowlists for permitted classes. Implement integrity checks. Use safe serialization formats.",
    "open_redirect": "Validate redirect URLs against allowlist. Use relative URLs. Never redirect to user-controlled destinations.",
    "weak_credentials": "Enforce strong password policies. Implement account lockout. Use MFA. Change all default credentials.",
    "info_disclosure": "Remove verbose error messages. Disable directory listing. Remove server version headers. Implement proper error handling.",
    "cors": "Configure strict CORS policies. Never use Access-Control-Allow-Origin: *. Validate Origin header on server side.",
}


class ReportGenerator:
    """Generates security assessment reports."""

    def __init__(self) -> None:
        self._report_counter = 0
        self._log = logger.bind(component="report_generator")

    def generate(
        self,
        target: str,
        findings: list[dict[str, Any]],
        attack_chains: list[dict[str, Any]] | None = None,
        tools_used: list[str] | None = None,
        kbs_used: list[str] | None = None,
        duration_s: float = 0.0,
    ) -> SecurityReport:
        """Generate a full security report."""
        self._report_counter += 1

        # Count by severity
        sev_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev in sev_counts:
                sev_counts[sev] += 1

        # Determine overall risk
        if sev_counts["critical"] > 0:
            overall_risk = "critical"
        elif sev_counts["high"] > 2:
            overall_risk = "high"
        elif sev_counts["high"] > 0:
            overall_risk = "medium-high"
        elif sev_counts["medium"] > 0:
            overall_risk = "medium"
        else:
            overall_risk = "low"

        # Generate executive summary
        exec_summary = self._generate_executive_summary(target, sev_counts, overall_risk, attack_chains or [])

        # Generate finding sections
        sections = self._generate_finding_sections(findings)

        report = SecurityReport(
            report_id=f"report-{self._report_counter}",
            target=target,
            executive_summary=exec_summary,
            sections=sections,
            total_findings=len(findings),
            critical_count=sev_counts["critical"],
            high_count=sev_counts["high"],
            medium_count=sev_counts["medium"],
            low_count=sev_counts["low"],
            info_count=sev_counts["info"],
            attack_chains=attack_chains or [],
            tools_used=tools_used or [],
            kbs_used=kbs_used or [],
            duration_s=duration_s,
            overall_risk=overall_risk,
        )

        return report

    def _generate_executive_summary(
        self,
        target: str,
        sev_counts: dict[str, int],
        overall_risk: str,
        chains: list[dict[str, Any]],
    ) -> str:
        """Generate executive summary."""
        total = sum(sev_counts.values())
        lines = [
            f"Security assessment of {target} identified {total} findings.",
            f"Overall risk level: {overall_risk.upper()}.",
        ]
        if sev_counts["critical"] > 0:
            lines.append(f"{sev_counts['critical']} CRITICAL vulnerabilities require immediate attention.")
        if sev_counts["high"] > 0:
            lines.append(f"{sev_counts['high']} HIGH severity issues should be addressed within 30 days.")
        if chains:
            lines.append(f"{len(chains)} attack chains were identified that amplify individual finding impact.")
        return " ".join(lines)

    def _generate_finding_sections(self, findings: list[dict[str, Any]]) -> list[ReportSection]:
        """Generate report sections from findings."""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.get("severity", "info"), 99))

        sections: list[ReportSection] = []
        for i, f in enumerate(sorted_findings[:50]):
            sev = f.get("severity", "info")
            title = f.get("title", "Untitled Finding")
            desc = f.get("description", "")
            evidence = f.get("evidence", "")
            vuln_type = f.get("type", "").lower()
            remediation = REMEDIATION_MAP.get(vuln_type, "Review and apply appropriate security controls.")

            content = f"**Severity:** {sev.upper()}\n"
            content += f"**Description:** {desc}\n"
            if evidence:
                content += f"**Evidence:** {evidence[:200]}\n"
            content += f"**Remediation:** {remediation}\n"

            sections.append(ReportSection(
                title=f"[{sev.upper()}] {title}",
                content=content,
                severity=sev,
                order=i,
            ))

        return sections

    def to_markdown(self, report: SecurityReport) -> str:
        """Convert report to Markdown format."""
        lines = [f"# Security Assessment Report: {report.target}\n"]
        lines.append(f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(report.generated_at))}")
        lines.append(f"**Duration:** {report.duration_s:.0f}s")
        lines.append(f"**Overall Risk:** {report.overall_risk.upper()}\n")

        lines.append("## Executive Summary\n")
        lines.append(report.executive_summary + "\n")

        lines.append("## Finding Summary\n")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        lines.append(f"| Critical | {report.critical_count} |")
        lines.append(f"| High | {report.high_count} |")
        lines.append(f"| Medium | {report.medium_count} |")
        lines.append(f"| Low | {report.low_count} |")
        lines.append(f"| Info | {report.info_count} |")
        lines.append(f"| **Total** | **{report.total_findings}** |\n")

        if report.attack_chains:
            lines.append("## Attack Chains\n")
            for chain in report.attack_chains[:10]:
                lines.append(f"### {chain.get('name', 'Unnamed Chain')}")
                lines.append(f"**Severity:** {chain.get('severity', 'unknown')}")
                for step in chain.get("steps", []):
                    lines.append(f"  {step.get('order', 0)+1}. {step.get('finding', '')}")
                lines.append("")

        lines.append("## Detailed Findings\n")
        for section in report.sections[:30]:
            lines.append(f"### {section.title}\n")
            lines.append(section.content)
            lines.append("")

        if report.tools_used:
            lines.append("## Tools Used\n")
            lines.append(", ".join(report.tools_used[:20]))

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {"reports_generated": self._report_counter}
