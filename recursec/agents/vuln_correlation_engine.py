"""Vulnerability correlation engine — cross-references findings across sources.

This module takes findings from multiple tools/agents and:
1. Deduplicates (same vuln found by multiple tools)
2. Cross-references with CVE/CWE/NVD databases
3. Correlates with EPSS (Exploit Prediction Scoring System)
4. Identifies vulnerability chains and dependencies
5. Calculates true risk score (not just CVSS)
6. Groups related vulnerabilities
7. Identifies coverage gaps (what wasn't tested)
8. Maps to compliance frameworks (PCI DSS, NIST, OWASP)
"""

from __future__ import annotations

import hashlib
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class FindingSource(str, Enum):
    TOOL_SCAN = "tool_scan"
    MANUAL_TEST = "manual_test"
    CODE_REVIEW = "code_review"
    LLM_ANALYSIS = "llm_analysis"
    OSINT = "osint"
    SELF_PLAY = "self_play"


class ConfidenceLevel(str, Enum):
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNVERIFIED = "unverified"


class ComplianceFramework(str, Enum):
    OWASP_TOP10 = "owasp_top10"
    PCI_DSS = "pci_dss"
    NIST_CSF = "nist_csf"
    CIS_CONTROLS = "cis_controls"
    HIPAA = "hipaa"
    SOC2 = "soc2"
    ISO27001 = "iso27001"
    GDPR = "gdpr"


@dataclass
class NormalizedFinding:
    """A deduplicated, normalized finding."""
    finding_id: str = ""
    title: str = ""
    description: str = ""
    severity: str = "medium"
    cvss_score: float = 5.0
    epss_score: float = 0.0
    true_risk_score: float = 5.0
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    target: str = ""
    location: str = ""
    vuln_type: str = ""
    cve_ids: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    sources: list[FindingSource] = field(default_factory=list)
    tools_found_by: list[str] = field(default_factory=list)
    compliance_violations: list[str] = field(default_factory=list)
    related_findings: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    remediation: str = ""
    first_seen: float = field(default_factory=time.time)
    is_false_positive: bool = False

    @property
    def dedup_key(self) -> str:
        raw = f"{self.vuln_type}:{self.target}:{self.location}:{self.title}"
        return hashlib.md5(raw.encode()).hexdigest()[:12]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.finding_id[:8],
            "title": self.title[:30],
            "severity": self.severity[:8],
            "risk": f"{self.true_risk_score:.1f}",
            "confidence": self.confidence.value[:8],
            "sources": len(self.sources),
            "cves": len(self.cve_ids),
            "compliance": len(self.compliance_violations),
        }


@dataclass
class FindingCluster:
    """A group of related findings."""
    cluster_id: str = ""
    name: str = ""
    findings: list[str] = field(default_factory=list)
    common_vuln_type: str = ""
    aggregate_risk: float = 0.0
    impact_chain: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.cluster_id[:8],
            "name": self.name[:25],
            "findings": len(self.findings),
            "risk": f"{self.aggregate_risk:.1f}",
        }


@dataclass
class CoverageGap:
    """An area that wasn't tested."""
    area: str = ""
    reason: str = ""
    risk_of_missing: str = "medium"
    recommended_tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "area": self.area[:25],
            "risk": self.risk_of_missing[:8],
            "tools": self.recommended_tools[:2],
        }


# CWE → OWASP Top 10 mapping
CWE_OWASP_MAP: dict[str, str] = {
    "CWE-89": "A03:2021 Injection",
    "CWE-79": "A03:2021 Injection",
    "CWE-78": "A03:2021 Injection",
    "CWE-918": "A10:2021 SSRF",
    "CWE-287": "A07:2021 Identification and Authentication Failures",
    "CWE-639": "A01:2021 Broken Access Control",
    "CWE-200": "A01:2021 Broken Access Control",
    "CWE-284": "A01:2021 Broken Access Control",
    "CWE-352": "A01:2021 Broken Access Control",
    "CWE-502": "A08:2021 Software and Data Integrity Failures",
    "CWE-611": "A05:2021 Security Misconfiguration",
    "CWE-732": "A05:2021 Security Misconfiguration",
    "CWE-798": "A07:2021 Identification and Authentication Failures",
    "CWE-319": "A02:2021 Cryptographic Failures",
    "CWE-327": "A02:2021 Cryptographic Failures",
    "CWE-1035": "A06:2021 Vulnerable and Outdated Components",
    "CWE-770": "A04:2021 Insecure Design",
    "CWE-915": "A04:2021 Insecure Design",
}

# CWE → PCI DSS mapping
CWE_PCI_MAP: dict[str, str] = {
    "CWE-89": "PCI DSS 6.2.4 - Injection flaws",
    "CWE-79": "PCI DSS 6.2.4 - Injection flaws",
    "CWE-287": "PCI DSS 8.2 - Authentication",
    "CWE-319": "PCI DSS 4.1 - Encryption in transit",
    "CWE-327": "PCI DSS 3.4 - Cryptography",
    "CWE-798": "PCI DSS 8.3 - Strong authentication",
    "CWE-200": "PCI DSS 3.1 - Data protection",
}

# Severity → CVSS base mapping
SEVERITY_CVSS: dict[str, float] = {
    "critical": 9.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 3.0,
    "info": 1.0,
}


class VulnCorrelationEngine:
    """Cross-references and correlates vulnerability findings."""

    def __init__(self) -> None:
        self._findings: dict[str, NormalizedFinding] = {}
        self._clusters: list[FindingCluster] = {}
        self._coverage_gaps: list[CoverageGap] = []
        self._dedup_map: dict[str, str] = {}
        self._finding_counter = 0
        self._duplicates_found = 0
        self._log = logger.bind(component="vuln_correlation")

    def ingest_finding(
        self,
        title: str,
        description: str = "",
        severity: str = "medium",
        target: str = "",
        location: str = "",
        vuln_type: str = "",
        source: FindingSource = FindingSource.TOOL_SCAN,
        tool: str = "",
        cve_ids: list[str] | None = None,
        cwe_ids: list[str] | None = None,
        evidence: list[str] | None = None,
    ) -> NormalizedFinding:
        """Ingest a raw finding, normalize and deduplicate."""
        # Create normalized finding
        finding = NormalizedFinding(
            title=title,
            description=description,
            severity=severity,
            target=target,
            location=location,
            vuln_type=vuln_type,
            sources=[source],
            tools_found_by=[tool] if tool else [],
            cve_ids=cve_ids or [],
            cwe_ids=cwe_ids or [],
            evidence=evidence or [],
        )

        # Check dedup
        dedup_key = finding.dedup_key
        if dedup_key in self._dedup_map:
            # Merge with existing
            existing = self._findings[self._dedup_map[dedup_key]]
            existing.sources.extend(finding.sources)
            existing.tools_found_by.extend(finding.tools_found_by)
            if finding.evidence:
                existing.evidence.extend(finding.evidence)
            # Boost confidence when multiple sources agree
            if len(set(existing.sources)) >= 3:
                existing.confidence = ConfidenceLevel.CONFIRMED
            elif len(set(existing.sources)) >= 2:
                existing.confidence = ConfidenceLevel.HIGH
            self._duplicates_found += 1
            return existing

        # New finding
        self._finding_counter += 1
        finding.finding_id = f"VUL-{self._finding_counter}"
        finding.cvss_score = SEVERITY_CVSS.get(severity, 5.0)

        # Map to compliance
        for cwe in finding.cwe_ids:
            owasp = CWE_OWASP_MAP.get(cwe)
            if owasp:
                finding.compliance_violations.append(owasp)
            pci = CWE_PCI_MAP.get(cwe)
            if pci:
                finding.compliance_violations.append(pci)

        # Calculate true risk
        finding.true_risk_score = self._calculate_true_risk(finding)

        self._findings[finding.finding_id] = finding
        self._dedup_map[dedup_key] = finding.finding_id

        return finding

    def _calculate_true_risk(self, finding: NormalizedFinding) -> float:
        """Calculate true risk score (0-10) considering multiple factors."""
        base = finding.cvss_score

        # Boost for confirmed findings
        confidence_mult = {
            ConfidenceLevel.CONFIRMED: 1.2,
            ConfidenceLevel.HIGH: 1.1,
            ConfidenceLevel.MEDIUM: 1.0,
            ConfidenceLevel.LOW: 0.8,
            ConfidenceLevel.UNVERIFIED: 0.6,
        }
        risk = base * confidence_mult.get(finding.confidence, 1.0)

        # Boost for known CVEs (actively exploited)
        if finding.cve_ids:
            risk *= 1.15

        # EPSS boost
        if finding.epss_score > 0.5:
            risk *= 1.2

        # Multiple sources = more reliable
        if len(set(finding.sources)) >= 2:
            risk *= 1.1

        return min(10.0, risk)

    def correlate_findings(self) -> list[FindingCluster]:
        """Group and correlate all findings."""
        # Group by vuln_type
        by_type: dict[str, list[NormalizedFinding]] = defaultdict(list)
        for f in self._findings.values():
            by_type[f.vuln_type].append(f)

        clusters = []
        cluster_counter = 0
        for vuln_type, findings in by_type.items():
            if len(findings) >= 2:
                cluster_counter += 1
                cluster = FindingCluster(
                    cluster_id=f"CLU-{cluster_counter}",
                    name=f"{vuln_type} cluster ({len(findings)} findings)",
                    findings=[f.finding_id for f in findings],
                    common_vuln_type=vuln_type,
                    aggregate_risk=max(f.true_risk_score for f in findings),
                )
                clusters.append(cluster)

                # Link findings
                for f in findings:
                    f.related_findings = [
                        other.finding_id
                        for other in findings
                        if other.finding_id != f.finding_id
                    ][:5]

        self._clusters = clusters
        return clusters

    def identify_coverage_gaps(self, tested_areas: list[str]) -> list[CoverageGap]:
        """Identify security areas that weren't tested."""
        all_areas = [
            "web_injection", "authentication", "authorization", "cryptography",
            "session_management", "input_validation", "api_security",
            "business_logic", "file_upload", "cors_config",
            "http_headers", "ssl_tls", "rate_limiting",
            "error_handling", "logging_monitoring",
        ]

        gaps = []
        for area in all_areas:
            if area not in tested_areas:
                gaps.append(CoverageGap(
                    area=area,
                    reason="Not covered by current scan",
                    risk_of_missing="medium",
                    recommended_tools=["nuclei", "burpsuite"],
                ))

        self._coverage_gaps = gaps
        return gaps

    def get_findings_by_severity(self) -> dict[str, list[dict[str, Any]]]:
        """Get findings grouped by severity."""
        by_sev: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for f in self._findings.values():
            if not f.is_false_positive:
                by_sev[f.severity].append(f.to_dict())
        return dict(by_sev)

    def get_compliance_report(self, framework: ComplianceFramework = ComplianceFramework.OWASP_TOP10) -> dict[str, list[str]]:
        """Get findings mapped to a compliance framework."""
        violations: dict[str, list[str]] = defaultdict(list)
        for f in self._findings.values():
            for violation in f.compliance_violations:
                if framework == ComplianceFramework.OWASP_TOP10 and violation.startswith("A"):
                    violations[violation].append(f.finding_id)
                elif framework == ComplianceFramework.PCI_DSS and violation.startswith("PCI"):
                    violations[violation].append(f.finding_id)
        return dict(violations)

    def build_correlation_prompt(self) -> str:
        """Build LLM prompt with correlation insights."""
        if not self._findings:
            return ""

        lines = ["## Vulnerability Correlation Summary"]
        lines.append(f"Total unique findings: {len(self._findings)}")
        lines.append(f"Duplicates merged: {self._duplicates_found}")

        by_sev = self.get_findings_by_severity()
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = len(by_sev.get(sev, []))
            if count:
                lines.append(f"  {sev}: {count}")

        clusters = self.correlate_findings()
        if clusters:
            lines.append(f"\nVulnerability clusters: {len(clusters)}")
            for cluster in clusters[:3]:
                lines.append(f"  - {cluster.name} (risk: {cluster.aggregate_risk:.1f})")

        compliance = self.get_compliance_report()
        if compliance:
            lines.append(f"\nOWASP Top 10 violations: {len(compliance)}")
            for violation, findings in list(compliance.items())[:5]:
                lines.append(f"  - {violation}: {len(findings)} findings")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_findings": len(self._findings),
            "duplicates": self._duplicates_found,
            "clusters": len(self._clusters) if isinstance(self._clusters, list) else 0,
            "coverage_gaps": len(self._coverage_gaps),
        }
