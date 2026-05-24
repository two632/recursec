"""Finding correlator — correlates and chains findings for higher impact.

Implements:
1. Cross-tool finding correlation
2. Attack chain building from individual findings
3. Impact amplification (chained findings > individual)
4. MITRE ATT&CK technique mapping
5. Duplicate/overlap detection
6. Coverage gap analysis
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class CorrelationType(str, Enum):
    SAME_TARGET = "same_target"
    SAME_VULN_TYPE = "same_vuln_type"
    CHAIN = "chain"
    AMPLIFICATION = "amplification"
    DUPLICATE = "duplicate"
    RELATED = "related"


@dataclass
class Correlation:
    """A correlation between two findings."""
    correlation_id: str = ""
    finding_a_id: str = ""
    finding_b_id: str = ""
    correlation_type: CorrelationType = CorrelationType.RELATED
    confidence: float = 0.5
    description: str = ""
    combined_severity: str = ""
    combined_impact: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.correlation_id[:8],
            "type": self.correlation_type.value[:8],
            "a": self.finding_a_id[:8],
            "b": self.finding_b_id[:8],
            "severity": self.combined_severity[:4],
        }


@dataclass
class CoverageGap:
    """A gap in assessment coverage."""
    gap_id: str = ""
    area: str = ""
    description: str = ""
    recommended_tools: list[str] = field(default_factory=list)
    recommended_kbs: list[str] = field(default_factory=list)
    priority: str = "medium"

    def to_dict(self) -> dict[str, Any]:
        return {"area": self.area[:15], "priority": self.priority[:4]}


# Attack chain patterns — known chains that amplify impact
CHAIN_PATTERNS: list[dict[str, Any]] = [
    {"name": "Info Leak → Auth Bypass → RCE", "stages": ["info_disclosure", "auth_bypass", "rce"], "severity": "critical", "description": "Information leakage reveals credentials/tokens, enabling authentication bypass, leading to remote code execution."},
    {"name": "SSRF → Cloud Metadata → Account Takeover", "stages": ["ssrf", "cloud_metadata", "credential_theft"], "severity": "critical", "description": "SSRF accesses cloud metadata endpoint, retrieves IAM credentials, enables full cloud account compromise."},
    {"name": "XSS → Session Hijack → Admin Access", "stages": ["xss", "session_theft", "privilege_escalation"], "severity": "high", "description": "Stored XSS steals admin session token, granting attacker administrative access."},
    {"name": "SQLi → Data Dump → Credential Reuse", "stages": ["sqli", "data_exfil", "credential_reuse"], "severity": "critical", "description": "SQL injection dumps user table with password hashes, cracked credentials enable access to other systems."},
    {"name": "Open Port → Service Exploit → Lateral Movement", "stages": ["open_port", "service_exploit", "lateral_movement"], "severity": "high", "description": "Exposed service has known vulnerability, exploitation gives foothold, pivot to internal network."},
    {"name": "Subdomain Takeover → Phishing → Credential Harvest", "stages": ["subdomain_takeover", "phishing", "credential_theft"], "severity": "high", "description": "Dangling DNS record enables subdomain takeover, used for convincing phishing campaign."},
    {"name": "IDOR → PII Leak → Compliance Violation", "stages": ["idor", "pii_leak", "compliance"], "severity": "high", "description": "Insecure direct object reference exposes PII of other users, violating GDPR/HIPAA."},
    {"name": "Weak Creds → Admin Panel → Data Exfil", "stages": ["weak_credentials", "admin_access", "data_exfil"], "severity": "critical", "description": "Default/weak credentials on admin panel enable full application control and data extraction."},
]

# Coverage domains to check
COVERAGE_DOMAINS: list[dict[str, Any]] = [
    {"area": "subdomain_enum", "tools": ["subfinder", "amass"], "kbs": ["dns"]},
    {"area": "port_scanning", "tools": ["nmap", "masscan"], "kbs": ["network"]},
    {"area": "web_vuln_scan", "tools": ["nuclei", "nikto"], "kbs": ["web_vuln"]},
    {"area": "injection_test", "tools": ["sqlmap"], "kbs": ["web_vuln", "xss"]},
    {"area": "dir_brute", "tools": ["ffuf", "gobuster"], "kbs": ["web_vuln"]},
    {"area": "ssl_analysis", "tools": ["testssl"], "kbs": ["network"]},
    {"area": "code_audit", "tools": ["semgrep", "bandit"], "kbs": ["supply_chain"]},
    {"area": "secret_scan", "tools": ["gitleaks"], "kbs": ["devsecops"]},
    {"area": "cloud_audit", "tools": ["prowler", "scoutsuite"], "kbs": ["cloud"]},
    {"area": "container_scan", "tools": ["trivy"], "kbs": ["container_k8s"]},
]


class FindingCorrelator:
    """Correlates findings and builds attack chains."""

    def __init__(self) -> None:
        self._correlations: list[Correlation] = []
        self._gaps: list[CoverageGap] = []
        self._corr_counter = 0
        self._gap_counter = 0
        self._log = logger.bind(component="finding_correlator")

    def correlate_findings(
        self,
        findings: list[dict[str, Any]],
    ) -> list[Correlation]:
        """Find correlations between findings."""
        correlations: list[Correlation] = []

        for i, fa in enumerate(findings):
            for fb in findings[i + 1:]:
                corr = self._check_correlation(fa, fb)
                if corr:
                    correlations.append(corr)

        self._correlations.extend(correlations)
        return correlations

    def _check_correlation(
        self,
        fa: dict[str, Any],
        fb: dict[str, Any],
    ) -> Correlation | None:
        """Check if two findings are correlated."""
        self._corr_counter += 1

        # Same target, different findings
        if fa.get("target") == fb.get("target"):
            # Check for chain pattern
            fa_type = fa.get("type", "").lower()
            fb_type = fb.get("type", "").lower()

            for chain in CHAIN_PATTERNS:
                stages = chain["stages"]
                for j, stage in enumerate(stages[:-1]):
                    next_stage = stages[j + 1]
                    if (stage in fa_type and next_stage in fb_type) or (stage in fb_type and next_stage in fa_type):
                        return Correlation(
                            correlation_id=f"corr-{self._corr_counter}",
                            finding_a_id=fa.get("id", ""),
                            finding_b_id=fb.get("id", ""),
                            correlation_type=CorrelationType.CHAIN,
                            confidence=0.7,
                            description=chain["description"],
                            combined_severity=chain["severity"],
                        )

            # Same vuln type on same target = duplicate
            if fa_type == fb_type:
                return Correlation(
                    correlation_id=f"corr-{self._corr_counter}",
                    finding_a_id=fa.get("id", ""),
                    finding_b_id=fb.get("id", ""),
                    correlation_type=CorrelationType.DUPLICATE,
                    confidence=0.8,
                    description="Same vulnerability type on same target",
                )

        return None

    def find_coverage_gaps(
        self,
        tools_used: list[str],
        kbs_loaded: list[str],
    ) -> list[CoverageGap]:
        """Identify gaps in assessment coverage."""
        gaps: list[CoverageGap] = []

        for domain in COVERAGE_DOMAINS:
            # Check if any required tool was used
            domain_tools = domain["tools"]
            if not any(t in tools_used for t in domain_tools):
                self._gap_counter += 1
                gap = CoverageGap(
                    gap_id=f"gap-{self._gap_counter}",
                    area=domain["area"],
                    description=f"No tools from [{', '.join(domain_tools)}] were used for {domain['area']}",
                    recommended_tools=domain_tools,
                    recommended_kbs=domain.get("kbs", []),
                )
                gaps.append(gap)

        self._gaps.extend(gaps)
        return gaps

    def get_chain_findings(self) -> list[Correlation]:
        """Get all chain correlations."""
        return [c for c in self._correlations if c.correlation_type == CorrelationType.CHAIN]

    def get_stats(self) -> dict[str, Any]:
        type_counts: dict[str, int] = {}
        for c in self._correlations:
            key = c.correlation_type.value
            type_counts[key] = type_counts.get(key, 0) + 1
        return {
            "total_correlations": len(self._correlations),
            "chains": len(self.get_chain_findings()),
            "gaps": len(self._gaps),
            "by_type": type_counts,
        }

    def build_correlator_prompt(self) -> str:
        """Build LLM prompt with correlation info."""
        stats = self.get_stats()
        lines = ["## Finding Correlations"]
        lines.append(f"Correlations: {stats['total_correlations']}")
        lines.append(f"Chains: {stats['chains']}")
        lines.append(f"Coverage gaps: {stats['gaps']}")
        chains = self.get_chain_findings()
        for c in chains[:5]:
            lines.append(f"  Chain: {c.description[:60]} [{c.combined_severity}]")
        return "\n".join(lines)
