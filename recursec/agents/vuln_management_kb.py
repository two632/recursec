"""Vulnerability management lifecycle knowledge base.

Deep knowledge about vulnerability management:
1. Vulnerability discovery and classification
2. CVSS scoring and prioritization
3. Remediation strategies
4. Patch management
5. Vulnerability tracking and metrics
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class VulnMgmtPattern:
    """A vulnerability management pattern."""
    pattern_id: str = ""
    name: str = ""
    category: str = ""
    severity: str = "high"
    description: str = ""
    detection_strategy: str = ""
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:25],
            "category": self.category[:12],
        }


VULNMGMT_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "vm-001", "name": "Vulnerability Discovery",
        "category": "discovery", "severity": "high",
        "desc": "Vulnerability discovery methods.",
        "detection": (
            "VULNERABILITY DISCOVERY:\n"
            "AUTOMATED SCANNING:\n"
            "  - Network scanners (Nessus, OpenVAS, Qualys)\n"
            "  - Web scanners (Burp Suite, OWASP ZAP)\n"
            "  - Container scanners (Trivy, Grype)\n"
            "  - Infrastructure (Prowler, ScoutSuite)\n"
            "  - Code analysis (Semgrep, CodeQL)\n"
            "  - Dependency scanning (Snyk, Dependabot)\n"
            "MANUAL TESTING:\n"
            "  - Penetration testing\n"
            "  - Code review\n"
            "  - Architecture review\n"
            "  - Threat modeling\n"
            "  - Red team exercises\n"
            "CONTINUOUS:\n"
            "  - CI/CD pipeline scanning\n"
            "  - Runtime monitoring (RASP)\n"
            "  - Bug bounty programs\n"
            "  - Threat intelligence feeds\n"
            "  - CVE monitoring\n"
            "CLASSIFICATION:\n"
            "  - CWE (Common Weakness Enumeration)\n"
            "  - CVE (Common Vulnerabilities)\n"
            "  - CPE (Common Platform Enumeration)\n"
            "  - OWASP categorization\n"
            "  - MITRE ATT&CK mapping\n"
            "TOOLS:\n"
            "  Nessus, OpenVAS, Trivy, Semgrep, Snyk"
        ),
        "tools": ["nuclei", "trivy"],
    },
    {
        "id": "vm-002", "name": "CVSS Scoring and Prioritization",
        "category": "scoring", "severity": "high",
        "desc": "Vulnerability scoring and prioritization.",
        "detection": (
            "CVSS SCORING:\n"
            "CVSS v3.1 METRICS:\n"
            "  BASE:\n"
            "    Attack Vector: Network/Adjacent/Local/Physical\n"
            "    Attack Complexity: Low/High\n"
            "    Privileges Required: None/Low/High\n"
            "    User Interaction: None/Required\n"
            "    Scope: Unchanged/Changed\n"
            "    CIA Impact: None/Low/High\n"
            "  TEMPORAL:\n"
            "    Exploit Code Maturity\n"
            "    Remediation Level\n"
            "    Report Confidence\n"
            "  ENVIRONMENTAL:\n"
            "    Modified base metrics\n"
            "    CIA Requirements\n"
            "SEVERITY RANGES:\n"
            "  Critical: 9.0-10.0\n"
            "  High: 7.0-8.9\n"
            "  Medium: 4.0-6.9\n"
            "  Low: 0.1-3.9\n"
            "  None: 0.0\n"
            "PRIORITIZATION FACTORS:\n"
            "  - CVSS score\n"
            "  - Exploit availability (EPSS score)\n"
            "  - Asset criticality\n"
            "  - Business context\n"
            "  - Compensating controls\n"
            "  - Threat intelligence\n"
            "  - CISA KEV catalog\n"
            "EPSS (Exploit Prediction):\n"
            "  - Probability of exploitation in 30 days\n"
            "  - Combined with CVSS for prioritization\n"
            "TOOLS:\n"
            "  CVSS Calculator, EPSS API, CISA KEV"
        ),
        "tools": [],
    },
    {
        "id": "vm-003", "name": "Remediation Strategies",
        "category": "remediation", "severity": "high",
        "desc": "Vulnerability remediation approaches.",
        "detection": (
            "REMEDIATION STRATEGIES:\n"
            "PATCHING:\n"
            "  - Apply vendor patches\n"
            "  - Emergency/out-of-band patches\n"
            "  - Testing before deployment\n"
            "  - Staged rollout\n"
            "  - Rollback plan\n"
            "WORKAROUNDS:\n"
            "  - Configuration changes\n"
            "  - Feature disabling\n"
            "  - Network segmentation\n"
            "  - WAF rules\n"
            "  - Virtual patching\n"
            "CODE FIXES:\n"
            "  - Input validation\n"
            "  - Output encoding\n"
            "  - Parameterized queries\n"
            "  - Authentication strengthening\n"
            "  - Crypto library updates\n"
            "COMPENSATING CONTROLS:\n"
            "  - IDS/IPS rules\n"
            "  - Network ACLs\n"
            "  - Application firewalls\n"
            "  - Monitoring/alerting\n"
            "  - Access restrictions\n"
            "SLA TARGETS:\n"
            "  Critical: 24 hours\n"
            "  High: 7 days\n"
            "  Medium: 30 days\n"
            "  Low: 90 days\n"
            "  Informational: next cycle\n"
            "RISK ACCEPTANCE:\n"
            "  - Documented decision\n"
            "  - Business justification\n"
            "  - Compensating controls noted\n"
            "  - Review date set"
        ),
        "tools": [],
    },
    {
        "id": "vm-004", "name": "Patch Management",
        "category": "patching", "severity": "high",
        "desc": "Patch management process.",
        "detection": (
            "PATCH MANAGEMENT:\n"
            "PROCESS:\n"
            "  1. Inventory (know your assets)\n"
            "  2. Monitor (vendor advisories)\n"
            "  3. Assess (relevance, urgency)\n"
            "  4. Test (staging environment)\n"
            "  5. Deploy (staged rollout)\n"
            "  6. Verify (scan post-patch)\n"
            "  7. Report (compliance status)\n"
            "AUTOMATION:\n"
            "  - WSUS (Windows Server Update Services)\n"
            "  - SCCM/Intune (Microsoft)\n"
            "  - Ansible/Puppet/Chef\n"
            "  - Unattended-Upgrades (Linux)\n"
            "  - Container image rebuilds\n"
            "  - Dependabot/Renovate (dependencies)\n"
            "CHALLENGES:\n"
            "  - Legacy systems\n"
            "  - Air-gapped networks\n"
            "  - Compliance requirements\n"
            "  - Change management windows\n"
            "  - Testing resources\n"
            "  - Rollback complexity\n"
            "ZERO-DAY RESPONSE:\n"
            "  - Emergency patch process\n"
            "  - WAF virtual patching\n"
            "  - Threat hunting for exploitation\n"
            "  - Vendor coordination\n"
            "TOOLS:\n"
            "  WSUS, Ansible, Renovate, Dependabot"
        ),
        "tools": [],
    },
    {
        "id": "vm-005", "name": "Vulnerability Tracking and Metrics",
        "category": "tracking", "severity": "medium",
        "desc": "Vulnerability tracking and KPIs.",
        "detection": (
            "VULNERABILITY TRACKING & METRICS:\n"
            "KEY METRICS:\n"
            "  - Mean Time to Detect (MTTD)\n"
            "  - Mean Time to Remediate (MTTR)\n"
            "  - Open vulnerability count\n"
            "  - Overdue vulnerabilities\n"
            "  - SLA compliance rate\n"
            "  - Scan coverage percentage\n"
            "  - False positive rate\n"
            "  - Reopen rate\n"
            "DASHBOARDS:\n"
            "  - Vulnerability by severity\n"
            "  - Vulnerability by asset group\n"
            "  - Aging report\n"
            "  - Trend analysis\n"
            "  - SLA compliance\n"
            "  - Top vulnerable assets\n"
            "  - Remediation velocity\n"
            "TRACKING PLATFORMS:\n"
            "  - Jira (custom workflows)\n"
            "  - DefectDojo (vuln management)\n"
            "  - Faraday (collaboration)\n"
            "  - ThreadFix (aggregation)\n"
            "  - ArcherySec (open-source)\n"
            "COMPLIANCE REPORTING:\n"
            "  - PCI DSS (quarterly scans)\n"
            "  - SOC 2 (continuous monitoring)\n"
            "  - ISO 27001 (risk assessment)\n"
            "  - NIST CSF (identify/protect)\n"
            "  - HIPAA (security rule)\n"
            "TOOLS:\n"
            "  DefectDojo, Faraday, ThreadFix"
        ),
        "tools": ["defectdojo"],
    },
]


class VulnManagementKB:
    """Vulnerability management knowledge base.

    Provides vulnerability management patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, VulnMgmtPattern] = {}
        self._log = logger.bind(component="vulnmgmt_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load vulnerability management patterns."""
        for data in VULNMGMT_PATTERNS:
            pattern = VulnMgmtPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[VulnMgmtPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_vulnmgmt_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build vulnerability management prompt."""
        lines = ["## Vulnerability Management\n"]
        count = 0
        for pattern in self._patterns.values():
            if categories and pattern.category.lower() not in [c.lower() for c in categories]:
                continue
            if count >= max_patterns:
                break
            lines.append(f"### {pattern.name} [{pattern.category.upper()}]")
            lines.append(pattern.detection_strategy)
            lines.append("")
            count += 1
        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        cat_counts: dict[str, int] = {}
        for p in self._patterns.values():
            cat_counts[p.category] = cat_counts.get(p.category, 0) + 1
        return {
            "patterns": len(self._patterns),
            "by_category": cat_counts,
        }
