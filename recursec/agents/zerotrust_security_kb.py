"""Zero Trust architecture security knowledge base.

Assessment patterns and techniques for:
- Identity verification at every layer
- Micro-segmentation evaluation
- Least privilege access analysis
- Continuous verification mechanisms
- Data protection in zero trust environments
- Network access control validation
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ZeroTrustAssessment:
    name: str = ""
    pillar: str = ""
    severity: str = "high"
    checks: list[str] = field(default_factory=list)
    weaknesses: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "pillar": self.pillar, "sev": self.severity}


ZEROTRUST_ASSESSMENTS: list[ZeroTrustAssessment] = [
    ZeroTrustAssessment(
        name="Identity Verification Gaps",
        pillar="identity",
        severity="critical",
        checks=[
            "MFA enforcement on all user and admin accounts",
            "Conditional access policies based on risk signals",
            "Service account authentication strength",
            "API authentication mechanism review",
            "Session management and token lifetime analysis",
            "Identity federation trust chain validation",
        ],
        weaknesses=[
            "SMS-based MFA (SIM swap vulnerable)",
            "Long-lived API tokens without rotation",
            "Service accounts with password authentication",
            "Missing conditional access for high-risk operations",
            "Federated identity with weak trust boundaries",
        ],
        tools=["prowler", "scoutsuite", "azuread-audit"],
    ),
    ZeroTrustAssessment(
        name="Network Micro-Segmentation",
        pillar="network",
        severity="high",
        checks=[
            "Network segmentation between workload tiers",
            "East-west traffic inspection and filtering",
            "Service mesh mTLS enforcement",
            "DNS-based service discovery security",
            "Network policy enforcement in Kubernetes",
            "VPN split tunnel configuration review",
        ],
        weaknesses=[
            "Flat network without segmentation",
            "Permissive firewall rules (allow all)",
            "Missing mTLS between microservices",
            "DNS poisoning in service discovery",
            "Overly permissive Kubernetes NetworkPolicies",
        ],
        tools=["nmap", "prowler", "kube-bench"],
    ),
    ZeroTrustAssessment(
        name="Least Privilege Access",
        pillar="access",
        severity="critical",
        checks=[
            "IAM policy review for overprivileged accounts",
            "Just-in-time access implementation",
            "Separation of duties enforcement",
            "Standing privilege elimination",
            "Access certification and recertification cycles",
            "Emergency access (break-glass) procedure review",
        ],
        weaknesses=[
            "Wildcard permissions (*, Admin*)",
            "Standing admin access without time limits",
            "Shared accounts or credentials",
            "Missing access reviews",
            "Orphaned accounts from departed employees",
        ],
        tools=["prowler", "scoutsuite", "iam-analyzer"],
    ),
    ZeroTrustAssessment(
        name="Data Protection Controls",
        pillar="data",
        severity="high",
        checks=[
            "Data classification and labeling",
            "Encryption at rest and in transit",
            "DLP policy enforcement",
            "Data access logging and monitoring",
            "Backup encryption and access controls",
            "Data residency and sovereignty compliance",
        ],
        weaknesses=[
            "Unencrypted data at rest in databases",
            "Missing TLS on internal service communication",
            "No DLP policies for sensitive data",
            "Insufficient data access logging",
            "Backup data not encrypted or poorly protected",
        ],
        tools=["prowler", "trivy", "scoutsuite"],
    ),
    ZeroTrustAssessment(
        name="Continuous Monitoring and Verification",
        pillar="monitoring",
        severity="high",
        checks=[
            "SIEM coverage of all critical systems",
            "Behavioral analytics (UEBA) deployment",
            "Automated threat detection rules",
            "Incident response automation",
            "Security posture continuous assessment",
            "Compliance monitoring automation",
        ],
        weaknesses=[
            "Gaps in log collection coverage",
            "Alert fatigue from high false positive rates",
            "Missing behavioral baselines",
            "Manual incident response processes",
            "Infrequent security assessments",
        ],
        tools=["splunk", "elastic", "wazuh"],
    ),
]

DOMAIN_META = {
    "domain": "zero_trust",
    "patterns": len(ZEROTRUST_ASSESSMENTS),
    "pillars": ["identity", "network", "access", "data", "monitoring"],
}


def build_zerotrust_kb_prompt() -> str:
    """Build LLM prompt with zero trust knowledge."""
    lines = ["## Zero Trust Architecture Assessment Knowledge"]
    for assess in ZEROTRUST_ASSESSMENTS:
        lines.append(f"\n### {assess.name} [{assess.pillar}]")
        lines.append("Checks:")
        for check in assess.checks[:3]:
            lines.append(f"  - {check}")
        lines.append("Common Weaknesses:")
        for w in assess.weaknesses[:3]:
            lines.append(f"  - {w}")
    return "\n".join(lines)
