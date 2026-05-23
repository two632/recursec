"""Cloud security knowledge base.

Deep knowledge about cloud platform security:
1. AWS attack techniques
2. Azure attack techniques
3. GCP attack techniques
4. Multi-cloud misconfigurations
5. Cloud identity and access management
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class CloudPattern:
    """A cloud security pattern."""
    pattern_id: str = ""
    name: str = ""
    category: str = ""
    severity: str = "critical"
    description: str = ""
    detection_strategy: str = ""
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:25],
            "category": self.category[:12],
        }


CLOUD_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "cloud-001", "name": "AWS Attack Techniques",
        "category": "aws", "severity": "critical",
        "desc": "AWS-specific attack and misconfig patterns.",
        "detection": (
            "AWS ATTACK TECHNIQUES:\n"
            "CREDENTIAL DISCOVERY:\n"
            "  # Instance metadata (IMDS)\n"
            "  curl http://169.254.169.254/latest/meta-data/iam/security-credentials/\n"
            "  # IMDSv2 (requires token)\n"
            "  TOKEN=$(curl -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600' http://169.254.169.254/latest/api/token)\n"
            "  curl -H \"X-aws-ec2-metadata-token: $TOKEN\" http://169.254.169.254/latest/meta-data/\n"
            "  # Environment variables (Lambda)\n"
            "  # AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN\n"
            "S3 BUCKET:\n"
            "  aws s3 ls s3://bucket-name --no-sign-request  # Public bucket\n"
            "  # Bucket policies, ACLs, Block Public Access\n"
            "  # Object-level permissions vs bucket-level\n"
            "  # Presigned URL abuse\n"
            "IAM EXPLOITATION:\n"
            "  # Enumerate permissions\n"
            "  aws iam list-attached-user-policies --user-name <user>\n"
            "  aws iam get-policy-version --policy-arn <arn> --version-id v1\n"
            "  # Privilege escalation paths:\n"
            "  - iam:PassRole + lambda:CreateFunction → exec as any role\n"
            "  - iam:CreatePolicyVersion → escalate own permissions\n"
            "  - sts:AssumeRole → pivot to other roles\n"
            "  - ec2:RunInstances + iam:PassRole → instance with privileged role\n"
            "LAMBDA:\n"
            "  # Code injection via event data\n"
            "  # Environment variable exfiltration\n"
            "  # Layer poisoning\n"
            "  # Timeout/concurrency abuse\n"
            "TOOLS:\n"
            "  pacu  # AWS exploitation framework\n"
            "  prowler  # AWS security assessment\n"
            "  ScoutSuite  # Multi-cloud auditing\n"
            "  enumerate-iam  # IAM permission enumeration"
        ),
        "tools": ["pacu", "prowler", "scoutsuite"],
    },
    {
        "id": "cloud-002", "name": "Azure Attack Techniques",
        "category": "azure", "severity": "critical",
        "desc": "Azure-specific attack and misconfig patterns.",
        "detection": (
            "AZURE ATTACK TECHNIQUES:\n"
            "ENTRA ID (Azure AD):\n"
            "  # Enumerate users and groups\n"
            "  az ad user list\n"
            "  az ad group list\n"
            "  # Password spray\n"
            "  # Token theft from az cli profile (~/.azure/)\n"
            "  # Application consent phishing (illicit consent grant)\n"
            "MANAGED IDENTITY:\n"
            "  # Instance metadata\n"
            "  curl -H 'Metadata: true' http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/\n"
            "  # System-assigned and user-assigned\n"
            "  # Access tokens for Azure services\n"
            "STORAGE:\n"
            "  # Blob storage misconfigurations\n"
            "  # Public containers\n"
            "  # SAS token abuse (overly permissive)\n"
            "  # Storage account key exposure\n"
            "RBAC:\n"
            "  # Overly permissive custom roles\n"
            "  # Contributor → can reset admin passwords\n"
            "  # User Access Administrator → assign any role\n"
            "  # Classic admins (legacy)\n"
            "RESOURCE MANAGER:\n"
            "  # ARM template injection\n"
            "  # Deployment history (may contain secrets)\n"
            "  az deployment group list -g <resource-group>\n"
            "  # Key Vault access policies\n"
            "TOOLS:\n"
            "  ROADtools  # Azure AD enumeration\n"
            "  AADInternals  # Azure AD exploitation\n"
            "  MicroBurst  # Azure enumeration\n"
            "  AzureHound  # BloodHound for Azure"
        ),
        "tools": ["roadtools", "azurehound", "scoutsuite"],
    },
    {
        "id": "cloud-003", "name": "GCP Attack Techniques",
        "category": "gcp", "severity": "critical",
        "desc": "GCP-specific attack and misconfig patterns.",
        "detection": (
            "GCP ATTACK TECHNIQUES:\n"
            "METADATA:\n"
            "  # Instance metadata\n"
            "  curl -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/\n"
            "  # Service account token\n"
            "  curl -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token\n"
            "  # Project metadata, SSH keys\n"
            "STORAGE:\n"
            "  # Public GCS buckets\n"
            "  gsutil ls gs://bucket-name\n"
            "  # Uniform vs fine-grained ACLs\n"
            "  # Signed URLs\n"
            "IAM:\n"
            "  # Overly permissive bindings\n"
            "  gcloud projects get-iam-policy <project>\n"
            "  # Service account key leaks\n"
            "  # Workload identity federation\n"
            "  # Cross-project access\n"
            "  # Custom roles with dangerous perms\n"
            "COMPUTE:\n"
            "  # Startup script injection\n"
            "  # Serial console access\n"
            "  # oslogin SSH key injection\n"
            "  # Snapshot/disk export\n"
            "CLOUD FUNCTIONS:\n"
            "  # Code injection\n"
            "  # Environment variable exfiltration\n"
            "  # Pub/Sub message poisoning\n"
            "TOOLS:\n"
            "  ScoutSuite  # Multi-cloud auditing\n"
            "  gcp_enum  # GCP enumeration\n"
            "  Cartography  # Infrastructure mapping"
        ),
        "tools": ["scoutsuite", "cartography"],
    },
    {
        "id": "cloud-004", "name": "Multi-Cloud Misconfigurations",
        "category": "misconfig", "severity": "high",
        "desc": "Common cloud misconfigurations across providers.",
        "detection": (
            "MULTI-CLOUD MISCONFIGURATIONS:\n"
            "STORAGE:\n"
            "  - Public buckets/blobs/objects\n"
            "  - Overly permissive ACLs\n"
            "  - Unencrypted data at rest\n"
            "  - No versioning (ransomware risk)\n"
            "  - Cross-account access\n"
            "NETWORKING:\n"
            "  - Security groups with 0.0.0.0/0 ingress\n"
            "  - No network segmentation (flat VPC)\n"
            "  - Publicly exposed management ports (22, 3389)\n"
            "  - Missing VPC flow logs\n"
            "  - DNS zone transfer enabled\n"
            "COMPUTE:\n"
            "  - Instance metadata v1 (no hop limit)\n"
            "  - Overprivileged instance roles\n"
            "  - Unpatched AMIs/images\n"
            "  - User data scripts with secrets\n"
            "  - Missing disk encryption\n"
            "IDENTITY:\n"
            "  - Long-lived access keys\n"
            "  - No MFA enforcement\n"
            "  - Overprivileged service accounts\n"
            "  - Cross-account trust abuse\n"
            "  - Inactive/orphaned accounts\n"
            "LOGGING:\n"
            "  - CloudTrail/Activity Log disabled\n"
            "  - No log monitoring/alerting\n"
            "  - Log tampering (delete trail)\n"
            "  - Missing S3 access logging\n"
            "TOOLS:\n"
            "  prowler  # AWS security\n"
            "  ScoutSuite  # Multi-cloud\n"
            "  cloudsploit  # Multi-cloud\n"
            "  checkov  # IaC scanning"
        ),
        "tools": ["prowler", "scoutsuite", "checkov"],
    },
    {
        "id": "cloud-005", "name": "Cloud IAM Attacks",
        "category": "iam", "severity": "critical",
        "desc": "Cloud identity and access management attacks.",
        "detection": (
            "CLOUD IAM ATTACKS:\n"
            "CREDENTIAL THEFT:\n"
            "  - Exposed access keys in code repos\n"
            "  - Environment variables in CI/CD\n"
            "  - Instance metadata SSRF\n"
            "  - Stolen browser tokens (Azure/GCP portal)\n"
            "  - Container credential exposure\n"
            "PRIVILEGE ESCALATION:\n"
            "  - Self-service policy modification\n"
            "  - Role chaining (assume → assume → assume)\n"
            "  - Service account impersonation\n"
            "  - Resource policy modification\n"
            "  - Cross-service privilege escalation\n"
            "PERSISTENCE:\n"
            "  - Create additional access keys\n"
            "  - Create new IAM user/service account\n"
            "  - Modify trust policies\n"
            "  - Add SSH keys to instances\n"
            "  - Create OAuth applications\n"
            "LATERAL MOVEMENT:\n"
            "  - Cross-account role assumption\n"
            "  - Service account key usage\n"
            "  - Shared VPC/VNet access\n"
            "  - Database IAM authentication\n"
            "DETECTION EVASION:\n"
            "  - Use legitimate service accounts\n"
            "  - API calls through VPC endpoints\n"
            "  - CloudTrail bypass (data events)\n"
            "  - Regions without logging\n"
            "TOOLS:\n"
            "  cloudfox  # Cloud attack surface\n"
            "  PMapper  # IAM privilege escalation\n"
            "  Rhino Security Labs tools"
        ),
        "tools": ["cloudfox", "pmapper"],
    },
]


class CloudSecurityKB:
    """Cloud security knowledge base.

    Provides cloud security patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, CloudPattern] = {}
        self._log = logger.bind(component="cloud_security_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load cloud patterns."""
        for data in CLOUD_PATTERNS:
            pattern = CloudPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "critical"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[CloudPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_cloud_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build cloud security prompt."""
        lines = ["## Cloud Security Patterns\n"]
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
