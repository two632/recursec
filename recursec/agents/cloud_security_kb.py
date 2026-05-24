"""Cloud security knowledge base.

Deep knowledge about cloud security:
1. AWS security
2. Azure security
3. GCP security
4. Multi-cloud and cloud-native security
5. Serverless and container orchestration
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


CLOUD_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "cloud-001", "name": "AWS Security",
        "category": "aws", "severity": "critical",
        "desc": "AWS security assessment.",
        "detection": (
            "AWS SECURITY:\n"
            "IAM:\n"
            "  # Enumerate permissions\n"
            "  aws iam get-user\n"
            "  aws iam list-attached-user-policies --user-name USER\n"
            "  # Check for overprivileged roles\n"
            "  # AdministratorAccess policy\n"
            "  # Unused access keys\n"
            "  aws iam list-access-keys --user-name USER\n"
            "  # MFA not enabled\n"
            "  # Cross-account role trust\n"
            "S3:\n"
            "  # Public buckets\n"
            "  aws s3api get-bucket-acl --bucket BUCKET\n"
            "  aws s3api get-bucket-policy --bucket BUCKET\n"
            "  # Block public access settings\n"
            "  aws s3api get-public-access-block --bucket BUCKET\n"
            "  # Encryption at rest\n"
            "  # Versioning and logging\n"
            "EC2/VPC:\n"
            "  # Security groups (0.0.0.0/0 inbound)\n"
            "  # Public IPs on instances\n"
            "  # IMDS v1 (metadata service)\n"
            "  curl http://169.254.169.254/latest/meta-data/\n"
            "  # Enforce IMDSv2\n"
            "  # EBS encryption\n"
            "LAMBDA:\n"
            "  # Function policies\n"
            "  # Environment variables (secrets)\n"
            "  # Execution role permissions\n"
            "  # Layer security\n"
            "TOOLS:\n"
            "  ScoutSuite, Prowler, Pacu, CloudSploit"
        ),
        "tools": ["prowler", "pacu"],
    },
    {
        "id": "cloud-002", "name": "Azure Security",
        "category": "azure", "severity": "critical",
        "desc": "Azure security assessment.",
        "detection": (
            "AZURE SECURITY:\n"
            "ENTRA ID (Azure AD):\n"
            "  # Enumerate tenants\n"
            "  az account list\n"
            "  # List users and roles\n"
            "  az ad user list\n"
            "  az role assignment list\n"
            "  # Conditional Access policies\n"
            "  # App registrations (secret exposure)\n"
            "  # Service principals\n"
            "  # Legacy authentication\n"
            "STORAGE:\n"
            "  # Public blob containers\n"
            "  az storage container list --account-name NAME\n"
            "  # SAS token abuse\n"
            "  # Storage access keys rotation\n"
            "  # Encryption at rest (managed keys vs CMK)\n"
            "NETWORKING:\n"
            "  # NSG rules (Network Security Groups)\n"
            "  az network nsg list\n"
            "  # Public IPs\n"
            "  az network public-ip list\n"
            "  # VNet peering\n"
            "  # Azure Firewall / WAF\n"
            "KUBERNETES (AKS):\n"
            "  # Managed identity\n"
            "  # RBAC configuration\n"
            "  # Network policies\n"
            "  # Pod security policies\n"
            "TOOLS:\n"
            "  ScoutSuite, AzureHound, ROADtools, Stormspotter"
        ),
        "tools": ["scoutsuite"],
    },
    {
        "id": "cloud-003", "name": "GCP Security",
        "category": "gcp", "severity": "critical",
        "desc": "GCP security assessment.",
        "detection": (
            "GCP SECURITY:\n"
            "IAM:\n"
            "  # Project IAM\n"
            "  gcloud projects get-iam-policy PROJECT\n"
            "  # Service accounts\n"
            "  gcloud iam service-accounts list\n"
            "  # Key management\n"
            "  gcloud iam service-accounts keys list --iam-account=SA\n"
            "  # Overprivileged: Editor, Owner roles\n"
            "  # Workload Identity Federation\n"
            "STORAGE:\n"
            "  # Public GCS buckets\n"
            "  gsutil iam get gs://BUCKET\n"
            "  # allUsers or allAuthenticatedUsers\n"
            "  # Uniform bucket-level access\n"
            "  # Object versioning\n"
            "COMPUTE:\n"
            "  # Firewall rules\n"
            "  gcloud compute firewall-rules list\n"
            "  # Metadata server\n"
            "  curl http://metadata.google.internal/computeMetadata/v1/\n"
            "  # Service account on instance\n"
            "  # Disk encryption (CMEK)\n"
            "GKE:\n"
            "  # Cluster security posture\n"
            "  # Workload identity\n"
            "  # Shielded nodes\n"
            "  # Binary authorization\n"
            "  # Network policy\n"
            "TOOLS:\n"
            "  ScoutSuite, GCPBucketBrute, Cartography"
        ),
        "tools": ["scoutsuite"],
    },
    {
        "id": "cloud-004", "name": "Multi-Cloud Security",
        "category": "multi_cloud", "severity": "high",
        "desc": "Multi-cloud and cloud-native security.",
        "detection": (
            "MULTI-CLOUD SECURITY:\n"
            "COMMON MISCONFIGURATIONS:\n"
            "  - Public storage (S3/Blob/GCS)\n"
            "  - Overprivileged IAM roles\n"
            "  - Unencrypted data at rest\n"
            "  - Unencrypted data in transit\n"
            "  - Missing MFA on privileged accounts\n"
            "  - Unused access keys/credentials\n"
            "  - Default VPC/network settings\n"
            "  - Excessive firewall rules\n"
            "  - Missing logging/monitoring\n"
            "  - Metadata service exposure\n"
            "INFRASTRUCTURE AS CODE:\n"
            "  # Terraform security\n"
            "  tfsec .           # Static analysis\n"
            "  checkov -d .      # Policy-as-code\n"
            "  terrascan scan    # Compliance\n"
            "  # CloudFormation\n"
            "  cfn-lint template.yaml\n"
            "  cfn_nag_scan --input-path template.yaml\n"
            "CSPM:\n"
            "  - Cloud Security Posture Management\n"
            "  - Continuous compliance monitoring\n"
            "  - Drift detection\n"
            "  - Automated remediation\n"
            "TOOLS:\n"
            "  ScoutSuite, Prowler, Checkov, tfsec, Cartography"
        ),
        "tools": ["prowler", "checkov"],
    },
    {
        "id": "cloud-005", "name": "Serverless Security",
        "category": "serverless", "severity": "high",
        "desc": "Serverless and FaaS security.",
        "detection": (
            "SERVERLESS SECURITY:\n"
            "ATTACK SURFACE:\n"
            "  - Function event injection\n"
            "  - Over-permissive execution roles\n"
            "  - Secrets in environment variables\n"
            "  - Dependency vulnerabilities\n"
            "  - Function chaining abuse\n"
            "  - Event source manipulation\n"
            "  - Cold start timing attacks\n"
            "AWS LAMBDA:\n"
            "  - Execution role permissions\n"
            "  - Layer security (malicious layers)\n"
            "  - Resource policy (who can invoke)\n"
            "  - VPC configuration\n"
            "  - Environment variable encryption\n"
            "AZURE FUNCTIONS:\n"
            "  - Managed identity\n"
            "  - Function keys (shared secrets)\n"
            "  - CORS configuration\n"
            "  - Network restrictions\n"
            "API GATEWAY:\n"
            "  - Authentication (API keys, JWT, OAuth)\n"
            "  - Rate limiting\n"
            "  - WAF integration\n"
            "  - Request validation\n"
            "  - Logging configuration\n"
            "  - Stage variables (secrets)\n"
            "TESTING:\n"
            "  - Function input fuzzing\n"
            "  - IAM policy analysis\n"
            "  - Dependency scanning\n"
            "  - Event source review\n"
            "TOOLS:\n"
            "  SLS-Dev-Tools, Serverless-Goat, PurplePanda"
        ),
        "tools": [],
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
                severity=data.get("severity", "high"),
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
        lines = ["## Cloud Security\n"]
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
