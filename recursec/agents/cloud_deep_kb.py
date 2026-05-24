"""Cloud security deep-dive knowledge base.

Deep knowledge about cloud security:
1. AWS-specific attacks
2. Azure-specific attacks
3. GCP-specific attacks
4. Multi-cloud and shared responsibility
5. Serverless and container security
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
        "id": "cloud-001", "name": "AWS-Specific Attacks",
        "category": "aws", "severity": "critical",
        "desc": "AWS-specific attack techniques.",
        "detection": (
            "AWS ATTACKS:\n"
            "IAM:\n"
            "  # Enumerate IAM\n"
            "  aws iam list-users\n"
            "  aws iam list-roles\n"
            "  aws iam list-policies --scope Local\n"
            "  # Privilege escalation paths (20+ known)\n"
            "  # iam:CreatePolicyVersion (modify own policy)\n"
            "  # iam:AttachUserPolicy (attach admin)\n"
            "  # iam:PassRole + lambda:CreateFunction\n"
            "  # iam:PassRole + ec2:RunInstances\n"
            "  # sts:AssumeRole (cross-account)\n"
            "  # TOOLS: Pacu, PMAPPER\n"
            "S3:\n"
            "  # Public bucket enum\n"
            "  aws s3 ls s3://BUCKET --no-sign-request\n"
            "  # ACL misconfiguration\n"
            "  # Bucket policy issues\n"
            "  # Server-side request forgery → S3\n"
            "  # Object-level permissions\n"
            "EC2:\n"
            "  # Instance metadata (IMDS)\n"
            "  curl http://169.254.169.254/latest/meta-data/\n"
            "  # IMDSv1 → get credentials\n"
            "  curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE\n"
            "  # User data scripts (may contain secrets)\n"
            "  # Security group misconfiguration\n"
            "  # EBS snapshot public access\n"
            "LAMBDA:\n"
            "  - Function code extraction\n"
            "  - Environment variable secrets\n"
            "  - Execution role abuse\n"
            "  - Event injection\n"
            "  - Layer poisoning\n"
            "TOOLS:\n"
            "  Pacu, ScoutSuite, Prowler, enumerate-iam"
        ),
        "tools": ["pacu"],
    },
    {
        "id": "cloud-002", "name": "Azure-Specific Attacks",
        "category": "azure", "severity": "critical",
        "desc": "Azure-specific attack techniques.",
        "detection": (
            "AZURE ATTACKS:\n"
            "ENTRA ID (AAD):\n"
            "  # Enumerate via Graph API\n"
            "  # AzureHound (BloodHound for Azure)\n"
            "  # Application registration abuse\n"
            "  # Consent grant (illicit consent)\n"
            "  # Service principal secrets\n"
            "  # Managed Identity token theft\n"
            "  # PRT (Primary Refresh Token) abuse\n"
            "  # Device code phishing\n"
            "STORAGE:\n"
            "  - Blob container enumeration\n"
            "  - SAS token misconfiguration\n"
            "  - Overly permissive SAS tokens\n"
            "  - Shared key authorization\n"
            "  - Anonymous blob access\n"
            "COMPUTE:\n"
            "  # IMDS\n"
            "  curl -H Metadata:true 'http://169.254.169.254/metadata/instance?api-version=2021-02-01'\n"
            "  # Managed Identity token\n"
            "  curl -H Metadata:true 'http://169.254.169.254/metadata/identity/oauth2/token?resource=https://management.azure.com/&api-version=2018-02-01'\n"
            "  # VM extensions (CustomScript)\n"
            "  # Serial console access\n"
            "  # Run commands\n"
            "RBAC:\n"
            "  - Overly permissive roles\n"
            "  - Custom role abuse\n"
            "  - Subscription-level access\n"
            "  - Resource group boundaries\n"
            "TOOLS:\n"
            "  AzureHound, ROADrecon, MicroBurst, TokenTactics"
        ),
        "tools": [],
    },
    {
        "id": "cloud-003", "name": "GCP-Specific Attacks",
        "category": "gcp", "severity": "critical",
        "desc": "GCP-specific attack techniques.",
        "detection": (
            "GCP ATTACKS:\n"
            "IAM:\n"
            "  # List all permissions\n"
            "  gcloud projects get-iam-policy PROJECT\n"
            "  # Service account key abuse\n"
            "  # Service account impersonation\n"
            "  # Custom role escalation\n"
            "  # setIamPolicy privilege\n"
            "  # actAs privilege (deploy as SA)\n"
            "STORAGE:\n"
            "  # Bucket enumeration\n"
            "  gsutil ls gs://BUCKET\n"
            "  # Public bucket access\n"
            "  # Uniform/fine-grained ACLs\n"
            "  # Signed URL abuse\n"
            "COMPUTE:\n"
            "  # Metadata server\n"
            "  curl -H 'Metadata-Flavor:Google' http://metadata.google.internal/computeMetadata/v1/\n"
            "  # Service account token\n"
            "  curl -H 'Metadata-Flavor:Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token\n"
            "  # Startup script secrets\n"
            "  # Custom metadata\n"
            "  # Serial port output\n"
            "CLOUD FUNCTIONS:\n"
            "  - Source code access\n"
            "  - Environment variables\n"
            "  - Service account abuse\n"
            "  - Event injection\n"
            "GKE:\n"
            "  - Kubelet API\n"
            "  - RBAC misconfig\n"
            "  - Workload identity\n"
            "TOOLS:\n"
            "  GCPBucketBrute, ScoutSuite, Prowler"
        ),
        "tools": [],
    },
    {
        "id": "cloud-004", "name": "Multi-Cloud Security",
        "category": "multicloud", "severity": "high",
        "desc": "Multi-cloud and shared responsibility.",
        "detection": (
            "MULTI-CLOUD SECURITY:\n"
            "SHARED RESPONSIBILITY:\n"
            "  IaaS: Customer → OS, apps, data\n"
            "  PaaS: Customer → apps, data\n"
            "  SaaS: Customer → data, access\n"
            "  Provider → physical, network, hypervisor\n"
            "COMMON MISCONFIGS:\n"
            "  - Over-permissive IAM roles\n"
            "  - Public storage buckets/blobs\n"
            "  - Unencrypted data at rest\n"
            "  - Logging/monitoring disabled\n"
            "  - Default credentials\n"
            "  - Exposed management ports\n"
            "  - Missing MFA on admin accounts\n"
            "  - Unrestricted outbound access\n"
            "CROSS-CLOUD:\n"
            "  - Trust relationships between clouds\n"
            "  - Federated identity abuse\n"
            "  - Cross-cloud credential reuse\n"
            "  - VPN/peering misconfig\n"
            "  - DNS delegation issues\n"
            "TERRAFORM/IAC:\n"
            "  - Hardcoded secrets in state\n"
            "  - Overly permissive modules\n"
            "  - State file exposure (S3 backend)\n"
            "  - Drift detection missing\n"
            "  # tfsec (static analysis)\n"
            "  # checkov (multi-cloud policy)\n"
            "  # terrascan\n"
            "TOOLS:\n"
            "  ScoutSuite, Prowler, Checkov, tfsec"
        ),
        "tools": [],
    },
    {
        "id": "cloud-005", "name": "Serverless Security",
        "category": "serverless", "severity": "high",
        "desc": "Serverless and container security.",
        "detection": (
            "SERVERLESS & CONTAINER:\n"
            "LAMBDA/FUNCTIONS:\n"
            "  - Injection via event data\n"
            "  - Over-privileged execution role\n"
            "  - Environment variable secrets\n"
            "  - Cold start timing attacks\n"
            "  - Dependency confusion\n"
            "  - Layer poisoning\n"
            "  - Ephemeral /tmp data leaks\n"
            "API GATEWAY:\n"
            "  - Missing authentication\n"
            "  - WAF bypass\n"
            "  - Rate limiting absence\n"
            "  - Request validation missing\n"
            "  - CORS misconfiguration\n"
            "CONTAINER REGISTRY:\n"
            "  - Public image repositories\n"
            "  - Image tag mutability\n"
            "  - Missing vulnerability scanning\n"
            "  - No image signing\n"
            "  - Base image vulnerabilities\n"
            "CONTAINER RUNTIME:\n"
            "  - Privileged containers\n"
            "  - Host path mounts\n"
            "  - Docker socket exposed\n"
            "  - No resource limits\n"
            "  - Lack of seccomp/AppArmor\n"
            "SUPPLY CHAIN:\n"
            "  - Typosquatting packages\n"
            "  - Compromised base images\n"
            "  - CI/CD pipeline injection\n"
            "  - SBOM (Software Bill of Materials)\n"
            "TOOLS:\n"
            "  Trivy, Grype, Snyk, Falco"
        ),
        "tools": ["trivy"],
    },
]


class CloudDeepKB:
    """Cloud security deep-dive knowledge base.

    Provides cloud security patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, CloudPattern] = {}
        self._log = logger.bind(component="cloud_deep_kb")
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
