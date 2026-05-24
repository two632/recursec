"""Cloud-native security knowledge base.

Deep knowledge about cloud-native security:
1. Serverless security
2. Service mesh security
3. Cloud storage security
4. Cloud IAM assessment
5. Cloud logging and monitoring
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class CloudNativePattern:
    """A cloud-native security pattern."""
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


CLOUD_NATIVE_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "cn-001", "name": "Serverless Security",
        "category": "serverless", "severity": "high",
        "desc": "Serverless function security.",
        "detection": (
            "SERVERLESS SECURITY:\n"
            "AWS LAMBDA:\n"
            "  - Function policy review\n"
            "    # aws lambda get-policy --function-name F\n"
            "  - Environment variable secrets\n"
            "    # aws lambda get-function-configuration\n"
            "  - Layer vulnerabilities\n"
            "  - Event injection\n"
            "    # API Gateway → Lambda\n"
            "    # S3 event → Lambda\n"
            "    # SNS/SQS → Lambda\n"
            "  - Execution role over-privilege\n"
            "  - Cold start timing attacks\n"
            "  - /tmp persistence between invocations\n"
            "  - VPC configuration\n"
            "AZURE FUNCTIONS:\n"
            "  - Managed Identity scope\n"
            "  - Host key exposure\n"
            "  - Function app settings\n"
            "  - Binding injection\n"
            "GCP CLOUD FUNCTIONS:\n"
            "  - Service account permissions\n"
            "  - Trigger permissions\n"
            "  - Environment secrets\n"
            "GENERAL:\n"
            "  - Dependency vulnerabilities\n"
            "  - Timeout/memory abuse\n"
            "  - Financial DoS (billionaire attack)\n"
            "  - SSRF from function\n"
            "TOOLS:\n"
            "  SLS-Scanner, Prowler, ScoutSuite"
        ),
        "tools": [],
    },
    {
        "id": "cn-002", "name": "Service Mesh Security",
        "category": "mesh", "severity": "medium",
        "desc": "Service mesh security assessment.",
        "detection": (
            "SERVICE MESH SECURITY:\n"
            "ISTIO:\n"
            "  - mTLS enforcement\n"
            "    # PeerAuthentication policies\n"
            "    # PERMISSIVE vs STRICT mode\n"
            "  - Authorization policies\n"
            "    # AuthorizationPolicy resources\n"
            "    # Default deny enforcement\n"
            "  - Sidecar injection\n"
            "    # Bypassed pods (no sidecar)\n"
            "  - Istiod compromise\n"
            "    # Control plane security\n"
            "  - Gateway configuration\n"
            "  - VirtualService routing\n"
            "LINKERD:\n"
            "  - Identity verification\n"
            "  - Traffic policies\n"
            "  - Control plane security\n"
            "CONSUL:\n"
            "  - Service intentions\n"
            "  - ACL enforcement\n"
            "  - Gossip encryption\n"
            "GENERAL:\n"
            "  - East-west traffic inspection\n"
            "  - Service-to-service auth\n"
            "  - Certificate rotation\n"
            "  - Observability data exposure\n"
            "  - Canary deployment abuse\n"
            "TOOLS:\n"
            "  istioctl, linkerd check, consul validate"
        ),
        "tools": [],
    },
    {
        "id": "cn-003", "name": "Cloud Storage Security",
        "category": "storage", "severity": "critical",
        "desc": "Cloud storage misconfiguration.",
        "detection": (
            "CLOUD STORAGE SECURITY:\n"
            "AWS S3:\n"
            "  - Public bucket detection\n"
            "    # aws s3 ls s3://BUCKET --no-sign-request\n"
            "    # Check bucket policy\n"
            "    # Check ACL\n"
            "  - Bucket policy analysis\n"
            "    # aws s3api get-bucket-policy\n"
            "    # Principal: '*' = public\n"
            "  - Encryption verification\n"
            "    # aws s3api get-bucket-encryption\n"
            "  - Versioning check\n"
            "  - Access logging\n"
            "  - Cross-account access\n"
            "  - Pre-signed URL abuse\n"
            "AZURE BLOB:\n"
            "  - Public container listing\n"
            "  - SAS token scope/expiry\n"
            "  - Shared Key authorization\n"
            "  - Immutability policies\n"
            "GCP CLOUD STORAGE:\n"
            "  - Uniform vs fine-grained ACL\n"
            "  - allUsers / allAuthenticatedUsers\n"
            "  - Signed URL abuse\n"
            "  - Retention policies\n"
            "TOOLS:\n"
            "  S3Scanner, cloud_enum, BucketFinder"
        ),
        "tools": [],
    },
    {
        "id": "cn-004", "name": "Cloud IAM Assessment",
        "category": "iam", "severity": "critical",
        "desc": "Cloud IAM security assessment.",
        "detection": (
            "CLOUD IAM ASSESSMENT:\n"
            "AWS IAM:\n"
            "  - Policy analysis\n"
            "    # aws iam list-policies --only-attached\n"
            "    # Check for Action: '*'\n"
            "    # Check for Resource: '*'\n"
            "  - Cross-account roles\n"
            "    # Trust policy analysis\n"
            "    # External ID requirement\n"
            "  - Access key age/rotation\n"
            "    # aws iam list-access-keys\n"
            "  - MFA enforcement\n"
            "  - Password policy\n"
            "  - Permission boundaries\n"
            "  - Service control policies (SCP)\n"
            "  - Organizations trail\n"
            "AZURE AD:\n"
            "  - App registrations\n"
            "  - Enterprise applications\n"
            "  - Conditional access policies\n"
            "  - PIM (Privileged Identity Mgmt)\n"
            "  - Role assignments\n"
            "  - Guest users\n"
            "GCP:\n"
            "  - IAM policy bindings\n"
            "  - Service account keys\n"
            "  - Org policy constraints\n"
            "  - Custom roles\n"
            "  - Domain-wide delegation\n"
            "TOOLS:\n"
            "  Prowler, ScoutSuite, CloudSploit, PMapper"
        ),
        "tools": [],
    },
    {
        "id": "cn-005", "name": "Cloud Logging and Monitoring",
        "category": "logging", "severity": "medium",
        "desc": "Cloud logging and monitoring gaps.",
        "detection": (
            "CLOUD LOGGING & MONITORING:\n"
            "AWS:\n"
            "  - CloudTrail enabled\n"
            "    # aws cloudtrail describe-trails\n"
            "    # Multi-region trail\n"
            "    # S3 data events\n"
            "    # Lambda data events\n"
            "  - CloudWatch alarms\n"
            "    # Root account usage\n"
            "    # Unauthorized API calls\n"
            "    # Console login without MFA\n"
            "    # IAM policy changes\n"
            "  - VPC Flow Logs\n"
            "    # All VPCs covered\n"
            "  - S3 access logging\n"
            "  - GuardDuty enabled\n"
            "  - Config enabled\n"
            "AZURE:\n"
            "  - Activity Log\n"
            "  - Diagnostic settings\n"
            "  - Azure Monitor\n"
            "  - Microsoft Sentinel\n"
            "  - Network Watcher\n"
            "GCP:\n"
            "  - Cloud Audit Logs\n"
            "  - Cloud Logging\n"
            "  - Data Access logs\n"
            "  - VPC Flow Logs\n"
            "  - Security Command Center\n"
            "GAPS:\n"
            "  - Log retention too short\n"
            "  - No alerting on critical events\n"
            "  - Disabled data event logging\n"
            "  - No centralized SIEM\n"
            "TOOLS:\n"
            "  Prowler, ScoutSuite, CloudSploit"
        ),
        "tools": [],
    },
]


class CloudNativeKB:
    """Cloud-native security knowledge base.

    Provides cloud-native patterns injected
    into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, CloudNativePattern] = {}
        self._log = logger.bind(component="cloud_native_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load cloud-native patterns."""
        for data in CLOUD_NATIVE_PATTERNS:
            pattern = CloudNativePattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[CloudNativePattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_cloud_native_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build cloud-native prompt."""
        lines = ["## Cloud-Native Security\n"]
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
