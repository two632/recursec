"""Cloud security knowledge base.

Deep knowledge about cloud infrastructure security:
1. AWS security testing
2. Azure security testing
3. GCP security testing
4. Kubernetes/container security
5. Serverless security
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class CloudVulnPattern:
    """A cloud vulnerability pattern."""
    pattern_id: str = ""
    name: str = ""
    provider: str = ""           # aws, azure, gcp, kubernetes, serverless
    severity: str = "high"
    description: str = ""
    testing_methodology: str = ""
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:30],
            "provider": self.provider[:10],
        }


CLOUD_VULN_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "cloud-001", "name": "AWS Security Assessment",
        "provider": "aws", "severity": "critical",
        "desc": "AWS cloud infrastructure security testing.",
        "testing": (
            "AWS SECURITY ASSESSMENT:\n"
            "1. IAM REVIEW:\n"
            "   - Enumerate users, roles, policies:\n"
            "     aws iam list-users\n"
            "     aws iam list-roles\n"
            "     aws iam list-policies --scope Local\n"
            "   - Check for overprivileged policies:\n"
            "     * Action: '*' (admin access)\n"
            "     * Resource: '*' (all resources)\n"
            "   - Check MFA enforcement:\n"
            "     aws iam get-credential-report\n"
            "   - Access key age (rotate if >90 days):\n"
            "     aws iam list-access-keys --user-name {user}\n"
            "   - Unused roles and policies\n"
            "   - Cross-account trust:\n"
            "     aws iam get-role --role-name {role} → check AssumeRolePolicyDocument\n"
            "2. S3 BUCKET SECURITY:\n"
            "   - List all buckets: aws s3 ls\n"
            "   - Check public access:\n"
            "     aws s3api get-bucket-acl --bucket {name}\n"
            "     aws s3api get-bucket-policy --bucket {name}\n"
            "     aws s3api get-public-access-block --bucket {name}\n"
            "   - Check encryption:\n"
            "     aws s3api get-bucket-encryption --bucket {name}\n"
            "   - Check versioning: aws s3api get-bucket-versioning --bucket {name}\n"
            "   - Test: curl https://{bucket}.s3.amazonaws.com/ (directory listing?)\n"
            "3. EC2/NETWORK:\n"
            "   - Security groups: aws ec2 describe-security-groups\n"
            "   - Check 0.0.0.0/0 inbound rules\n"
            "   - IMDSv1 vs IMDSv2 (SSRF risk):\n"
            "     curl http://169.254.169.254/latest/meta-data/ (v1, no token)\n"
            "   - VPC flow logs enabled?\n"
            "4. SECRETS:\n"
            "   - Lambda environment variables: aws lambda get-function-configuration\n"
            "   - SSM Parameter Store: aws ssm describe-parameters\n"
            "   - Secrets Manager: aws secretsmanager list-secrets\n"
            "5. TOOLS:\n"
            "   - ScoutSuite: Multi-cloud security auditing\n"
            "   - Prowler: AWS security best practices\n"
            "   - CloudSploit: Cloud security scanning\n"
            "   - Pacu: AWS exploitation framework"
        ),
        "tools": ["ScoutSuite", "Prowler", "Pacu", "CloudSploit"],
    },
    {
        "id": "cloud-002", "name": "Azure Security Assessment",
        "provider": "azure", "severity": "critical",
        "desc": "Azure cloud infrastructure security testing.",
        "testing": (
            "AZURE SECURITY ASSESSMENT:\n"
            "1. ENTRA ID (formerly Azure AD):\n"
            "   - Enumerate users and groups:\n"
            "     az ad user list\n"
            "     az ad group list\n"
            "   - Check app registrations:\n"
            "     az ad app list\n"
            "   - Service principal permissions\n"
            "   - Conditional Access policies review\n"
            "   - Guest user enumeration\n"
            "   - Consent grant analysis\n"
            "2. STORAGE:\n"
            "   - List storage accounts:\n"
            "     az storage account list\n"
            "   - Check public access:\n"
            "     az storage account show --name {name} → allowBlobPublicAccess\n"
            "   - SAS token analysis (expiry, permissions, IP restrictions)\n"
            "   - Encryption settings\n"
            "3. NETWORK:\n"
            "   - NSG rules: az network nsg list\n"
            "   - Check for 0.0.0.0/0 inbound rules\n"
            "   - VNet peering review\n"
            "   - Azure Firewall / WAF configuration\n"
            "4. RESOURCE MANAGER:\n"
            "   - Role assignments:\n"
            "     az role assignment list\n"
            "   - Custom role definitions\n"
            "   - Resource locks\n"
            "   - Policy compliance: az policy state list\n"
            "5. TOOLS:\n"
            "   - ScoutSuite: Multi-cloud security auditing\n"
            "   - Azucar: Azure security scanner\n"
            "   - PowerZure: Azure exploitation\n"
            "   - ROADtools: Azure AD analysis"
        ),
        "tools": ["ScoutSuite", "Azucar", "PowerZure", "ROADtools"],
    },
    {
        "id": "cloud-003", "name": "GCP Security Assessment",
        "provider": "gcp", "severity": "critical",
        "desc": "Google Cloud Platform security testing.",
        "testing": (
            "GCP SECURITY ASSESSMENT:\n"
            "1. IAM:\n"
            "   - List IAM policies:\n"
            "     gcloud projects get-iam-policy {project}\n"
            "   - Check for overprivileged accounts:\n"
            "     * roles/owner, roles/editor on project level\n"
            "   - Service account keys:\n"
            "     gcloud iam service-accounts keys list --iam-account {sa}\n"
            "   - Workload Identity Federation review\n"
            "2. STORAGE:\n"
            "   - List buckets: gsutil ls\n"
            "   - Check public access:\n"
            "     gsutil iam get gs://{bucket}\n"
            "   - Uniform bucket-level access\n"
            "   - Signed URL analysis\n"
            "3. COMPUTE/NETWORK:\n"
            "   - Firewall rules:\n"
            "     gcloud compute firewall-rules list\n"
            "   - Check 0.0.0.0/0 source ranges\n"
            "   - Metadata server:\n"
            "     curl http://metadata.google.internal/computeMetadata/v1/\n"
            "     (requires Metadata-Flavor: Google header)\n"
            "   - OS Login vs SSH keys\n"
            "4. SECRETS:\n"
            "   - Secret Manager: gcloud secrets list\n"
            "   - Datastore/Firestore for sensitive data\n"
            "   - Cloud Functions environment variables\n"
            "5. TOOLS:\n"
            "   - ScoutSuite: Multi-cloud\n"
            "   - GCPBucketBrute: GCS bucket enumeration\n"
            "   - Hayat: GCP security scanner"
        ),
        "tools": ["ScoutSuite", "GCPBucketBrute", "gcloud CLI"],
    },
    {
        "id": "cloud-004", "name": "Kubernetes Security",
        "provider": "kubernetes", "severity": "critical",
        "desc": "Kubernetes and container orchestration security.",
        "testing": (
            "KUBERNETES SECURITY:\n"
            "1. CLUSTER CONFIGURATION:\n"
            "   - API server access:\n"
            "     kubectl cluster-info\n"
            "     kubectl auth can-i --list (current user permissions)\n"
            "   - Anonymous access:\n"
            "     curl -k https://{api-server}:6443/api/v1/namespaces\n"
            "   - RBAC review:\n"
            "     kubectl get clusterroles,clusterrolebindings\n"
            "     kubectl get roles,rolebindings -A\n"
            "   - Pod Security Standards (PSS) enforcement\n"
            "2. CONTAINER SECURITY:\n"
            "   - Privileged containers:\n"
            "     kubectl get pods -A -o json | jq '.items[] | select(.spec.containers[].securityContext.privileged==true)'\n"
            "   - Host path mounts:\n"
            "     Check for hostPath volumes (/ or /etc)\n"
            "   - Root containers:\n"
            "     runAsUser: 0 or not set\n"
            "   - Image scanning:\n"
            "     trivy image {image}:latest\n"
            "     grype {image}:latest\n"
            "3. NETWORK POLICIES:\n"
            "   - Check if NetworkPolicies exist:\n"
            "     kubectl get networkpolicies -A\n"
            "   - Default deny ingress/egress\n"
            "   - Pod-to-pod communication restrictions\n"
            "4. SECRETS:\n"
            "   - Enumerate secrets:\n"
            "     kubectl get secrets -A\n"
            "   - Secrets stored as base64 (not encrypted at rest by default)\n"
            "   - Service account token automount\n"
            "   - etcd encryption at rest\n"
            "5. ESCAPE TECHNIQUES:\n"
            "   - Container escape via privileged mode\n"
            "   - cgroups escape\n"
            "   - Mount host filesystem\n"
            "   - Service account token → API server\n"
            "   - Cloud metadata from pod\n"
            "6. TOOLS:\n"
            "   - kube-bench: CIS Kubernetes Benchmark\n"
            "   - kubeaudit: Kubernetes security auditing\n"
            "   - kube-hunter: Kubernetes penetration testing\n"
            "   - Falco: Runtime security monitoring"
        ),
        "tools": ["kube-bench", "kubeaudit", "kube-hunter", "trivy", "Falco"],
    },
    {
        "id": "cloud-005", "name": "Serverless Security",
        "provider": "serverless", "severity": "high",
        "desc": "Serverless function and API security.",
        "testing": (
            "SERVERLESS SECURITY:\n"
            "1. FUNCTION CONFIGURATION:\n"
            "   - Overprivileged execution roles\n"
            "   - Environment variable secrets (plaintext)\n"
            "   - Timeout and memory limits (DoS potential)\n"
            "   - VPC configuration (can function reach internal resources?)\n"
            "   - Cold start timing attacks\n"
            "2. EVENT INJECTION:\n"
            "   - API Gateway: SQL injection, XSS in query/headers\n"
            "   - S3 event trigger: Malicious filename injection\n"
            "   - SQS/SNS: Message body injection\n"
            "   - DynamoDB Streams: Data manipulation\n"
            "   - CloudWatch Events: Cron expression injection\n"
            "3. DEPENDENCY ATTACKS:\n"
            "   - Vulnerable dependencies in Lambda layers\n"
            "   - Dependency confusion attacks\n"
            "   - Supply chain compromise of Lambda packages\n"
            "4. DATA EXPOSURE:\n"
            "   - CloudWatch Logs: Sensitive data in function logs\n"
            "   - /tmp directory persistence between invocations\n"
            "   - Return value exposure\n"
            "5. TOOLS:\n"
            "   - SLS-Dev-Tools: Serverless debugging\n"
            "   - Serverless-Goat: Vulnerable serverless app\n"
            "   - PureSec: Serverless security"
        ),
        "tools": ["SLS-Dev-Tools", "ScoutSuite"],
    },
]


class CloudSecurityKB:
    """Cloud security knowledge base.

    Provides cloud-specific security testing methodology
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, CloudVulnPattern] = {}
        self._log = logger.bind(component="cloud_security_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load cloud vulnerability patterns."""
        for data in CLOUD_VULN_PATTERNS:
            pattern = CloudVulnPattern(
                pattern_id=data["id"],
                name=data["name"],
                provider=data.get("provider", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                testing_methodology=data.get("testing", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_patterns_for_provider(
        self,
        provider: str,
    ) -> list[CloudVulnPattern]:
        """Get patterns by provider."""
        return [
            p for p in self._patterns.values()
            if p.provider == provider
        ]

    def build_cloud_prompt(
        self,
        providers: list[str] | None = None,
        max_patterns: int = 3,
    ) -> str:
        """Build cloud security prompt."""
        lines = ["## Cloud Security Testing\n"]
        count = 0
        for pattern in self._patterns.values():
            if providers and pattern.provider not in providers:
                continue
            if count >= max_patterns:
                break
            lines.append(f"### {pattern.name} [{pattern.severity.upper()}]")
            lines.append(pattern.testing_methodology)
            lines.append("")
            count += 1
        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        prov_counts: dict[str, int] = defaultdict(int)
        for p in self._patterns.values():
            prov_counts[p.provider] += 1
        return {
            "patterns": len(self._patterns),
            "by_provider": dict(prov_counts),
        }
