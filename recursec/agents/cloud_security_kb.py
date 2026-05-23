"""Cloud security knowledge base.

Deep knowledge about cloud-specific attacks:
1. AWS misconfiguration exploitation
2. Azure AD attacks
3. GCP privilege escalation
4. Kubernetes security
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
    platform: str = ""
    severity: str = "high"
    description: str = ""
    detection_strategy: str = ""
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:25],
            "platform": self.platform[:10],
        }


CLOUD_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "cloud-001", "name": "AWS S3 Bucket Misconfiguration",
        "platform": "aws", "severity": "critical",
        "desc": "Exposed S3 buckets and misconfigurations.",
        "detection": (
            "AWS S3 MISCONFIGURATION:\n"
            "ENUMERATION:\n"
            "  # Brute force bucket names\n"
            "  aws s3 ls s3://<bucket-name> --no-sign-request\n"
            "  # Tools:\n"
            "  bucket-finder <wordlist>  # Find buckets by name\n"
            "  s3scanner scan --bucket <name>  # Check permissions\n"
            "  flaws.cloud method: <target>.s3.amazonaws.com\n"
            "PERMISSION CHECKS:\n"
            "  Public read:\n"
            "    curl https://<bucket>.s3.amazonaws.com/\n"
            "    → ListBucketResult = readable\n"
            "  Public write:\n"
            "    aws s3 cp test.txt s3://<bucket>/test.txt --no-sign-request\n"
            "  ACL check:\n"
            "    aws s3api get-bucket-acl --bucket <name> --no-sign-request\n"
            "  Policy check:\n"
            "    aws s3api get-bucket-policy --bucket <name>\n"
            "COMMON MISCONFIGS:\n"
            "  - Public read on sensitive data (backups, configs, DB dumps)\n"
            "  - Public write allowing file upload (deface, malware hosting)\n"
            "  - Overly permissive bucket policies\n"
            "  - Missing encryption (server-side)\n"
            "  - Missing access logging\n"
            "  - Versioning disabled (no recovery from deletion)"
        ),
        "tools": ["aws-cli", "s3scanner", "bucket-finder"],
    },
    {
        "id": "cloud-002", "name": "AWS IAM Privilege Escalation",
        "platform": "aws", "severity": "critical",
        "desc": "Escalating privileges through IAM misconfigurations.",
        "detection": (
            "AWS IAM PRIVILEGE ESCALATION:\n"
            "ENUMERATION:\n"
            "  # Who am I?\n"
            "  aws sts get-caller-identity\n"
            "  # What can I do?\n"
            "  aws iam list-attached-user-policies --user-name <user>\n"
            "  aws iam list-user-policies --user-name <user>\n"
            "  # Automated enumeration:\n"
            "  enumerate-iam --access-key <key> --secret-key <secret>\n"
            "  pacu (AWS exploitation framework)\n"
            "ESCALATION PATHS:\n"
            "  iam:CreatePolicyVersion:\n"
            "    - Create new policy version with admin permissions\n"
            "    - Set as default version\n"
            "  iam:AttachUserPolicy:\n"
            "    - Attach AdministratorAccess to self\n"
            "  iam:CreateLoginProfile:\n"
            "    - Create console password for any user\n"
            "  iam:PassRole + lambda:CreateFunction:\n"
            "    - Create Lambda with admin role\n"
            "    - Execute Lambda to perform admin actions\n"
            "  sts:AssumeRole:\n"
            "    - Assume higher-privileged role\n"
            "    - Check trust policies for over-permissive conditions\n"
            "TOOLS:\n"
            "  pacu: AWS post-exploitation framework\n"
            "  cloudsplaining: IAM policy analysis\n"
            "  ScoutSuite: Multi-cloud security audit"
        ),
        "tools": ["pacu", "enumerate-iam", "scoutsuite"],
    },
    {
        "id": "cloud-003", "name": "Kubernetes Security Issues",
        "platform": "k8s", "severity": "critical",
        "desc": "Kubernetes cluster misconfigurations and attacks.",
        "detection": (
            "KUBERNETES SECURITY:\n"
            "UNAUTHENTICATED ACCESS:\n"
            "  # Check for exposed API server\n"
            "  curl -k https://<k8s-api>:6443/api\n"
            "  curl -k https://<k8s-api>:6443/api/v1/namespaces\n"
            "  # Check kubelet (10250)\n"
            "  curl -k https://<node>:10250/pods\n"
            "  curl -k https://<node>:10250/run/<ns>/<pod>/<container>\n"
            "  # Check etcd (2379)\n"
            "  curl https://<node>:2379/v2/keys?recursive=true\n"
            "RBAC MISCONFIGS:\n"
            "  - cluster-admin binding to default service account\n"
            "  - Wildcard permissions in roles\n"
            "  - Check: kubectl auth can-i --list\n"
            "  - Tool: rbac-police, kubeaudit\n"
            "CONTAINER ESCAPE:\n"
            "  Privileged containers:\n"
            "    - Mount host filesystem: nsenter --target 1 --mount -- /bin/bash\n"
            "  Host PID namespace:\n"
            "    - See host processes, ptrace attack\n"
            "  Host network:\n"
            "    - Access node services, metadata API\n"
            "  Service account token:\n"
            "    /var/run/secrets/kubernetes.io/serviceaccount/token\n"
            "    → Use to access API server\n"
            "METADATA API:\n"
            "  curl http://169.254.169.254/latest/meta-data/iam/security-credentials/"
        ),
        "tools": ["kubeaudit", "kube-bench", "trivy"],
    },
    {
        "id": "cloud-004", "name": "Azure AD Attack Paths",
        "platform": "azure", "severity": "critical",
        "desc": "Azure Active Directory exploitation.",
        "detection": (
            "AZURE AD ATTACKS:\n"
            "ENUMERATION:\n"
            "  # Tenant enumeration\n"
            "  https://login.microsoftonline.com/<domain>/.well-known/openid-configuration\n"
            "  # User enumeration\n"
            "  POST https://login.microsoftonline.com/common/GetCredentialType\n"
            "  # Graph API (if token available)\n"
            "  az ad user list --query '[].{UPN:userPrincipalName}'\n"
            "ATTACKS:\n"
            "  Password Spray:\n"
            "    - Use common passwords against all users\n"
            "    - Respect lockout threshold (typically 10 attempts)\n"
            "    - Tool: MSOLSpray, o365spray\n"
            "  Token Theft:\n"
            "    - Steal access tokens from az CLI cache\n"
            "    - ~/.azure/accessTokens.json\n"
            "    - FOCI: Family of Client IDs (token reuse)\n"
            "  Application Consent:\n"
            "    - Illicit consent grant attack\n"
            "    - Create malicious app requesting permissions\n"
            "  PRT (Primary Refresh Token):\n"
            "    - Device-bound token for SSO\n"
            "    - Extract with mimikatz or ROADtools\n"
            "TOOLS:\n"
            "  ROADtools: Azure AD enumeration/exploitation\n"
            "  AzureHound: BloodHound for Azure\n"
            "  TokenTactics: Token manipulation"
        ),
        "tools": ["roadtools", "azurehound", "msolspray"],
    },
    {
        "id": "cloud-005", "name": "Serverless Security Issues",
        "platform": "serverless", "severity": "high",
        "desc": "Serverless function vulnerabilities.",
        "detection": (
            "SERVERLESS SECURITY:\n"
            "AWS LAMBDA:\n"
            "  Event Injection:\n"
            "    - User input flows directly into Lambda event\n"
            "    - SQL injection via event parameters\n"
            "    - Command injection via event data\n"
            "    - Path traversal in S3 trigger key names\n"
            "  Environment Variables:\n"
            "    - Secrets stored in plaintext env vars\n"
            "    - aws lambda get-function --function-name <func>\n"
            "    - Leaked in error messages/logs\n"
            "  Permissions:\n"
            "    - Overly permissive IAM role\n"
            "    - Resource:* in policy (no least privilege)\n"
            "    - Cross-function privilege escalation\n"
            "  Cold Start:\n"
            "    - /tmp persists between invocations\n"
            "    - Previous execution data accessible\n"
            "API GATEWAY:\n"
            "  - Missing authentication on endpoints\n"
            "  - Broken function-level authorization\n"
            "  - Debug mode left enabled\n"
            "  - Custom domain misconfiguration\n"
            "  - WAF bypass via direct Lambda URL\n"
            "TESTING:\n"
            "  - Enumerate functions: aws lambda list-functions\n"
            "  - Check permissions: aws lambda get-policy\n"
            "  - Test event injection with crafted payloads"
        ),
        "tools": ["aws-cli", "pacu", "serverless-spy"],
    },
]


class CloudSecurityKB:
    """Cloud security knowledge base.

    Provides cloud attack patterns injected
    into agent prompts.
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
                platform=data.get("platform", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_platform(self, platform: str) -> list[CloudPattern]:
        """Get patterns by cloud platform."""
        return [
            p for p in self._patterns.values()
            if p.platform.lower() == platform.lower()
        ]

    def build_cloud_prompt(
        self,
        platforms: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build cloud security prompt."""
        lines = ["## Cloud Security Patterns\n"]
        count = 0
        for pattern in self._patterns.values():
            if platforms and pattern.platform.lower() not in [p.lower() for p in platforms]:
                continue
            if count >= max_patterns:
                break
            lines.append(f"### {pattern.name} [{pattern.platform.upper()}]")
            lines.append(pattern.detection_strategy)
            lines.append("")
            count += 1
        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        plat_counts: dict[str, int] = {}
        for p in self._patterns.values():
            plat_counts[p.platform] = plat_counts.get(p.platform, 0) + 1
        return {
            "patterns": len(self._patterns),
            "by_platform": plat_counts,
        }
