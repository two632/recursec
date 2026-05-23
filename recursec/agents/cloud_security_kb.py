"""Cloud security knowledge base.

Deep knowledge about cloud infrastructure vulnerabilities:
1. AWS-specific attack patterns
2. Azure attack surfaces
3. GCP misconfigurations
4. Cloud-native vulnerabilities (K8s, containers)
5. IAM and identity attacks
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
    provider: str = ""
    severity: str = "high"
    description: str = ""
    detection_strategy: str = ""
    services: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:25],
            "provider": self.provider[:10],
        }


CLOUD_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "cloud-001", "name": "AWS S3 Bucket Misconfiguration",
        "provider": "aws", "severity": "critical",
        "desc": "Publicly accessible S3 buckets leaking sensitive data.",
        "detection": (
            "AWS S3 BUCKET MISCONFIGURATION:\n"
            "DISCOVERY:\n"
            "  - Enumerate bucket names from DNS, source code, APIs\n"
            "  - Common patterns: <company>-backup, <company>-data, <company>-logs\n"
            "  - Check: aws s3 ls s3://<bucket> --no-sign-request\n"
            "  - Test: curl https://<bucket>.s3.amazonaws.com/\n"
            "PUBLIC ACCESS CHECKS:\n"
            "  - ACL: aws s3api get-bucket-acl --bucket <name>\n"
            "  - Policy: aws s3api get-bucket-policy --bucket <name>\n"
            "  - Public access block: aws s3api get-public-access-block --bucket <name>\n"
            "  - Look for: AllUsers, AuthenticatedUsers grants\n"
            "COMMON DATA LEAKS:\n"
            "  - Database backups (.sql, .bak, .dump)\n"
            "  - Configuration files (.env, config.json)\n"
            "  - Source code (.zip, .tar.gz, .git)\n"
            "  - Credentials (access keys, private keys)\n"
            "  - Log files with PII or tokens\n"
            "TESTING TOOLS:\n"
            "  - S3Scanner: Scan for open S3 buckets\n"
            "  - bucket_finder: Enumerate S3 buckets\n"
            "  - aws s3 sync: Download bucket contents\n"
            "  - nuclei -t cloud/ -target <domain>"
        ),
        "services": ["s3"],
        "tools": ["aws-cli", "nuclei", "s3scanner"],
    },
    {
        "id": "cloud-002", "name": "AWS IAM Privilege Escalation",
        "provider": "aws", "severity": "critical",
        "desc": "Escalating AWS IAM privileges through policy misconfigurations.",
        "detection": (
            "AWS IAM PRIVILEGE ESCALATION:\n"
            "COMMON ESCALATION PATHS:\n"
            "  1. iam:CreatePolicyVersion → Create new policy version with admin access\n"
            "  2. iam:SetDefaultPolicyVersion → Activate hidden permissive version\n"
            "  3. iam:CreateAccessKey → Create keys for more privileged user\n"
            "  4. iam:AttachUserPolicy → Attach AdministratorAccess to self\n"
            "  5. iam:PutUserPolicy → Inline admin policy on self\n"
            "  6. iam:PassRole + lambda:CreateFunction → Create Lambda with admin role\n"
            "  7. iam:PassRole + ec2:RunInstances → Launch EC2 with admin role\n"
            "  8. sts:AssumeRole → Assume cross-account admin role\n"
            "  9. glue:CreateDevEndpoint + iam:PassRole → Glue with admin role\n"
            "  10. lambda:UpdateFunctionCode → Inject code into existing Lambda\n"
            "DETECTION:\n"
            "  - Enumerate policies: aws iam list-attached-user-policies --user-name <name>\n"
            "  - Check inline: aws iam list-user-policies --user-name <name>\n"
            "  - Analyze with: PACU, Prowler, ScoutSuite\n"
            "  - Map: pmapper (Principal Mapper)\n"
            "AUTOMATED TOOLS:\n"
            "  - PACU: AWS exploitation framework\n"
            "  - Prowler: AWS security assessment\n"
            "  - ScoutSuite: Multi-cloud assessment\n"
            "  - CloudSploit: Cloud configuration scanner"
        ),
        "services": ["iam", "lambda", "ec2"],
        "tools": ["pacu", "prowler", "scoutsuite"],
    },
    {
        "id": "cloud-003", "name": "Kubernetes Misconfigurations",
        "provider": "multi", "severity": "critical",
        "desc": "Kubernetes cluster security issues.",
        "detection": (
            "KUBERNETES SECURITY:\n"
            "API SERVER EXPOSURE:\n"
            "  - Anonymous auth: curl -k https://<api-server>:6443/api/v1/namespaces\n"
            "  - Insecure port (8080): curl http://<api-server>:8080/api/v1/pods\n"
            "  - Dashboard: https://<node>:30000 (NodePort)\n"
            "RBAC ISSUES:\n"
            "  - Overly permissive ClusterRoleBindings\n"
            "  - Default ServiceAccount with elevated privileges\n"
            "  - kubectl auth can-i --list --as=system:serviceaccount:default:default\n"
            "CONTAINER ESCAPE:\n"
            "  - Privileged containers: securityContext.privileged=true\n"
            "  - Host PID/Network: hostPID=true, hostNetwork=true\n"
            "  - Mounted host paths: /var/run/docker.sock\n"
            "  - SYS_ADMIN capability\n"
            "SECRET EXPOSURE:\n"
            "  - Secrets as environment variables (visible in /proc)\n"
            "  - Unencrypted etcd storage\n"
            "  - kubectl get secrets -A -o yaml\n"
            "NETWORK POLICIES:\n"
            "  - Missing NetworkPolicies (default allow-all)\n"
            "  - Pod-to-pod communication unrestricted\n"
            "TOOLS:\n"
            "  - kube-hunter: K8s penetration testing\n"
            "  - kubeaudit: K8s manifest auditing\n"
            "  - trivy k8s: K8s misconfiguration scanning\n"
            "  - kubectl-who-can: RBAC analysis"
        ),
        "services": ["kubernetes"],
        "tools": ["kube-hunter", "kubeaudit", "trivy"],
    },
    {
        "id": "cloud-004", "name": "Azure AD and Identity Attacks",
        "provider": "azure", "severity": "critical",
        "desc": "Azure Active Directory attack patterns.",
        "detection": (
            "AZURE AD ATTACKS:\n"
            "ENUMERATION:\n"
            "  - Tenant discovery: https://login.microsoftonline.com/<domain>/.well-known/openid-configuration\n"
            "  - User enumeration: timing differences on login page\n"
            "  - AADInternals: Invoke-AADIntReconAsOutsider\n"
            "PASSWORD SPRAY:\n"
            "  - Low and slow: 1 password per user per hour\n"
            "  - Avoid lockout: stay under threshold (typically 10)\n"
            "  - Tools: MSOLSpray, o365spray\n"
            "  - Common passwords: Season+Year (Spring2024), Company+123\n"
            "TOKEN ABUSE:\n"
            "  - Refresh token theft → persistent access\n"
            "  - Access token reuse across apps\n"
            "  - ROADtools: Azure AD exploration\n"
            "  - TokenTactics: Token manipulation\n"
            "PRIVILEGE ESCALATION:\n"
            "  - Global Admin via compromised service principal\n"
            "  - Managed Identity abuse from compromised VM\n"
            "  - Key Vault access from compromised identity\n"
            "  - Application consent phishing\n"
            "CONDITIONAL ACCESS BYPASS:\n"
            "  - Device compliance spoofing\n"
            "  - Location-based bypass via VPN\n"
            "  - Legacy auth protocols (IMAP, SMTP)"
        ),
        "services": ["azure_ad", "key_vault"],
        "tools": ["roadtools", "msolspray", "aad-internals"],
    },
    {
        "id": "cloud-005", "name": "Serverless Function Attacks",
        "provider": "multi", "severity": "high",
        "desc": "Serverless (Lambda/Functions/Cloud Functions) vulnerabilities.",
        "detection": (
            "SERVERLESS SECURITY:\n"
            "EVENT INJECTION:\n"
            "  - Inject payloads via event sources (S3, API Gateway, SNS)\n"
            "  - SQL injection through Lambda → RDS\n"
            "  - Command injection in runtime.exec() or subprocess\n"
            "  - SSRF via function → internal APIs\n"
            "ENVIRONMENT VARIABLES:\n"
            "  - Secrets in env vars visible to function code\n"
            "  - aws lambda get-function-configuration --function-name <name>\n"
            "  - Environment variable exfiltration on compromise\n"
            "IAM OVER-PRIVILEGE:\n"
            "  - Function with wildcard (*) permissions\n"
            "  - Cross-account role assumption\n"
            "  - Resource-based policy exploitation\n"
            "RUNTIME ATTACKS:\n"
            "  - /tmp directory persistence between warm invocations\n"
            "  - Cold start timing side channels\n"
            "  - Layer poisoning (compromised shared layers)\n"
            "  - Dependency confusion in function packages\n"
            "DETECTION:\n"
            "  - Review function configurations and env vars\n"
            "  - Check IAM roles attached to functions\n"
            "  - Test event sources for injection\n"
            "  - Monitor with CloudTrail/CloudWatch"
        ),
        "services": ["lambda", "api_gateway"],
        "tools": ["pacu", "prowler", "nuclei"],
    },
]


class CloudSecurityKB:
    """Cloud security knowledge base.

    Provides cloud-specific attack patterns
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
                provider=data.get("provider", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                services=data.get("services", []),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_provider(self, provider: str) -> list[CloudPattern]:
        """Get patterns by cloud provider."""
        return [
            p for p in self._patterns.values()
            if p.provider.lower() == provider.lower() or p.provider == "multi"
        ]

    def build_cloud_prompt(
        self,
        provider: str = "",
        max_patterns: int = 4,
    ) -> str:
        """Build cloud security prompt."""
        lines = ["## Cloud Security Patterns\n"]
        count = 0
        for pattern in self._patterns.values():
            if provider and pattern.provider not in (provider, "multi"):
                continue
            if count >= max_patterns:
                break
            lines.append(f"### {pattern.name} [{pattern.provider.upper()}]")
            lines.append(pattern.detection_strategy)
            lines.append("")
            count += 1
        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        prov_counts: dict[str, int] = {}
        for p in self._patterns.values():
            prov_counts[p.provider] = prov_counts.get(p.provider, 0) + 1
        return {
            "patterns": len(self._patterns),
            "by_provider": prov_counts,
        }
