"""Cloud security knowledge base.

Deep knowledge about cloud vulnerabilities:
1. AWS security misconfigurations
2. Azure and Entra ID attacks
3. GCP privilege escalation
4. Multi-cloud metadata attacks
5. Serverless security issues
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
        "id": "cloud-001", "name": "AWS Security Misconfigurations",
        "category": "aws", "severity": "critical",
        "desc": "Common AWS security misconfigurations.",
        "detection": (
            "AWS SECURITY MISCONFIGURATIONS:\n"
            "S3 BUCKET:\n"
            "  # Check public access\n"
            "  aws s3api get-bucket-acl --bucket <name>\n"
            "  aws s3api get-bucket-policy --bucket <name>\n"
            "  aws s3api get-public-access-block --bucket <name>\n"
            "  # Enumerate buckets\n"
            "  aws s3 ls s3://<bucket> --no-sign-request\n"
            "  # Common names: <company>-dev, <company>-backup, <company>-logs\n"
            "IAM:\n"
            "  # Enumerate permissions\n"
            "  aws iam get-user\n"
            "  aws iam list-attached-user-policies --user-name <user>\n"
            "  aws iam list-user-policies --user-name <user>\n"
            "  # Check for iam:PassRole + lambda/ec2 = escalation\n"
            "  # Check for sts:AssumeRole to higher-priv roles\n"
            "  # Dangerous policies: AdministratorAccess, IAMFullAccess\n"
            "EC2:\n"
            "  # Metadata service\n"
            "  curl http://169.254.169.254/latest/meta-data/iam/security-credentials/\n"
            "  # IMDSv2 check\n"
            "  TOKEN=$(curl -X PUT http://169.254.169.254/latest/api/token \\\n"
            "    -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600')\n"
            "  # Security groups: Check 0.0.0.0/0 ingress\n"
            "TOOLS:\n"
            "  prowler  # AWS security audit\n"
            "  ScoutSuite  # Multi-cloud audit\n"
            "  pacu  # AWS exploitation framework\n"
            "  enumerate-iam  # Enumerate IAM permissions"
        ),
        "tools": ["prowler", "scoutsuite", "pacu"],
    },
    {
        "id": "cloud-002", "name": "Azure and Entra ID Attacks",
        "category": "azure", "severity": "critical",
        "desc": "Azure and Microsoft Entra ID vulnerability assessment.",
        "detection": (
            "AZURE / ENTRA ID ATTACKS:\n"
            "ENTRA ID (Azure AD):\n"
            "  # Enumerate users\n"
            "  az ad user list --query '[].{UPN:userPrincipalName}'\n"
            "  # Enumerate groups\n"
            "  az ad group list --query '[].{Name:displayName}'\n"
            "  # Check app registrations\n"
            "  az ad app list --query '[].{Name:displayName,AppId:appId}'\n"
            "  # Service principal secrets\n"
            "  az ad app credential list --id <app-id>\n"
            "COMMON ATTACKS:\n"
            "  - Consent phishing (illicit consent grant)\n"
            "  - Application proxy abuse\n"
            "  - PRT (Primary Refresh Token) theft\n"
            "  - Device code phishing\n"
            "  - Password spray against AzureAD\n"
            "MANAGED IDENTITIES:\n"
            "  # From Azure VM, get managed identity token\n"
            "  curl 'http://169.254.169.254/metadata/identity/oauth2/token'\\\n"
            "    '?api-version=2018-02-01&resource=https://management.azure.com/'\\\n"
            "    -H Metadata:true\n"
            "TOOLS:\n"
            "  ROADtools  # Azure AD enumeration\n"
            "  AzureHound  # BloodHound for Azure\n"
            "  MicroBurst  # Azure security toolkit\n"
            "  TokenTactics  # Azure token manipulation"
        ),
        "tools": ["roadtools", "azurehound"],
    },
    {
        "id": "cloud-003", "name": "GCP Privilege Escalation",
        "category": "gcp", "severity": "critical",
        "desc": "GCP-specific privilege escalation techniques.",
        "detection": (
            "GCP PRIVILEGE ESCALATION:\n"
            "SERVICE ACCOUNT:\n"
            "  # List service accounts\n"
            "  gcloud iam service-accounts list\n"
            "  # Get service account keys\n"
            "  gcloud iam service-accounts keys list --iam-account=<sa>\n"
            "  # Check IAM bindings\n"
            "  gcloud projects get-iam-policy <project>\n"
            "ESCALATION PATHS:\n"
            "  - iam.serviceAccountKeys.create → Create SA key\n"
            "  - iam.serviceAccounts.actAs + compute.instances.create → Spawn VM as SA\n"
            "  - deploymentmanager.deployments.create → Deploy as project editor\n"
            "  - cloudfunctions.functions.create + iam.serviceAccounts.actAs\n"
            "  - run.services.create + iam.serviceAccounts.actAs\n"
            "  - composer.environments.create → Airflow as SA\n"
            "METADATA:\n"
            "  # GCP metadata service\n"
            "  curl -H 'Metadata-Flavor: Google' \\\n"
            "    http://169.254.169.254/computeMetadata/v1/instance/service-accounts/\n"
            "  curl -H 'Metadata-Flavor: Google' \\\n"
            "    http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token\n"
            "TOOLS:\n"
            "  gcp-iam-collector  # Enumerate permissions\n"
            "  ScoutSuite --provider gcp"
        ),
        "tools": ["scoutsuite", "gcloud"],
    },
    {
        "id": "cloud-004", "name": "Serverless Security",
        "category": "serverless", "severity": "high",
        "desc": "Serverless function security issues.",
        "detection": (
            "SERVERLESS SECURITY:\n"
            "AWS LAMBDA:\n"
            "  # Environment variable exposure\n"
            "  aws lambda get-function-configuration --function-name <name>\n"
            "  # Layer inspection\n"
            "  aws lambda get-layer-version --layer-name <name> --version-number 1\n"
            "  # Invoke with injection payload\n"
            "  aws lambda invoke --function-name <name> \\\n"
            "    --payload '{\"cmd\":\"id\"}' output.json\n"
            "COMMON ISSUES:\n"
            "  - Secrets in environment variables\n"
            "  - Over-permissive IAM execution role\n"
            "  - Event injection (untrusted event data)\n"
            "  - Dependency confusion in layers\n"
            "  - Cold start timing attacks\n"
            "  - /tmp persistence between invocations\n"
            "  - Shared execution environment\n"
            "AZURE FUNCTIONS:\n"
            "  - Function keys in URL (Kudu exposure)\n"
            "  - Managed identity token theft\n"
            "  - Storage account key exposure\n"
            "GCP CLOUD FUNCTIONS:\n"
            "  - Environment variable enumeration\n"
            "  - Service account token from metadata\n"
            "TESTING:\n"
            "  - Check function URL authentication\n"
            "  - Test event data sanitization\n"
            "  - Review execution role permissions\n"
            "  - Check for hardcoded secrets"
        ),
        "tools": ["prowler", "scoutsuite"],
    },
    {
        "id": "cloud-005", "name": "Terraform and IaC Misconfigs",
        "category": "iac", "severity": "high",
        "desc": "Infrastructure as Code security misconfigurations.",
        "detection": (
            "TERRAFORM / IaC MISCONFIGURATIONS:\n"
            "STATE FILE:\n"
            "  # Terraform state contains ALL secrets\n"
            "  # Check for exposed state files\n"
            "  # S3 bucket: company-terraform-state\n"
            "  # Azure blob: tfstate container\n"
            "  # HTTP backend without auth\n"
            "COMMON MISCONFIGS:\n"
            "  - Public S3/blob for state storage\n"
            "  - No state file encryption\n"
            "  - Secrets in terraform.tfvars committed to git\n"
            "  - Hardcoded credentials in provider blocks\n"
            "  - Overly permissive security groups\n"
            "  - Public RDS/database instances\n"
            "  - Disabled logging/monitoring\n"
            "  - Missing encryption at rest\n"
            "SCANNING:\n"
            "  # tfsec (Terraform)\n"
            "  tfsec ./terraform/\n"
            "  # checkov (multi-IaC)\n"
            "  checkov -d ./terraform/\n"
            "  # terrascan\n"
            "  terrascan scan -t aws -d ./terraform/\n"
            "  # kics (Checkmarx)\n"
            "  kics scan -p ./\n"
            "TOOLS:\n"
            "  tfsec  # Terraform security scanner\n"
            "  checkov  # Multi-framework IaC scanner\n"
            "  terrascan  # OPA-based IaC scanner\n"
            "  trivy config ./  # Trivy IaC scanning"
        ),
        "tools": ["tfsec", "checkov", "trivy"],
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
