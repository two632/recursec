"""Secrets management knowledge base.

Deep knowledge about secrets management:
1. Secret discovery and detection
2. Cloud secrets management
3. Vault/HSM systems
4. Secret rotation strategies
5. Credential leakage prevention
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class SecretsPattern:
    """A secrets management pattern."""
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


SECRETS_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "sec-001", "name": "Secret Discovery and Detection",
        "category": "discovery", "severity": "critical",
        "desc": "Finding exposed secrets and credentials.",
        "detection": (
            "SECRET DISCOVERY:\n"
            "SOURCE CODE:\n"
            "  # Trufflehog (git history)\n"
            "  trufflehog git https://github.com/org/repo\n"
            "  trufflehog filesystem /path/to/code\n"
            "  # Gitleaks\n"
            "  gitleaks detect --source /repo\n"
            "  gitleaks detect --source /repo --log-opts='--all'\n"
            "  # detect-secrets\n"
            "  detect-secrets scan > .secrets.baseline\n"
            "PATTERNS TO FIND:\n"
            "  - AWS access keys (AKIA...)\n"
            "  - Azure connection strings\n"
            "  - GCP service account keys (JSON)\n"
            "  - Private keys (RSA, ECDSA)\n"
            "  - JWT secrets\n"
            "  - Database connection strings\n"
            "  - API keys and tokens\n"
            "  - OAuth client secrets\n"
            "  - Password hashes\n"
            "  - .env files committed\n"
            "GITHUB/GITLAB:\n"
            "  - GitHub secret scanning\n"
            "  - GitHub Advanced Security\n"
            "  - GitLab secret detection\n"
            "  - Commit history search\n"
            "  - Forked repo secrets\n"
            "NETWORK:\n"
            "  - PCAP analysis for cleartext\n"
            "  - Service enumeration (default creds)\n"
            "  - Exposed config endpoints\n"
            "  - Debug pages with credentials\n"
            "TOOLS:\n"
            "  TruffleHog, Gitleaks, detect-secrets"
        ),
        "tools": ["trufflehog", "gitleaks"],
    },
    {
        "id": "sec-002", "name": "Cloud Secrets Management",
        "category": "cloud_secrets", "severity": "high",
        "desc": "Cloud-native secrets management.",
        "detection": (
            "CLOUD SECRETS MANAGEMENT:\n"
            "AWS:\n"
            "  # Secrets Manager\n"
            "  aws secretsmanager list-secrets\n"
            "  aws secretsmanager get-secret-value --secret-id NAME\n"
            "  # Parameter Store (SSM)\n"
            "  aws ssm get-parameters-by-path --path /app/ --with-decryption\n"
            "  # KMS key management\n"
            "  aws kms list-keys\n"
            "  # MISCONFIGURATIONS:\n"
            "  #   - Secrets in env vars (ECS task def)\n"
            "  #   - Secrets in Lambda environment\n"
            "  #   - Unencrypted parameters\n"
            "  #   - Overly permissive KMS policies\n"
            "AZURE:\n"
            "  # Key Vault\n"
            "  az keyvault list\n"
            "  az keyvault secret list --vault-name NAME\n"
            "  # Managed Identity for access\n"
            "  # MISCONFIGURATIONS:\n"
            "  #   - Access policy too broad\n"
            "  #   - No soft-delete/purge protection\n"
            "  #   - Network rules missing\n"
            "GCP:\n"
            "  # Secret Manager\n"
            "  gcloud secrets list\n"
            "  gcloud secrets versions access latest --secret=NAME\n"
            "  # MISCONFIGURATIONS:\n"
            "  #   - IAM bindings too broad\n"
            "  #   - Missing audit logging\n"
            "  #   - No rotation configured\n"
            "TOOLS:\n"
            "  AWS CLI, Azure CLI, gcloud, Prowler"
        ),
        "tools": ["prowler"],
    },
    {
        "id": "sec-003", "name": "Vault and HSM Systems",
        "category": "vault", "severity": "high",
        "desc": "Secret vault and HSM systems.",
        "detection": (
            "VAULT AND HSM SYSTEMS:\n"
            "HASHICORP VAULT:\n"
            "  # Auth methods\n"
            "  vault auth list\n"
            "  # Secrets engines\n"
            "  vault secrets list\n"
            "  # Read secrets\n"
            "  vault kv get secret/data/app\n"
            "  # SECURITY CHECKS:\n"
            "  #   - Audit logging enabled\n"
            "  #   - Auto-unseal configured\n"
            "  #   - TLS termination\n"
            "  #   - Policy least-privilege\n"
            "  #   - Token TTL settings\n"
            "  #   - Seal/unseal key management\n"
            "CYBERARK:\n"
            "  - Privileged Access Security\n"
            "  - Session management\n"
            "  - Credential rotation\n"
            "  - EPV (Enterprise Password Vault)\n"
            "HSM (Hardware Security Module):\n"
            "  - PKCS#11 interface\n"
            "  - Key ceremony procedures\n"
            "  - Multi-party authentication\n"
            "  - FIPS 140-2/3 compliance\n"
            "  - AWS CloudHSM\n"
            "  - Azure Dedicated HSM\n"
            "  - GCP Cloud HSM\n"
            "CHECKS:\n"
            "  - Key ceremony documentation\n"
            "  - Backup and recovery procedures\n"
            "  - Access control auditing\n"
            "  - Firmware update policy\n"
            "TOOLS:\n"
            "  Vault CLI, pkcs11-tool, custom scripts"
        ),
        "tools": [],
    },
    {
        "id": "sec-004", "name": "Secret Rotation Strategies",
        "category": "rotation", "severity": "high",
        "desc": "Automated secret rotation.",
        "detection": (
            "SECRET ROTATION:\n"
            "STRATEGIES:\n"
            "  AUTOMATED:\n"
            "    - AWS Secrets Manager rotation Lambda\n"
            "    - Vault dynamic secrets\n"
            "    - CyberArk CPM rotation\n"
            "    - Azure Key Vault auto-rotation\n"
            "  ZERO-DOWNTIME:\n"
            "    - Dual-credential rotation\n"
            "    - Version-based secrets\n"
            "    - Graceful credential transition\n"
            "    - Blue-green credential swap\n"
            "  EMERGENCY:\n"
            "    - Breach response rotation\n"
            "    - All secrets at once\n"
            "    - Certificate revocation\n"
            "    - Token invalidation\n"
            "WHAT TO ROTATE:\n"
            "  - Database passwords (30-90 days)\n"
            "  - API keys (90 days)\n"
            "  - TLS certificates (annually)\n"
            "  - SSH keys (180 days)\n"
            "  - Service account credentials (90 days)\n"
            "  - Encryption keys (annually)\n"
            "  - OAuth tokens (per session)\n"
            "CHECKS:\n"
            "  - Is rotation automated?\n"
            "  - Last rotation date\n"
            "  - Rotation frequency compliance\n"
            "  - Failed rotation alerts\n"
            "  - Orphaned/stale secrets\n"
            "TOOLS:\n"
            "  Vault, AWS Secrets Manager, custom scripts"
        ),
        "tools": [],
    },
    {
        "id": "sec-005", "name": "Credential Leakage Prevention",
        "category": "prevention", "severity": "high",
        "desc": "Preventing credential leakage.",
        "detection": (
            "CREDENTIAL LEAKAGE PREVENTION:\n"
            "PRE-COMMIT:\n"
            "  # pre-commit hooks\n"
            "  # .pre-commit-config.yaml:\n"
            "  # - repo: https://github.com/Yelp/detect-secrets\n"
            "  #   hooks:\n"
            "  #     - id: detect-secrets\n"
            "  # Git hooks\n"
            "  # Gitleaks pre-commit\n"
            "  # Talisman (ThoughtWorks)\n"
            "CI/CD:\n"
            "  - Secret scanning in pipeline\n"
            "  - No secrets in build logs\n"
            "  - Environment variable injection\n"
            "  - Sealed secrets (K8s)\n"
            "  - External secrets operator\n"
            "  - SOPS (Mozilla) for encrypted configs\n"
            "RUNTIME:\n"
            "  - Environment variable injection\n"
            "  - Sidecar pattern (Vault Agent)\n"
            "  - Init container secrets\n"
            "  - Memory-only secrets\n"
            "  - Short-lived credentials\n"
            "MONITORING:\n"
            "  - GitHub secret scanning alerts\n"
            "  - GitGuardian (real-time monitoring)\n"
            "  - TruffleHog GitHub Action\n"
            "  - Automated revocation on detection\n"
            "  - SIEM correlation rules\n"
            ".GITIGNORE ESSENTIALS:\n"
            "  .env, *.pem, *.key, *.p12,\n"
            "  credentials.*, *secret*, *password*,\n"
            "  serviceaccount*.json\n"
            "TOOLS:\n"
            "  detect-secrets, Gitleaks, GitGuardian, SOPS"
        ),
        "tools": ["gitleaks"],
    },
]


class SecretsManagementKB:
    """Secrets management knowledge base.

    Provides secrets management patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, SecretsPattern] = {}
        self._log = logger.bind(component="secrets_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load secrets patterns."""
        for data in SECRETS_PATTERNS:
            pattern = SecretsPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "critical"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[SecretsPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_secrets_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build secrets management prompt."""
        lines = ["## Secrets Management\n"]
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
