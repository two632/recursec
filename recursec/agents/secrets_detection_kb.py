"""Secrets detection knowledge base.

Comprehensive knowledge about secret detection:
1. API key patterns
2. Credential patterns
3. Token patterns
4. Certificate patterns
5. Cloud-specific secrets
6. Database connection strings
7. Private key detection
8. Entropy-based detection
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class SecretPattern:
    """A secret detection pattern."""
    pattern_id: str = ""
    name: str = ""
    category: str = ""         # api_key, credential, token, certificate, cloud, database
    severity: str = "high"
    regex: str = ""
    description: str = ""
    false_positive_hints: list[str] = field(default_factory=list)
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:30],
            "category": self.category[:12],
            "severity": self.severity,
        }


SECRET_PATTERNS: list[dict[str, Any]] = [
    # ── AWS ───────────────────────────────────────────────
    {
        "id": "sec-001", "name": "AWS Access Key ID",
        "category": "cloud", "severity": "critical",
        "regex": r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}",
        "desc": "AWS IAM access key identifier.",
        "fp_hints": ["Example keys in documentation", "Test/dummy keys"],
        "remediation": "Rotate the key immediately via AWS IAM console. Check CloudTrail for unauthorized usage.",
    },
    {
        "id": "sec-002", "name": "AWS Secret Access Key",
        "category": "cloud", "severity": "critical",
        "regex": r"(?i)aws[_\-\.]?secret[_\-\.]?access[_\-\.]?key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        "desc": "AWS IAM secret access key.",
        "fp_hints": ["Placeholder values", "Documentation examples"],
        "remediation": "Rotate immediately. Enable MFA delete on S3 buckets if compromised.",
    },
    # ── GCP ───────────────────────────────────────────────
    {
        "id": "sec-003", "name": "Google Cloud API Key",
        "category": "cloud", "severity": "high",
        "regex": r"AIza[0-9A-Za-z\-_]{35}",
        "desc": "Google Cloud Platform API key.",
        "fp_hints": ["Maps API keys restricted by referrer"],
        "remediation": "Restrict API key to specific services/IPs. Regenerate if unrestricted.",
    },
    {
        "id": "sec-004", "name": "Google OAuth Client Secret",
        "category": "cloud", "severity": "critical",
        "regex": r"GOCSPX-[A-Za-z0-9\-_]{28}",
        "desc": "Google OAuth 2.0 client secret.",
        "remediation": "Regenerate the client secret in Google Cloud Console.",
    },
    # ── Azure ─────────────────────────────────────────────
    {
        "id": "sec-005", "name": "Azure Storage Account Key",
        "category": "cloud", "severity": "critical",
        "regex": r"(?i)(?:DefaultEndpointsProtocol|AccountKey)\s*=\s*[A-Za-z0-9+/=]{86,88}",
        "desc": "Azure Storage account access key.",
        "remediation": "Rotate key in Azure Portal → Storage Account → Access Keys.",
    },
    {
        "id": "sec-006", "name": "Azure AD Client Secret",
        "category": "cloud", "severity": "critical",
        "regex": r"(?i)(?:azure|ad|aad)[_\-\.]?(?:client|app)[_\-\.]?secret\s*[=:]\s*['\"]?([A-Za-z0-9~._\-]{34,})['\"]?",
        "desc": "Azure Active Directory application client secret.",
        "remediation": "Rotate secret in Azure Portal → App Registrations → Certificates & Secrets.",
    },
    # ── GitHub ────────────────────────────────────────────
    {
        "id": "sec-007", "name": "GitHub Personal Access Token",
        "category": "token", "severity": "critical",
        "regex": r"ghp_[A-Za-z0-9]{36}",
        "desc": "GitHub personal access token (classic).",
        "remediation": "Revoke at github.com/settings/tokens. Check audit log for usage.",
    },
    {
        "id": "sec-008", "name": "GitHub Fine-Grained Token",
        "category": "token", "severity": "critical",
        "regex": r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}",
        "desc": "GitHub fine-grained personal access token.",
        "remediation": "Revoke at github.com/settings/tokens. Review permissions granted.",
    },
    {
        "id": "sec-009", "name": "GitHub App Token",
        "category": "token", "severity": "critical",
        "regex": r"(?:ghu|ghs)_[A-Za-z0-9]{36}",
        "desc": "GitHub App installation or user-to-server token.",
        "remediation": "Tokens are short-lived but review app permissions.",
    },
    # ── Stripe ────────────────────────────────────────────
    {
        "id": "sec-010", "name": "Stripe Secret Key",
        "category": "api_key", "severity": "critical",
        "regex": r"sk_(?:live|test)_[A-Za-z0-9]{24,}",
        "desc": "Stripe API secret key.",
        "remediation": "Roll the key in Stripe Dashboard → Developers → API Keys.",
    },
    {
        "id": "sec-011", "name": "Stripe Restricted Key",
        "category": "api_key", "severity": "high",
        "regex": r"rk_(?:live|test)_[A-Za-z0-9]{24,}",
        "desc": "Stripe restricted API key.",
        "remediation": "Delete and recreate with minimum permissions.",
    },
    # ── Slack ─────────────────────────────────────────────
    {
        "id": "sec-012", "name": "Slack Bot Token",
        "category": "token", "severity": "critical",
        "regex": r"xoxb-[0-9]{10,12}-[0-9]{10,12}-[A-Za-z0-9]{24}",
        "desc": "Slack Bot OAuth token.",
        "remediation": "Regenerate token in Slack App settings.",
    },
    {
        "id": "sec-013", "name": "Slack Webhook URL",
        "category": "token", "severity": "high",
        "regex": r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/[A-Za-z0-9]{24}",
        "desc": "Slack incoming webhook URL.",
        "remediation": "Regenerate webhook URL in Slack App settings.",
    },
    # ── Private Keys ──────────────────────────────────────
    {
        "id": "sec-014", "name": "RSA Private Key",
        "category": "certificate", "severity": "critical",
        "regex": r"-----BEGIN RSA PRIVATE KEY-----",
        "desc": "RSA private key in PEM format.",
        "remediation": "Revoke associated certificate. Generate new key pair.",
    },
    {
        "id": "sec-015", "name": "SSH Private Key (OpenSSH)",
        "category": "certificate", "severity": "critical",
        "regex": r"-----BEGIN OPENSSH PRIVATE KEY-----",
        "desc": "OpenSSH private key.",
        "remediation": "Remove from repository. Regenerate SSH key pair. Update authorized_keys.",
    },
    {
        "id": "sec-016", "name": "PGP Private Key",
        "category": "certificate", "severity": "critical",
        "regex": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "desc": "PGP/GPG private key.",
        "remediation": "Revoke key on keyservers. Generate new key pair.",
    },
    # ── Database ──────────────────────────────────────────
    {
        "id": "sec-017", "name": "PostgreSQL Connection String",
        "category": "database", "severity": "critical",
        "regex": r"postgres(?:ql)?://[^\s:]+:[^\s@]+@[^\s/]+(?::\d+)?/[^\s]+",
        "desc": "PostgreSQL connection URI with embedded credentials.",
        "remediation": "Rotate database password. Use environment variables or secrets manager.",
    },
    {
        "id": "sec-018", "name": "MySQL Connection String",
        "category": "database", "severity": "critical",
        "regex": r"mysql://[^\s:]+:[^\s@]+@[^\s/]+(?::\d+)?/[^\s]+",
        "desc": "MySQL connection URI with embedded credentials.",
        "remediation": "Rotate password. Use environment variables.",
    },
    {
        "id": "sec-019", "name": "MongoDB Connection String",
        "category": "database", "severity": "critical",
        "regex": r"mongodb(?:\+srv)?://[^\s:]+:[^\s@]+@[^\s/]+",
        "desc": "MongoDB connection string with credentials.",
        "remediation": "Rotate password. Use environment variables.",
    },
    # ── JWT ───────────────────────────────────────────────
    {
        "id": "sec-020", "name": "JSON Web Token",
        "category": "token", "severity": "medium",
        "regex": r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        "desc": "JSON Web Token (may contain sensitive claims).",
        "fp_hints": ["Test tokens", "Expired tokens", "Example JWTs"],
        "remediation": "Check token expiry. Validate audience and issuer claims.",
    },
    # ── Generic ───────────────────────────────────────────
    {
        "id": "sec-021", "name": "Generic API Key Variable",
        "category": "api_key", "severity": "high",
        "regex": r"(?i)(?:api[_\-\.]?key|apikey)\s*[=:]\s*['\"]?([A-Za-z0-9\-_]{20,})['\"]?",
        "desc": "Generic API key assignment in code.",
        "fp_hints": ["Placeholder values (xxx, YOUR_KEY_HERE)", "Test/mock values"],
        "remediation": "Move to environment variable or secrets manager.",
    },
    {
        "id": "sec-022", "name": "Generic Password Variable",
        "category": "credential", "severity": "high",
        "regex": r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
        "desc": "Password hardcoded in source code.",
        "fp_hints": ["Placeholder strings", "Password policy descriptions"],
        "remediation": "Move to secrets manager. Never hardcode passwords.",
    },
    # ── SendGrid ──────────────────────────────────────────
    {
        "id": "sec-023", "name": "SendGrid API Key",
        "category": "api_key", "severity": "high",
        "regex": r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}",
        "desc": "SendGrid email API key.",
        "remediation": "Regenerate in SendGrid dashboard.",
    },
    # ── Twilio ────────────────────────────────────────────
    {
        "id": "sec-024", "name": "Twilio API Key",
        "category": "api_key", "severity": "high",
        "regex": r"SK[A-Fa-f0-9]{32}",
        "desc": "Twilio API key.",
        "remediation": "Revoke and regenerate in Twilio console.",
    },
    # ── Mailgun ───────────────────────────────────────────
    {
        "id": "sec-025", "name": "Mailgun API Key",
        "category": "api_key", "severity": "high",
        "regex": r"key-[A-Za-z0-9]{32}",
        "desc": "Mailgun API key.",
        "remediation": "Regenerate in Mailgun dashboard.",
    },
]


class SecretsDetectionKB:
    """Secrets detection knowledge base.

    Provides regex patterns and context for detecting
    hardcoded secrets in source code. These patterns
    are injected into agent prompts to guide code review
    and secret scanning operations.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, SecretPattern] = {}
        self._compiled: dict[str, re.Pattern[str]] = {}
        self._log = logger.bind(component="secrets_detection_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load secret patterns."""
        for data in SECRET_PATTERNS:
            pattern = SecretPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                regex=data.get("regex", ""),
                description=data.get("desc", ""),
                false_positive_hints=data.get("fp_hints", []),
                remediation=data.get("remediation", ""),
            )
            self._patterns[pattern.pattern_id] = pattern

            if pattern.regex:
                try:
                    self._compiled[pattern.pattern_id] = re.compile(pattern.regex)
                except re.error:
                    pass

    def scan_text(self, text: str) -> list[dict[str, Any]]:
        """Scan text for secrets."""
        findings = []
        for pid, compiled in self._compiled.items():
            pattern = self._patterns[pid]
            for match in compiled.finditer(text):
                findings.append({
                    "pattern": pattern.name,
                    "category": pattern.category,
                    "severity": pattern.severity,
                    "match": match.group()[:50],
                    "position": match.start(),
                    "remediation": pattern.remediation,
                })
        return findings

    def get_patterns_for_category(
        self,
        category: str,
    ) -> list[SecretPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category == category
        ]

    def build_secrets_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 10,
    ) -> str:
        """Build secrets detection prompt."""
        lines = ["## Secret Detection Patterns\n"]
        count = 0
        for pattern in self._patterns.values():
            if categories and pattern.category not in categories:
                continue
            if count >= max_patterns:
                break
            lines.append(f"- **{pattern.name}** [{pattern.severity}]: `{pattern.regex[:50]}`")
            if pattern.remediation:
                lines.append(f"  Remediation: {pattern.remediation[:80]}")
            count += 1
        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        cat_counts: dict[str, int] = defaultdict(int)
        for p in self._patterns.values():
            cat_counts[p.category] += 1
        return {
            "patterns": len(self._patterns),
            "compiled": len(self._compiled),
            "by_category": dict(cat_counts),
        }
