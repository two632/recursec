"""Authentication security knowledge base.

Deep knowledge about authentication vulnerabilities:
1. Password attacks and credential stuffing
2. Multi-factor authentication bypass
3. Session management flaws
4. OAuth/OIDC vulnerabilities
5. SSO and SAML attacks
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class AuthPattern:
    """An authentication security pattern."""
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


AUTH_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "auth-001", "name": "Password Attack Techniques",
        "category": "password", "severity": "high",
        "desc": "Password-based attack techniques and detection.",
        "detection": (
            "PASSWORD ATTACKS:\n"
            "BRUTE FORCE:\n"
            "  hydra -l admin -P rockyou.txt <target> http-post-form \\\n"
            "    '/login:user=^USER^&pass=^PASS^:F=Invalid'\n"
            "  hydra -l admin -P wordlist.txt <target> ssh\n"
            "  medusa -h <target> -u admin -P passwords.txt -M ssh\n"
            "PASSWORD SPRAYING:\n"
            "  - Low and slow: 1 password per user per interval\n"
            "  - Common passwords: Season+Year (Winter2026!)\n"
            "  - Company name variations\n"
            "  crackmapexec smb <target> -u users.txt -p 'Winter2026!'\n"
            "  sprayhound --url https://<target>/login -U users.txt\n"
            "CREDENTIAL STUFFING:\n"
            "  - Use leaked credential pairs\n"
            "  - Automated with proxy rotation\n"
            "  - Target services with same email login\n"
            "HASH CRACKING:\n"
            "  hashcat -m 1000 ntlm_hashes.txt rockyou.txt  # NTLM\n"
            "  hashcat -m 1800 shadow_hashes.txt rockyou.txt  # sha512crypt\n"
            "  hashcat -m 3200 bcrypt_hashes.txt rockyou.txt  # bcrypt\n"
            "  john --wordlist=rockyou.txt hashes.txt\n"
            "DETECTION:\n"
            "  - Check account lockout policy\n"
            "  - Test rate limiting on login\n"
            "  - Check password complexity requirements\n"
            "  - Test CAPTCHA implementation"
        ),
        "tools": ["hydra", "hashcat", "john"],
    },
    {
        "id": "auth-002", "name": "MFA Bypass Techniques",
        "category": "mfa", "severity": "critical",
        "desc": "Techniques for bypassing multi-factor authentication.",
        "detection": (
            "MFA BYPASS:\n"
            "REAL-TIME PHISHING:\n"
            "  - Evilginx2: Transparent proxy captures session\n"
            "  - Modlishka: Similar transparent proxy\n"
            "  - Captures MFA tokens in real-time\n"
            "  - Relays to actual site, gets session cookie\n"
            "MFA IMPLEMENTATION FLAWS:\n"
            "  - MFA code reuse (same code valid multiple times)\n"
            "  - Long validity window (>60 seconds)\n"
            "  - No rate limiting on code entry\n"
            "  - Predictable codes (sequential, time-based without secret)\n"
            "  - MFA bypass via API endpoint (no MFA on API)\n"
            "  - MFA skip by modifying response (isValid:true)\n"
            "RECOVERY CODE ATTACKS:\n"
            "  - Brute force recovery codes\n"
            "  - Social engineering helpdesk for reset\n"
            "  - Recovery email/phone takeover\n"
            "  - Backup code generation without auth\n"
            "SESSION ATTACKS:\n"
            "  - Session fixation before MFA\n"
            "  - Remember-me token theft\n"
            "  - Session token in URL\n"
            "  - Weak session binding (no IP/UA check)\n"
            "TESTING:\n"
            "  - Submit empty MFA code\n"
            "  - Submit null/0 MFA code\n"
            "  - Try previous valid codes\n"
            "  - Check for MFA on all entry points"
        ),
        "tools": ["evilginx2", "burpsuite"],
    },
    {
        "id": "auth-003", "name": "Session Management Flaws",
        "category": "session", "severity": "high",
        "desc": "Session management vulnerability assessment.",
        "detection": (
            "SESSION MANAGEMENT FLAWS:\n"
            "SESSION TOKEN ANALYSIS:\n"
            "  - Check entropy (should be >= 128 bits)\n"
            "  - Check for predictable patterns\n"
            "  - Test sequential session IDs\n"
            "  - Look for encoded user data in token\n"
            "  - JWT: Check algorithm confusion (none/HS256)\n"
            "FIXATION:\n"
            "  - Pre-auth session carried to post-auth?\n"
            "  - Can attacker set session cookie?\n"
            "  - Session regeneration on login check\n"
            "HIJACKING:\n"
            "  - Cookies without Secure flag\n"
            "  - Cookies without HttpOnly flag\n"
            "  - Cookies without SameSite attribute\n"
            "  - Session token in URL parameters\n"
            "  - XSS → cookie theft\n"
            "JWT ATTACKS:\n"
            "  # Algorithm none\n"
            "  # Change alg:HS256 → alg:none, remove signature\n"
            "  # Key confusion: RS256 → HS256 (use public key as HMAC)\n"
            "  # Weak secret: hashcat -m 16500 jwt.txt wordlist.txt\n"
            "  # kid injection: kid parameter SQL injection\n"
            "  # jku/x5u header manipulation\n"
            "TOOLS:\n"
            "  jwt_tool <token>  # JWT analysis and attacks\n"
            "  jwt-cracker <token>  # Brute force JWT secret"
        ),
        "tools": ["jwt_tool", "burpsuite"],
    },
    {
        "id": "auth-004", "name": "OAuth and OIDC Vulnerabilities",
        "category": "oauth", "severity": "critical",
        "desc": "OAuth 2.0 and OpenID Connect security issues.",
        "detection": (
            "OAUTH/OIDC VULNERABILITIES:\n"
            "AUTHORIZATION CODE FLOW:\n"
            "  - Open redirect in redirect_uri\n"
            "  - Missing state parameter (CSRF)\n"
            "  - Authorization code replay\n"
            "  - Code injection (swap code from attacker flow)\n"
            "  - Insufficient redirect_uri validation\n"
            "    redirect_uri=https://attacker.com\n"
            "    redirect_uri=https://legit.com@attacker.com\n"
            "    redirect_uri=https://legit.com/.attacker.com\n"
            "IMPLICIT FLOW:\n"
            "  - Token leakage via Referer header\n"
            "  - Token in URL fragment\n"
            "  - No state validation\n"
            "TOKEN ATTACKS:\n"
            "  - Scope escalation (request additional scopes)\n"
            "  - Token reuse across applications\n"
            "  - Refresh token theft\n"
            "  - JWT algorithm confusion\n"
            "CLIENT ATTACKS:\n"
            "  - Client secret in source code\n"
            "  - Client impersonation\n"
            "  - Registration endpoint abuse\n"
            "TESTING:\n"
            "  - Modify redirect_uri in auth request\n"
            "  - Remove/change state parameter\n"
            "  - Replay captured authorization codes\n"
            "  - Test scope parameter manipulation"
        ),
        "tools": ["burpsuite"],
    },
    {
        "id": "auth-005", "name": "SAML and SSO Attacks",
        "category": "sso", "severity": "critical",
        "desc": "SAML and SSO vulnerability assessment.",
        "detection": (
            "SAML AND SSO ATTACKS:\n"
            "SAML ATTACKS:\n"
            "  - XML Signature Wrapping (XSW)\n"
            "    - Move signed assertion, add unsigned one\n"
            "    - Service provider validates signature\n"
            "    - But processes unsigned assertion\n"
            "  - Assertion replay\n"
            "  - Certificate confusion\n"
            "  - Comment injection in NameID\n"
            "    admin@company.com<!-- -->.attacker.com\n"
            "  - XXE in SAML response\n"
            "SSO TESTING:\n"
            "  - Token relay between services\n"
            "  - Session timeout synchronization\n"
            "  - Logout propagation\n"
            "  - Account linking vulnerabilities\n"
            "  - IdP impersonation\n"
            "GOLDEN SAML:\n"
            "  - Steal ADFS token-signing certificate\n"
            "  - Forge any SAML assertion\n"
            "  - Access any federated service\n"
            "  - Hard to detect (valid signatures)\n"
            "  # ADFSDump: Extract certificate from ADFS\n"
            "  # shimit: Forge SAML tokens\n"
            "TOOLS:\n"
            "  SAMLRaider (Burp extension)\n"
            "  SAML-decoder: Decode and inspect tokens\n"
            "  saml2aws: CLI for SAML SSO"
        ),
        "tools": ["burpsuite", "samlraider"],
    },
]


class AuthSecurityKB:
    """Authentication security knowledge base.

    Provides authentication vulnerability patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, AuthPattern] = {}
        self._log = logger.bind(component="auth_security_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load authentication patterns."""
        for data in AUTH_PATTERNS:
            pattern = AuthPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[AuthPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_auth_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build authentication security prompt."""
        lines = ["## Authentication Security Patterns\n"]
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
