"""Authentication attacks knowledge base.

Deep knowledge about authentication attacks:
1. Password attacks
2. MFA bypass techniques
3. Session management attacks
4. OAuth/SAML attacks
5. SSO and federation attacks
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class AuthPattern:
    """An authentication attack pattern."""
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


AUTH_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "auth-001", "name": "Password Attacks",
        "category": "password", "severity": "high",
        "desc": "Password-based attacks.",
        "detection": (
            "PASSWORD ATTACKS:\n"
            "BRUTE FORCE:\n"
            "  # Hydra (multi-protocol)\n"
            "  hydra -L users.txt -P pass.txt TARGET ssh\n"
            "  hydra -L users.txt -P pass.txt TARGET http-post-form\n"
            "  # Medusa\n"
            "  medusa -U users.txt -P pass.txt -h TARGET -M ssh\n"
            "  # Ncrack\n"
            "  ncrack -U users.txt -P pass.txt TARGET:22\n"
            "PASSWORD SPRAYING:\n"
            "  - One password, many accounts\n"
            "  - Avoids lockout thresholds\n"
            "  - Common passwords: Season+Year, Company+123\n"
            "  # CrackMapExec\n"
            "  crackmapexec smb TARGET -u users.txt -p 'Summer2026!'\n"
            "  # SprayingToolkit\n"
            "  # Ruler (Exchange)\n"
            "CREDENTIAL STUFFING:\n"
            "  - Use leaked credential databases\n"
            "  - Combo lists (email:password)\n"
            "  - Proxy rotation to avoid blocks\n"
            "  - CAPTCHA solving services\n"
            "DEFAULT CREDENTIALS:\n"
            "  - Check vendor defaults\n"
            "  - admin:admin, root:root, admin:password\n"
            "  - SecLists default credentials\n"
            "  - Nuclei default-login templates\n"
            "  nuclei -t default-logins/ -l targets.txt\n"
            "OFFLINE:\n"
            "  - Hashcat/John for hash cracking\n"
            "  - Rainbow tables\n"
            "  - Rule-based attacks\n"
            "TOOLS:\n"
            "  Hydra, CrackMapExec, Hashcat, Burp Intruder"
        ),
        "tools": ["hydra", "crackmapexec"],
    },
    {
        "id": "auth-002", "name": "MFA Bypass Techniques",
        "category": "mfa", "severity": "critical",
        "desc": "MFA bypass and circumvention.",
        "detection": (
            "MFA BYPASS:\n"
            "PHISHING:\n"
            "  - Real-time phishing proxy (Evilginx2)\n"
            "  - Captures session token after MFA\n"
            "  - Transparent reverse proxy\n"
            "  - Modlishka, Muraena alternatives\n"
            "MFA FATIGUE:\n"
            "  - Spam push notifications\n"
            "  - User approves to stop alerts\n"
            "  - Lapsus$ group technique\n"
            "  - Mitigated by number matching\n"
            "SIM SWAPPING:\n"
            "  - Port victim's phone number\n"
            "  - Receive SMS OTP\n"
            "  - Social engineer carrier\n"
            "RECOVERY:\n"
            "  - Backup code theft\n"
            "  - Recovery email compromise\n"
            "  - Recovery phone compromise\n"
            "  - Security question answers (OSINT)\n"
            "IMPLEMENTATION:\n"
            "  - Missing MFA on some endpoints\n"
            "  - MFA not required for API\n"
            "  - Remember device bypass\n"
            "  - Rate limiting absent on OTP\n"
            "  - OTP brute force (4-6 digits)\n"
            "  - OTP reuse allowed\n"
            "  - Time-based OTP with long window\n"
            "TOKEN THEFT:\n"
            "  - Session cookie theft post-MFA\n"
            "  - Token replay\n"
            "  - Pass-the-cookie\n"
            "TOOLS:\n"
            "  Evilginx2, Modlishka, Muraena"
        ),
        "tools": ["evilginx2"],
    },
    {
        "id": "auth-003", "name": "Session Management Attacks",
        "category": "session", "severity": "high",
        "desc": "Session management attacks.",
        "detection": (
            "SESSION MANAGEMENT ATTACKS:\n"
            "SESSION FIXATION:\n"
            "  - Set known session ID before auth\n"
            "  - URL-based session ID\n"
            "  - Cookie injection\n"
            "  - Check: session ID changes after login\n"
            "SESSION HIJACKING:\n"
            "  - XSS → steal session cookie\n"
            "  - Network sniffing (no HTTPS)\n"
            "  - Predictable session IDs\n"
            "  - Side-jacking (Firesheep-style)\n"
            "COOKIE ISSUES:\n"
            "  - Missing Secure flag\n"
            "  - Missing HttpOnly flag\n"
            "  - Missing SameSite attribute\n"
            "  - Overly long expiration\n"
            "  - Domain scope too broad\n"
            "  - Path scope too broad\n"
            "JWT ATTACKS:\n"
            "  - Algorithm confusion (RS256→HS256)\n"
            "  - None algorithm\n"
            "  - Weak signing key\n"
            "  - Missing expiration\n"
            "  - Missing signature verification\n"
            "  - jku/jwk header injection\n"
            "  # jwt_tool\n"
            "  python3 jwt_tool.py TOKEN -T\n"
            "  python3 jwt_tool.py TOKEN -X a  # alg confusion\n"
            "  python3 jwt_tool.py TOKEN -C -d wordlist.txt  # crack\n"
            "TOOLS:\n"
            "  jwt_tool, Burp Suite, cookie editors"
        ),
        "tools": ["jwt_tool"],
    },
    {
        "id": "auth-004", "name": "OAuth/SAML Attacks",
        "category": "oauth_saml", "severity": "critical",
        "desc": "OAuth and SAML protocol attacks.",
        "detection": (
            "OAUTH/SAML ATTACKS:\n"
            "OAUTH:\n"
            "  - Authorization code interception\n"
            "  - CSRF on callback URL\n"
            "  - Open redirect in redirect_uri\n"
            "  - Scope manipulation\n"
            "  - Token leakage (Referer header)\n"
            "  - Client secret exposure\n"
            "  - PKCE bypass\n"
            "  - Token endpoint brute force\n"
            "  CHECK:\n"
            "    - Is redirect_uri validated strictly?\n"
            "    - Is state parameter used (CSRF)?\n"
            "    - Is PKCE enforced?\n"
            "    - Are tokens properly scoped?\n"
            "SAML:\n"
            "  - XML Signature Wrapping (XSW)\n"
            "  - Assertion replay\n"
            "  - SAML assertion forging\n"
            "  - Comment injection in NameID\n"
            "  - Signature exclusion\n"
            "  - Recipient validation bypass\n"
            "  CHECK:\n"
            "    - Signature validation strict?\n"
            "    - Assertion expiry checked?\n"
            "    - Audience restriction enforced?\n"
            "    - InResponseTo verified?\n"
            "OPENID CONNECT:\n"
            "  - ID token substitution\n"
            "  - Nonce not verified\n"
            "  - Discovery endpoint manipulation\n"
            "  - Dynamic registration abuse\n"
            "TOOLS:\n"
            "  Burp Suite, SAMLRaider, EvilSAML"
        ),
        "tools": [],
    },
    {
        "id": "auth-005", "name": "SSO and Federation Attacks",
        "category": "sso", "severity": "critical",
        "desc": "SSO and federation attacks.",
        "detection": (
            "SSO & FEDERATION ATTACKS:\n"
            "SSO BYPASS:\n"
            "  - Direct endpoint access\n"
            "  - API endpoints without SSO\n"
            "  - Legacy authentication fallback\n"
            "  - Local account alongside SSO\n"
            "  - Admin panel separate auth\n"
            "GOLDEN SAML:\n"
            "  - Steal ADFS signing certificate\n"
            "  - Forge any SAML assertion\n"
            "  - Access any federated service\n"
            "  - Solorigate/SolarWinds technique\n"
            "  # mimikatz\n"
            "  # ADFSDump (extract signing cert)\n"
            "PASS-THE-COOKIE:\n"
            "  - Steal browser cookies\n"
            "  - Replay SSO session\n"
            "  - Bypass all MFA\n"
            "  - Works with Azure AD, Okta, etc.\n"
            "DEVICE CODE PHISHING:\n"
            "  - Azure AD device code flow\n"
            "  - Attacker initiates device login\n"
            "  - Victim enters code on attacker's behalf\n"
            "  - Attacker gets full access token\n"
            "FEDERATION:\n"
            "  - Trust relationship abuse\n"
            "  - Tenant misconfiguration\n"
            "  - Cross-tenant access\n"
            "  - B2B/B2C confusion\n"
            "  - External identity provider abuse\n"
            "TOOLS:\n"
            "  mimikatz, ADFSDump, ROADtools"
        ),
        "tools": ["mimikatz"],
    },
]


class AuthenticationKB:
    """Authentication attacks knowledge base.

    Provides authentication attack patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, AuthPattern] = {}
        self._log = logger.bind(component="auth_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load authentication patterns."""
        for data in AUTH_PATTERNS:
            pattern = AuthPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "critical"),
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
        """Build authentication attacks prompt."""
        lines = ["## Authentication Attacks\n"]
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
