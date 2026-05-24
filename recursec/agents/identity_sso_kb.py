"""Identity and SSO security knowledge base.

Deep knowledge about identity security:
1. SAML attacks
2. OAuth/OIDC attacks
3. LDAP security
4. Kerberos attacks
5. MFA bypass techniques
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class IdentityPattern:
    """An identity security pattern."""
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


IDENTITY_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "id-001", "name": "SAML Attacks",
        "category": "saml", "severity": "critical",
        "desc": "SAML authentication attacks.",
        "detection": (
            "SAML ATTACKS:\n"
            "XML SIGNATURE WRAPPING:\n"
            "  - Move signed element\n"
            "  - Insert malicious assertion\n"
            "  - Clone signed assertion\n"
            "  - XSW1-8 variants\n"
            "  # SAMLRaider Burp extension\n"
            "SIGNATURE BYPASS:\n"
            "  - Remove signature entirely\n"
            "  - Change algorithm to None\n"
            "  - Use self-signed certificate\n"
            "  - Comment injection in NameID\n"
            "    # user@evil.com<!---->@victim.com\n"
            "ASSERTION ATTACKS:\n"
            "  - Assertion replay\n"
            "  - NotBefore/NotOnOrAfter bypass\n"
            "  - Audience restriction bypass\n"
            "  - InResponseTo manipulation\n"
            "  - Subject confirmation bypass\n"
            "XXE IN SAML:\n"
            "  - XXE in SAML request/response\n"
            "  - SSRF via XXE\n"
            "  - File read via XXE\n"
            "  - Billion laughs DoS\n"
            "GOLDEN SAML:\n"
            "  - Steal ADFS token signing cert\n"
            "  - Forge any SAML assertion\n"
            "  - Persistent access\n"
            "TOOLS:\n"
            "  SAMLRaider, Burp, saml2aws, shimit"
        ),
        "tools": [],
    },
    {
        "id": "id-002", "name": "OAuth/OIDC Attacks",
        "category": "oauth", "severity": "critical",
        "desc": "OAuth 2.0 and OIDC attack techniques.",
        "detection": (
            "OAUTH/OIDC ATTACKS:\n"
            "REDIRECT URI:\n"
            "  - Open redirect in callback\n"
            "    # redirect_uri=https://evil.com\n"
            "    # Path traversal in URI\n"
            "    # Subdomain matching bypass\n"
            "    # Fragment injection\n"
            "  - Authorization code theft\n"
            "CSRF:\n"
            "  - Missing state parameter\n"
            "  - Predictable state\n"
            "  - State not bound to session\n"
            "TOKEN ATTACKS:\n"
            "  - Token leakage (Referer)\n"
            "  - Token in URL fragment\n"
            "  - Implicit flow token theft\n"
            "  - Token replay\n"
            "  - Refresh token abuse\n"
            "  - JWT attacks (see JWT KB)\n"
            "PKCE BYPASS:\n"
            "  - Missing code_challenge\n"
            "  - Downgrade to non-PKCE flow\n"
            "  - code_verifier brute force\n"
            "OIDC SPECIFIC:\n"
            "  - ID token manipulation\n"
            "  - Nonce replay\n"
            "  - Claim injection\n"
            "  - Dynamic client registration\n"
            "  - .well-known/openid-configuration\n"
            "TOOLS:\n"
            "  Burp, EsPReSSO, jwt_tool"
        ),
        "tools": [],
    },
    {
        "id": "id-003", "name": "LDAP Security",
        "category": "ldap", "severity": "high",
        "desc": "LDAP security assessment.",
        "detection": (
            "LDAP SECURITY:\n"
            "ENUMERATION:\n"
            "  - Anonymous bind\n"
            "    # ldapsearch -x -H ldap://DC -b DC=domain,DC=com\n"
            "  - Null base DN query\n"
            "  - RootDSE query\n"
            "  - Schema enumeration\n"
            "INJECTION:\n"
            "  - LDAP injection\n"
            "    # (&(uid=USER)(password=*))\n"
            "    # )(|(uid=*)(password=*))\n"
            "    # Wildcard injection\n"
            "  - Blind LDAP injection\n"
            "    # Boolean-based\n"
            "    # Time-based\n"
            "  - DN injection\n"
            "CREDENTIAL ATTACKS:\n"
            "  - Pass-back attack\n"
            "    # Redirect LDAP auth to attacker\n"
            "  - Cleartext LDAP (port 389)\n"
            "  - Credential relay\n"
            "  - Password spray via LDAP\n"
            "ACTIVE DIRECTORY LDAP:\n"
            "  - SPNs enumeration\n"
            "    # Kerberoasting targets\n"
            "  - Domain trusts\n"
            "  - Group policy objects\n"
            "  - Delegation settings\n"
            "  - AdminSDHolder\n"
            "TOOLS:\n"
            "  ldapsearch, ldapdomaindump, BloodHound"
        ),
        "tools": [],
    },
    {
        "id": "id-004", "name": "Kerberos Attacks",
        "category": "kerberos", "severity": "critical",
        "desc": "Kerberos attack techniques.",
        "detection": (
            "KERBEROS ATTACKS:\n"
            "KERBEROASTING:\n"
            "  # GetUserSPNs.py DOMAIN/user:pass -dc-ip DC\n"
            "  # Request TGS tickets for SPNs\n"
            "  # Crack offline with hashcat\n"
            "  # hashcat -m 13100 ticket.hash wordlist\n"
            "AS-REP ROASTING:\n"
            "  # Users with DONT_REQUIRE_PREAUTH\n"
            "  # GetNPUsers.py DOMAIN/ -dc-ip DC -no-pass\n"
            "  # hashcat -m 18200\n"
            "PASS THE TICKET:\n"
            "  # Export ticket: sekurlsa::tickets /export\n"
            "  # Inject ticket: kerberos::ptt ticket.kirbi\n"
            "GOLDEN TICKET:\n"
            "  # Need krbtgt hash\n"
            "  # mimikatz: kerberos::golden /user:admin\n"
            "  #   /domain:DOMAIN /sid:S-1-5-... /krbtgt:HASH\n"
            "  # Unlimited domain access\n"
            "SILVER TICKET:\n"
            "  # Need service account hash\n"
            "  # Forge TGS for specific service\n"
            "  # No DC contact needed\n"
            "DELEGATION:\n"
            "  - Unconstrained delegation\n"
            "    # TGT stored on server\n"
            "    # Coerce auth → steal TGT\n"
            "  - Constrained delegation\n"
            "    # S4U2self + S4U2proxy\n"
            "  - Resource-based (RBCD)\n"
            "    # Add computer → RBCD\n"
            "TOOLS:\n"
            "  Impacket, Rubeus, mimikatz, BloodHound"
        ),
        "tools": [],
    },
    {
        "id": "id-005", "name": "MFA Bypass Techniques",
        "category": "mfa", "severity": "critical",
        "desc": "Multi-factor authentication bypass.",
        "detection": (
            "MFA BYPASS TECHNIQUES:\n"
            "PHISHING:\n"
            "  - Real-time phishing proxy\n"
            "    # evilginx2, Modlishka\n"
            "    # Capture MFA token in real-time\n"
            "    # Session cookie theft\n"
            "  - AitM (Adversary-in-the-Middle)\n"
            "TOKEN BYPASS:\n"
            "  - MFA fatigue (push spam)\n"
            "    # Send many push notifications\n"
            "    # User approves out of fatigue\n"
            "  - OTP brute force\n"
            "    # 6-digit = 1M combinations\n"
            "    # Rate limiting check\n"
            "  - OTP reuse (no one-time check)\n"
            "  - Backup code theft\n"
            "IMPLEMENTATION:\n"
            "  - MFA not enforced on all flows\n"
            "    # API endpoints without MFA\n"
            "    # Legacy auth protocols\n"
            "    # Mobile app bypass\n"
            "  - Remember device token theft\n"
            "  - Step-up auth bypass\n"
            "  - Registration flow hijack\n"
            "SESSION:\n"
            "  - Session hijacking post-MFA\n"
            "  - Token theft (cookie/JWT)\n"
            "  - Session fixation pre-MFA\n"
            "RECOVERY:\n"
            "  - Recovery flow bypass\n"
            "  - SMS interception (SIM swap)\n"
            "  - Voicemail access (OTP)\n"
            "TOOLS:\n"
            "  evilginx2, Modlishka, muraena"
        ),
        "tools": [],
    },
]


class IdentitySSOKB:
    """Identity and SSO security knowledge base.

    Provides identity/SSO patterns injected
    into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, IdentityPattern] = {}
        self._log = logger.bind(component="identity_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load identity patterns."""
        for data in IDENTITY_PATTERNS:
            pattern = IdentityPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "critical"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[IdentityPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_identity_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build identity security prompt."""
        lines = ["## Identity & SSO Security\n"]
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
