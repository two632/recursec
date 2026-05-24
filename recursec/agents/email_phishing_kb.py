"""Email and phishing security knowledge base.

Deep knowledge about email security:
1. Email infrastructure assessment
2. Phishing detection and analysis
3. Email spoofing techniques
4. Email header analysis
5. Business email compromise
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class EmailPattern:
    """An email security pattern."""
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


EMAIL_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "email-001", "name": "Email Infrastructure",
        "category": "infrastructure", "severity": "medium",
        "desc": "Email infrastructure assessment.",
        "detection": (
            "EMAIL INFRASTRUCTURE:\n"
            "DNS RECORDS:\n"
            "  - MX records\n"
            "    # dig MX domain.com\n"
            "  - SPF record\n"
            "    # dig TXT domain.com\n"
            "    # Check: v=spf1 ... -all\n"
            "    # Common misconfig: ~all (softfail)\n"
            "    # Worst: no SPF record\n"
            "  - DKIM\n"
            "    # dig TXT selector._domainkey.domain.com\n"
            "    # Check key strength (RSA 2048+)\n"
            "  - DMARC\n"
            "    # dig TXT _dmarc.domain.com\n"
            "    # Check: p=reject (strongest)\n"
            "    # Common misconfig: p=none (monitor only)\n"
            "    # Check rua/ruf reporting\n"
            "  - MTA-STS\n"
            "    # dig TXT _mta-sts.domain.com\n"
            "    # Check /.well-known/mta-sts.txt\n"
            "  - DANE/TLSA\n"
            "    # dig TLSA _25._tcp.mail.domain.com\n"
            "STARTTLS:\n"
            "  - Test SMTP STARTTLS\n"
            "    # openssl s_client -starttls smtp -connect mail:25\n"
            "  - Certificate validation\n"
            "  - Cipher suite analysis\n"
            "OPEN RELAY:\n"
            "  - Test for open relay\n"
            "    # nmap --script smtp-open-relay\n"
            "  - VRFY/EXPN enumeration\n"
            "    # nmap --script smtp-enum-users\n"
            "TOOLS:\n"
            "  nmap, testssl.sh, mxtoolbox, checkdmarc"
        ),
        "tools": [],
    },
    {
        "id": "email-002", "name": "Phishing Detection",
        "category": "phishing", "severity": "high",
        "desc": "Phishing analysis and detection.",
        "detection": (
            "PHISHING DETECTION:\n"
            "URL ANALYSIS:\n"
            "  - Suspicious domains\n"
            "    # Typosquatting (gooqle.com)\n"
            "    # Homograph (gооgle with Cyrillic)\n"
            "    # Subdomain abuse (login.google.evil.com)\n"
            "    # URL shorteners\n"
            "  - Redirect chains\n"
            "  - JavaScript-based redirects\n"
            "  - Open redirects abuse\n"
            "ATTACHMENT ANALYSIS:\n"
            "  - Macro-enabled documents (.docm, .xlsm)\n"
            "  - Embedded OLE objects\n"
            "  - Password-protected archives\n"
            "  - Double extensions (report.pdf.exe)\n"
            "  - ISO/IMG/VHD containers\n"
            "  - HTML smuggling\n"
            "  - OneNote attachments\n"
            "HEADER INDICATORS:\n"
            "  - Envelope-From mismatch\n"
            "  - Reply-To different from From\n"
            "  - X-Originating-IP analysis\n"
            "  - Authentication-Results\n"
            "  - Received chain analysis\n"
            "CONTENT:\n"
            "  - Urgency language\n"
            "  - Impersonation indicators\n"
            "  - Suspicious call-to-action\n"
            "  - Brand impersonation\n"
            "TOOLS:\n"
            "  PhishTool, URLscan, VirusTotal, oletools"
        ),
        "tools": [],
    },
    {
        "id": "email-003", "name": "Email Spoofing",
        "category": "spoofing", "severity": "high",
        "desc": "Email spoofing techniques.",
        "detection": (
            "EMAIL SPOOFING:\n"
            "TECHNIQUES:\n"
            "  - Direct spoofing (no SPF/DMARC)\n"
            "  - Subdomain spoofing\n"
            "    # Spoof sub.domain.com if no SPF\n"
            "  - Display name spoofing\n"
            "    # From: CEO Name <attacker@evil.com>\n"
            "  - Look-alike domains\n"
            "    # domain.com → doma1n.com\n"
            "  - Cousin domains\n"
            "    # company-secure.com\n"
            "  - Reply-To manipulation\n"
            "  - ARC (Authenticated Received Chain) abuse\n"
            "SPF BYPASS:\n"
            "  - Include over-permissive IP ranges\n"
            "  - +all or ?all policies\n"
            "  - DNS lookup limit (>10 lookups)\n"
            "  - Void lookups\n"
            "  - Include chain abuse\n"
            "DKIM BYPASS:\n"
            "  - Key reuse/theft\n"
            "  - l= tag abuse (body length)\n"
            "  - Replay attacks\n"
            "  - Selector enumeration\n"
            "DMARC BYPASS:\n"
            "  - p=none (no enforcement)\n"
            "  - Organizational domain mismatch\n"
            "  - Subdomain policy (sp=none)\n"
            "  - Third-party sender issues\n"
            "TOOLS:\n"
            "  swaks, SET, GoPhish, King Phisher"
        ),
        "tools": [],
    },
    {
        "id": "email-004", "name": "Email Header Analysis",
        "category": "headers", "severity": "medium",
        "desc": "Email header forensics.",
        "detection": (
            "EMAIL HEADER ANALYSIS:\n"
            "RECEIVED CHAIN:\n"
            "  - Read bottom-to-top\n"
            "  - Verify each hop\n"
            "  - Check for forgery\n"
            "  - Identify origin IP\n"
            "  - Timestamp analysis\n"
            "AUTHENTICATION HEADERS:\n"
            "  Authentication-Results:\n"
            "    # spf=pass/fail\n"
            "    # dkim=pass/fail\n"
            "    # dmarc=pass/fail\n"
            "    # compauth=pass/fail (composite)\n"
            "  ARC-Authentication-Results:\n"
            "    # For forwarded messages\n"
            "X-HEADERS:\n"
            "  X-Originating-IP:\n"
            "    # Sender's actual IP\n"
            "  X-Mailer:\n"
            "    # Email client identification\n"
            "  X-Spam-Status:\n"
            "    # Spam filter results\n"
            "  X-MS-Exchange-*:\n"
            "    # Exchange-specific headers\n"
            "MESSAGE-ID:\n"
            "  - Format analysis\n"
            "  - Domain correlation\n"
            "  - Timestamp extraction\n"
            "CONTENT-TYPE:\n"
            "  - MIME boundary analysis\n"
            "  - Charset indicators\n"
            "  - Multipart structure\n"
            "  - Embedded content\n"
            "TOOLS:\n"
            "  MHA (Message Header Analyzer), mxtoolbox"
        ),
        "tools": [],
    },
    {
        "id": "email-005", "name": "Business Email Compromise",
        "category": "bec", "severity": "critical",
        "desc": "BEC detection and prevention.",
        "detection": (
            "BUSINESS EMAIL COMPROMISE:\n"
            "BEC TYPES:\n"
            "  1. CEO fraud\n"
            "    # Impersonate executive\n"
            "    # Urgent wire transfer request\n"
            "  2. Account compromise\n"
            "    # Hacked email account\n"
            "    # Invoice redirection\n"
            "  3. Vendor impersonation\n"
            "    # Fake vendor invoices\n"
            "    # Updated payment details\n"
            "  4. Attorney impersonation\n"
            "    # Legal urgency\n"
            "    # Confidentiality pressure\n"
            "  5. Data theft\n"
            "    # HR/payroll targeting\n"
            "    # W-2/tax form requests\n"
            "INDICATORS:\n"
            "  - Unusual payment requests\n"
            "  - Urgency + secrecy\n"
            "  - Changed payment details\n"
            "  - Free email domains\n"
            "  - Unusual sender behavior\n"
            "  - Domain impersonation\n"
            "PREVENTION:\n"
            "  - DMARC enforcement (p=reject)\n"
            "  - Display name checks\n"
            "  - Payment verification procedures\n"
            "  - Conditional access policies\n"
            "  - Mailbox audit logging\n"
            "  - Impossible travel detection\n"
            "TOOLS:\n"
            "  Microsoft Defender, Proofpoint, Abnormal"
        ),
        "tools": [],
    },
]


class EmailPhishingKB:
    """Email and phishing security knowledge base.

    Provides email security patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, EmailPattern] = {}
        self._log = logger.bind(component="email_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load email patterns."""
        for data in EMAIL_PATTERNS:
            pattern = EmailPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[EmailPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_email_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build email security prompt."""
        lines = ["## Email Security\n"]
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
