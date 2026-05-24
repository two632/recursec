"""Evasion techniques knowledge base.

Deep knowledge about detection evasion:
1. AV/EDR evasion techniques
2. WAF bypass techniques
3. IDS/IPS evasion
4. Log evasion and cleanup
5. Network detection evasion
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class EvasionPattern:
    """An evasion technique pattern."""
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


EVASION_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "ev-001", "name": "AV/EDR Evasion",
        "category": "av_edr", "severity": "high",
        "desc": "Antivirus and EDR evasion.",
        "detection": (
            "AV/EDR EVASION:\n"
            "PAYLOAD MODIFICATION:\n"
            "  - Obfuscation\n"
            "    # String encryption\n"
            "    # Control flow flattening\n"
            "    # Dead code insertion\n"
            "    # Variable renaming\n"
            "  - Encoding\n"
            "    # XOR encoding (single/multi-byte)\n"
            "    # AES encryption with runtime decrypt\n"
            "    # Custom encoding schemes\n"
            "  - Packing\n"
            "    # UPX (detectable)\n"
            "    # Custom packers\n"
            "    # Process hollowing\n"
            "EXECUTION:\n"
            "  - Process injection\n"
            "    # Classic DLL injection\n"
            "    # Reflective DLL injection\n"
            "    # Process hollowing\n"
            "    # Thread hijacking\n"
            "    # APC injection\n"
            "  - Living off the Land (LOLBins)\n"
            "    # mshta, certutil, regsvr32\n"
            "    # msbuild, installutil\n"
            "    # wmic, rundll32\n"
            "    # powershell -enc BASE64\n"
            "  - AMSI bypass\n"
            "    # Patch amsi.dll in memory\n"
            "    # CLM bypass\n"
            "DETECTION CHECK:\n"
            "  # Upload to antiscan.me (not VT)\n"
            "  # Test against Defender, CrowdStrike\n"
            "TOOLS:\n"
            "  Donut, ScareCrow, Nimcrypt2, PEzor"
        ),
        "tools": [],
    },
    {
        "id": "ev-002", "name": "WAF Bypass Techniques",
        "category": "waf", "severity": "high",
        "desc": "Web application firewall bypass.",
        "detection": (
            "WAF BYPASS:\n"
            "ENCODING:\n"
            "  - URL encoding (double, triple)\n"
            "    # %27 → %2527 → %252527\n"
            "  - Unicode/UTF-8 encoding\n"
            "    # \\u0027, \\xE2\\x80\\x99\n"
            "  - HTML entity encoding\n"
            "    # &#39; &#x27;\n"
            "  - Base64 encoding\n"
            "  - Mixed encodings\n"
            "SQL INJECTION WAF BYPASS:\n"
            "  - Comment insertion\n"
            "    # SEL/**/ECT, UN/**/ION\n"
            "  - Case alternation\n"
            "    # SeLeCt, uNiOn\n"
            "  - Alternative syntax\n"
            "    # group_concat, substring, mid\n"
            "  - Whitespace alternatives\n"
            "    # \\t, \\n, /**/, +(MySQL)\n"
            "  - String concatenation\n"
            "    # 'ad'||'min', CONCAT('a','b')\n"
            "XSS WAF BYPASS:\n"
            "  - Event handlers\n"
            "    # onerror, onload, onfocus\n"
            "  - SVG/MathML tags\n"
            "  - Template literals\n"
            "  - JavaScript protocol\n"
            "  - Data URIs\n"
            "PROTOCOL LEVEL:\n"
            "  - HTTP/2 specific bypasses\n"
            "  - Chunked transfer encoding\n"
            "  - Content-Type manipulation\n"
            "  - HTTP parameter pollution\n"
            "TOOLS:\n"
            "  WAFNinja, WAFw00f, sqlmap tamper scripts"
        ),
        "tools": [],
    },
    {
        "id": "ev-003", "name": "IDS/IPS Evasion",
        "category": "ids_ips", "severity": "high",
        "desc": "IDS/IPS detection evasion.",
        "detection": (
            "IDS/IPS EVASION:\n"
            "FRAGMENTATION:\n"
            "  - IP fragmentation\n"
            "    # nmap -f (fragment packets)\n"
            "    # fragroute\n"
            "  - TCP segmentation\n"
            "    # Small TCP segments\n"
            "    # Out-of-order reassembly\n"
            "  - Overlapping fragments\n"
            "    # Different reassembly policies\n"
            "TIMING:\n"
            "  - Slow scanning\n"
            "    # nmap -T0 (paranoid), -T1 (sneaky)\n"
            "  - Randomized delays\n"
            "  - Time-based evasion\n"
            "    # Spread across hours/days\n"
            "OBFUSCATION:\n"
            "  - Encrypted payloads\n"
            "    # TLS/SSL encapsulation\n"
            "    # SSH tunneling\n"
            "  - Protocol misuse\n"
            "    # DNS tunneling\n"
            "    # ICMP tunneling\n"
            "    # HTTP within HTTPS\n"
            "  - Decoy traffic\n"
            "    # nmap -D decoy1,decoy2\n"
            "    # Noise generation\n"
            "SOURCE MANIPULATION:\n"
            "  - IP spoofing\n"
            "  - MAC spoofing\n"
            "  - Proxy chains\n"
            "  - Tor/VPN\n"
            "TOOLS:\n"
            "  fragroute, nmap, hping3, tcpreplay"
        ),
        "tools": [],
    },
    {
        "id": "ev-004", "name": "Log Evasion and Cleanup",
        "category": "log_evasion", "severity": "high",
        "desc": "Log manipulation and cleanup.",
        "detection": (
            "LOG EVASION:\n"
            "WINDOWS:\n"
            "  Event Logs:\n"
            "    # wevtutil cl Security\n"
            "    # wevtutil cl System\n"
            "    # wevtutil cl Application\n"
            "  Selective Deletion:\n"
            "    # Mimikatz event:drop\n"
            "    # Phantom (thread suspension)\n"
            "    # EventLogCleaner (specific events)\n"
            "  Anti-logging:\n"
            "    # Disable ETW tracing\n"
            "    # Patch EventWrite in ntdll\n"
            "    # Suspend Event Log service\n"
            "LINUX:\n"
            "  Log Files:\n"
            "    # /var/log/auth.log\n"
            "    # /var/log/syslog\n"
            "    # /var/log/apache2/access.log\n"
            "    # ~/.bash_history\n"
            "  Techniques:\n"
            "    # shred -zu /var/log/auth.log\n"
            "    # echo > /var/log/syslog\n"
            "    # unset HISTFILE\n"
            "    # export HISTSIZE=0\n"
            "    # ln -sf /dev/null ~/.bash_history\n"
            "  Timestomping:\n"
            "    # touch -t YYYYMMDD file\n"
            "    # debugfs (ext4)\n"
            "DETECTION:\n"
            "  - Forward logs to SIEM\n"
            "  - Immutable log storage\n"
            "  - File integrity monitoring\n"
            "  - Log gap detection\n"
            "TOOLS:\n"
            "  Phantom, Mimikatz, wevtutil, shred"
        ),
        "tools": [],
    },
    {
        "id": "ev-005", "name": "Network Detection Evasion",
        "category": "network_evasion", "severity": "high",
        "desc": "Network monitoring evasion.",
        "detection": (
            "NETWORK DETECTION EVASION:\n"
            "C2 TECHNIQUES:\n"
            "  - Domain fronting\n"
            "    # Use CDN as cover\n"
            "    # Different Host header vs SNI\n"
            "  - DNS over HTTPS (DoH)\n"
            "    # Encapsulate DNS in HTTPS\n"
            "  - Legitimate services as C2\n"
            "    # Slack, Discord, Telegram bots\n"
            "    # Cloud storage (OneDrive, GDrive)\n"
            "    # GitHub/GitLab/Pastebin\n"
            "  - Malleable C2 profiles\n"
            "    # Mimic legitimate traffic\n"
            "    # Match known applications\n"
            "TRAFFIC BLENDING:\n"
            "  - HTTPS everywhere\n"
            "  - Mimic browser User-Agent\n"
            "  - Use common ports (80, 443)\n"
            "  - Jitter on beacon intervals\n"
            "  - Legitimate certificate (Let's Encrypt)\n"
            "DATA HIDING:\n"
            "  - Steganography in images\n"
            "  - Covert channels in protocols\n"
            "  - DNS CNAME/TXT records\n"
            "  - ICMP payload data\n"
            "INFRASTRUCTURE:\n"
            "  - Redirectors\n"
            "  - CDN fronting\n"
            "  - Cloud functions as relay\n"
            "  - Tor hidden services\n"
            "TOOLS:\n"
            "  Cobalt Strike, Empire, Sliver, Mythic"
        ),
        "tools": [],
    },
]


class EvasionKB:
    """Evasion techniques knowledge base.

    Provides evasion patterns injected
    into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, EvasionPattern] = {}
        self._log = logger.bind(component="evasion_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load evasion patterns."""
        for data in EVASION_PATTERNS:
            pattern = EvasionPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[EvasionPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_evasion_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build evasion prompt."""
        lines = ["## Evasion Techniques\n"]
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
