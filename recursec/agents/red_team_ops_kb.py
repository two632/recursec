"""Red team operations knowledge base.

Deep knowledge about red team methodology:
1. Red team planning and scoping
2. Initial access techniques
3. Command and control (C2)
4. Data exfiltration
5. Adversary simulation frameworks
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class RedTeamPattern:
    """A red team operations pattern."""
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


RED_TEAM_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "rt-001", "name": "Red Team Planning",
        "category": "planning", "severity": "high",
        "desc": "Red team engagement planning and methodology.",
        "detection": (
            "RED TEAM PLANNING:\n"
            "ENGAGEMENT TYPES:\n"
            "  - Full scope (assume breach, external, internal)\n"
            "  - Objective-based (specific goals)\n"
            "  - Purple team (collaborative with defenders)\n"
            "  - Adversary simulation (emulate specific APT)\n"
            "PHASES:\n"
            "  1. Reconnaissance (passive + active)\n"
            "  2. Initial access (phishing, external exploit)\n"
            "  3. Execution (run payload on target)\n"
            "  4. Persistence (survive reboots)\n"
            "  5. Privilege escalation (user → admin → system)\n"
            "  6. Defense evasion (bypass AV/EDR)\n"
            "  7. Discovery (enumerate internal)\n"
            "  8. Lateral movement (pivot to other systems)\n"
            "  9. Collection (gather target data)\n"
            "  10. Exfiltration (extract data)\n"
            "  11. Impact (demonstrate objective)\n"
            "RULES OF ENGAGEMENT:\n"
            "  - Scope (IP ranges, domains, off-limits)\n"
            "  - Timing (business hours, maintenance windows)\n"
            "  - Deconfliction (emergency contacts)\n"
            "  - Evidence handling\n"
            "  - Reporting cadence\n"
            "FRAMEWORKS:\n"
            "  MITRE ATT&CK, Unified Kill Chain, Diamond Model"
        ),
        "tools": [],
    },
    {
        "id": "rt-002", "name": "Initial Access",
        "category": "initial_access", "severity": "critical",
        "desc": "Red team initial access techniques.",
        "detection": (
            "INITIAL ACCESS:\n"
            "PHISHING:\n"
            "  - Spearphishing attachment (macro-enabled docs)\n"
            "  - Spearphishing link (credential harvest)\n"
            "  - QR phishing (quishing)\n"
            "  - Callback phishing (BazarCall)\n"
            "  - Infrastructure: GoPhish, Evilginx2, Modlishka\n"
            "  - Payload: Office macros, ISO/LNK, OneNote\n"
            "  - Delivery: typosquatting, lookalike domains\n"
            "EXTERNAL EXPLOITATION:\n"
            "  - VPN appliance vulns (Pulse Secure, Fortinet, Citrix)\n"
            "  - Exchange Server (ProxyLogon, ProxyShell)\n"
            "  - Web application vulnerabilities\n"
            "  - Exposed management interfaces\n"
            "  - Default credentials on internet-facing services\n"
            "SUPPLY CHAIN:\n"
            "  - Compromise software update mechanism\n"
            "  - Typosquatting packages (npm, PyPI)\n"
            "  - Compromise CI/CD pipeline\n"
            "  - Third-party vendor access\n"
            "PHYSICAL:\n"
            "  - Dropped USB devices\n"
            "  - Rogue device placement\n"
            "  - Badge cloning → physical access\n"
            "  - Social engineering at front desk\n"
            "TOOLS:\n"
            "  GoPhish, Evilginx2, CoerceAndCatch"
        ),
        "tools": ["gophish", "evilginx2"],
    },
    {
        "id": "rt-003", "name": "Command and Control",
        "category": "c2", "severity": "critical",
        "desc": "C2 frameworks and communication channels.",
        "detection": (
            "COMMAND AND CONTROL:\n"
            "C2 FRAMEWORKS:\n"
            "  - Cobalt Strike (commercial, most mature)\n"
            "  - Sliver (open-source, Go-based)\n"
            "  - Havoc (open-source, modern)\n"
            "  - Mythic (open-source, multi-agent)\n"
            "  - Covenant (C#, .NET)\n"
            "  - Brute Ratel (commercial, EDR evasion)\n"
            "  - Nighthawk (commercial)\n"
            "COMMUNICATION CHANNELS:\n"
            "  - HTTPS (most common, blends with traffic)\n"
            "  - DNS (slow but stealthy)\n"
            "  - SMB named pipes (internal lateral)\n"
            "  - DoH/DoT (encrypted DNS)\n"
            "  - WebSocket\n"
            "  - Cloud services (Azure, AWS, GCP)\n"
            "EVASION:\n"
            "  - Domain fronting (CDN abuse)\n"
            "  - Redirectors (Apache mod_rewrite)\n"
            "  - Malleable C2 profiles (Cobalt Strike)\n"
            "  - Jitter and sleep (irregular callbacks)\n"
            "  - Kill dates\n"
            "  - Peer-to-peer (SMB, TCP)\n"
            "INFRASTRUCTURE:\n"
            "  - Short-lived VPS (Vultr, DigitalOcean)\n"
            "  - CDN fronting\n"
            "  - Categorized domains (reputable)\n"
            "  - HTTPS certificates (Let's Encrypt)\n"
            "  - Redirector chains\n"
            "TOOLS:\n"
            "  Sliver, Mythic, Havoc, Cobalt Strike"
        ),
        "tools": ["sliver", "mythic", "havoc"],
    },
    {
        "id": "rt-004", "name": "Data Exfiltration",
        "category": "exfiltration", "severity": "critical",
        "desc": "Data exfiltration techniques.",
        "detection": (
            "DATA EXFILTRATION:\n"
            "NETWORK:\n"
            "  - HTTPS POST to external server\n"
            "  - DNS exfiltration (encode in subdomains)\n"
            "  - ICMP tunneling\n"
            "  - Steganography in images\n"
            "  - Cloud storage (S3, Azure Blob)\n"
            "  - Email (SMTP, Exchange)\n"
            "  - Protocol tunneling (DNS, HTTPS, WebSocket)\n"
            "ENCODING:\n"
            "  - Base64/Base32\n"
            "  - Hex encoding\n"
            "  - Custom XOR cipher\n"
            "  - Compression + encryption (AES)\n"
            "  - Chunked transfer\n"
            "STAGING:\n"
            "  - Compress and encrypt before exfil\n"
            "  - Split into chunks\n"
            "  - Stage in temp directories\n"
            "  - Password-protected archives\n"
            "  - Use legitimate backup tools\n"
            "COVERT CHANNELS:\n"
            "  - Timing-based (packet delays)\n"
            "  - Storage-based (unused header fields)\n"
            "  - TCP ISN covert channel\n"
            "  - DNS TXT records\n"
            "  - Social media (Twitter, Pastebin)\n"
            "TOOLS:\n"
            "  dnscat2, iodine, rclone, DNSExfiltrator"
        ),
        "tools": ["dnscat2", "iodine"],
    },
    {
        "id": "rt-005", "name": "Adversary Simulation",
        "category": "adversary_sim", "severity": "high",
        "desc": "Adversary simulation and emulation frameworks.",
        "detection": (
            "ADVERSARY SIMULATION:\n"
            "APT EMULATION:\n"
            "  - MITRE ATT&CK Navigator (coverage mapping)\n"
            "  - MITRE Caldera (automated adversary emulation)\n"
            "  - Atomic Red Team (atomic tests per technique)\n"
            "  - APTSimulator (quick APT behavior simulation)\n"
            "THREAT INTELLIGENCE:\n"
            "  - Map real APT TTPs to ATT&CK\n"
            "  - Replicate specific campaign tradecraft\n"
            "  - Use published threat reports as playbooks\n"
            "  - MITRE ATT&CK Groups (APT28, APT29, etc.)\n"
            "TESTING:\n"
            "  - Detection coverage (which techniques trigger alerts?)\n"
            "  - Response time (MTTD, MTTR)\n"
            "  - Analyst capability (can they investigate?)\n"
            "  - Tool effectiveness (EDR, SIEM, NDR)\n"
            "METRICS:\n"
            "  - Techniques tested vs detected\n"
            "  - Time to detect per technique\n"
            "  - False positive rate\n"
            "  - SOC analyst response quality\n"
            "  - Remediation effectiveness\n"
            "PLATFORMS:\n"
            "  MITRE Caldera, AttackIQ, SafeBreach, Randori"
        ),
        "tools": ["caldera", "atomic-red-team"],
    },
]


class RedTeamOpsKB:
    """Red team operations knowledge base.

    Provides red team methodology patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, RedTeamPattern] = {}
        self._log = logger.bind(component="red_team_ops_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load red team patterns."""
        for data in RED_TEAM_PATTERNS:
            pattern = RedTeamPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "critical"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[RedTeamPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_redteam_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build red team operations prompt."""
        lines = ["## Red Team Operations\n"]
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
