"""Red team operations knowledge base.

Deep knowledge about red team operations:
1. Initial access techniques
2. Command and control (C2)
3. Evasion and OPSEC
4. Adversary emulation
5. Purple team exercises
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


REDTEAM_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "rt-001", "name": "Initial Access Techniques",
        "category": "initial_access", "severity": "high",
        "desc": "Initial access techniques for red team.",
        "detection": (
            "INITIAL ACCESS:\n"
            "PHISHING:\n"
            "  - Macro-enabled documents\n"
            "    # VBA macros (.docm, .xlsm)\n"
            "    # Auto-execute (Document_Open)\n"
            "  - ISO/IMG containers (bypass MOTW)\n"
            "  - LNK files (shortcut abuse)\n"
            "  - HTML smuggling (JS drops payload)\n"
            "  - OneNote attachments (.one)\n"
            "  - Password-protected archives\n"
            "  # Delivery: GoPhish + Evilginx2\n"
            "EXTERNAL SERVICES:\n"
            "  - VPN exploitation (Pulse, Fortinet)\n"
            "  - RDP brute force / spray\n"
            "  - Exchange (ProxyLogon/ProxyShell)\n"
            "  - Citrix (CVE-2019-19781)\n"
            "  - Public-facing web apps\n"
            "SUPPLY CHAIN:\n"
            "  - Trusted relationship abuse\n"
            "  - SaaS OAuth app poisoning\n"
            "  - Partner portal compromise\n"
            "PHYSICAL:\n"
            "  - USB drop (Rubber Ducky)\n"
            "  - Evil twin WiFi\n"
            "  - Rogue network device\n"
            "  - Badge cloning\n"
            "CREDENTIAL:\n"
            "  - Password spraying (low-and-slow)\n"
            "  - Credential stuffing\n"
            "  - MFA bypass (SIM swap, fatigue)\n"
            "  - AitM (adversary-in-the-middle)\n"
            "TOOLS:\n"
            "  Cobalt Strike, Evilginx2, GoPhish, SET"
        ),
        "tools": [],
    },
    {
        "id": "rt-002", "name": "Command and Control (C2)",
        "category": "c2", "severity": "critical",
        "desc": "C2 infrastructure and techniques.",
        "detection": (
            "COMMAND AND CONTROL:\n"
            "C2 FRAMEWORKS:\n"
            "  - Cobalt Strike (commercial)\n"
            "    # Beacon: HTTP/S, DNS, SMB, TCP\n"
            "    # Malleable C2 profiles\n"
            "    # BOF (Beacon Object Files)\n"
            "  - Sliver (open-source, Go)\n"
            "    # mTLS, WireGuard, HTTP/S, DNS\n"
            "    # Implant generation\n"
            "    # Armory (extensions)\n"
            "  - Havoc (open-source, C)\n"
            "    # Demon agent\n"
            "    # Sleep obfuscation\n"
            "    # Indirect syscalls\n"
            "  - Mythic (open-source, modular)\n"
            "    # Container-based agents\n"
            "    # Custom C2 profiles\n"
            "EVASION:\n"
            "  - Domain fronting\n"
            "  - CDN-based C2\n"
            "  - DNS over HTTPS (DoH)\n"
            "  - Cloud service C2 (Azure, AWS, GCP)\n"
            "  - Social media C2 (Twitter, Telegram)\n"
            "  - Steganography C2\n"
            "INFRASTRUCTURE:\n"
            "  - Redirectors (Apache, Nginx, Cloudflare)\n"
            "  - Domain categorization\n"
            "  - Certificate management\n"
            "  - Aged domains\n"
            "  - Disposable infrastructure\n"
            "TOOLS:\n"
            "  Cobalt Strike, Sliver, Havoc, Mythic"
        ),
        "tools": [],
    },
    {
        "id": "rt-003", "name": "Evasion and OPSEC",
        "category": "evasion", "severity": "high",
        "desc": "Evasion and operational security.",
        "detection": (
            "EVASION & OPSEC:\n"
            "AV/EDR EVASION:\n"
            "  - AMSI bypass\n"
            "    # Patching amsi.dll in memory\n"
            "    # String obfuscation\n"
            "  - ETW bypass\n"
            "    # Patch EtwEventWrite\n"
            "  - Unhooking ntdll.dll\n"
            "    # Read fresh copy from disk\n"
            "    # Direct syscalls\n"
            "    # Indirect syscalls (Halo's Gate)\n"
            "  - Process injection techniques\n"
            "    # Early bird APC injection\n"
            "    # Process hollowing\n"
            "    # Module stomping\n"
            "    # Thread pool abuse\n"
            "  - Sleep obfuscation\n"
            "    # Ekko, Foliage, Cronos\n"
            "  - Payload encryption\n"
            "    # AES/RC4 encrypted shellcode\n"
            "    # XOR with rolling key\n"
            "LIVING-OFF-THE-LAND:\n"
            "  - PowerShell (constrained language)\n"
            "  - WMIC, CertUtil, BITSAdmin\n"
            "  - MSBuild, InstallUtil, RegSvr32\n"
            "  - Rundll32, MSHTA\n"
            "  # LOLBAS project\n"
            "  # GTFOBins (Linux)\n"
            "LOG EVASION:\n"
            "  - Timestomping\n"
            "  - Log clearing/modification\n"
            "  - Sysmon evasion\n"
            "  - Event log patching\n"
            "TOOLS:\n"
            "  ScareCrow, NimPackt, Donut, SharpC2"
        ),
        "tools": [],
    },
    {
        "id": "rt-004", "name": "Adversary Emulation",
        "category": "emulation", "severity": "medium",
        "desc": "Adversary emulation frameworks.",
        "detection": (
            "ADVERSARY EMULATION:\n"
            "FRAMEWORKS:\n"
            "  - MITRE ATT&CK (technique reference)\n"
            "  - Atomic Red Team\n"
            "    # Pre-built atomics per technique\n"
            "    # Invoke-AtomicRedTeam (PowerShell)\n"
            "    # atomic-red-team (repository)\n"
            "  - MITRE CALDERA\n"
            "    # Automated adversary emulation\n"
            "    # Plugins for different APTs\n"
            "    # Agent-based execution\n"
            "  - Prelude Operator\n"
            "    # TTPs from threat intelligence\n"
            "    # Chain execution\n"
            "THREAT GROUPS:\n"
            "  - APT29 (Cozy Bear) — SolarWinds\n"
            "  - APT28 (Fancy Bear) — phishing + implants\n"
            "  - Lazarus — financial + crypto\n"
            "  - FIN7 — POS + e-commerce\n"
            "  - Sandworm — ICS/SCADA destructive\n"
            "EMULATION PLANNING:\n"
            "  1. Select threat group/scenario\n"
            "  2. Map TTPs to ATT&CK\n"
            "  3. Build attack flow\n"
            "  4. Execute techniques\n"
            "  5. Document detections/gaps\n"
            "  6. Report findings\n"
            "TOOLS:\n"
            "  Atomic Red Team, CALDERA, Prelude"
        ),
        "tools": [],
    },
    {
        "id": "rt-005", "name": "Purple Team Exercises",
        "category": "purple", "severity": "medium",
        "desc": "Purple team exercises.",
        "detection": (
            "PURPLE TEAM EXERCISES:\n"
            "METHODOLOGY:\n"
            "  1. Define scope and objectives\n"
            "  2. Select TTPs to test\n"
            "  3. Red team executes technique\n"
            "  4. Blue team attempts detection\n"
            "  5. Evaluate detection capability\n"
            "  6. Tune/create detections\n"
            "  7. Re-test to verify\n"
            "  8. Document coverage matrix\n"
            "DETECTION ENGINEERING:\n"
            "  - Sigma rules (generic detection)\n"
            "  - YARA rules (file/memory)\n"
            "  - Suricata rules (network)\n"
            "  - Splunk/Elastic queries\n"
            "  - Custom analytics\n"
            "COVERAGE MATRIX:\n"
            "  Technique | Logged | Alerted | Blocked\n"
            "  T1003.001 |  Yes   |   Yes   |   No\n"
            "  T1021.002 |  Yes   |   No    |   No\n"
            "  T1059.001 |  Yes   |   Yes   |   Yes\n"
            "METRICS:\n"
            "  - Detection coverage percentage\n"
            "  - Mean time to detect (MTTD)\n"
            "  - Mean time to respond (MTTR)\n"
            "  - False positive rate\n"
            "  - Coverage gaps by ATT&CK tactic\n"
            "REPORTING:\n"
            "  - Coverage heatmap (ATT&CK Navigator)\n"
            "  - Gap analysis\n"
            "  - Detection improvement plan\n"
            "  - Quarterly trend tracking\n"
            "TOOLS:\n"
            "  ATT&CK Navigator, Sigma, DeTTECT"
        ),
        "tools": [],
    },
]


class RedTeamOpsKB:
    """Red team operations knowledge base.

    Provides red team patterns injected
    into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, RedTeamPattern] = {}
        self._log = logger.bind(component="redteam_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load red team patterns."""
        for data in REDTEAM_PATTERNS:
            pattern = RedTeamPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
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
        """Build red team prompt."""
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
