"""Red team operations knowledge base.

Deep knowledge about red team operations:
1. Red team methodology
2. Initial access techniques
3. Lateral movement
4. Persistence mechanisms
5. Command and control (C2)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class RedTeamPattern:
    """A red team pattern."""
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


RT_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "rt-001", "name": "Red Team Methodology",
        "category": "methodology", "severity": "critical",
        "desc": "Red team engagement methodology.",
        "detection": (
            "RED TEAM METHODOLOGY:\n"
            "PHASES:\n"
            "  1. Reconnaissance (passive + active)\n"
            "  2. Initial Access (foothold)\n"
            "  3. Execution (run malicious code)\n"
            "  4. Persistence (survive reboots)\n"
            "  5. Privilege Escalation (admin/root)\n"
            "  6. Defense Evasion (avoid detection)\n"
            "  7. Credential Access (passwords/tokens)\n"
            "  8. Discovery (internal recon)\n"
            "  9. Lateral Movement (pivot)\n"
            "  10. Collection (gather data)\n"
            "  11. Command & Control (maintain access)\n"
            "  12. Exfiltration (extract data)\n"
            "  13. Impact (if authorized)\n"
            "FRAMEWORKS:\n"
            "  - MITRE ATT&CK (technique mapping)\n"
            "  - Cyber Kill Chain (Lockheed Martin)\n"
            "  - PTES (Penetration Testing Execution Standard)\n"
            "  - OSSTMM\n"
            "RULES:\n"
            "  - Stay within authorized scope\n"
            "  - Document everything\n"
            "  - Have emergency contacts\n"
            "  - Permission letters (Get Out of Jail)\n"
            "  - Deconfliction with blue team\n"
            "  - Safe words / abort procedures"
        ),
        "tools": [],
    },
    {
        "id": "rt-002", "name": "Initial Access Techniques",
        "category": "initial_access", "severity": "critical",
        "desc": "Initial access techniques.",
        "detection": (
            "INITIAL ACCESS:\n"
            "EXTERNAL:\n"
            "  - Phishing (credentials, payload)\n"
            "  - Public-facing exploitation (CVEs)\n"
            "  - Password spraying (O365, VPN)\n"
            "  - Supply chain compromise\n"
            "  - Trusted relationship abuse\n"
            "  - VPN/RDP brute force\n"
            "  - Cloud misconfig (S3, storage)\n"
            "TECHNIQUES:\n"
            "  PHISHING:\n"
            "    - HTML smuggling\n"
            "    - ISO/IMG containers (MotW bypass)\n"
            "    - OneNote payloads\n"
            "    - QR code phishing\n"
            "    - Evilginx (session hijacking)\n"
            "  PASSWORD SPRAYING:\n"
            "    # O365\n"
            "    trevorspray -u users.txt -p 'Winter2026!'\n"
            "    # OWA\n"
            "    ruler --domain target.com brute\n"
            "  EXPLOITATION:\n"
            "    # External services\n"
            "    nuclei -t cves/ -u https://target.com\n"
            "    # Known vulns: Exchange (ProxyLogon/Shell)\n"
            "    # Citrix, VPN appliances, Confluence\n"
            "OPSEC:\n"
            "  - Rotate source IPs\n"
            "  - Respect lockout thresholds\n"
            "  - Use residential proxies\n"
            "  - Domain fronting\n"
            "TOOLS:\n"
            "  GoPhish, Evilginx2, TrevorSpray, Ruler"
        ),
        "tools": ["gophish", "evilginx2"],
    },
    {
        "id": "rt-003", "name": "Lateral Movement",
        "category": "lateral", "severity": "critical",
        "desc": "Lateral movement techniques.",
        "detection": (
            "LATERAL MOVEMENT:\n"
            "WINDOWS:\n"
            "  - PSExec / SMBExec\n"
            "  - WMI (wmic, Invoke-WmiMethod)\n"
            "  - WinRM (Enter-PSSession)\n"
            "  - RDP (mstsc, SharpRDP)\n"
            "  - DCOM (MMC20, ShellWindows)\n"
            "  - Pass-the-Hash (PTH)\n"
            "  - Pass-the-Ticket (PTT)\n"
            "  - Overpass-the-Hash (PTK)\n"
            "  - Token impersonation\n"
            "LINUX:\n"
            "  - SSH (keys, agent forwarding)\n"
            "  - SSH tunneling / port forwarding\n"
            "  - Ansible / Salt / Puppet abuse\n"
            "  - NFS/SMB shares\n"
            "CREDENTIAL:\n"
            "  # Mimikatz\n"
            "  mimikatz 'sekurlsa::logonpasswords'\n"
            "  # LSASS dump\n"
            "  procdump -ma lsass.exe lsass.dmp\n"
            "  # SAM dump\n"
            "  reg save HKLM\\SAM sam.hive\n"
            "  # Kerberoasting\n"
            "  GetUserSPNs.py domain/user:pass -dc-ip DC\n"
            "  # AS-REP Roasting\n"
            "  GetNPUsers.py domain/ -usersfile users.txt\n"
            "AD:\n"
            "  # BloodHound (path finding)\n"
            "  bloodhound-python -d domain -u user -p pass\n"
            "  # DCSync\n"
            "  secretsdump.py domain/admin@DC\n"
            "TOOLS:\n"
            "  Impacket, Mimikatz, BloodHound, CrackMapExec"
        ),
        "tools": ["impacket", "bloodhound"],
    },
    {
        "id": "rt-004", "name": "Persistence Mechanisms",
        "category": "persistence", "severity": "high",
        "desc": "Persistence techniques.",
        "detection": (
            "PERSISTENCE:\n"
            "WINDOWS:\n"
            "  - Registry Run keys\n"
            "  - Scheduled Tasks (schtasks)\n"
            "  - Services (sc.exe)\n"
            "  - WMI event subscriptions\n"
            "  - DLL hijacking / search order\n"
            "  - COM object hijacking\n"
            "  - Startup folder\n"
            "  - Golden/Silver tickets (Kerberos)\n"
            "  - DSRM password\n"
            "  - Skeleton key\n"
            "  - AdminSDHolder\n"
            "  - SID History injection\n"
            "LINUX:\n"
            "  - Crontab\n"
            "  - systemd service\n"
            "  - SSH authorized_keys\n"
            "  - .bashrc / .profile\n"
            "  - LD_PRELOAD\n"
            "  - PAM backdoor\n"
            "  - Kernel module (rootkit)\n"
            "  - Web shell\n"
            "CLOUD:\n"
            "  - IAM user/role creation\n"
            "  - Lambda/Function backdoor\n"
            "  - OAuth app registration\n"
            "  - Service principal\n"
            "  - API key creation\n"
            "WEB:\n"
            "  - Web shell upload\n"
            "  - Stored XSS for credential harvest\n"
            "  - Database backdoor (trigger/function)\n"
            "TOOLS:\n"
            "  SharPersist, PowerLurk, Merlin"
        ),
        "tools": [],
    },
    {
        "id": "rt-005", "name": "Command and Control",
        "category": "c2", "severity": "critical",
        "desc": "C2 frameworks and techniques.",
        "detection": (
            "COMMAND AND CONTROL (C2):\n"
            "FRAMEWORKS:\n"
            "  COBALT STRIKE:\n"
            "    - Industry standard (commercial)\n"
            "    - Beacon payload\n"
            "    - Malleable C2 profiles\n"
            "    - Team server\n"
            "  SLIVER:\n"
            "    - Open source (BishopFox)\n"
            "    - Multi-protocol (mTLS, HTTP, DNS, WG)\n"
            "    - Implant generation\n"
            "    - Multiplayer operation\n"
            "  HAVOC:\n"
            "    - Modern, open source\n"
            "    - BOF (Beacon Object Files) support\n"
            "    - Demon agent\n"
            "    - Team collaboration\n"
            "  MYTHIC:\n"
            "    - Modular, web UI\n"
            "    - Multi-agent support\n"
            "    - Container-based\n"
            "TECHNIQUES:\n"
            "  - HTTPS (blend with web traffic)\n"
            "  - DNS (slow but stealthy)\n"
            "  - Domain fronting (CDN abuse)\n"
            "  - Named pipes (SMB, internal)\n"
            "  - Jitter (random sleep intervals)\n"
            "  - Kill dates (auto-cleanup)\n"
            "  - Encrypted channels\n"
            "OPSEC:\n"
            "  - Categorized domains\n"
            "  - Aged domains\n"
            "  - Redirectors (Apache, Nginx)\n"
            "  - CDN/cloud functions as relays\n"
            "  - Traffic profiles (mimic legitimate)\n"
            "TOOLS:\n"
            "  Cobalt Strike, Sliver, Havoc, Mythic, Merlin"
        ),
        "tools": ["sliver", "havoc"],
    },
]


class RedTeamKB:
    """Red team operations knowledge base.

    Provides red team patterns injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, RedTeamPattern] = {}
        self._log = logger.bind(component="red_team_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load red team patterns."""
        for data in RT_PATTERNS:
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
