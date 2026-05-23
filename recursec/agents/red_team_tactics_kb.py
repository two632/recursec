"""Red team tactics knowledge base.

Deep knowledge about red team operations:
1. Initial access techniques
2. Social engineering vectors
3. Physical security assessment
4. Evasion and bypass techniques
5. C2 infrastructure
6. Data exfiltration methods
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class TacticPattern:
    """A red team tactic pattern."""
    pattern_id: str = ""
    name: str = ""
    category: str = ""
    mitre_tactic: str = ""
    severity: str = "high"
    description: str = ""
    testing_methodology: str = ""
    tools: list[str] = field(default_factory=list)
    opsec_notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:30],
            "tactic": self.mitre_tactic[:15],
        }


RED_TEAM_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "rt-001", "name": "Initial Access Techniques",
        "category": "initial_access", "mitre_tactic": "TA0001",
        "severity": "critical",
        "desc": "Gaining initial access to target organization.",
        "testing": (
            "INITIAL ACCESS TECHNIQUES:\n"
            "1. PHISHING:\n"
            "   - Spear-phishing with crafted payloads:\n"
            "     * Office macros (VBA): AutoOpen/Document_Open\n"
            "     * HTML smuggling: Embed payload in HTML attachment\n"
            "     * OneNote .one files (post-macro era): Embedded scripts\n"
            "     * ISO/VHD attachments: Mount on Windows, bypass MOTW\n"
            "     * LNK files: Shortcut that executes PowerShell\n"
            "   - Phishing infrastructure:\n"
            "     * GoPhish: Campaign management\n"
            "     * evilginx2: Reverse proxy for MFA phishing\n"
            "     * Modlishka: Real-time credential capture\n"
            "2. EXTERNAL SERVICES:\n"
            "   - VPN/RDP with credential stuffing/spraying\n"
            "   - OWA/O365 password spray → token → full access\n"
            "   - Citrix/VMware Horizon vulns (CVE-2023-xxx series)\n"
            "   - Public-facing application exploitation\n"
            "3. SUPPLY CHAIN:\n"
            "   - Compromise vendor/supplier portal\n"
            "   - Poison software update mechanism\n"
            "   - Compromise open-source dependency\n"
            "4. TRUSTED RELATIONSHIP:\n"
            "   - Compromise MSP (Managed Service Provider)\n"
            "   - Abuse federation trust\n"
            "   - Domain trust exploitation\n"
            "5. DRIVE-BY:\n"
            "   - Watering hole: Compromise site visited by targets\n"
            "   - Browser exploits via malvertising"
        ),
        "tools": ["GoPhish", "evilginx2", "Modlishka"],
        "opsec": "Use burner domains aged 30+ days. Categorize domain before use.",
    },
    {
        "id": "rt-002", "name": "Defense Evasion Techniques",
        "category": "evasion", "mitre_tactic": "TA0005",
        "severity": "high",
        "desc": "Evading security controls during operations.",
        "testing": (
            "DEFENSE EVASION:\n"
            "1. AMSI BYPASS (Windows):\n"
            "   - Patch amsi.dll in memory:\n"
            "     [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')\n"
            "     .GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)\n"
            "   - String obfuscation: Split/join/encode sensitive strings\n"
            "   - Custom .NET assembly loading to avoid on-disk detection\n"
            "2. EDR EVASION:\n"
            "   - Unhooking ntdll.dll: Map fresh copy from disk/KnownDlls\n"
            "   - Direct syscalls: SysWhispers3, HellsGate\n"
            "   - Shellcode injection:\n"
            "     * Process hollowing (create suspended → unmap → inject → resume)\n"
            "     * Early bird APC injection\n"
            "     * Thread pool callback\n"
            "     * Fiber-based execution\n"
            "   - Sleep obfuscation: Encrypt payload in memory during sleep\n"
            "   - ETW patching: Disable Event Tracing for Windows\n"
            "3. AV EVASION:\n"
            "   - Payload encryption: AES/XOR encrypt shellcode, decrypt at runtime\n"
            "   - Custom loaders: Don't use known frameworks (Cobalt Strike, Meterpreter)\n"
            "   - Signed binary abuse: DLL side-loading via signed executables\n"
            "   - Living off the land (LOLBins): certutil, mshta, rundll32, regsvr32\n"
            "4. NETWORK EVASION:\n"
            "   - Domain fronting: Use CDN to hide C2 traffic\n"
            "   - DNS over HTTPS for C2\n"
            "   - Legitimate services as C2: Slack, Teams, GitHub, Notion\n"
            "   - Traffic blending: Match normal corporate traffic patterns\n"
            "5. LOG EVASION:\n"
            "   - Timestomping: Modify file timestamps\n"
            "   - Event log tampering: wevtutil cl Security\n"
            "   - Disable Sysmon: Unload minifilter driver"
        ),
        "tools": ["SysWhispers3", "Donut", "ScareCrow"],
        "opsec": "Assume all activity is logged. Minimize on-disk artifacts.",
    },
    {
        "id": "rt-003", "name": "Command & Control Infrastructure",
        "category": "c2", "mitre_tactic": "TA0011",
        "severity": "high",
        "desc": "Setting up and managing C2 infrastructure.",
        "testing": (
            "COMMAND & CONTROL:\n"
            "1. C2 FRAMEWORKS:\n"
            "   - Sliver (open-source): HTTP/HTTPS/DNS/mTLS/WireGuard\n"
            "     * generate --mtls target.com --os windows --arch amd64\n"
            "   - Havoc (open-source): Feature-rich, modern C2\n"
            "   - Mythic (open-source): Agent-agnostic, extensible\n"
            "   - Cobalt Strike: Commercial, widely used\n"
            "   - Brute Ratel: Evasive, modern\n"
            "2. INFRASTRUCTURE:\n"
            "   - Redirectors: Apache/Nginx mod_rewrite to filter traffic\n"
            "   - Domain categorization: Categorize C2 domain before use\n"
            "   - Certificate configuration: Let's Encrypt valid certs\n"
            "   - CDN fronting: CloudFlare, Azure CDN, AWS CloudFront\n"
            "3. COMMUNICATION CHANNELS:\n"
            "   - HTTPS (most common, blends with web traffic)\n"
            "   - DNS (slow but stealthy, hard to block)\n"
            "   - DoH (DNS over HTTPS, encrypted)\n"
            "   - SMB named pipes (internal lateral movement)\n"
            "   - External services: Slack, Teams webhooks as C2\n"
            "4. RESILIENCE:\n"
            "   - Multiple C2 channels (failover)\n"
            "   - Peer-to-peer mesh between implants\n"
            "   - Dead drops: Paste sites, cloud storage\n"
            "   - Scheduled check-in with jitter (avoid pattern detection)\n"
            "5. OPSEC:\n"
            "   - Separate infrastructure per engagement\n"
            "   - Burn after use\n"
            "   - Avoid shared hosting with known malicious IPs"
        ),
        "tools": ["Sliver", "Havoc", "Mythic", "Cobalt Strike"],
        "opsec": "Separate C2 infra per engagement. Aged domains with valid certs.",
    },
    {
        "id": "rt-004", "name": "Data Exfiltration Techniques",
        "category": "exfiltration", "mitre_tactic": "TA0010",
        "severity": "critical",
        "desc": "Extracting data from target environment.",
        "testing": (
            "DATA EXFILTRATION:\n"
            "1. NETWORK CHANNELS:\n"
            "   - HTTPS POST to attacker server (most common)\n"
            "   - DNS exfiltration: Encode data in DNS queries\n"
            "     dnscat2, iodine, DNSExfiltrator\n"
            "   - ICMP tunneling: icmpsh, ptunnel\n"
            "2. CLOUD SERVICES:\n"
            "   - Upload to cloud storage: S3, Azure Blob, GCS\n"
            "   - Email: Send via SMTP or webmail\n"
            "   - Collaboration tools: SharePoint, OneDrive, Google Drive\n"
            "   - Code repos: Private GitHub/GitLab repo\n"
            "3. STEGANOGRAPHY:\n"
            "   - Hide data in images: steghide, OpenStego\n"
            "   - Hide in video/audio files\n"
            "   - White space encoding in text documents\n"
            "4. COMPRESSION & ENCRYPTION:\n"
            "   - Compress before exfil: reduces detection surface\n"
            "   - Encrypt with AES: tar czf - data/ | openssl enc -aes-256-cbc\n"
            "   - Split into chunks: split -b 1M encrypted.bin chunk_\n"
            "5. PHYSICAL:\n"
            "   - USB drive exfiltration\n"
            "   - Print sensitive documents\n"
            "   - Photograph screens\n"
            "6. DETECTION EVASION:\n"
            "   - Slow exfil: Trickle data over days/weeks\n"
            "   - Match normal traffic patterns (during business hours)\n"
            "   - Use allowed protocols and destinations\n"
            "   - DLP bypass: Encrypt, encode, or fragment data"
        ),
        "tools": ["dnscat2", "PacketWhisper", "DNSExfiltrator"],
        "opsec": "Slow exfil during business hours. Match normal traffic patterns.",
    },
    {
        "id": "rt-005", "name": "Web Application Attack Chains",
        "category": "web_attack_chain", "mitre_tactic": "TA0001,TA0003",
        "severity": "critical",
        "desc": "Multi-step web application exploitation chains.",
        "testing": (
            "WEB APPLICATION ATTACK CHAINS:\n"
            "1. SSRF → INTERNAL ACCESS:\n"
            "   - Find SSRF: URL parameters, webhooks, file import\n"
            "   - Escalate: Access internal services\n"
            "     * Cloud metadata: http://169.254.169.254/latest/meta-data/\n"
            "     * Internal APIs: http://localhost:8080/admin\n"
            "     * Redis: dict://localhost:6379/INFO\n"
            "     * Internal network scanning\n"
            "2. XSS → ACCOUNT TAKEOVER:\n"
            "   - Find stored XSS in shared context\n"
            "   - Steal session tokens: document.cookie\n"
            "   - Steal OAuth tokens from localStorage\n"
            "   - Perform CSRF with XSS (bypass CSRF tokens)\n"
            "   - Keylog admin credentials\n"
            "3. SQL INJECTION → RCE:\n"
            "   - Extract credentials from database\n"
            "   - Write webshell: INTO OUTFILE (MySQL)\n"
            "   - Stacked queries → xp_cmdshell (MSSQL)\n"
            "   - COPY TO PROGRAM (PostgreSQL)\n"
            "   - File read → source code → more vulns\n"
            "4. FILE UPLOAD → RCE:\n"
            "   - Bypass extension filter: .php.jpg, .phtml, .php5\n"
            "   - Bypass content-type check: Magic bytes\n"
            "   - Bypass path restriction: ../../uploads/shell.php\n"
            "   - Race condition: Upload then access before cleanup\n"
            "5. IDOR → DATA BREACH:\n"
            "   - Enumerate user IDs sequentially\n"
            "   - Access other users' PII, documents, messages\n"
            "   - Modify other users' data (escalation)\n"
            "   - Chain with admin functions for privilege escalation\n"
            "6. SSTI → RCE:\n"
            "   - Detect: {{7*7}} → 49\n"
            "   - Jinja2: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}\n"
            "   - Twig: {{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}\n"
            "   - Freemarker: <#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}"
        ),
        "tools": ["Burp Suite", "sqlmap", "ffuf", "nuclei"],
        "opsec": "Avoid destructive exploitation. Document evidence at each step.",
    },
]


class RedTeamTacticsKB:
    """Red team tactics knowledge base.

    Provides deep red team methodology injected into
    agent prompts for offensive security operations.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, TacticPattern] = {}
        self._log = logger.bind(component="red_team_tactics_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load red team tactic patterns."""
        for data in RED_TEAM_PATTERNS:
            pattern = TacticPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                mitre_tactic=data.get("mitre_tactic", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                testing_methodology=data.get("testing", ""),
                tools=data.get("tools", []),
                opsec_notes=data.get("opsec", ""),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_patterns_for_tactic(
        self,
        mitre_tactic: str,
    ) -> list[TacticPattern]:
        """Get patterns by MITRE ATT&CK tactic."""
        return [
            p for p in self._patterns.values()
            if mitre_tactic in p.mitre_tactic
        ]

    def get_patterns_for_category(
        self,
        category: str,
    ) -> list[TacticPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category == category
        ]

    def get_testing_prompts(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 3,
    ) -> list[str]:
        """Get testing prompts for agent context injection."""
        prompts = []
        for pattern in self._patterns.values():
            if categories and pattern.category not in categories:
                continue
            if pattern.testing_methodology:
                prompts.append(pattern.testing_methodology)
            if len(prompts) >= max_patterns:
                break
        return prompts

    def build_red_team_prompt(
        self,
        categories: list[str] | None = None,
        include_opsec: bool = True,
        max_patterns: int = 3,
    ) -> str:
        """Build red team testing prompt."""
        lines = ["## Red Team Tactics\n"]
        count = 0
        for pattern in self._patterns.values():
            if categories and pattern.category not in categories:
                continue
            if count >= max_patterns:
                break
            lines.append(f"### {pattern.name} [{pattern.severity.upper()}]")
            if pattern.mitre_tactic:
                lines.append(f"MITRE ATT&CK: {pattern.mitre_tactic}")
            lines.append(pattern.testing_methodology)
            if include_opsec and pattern.opsec_notes:
                lines.append(f"OPSEC: {pattern.opsec_notes}")
            lines.append("")
            count += 1
        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        cat_counts: dict[str, int] = defaultdict(int)
        for p in self._patterns.values():
            cat_counts[p.category] += 1
        return {
            "patterns": len(self._patterns),
            "by_category": dict(cat_counts),
        }
