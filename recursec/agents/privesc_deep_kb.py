"""Privilege escalation deep knowledge base.

Deep knowledge about privilege escalation:
1. Linux privilege escalation
2. Windows privilege escalation
3. Docker/container escape
4. Cloud privilege escalation
5. Database privilege escalation
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


PRIVESC_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "pe-001", "name": "Linux Privilege Escalation",
        "category": "linux", "severity": "high",
        "desc": "Linux privesc techniques.",
        "detection": (
            "LINUX PRIVILEGE ESCALATION:\n"
            "SUID/SGID:\n"
            "  find / -perm -4000 -type f 2>/dev/null\n"
            "  find / -perm -2000 -type f 2>/dev/null\n"
            "  # Check GTFOBins for each binary\n"
            "SUDO:\n"
            "  sudo -l\n"
            "  # Check each allowed command\n"
            "  # Wildcard injection\n"
            "  # LD_PRELOAD (env_keep)\n"
            "  # sudo version (<1.8.28 → CVE-2019-14287)\n"
            "  # Path hijacking\n"
            "CAPABILITIES:\n"
            "  getcap -r / 2>/dev/null\n"
            "  # cap_setuid, cap_sys_admin\n"
            "  # cap_dac_override, cap_net_raw\n"
            "CRON:\n"
            "  cat /etc/crontab\n"
            "  ls -la /etc/cron.d/\n"
            "  crontab -l\n"
            "  # PATH injection in cron\n"
            "  # Writable cron scripts\n"
            "  # Wildcard injection (tar, rsync)\n"
            "KERNEL:\n"
            "  uname -a\n"
            "  # DirtyPipe (CVE-2022-0847)\n"
            "  # DirtyCOW (CVE-2016-5195)\n"
            "  # PwnKit (CVE-2021-4034)\n"
            "SERVICES:\n"
            "  # Writable service files\n"
            "  # Shared library injection\n"
            "  # NFS no_root_squash\n"
            "  # Docker group membership\n"
            "TOOLS:\n"
            "  linpeas.sh, LinEnum, pspy, GTFOBins"
        ),
        "tools": [],
    },
    {
        "id": "pe-002", "name": "Windows Privilege Escalation",
        "category": "windows", "severity": "high",
        "desc": "Windows privesc techniques.",
        "detection": (
            "WINDOWS PRIVILEGE ESCALATION:\n"
            "TOKENS:\n"
            "  whoami /priv\n"
            "  # SeImpersonatePrivilege → Potato\n"
            "  # SeDebugPrivilege → Process injection\n"
            "  # SeBackupPrivilege → SAM dump\n"
            "  # SeRestorePrivilege → DLL hijack\n"
            "  # SeTakeOwnershipPrivilege\n"
            "SERVICE MISCONFIG:\n"
            "  # Unquoted service paths\n"
            "  wmic service get name,pathname,startmode\n"
            "  # Weak service permissions\n"
            "  sc qc SERVICE_NAME\n"
            "  # Writable service binary\n"
            "  accesschk.exe -uwcqv SERVICE\n"
            "  # DLL hijacking\n"
            "  # Registry service keys\n"
            "POTATOES:\n"
            "  # JuicyPotato (< Win10 1809)\n"
            "  # RoguePotato\n"
            "  # PrintSpoofer\n"
            "  # GodPotato\n"
            "  # SweetPotato\n"
            "ALWAYS INSTALL ELEVATED:\n"
            "  reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\n"
            "  # AlwaysInstallElevated = 1\n"
            "  # Create malicious MSI\n"
            "SCHEDULED TASKS:\n"
            "  schtasks /query /fo LIST /v\n"
            "  # Writable task executables\n"
            "  # Modifiable task XML\n"
            "UAC BYPASS:\n"
            "  # eventvwr.exe, fodhelper.exe\n"
            "  # UACME project\n"
            "TOOLS:\n"
            "  winPEAS, PowerUp, SharpUp, Seatbelt"
        ),
        "tools": [],
    },
    {
        "id": "pe-003", "name": "Container Escape",
        "category": "container", "severity": "critical",
        "desc": "Docker/container escape techniques.",
        "detection": (
            "CONTAINER ESCAPE:\n"
            "DETECTION:\n"
            "  # Am I in a container?\n"
            "  cat /proc/1/cgroup\n"
            "  ls /.dockerenv\n"
            "  cat /proc/self/status | grep CapEff\n"
            "PRIVILEGED:\n"
            "  # Privileged container (--privileged)\n"
            "  mount /dev/sda1 /mnt\n"
            "  chroot /mnt\n"
            "  # Or access host devices\n"
            "  # Or modify kernel modules\n"
            "CAPABILITIES:\n"
            "  # CAP_SYS_ADMIN\n"
            "    # Mount host filesystem\n"
            "    # Exploit cgroup release_agent\n"
            "  # CAP_NET_ADMIN\n"
            "    # ARP spoofing\n"
            "  # CAP_SYS_PTRACE\n"
            "    # Inject into host processes\n"
            "  # CAP_DAC_READ_SEARCH\n"
            "    # Read any file\n"
            "SOCKETS:\n"
            "  # Docker socket mounted\n"
            "  ls -la /var/run/docker.sock\n"
            "  # Full host control via Docker API\n"
            "  curl --unix-socket /var/run/docker.sock http:/v1.40/containers/json\n"
            "KERNEL:\n"
            "  # Dirty Pipe works from container\n"
            "  # Container kernel == host kernel\n"
            "  # Kernel exploits escape container\n"
            "METADATA:\n"
            "  # Cloud metadata from container\n"
            "  curl http://169.254.169.254/latest/meta-data/\n"
            "TOOLS:\n"
            "  deepce, CDK, amicontained, PEIRATES"
        ),
        "tools": [],
    },
    {
        "id": "pe-004", "name": "Cloud Privilege Escalation",
        "category": "cloud", "severity": "critical",
        "desc": "Cloud IAM privilege escalation.",
        "detection": (
            "CLOUD PRIVILEGE ESCALATION:\n"
            "AWS:\n"
            "  - IAM policy enumeration\n"
            "    # aws iam list-attached-user-policies\n"
            "    # aws iam list-user-policies\n"
            "  - iam:CreatePolicy → create admin policy\n"
            "  - iam:AttachUserPolicy → attach admin\n"
            "  - iam:CreateLoginProfile → new console user\n"
            "  - iam:UpdateLoginProfile → reset password\n"
            "  - iam:PassRole + lambda:CreateFunction\n"
            "    # Pass admin role to Lambda\n"
            "  - sts:AssumeRole → cross-account\n"
            "  - ec2:RunInstances + iam:PassRole\n"
            "    # Launch instance with admin role\n"
            "  - ssm:SendCommand (on admin EC2)\n"
            "  - Cognito identity pool misconfig\n"
            "AZURE:\n"
            "  - Managed Identity exploitation\n"
            "  - Role assignment (Owner, Contributor)\n"
            "  - Custom role misconfig\n"
            "  - Service Principal secrets\n"
            "  - Conditional Access bypass\n"
            "GCP:\n"
            "  - setIamPolicy permissions\n"
            "  - Service account impersonation\n"
            "  - Custom role creation\n"
            "  - Metadata server (token theft)\n"
            "TOOLS:\n"
            "  Pacu, ScoutSuite, Prowler, CloudFox"
        ),
        "tools": [],
    },
    {
        "id": "pe-005", "name": "Database Privilege Escalation",
        "category": "database", "severity": "high",
        "desc": "Database privilege escalation.",
        "detection": (
            "DATABASE PRIVILEGE ESCALATION:\n"
            "MYSQL:\n"
            "  - UDF (User Defined Function)\n"
            "    # raptor_udf2.c → shared library\n"
            "    # CREATE FUNCTION sys_exec\n"
            "    # SELECT sys_exec('command')\n"
            "  - INTO OUTFILE → web shell\n"
            "  - Local file read (LOAD_FILE)\n"
            "  - Abuse GRANT OPTION\n"
            "MSSQL:\n"
            "  - xp_cmdshell\n"
            "    # EXEC sp_configure 'xp_cmdshell', 1\n"
            "    # EXEC xp_cmdshell 'command'\n"
            "  - IMPERSONATE\n"
            "    # EXECUTE AS LOGIN = 'sa'\n"
            "  - Linked servers\n"
            "    # EXEC sp_linkedservers\n"
            "    # OPENQUERY to execute on linked\n"
            "  - Agent jobs (SQLAgent)\n"
            "  - CLR assembly\n"
            "POSTGRESQL:\n"
            "  - COPY TO/FROM PROGRAM\n"
            "    # COPY (SELECT 1) TO PROGRAM 'command'\n"
            "  - Large objects\n"
            "  - pg_read_file() / pg_ls_dir()\n"
            "  - Extensions (plpythonu)\n"
            "  - ALTER ROLE ... SUPERUSER\n"
            "ORACLE:\n"
            "  - DBMS_SCHEDULER for OS commands\n"
            "  - Java stored procedures\n"
            "  - UTL_HTTP/UTL_FILE\n"
            "  - DBA role escalation\n"
            "TOOLS:\n"
            "  sqlmap (--os-shell), PowerUpSQL, ODAT"
        ),
        "tools": [],
    },
]


class PrivescDeepKB:
    """Privilege escalation deep knowledge base.

    Provides privesc patterns injected
    into agent prompts.
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
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[PrivescPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_privesc_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build privesc prompt."""
        lines = ["## Privilege Escalation\n"]
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
