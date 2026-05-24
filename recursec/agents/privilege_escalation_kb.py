"""Privilege escalation knowledge base.

Deep knowledge about privilege escalation:
1. Linux privilege escalation
2. Windows privilege escalation
3. Active Directory escalation
4. Container escape
5. Cloud privilege escalation
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
            "LINUX PRIVESC:\n"
            "SUID/SGID:\n"
            "  find / -perm -4000 -type f 2>/dev/null   # SUID\n"
            "  find / -perm -2000 -type f 2>/dev/null   # SGID\n"
            "  # Check GTFOBins for exploitable binaries\n"
            "  # Custom SUID binaries (most interesting)\n"
            "SUDO:\n"
            "  sudo -l         # List allowed commands\n"
            "  # NOPASSWD entries\n"
            "  # Wildcards in sudo rules\n"
            "  # sudo CVEs: CVE-2021-3156 (Baron Samedit)\n"
            "  # LD_PRELOAD with sudo\n"
            "  # sudo -u#-1 (CVE-2019-14287)\n"
            "CAPABILITIES:\n"
            "  getcap -r / 2>/dev/null\n"
            "  # Dangerous: cap_setuid, cap_setgid\n"
            "  # cap_dac_override, cap_sys_admin\n"
            "  # cap_sys_ptrace (process injection)\n"
            "CRON/TIMERS:\n"
            "  cat /etc/crontab\n"
            "  ls -la /etc/cron.d/\n"
            "  systemctl list-timers\n"
            "  # Writable cron scripts\n"
            "  # PATH injection in cron\n"
            "  # Wildcard injection (tar, rsync)\n"
            "KERNEL:\n"
            "  uname -r          # Kernel version\n"
            "  # DirtyPipe (CVE-2022-0847)\n"
            "  # DirtyCow (CVE-2016-5195)\n"
            "  # Linux kernel exploits database\n"
            "MISC:\n"
            "  - NFS no_root_squash\n"
            "  - Writable /etc/passwd\n"
            "  - Docker group membership\n"
            "  - LXD/LXC group\n"
            "  - PATH hijacking\n"
            "  - Shared library injection\n"
            "TOOLS:\n"
            "  LinPEAS, linux-exploit-suggester, pspy"
        ),
        "tools": ["linpeas"],
    },
    {
        "id": "pe-002", "name": "Windows Privilege Escalation",
        "category": "windows", "severity": "critical",
        "desc": "Windows privilege escalation techniques.",
        "detection": (
            "WINDOWS PRIVESC:\n"
            "TOKEN MANIPULATION:\n"
            "  - SeImpersonatePrivilege\n"
            "  - SeAssignPrimaryTokenPrivilege\n"
            "  # Potato family (JuicyPotato, SweetPotato,\n"
            "  #   GodPotato, PrintSpoofer)\n"
            "  whoami /priv       # Check privileges\n"
            "SERVICE EXPLOITS:\n"
            "  - Unquoted service paths\n"
            "  - Weak service permissions (sc.exe)\n"
            "  - DLL hijacking in service\n"
            "  - Writable service binary\n"
            "  # Check with:\n"
            "  sc qc ServiceName\n"
            "  accesschk.exe /accepteula -ucqv ServiceName\n"
            "REGISTRY:\n"
            "  - AlwaysInstallElevated\n"
            "  - AutoLogon credentials\n"
            "  - Run/RunOnce keys\n"
            "  reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\\n"
            "    Windows\\Installer /v AlwaysInstallElevated\n"
            "UAC BYPASS:\n"
            "  - fodhelper.exe\n"
            "  - eventvwr.exe\n"
            "  - sdclt.exe\n"
            "  - Auto-elevate COM objects\n"
            "SCHEDULED TASKS:\n"
            "  schtasks /query /fo LIST /v\n"
            "  # Writable task binaries\n"
            "  # Missing binary tasks\n"
            "MISC:\n"
            "  - Unattend.xml passwords\n"
            "  - Web.config credentials\n"
            "  - DPAPI secrets\n"
            "  - Stored WiFi passwords\n"
            "  - Cached GPP passwords\n"
            "TOOLS:\n"
            "  WinPEAS, PowerUp, SharpUp, Seatbelt"
        ),
        "tools": ["winpeas"],
    },
    {
        "id": "pe-003", "name": "Active Directory Escalation",
        "category": "ad", "severity": "critical",
        "desc": "AD privilege escalation to Domain Admin.",
        "detection": (
            "AD PRIVILEGE ESCALATION:\n"
            "KERBEROS ATTACKS:\n"
            "  KERBEROASTING:\n"
            "    GetUserSPNs.py domain/user:pass -dc-ip DC\n"
            "    # Crack with hashcat -m 13100\n"
            "  AS-REP ROASTING:\n"
            "    GetNPUsers.py domain/ -usersfile users.txt\n"
            "    # Crack with hashcat -m 18200\n"
            "  GOLDEN TICKET:\n"
            "    # Need krbtgt NTLM hash\n"
            "    mimikatz: kerberos::golden /domain:DOMAIN\n"
            "    /sid:S-1-5-21-... /krbtgt:HASH /user:admin\n"
            "  SILVER TICKET:\n"
            "    # Need service account NTLM hash\n"
            "    # Target specific service\n"
            "ACL ABUSE:\n"
            "  - GenericAll on user → reset password\n"
            "  - GenericWrite → set SPN → Kerberoast\n"
            "  - WriteDACL → grant GenericAll\n"
            "  - WriteOwner → take ownership\n"
            "  - ForceChangePassword\n"
            "  - AddMember → add to privileged group\n"
            "DELEGATION:\n"
            "  - Unconstrained delegation\n"
            "  - Constrained delegation (S4U2Self/S4U2Proxy)\n"
            "  - RBCD (Resource-Based Constrained)\n"
            "CERTIFICATE ABUSE (AD CS):\n"
            "  # Certifried (CVE-2022-26923)\n"
            "  # ESC1-ESC8 template attacks\n"
            "  certipy find -u user -p pass -dc-ip DC\n"
            "TOOLS:\n"
            "  BloodHound, Impacket, Rubeus, Certipy"
        ),
        "tools": ["bloodhound", "impacket", "certipy"],
    },
    {
        "id": "pe-004", "name": "Container Escape",
        "category": "container", "severity": "critical",
        "desc": "Container escape techniques.",
        "detection": (
            "CONTAINER ESCAPE:\n"
            "DOCKER:\n"
            "  # Check if in container\n"
            "  cat /proc/1/cgroup\n"
            "  ls /.dockerenv\n"
            "  # Privileged mode\n"
            "  # --privileged flag gives all capabilities\n"
            "  mount /dev/sda1 /mnt  # Mount host disk\n"
            "  # Docker socket mount\n"
            "  ls -la /var/run/docker.sock\n"
            "  docker -H unix:///var/run/docker.sock run -v /:/host\n"
            "  # Capabilities\n"
            "  capsh --print\n"
            "  # CAP_SYS_ADMIN → mount, cgroup escape\n"
            "  # CAP_SYS_PTRACE → process injection\n"
            "  # CAP_NET_ADMIN → network manipulation\n"
            "KUBERNETES:\n"
            "  # Service account token\n"
            "  cat /var/run/secrets/kubernetes.io/serviceaccount/token\n"
            "  # API server access\n"
            "  curl -sk https://kubernetes.default.svc/\n"
            "  # Host PID namespace\n"
            "  # Host network namespace\n"
            "  # Privileged pods\n"
            "CVEs:\n"
            "  - CVE-2019-5736 (runc escape)\n"
            "  - CVE-2020-15257 (containerd shim)\n"
            "  - CVE-2022-0185 (kernel exploit)\n"
            "  - Leaky Vessels (CVE-2024-21626)\n"
            "TOOLS:\n"
            "  deepce, CDK, amicontained, kubectl"
        ),
        "tools": ["deepce"],
    },
    {
        "id": "pe-005", "name": "Cloud Privilege Escalation",
        "category": "cloud_privesc", "severity": "critical",
        "desc": "Cloud privilege escalation.",
        "detection": (
            "CLOUD PRIVESC:\n"
            "AWS:\n"
            "  # IAM policy enumeration\n"
            "  aws iam list-attached-user-policies --user USER\n"
            "  # Privilege escalation paths:\n"
            "  - iam:CreatePolicyVersion\n"
            "  - iam:SetDefaultPolicyVersion\n"
            "  - iam:PassRole + lambda:CreateFunction\n"
            "  - iam:PassRole + ec2:RunInstances\n"
            "  - iam:CreateLoginProfile\n"
            "  - iam:UpdateLoginProfile\n"
            "  - iam:AttachUserPolicy\n"
            "  - iam:PutUserPolicy\n"
            "  - iam:AttachGroupPolicy\n"
            "  - lambda:UpdateFunctionCode\n"
            "  - EC2 instance profile → role assumption\n"
            "  - STS assume-role chains\n"
            "AZURE:\n"
            "  - Contributor → RunCommand on VMs\n"
            "  - Automation Account → RunAs account\n"
            "  - App registration → certificate auth\n"
            "  - Managed Identity abuse\n"
            "  - KeyVault access policies\n"
            "GCP:\n"
            "  - setIamPolicy permission\n"
            "  - Service account impersonation\n"
            "  - Compute instance → default SA\n"
            "  - Cloud Function → SA token\n"
            "TOOLS:\n"
            "  Pacu (AWS), ROADtools (Azure), GCPBucketBrute"
        ),
        "tools": ["pacu"],
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
