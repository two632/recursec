"""Linux security knowledge base.

Deep knowledge about Linux security:
1. Linux privilege escalation
2. Linux persistence
3. Container escape
4. Linux hardening assessment
5. Linux forensics
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class LinuxSecPattern:
    """A Linux security pattern."""
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


LINUXSEC_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "lnx-001", "name": "Linux Privilege Escalation",
        "category": "privesc", "severity": "critical",
        "desc": "Linux privilege escalation.",
        "detection": (
            "LINUX PRIVILEGE ESCALATION:\n"
            "SUID/SGID:\n"
            "  find / -perm -4000 -type f 2>/dev/null\n"
            "  find / -perm -2000 -type f 2>/dev/null\n"
            "  # GTFOBins for exploitation\n"
            "SUDO:\n"
            "  sudo -l  # list allowed commands\n"
            "  # sudo version exploit (CVE-2021-3156 Baron Samedit)\n"
            "  # Wildcard injection in sudo\n"
            "  # env_keep abuse\n"
            "  # LD_PRELOAD with sudo\n"
            "  # NOPASSWD entries\n"
            "CAPABILITIES:\n"
            "  getcap -r / 2>/dev/null\n"
            "  # cap_setuid=ep → escalation\n"
            "  # cap_dac_override → read any file\n"
            "  # cap_sys_admin → mount, namespace\n"
            "CRON/TIMERS:\n"
            "  cat /etc/crontab\n"
            "  ls -la /etc/cron.d/\n"
            "  systemctl list-timers\n"
            "  # Writable cron scripts\n"
            "  # Writable PATH in cron\n"
            "  # Wildcard injection (tar, rsync)\n"
            "KERNEL:\n"
            "  uname -r  # check kernel version\n"
            "  # DirtyPipe (CVE-2022-0847)\n"
            "  # DirtyCow (CVE-2016-5195)\n"
            "  # Overlayfs exploits\n"
            "  # PwnKit (CVE-2021-4034)\n"
            "NFS:\n"
            "  showmount -e TARGET\n"
            "  # no_root_squash → create SUID binary\n"
            "WRITABLE:\n"
            "  - /etc/passwd (add root user)\n"
            "  - /etc/shadow (crack/replace)\n"
            "  - .bashrc/.profile\n"
            "  - Service configs\n"
            "TOOLS:\n"
            "  LinPEAS, linux-exploit-suggester, pspy"
        ),
        "tools": ["linpeas"],
    },
    {
        "id": "lnx-002", "name": "Linux Persistence",
        "category": "persistence", "severity": "high",
        "desc": "Linux persistence mechanisms.",
        "detection": (
            "LINUX PERSISTENCE:\n"
            "CRON:\n"
            "  - User crontab: crontab -e\n"
            "  - System: /etc/crontab, /etc/cron.d/*\n"
            "  - Anacron: /etc/anacrontab\n"
            "  - Systemd timers\n"
            "SYSTEMD:\n"
            "  - Custom service unit\n"
            "  - User-level service (~/.config/systemd/user/)\n"
            "  - Socket activation\n"
            "  - Path-triggered units\n"
            "SHELL:\n"
            "  - .bashrc / .zshrc\n"
            "  - .profile / .bash_profile\n"
            "  - .bash_logout\n"
            "  - /etc/profile.d/ scripts\n"
            "  - PROMPT_COMMAND\n"
            "  - LD_PRELOAD in /etc/ld.so.preload\n"
            "SSH:\n"
            "  - authorized_keys\n"
            "  - Custom SSH config\n"
            "  - pam_exec module\n"
            "  - SSH daemon modification\n"
            "ADVANCED:\n"
            "  - Kernel module (rootkit)\n"
            "  - eBPF-based persistence\n"
            "  - PAM backdoor module\n"
            "  - Alias commands in .bashrc\n"
            "  - Modified /usr/bin/ binaries\n"
            "  - udev rules\n"
            "  - XDG autostart\n"
            "  - Motd scripts (/etc/update-motd.d/)\n"
            "TOOLS:\n"
            "  pspy, unhide, rkhunter, chkrootkit"
        ),
        "tools": [],
    },
    {
        "id": "lnx-003", "name": "Container Escape",
        "category": "container", "severity": "critical",
        "desc": "Container escape techniques.",
        "detection": (
            "CONTAINER ESCAPE:\n"
            "DETECTION:\n"
            "  # Am I in a container?\n"
            "  cat /proc/1/cgroup  # docker/lxc entries\n"
            "  ls /.dockerenv\n"
            "  cat /proc/self/mountinfo\n"
            "  hostname  # random string = container\n"
            "DOCKER SOCKET:\n"
            "  # If /var/run/docker.sock is mounted\n"
            "  docker run -v /:/host -it alpine chroot /host\n"
            "  # Full host access\n"
            "PRIVILEGED:\n"
            "  # If --privileged flag was used\n"
            "  mount /dev/sda1 /mnt  # mount host disk\n"
            "  nsenter -t 1 -m -u -i -n -p -- /bin/bash  # host PID 1\n"
            "CAPABILITIES:\n"
            "  # CAP_SYS_ADMIN\n"
            "  # Release agent escape (cgroup)\n"
            "  # CAP_NET_ADMIN (network manipulation)\n"
            "  # CAP_SYS_PTRACE (process injection)\n"
            "CVE EXPLOITS:\n"
            "  - CVE-2019-5736 (runc overwrite)\n"
            "  - CVE-2020-15257 (containerd shim)\n"
            "  - CVE-2022-0185 (filesystem context)\n"
            "  - CVE-2022-0847 (DirtyPipe in container)\n"
            "  - CVE-2024-21626 (runc leaky fd)\n"
            "KUBERNETES:\n"
            "  - Service account token → API server\n"
            "  - Kubelet API (port 10250)\n"
            "  - etcd access\n"
            "  - Node host access\n"
            "TOOLS:\n"
            "  CDK, deepce, PEIRATES, amicontained"
        ),
        "tools": [],
    },
    {
        "id": "lnx-004", "name": "Linux Hardening Assessment",
        "category": "hardening", "severity": "medium",
        "desc": "Linux hardening assessment.",
        "detection": (
            "LINUX HARDENING ASSESSMENT:\n"
            "KERNEL:\n"
            "  - ASLR: cat /proc/sys/kernel/randomize_va_space (should be 2)\n"
            "  - exec-shield/NX\n"
            "  - KASLR enabled\n"
            "  - Kernel module restrictions\n"
            "  - ptrace scope: /proc/sys/kernel/yama/ptrace_scope\n"
            "  - Unprivileged user namespaces\n"
            "  - Core dumps disabled\n"
            "FILESYSTEM:\n"
            "  - World-writable files\n"
            "  - SUID/SGID audit\n"
            "  - /tmp noexec,nosuid,nodev\n"
            "  - Proper permissions on /etc/shadow\n"
            "  - Immutable flag on critical files\n"
            "NETWORK:\n"
            "  - Firewall rules (iptables/nftables)\n"
            "  - Open ports audit\n"
            "  - SSH config hardening\n"
            "    PermitRootLogin no\n"
            "    PasswordAuthentication no\n"
            "    MaxAuthTries 3\n"
            "  - TCP wrappers\n"
            "  - IP forwarding disabled\n"
            "AUTH:\n"
            "  - PAM configuration\n"
            "  - Password policy (pam_pwquality)\n"
            "  - Account lockout\n"
            "  - Password aging\n"
            "  - /etc/login.defs\n"
            "AUDIT:\n"
            "  - auditd rules\n"
            "  - Log rotation\n"
            "  - Remote syslog\n"
            "TOOLS:\n"
            "  Lynis, CIS-CAT, OpenSCAP, linux-audit"
        ),
        "tools": ["lynis"],
    },
    {
        "id": "lnx-005", "name": "Linux Forensics",
        "category": "forensics", "severity": "medium",
        "desc": "Linux forensic analysis.",
        "detection": (
            "LINUX FORENSICS:\n"
            "VOLATILE:\n"
            "  - Memory dump: dd, LiME, AVML\n"
            "  - Running processes: ps aux, /proc/*/\n"
            "  - Network connections: ss -tlnp, /proc/net/*\n"
            "  - Open files: lsof\n"
            "  - Loaded modules: lsmod\n"
            "  - Mount points: mount, /proc/mounts\n"
            "  - Routing: ip route, arp cache\n"
            "NON-VOLATILE:\n"
            "  - Disk image: dd, dc3dd\n"
            "  - Filesystem timeline: fls, mactime\n"
            "  - Deleted files: extundelete, photorec\n"
            "  - File metadata: stat, exiftool\n"
            "LOGS:\n"
            "  - /var/log/auth.log (authentication)\n"
            "  - /var/log/syslog (system)\n"
            "  - /var/log/kern.log (kernel)\n"
            "  - /var/log/apache2/*.log (web)\n"
            "  - journalctl (systemd)\n"
            "  - lastlog, wtmp, btmp (logins)\n"
            "  - /var/log/audit/audit.log (auditd)\n"
            "ARTIFACTS:\n"
            "  - .bash_history (all users)\n"
            "  - /tmp and /var/tmp\n"
            "  - Cron jobs\n"
            "  - SSH authorized_keys\n"
            "  - Package install logs\n"
            "  - Last modified files\n"
            "    find / -mtime -1 -type f 2>/dev/null\n"
            "TIMELINE:\n"
            "  # plaso/log2timeline\n"
            "  log2timeline.py timeline.plaso /path/to/image\n"
            "  psort.py -o l2tcsv timeline.plaso\n"
            "TOOLS:\n"
            "  Volatility, Autopsy, log2timeline, LiME"
        ),
        "tools": [],
    },
]


class LinuxSecurityKB:
    """Linux security knowledge base.

    Provides Linux security patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, LinuxSecPattern] = {}
        self._log = logger.bind(component="linuxsec_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load Linux security patterns."""
        for data in LINUXSEC_PATTERNS:
            pattern = LinuxSecPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[LinuxSecPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_linux_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build Linux security prompt."""
        lines = ["## Linux Security\n"]
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
