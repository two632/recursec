"""Linux security knowledge base.

Attack patterns for Linux environments:
1. Linux Privilege Escalation — SUID, capabilities, cron, kernel, sudo
2. Linux Persistence — cron, systemd, bashrc, PAM, shared objects
3. Linux Credential Access — /etc/shadow, SSH keys, GNOME keyring, memory
4. Linux Container Escape — namespace, cgroup, capability abuse
5. Linux Hardening Assessment — kernel params, file perms, services, audit
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class LinuxAttackType(str, Enum):
    PRIVESC = "privesc"
    PERSISTENCE = "persistence"
    CREDENTIAL_ACCESS = "credential_access"
    CONTAINER_ESCAPE = "container_escape"
    HARDENING = "hardening"


@dataclass
class LinuxPattern:
    name: str = ""
    attack_type: LinuxAttackType = LinuxAttackType.PRIVESC
    description: str = ""
    techniques: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    mitre_ids: list[str] = field(default_factory=list)
    severity: str = "high"

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "type": self.attack_type.value, "severity": self.severity}


LINUX_PATTERNS: list[LinuxPattern] = [
    LinuxPattern(
        name="Linux Privilege Escalation",
        attack_type=LinuxAttackType.PRIVESC,
        description="Escalating to root: SUID binary exploitation, Linux capabilities abuse (cap_setuid, cap_dac_override), misconfigured sudo rules (GTFOBins), cron job hijacking, writable PATH directories, and kernel exploits (DirtyPipe, DirtyCow).",
        techniques=[
            "SUID binary abuse: find unusual SUID binaries, use GTFOBins",
            "Capabilities abuse: cap_setuid on Python/Perl for root",
            "Sudo misconfig: sudo -l shows NOPASSWD for exploitable binary",
            "Cron job hijacking: writable cron scripts or wildcard injection",
            "PATH hijacking: writable directory in system PATH",
            "Kernel exploit: DirtyPipe (CVE-2022-0847), DirtyCow (CVE-2016-5195)",
            "NFS no_root_squash: mount share, create SUID binary",
            "Writable /etc/passwd: add root-level user entry",
        ],
        indicators=[
            "Unusual SUID binaries outside standard system paths",
            "Capabilities set on scripting interpreters",
            "NOPASSWD sudo entries for dangerous commands",
            "World-writable cron scripts or directories",
            "Kernel version vulnerable to known exploits",
            "NFS exports with no_root_squash option",
        ],
        tools=["linpeas", "linenum", "linux-exploit-suggester", "pspy", "GTFOBins"],
        commands=[
            "find / -perm -4000 -type f 2>/dev/null",
            "getcap -r / 2>/dev/null",
            "sudo -l",
            "cat /etc/crontab && ls -la /etc/cron.d/",
            "echo $PATH | tr ':' '\\n' | xargs -I{} ls -la {} 2>/dev/null | grep -v root",
            "uname -r && cat /proc/version",
            "showmount -e localhost",
            "ls -la /etc/passwd && cat /etc/passwd | grep ':0:'",
        ],
        mitre_ids=["T1548", "T1068", "T1053"],
        severity="critical",
    ),
    LinuxPattern(
        name="Linux Persistence",
        attack_type=LinuxAttackType.PERSISTENCE,
        description="Maintaining access: cron jobs, systemd services/timers, bashrc/profile modifications, PAM backdoor modules, shared object injection (LD_PRELOAD), SSH authorized_keys, and at/batch jobs.",
        techniques=[
            "Cron job: add to /etc/crontab or user crontab",
            "Systemd service: create .service unit with reverse shell",
            "Systemd timer: periodic execution without cron",
            "Bashrc/profile: append payload to .bashrc or /etc/profile",
            "PAM backdoor: modify pam_unix.so for any-password auth",
            "LD_PRELOAD: inject shared object loaded by all processes",
            "SSH authorized_keys: add attacker public key",
            "At/batch job: schedule one-time or batch execution",
        ],
        indicators=[
            "New cron entry for unknown script or binary",
            "New systemd service/timer in user or system directory",
            "Modified .bashrc/.profile with encoded commands",
            "PAM module modified or replaced",
            "LD_PRELOAD set in /etc/ld.so.preload",
            "Unknown SSH key in authorized_keys",
        ],
        tools=["pspy", "chkrootkit", "rkhunter", "auditd"],
        commands=[
            "crontab -l && cat /etc/crontab",
            "systemctl list-unit-files --type=service | grep enabled",
            "find /etc/systemd/ ~/.config/systemd/ -name '*.service' -newer /etc/hostname",
            "cat ~/.bashrc ~/.profile /etc/profile | grep -v '^#' | grep -v '^$'",
            "find / -name 'authorized_keys' -exec cat {} + 2>/dev/null",
            "cat /etc/ld.so.preload 2>/dev/null",
            "atq && at -l",
        ],
        mitre_ids=["T1053", "T1543", "T1546", "T1556"],
        severity="high",
    ),
    LinuxPattern(
        name="Linux Credential Access",
        attack_type=LinuxAttackType.CREDENTIAL_ACCESS,
        description="Extracting credentials: /etc/shadow hash cracking, SSH private key discovery, GNOME Keyring extraction, process memory scraping, credential files in home directories, and credential caching.",
        techniques=[
            "Shadow file: extract hashes if readable, crack with hashcat/john",
            "SSH keys: find unprotected private keys",
            "GNOME Keyring: extract stored passwords",
            "Process memory: scrape credentials from running services",
            ".bash_history: search for passwords in command history",
            "Config files: grep for passwords in /etc/ and home dirs",
            "KeePass/password manager databases on disk",
            "Browser credential extraction (Chrome/Firefox on Linux)",
        ],
        indicators=[
            "/etc/shadow readable by non-root user",
            "SSH private keys without passphrase protection",
            "Credentials in .bash_history or .env files",
            "Process memory containing plaintext passwords",
            "Password manager databases accessible to user",
        ],
        tools=["hashcat", "john", "ssh-audit", "mimipenguin", "lazagne"],
        commands=[
            "cat /etc/shadow 2>/dev/null",
            "find / -name 'id_rsa' -o -name 'id_ed25519' -o -name '*.pem' 2>/dev/null",
            "grep -rn 'password\\|passwd\\|secret\\|token' /home/ /etc/ 2>/dev/null | head -50",
            "cat ~/.bash_history | grep -i 'pass\\|secret\\|token\\|key'",
            "find / -name '*.kdbx' -o -name 'credentials.xml' 2>/dev/null",
            "john --wordlist=/usr/share/wordlists/rockyou.txt shadow_hashes.txt",
        ],
        mitre_ids=["T1003", "T1552", "T1555"],
        severity="critical",
    ),
    LinuxPattern(
        name="Linux Container Escape",
        attack_type=LinuxAttackType.CONTAINER_ESCAPE,
        description="Breaking out of Linux containers: privileged mode abuse, Docker socket mount, host PID namespace, cgroup release_agent, cap_sys_admin with mount, and CVE-based kernel escapes.",
        techniques=[
            "Privileged container: mount host filesystem, chroot out",
            "Docker socket: mount /var/run/docker.sock, spawn host container",
            "Host PID namespace: access host processes, inject into them",
            "Cgroup release_agent: write payload to cgroup notify_on_release",
            "CAP_SYS_ADMIN: mount host filesystem from within container",
            "CVE-2022-0185: heap overflow in legacy_parse_param",
            "CVE-2024-21626: runc process.cwd container escape",
            "/proc/sysrq-trigger: trigger kernel functions from container",
        ],
        indicators=[
            "Container running with --privileged flag",
            "Docker socket accessible inside container",
            "Host PID namespace visible (can see host processes)",
            "CAP_SYS_ADMIN capability granted to container",
            "Host filesystem mounted as volume",
            "Kernel version vulnerable to container escape CVEs",
        ],
        tools=["deepce", "CDK", "amicontained", "peirates", "traitor"],
        commands=[
            "cat /proc/1/cgroup",
            "ls -la /var/run/docker.sock",
            "capsh --print | grep sys_admin",
            "mount -t proc proc /proc && ls /proc/*/root/etc/shadow",
            "deepce.sh --exploit",
            "nsenter --target 1 --mount --uts --ipc --net --pid /bin/bash",
        ],
        mitre_ids=["T1611"],
        severity="critical",
    ),
    LinuxPattern(
        name="Linux Hardening Assessment",
        attack_type=LinuxAttackType.HARDENING,
        description="Assessing Linux hardening: kernel security parameters (ASLR, stack protection, Yama ptrace), file permission audit, service exposure, AppArmor/SELinux status, and audit configuration.",
        techniques=[
            "Check kernel security params (ASLR, exec-shield, kptr_restrict)",
            "Verify Yama ptrace scope for process debugging restrictions",
            "Audit file permissions on sensitive files (/etc/shadow, SSH keys)",
            "Check for unnecessary SUID/SGID binaries",
            "Verify AppArmor/SELinux enforcing mode",
            "Check open ports and unnecessary running services",
            "Verify auditd rules for critical file/process monitoring",
            "Check for automatic security updates configuration",
        ],
        indicators=[
            "ASLR disabled (randomize_va_space=0)",
            "Yama ptrace_scope=0 (any process can ptrace any other)",
            "/etc/shadow world-readable or group-readable",
            "SELinux/AppArmor in permissive or disabled mode",
            "Unnecessary services (telnet, rsh) running",
            "No auditd rules configured",
        ],
        tools=["lynis", "linux-audit", "checksec", "oscap"],
        commands=[
            "cat /proc/sys/kernel/randomize_va_space",
            "cat /proc/sys/kernel/yama/ptrace_scope",
            "ls -la /etc/shadow /etc/passwd /etc/sudoers",
            "getenforce 2>/dev/null || aa-status 2>/dev/null",
            "ss -tlnp",
            "auditctl -l",
            "lynis audit system --quick",
            "checksec --dir=/usr/bin/ | head -20",
        ],
        mitre_ids=["T1518", "T1082"],
        severity="medium",
    ),
]


def build_linux_security_prompt(focus_type: LinuxAttackType | None = None, max_patterns: int = 5) -> str:
    lines = ["## Linux Security Knowledge\n"]
    patterns = LINUX_PATTERNS
    if focus_type:
        patterns = [p for p in patterns if p.attack_type == focus_type]
    for pattern in patterns[:max_patterns]:
        lines.append(f"### {pattern.name} [{pattern.severity}]")
        lines.append(pattern.description)
        lines.append("\nTechniques:")
        for t in pattern.techniques[:4]:
            lines.append(f"  - {t}")
        lines.append("\nCommands:")
        for c in pattern.commands[:3]:
            lines.append(f"  $ {c}")
        lines.append("")
    return "\n".join(lines)
