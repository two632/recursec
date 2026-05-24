"""Network attack knowledge base.

Deep knowledge about network attacks:
1. Man-in-the-middle attacks
2. DNS attacks
3. ARP attacks
4. VLAN attacks
5. Routing protocol attacks
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class NetworkAttackPattern:
    """A network attack pattern."""
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
        "id": "net-001", "name": "Man-in-the-Middle",
        "category": "mitm", "severity": "critical",
        "desc": "MITM attack techniques.",
        "detection": (
            "MAN-IN-THE-MIDDLE:\n"
            "ARP SPOOFING:\n"
            "  # arpspoof -i eth0 -t TARGET GATEWAY\n"
            "  # arpspoof -i eth0 -t GATEWAY TARGET\n"
            "  # Enable forwarding: echo 1 > /proc/sys/net/ipv4/ip_forward\n"
            "  # Bettercap:\n"
            "  # net.probe on; arp.spoof on; set arp.spoof.targets TARGET\n"
            "SSL/TLS INTERCEPTION:\n"
            "  - sslstrip (HTTPS downgrade)\n"
            "  - mitmproxy (full proxy)\n"
            "  - Certificate generation\n"
            "  - HSTS bypass (SSLstrip2 + dns2proxy)\n"
            "  - Burp invisible proxy\n"
            "DNS SPOOFING:\n"
            "  # Bettercap: dns.spoof on\n"
            "  # Ettercap: dns_spoof plugin\n"
            "  # Redirect DNS queries\n"
            "  # Captive portal\n"
            "LLMNR/NBT-NS:\n"
            "  # Responder -I eth0 -wrf\n"
            "  # Capture NTLMv2 hashes\n"
            "  # Relay attacks (ntlmrelayx)\n"
            "DHCP:\n"
            "  - Rogue DHCP server\n"
            "  - DHCP starvation\n"
            "  - Set attacker as gateway/DNS\n"
            "TOOLS:\n"
            "  Bettercap, Ettercap, mitmproxy, Responder"
        ),
        "tools": [],
    },
    {
        "id": "net-002", "name": "DNS Attacks",
        "category": "dns", "severity": "high",
        "desc": "DNS attack techniques.",
        "detection": (
            "DNS ATTACKS:\n"
            "CACHE POISONING:\n"
            "  - Birthday attack on TXID\n"
            "  - Kaminsky attack\n"
            "  - SAD DNS (side channel)\n"
            "  - DNS rebinding\n"
            "    # Rotate A records (external → 127.0.0.1)\n"
            "    # Bypass same-origin policy\n"
            "ZONE TRANSFER:\n"
            "  dig axfr domain.com @ns.domain.com\n"
            "  # Full zone data if misconfigured\n"
            "  host -l domain.com ns.domain.com\n"
            "SUBDOMAIN TAKEOVER:\n"
            "  - Check CNAME → unclaimed resources\n"
            "    # GitHub Pages\n"
            "    # AWS S3 buckets\n"
            "    # Azure services\n"
            "    # Heroku\n"
            "    # Shopify\n"
            "  # subjack, can-i-take-over-xyz\n"
            "DNS TUNNELING:\n"
            "  - Data exfiltration via DNS\n"
            "    # iodine, dnscat2, dns2tcp\n"
            "  - C2 over DNS TXT/NULL\n"
            "  - Detection evasion\n"
            "DNS AMPLIFICATION:\n"
            "  - ANY query amplification\n"
            "  - DNSSEC amplification\n"
            "  - Open resolver abuse\n"
            "TOOLS:\n"
            "  dig, dnsrecon, fierce, dnscat2, iodine"
        ),
        "tools": [],
    },
    {
        "id": "net-003", "name": "ARP and Layer 2 Attacks",
        "category": "layer2", "severity": "high",
        "desc": "Layer 2 network attacks.",
        "detection": (
            "ARP & LAYER 2 ATTACKS:\n"
            "ARP SPOOFING:\n"
            "  - Gratuitous ARP packets\n"
            "  - MAC flooding (macof)\n"
            "    # Fill switch CAM table\n"
            "    # Switch becomes hub\n"
            "  - ARP cache poisoning\n"
            "STP ATTACK:\n"
            "  - Root bridge takeover\n"
            "  - STP BPDU spoofing\n"
            "  - Yersinia framework\n"
            "CDP/LLDP:\n"
            "  - CDP/LLDP enumeration\n"
            "    # Device discovery\n"
            "    # VLAN information\n"
            "    # Management addresses\n"
            "  - CDP flooding\n"
            "802.1X BYPASS:\n"
            "  - Hub/switch insertion\n"
            "  - MAC cloning\n"
            "  - Transparent bridging\n"
            "  - NAC bypass\n"
            "MAC ATTACKS:\n"
            "  - MAC spoofing\n"
            "  - CAM table overflow\n"
            "  - Port stealing\n"
            "TOOLS:\n"
            "  Yersinia, macof, arpspoof, Bettercap"
        ),
        "tools": [],
    },
    {
        "id": "net-004", "name": "VLAN Attacks",
        "category": "vlan", "severity": "high",
        "desc": "VLAN hopping and attacks.",
        "detection": (
            "VLAN ATTACKS:\n"
            "VLAN HOPPING:\n"
            "  - Switch spoofing (DTP)\n"
            "    # Negotiate trunk port\n"
            "    # Access all VLANs\n"
            "    # Yersinia: yersinia dtp -attack 1\n"
            "  - Double tagging\n"
            "    # Add two 802.1Q tags\n"
            "    # Outer tag = native VLAN\n"
            "    # Inner tag = target VLAN\n"
            "    # One-way attack\n"
            "VLAN ENUMERATION:\n"
            "  - CDP/LLDP VLAN info\n"
            "  - SNMP community string\n"
            "    # snmpwalk -c public SWITCH\n"
            "    # VLAN configuration\n"
            "  - Trunk port detection\n"
            "INTER-VLAN:\n"
            "  - Router-on-a-stick misconfig\n"
            "  - ACL bypass\n"
            "  - Firewall rule gaps\n"
            "  - VLAN-aware routing\n"
            "PRIVATE VLAN:\n"
            "  - PVLAN proxy attack\n"
            "  - Promiscuous port access\n"
            "  - Community VLAN isolation\n"
            "TOOLS:\n"
            "  Yersinia, Scapy, VLAN hopper, nmap"
        ),
        "tools": [],
    },
    {
        "id": "net-005", "name": "Routing Protocol Attacks",
        "category": "routing", "severity": "critical",
        "desc": "Routing protocol exploitation.",
        "detection": (
            "ROUTING PROTOCOL ATTACKS:\n"
            "BGP:\n"
            "  - Route hijacking\n"
            "    # Announce more-specific prefixes\n"
            "    # Traffic redirection\n"
            "  - Route leak\n"
            "  - BGP session reset\n"
            "  - AS path manipulation\n"
            "  - Community attribute abuse\n"
            "OSPF:\n"
            "  - Rogue router injection\n"
            "  - LSA flooding\n"
            "  - Designated router election\n"
            "  - Area manipulation\n"
            "  - Authentication bypass\n"
            "  # Scapy: craft OSPF hello packets\n"
            "EIGRP:\n"
            "  - Rogue neighbor\n"
            "  - Route injection\n"
            "  - Authentication cracking\n"
            "RIP:\n"
            "  - Route poisoning\n"
            "  - No authentication (RIPv1)\n"
            "  - Rogue route injection\n"
            "MPLS:\n"
            "  - Label injection\n"
            "  - VRF leaking\n"
            "  - PE router compromise\n"
            "DETECTION:\n"
            "  - Route monitoring (RIPE RIS)\n"
            "  - BGP origin validation (RPKI)\n"
            "  - Route filtering best practices\n"
            "TOOLS:\n"
            "  Scapy, Loki, FRRouting, GoBGP"
        ),
        "tools": [],
    },
]


class NetworkAttackKB:
    """Network attack knowledge base.

    Provides network attack patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, NetworkAttackPattern] = {}
        self._log = logger.bind(component="net_attack_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load network attack patterns."""
        for data in NETWORK_PATTERNS:
            pattern = NetworkAttackPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[NetworkAttackPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_network_attack_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build network attack prompt."""
        lines = ["## Network Attacks\n"]
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
