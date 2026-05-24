"""Network protocol deep-dive knowledge base.

Deep knowledge about network protocol security:
1. DNS attacks
2. BGP and routing attacks
3. TLS/SSL attacks
4. ARP and Layer 2 attacks
5. VPN and tunneling attacks
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class NetProtoPattern:
    """A network protocol pattern."""
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


NETPROTO_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "np-001", "name": "DNS Attacks",
        "category": "dns", "severity": "high",
        "desc": "DNS attack techniques.",
        "detection": (
            "DNS ATTACKS:\n"
            "DNS SPOOFING/POISONING:\n"
            "  - Cache poisoning (Kaminsky)\n"
            "  - DNS rebinding\n"
            "  - Response forgery\n"
            "  # dnschef (DNS proxy)\n"
            "  # responder (LLMNR/NBT-NS/mDNS)\n"
            "DNS TUNNELING:\n"
            "  - Exfiltration over DNS\n"
            "  - C2 over DNS\n"
            "  # iodine (IP over DNS)\n"
            "  # dnscat2 (encrypted DNS tunnel)\n"
            "  # dns2tcp\n"
            "  Detection: high TXT query volume,\n"
            "  long subdomain labels, entropy analysis\n"
            "DNS ENUMERATION:\n"
            "  - Zone transfer (AXFR)\n"
            "  dig axfr @ns.target target.com\n"
            "  - Subdomain brute force\n"
            "  - DNSSEC walking (NSEC)\n"
            "  - Reverse DNS sweeping\n"
            "  - DNS ANY query amplification\n"
            "DNS HIJACKING:\n"
            "  - Registrar account compromise\n"
            "  - DNS server compromise\n"
            "  - BGP hijacking for DNS\n"
            "  - Subdomain takeover\n"
            "    # Dangling CNAME records\n"
            "    # Expired cloud resources\n"
            "    subjack, can-i-take-over-xyz\n"
            "DNSSEC:\n"
            "  - DNSSEC validation bypass\n"
            "  - Key rollover issues\n"
            "  - NSEC3 hash cracking\n"
            "TOOLS:\n"
            "  dnschef, Responder, dnscat2, dig"
        ),
        "tools": ["dnscat2"],
    },
    {
        "id": "np-002", "name": "BGP and Routing Attacks",
        "category": "bgp", "severity": "critical",
        "desc": "BGP and routing attacks.",
        "detection": (
            "BGP & ROUTING ATTACKS:\n"
            "BGP HIJACKING:\n"
            "  - Prefix hijacking (announce others' prefixes)\n"
            "  - Sub-prefix hijacking (more-specific route)\n"
            "  - Route leak\n"
            "  - AS path manipulation\n"
            "  Detection:\n"
            "    # RIPE RIS, RouteViews\n"
            "    # BGPStream (real-time monitoring)\n"
            "    # RPKI (Resource Public Key Infrastructure)\n"
            "    # ROA (Route Origin Authorization)\n"
            "OSPF/EIGRP:\n"
            "  - Rogue router injection\n"
            "  - Route redistribution attacks\n"
            "  - LSA flooding\n"
            "  - Authentication bypass (MD5 weak keys)\n"
            "  # Loki (OSPF manipulation)\n"
            "VLAN:\n"
            "  - VLAN hopping (double tagging)\n"
            "  - DTP negotiation (trunk port)\n"
            "  - VTP manipulation\n"
            "  - Inter-VLAN routing bypass\n"
            "  # yersinia (Layer 2 attacks)\n"
            "STP:\n"
            "  - Root bridge election manipulation\n"
            "  - BPDU flooding\n"
            "  - Topology change manipulation\n"
            "GRE/VXLAN:\n"
            "  - Tunnel injection\n"
            "  - Encapsulation abuse\n"
            "  - No built-in authentication\n"
            "TOOLS:\n"
            "  yersinia, Loki, Scapy, BGPStream"
        ),
        "tools": [],
    },
    {
        "id": "np-003", "name": "TLS/SSL Attacks",
        "category": "tls", "severity": "high",
        "desc": "TLS/SSL attack techniques.",
        "detection": (
            "TLS/SSL ATTACKS:\n"
            "PROTOCOL DOWNGRADE:\n"
            "  - SSL stripping (HTTPS → HTTP)\n"
            "  # sslstrip\n"
            "  - TLS downgrade (TLS 1.3 → 1.0)\n"
            "  - POODLE (SSLv3)\n"
            "  - DROWN (SSLv2)\n"
            "  - FREAK (export ciphers)\n"
            "  - Logjam (DH export)\n"
            "CERTIFICATE:\n"
            "  - Self-signed certificate acceptance\n"
            "  - Expired certificates\n"
            "  - Wrong hostname\n"
            "  - Weak signing algorithm (SHA-1, MD5)\n"
            "  - Certificate pinning bypass (mobile)\n"
            "  - CT log monitoring evasion\n"
            "IMPLEMENTATION:\n"
            "  - Heartbleed (OpenSSL CVE-2014-0160)\n"
            "  - BEAST (CBC IV prediction)\n"
            "  - CRIME/BREACH (compression oracle)\n"
            "  - Lucky13 (timing on MAC)\n"
            "  - ROBOT (Bleichenbacher)\n"
            "  - Raccoon (DH timing)\n"
            "TESTING:\n"
            "  # testssl.sh (comprehensive)\n"
            "  testssl.sh TARGET\n"
            "  # sslyze\n"
            "  sslyze --regular TARGET\n"
            "  # nmap ssl scripts\n"
            "  nmap --script ssl* TARGET\n"
            "  # sslscan\n"
            "MITM:\n"
            "  - mitmproxy (transparent proxy)\n"
            "  - Burp Suite (intercept proxy)\n"
            "  - bettercap (ARP + SSL strip)\n"
            "TOOLS:\n"
            "  testssl.sh, sslyze, sslstrip, bettercap"
        ),
        "tools": ["testssl"],
    },
    {
        "id": "np-004", "name": "ARP and Layer 2 Attacks",
        "category": "layer2", "severity": "high",
        "desc": "ARP and Layer 2 attacks.",
        "detection": (
            "ARP & LAYER 2 ATTACKS:\n"
            "ARP SPOOFING:\n"
            "  - ARP cache poisoning\n"
            "  - Gratuitous ARP injection\n"
            "  - Man-in-the-middle via ARP\n"
            "  # arpspoof (dsniff)\n"
            "  arpspoof -i eth0 -t VICTIM GATEWAY\n"
            "  # bettercap\n"
            "  bettercap -iface eth0 -eval 'arp.spoof on'\n"
            "  # ettercap\n"
            "  Detection: Dynamic ARP Inspection (DAI)\n"
            "DHCP:\n"
            "  - DHCP starvation (exhaust pool)\n"
            "  - Rogue DHCP server\n"
            "  - DHCP relay attacks\n"
            "  # yersinia -I  (DHCP attack mode)\n"
            "  Detection: DHCP snooping\n"
            "CDP/LLDP:\n"
            "  - Information disclosure\n"
            "  - CDP flooding\n"
            "  - Device impersonation\n"
            "  # cdpsnarf (CDP info extraction)\n"
            "MAC:\n"
            "  - MAC flooding (CAM table overflow)\n"
            "  # macof (dsniff suite)\n"
            "  macof -i eth0\n"
            "  - MAC spoofing\n"
            "  # ip link set eth0 address XX:XX:XX:XX:XX:XX\n"
            "  Detection: Port security, 802.1X\n"
            "802.1X:\n"
            "  - EAP downgrade\n"
            "  - MAB bypass\n"
            "  - Certificate spoofing\n"
            "  # eapmd5pass\n"
            "TOOLS:\n"
            "  bettercap, ettercap, yersinia, arpspoof"
        ),
        "tools": ["bettercap"],
    },
    {
        "id": "np-005", "name": "VPN and Tunneling Attacks",
        "category": "vpn", "severity": "high",
        "desc": "VPN and tunneling attacks.",
        "detection": (
            "VPN & TUNNELING:\n"
            "IPSEC:\n"
            "  - IKEv1 aggressive mode (hash capture)\n"
            "  # ike-scan TARGET\n"
            "  ike-scan --aggressive -M TARGET\n"
            "  - Weak pre-shared keys\n"
            "  - IKEv1 phase 1 hash cracking\n"
            "  # psk-crack hash.txt\n"
            "  - Transform enumeration\n"
            "SSL VPN:\n"
            "  - Known CVEs:\n"
            "    # Pulse Secure (CVE-2019-11510)\n"
            "    # Fortinet (CVE-2018-13379)\n"
            "    # Citrix (CVE-2019-19781)\n"
            "    # Palo Alto GlobalProtect\n"
            "  - Default credentials\n"
            "  - Path traversal to config\n"
            "  - Session fixation\n"
            "WIREGUARD:\n"
            "  - Key leakage\n"
            "  - Configuration exposure\n"
            "  - Endpoint enumeration\n"
            "OPENVPN:\n"
            "  - Config file with embedded certs\n"
            "  - Weak cipher negotiation\n"
            "  - Missing CRL checking\n"
            "TUNNELING:\n"
            "  - SSH tunneling (-L, -R, -D)\n"
            "  - Chisel (HTTP tunnel)\n"
            "  - Ligolo-ng (reverse tunnel)\n"
            "  - socat (bidirectional relay)\n"
            "  - HTTP/DNS/ICMP tunnels for evasion\n"
            "TOOLS:\n"
            "  ike-scan, Chisel, Ligolo-ng, socat"
        ),
        "tools": ["ike-scan"],
    },
]


class NetworkProtocolDeepKB:
    """Network protocol deep-dive knowledge base.

    Provides protocol security patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, NetProtoPattern] = {}
        self._log = logger.bind(component="netproto_deep_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load network protocol patterns."""
        for data in NETPROTO_PATTERNS:
            pattern = NetProtoPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[NetProtoPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_netproto_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build network protocol prompt."""
        lines = ["## Network Protocol Security\n"]
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
