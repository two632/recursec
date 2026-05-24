"""Network protocol attacks knowledge base.

Deep knowledge about network protocol attacks:
1. DNS attacks
2. ARP/Layer 2 attacks
3. BGP/routing attacks
4. SMTP/email attacks
5. SNMP/management protocol attacks
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class NetProtoPattern:
    """A network protocol attack pattern."""
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
        "desc": "DNS protocol attacks.",
        "detection": (
            "DNS ATTACKS:\n"
            "DNS ENUMERATION:\n"
            "  # Zone transfer\n"
            "  dig AXFR @ns.target.com target.com\n"
            "  # Subdomain brute force\n"
            "  subfinder -d target.com\n"
            "  amass enum -d target.com\n"
            "  # DNS record types\n"
            "  dig target.com ANY\n"
            "  dig target.com MX\n"
            "  dig target.com TXT\n"
            "  dig target.com NS\n"
            "DNS CACHE POISONING:\n"
            "  - Kaminsky attack\n"
            "  - Birthday paradox-based\n"
            "  - SAD DNS (side channel)\n"
            "  - Requires DNSSEC absence\n"
            "DNS REBINDING:\n"
            "  - Bypass same-origin policy\n"
            "  - Access internal services\n"
            "  - TTL manipulation\n"
            "  - Multiple A records (rebind IP)\n"
            "DNS TUNNELING:\n"
            "  - Data exfiltration via DNS queries\n"
            "  - C2 over DNS (iodine, dnscat2)\n"
            "  - TXT record encoding\n"
            "  - Subdomain encoding\n"
            "DNS TAKEOVER:\n"
            "  - Dangling CNAME records\n"
            "  - Expired cloud resources\n"
            "  - NS delegation takeover\n"
            "  # Check: subjack, can-i-take-over-xyz\n"
            "TOOLS:\n"
            "  dig, subfinder, amass, dnscat2, iodine"
        ),
        "tools": ["subfinder", "amass"],
    },
    {
        "id": "np-002", "name": "ARP/Layer 2 Attacks",
        "category": "layer2", "severity": "high",
        "desc": "Layer 2 network attacks.",
        "detection": (
            "ARP/LAYER 2 ATTACKS:\n"
            "ARP SPOOFING:\n"
            "  # arpspoof (dsniff)\n"
            "  arpspoof -i eth0 -t TARGET GATEWAY\n"
            "  arpspoof -i eth0 -t GATEWAY TARGET\n"
            "  # bettercap\n"
            "  bettercap -eval 'set arp.spoof.targets TARGET; arp.spoof on'\n"
            "  # Enables MITM\n"
            "  # Intercept traffic, inject packets\n"
            "VLAN HOPPING:\n"
            "  - Switch spoofing (DTP)\n"
            "  - Double tagging (802.1Q)\n"
            "  # yersinia (Layer 2 attack tool)\n"
            "  yersinia -G  # GUI mode\n"
            "STP ATTACKS:\n"
            "  - STP root bridge takeover\n"
            "  - BPDU flooding\n"
            "  - STP manipulation\n"
            "DHCP:\n"
            "  - DHCP starvation\n"
            "  - Rogue DHCP server\n"
            "  - DHCP spoofing (DNS/gateway)\n"
            "MAC FLOODING:\n"
            "  - CAM table overflow\n"
            "  - Switch failopen to hub mode\n"
            "  macof -i eth0\n"
            "LLDP/CDP:\n"
            "  - Information disclosure\n"
            "  - Device enumeration\n"
            "  - VLAN discovery\n"
            "TOOLS:\n"
            "  bettercap, arpspoof, yersinia, macof"
        ),
        "tools": ["bettercap"],
    },
    {
        "id": "np-003", "name": "BGP/Routing Attacks",
        "category": "routing", "severity": "critical",
        "desc": "BGP and routing protocol attacks.",
        "detection": (
            "BGP/ROUTING ATTACKS:\n"
            "BGP HIJACKING:\n"
            "  - Announce more-specific prefix\n"
            "  - AS path manipulation\n"
            "  - Traffic interception/redirection\n"
            "  - Cryptocurrency theft via BGP\n"
            "  - Detection: RPKI, BGP monitoring\n"
            "BGP MONITORING:\n"
            "  - RIPE RIS Live\n"
            "  - BGPStream\n"
            "  - Looking glass servers\n"
            "  - RPKI validation\n"
            "OSPF ATTACKS:\n"
            "  - Rogue OSPF router\n"
            "  - LSA manipulation\n"
            "  - Area 0 injection\n"
            "  - MD5 auth bypass (if weak)\n"
            "RIP ATTACKS:\n"
            "  - Route injection\n"
            "  - Metric manipulation\n"
            "  - No authentication (RIPv1)\n"
            "VRRP/HSRP:\n"
            "  - Priority manipulation\n"
            "  - Virtual router takeover\n"
            "  - HSRP plaintext auth cracking\n"
            "DETECTION:\n"
            "  - Route origin validation (RPKI)\n"
            "  - BGP flowspec (DDoS mitigation)\n"
            "  - Route filtering (prefix lists)\n"
            "  - Community-based filtering\n"
            "TOOLS:\n"
            "  bgpstream, Loki (routing attacks), scapy"
        ),
        "tools": ["scapy"],
    },
    {
        "id": "np-004", "name": "SMTP/Email Attacks",
        "category": "smtp", "severity": "high",
        "desc": "SMTP and email protocol attacks.",
        "detection": (
            "SMTP/EMAIL ATTACKS:\n"
            "ENUMERATION:\n"
            "  # VRFY (verify user)\n"
            "  smtp-user-enum -M VRFY -U users.txt -t mail.target.com\n"
            "  # EXPN (expand mailing list)\n"
            "  smtp-user-enum -M EXPN -U users.txt -t mail.target.com\n"
            "  # RCPT TO enumeration\n"
            "  smtp-user-enum -M RCPT -U users.txt -t mail.target.com\n"
            "SPOOFING:\n"
            "  - Missing SPF record\n"
            "  - Weak DKIM (short key)\n"
            "  - No DMARC policy\n"
            "  - DMARC p=none\n"
            "  # Check:\n"
            "  dig target.com TXT          # SPF\n"
            "  dig _dmarc.target.com TXT   # DMARC\n"
            "  dig selector._domainkey.target.com TXT  # DKIM\n"
            "RELAY:\n"
            "  - Open relay testing\n"
            "  # nmap\n"
            "  nmap --script smtp-open-relay -p 25 target\n"
            "  # Manual\n"
            "  HELO test\n"
            "  MAIL FROM:<test@evil.com>\n"
            "  RCPT TO:<victim@other.com>\n"
            "ATTACKS:\n"
            "  - Header injection\n"
            "  - SMTP smuggling\n"
            "  - Attachment-based phishing\n"
            "  - Email bombing\n"
            "  - STARTTLS stripping\n"
            "TOOLS:\n"
            "  smtp-user-enum, swaks, nmap, SpamAssassin"
        ),
        "tools": ["nmap"],
    },
    {
        "id": "np-005", "name": "SNMP/Management Protocols",
        "category": "management", "severity": "high",
        "desc": "SNMP and management protocol attacks.",
        "detection": (
            "SNMP/MANAGEMENT PROTOCOL ATTACKS:\n"
            "SNMP:\n"
            "  # Community string brute force\n"
            "  onesixtyone -c community.txt TARGET\n"
            "  # SNMP walk (enumerate all)\n"
            "  snmpwalk -v2c -c public TARGET\n"
            "  # SNMPv1/v2c: cleartext community strings\n"
            "  # Default: public (read), private (write)\n"
            "  # Information exposed:\n"
            "  #   - System info, interfaces, routes\n"
            "  #   - Running processes, installed software\n"
            "  #   - User accounts, network config\n"
            "  # SNMP write access:\n"
            "  snmpset -v2c -c private TARGET OID type value\n"
            "  #   - Change device config\n"
            "  #   - Upload firmware\n"
            "  #   - Modify ACLs\n"
            "IPMI:\n"
            "  - IPMI 2.0 RAKP hash disclosure\n"
            "  # Retrieve hash without auth\n"
            "  ipmitool -I lanplus -H TARGET -U '' -P '' user list\n"
            "  # Metasploit\n"
            "  use auxiliary/scanner/ipmi/ipmi_dumphashes\n"
            "  # Default creds: ADMIN/ADMIN, root/calvin\n"
            "SSH:\n"
            "  - SSH key enumeration\n"
            "  - Weak algorithms (ssh-audit)\n"
            "  - User enumeration (CVE-2018-15473)\n"
            "  ssh-audit TARGET\n"
            "TELNET:\n"
            "  - Cleartext credentials\n"
            "  - Default credentials\n"
            "  - Banner grabbing\n"
            "TOOLS:\n"
            "  onesixtyone, snmpwalk, ipmitool, ssh-audit"
        ),
        "tools": ["nmap"],
    },
]


class NetworkProtocolKB:
    """Network protocol attacks knowledge base.

    Provides network protocol attack patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, NetProtoPattern] = {}
        self._log = logger.bind(component="netproto_kb")
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
        lines = ["## Network Protocol Attacks\n"]
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
