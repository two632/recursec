"""Network protocol security knowledge base.

Deep knowledge about network protocol vulnerabilities:
1. DNS attacks (cache poisoning, rebinding, tunneling)
2. TLS/SSL attacks (downgrade, MITM, certificate issues)
3. BGP hijacking
4. ARP spoofing
5. SNMP exploitation
6. SMB/NTLM relay
7. LDAP injection
8. Kerberos attacks
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class ProtocolVulnPattern:
    """A network protocol vulnerability pattern with methodology."""
    pattern_id: str = ""
    name: str = ""
    category: str = ""
    severity: str = "high"
    protocol: str = ""
    description: str = ""
    testing_methodology: str = ""
    tools: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:30],
            "protocol": self.protocol[:10],
            "severity": self.severity,
        }


PROTOCOL_VULN_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "net-001", "name": "DNS Security Assessment",
        "category": "dns", "severity": "high",
        "protocol": "DNS", "ports": [53],
        "desc": "DNS protocol vulnerabilities: poisoning, rebinding, tunneling, zone transfer.",
        "testing": (
            "DNS SECURITY TESTING:\n"
            "1. ZONE TRANSFER (AXFR):\n"
            "   dig @nameserver domain.com AXFR\n"
            "   If successful → full DNS zone leaked (all subdomains, IPs)\n"
            "   Test all authoritative nameservers\n"
            "2. DNS CACHE POISONING:\n"
            "   - Check DNSSEC: dig domain.com +dnssec\n"
            "   - If no DNSSEC → vulnerable to Kaminsky attack\n"
            "   - Check source port randomization\n"
            "   - Check transaction ID randomization\n"
            "3. DNS REBINDING:\n"
            "   - Set up DNS server that alternates between:\n"
            "     First query → attacker IP (pass CORS check)\n"
            "     Second query → target internal IP (127.0.0.1, 10.x.x.x)\n"
            "   - Bypass same-origin policy to access internal services\n"
            "   - Tools: singularity, rbndr\n"
            "4. DNS TUNNELING:\n"
            "   - Detect: unusually long DNS queries, high query volume\n"
            "   - Tools: iodine, dns2tcp, dnscat2\n"
            "   - Monitor TXT/NULL/CNAME record queries\n"
            "5. SUBDOMAIN TAKEOVER:\n"
            "   - Check CNAME records pointing to deprovisioned services\n"
            "   - GitHub Pages, Heroku, S3, Azure, Shopify, etc.\n"
            "   - dig CNAME subdomain.domain.com → NXDOMAIN on target = vulnerable\n"
            "6. DNS ENUMERATION:\n"
            "   - Brute force: fierce, dnsrecon, amass\n"
            "   - Certificate transparency: crt.sh\n"
            "   - Reverse DNS: host IP, dnsrecon -r range"
        ),
        "tools": ["dig", "dnsrecon", "amass", "subfinder", "fierce"],
    },
    {
        "id": "net-002", "name": "TLS/SSL Security Assessment",
        "category": "tls", "severity": "critical",
        "protocol": "TLS", "ports": [443, 8443, 993, 995, 465, 636],
        "desc": "TLS/SSL configuration and implementation vulnerabilities.",
        "testing": (
            "TLS/SSL SECURITY TESTING:\n"
            "1. PROTOCOL VERSION:\n"
            "   - testssl.sh target:443 (comprehensive)\n"
            "   - Check for: SSLv2, SSLv3, TLS 1.0, TLS 1.1 (all deprecated)\n"
            "   - Only TLS 1.2 and 1.3 should be enabled\n"
            "2. CIPHER SUITES:\n"
            "   - nmap --script ssl-enum-ciphers -p 443 target\n"
            "   - Flag: RC4, DES, 3DES, NULL, EXPORT ciphers\n"
            "   - Check for perfect forward secrecy (ECDHE, DHE)\n"
            "   - CBC mode ciphers with TLS 1.0 → BEAST\n"
            "3. KNOWN ATTACKS:\n"
            "   - POODLE (SSLv3): testssl --poodle\n"
            "   - BEAST (CBC+TLS1.0): testssl --beast\n"
            "   - CRIME/BREACH (compression): testssl --crime\n"
            "   - Heartbleed (CVE-2014-0160): nmap --script ssl-heartbleed\n"
            "   - ROBOT (RSA padding oracle): testssl --robot\n"
            "   - DROWN (SSLv2 cross-protocol): testssl --drown\n"
            "   - Lucky13 (CBC timing)\n"
            "4. CERTIFICATE ANALYSIS:\n"
            "   - Expiry: openssl s_client -connect target:443 | openssl x509 -dates\n"
            "   - Weak key (RSA < 2048, EC < 256)\n"
            "   - Self-signed, wrong CN/SAN, expired CA\n"
            "   - Certificate transparency: check CT logs\n"
            "   - OCSP stapling: openssl s_client -status\n"
            "5. HSTS:\n"
            "   - Check Strict-Transport-Security header\n"
            "   - includeSubDomains and preload flags\n"
            "   - HSTS preload list: hstspreload.org"
        ),
        "tools": ["testssl.sh", "sslyze", "nmap", "openssl"],
    },
    {
        "id": "net-003", "name": "SMB/NTLM Relay Attacks",
        "category": "smb", "severity": "critical",
        "protocol": "SMB", "ports": [139, 445],
        "desc": "SMB protocol attacks: relay, signing bypass, credential theft.",
        "testing": (
            "SMB/NTLM RELAY TESTING:\n"
            "1. SMB SIGNING CHECK:\n"
            "   - crackmapexec smb target --gen-relay-list relay.txt\n"
            "   - nmap --script smb-security-mode -p 445 target\n"
            "   - If signing NOT required → vulnerable to relay\n"
            "2. NTLM RELAY:\n"
            "   - Tool: impacket-ntlmrelayx\n"
            "   - ntlmrelayx.py -tf targets.txt -smb2support\n"
            "   - Coerce authentication: PetitPotam, PrinterBug, DFSCoerce\n"
            "   - Relay to: LDAP (add computer), SMB (exec), HTTP (ADCS)\n"
            "3. NTLM HASH CAPTURE:\n"
            "   - Responder: responds to LLMNR/NBT-NS/MDNS\n"
            "   - Captures NTLMv1/v2 hashes\n"
            "   - Crack with hashcat: mode 5600 (NTLMv2), 5500 (NTLMv1)\n"
            "4. SMB ENUMERATION:\n"
            "   - enum4linux-ng -A target\n"
            "   - smbclient -L //target -N (null session)\n"
            "   - crackmapexec smb target -u '' -p '' --shares\n"
            "   - Sensitive shares: SYSVOL, NETLOGON, C$, ADMIN$\n"
            "5. COERCION ATTACKS:\n"
            "   - PetitPotam: Forces NTLM auth from DC\n"
            "   - PrinterBug: MS-RPRN abuse\n"
            "   - DFSCoerce: MS-DFSNM abuse\n"
            "   - Relay to ADCS → domain admin"
        ),
        "tools": ["crackmapexec", "impacket", "Responder", "enum4linux"],
    },
    {
        "id": "net-004", "name": "Kerberos Attack Methodology",
        "category": "kerberos", "severity": "critical",
        "protocol": "Kerberos", "ports": [88],
        "desc": "Kerberos authentication attacks in Active Directory.",
        "testing": (
            "KERBEROS ATTACK METHODOLOGY:\n"
            "1. AS-REP ROASTING:\n"
            "   - Find accounts with 'Do not require Kerberos preauthentication'\n"
            "   - impacket-GetNPUsers domain/user -no-pass -dc-ip DC\n"
            "   - Crack with hashcat: mode 18200\n"
            "2. KERBEROASTING:\n"
            "   - Request TGS for service accounts\n"
            "   - impacket-GetUserSPNs domain/user:pass -dc-ip DC\n"
            "   - Crack with hashcat: mode 13100 (RC4), 19600/19700 (AES)\n"
            "   - Target: service accounts with weak passwords\n"
            "3. GOLDEN TICKET:\n"
            "   - Requires: krbtgt hash (domain compromise)\n"
            "   - impacket-ticketer -domain DOMAIN -domain-sid SID -nthash HASH admin\n"
            "   - Grants access to ANY service in the domain\n"
            "   - Valid until krbtgt password changes (twice)\n"
            "4. SILVER TICKET:\n"
            "   - Requires: service account hash\n"
            "   - Forged TGS for specific service\n"
            "   - Doesn't touch DC → harder to detect\n"
            "5. DELEGATION ATTACKS:\n"
            "   - Unconstrained delegation: Capture TGTs\n"
            "   - Constrained delegation: S4U2Self + S4U2Proxy abuse\n"
            "   - Resource-based constrained delegation (RBCD)\n"
            "6. PASS-THE-TICKET:\n"
            "   - Export tickets: klist, Rubeus dump\n"
            "   - Import: export KRB5CCNAME=ticket.ccache"
        ),
        "tools": ["impacket", "Rubeus", "hashcat", "crackmapexec"],
    },
    {
        "id": "net-005", "name": "LDAP Security Assessment",
        "category": "ldap", "severity": "high",
        "protocol": "LDAP", "ports": [389, 636, 3268, 3269],
        "desc": "LDAP protocol security and Active Directory enumeration.",
        "testing": (
            "LDAP SECURITY TESTING:\n"
            "1. ANONYMOUS BIND:\n"
            "   ldapsearch -x -H ldap://target -b 'dc=domain,dc=com'\n"
            "   If returns data → anonymous read access (information disclosure)\n"
            "2. LDAP INJECTION:\n"
            "   - Input: *)(uid=*))(|(uid=*\n"
            "   - Bypass authentication: admin)(&)\n"
            "   - OR injection: )(|(password=*)\n"
            "   - Wildcard: * matches everything\n"
            "3. AD ENUMERATION:\n"
            "   - bloodhound-python -c All -d domain.com -u user -p pass\n"
            "   - ldapdomaindump -u domain\\\\user -p pass target\n"
            "   - Enumerate: users, groups, computers, GPOs, trusts, ACLs\n"
            "4. PRIVILEGE ESCALATION:\n"
            "   - ACL abuse: WriteDACL, GenericAll, GenericWrite\n"
            "   - Group membership: Add self to Domain Admins\n"
            "   - Password change: ForceChangePassword ACE\n"
            "   - Shadow credentials: msDS-KeyCredentialLink\n"
            "5. LDAPS (LDAP over TLS):\n"
            "   - Check if LDAP (389) accepts cleartext auth\n"
            "   - Channel binding: Prevents NTLM relay to LDAP\n"
            "   - LDAP signing: Required vs not required"
        ),
        "tools": ["ldapsearch", "bloodhound", "ldapdomaindump", "crackmapexec"],
    },
    {
        "id": "net-006", "name": "SNMP Exploitation",
        "category": "snmp", "severity": "high",
        "protocol": "SNMP", "ports": [161, 162],
        "desc": "SNMP protocol security: community string bruteforce, information disclosure.",
        "testing": (
            "SNMP SECURITY TESTING:\n"
            "1. COMMUNITY STRING:\n"
            "   - Default strings: public, private, manager, cisco, admin\n"
            "   - Brute force: onesixtyone -c wordlist.txt target\n"
            "   - snmpwalk -v2c -c public target\n"
            "2. INFORMATION DISCLOSURE:\n"
            "   - System info: snmpwalk -v2c -c public target 1.3.6.1.2.1.1\n"
            "   - Interfaces: 1.3.6.1.2.1.2\n"
            "   - ARP table: 1.3.6.1.2.1.3\n"
            "   - Routing table: 1.3.6.1.2.1.4\n"
            "   - Running processes: 1.3.6.1.2.1.25.4.2\n"
            "   - Installed software: 1.3.6.1.2.1.25.6.3\n"
            "   - Network connections: 1.3.6.1.2.1.6.13\n"
            "3. WRITE ACCESS:\n"
            "   - If 'private' community has write access:\n"
            "   - snmpset -v2c -c private target OID type value\n"
            "   - Can modify: routing tables, VLAN config, SNMP config itself\n"
            "4. SNMP v3:\n"
            "   - Check authentication: noAuthNoPriv, authNoPriv, authPriv\n"
            "   - Brute force users: snmpv3enum, nmap snmp-brute\n"
            "5. CISCO SPECIFIC:\n"
            "   - Copy running-config via SNMP (OID: 1.3.6.1.4.1.9.2.1.55)\n"
            "   - Contains cleartext passwords if service password-encryption not set"
        ),
        "tools": ["snmpwalk", "onesixtyone", "snmp-check", "nmap"],
    },
]


class NetworkProtocolKB:
    """Network protocol security knowledge base.

    Provides deep network protocol attack methodology injected
    into agent prompts for network security assessment.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, ProtocolVulnPattern] = {}
        self._log = logger.bind(component="network_protocol_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load protocol vulnerability patterns."""
        for data in PROTOCOL_VULN_PATTERNS:
            pattern = ProtocolVulnPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                protocol=data.get("protocol", ""),
                description=data.get("desc", ""),
                testing_methodology=data.get("testing", ""),
                tools=data.get("tools", []),
                ports=data.get("ports", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_patterns_for_protocol(
        self,
        protocol: str,
    ) -> list[ProtocolVulnPattern]:
        """Get patterns for a specific protocol."""
        return [
            p for p in self._patterns.values()
            if p.protocol.lower() == protocol.lower()
        ]

    def get_patterns_for_port(
        self,
        port: int,
    ) -> list[ProtocolVulnPattern]:
        """Get patterns relevant to a specific port."""
        return [
            p for p in self._patterns.values()
            if port in p.ports
        ]

    def get_testing_prompts(
        self,
        protocols: list[str] | None = None,
        max_patterns: int = 3,
    ) -> list[str]:
        """Get testing prompts for agent context injection."""
        prompts = []
        for pattern in self._patterns.values():
            if protocols and pattern.protocol.lower() not in [p.lower() for p in protocols]:
                continue
            if pattern.testing_methodology:
                prompts.append(pattern.testing_methodology)
            if len(prompts) >= max_patterns:
                break
        return prompts

    def build_protocol_prompt(
        self,
        open_ports: list[int] | None = None,
        max_patterns: int = 3,
    ) -> str:
        """Build protocol testing prompt based on open ports."""
        relevant = []

        if open_ports:
            seen = set()
            for port in open_ports:
                for pattern in self.get_patterns_for_port(port):
                    if pattern.pattern_id not in seen:
                        relevant.append(pattern)
                        seen.add(pattern.pattern_id)
        else:
            relevant = list(self._patterns.values())

        lines = ["## Network Protocol Security Testing\n"]
        for pattern in relevant[:max_patterns]:
            lines.append(f"### {pattern.name} [{pattern.severity.upper()}] ({pattern.protocol})")
            lines.append(pattern.testing_methodology)
            lines.append("")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        cat_counts: dict[str, int] = defaultdict(int)
        for p in self._patterns.values():
            cat_counts[p.category] += 1
        return {
            "patterns": len(self._patterns),
            "by_category": dict(cat_counts),
        }
