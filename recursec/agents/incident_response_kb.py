"""Incident response knowledge base.

Playbooks for incident response scenarios:
1. Ransomware response
2. Data breach investigation
3. Insider threat detection
4. DDoS mitigation
5. Compromise assessment (post-breach)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class IRPattern:
    """An incident response pattern."""
    pattern_id: str = ""
    name: str = ""
    category: str = ""
    severity: str = "critical"
    description: str = ""
    playbook: str = ""
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:25],
            "category": self.category[:12],
        }


IR_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "ir-001", "name": "Ransomware Response",
        "category": "ransomware", "severity": "critical",
        "desc": "Ransomware incident response playbook.",
        "playbook": (
            "RANSOMWARE RESPONSE:\n"
            "IMMEDIATE ACTIONS:\n"
            "  1. Isolate affected systems (network disconnect)\n"
            "  2. Do NOT power off encrypted systems (volatile memory)\n"
            "  3. Capture memory dump: winpmem/LiME\n"
            "  4. Image affected disks before containment\n"
            "IDENTIFICATION:\n"
            "  # Identify ransomware family\n"
            "  - File extension analysis (.locked, .encrypted, etc.)\n"
            "  - Ransom note analysis\n"
            "  - https://id-ransomware.malwarehunterteam.com/\n"
            "  - Check for known decryptors: nomoreransom.org\n"
            "FORENSICS:\n"
            "  # Timeline analysis\n"
            "  - Windows: Event logs (Security, System, PowerShell)\n"
            "  - Check scheduled tasks and services\n"
            "  - MFT analysis for file modification timeline\n"
            "  - Prefetch analysis for execution history\n"
            "  # Lateral movement indicators\n"
            "  - RDP connections (Event ID 4624 Type 10)\n"
            "  - PsExec artifacts\n"
            "  - WMI event subscriptions\n"
            "  - PowerShell remoting (WinRM)\n"
            "RECOVERY:\n"
            "  - Restore from clean backups\n"
            "  - Rebuild from gold images\n"
            "  - Patch the initial access vector\n"
            "  - Reset ALL credentials (assume compromised)"
        ),
        "tools": ["volatility3", "autopsy", "plaso"],
    },
    {
        "id": "ir-002", "name": "Data Breach Investigation",
        "category": "breach", "severity": "critical",
        "desc": "Data breach investigation and containment.",
        "playbook": (
            "DATA BREACH INVESTIGATION:\n"
            "SCOPE ASSESSMENT:\n"
            "  1. Identify data types exposed (PII, PHI, PCI, credentials)\n"
            "  2. Determine volume of records affected\n"
            "  3. Identify access methods (external/insider)\n"
            "  4. Timeline of unauthorized access\n"
            "LOG ANALYSIS:\n"
            "  # Web server logs\n"
            "  - Unusual query patterns (mass downloads)\n"
            "  - SQL injection indicators in URIs\n"
            "  - Unusual user agents\n"
            "  # Database audit logs\n"
            "  - Large SELECT queries\n"
            "  - Bulk data export\n"
            "  - Schema enumeration queries\n"
            "  # Network logs\n"
            "  - Large outbound transfers\n"
            "  - Connections to known bad IPs\n"
            "  - DNS tunneling indicators\n"
            "CONTAINMENT:\n"
            "  - Block exfiltration channels\n"
            "  - Revoke compromised credentials\n"
            "  - Patch exploited vulnerability\n"
            "  - Enable additional monitoring\n"
            "NOTIFICATION:\n"
            "  - Legal/compliance team\n"
            "  - Regulatory bodies (GDPR: 72 hours)\n"
            "  - Affected individuals\n"
            "  - Law enforcement if applicable"
        ),
        "tools": ["splunk", "elasticsearch", "velociraptor"],
    },
    {
        "id": "ir-003", "name": "Insider Threat Detection",
        "category": "insider", "severity": "high",
        "desc": "Insider threat indicators and investigation.",
        "playbook": (
            "INSIDER THREAT DETECTION:\n"
            "BEHAVIORAL INDICATORS:\n"
            "  - Accessing data outside normal role\n"
            "  - Large file downloads/copies\n"
            "  - After-hours access patterns\n"
            "  - USB device usage spikes\n"
            "  - Cloud storage uploads\n"
            "  - Email to personal accounts\n"
            "TECHNICAL INDICATORS:\n"
            "  # Windows\n"
            "  - Event ID 4663: File access auditing\n"
            "  - Event ID 4688: Process creation\n"
            "  - Event ID 4648: Explicit credential logon\n"
            "  - USB: Event ID 6416 (device connect)\n"
            "  # Linux\n"
            "  - auditd rules for file access\n"
            "  - Command history analysis\n"
            "  - SSH key usage patterns\n"
            "INVESTIGATION:\n"
            "  # User activity timeline\n"
            "  - Correlate login times with file access\n"
            "  - Network traffic analysis per user\n"
            "  - Email analysis (DLP)\n"
            "  - Endpoint forensics\n"
            "DLP MONITORING:\n"
            "  - Sensitive data classification\n"
            "  - Egress monitoring\n"
            "  - Cloud access security broker (CASB)\n"
            "  - Endpoint detection and response (EDR)"
        ),
        "tools": ["velociraptor", "osquery", "sysmon"],
    },
    {
        "id": "ir-004", "name": "DDoS Mitigation",
        "category": "ddos", "severity": "high",
        "desc": "DDoS attack identification and mitigation.",
        "playbook": (
            "DDoS MITIGATION:\n"
            "IDENTIFICATION:\n"
            "  # Determine attack type\n"
            "  - Volumetric: UDP flood, ICMP flood, DNS amplification\n"
            "  - Protocol: SYN flood, ACK flood, fragmentation\n"
            "  - Application: HTTP flood, slowloris, RUDY\n"
            "  # Indicators\n"
            "  - Bandwidth utilization spike\n"
            "  - Connection count spike\n"
            "  - Request rate anomaly\n"
            "  - Geographic distribution of sources\n"
            "IMMEDIATE RESPONSE:\n"
            "  - Enable rate limiting\n"
            "  - Block attack source ranges\n"
            "  - Enable GeoIP blocking if applicable\n"
            "  - Activate upstream DDoS protection\n"
            "  - Increase server resources (auto-scale)\n"
            "NETWORK LEVEL:\n"
            "  # iptables rate limiting\n"
            "  iptables -A INPUT -p tcp --dport 80 -m limit \\\n"
            "    --limit 50/s --limit-burst 100 -j ACCEPT\n"
            "  # SYN flood protection\n"
            "  sysctl -w net.ipv4.tcp_syncookies=1\n"
            "  sysctl -w net.ipv4.tcp_max_syn_backlog=4096\n"
            "APPLICATION LEVEL:\n"
            "  - CAPTCHA for suspicious requests\n"
            "  - JavaScript challenges\n"
            "  - Request signature analysis\n"
            "  - Behavioral analysis (bot detection)"
        ),
        "tools": ["tcpdump", "nftables"],
    },
    {
        "id": "ir-005", "name": "Compromise Assessment",
        "category": "compromise", "severity": "critical",
        "desc": "Post-breach compromise assessment.",
        "playbook": (
            "COMPROMISE ASSESSMENT:\n"
            "IOC COLLECTION:\n"
            "  # File-based IOCs\n"
            "  - Hash suspicious files (MD5, SHA256)\n"
            "  - Check against VirusTotal, MISP\n"
            "  - YARA rule scanning\n"
            "  yara -r rules/ /path/to/scan/\n"
            "  # Network IOCs\n"
            "  - DNS query logs for C2 domains\n"
            "  - Netflow for beaconing patterns\n"
            "  - TLS certificate analysis\n"
            "PERSISTENCE MECHANISMS:\n"
            "  # Windows\n"
            "  - Scheduled tasks: schtasks /query /fo LIST\n"
            "  - Services: sc query type=all state=all\n"
            "  - Registry run keys\n"
            "  - WMI event subscriptions\n"
            "  - DLL search order hijacking\n"
            "  - COM object hijacking\n"
            "  # Linux\n"
            "  - Crontabs: crontab -l; ls /etc/cron.*\n"
            "  - Systemd services: systemctl list-units\n"
            "  - SSH authorized_keys\n"
            "  - LD_PRELOAD hijacking\n"
            "  - Modified binaries (debsums/rpm -V)\n"
            "MEMORY ANALYSIS:\n"
            "  # Volatility 3\n"
            "  vol3 -f memory.dmp windows.pslist\n"
            "  vol3 -f memory.dmp windows.malfind\n"
            "  vol3 -f memory.dmp windows.netscan\n"
            "  vol3 -f memory.dmp windows.cmdline"
        ),
        "tools": ["volatility3", "yara", "velociraptor"],
    },
]


class IncidentResponseKB:
    """Incident response knowledge base.

    Provides IR playbooks and patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, IRPattern] = {}
        self._log = logger.bind(component="incident_response_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load IR patterns."""
        for data in IR_PATTERNS:
            pattern = IRPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "critical"),
                description=data.get("desc", ""),
                playbook=data.get("playbook", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[IRPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_ir_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build incident response prompt."""
        lines = ["## Incident Response Playbooks\n"]
        count = 0
        for pattern in self._patterns.values():
            if categories and pattern.category.lower() not in [c.lower() for c in categories]:
                continue
            if count >= max_patterns:
                break
            lines.append(f"### {pattern.name} [{pattern.category.upper()}]")
            lines.append(pattern.playbook)
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
