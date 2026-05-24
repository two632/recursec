"""Incident response knowledge base.

Deep knowledge about incident response:
1. IR lifecycle and process
2. Containment strategies
3. Evidence collection
4. Root cause analysis
5. Recovery and lessons learned
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
    severity: str = "medium"
    description: str = ""
    detection_strategy: str = ""
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:25],
            "category": self.category[:12],
        }


IR_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "ir-001", "name": "IR Lifecycle",
        "category": "lifecycle", "severity": "medium",
        "desc": "Incident response lifecycle.",
        "detection": (
            "INCIDENT RESPONSE LIFECYCLE:\n"
            "NIST SP 800-61:\n"
            "  1. PREPARATION:\n"
            "    - IR plan and playbooks\n"
            "    - Communication plan\n"
            "    - Tool readiness\n"
            "    - Jump bag / forensic kit\n"
            "    - Contact lists (legal, PR, mgmt)\n"
            "    - Practice (tabletop exercises)\n"
            "  2. DETECTION & ANALYSIS:\n"
            "    - Alert triage and classification\n"
            "    - Severity assessment\n"
            "    - Scope determination\n"
            "    - Timeline construction\n"
            "    - IOC identification\n"
            "    - Affected systems inventory\n"
            "  3. CONTAINMENT:\n"
            "    - Short-term (isolate)\n"
            "    - Long-term (remediate)\n"
            "    - Evidence preservation\n"
            "  4. ERADICATION:\n"
            "    - Malware removal\n"
            "    - Vulnerability patching\n"
            "    - Account reset\n"
            "    - System rebuild\n"
            "  5. RECOVERY:\n"
            "    - System restoration\n"
            "    - Service validation\n"
            "    - Monitoring enhancement\n"
            "  6. LESSONS LEARNED:\n"
            "    - Post-incident review\n"
            "    - Process improvement\n"
            "    - Detection enhancement\n"
            "TOOLS:\n"
            "  TheHive, RTIR, Cortex, SOAR platforms"
        ),
        "tools": [],
    },
    {
        "id": "ir-002", "name": "Containment Strategies",
        "category": "containment", "severity": "high",
        "desc": "Incident containment techniques.",
        "detection": (
            "CONTAINMENT STRATEGIES:\n"
            "NETWORK:\n"
            "  - VLAN isolation\n"
            "  - Firewall rule insertion\n"
            "    # Block malicious IPs/domains\n"
            "    # Isolate compromised segments\n"
            "  - DNS sinkhole (C2 domains)\n"
            "  - Proxy block rules\n"
            "  - BGP blackhole\n"
            "ENDPOINT:\n"
            "  - Network quarantine (EDR)\n"
            "  - Process termination\n"
            "  - Service disabling\n"
            "  - Account lockout\n"
            "  - USB blocking\n"
            "  - Full disk encryption lock\n"
            "IDENTITY:\n"
            "  - Password reset (compromised accounts)\n"
            "  - MFA enforcement\n"
            "  - Token revocation\n"
            "  - Session invalidation\n"
            "  - Conditional access policies\n"
            "  - Service account rotation\n"
            "CLOUD:\n"
            "  - Security group lockdown\n"
            "  - IAM policy restriction\n"
            "  - Instance isolation\n"
            "  - API key rotation\n"
            "  - S3 bucket policy\n"
            "EMAIL:\n"
            "  - Phishing URL blocking\n"
            "  - Sender blocking\n"
            "  - Attachment quarantine\n"
            "TOOLS:\n"
            "  CrowdStrike, SentinelOne, Carbon Black"
        ),
        "tools": [],
    },
    {
        "id": "ir-003", "name": "Evidence Collection",
        "category": "evidence", "severity": "medium",
        "desc": "Digital evidence collection.",
        "detection": (
            "EVIDENCE COLLECTION:\n"
            "ORDER OF VOLATILITY:\n"
            "  1. CPU registers, cache\n"
            "  2. Routing table, ARP cache, processes\n"
            "  3. Memory (RAM)\n"
            "  4. Temporary file systems\n"
            "  5. Disk\n"
            "  6. Remote logging, monitoring\n"
            "  7. Physical config, topology\n"
            "  8. Archival media\n"
            "MEMORY:\n"
            "  # LiME (Linux)\n"
            "  insmod lime.ko path=/tmp/mem.lime format=lime\n"
            "  # WinPmem (Windows)\n"
            "  winpmem_mini.exe mem.raw\n"
            "  # DumpIt\n"
            "DISK:\n"
            "  # Write-blocker (hardware preferred)\n"
            "  # dd with hash verification\n"
            "  dc3dd if=/dev/sda of=image.raw hash=sha256\n"
            "NETWORK:\n"
            "  # Full packet capture\n"
            "  tcpdump -i eth0 -w evidence.pcap\n"
            "  # NetFlow records\n"
            "  # Proxy/firewall logs\n"
            "LOGS:\n"
            "  - Windows: evtx files\n"
            "  - Linux: /var/log/*\n"
            "  - Application: web server, DB\n"
            "  - Cloud: CloudTrail, Activity Log\n"
            "CHAIN OF CUSTODY:\n"
            "  - Document every transfer\n"
            "  - Hash all evidence\n"
            "  - Timestamp everything\n"
            "  - Secure storage\n"
            "TOOLS:\n"
            "  LiME, WinPmem, dc3dd, FTK Imager"
        ),
        "tools": [],
    },
    {
        "id": "ir-004", "name": "Root Cause Analysis",
        "category": "rca", "severity": "medium",
        "desc": "Root cause analysis techniques.",
        "detection": (
            "ROOT CAUSE ANALYSIS:\n"
            "TIMELINE:\n"
            "  - Plaso/log2timeline\n"
            "    # Create super-timeline from all sources\n"
            "  - Correlate:\n"
            "    # Network events\n"
            "    # Endpoint events\n"
            "    # Authentication events\n"
            "    # Application events\n"
            "    # Cloud events\n"
            "INITIAL ACCESS:\n"
            "  - Phishing email analysis\n"
            "  - Exploit identification\n"
            "  - Credential source\n"
            "  - Supply chain compromise\n"
            "  - Insider threat\n"
            "LATERAL MOVEMENT:\n"
            "  - RDP/SSH session tracking\n"
            "  - PsExec/WMI/WinRM\n"
            "  - Pass-the-hash/ticket\n"
            "  - Service account abuse\n"
            "  - SMB/admin shares\n"
            "PERSISTENCE:\n"
            "  - Scheduled tasks/cron\n"
            "  - Registry run keys\n"
            "  - Service creation\n"
            "  - Web shells\n"
            "  - Bootkit/rootkit\n"
            "  - Account creation\n"
            "IMPACT:\n"
            "  - Data access/exfiltration\n"
            "  - System modification\n"
            "  - Privilege escalation path\n"
            "  - Ransomware deployment\n"
            "TOOLS:\n"
            "  Plaso, Autopsy, Volatility, KAPE"
        ),
        "tools": [],
    },
    {
        "id": "ir-005", "name": "Recovery and Lessons Learned",
        "category": "recovery", "severity": "medium",
        "desc": "Recovery procedures and improvement.",
        "detection": (
            "RECOVERY & LESSONS LEARNED:\n"
            "SYSTEM RECOVERY:\n"
            "  - Rebuild from clean images\n"
            "  - Restore from verified backups\n"
            "  - Patch all vulnerabilities\n"
            "  - Reset all credentials\n"
            "  - Verify system integrity\n"
            "  - Staged reconnection\n"
            "VALIDATION:\n"
            "  - Vulnerability scan (post-fix)\n"
            "  - IOC sweep (re-scan)\n"
            "  - Behavioral monitoring\n"
            "  - User verification\n"
            "  - Service health checks\n"
            "MONITORING:\n"
            "  - Enhanced logging\n"
            "  - New detection rules\n"
            "  - Threat hunting queries\n"
            "  - Increased alert sensitivity\n"
            "LESSONS LEARNED:\n"
            "  - Conduct post-incident review\n"
            "  - Document:\n"
            "    # What happened\n"
            "    # When detected\n"
            "    # How contained\n"
            "    # What worked / didn't work\n"
            "    # Recommendations\n"
            "  - Update:\n"
            "    # IR playbooks\n"
            "    # Detection rules\n"
            "    # Security policies\n"
            "    # Training materials\n"
            "  - Track improvements\n"
            "  - Metrics: MTTD, MTTR, MTTC\n"
            "TOOLS:\n"
            "  TheHive, RTIR, Jira, Wiki"
        ),
        "tools": [],
    },
]


class IncidentResponseKB:
    """Incident response knowledge base.

    Provides IR patterns injected
    into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, IRPattern] = {}
        self._log = logger.bind(component="ir_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load IR patterns."""
        for data in IR_PATTERNS:
            pattern = IRPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "medium"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
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
        """Build IR prompt."""
        lines = ["## Incident Response\n"]
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
