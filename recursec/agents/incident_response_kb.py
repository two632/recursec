"""Incident response knowledge base.

Deep knowledge about incident response:
1. IR methodology (NIST/SANS)
2. Containment strategies
3. Eradication procedures
4. Evidence collection and preservation
5. Post-incident analysis
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


IR_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "ir-001", "name": "IR Methodology",
        "category": "methodology", "severity": "high",
        "desc": "Incident response methodology.",
        "detection": (
            "IR METHODOLOGY:\n"
            "NIST SP 800-61:\n"
            "  1. PREPARATION:\n"
            "    - IR plan and team\n"
            "    - Communication plans\n"
            "    - Tool deployment\n"
            "    - Training and exercises\n"
            "  2. DETECTION & ANALYSIS:\n"
            "    - Alert triage and validation\n"
            "    - Initial scoping\n"
            "    - Indicator analysis\n"
            "    - Impact assessment\n"
            "    - Classification (severity, type)\n"
            "  3. CONTAINMENT, ERADICATION, RECOVERY:\n"
            "    - Short-term containment\n"
            "    - Evidence preservation\n"
            "    - Long-term containment\n"
            "    - Threat eradication\n"
            "    - System recovery\n"
            "  4. POST-INCIDENT:\n"
            "    - Lessons learned\n"
            "    - Report writing\n"
            "    - Process improvement\n"
            "SANS 6-STEP:\n"
            "  1. Preparation\n"
            "  2. Identification\n"
            "  3. Containment\n"
            "  4. Eradication\n"
            "  5. Recovery\n"
            "  6. Lessons Learned\n"
            "CLASSIFICATION:\n"
            "  - Malware infection\n"
            "  - Data breach/exfiltration\n"
            "  - Unauthorized access\n"
            "  - Denial of service\n"
            "  - Insider threat\n"
            "  - Ransomware\n"
            "  - Supply chain compromise"
        ),
        "tools": [],
    },
    {
        "id": "ir-002", "name": "Containment Strategies",
        "category": "containment", "severity": "critical",
        "desc": "Incident containment approaches.",
        "detection": (
            "CONTAINMENT STRATEGIES:\n"
            "NETWORK:\n"
            "  - Isolate affected hosts\n"
            "  - Block malicious IPs/domains\n"
            "  - Sinkhole DNS\n"
            "  - Null-route traffic\n"
            "  - Segment network (VLANs)\n"
            "  - Enable firewall rules\n"
            "  - Disable compromised VPN accounts\n"
            "ENDPOINT:\n"
            "  - Quarantine host (EDR)\n"
            "  - Disable user accounts\n"
            "  - Revoke tokens/sessions\n"
            "  - Reset credentials\n"
            "  - Disable remote access\n"
            "  - Block process execution\n"
            "CLOUD:\n"
            "  - Revoke IAM keys/roles\n"
            "  - Disable API endpoints\n"
            "  - Isolate compromised instances\n"
            "  - Restrict security groups\n"
            "  - Rotate secrets\n"
            "  - Enable MFA enforcement\n"
            "EMAIL:\n"
            "  - Block sender/domain\n"
            "  - Purge malicious emails\n"
            "  - Disable mail rules\n"
            "  - Reset compromised mailboxes\n"
            "DECISION FACTORS:\n"
            "  - Business impact of containment\n"
            "  - Evidence preservation needs\n"
            "  - Attacker awareness risk\n"
            "  - Scope of compromise"
        ),
        "tools": [],
    },
    {
        "id": "ir-003", "name": "Eradication Procedures",
        "category": "eradication", "severity": "critical",
        "desc": "Threat eradication techniques.",
        "detection": (
            "ERADICATION PROCEDURES:\n"
            "MALWARE:\n"
            "  - Identify all infected systems\n"
            "  - Remove malware binaries\n"
            "  - Clean registry/startup entries\n"
            "  - Remove scheduled tasks\n"
            "  - Clean WMI subscriptions\n"
            "  - Rebuild from clean image if needed\n"
            "PERSISTENCE:\n"
            "  - Registry run keys\n"
            "  - Services and drivers\n"
            "  - Scheduled tasks/cron jobs\n"
            "  - DLL side-loading\n"
            "  - Bootkit/rootkit removal\n"
            "  - Web shells\n"
            "  - Backdoor accounts\n"
            "  - SSH authorized_keys\n"
            "  - GPO modifications\n"
            "CREDENTIAL RESET:\n"
            "  - All compromised accounts\n"
            "  - Service accounts\n"
            "  - Kerberos tickets (krbtgt reset)\n"
            "  - Machine account passwords\n"
            "  - API keys and tokens\n"
            "  - Certificate revocation\n"
            "AD SPECIFIC:\n"
            "  - krbtgt password reset (2x)\n"
            "  - Trust relationship review\n"
            "  - AdminSDHolder cleanup\n"
            "  - Group policy review\n"
            "  - ACL audit\n"
            "VERIFICATION:\n"
            "  - Scan all systems\n"
            "  - Monitor for re-infection\n"
            "  - Network traffic analysis\n"
            "  - Hash-based IOC sweep"
        ),
        "tools": [],
    },
    {
        "id": "ir-004", "name": "Evidence Collection",
        "category": "evidence", "severity": "high",
        "desc": "Digital evidence collection and preservation.",
        "detection": (
            "EVIDENCE COLLECTION:\n"
            "ORDER OF VOLATILITY:\n"
            "  1. CPU registers, cache\n"
            "  2. Memory (RAM)\n"
            "  3. Network connections\n"
            "  4. Running processes\n"
            "  5. Disk (filesystem)\n"
            "  6. Remote logs\n"
            "  7. Physical evidence\n"
            "MEMORY:\n"
            "  # Windows\n"
            "  winpmem_mini.exe memdump.raw\n"
            "  # Linux\n"
            "  dd if=/proc/kcore of=memdump.raw\n"
            "  # LiME module\n"
            "  insmod lime.ko path=/tmp/mem.lime format=lime\n"
            "DISK:\n"
            "  # Full disk image\n"
            "  dd if=/dev/sda of=disk.img bs=4M conv=sync,noerror\n"
            "  # With hashing\n"
            "  dc3dd if=/dev/sda of=disk.img hash=md5 log=hash.log\n"
            "  # Selective collection\n"
            "  # Triage: logs, prefetch, registry, browser\n"
            "LOGS:\n"
            "  # Windows Event Logs\n"
            "  wevtutil epl Security sec.evtx\n"
            "  wevtutil epl System sys.evtx\n"
            "  # Linux\n"
            "  /var/log/auth.log\n"
            "  /var/log/syslog\n"
            "  journalctl --since '24 hours ago'\n"
            "CHAIN OF CUSTODY:\n"
            "  - Document who, what, when, where\n"
            "  - Hash all evidence (SHA-256)\n"
            "  - Secure storage\n"
            "  - Access log\n"
            "TOOLS:\n"
            "  FTK Imager, dc3dd, LiME, Velociraptor"
        ),
        "tools": ["velociraptor"],
    },
    {
        "id": "ir-005", "name": "Post-Incident Analysis",
        "category": "post_incident", "severity": "medium",
        "desc": "Post-incident analysis and improvement.",
        "detection": (
            "POST-INCIDENT ANALYSIS:\n"
            "TIMELINE RECONSTRUCTION:\n"
            "  - Build complete attack timeline\n"
            "  - Initial compromise vector\n"
            "  - Lateral movement path\n"
            "  - Data access/exfiltration\n"
            "  - Persistence mechanisms\n"
            "  - Tools: Plaso (log2timeline), Timesketch\n"
            "ROOT CAUSE ANALYSIS:\n"
            "  - What vulnerability was exploited?\n"
            "  - Why wasn't it detected earlier?\n"
            "  - What controls failed?\n"
            "  - 5 Whys technique\n"
            "  - Fishbone diagram\n"
            "METRICS:\n"
            "  - MTTD: Mean Time To Detect\n"
            "  - MTTC: Mean Time To Contain\n"
            "  - MTTR: Mean Time To Recover\n"
            "  - Scope: Systems/accounts affected\n"
            "  - Data exposure volume\n"
            "  - Business impact ($)\n"
            "LESSONS LEARNED:\n"
            "  - What went well?\n"
            "  - What could improve?\n"
            "  - Specific action items\n"
            "  - Detection gap remediation\n"
            "  - Process improvements\n"
            "  - Training needs\n"
            "REPORTING:\n"
            "  - Executive summary\n"
            "  - Technical details\n"
            "  - Timeline\n"
            "  - Impact assessment\n"
            "  - Remediation recommendations\n"
            "  - Regulatory notifications\n"
            "    (GDPR: 72 hours, PCI: immediately)\n"
            "TOOLS:\n"
            "  Plaso, Timesketch, TheHive, MISP"
        ),
        "tools": ["plaso", "thehive"],
    },
]


class IncidentResponseKB:
    """Incident response knowledge base.

    Provides IR patterns injected into agent prompts.
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
                severity=data.get("severity", "high"),
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
        """Build incident response prompt."""
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
