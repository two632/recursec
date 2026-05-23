"""Incident response knowledge base.

Deep knowledge about incident response:
1. IR lifecycle and frameworks
2. Containment strategies
3. Evidence collection and preservation
4. Post-incident analysis
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
    severity: str = "critical"
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
        "category": "lifecycle", "severity": "critical",
        "desc": "NIST SP 800-61 incident response lifecycle.",
        "detection": (
            "IR LIFECYCLE (NIST SP 800-61):\n"
            "PHASE 1: PREPARATION\n"
            "  - IR plan and playbooks\n"
            "  - Communication plans (internal, external, legal)\n"
            "  - Tool readiness (forensics kit, jump bag)\n"
            "  - Contact lists (CIRT, legal, PR, vendors)\n"
            "  - Tabletop exercises\n"
            "  - Baseline documentation\n"
            "PHASE 2: DETECTION & ANALYSIS\n"
            "  - Alert triage and validation\n"
            "  - Indicator correlation\n"
            "  - Scope determination\n"
            "  - Timeline construction\n"
            "  - Initial classification:\n"
            "    P1: Critical (active data breach)\n"
            "    P2: High (ransomware, active intrusion)\n"
            "    P3: Medium (malware, policy violation)\n"
            "    P4: Low (scanning, recon attempts)\n"
            "PHASE 3: CONTAINMENT, ERADICATION, RECOVERY\n"
            "  - Short-term containment (isolate)\n"
            "  - Evidence preservation\n"
            "  - Long-term containment (patch, harden)\n"
            "  - Eradication (remove threat)\n"
            "  - Recovery (restore, monitor)\n"
            "PHASE 4: POST-INCIDENT\n"
            "  - Lessons learned meeting\n"
            "  - Report writing\n"
            "  - Metrics tracking (MTTD, MTTR)\n"
            "  - Process improvements"
        ),
        "tools": [],
    },
    {
        "id": "ir-002", "name": "Containment Strategies",
        "category": "containment", "severity": "critical",
        "desc": "Incident containment strategies.",
        "detection": (
            "CONTAINMENT STRATEGIES:\n"
            "NETWORK:\n"
            "  - VLAN isolation (quarantine VLAN)\n"
            "  - Firewall rules (block C2, lateral)\n"
            "  - DNS sinkhole (redirect C2 domains)\n"
            "  - Network segment isolation\n"
            "  - VPN access revocation\n"
            "  - BGP blackhole (DDoS)\n"
            "HOST:\n"
            "  - Endpoint isolation (EDR containment)\n"
            "  - Disable compromised accounts\n"
            "  - Disable remote services (RDP, SSH)\n"
            "  - Block malicious hashes (AppLocker)\n"
            "  - Remove persistence mechanisms\n"
            "  - Memory dump before shutdown\n"
            "IDENTITY:\n"
            "  - Password reset (compromised accounts)\n"
            "  - Revoke OAuth/API tokens\n"
            "  - Disable service accounts\n"
            "  - Force MFA re-enrollment\n"
            "  - Revoke certificates\n"
            "  - Conditional access policies\n"
            "CLOUD:\n"
            "  - Revoke IAM credentials\n"
            "  - Security group lockdown\n"
            "  - Snapshot compromised instances\n"
            "  - Disable API keys\n"
            "  - CloudTrail review\n"
            "  - S3 bucket policy lockdown\n"
            "DECISION:\n"
            "  - Business impact vs threat containment\n"
            "  - Evidence preservation vs immediate action\n"
            "  - Alert tipping (will attacker notice?)"
        ),
        "tools": [],
    },
    {
        "id": "ir-003", "name": "Evidence Collection",
        "category": "evidence", "severity": "high",
        "desc": "Digital evidence collection and preservation.",
        "detection": (
            "EVIDENCE COLLECTION:\n"
            "ORDER OF VOLATILITY:\n"
            "  1. Registers, cache\n"
            "  2. Memory (RAM)\n"
            "  3. Network state (connections, ARP)\n"
            "  4. Running processes\n"
            "  5. Disk (filesystem, swap)\n"
            "  6. Remote logging (SIEM)\n"
            "  7. Physical config\n"
            "  8. Archival media\n"
            "MEMORY:\n"
            "  # Linux\n"
            "  insmod lime.ko 'path=/evidence/mem.raw format=raw'\n"
            "  # Windows\n"
            "  winpmem_mini.exe evidence\\mem.raw\n"
            "  # Analysis: Volatility 3\n"
            "  vol3 -f mem.raw windows.pslist\n"
            "  vol3 -f mem.raw windows.netscan\n"
            "DISK:\n"
            "  # Full disk image\n"
            "  dc3dd if=/dev/sda of=disk.raw hash=sha256 log=disk.log\n"
            "  # Verify integrity\n"
            "  sha256sum disk.raw\n"
            "  # Mount read-only\n"
            "  mount -o ro,loop disk.raw /mnt/evidence\n"
            "NETWORK:\n"
            "  # Capture current connections\n"
            "  netstat -anob > connections.txt  # Windows\n"
            "  ss -tunap > connections.txt  # Linux\n"
            "  # Full packet capture\n"
            "  tcpdump -i eth0 -w capture.pcap\n"
            "LOGS:\n"
            "  - Export SIEM data for timeframe\n"
            "  - Windows Event Logs (evtx)\n"
            "  - Linux syslog, auth.log, journald\n"
            "  - Cloud audit logs (CloudTrail, Activity Log)\n"
            "CHAIN OF CUSTODY:\n"
            "  - Document who, what, when, where\n"
            "  - Hash all evidence (SHA-256)\n"
            "  - Secure storage (encrypted, access-controlled)"
        ),
        "tools": ["volatility3", "dc3dd"],
    },
    {
        "id": "ir-004", "name": "Post-Incident Analysis",
        "category": "post_incident", "severity": "medium",
        "desc": "Post-incident analysis and reporting.",
        "detection": (
            "POST-INCIDENT ANALYSIS:\n"
            "TIMELINE RECONSTRUCTION:\n"
            "  - Correlate all evidence sources\n"
            "  - Build unified timeline\n"
            "  - Identify initial access vector\n"
            "  - Map lateral movement\n"
            "  - Document data accessed/exfiltrated\n"
            "  - Determine dwell time\n"
            "ROOT CAUSE ANALYSIS:\n"
            "  - What vulnerability was exploited?\n"
            "  - Why wasn't it detected sooner?\n"
            "  - What controls failed?\n"
            "  - 5 Whys technique\n"
            "  - Fishbone diagram (Ishikawa)\n"
            "METRICS:\n"
            "  MTTD: Mean Time to Detect\n"
            "  MTTR: Mean Time to Respond\n"
            "  MTTC: Mean Time to Contain\n"
            "  MTTRE: Mean Time to Remediate\n"
            "  Cost: Financial impact\n"
            "  Scope: Systems/data affected\n"
            "REPORT:\n"
            "  - Executive summary\n"
            "  - Incident timeline\n"
            "  - Technical details\n"
            "  - Impact assessment\n"
            "  - Root cause\n"
            "  - Recommendations\n"
            "  - Indicators of Compromise\n"
            "LESSONS LEARNED:\n"
            "  - What worked well?\n"
            "  - What didn't work?\n"
            "  - Process improvements\n"
            "  - Tool gaps\n"
            "  - Training needs"
        ),
        "tools": [],
    },
    {
        "id": "ir-005", "name": "Recovery Procedures",
        "category": "recovery", "severity": "high",
        "desc": "System recovery and restoration.",
        "detection": (
            "RECOVERY PROCEDURES:\n"
            "PRIORITIZATION:\n"
            "  - Critical business services first\n"
            "  - Dependencies mapping\n"
            "  - Recovery Time Objective (RTO)\n"
            "  - Recovery Point Objective (RPO)\n"
            "REBUILD:\n"
            "  - Clean OS install from known-good media\n"
            "  - Patch to current before connecting to network\n"
            "  - Restore data from verified clean backups\n"
            "  - Change all credentials\n"
            "  - Review and harden configurations\n"
            "  - Verify no persistence remains\n"
            "RANSOMWARE:\n"
            "  - Check NoMoreRansom.org for decryptors\n"
            "  - Assess backup integrity\n"
            "  - Negotiate if no backups (last resort)\n"
            "  - Report to law enforcement (FBI IC3)\n"
            "  - Rebuild from clean state preferred\n"
            "VALIDATION:\n"
            "  - Verify clean state (AV/EDR scan)\n"
            "  - Monitor for re-compromise (30-90 days)\n"
            "  - Enhanced logging post-recovery\n"
            "  - Verify all IOCs absent\n"
            "  - User validation testing\n"
            "BUSINESS CONTINUITY:\n"
            "  - Activate BCP if needed\n"
            "  - Communication to stakeholders\n"
            "  - Regulatory notifications (GDPR 72hr)\n"
            "  - Insurance claims\n"
            "  - Customer notification if data breach"
        ),
        "tools": [],
    },
]


class IncidentResponseKB:
    """Incident response knowledge base.

    Provides IR methodology patterns
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
