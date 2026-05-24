"""Incident response knowledge base.

Attack patterns and procedures for incident response:
1. Detection & Triage — alert analysis, severity classification, initial scoping
2. Containment Strategies — isolation, blocking, network segmentation
3. Evidence Collection — forensic imaging, log preservation, chain of custody
4. Eradication & Recovery — malware removal, persistence cleanup, rebuilding
5. Post-Incident Analysis — root cause, timeline reconstruction, lessons learned
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class IRPhase(str, Enum):
    DETECTION = "detection"
    CONTAINMENT = "containment"
    EVIDENCE = "evidence"
    ERADICATION = "eradication"
    POST_INCIDENT = "post_incident"


@dataclass
class IRPattern:
    """An incident response pattern."""
    name: str = ""
    phase: IRPhase = IRPhase.DETECTION
    description: str = ""
    procedures: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    checklists: list[str] = field(default_factory=list)
    severity: str = "high"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "phase": self.phase.value,
            "severity": self.severity,
            "procedures": len(self.procedures),
        }


IR_PATTERNS: list[IRPattern] = [
    IRPattern(
        name="Detection & Triage",
        phase=IRPhase.DETECTION,
        description=(
            "Initial detection, alert analysis, severity classification, "
            "and scoping of security incidents. Determine blast radius "
            "and activate appropriate response level."
        ),
        procedures=[
            "Classify alert source (SIEM, EDR, IDS, user report, threat intel)",
            "Determine alert fidelity (true positive, false positive, benign)",
            "Assess severity using CVSS/org-specific severity matrix",
            "Identify affected systems, users, and data scope",
            "Check for related alerts across time window (correlation)",
            "Determine if incident is ongoing or historical",
            "Activate incident response team at appropriate level",
            "Create incident ticket with initial findings and timeline",
        ],
        indicators=[
            "Multiple failed login attempts followed by success",
            "Unusual process execution (powershell, certutil, bitsadmin)",
            "Outbound connections to known C2 infrastructure",
            "Large data transfers outside business hours",
            "New scheduled tasks or services created",
            "Registry run key modifications",
        ],
        tools=["splunk", "elastic", "crowdstrike", "sentinel", "velociraptor"],
        commands=[
            "splunk search 'index=security sourcetype=WinEventLog EventCode=4625 | stats count by src_ip'",
            "elastic query: {\"query\":{\"range\":{\"@timestamp\":{\"gte\":\"now-1h\"}}}}",
            "velociraptor collect Windows.System.Pslist",
            "crowdstrike falcon search /detects",
            "grep -rn 'CRITICAL\\|ALERT' /var/log/syslog | tail -50",
        ],
        checklists=[
            "Alert received and acknowledged within SLA",
            "Initial severity assessment completed",
            "Affected scope identified (systems, users, data)",
            "Incident response team notified",
            "Incident ticket created with timeline",
        ],
        severity="high",
    ),
    IRPattern(
        name="Containment Strategies",
        phase=IRPhase.CONTAINMENT,
        description=(
            "Short-term and long-term containment: network isolation, "
            "account disabling, firewall rule deployment, DNS sinkholing, "
            "and controlled environment for monitoring adversary."
        ),
        procedures=[
            "Isolate affected hosts from network (disable port or VLAN change)",
            "Disable compromised user accounts and revoke sessions",
            "Block malicious IPs/domains at firewall/proxy/DNS",
            "Deploy emergency firewall rules to segment affected network",
            "Sinkhole C2 domains to monitor beacon attempts",
            "Quarantine malicious files across all endpoints via EDR",
            "Reset credentials for affected and potentially affected accounts",
            "Preserve system state before containment actions for forensics",
        ],
        indicators=[
            "Continued C2 beaconing after initial detection",
            "Lateral movement attempts from compromised host",
            "Data staging or exfiltration in progress",
            "Additional hosts showing compromise indicators",
            "Adversary attempting to escalate privileges",
            "Persistence mechanisms being deployed",
        ],
        tools=["crowdstrike", "sentinel", "paloalto", "cisco-ise", "iptables"],
        commands=[
            "iptables -I INPUT -s MALICIOUS_IP -j DROP",
            "iptables -I OUTPUT -d MALICIOUS_IP -j DROP",
            "crowdstrike contain-host --host-id <id>",
            "net user COMPROMISED_USER /active:no /domain",
            "dnsmasq --address=/malicious-domain.com/127.0.0.1",
            "ip link set eth0 down  # network isolation",
        ],
        checklists=[
            "Affected hosts isolated from production network",
            "Compromised accounts disabled and sessions revoked",
            "Malicious IPs/domains blocked at perimeter",
            "EDR containment actions deployed",
            "Evidence preserved before containment changes",
        ],
        severity="critical",
    ),
    IRPattern(
        name="Evidence Collection",
        phase=IRPhase.EVIDENCE,
        description=(
            "Forensic evidence collection with chain of custody: "
            "memory acquisition, disk imaging, log preservation, "
            "network capture, and artifact collection."
        ),
        procedures=[
            "Acquire volatile memory before shutdown (RAM dump)",
            "Create forensic disk image (bit-for-bit copy)",
            "Collect and preserve relevant log sources",
            "Capture network traffic from affected segments",
            "Document chain of custody for all evidence",
            "Hash all evidence files (SHA256) for integrity",
            "Collect browser artifacts, email headers, file metadata",
            "Preserve cloud audit logs and API activity logs",
        ],
        indicators=[
            "Memory contains running malware processes",
            "Disk artifacts show deleted files or wiped logs",
            "Network captures show C2 protocol patterns",
            "Log gaps indicating log tampering or deletion",
            "Browser history showing phishing site access",
            "Email headers with spoofed sender addresses",
        ],
        tools=["volatility3", "autopsy", "ftk-imager", "wireshark",
               "velociraptor", "kape"],
        commands=[
            "winpmem_mini.exe memdump.raw",
            "dc3dd if=/dev/sda of=disk.dd hash=sha256 log=imaging.log",
            "volatility3 -f memdump.raw windows.pslist.PsList",
            "volatility3 -f memdump.raw windows.netscan.NetScan",
            "sha256sum evidence_* > hashes.txt",
            "tcpdump -i eth0 -w capture.pcap -c 100000",
        ],
        checklists=[
            "Memory dump acquired before system shutdown",
            "Disk image created with hash verification",
            "All relevant logs collected and preserved",
            "Network capture from affected segments",
            "Chain of custody documentation complete",
            "Evidence hashes recorded and verified",
        ],
        severity="high",
    ),
    IRPattern(
        name="Eradication & Recovery",
        phase=IRPhase.ERADICATION,
        description=(
            "Complete removal of adversary presence: malware removal, "
            "persistence mechanism cleanup, system rebuilding, "
            "credential rotation, and controlled restoration."
        ),
        procedures=[
            "Identify all persistence mechanisms (autoruns, scheduled tasks, services)",
            "Remove malware from all affected systems",
            "Clean registry modifications and startup entries",
            "Remove unauthorized user accounts and SSH keys",
            "Rotate all potentially compromised credentials",
            "Rebuild compromised systems from known-good images",
            "Patch vulnerabilities exploited in initial compromise",
            "Restore data from verified clean backups",
        ],
        indicators=[
            "All known malware samples removed and verified",
            "No persistence mechanisms remaining",
            "All compromised credentials rotated",
            "Vulnerabilities patched on all affected systems",
            "Systems rebuilt from clean images",
            "Monitoring confirms no continued adversary activity",
        ],
        tools=["autoruns", "procmon", "yara", "crowdstrike",
               "velociraptor", "ansible"],
        commands=[
            "autoruns -a -m -h -c > autoruns.csv",
            "schtasks /query /fo CSV /v > scheduled_tasks.csv",
            "yara -r malware_rules.yar / 2>/dev/null",
            "find / -name 'authorized_keys' -exec cat {} +",
            "find / -newer /tmp/incident_time -type f 2>/dev/null | head -100",
            "chkrootkit",
        ],
        checklists=[
            "All malware removed from all systems",
            "All persistence mechanisms identified and removed",
            "All compromised credentials rotated",
            "Affected systems rebuilt or verified clean",
            "Patches deployed for exploited vulnerabilities",
            "Restored systems monitored for re-compromise",
        ],
        severity="critical",
    ),
    IRPattern(
        name="Post-Incident Analysis",
        phase=IRPhase.POST_INCIDENT,
        description=(
            "Root cause analysis, timeline reconstruction, lessons "
            "learned, and process improvement after incident closure."
        ),
        procedures=[
            "Reconstruct full incident timeline from all evidence",
            "Identify root cause and initial attack vector",
            "Map adversary TTPs to MITRE ATT&CK framework",
            "Assess data exposure and regulatory impact",
            "Document detection gaps and missed indicators",
            "Identify process failures and improvement opportunities",
            "Update detection rules based on incident IOCs",
            "Conduct blameless post-mortem with all stakeholders",
        ],
        indicators=[
            "Complete timeline from initial compromise to containment",
            "Root cause identified with confidence level",
            "All adversary TTPs mapped to MITRE ATT&CK",
            "Data exposure scope fully assessed",
            "Detection improvements implemented",
            "Updated runbooks and procedures documented",
        ],
        tools=["mitre-attack-navigator", "timesketch", "plaso",
               "misp", "opencti"],
        commands=[
            "plaso log2timeline --storage-file timeline.plaso /evidence/",
            "psort.py -o l2tcsv -w timeline.csv timeline.plaso",
            "misp-warninglist check <ioc_list>",
            "grep -rn 'T[0-9][0-9][0-9][0-9]' incident_report.md",
            "# Generate MITRE ATT&CK Navigator layer from TTPs",
        ],
        checklists=[
            "Full incident timeline documented",
            "Root cause analysis completed",
            "Adversary TTPs mapped to ATT&CK",
            "Data exposure assessment complete",
            "Lessons learned documented",
            "Detection and response improvements planned",
            "Post-mortem meeting conducted",
        ],
        severity="medium",
    ),
]


def build_incident_response_prompt(
    focus_phase: IRPhase | None = None,
    max_patterns: int = 5,
) -> str:
    """Build LLM prompt with incident response knowledge."""
    lines = ["## Incident Response Knowledge\n"]

    patterns = IR_PATTERNS
    if focus_phase:
        patterns = [p for p in patterns if p.phase == focus_phase]

    for pattern in patterns[:max_patterns]:
        lines.append(f"### {pattern.name} [{pattern.severity}]")
        lines.append(pattern.description)
        lines.append("\nProcedures:")
        for proc in pattern.procedures[:4]:
            lines.append(f"  - {proc}")
        lines.append("\nIndicators:")
        for indicator in pattern.indicators[:3]:
            lines.append(f"  - {indicator}")
        lines.append("\nCommands:")
        for cmd in pattern.commands[:3]:
            lines.append(f"  $ {cmd}")
        lines.append("\nChecklist:")
        for item in pattern.checklists[:3]:
            lines.append(f"  [ ] {item}")
        lines.append("")

    return "\n".join(lines)
