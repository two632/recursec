"""Threat intelligence knowledge base."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
import structlog
logger = structlog.get_logger()

class ThreatIntelType(str, Enum):
    MITRE_ATTACK = "mitre_attack"
    IOC_ANALYSIS = "ioc_analysis"
    ACTOR_PROFILING = "actor_profiling"
    KILL_CHAIN = "kill_chain"
    THREAT_HUNTING = "threat_hunting"

@dataclass
class ThreatIntelPattern:
    name: str = ""
    intel_type: ThreatIntelType = ThreatIntelType.MITRE_ATTACK
    description: str = ""
    methodology: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    severity: str = "high"
    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "type": self.intel_type.value, "severity": self.severity}

THREAT_INTEL_PATTERNS: list[ThreatIntelPattern] = [
    ThreatIntelPattern(name="MITRE ATT&CK Framework Mapping", intel_type=ThreatIntelType.MITRE_ATTACK, description="Map observed behaviors to MITRE ATT&CK tactics/techniques. 14 tactics, 200+ techniques, sub-techniques. Enables standardized threat communication and gap analysis.", methodology=["Collect observed adversary behaviors from logs/alerts", "Map each behavior to ATT&CK technique ID (T1566 Phishing)", "Identify tactic (Initial Access, Execution, Persistence)", "Check sub-techniques (T1566.001 Spear-phishing Attachment)", "Build ATT&CK Navigator layer for visual coverage", "Identify defensive gaps", "Map to data sources needed for detection", "Create detection rules (Sigma, YARA, Snort) per technique"], indicators=["14 Tactics: Recon→Resource Dev→Initial Access→Execution→Persistence→PrivEsc→Defense Evasion→Cred Access→Discovery→Lateral Movement→Collection→C2→Exfil→Impact", "200+ techniques with unique IDs", "Sub-techniques for granular mapping"], tools=["mitre-attack-navigator", "sigma", "atomic-red-team", "caldera"], commands=["sigma convert -t splunk -p sysmon rules/windows/*.yml", "invoke-atomictest T1566.001 -GetPrereqs"], severity="high"),
    ThreatIntelPattern(name="IoC Analysis", intel_type=ThreatIntelType.IOC_ANALYSIS, description="Analyze and correlate IoCs: file hashes, IPs, domains, URLs, YARA rules. Cross-reference with threat intel feeds.", methodology=["Collect IoCs: hashes, IPs, domains, URLs", "Query threat intel platforms (VirusTotal, OTX, MISP)", "Cross-reference with known actor infrastructure", "Check domain registration and hosting patterns", "Build YARA rules for similar sample detection", "Create STIX/TAXII bundles for sharing", "Set up continuous monitoring for IoC hits"], indicators=["File hashes (MD5/SHA256)", "C2 IPs and domains", "Malicious URLs and emails", "JA3/JA3S TLS fingerprints"], tools=["yara", "misp", "opencti", "threatfox"], commands=["yara -r rules/ /path/to/scan/", "sha256sum suspicious_file", "whois suspicious.domain"], severity="high"),
    ThreatIntelPattern(name="Threat Actor Profiling", intel_type=ThreatIntelType.ACTOR_PROFILING, description="Profile APT groups, cybercriminals, hacktivists. Analyze TTPs, tools, targets, infrastructure for attribution.", methodology=["Collect artifacts from incident", "Match TTPs to known actor playbooks", "Analyze infrastructure patterns", "Check code overlap with known malware families", "Review working hours and language artifacts", "Assess attribution confidence level"], indicators=["Shared code/infrastructure with known APTs", "Language artifacts in malware", "Working hours suggesting timezone", "Target industry alignment"], tools=["misp", "opencti", "maltego"], commands=["strings malware.exe | grep -i 'pdb\\|debug'", "exiftool malware.doc | grep -i 'author'"], severity="high"),
    ThreatIntelPattern(name="Kill Chain Analysis", intel_type=ThreatIntelType.KILL_CHAIN, description="Lockheed Martin Cyber Kill Chain: Recon→Weaponization→Delivery→Exploitation→Installation→C2→Actions. Identify where defenses failed.", methodology=["Phase 1 Recon: identify target research", "Phase 2 Weaponization: payload creation", "Phase 3 Delivery: email/web/USB", "Phase 4 Exploitation: vulnerability exploited", "Phase 5 Installation: persistence established", "Phase 6 C2: channel analysis", "Phase 7 Actions: final objective", "Identify earliest detection point"], indicators=["Port scans, DNS lookups", "Phishing emails, watering holes", "New services, scheduled tasks", "Beacon traffic, DNS tunneling", "Data staging, exfiltration"], tools=["splunk", "elastic", "sigma", "suricata"], commands=["suricata -c suricata.yaml -r capture.pcap -l /tmp/logs/"], severity="critical"),
    ThreatIntelPattern(name="Proactive Threat Hunting", intel_type=ThreatIntelType.THREAT_HUNTING, description="Hypothesis-driven proactive hunting: form hypotheses, search telemetry, discover threats evading automated detection.", methodology=["Form hypothesis about likely threats", "Identify needed data sources (EDR, firewall, DNS)", "Build hunting queries (SPL, KQL, Lucene)", "Execute across telemetry", "Analyze: normal vs suspicious", "Investigate anomalies with timeline", "Escalate confirmed threats to IR", "Document hypothesis, queries, findings"], indicators=["Unusual process chains (Excel→cmd→PowerShell)", "Rare outbound connections", "Service creation from non-admin", "DNS to recently registered domains", "Auth anomalies (time, location)"], tools=["splunk", "elastic", "velociraptor", "osquery"], commands=["osqueryi --json 'SELECT * FROM processes WHERE path LIKE \"%temp%\"'"], severity="high"),
]

def build_threat_intel_prompt(focus_type: ThreatIntelType | None = None, max_patterns: int = 5) -> str:
    lines = ["## Threat Intelligence Knowledge\n"]
    patterns = THREAT_INTEL_PATTERNS if not focus_type else [p for p in THREAT_INTEL_PATTERNS if p.intel_type == focus_type]
    for p in patterns[:max_patterns]:
        lines.append(f"### {p.name} [{p.severity}]")
        lines.append(p.description)
        lines.append("\nMethodology:")
        for m in p.methodology[:4]:
            lines.append(f"  - {m}")
        lines.append("")
    return "\n".join(lines)
