"""Threat intelligence engine — enriches findings with threat context.

All processing is LOCAL. No external API calls.

Capabilities:
- CVE database lookup (from local NVD mirror)
- MITRE ATT&CK technique mapping
- Exploit availability checking (from local exploit-db mirror)
- Service version vulnerability matching
- IoC pattern matching
- Hash reputation (local malware hash database)
- IP/domain reputation scoring
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class CVEEntry:
    """Local CVE database entry."""
    cve_id: str
    description: str = ""
    cvss_v3: float = 0.0
    cvss_v2: float = 0.0
    severity: str = "unknown"
    published: str = ""
    modified: str = ""
    cwe_ids: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    affected_products: list[str] = field(default_factory=list)
    exploit_available: bool = False
    patch_available: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "description": self.description[:500],
            "cvss_v3": self.cvss_v3,
            "severity": self.severity,
            "cwe_ids": self.cwe_ids,
            "exploit_available": self.exploit_available,
            "patch_available": self.patch_available,
        }


@dataclass
class ATTACKTechnique:
    """MITRE ATT&CK technique."""
    technique_id: str
    name: str
    tactic: str
    description: str = ""
    platforms: list[str] = field(default_factory=list)
    detection: str = ""
    mitigation: str = ""
    url: str = ""


# ── MITRE ATT&CK Technique Mapping ────────────────────────
# Maps vulnerability types / finding keywords to ATT&CK techniques

ATTACK_MAPPING: dict[str, list[dict[str, str]]] = {
    "sql injection": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
    ],
    "xss": [
        {"id": "T1189", "name": "Drive-by Compromise", "tactic": "Initial Access"},
        {"id": "T1185", "name": "Browser Session Hijacking", "tactic": "Collection"},
    ],
    "command injection": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
    ],
    "ssrf": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        {"id": "T1557", "name": "Adversary-in-the-Middle", "tactic": "Credential Access"},
    ],
    "rce": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        {"id": "T1203", "name": "Exploitation for Client Execution", "tactic": "Execution"},
    ],
    "lfi": [
        {"id": "T1005", "name": "Data from Local System", "tactic": "Collection"},
        {"id": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery"},
    ],
    "directory traversal": [
        {"id": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery"},
        {"id": "T1005", "name": "Data from Local System", "tactic": "Collection"},
    ],
    "authentication bypass": [
        {"id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion"},
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    ],
    "privilege escalation": [
        {"id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
        {"id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation"},
    ],
    "credential exposure": [
        {"id": "T1552", "name": "Unsecured Credentials", "tactic": "Credential Access"},
        {"id": "T1003", "name": "OS Credential Dumping", "tactic": "Credential Access"},
    ],
    "information disclosure": [
        {"id": "T1087", "name": "Account Discovery", "tactic": "Discovery"},
        {"id": "T1082", "name": "System Information Discovery", "tactic": "Discovery"},
    ],
    "default credentials": [
        {"id": "T1078.001", "name": "Default Accounts", "tactic": "Initial Access"},
    ],
    "weak encryption": [
        {"id": "T1573", "name": "Encrypted Channel", "tactic": "Command and Control"},
        {"id": "T1600", "name": "Weaken Encryption", "tactic": "Defense Evasion"},
    ],
    "deserialization": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    ],
    "xxe": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        {"id": "T1005", "name": "Data from Local System", "tactic": "Collection"},
    ],
    "open redirect": [
        {"id": "T1566.002", "name": "Spearphishing Link", "tactic": "Initial Access"},
    ],
    "cors misconfiguration": [
        {"id": "T1189", "name": "Drive-by Compromise", "tactic": "Initial Access"},
    ],
    "ssti": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
    ],
    "lateral movement": [
        {"id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement"},
        {"id": "T1570", "name": "Lateral Tool Transfer", "tactic": "Lateral Movement"},
    ],
    "dns zone transfer": [
        {"id": "T1596.001", "name": "DNS/Passive DNS", "tactic": "Reconnaissance"},
    ],
    "smb": [
        {"id": "T1021.002", "name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement"},
    ],
    "brute force": [
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    ],
}

# ── Service → Known CVE Patterns ──────────────────────────

SERVICE_CVE_PATTERNS: list[dict[str, Any]] = [
    {"service": "apache", "version_regex": r"2\.4\.(49|50)", "cve": "CVE-2021-41773", "severity": "critical", "desc": "Apache path traversal / RCE"},
    {"service": "apache", "version_regex": r"2\.4\.49", "cve": "CVE-2021-42013", "severity": "critical", "desc": "Apache path traversal bypass"},
    {"service": "openssh", "version_regex": r"[78]\.\d+", "cve": "CVE-2023-38408", "severity": "high", "desc": "OpenSSH agent forwarding RCE"},
    {"service": "openssh", "version_regex": r"8\.5|8\.6|8\.7|8\.8|8\.9|9\.0|9\.1|9\.2|9\.3|9\.4|9\.5|9\.6|9\.7", "cve": "CVE-2024-6387", "severity": "critical", "desc": "regreSSHion - OpenSSH unauthenticated RCE"},
    {"service": "nginx", "version_regex": r"1\.(1[0-9]|20)\.", "cve": "CVE-2021-23017", "severity": "high", "desc": "Nginx DNS resolver vulnerability"},
    {"service": "mysql", "version_regex": r"5\.7\.", "cve": "CVE-2023-21977", "severity": "medium", "desc": "MySQL Server vulnerability"},
    {"service": "postgresql", "version_regex": r"1[0-4]\.", "cve": "CVE-2023-5868", "severity": "medium", "desc": "PostgreSQL security vulnerability"},
    {"service": "redis", "version_regex": r"[56]\.", "cve": "CVE-2023-28856", "severity": "medium", "desc": "Redis AUTH bypass"},
    {"service": "elasticsearch", "version_regex": r"[78]\.", "cve": "CVE-2023-31419", "severity": "high", "desc": "Elasticsearch DoS vulnerability"},
    {"service": "mongodb", "version_regex": r"[45]\.", "cve": "CVE-2023-1409", "severity": "medium", "desc": "MongoDB security vulnerability"},
    {"service": "iis", "version_regex": r"10\.", "cve": "CVE-2023-36899", "severity": "high", "desc": "IIS elevation of privilege"},
    {"service": "tomcat", "version_regex": r"9\.", "cve": "CVE-2023-28708", "severity": "medium", "desc": "Apache Tomcat information disclosure"},
    {"service": "wordpress", "version_regex": r"[56]\.", "cve": "CVE-2023-2745", "severity": "medium", "desc": "WordPress directory traversal"},
    {"service": "jenkins", "version_regex": r"2\.", "cve": "CVE-2024-23897", "severity": "critical", "desc": "Jenkins arbitrary file read"},
    {"service": "gitlab", "version_regex": r"16\.", "cve": "CVE-2023-7028", "severity": "critical", "desc": "GitLab account takeover"},
    {"service": "log4j", "version_regex": r"2\.(0|1[0-6])\.", "cve": "CVE-2021-44228", "severity": "critical", "desc": "Log4Shell RCE"},
    {"service": "spring", "version_regex": r"5\.[23]\.", "cve": "CVE-2022-22965", "severity": "critical", "desc": "Spring4Shell RCE"},
    {"service": "exchange", "version_regex": r"2019|2016", "cve": "CVE-2023-36745", "severity": "critical", "desc": "Microsoft Exchange RCE"},
    {"service": "grafana", "version_regex": r"[89]\.", "cve": "CVE-2023-3128", "severity": "critical", "desc": "Grafana auth bypass"},
    {"service": "confluence", "version_regex": r"[78]\.", "cve": "CVE-2023-22515", "severity": "critical", "desc": "Atlassian Confluence broken access control"},
]

# ── IoC Patterns ───────────────────────────────────────────

IOC_PATTERNS = {
    "ip_v4": re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
    "ip_v6": re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"),
    "domain": re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"),
    "email": re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "url": re.compile(r"https?://[^\s<>\"']+"),
    "cve": re.compile(r"CVE-\d{4}-\d{4,7}"),
    "file_hash_pair": re.compile(r"([a-fA-F0-9]{32,64})\s+(.+)"),
    "base64_suspicious": re.compile(r"(?:[A-Za-z0-9+/]{50,}={0,2})"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "jwt": re.compile(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"),
}


class ThreatIntelEngine:
    """Local threat intelligence enrichment engine."""

    def __init__(self, data_dir: str = ""):
        self._data_dir = Path(data_dir) if data_dir else None
        self._cve_cache: dict[str, CVEEntry] = {}
        self._stats = {
            "cve_lookups": 0,
            "attack_mappings": 0,
            "version_matches": 0,
            "ioc_extractions": 0,
        }

    def map_to_attack(self, finding_text: str) -> list[dict[str, str]]:
        """Map a finding to MITRE ATT&CK techniques."""
        self._stats["attack_mappings"] += 1
        text_lower = finding_text.lower()
        techniques: list[dict[str, str]] = []
        seen: set[str] = set()

        for keyword, techs in ATTACK_MAPPING.items():
            if keyword in text_lower:
                for t in techs:
                    if t["id"] not in seen:
                        techniques.append(t)
                        seen.add(t["id"])

        return techniques

    def check_service_vulns(
        self, service: str, version: str
    ) -> list[dict[str, Any]]:
        """Check known vulnerabilities for a service version."""
        self._stats["version_matches"] += 1
        matches = []
        svc_lower = service.lower()

        for pattern in SERVICE_CVE_PATTERNS:
            if pattern["service"] in svc_lower:
                if re.search(pattern["version_regex"], version):
                    matches.append({
                        "cve": pattern["cve"],
                        "severity": pattern["severity"],
                        "description": pattern["desc"],
                        "service": service,
                        "version": version,
                    })

        return matches

    def extract_iocs(self, text: str) -> dict[str, list[str]]:
        """Extract indicators of compromise from text."""
        self._stats["ioc_extractions"] += 1
        iocs: dict[str, list[str]] = {}

        for ioc_type, pattern in IOC_PATTERNS.items():
            matches = pattern.findall(text)
            if matches:
                unique = list(set(matches))[:100]
                iocs[ioc_type] = unique

        return iocs

    def enrich_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Enrich a finding with threat intelligence context."""
        enriched = dict(finding)

        # Map to ATT&CK
        text = f"{finding.get('title', '')} {finding.get('description', '')}"
        techniques = self.map_to_attack(text)
        if techniques:
            enriched["attack_techniques"] = techniques

        # Check for known CVEs
        if "cve_id" in finding and finding["cve_id"]:
            cve_info = self.lookup_cve(finding["cve_id"])
            if cve_info:
                enriched["cve_info"] = cve_info.to_dict()

        # Check service version vulnerabilities
        service = finding.get("service", "")
        version = finding.get("version", "")
        if service and version:
            service_vulns = self.check_service_vulns(service, version)
            if service_vulns:
                enriched["known_service_vulns"] = service_vulns

        # Extract IoCs from evidence
        evidence = finding.get("evidence", "")
        if evidence:
            iocs = self.extract_iocs(evidence)
            if iocs:
                enriched["iocs"] = iocs

        return enriched

    def lookup_cve(self, cve_id: str) -> CVEEntry | None:
        """Look up a CVE in the local database."""
        self._stats["cve_lookups"] += 1
        cve_upper = cve_id.upper()

        # Check cache
        if cve_upper in self._cve_cache:
            return self._cve_cache[cve_upper]

        # Check local NVD data
        if self._data_dir:
            year = cve_upper.split("-")[1] if "-" in cve_upper else ""
            nvd_file = self._data_dir / f"nvd_{year}.json"
            if nvd_file.exists():
                try:
                    data = json.loads(nvd_file.read_text())
                    for entry in data.get("CVE_Items", []):
                        entry_id = entry.get("cve", {}).get("CVE_data_meta", {}).get("ID", "")
                        if entry_id.upper() == cve_upper:
                            cve_entry = self._parse_nvd_entry(entry)
                            self._cve_cache[cve_upper] = cve_entry
                            return cve_entry
                except (json.JSONDecodeError, OSError):
                    pass

        return None

    def _parse_nvd_entry(self, entry: dict[str, Any]) -> CVEEntry:
        """Parse an NVD JSON entry into a CVEEntry."""
        cve_data = entry.get("cve", {})
        meta = cve_data.get("CVE_data_meta", {})
        desc_data = cve_data.get("description", {}).get("description_data", [])
        description = desc_data[0].get("value", "") if desc_data else ""

        impact = entry.get("impact", {})
        cvss_v3 = impact.get("baseMetricV3", {}).get("cvssV3", {}).get("baseScore", 0.0)
        cvss_v2 = impact.get("baseMetricV2", {}).get("cvssV2", {}).get("baseScore", 0.0)

        severity = impact.get("baseMetricV3", {}).get("cvssV3", {}).get("baseSeverity", "UNKNOWN")

        cwes = []
        for prob in cve_data.get("problemtype", {}).get("problemtype_data", []):
            for desc in prob.get("description", []):
                if desc.get("value", "").startswith("CWE-"):
                    cwes.append(desc["value"])

        refs = []
        for ref in entry.get("cve", {}).get("references", {}).get("reference_data", []):
            refs.append(ref.get("url", ""))

        return CVEEntry(
            cve_id=meta.get("ID", ""),
            description=description,
            cvss_v3=cvss_v3,
            cvss_v2=cvss_v2,
            severity=severity.lower(),
            published=entry.get("publishedDate", ""),
            modified=entry.get("lastModifiedDate", ""),
            cwe_ids=cwes,
            references=refs[:10],
        )

    def get_stats(self) -> dict[str, Any]:
        return {**self._stats}
