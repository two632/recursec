"""Finding correlator — deduplicates, correlates, and enriches findings.

Implements:
1. Finding deduplication (same vuln from different tools)
2. Cross-tool correlation (combine evidence from multiple sources)
3. Finding enrichment (add CWE, CVSS, MITRE ATT&CK)
4. Attack chain assembly from correlated findings
5. Severity re-calculation based on combined evidence
6. False positive scoring
7. Finding grouping by target/type/severity
8. Prompt generation for LLM-based correlation
"""

from __future__ import annotations

import hashlib
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    NEW = "new"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    DUPLICATE = "duplicate"
    CHAIN_COMPONENT = "chain_component"


@dataclass
class RawFinding:
    """A finding from a single tool."""
    finding_id: str = ""
    title: str = ""
    description: str = ""
    severity: FindingSeverity = FindingSeverity.MEDIUM
    target: str = ""               # host/URL/file affected
    tool: str = ""
    evidence: str = ""
    cwe_id: str = ""
    cvss_score: float = 0.0
    confidence: float = 0.5
    raw_output: str = ""
    timestamp: float = field(default_factory=time.time)

    @property
    def fingerprint(self) -> str:
        """Generate a fingerprint for dedup."""
        data = f"{self.title}:{self.target}:{self.cwe_id}".lower()
        data = re.sub(r"[^a-z0-9:]+", "", data)
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.finding_id,
            "title": self.title[:30],
            "severity": self.severity.value,
            "target": self.target[:25],
            "tool": self.tool[:15],
            "confidence": round(self.confidence, 2),
            "cwe": self.cwe_id[:10],
        }


@dataclass
class CorrelatedFinding:
    """A finding correlated from multiple sources."""
    correlation_id: str = ""
    title: str = ""
    description: str = ""
    severity: FindingSeverity = FindingSeverity.MEDIUM
    target: str = ""
    status: FindingStatus = FindingStatus.NEW
    sources: list[str] = field(default_factory=list)         # Raw finding IDs
    tools_confirming: list[str] = field(default_factory=list)
    combined_evidence: str = ""
    confidence: float = 0.5
    false_positive_score: float = 0.0
    cwe_id: str = ""
    cvss_score: float = 0.0
    mitre_techniques: list[str] = field(default_factory=list)
    chain_with: list[str] = field(default_factory=list)     # Other correlated IDs in chain
    enrichment: dict[str, Any] = field(default_factory=dict)

    @property
    def num_confirmations(self) -> int:
        return len(self.tools_confirming)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.correlation_id,
            "title": self.title[:30],
            "severity": self.severity.value,
            "target": self.target[:25],
            "status": self.status.value,
            "tools": self.tools_confirming,
            "confidence": round(self.confidence, 2),
            "fp_score": round(self.false_positive_score, 2),
        }


@dataclass
class FindingGroup:
    """A group of related findings."""
    group_id: str = ""
    group_by: str = ""             # target, type, severity
    key: str = ""
    finding_ids: list[str] = field(default_factory=list)
    count: int = 0
    max_severity: FindingSeverity = FindingSeverity.INFO

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.group_id,
            "by": self.group_by[:10],
            "key": self.key[:20],
            "count": self.count,
            "max_severity": self.max_severity.value,
        }


# ── CWE Enrichment Database ──────────────────────────────────

CWE_DATABASE: dict[str, dict[str, Any]] = {
    "CWE-79": {"name": "Cross-site Scripting (XSS)", "category": "injection", "base_cvss": 6.1},
    "CWE-89": {"name": "SQL Injection", "category": "injection", "base_cvss": 8.6},
    "CWE-22": {"name": "Path Traversal", "category": "injection", "base_cvss": 7.5},
    "CWE-78": {"name": "OS Command Injection", "category": "injection", "base_cvss": 9.8},
    "CWE-918": {"name": "Server-Side Request Forgery (SSRF)", "category": "injection", "base_cvss": 7.5},
    "CWE-502": {"name": "Deserialization of Untrusted Data", "category": "injection", "base_cvss": 9.8},
    "CWE-287": {"name": "Improper Authentication", "category": "auth", "base_cvss": 8.0},
    "CWE-862": {"name": "Missing Authorization", "category": "auth", "base_cvss": 7.5},
    "CWE-863": {"name": "Incorrect Authorization", "category": "auth", "base_cvss": 7.5},
    "CWE-352": {"name": "Cross-Site Request Forgery (CSRF)", "category": "auth", "base_cvss": 6.5},
    "CWE-200": {"name": "Exposure of Sensitive Information", "category": "disclosure", "base_cvss": 5.3},
    "CWE-311": {"name": "Missing Encryption of Sensitive Data", "category": "crypto", "base_cvss": 7.5},
    "CWE-327": {"name": "Use of a Broken Crypto Algorithm", "category": "crypto", "base_cvss": 7.5},
    "CWE-798": {"name": "Use of Hard-coded Credentials", "category": "auth", "base_cvss": 9.8},
    "CWE-434": {"name": "Unrestricted Upload of Dangerous File Type", "category": "injection", "base_cvss": 9.8},
    "CWE-611": {"name": "Improper Restriction of XML External Entity", "category": "injection", "base_cvss": 7.5},
    "CWE-94": {"name": "Improper Control of Code Generation (Code Injection)", "category": "injection", "base_cvss": 9.8},
    "CWE-1321": {"name": "Improperly Controlled Modification of Object Prototype Attributes", "category": "injection", "base_cvss": 7.3},
    "CWE-400": {"name": "Uncontrolled Resource Consumption", "category": "dos", "base_cvss": 5.3},
    "CWE-522": {"name": "Insufficiently Protected Credentials", "category": "auth", "base_cvss": 7.5},
}

# ── MITRE ATT&CK Mapping ─────────────────────────────────────

CWE_TO_MITRE: dict[str, list[str]] = {
    "CWE-89": ["T1190"],  # Exploit Public-Facing Application
    "CWE-79": ["T1189", "T1059.007"],  # Drive-by Compromise, JavaScript
    "CWE-78": ["T1059"],  # Command and Scripting Interpreter
    "CWE-918": ["T1090"],  # Proxy
    "CWE-502": ["T1190"],
    "CWE-287": ["T1078"],  # Valid Accounts
    "CWE-798": ["T1078.001"],  # Default Accounts
    "CWE-434": ["T1105"],  # Ingress Tool Transfer
    "CWE-22": ["T1083"],  # File and Directory Discovery
}

# ── False Positive Indicators ─────────────────────────────────

FP_INDICATORS: list[dict[str, Any]] = [
    {"pattern": r"version\s+disclosure", "fp_score": 0.3, "reason": "Version disclosure is often informational"},
    {"pattern": r"missing\s+header", "fp_score": 0.25, "reason": "Missing security headers may not be exploitable"},
    {"pattern": r"cookie\s+without", "fp_score": 0.2, "reason": "Cookie flag issues are often low risk"},
    {"pattern": r"ssl.*weak", "fp_score": 0.15, "reason": "Weak SSL may be intentional for compatibility"},
    {"pattern": r"directory\s+listing", "fp_score": 0.1, "reason": "Directory listing may be intentional"},
]

SEVERITY_ORDER = [
    FindingSeverity.CRITICAL,
    FindingSeverity.HIGH,
    FindingSeverity.MEDIUM,
    FindingSeverity.LOW,
    FindingSeverity.INFO,
]


class FindingCorrelator:
    """Deduplicates, correlates, and enriches security findings.

    Combines findings from multiple tools into correlated
    results with combined evidence, enriched metadata,
    and false positive scoring.
    """

    def __init__(self) -> None:
        self._raw_findings: dict[str, RawFinding] = {}
        self._correlated: dict[str, CorrelatedFinding] = {}
        self._fingerprint_map: dict[str, str] = {}   # fingerprint → correlation_id
        self._groups: dict[str, FindingGroup] = {}
        self._raw_counter = 0
        self._corr_counter = 0
        self._group_counter = 0
        self._log = logger.bind(component="finding_correlator")

    def ingest(self, finding: RawFinding) -> CorrelatedFinding:
        """Ingest a raw finding, deduplicating and correlating."""
        self._raw_counter += 1
        if not finding.finding_id:
            finding.finding_id = f"raw-{self._raw_counter}"

        self._raw_findings[finding.finding_id] = finding

        fp = finding.fingerprint

        # Check for existing correlation
        if fp in self._fingerprint_map:
            corr_id = self._fingerprint_map[fp]
            correlated = self._correlated[corr_id]

            # Add this as additional evidence
            correlated.sources.append(finding.finding_id)
            if finding.tool not in correlated.tools_confirming:
                correlated.tools_confirming.append(finding.tool)

            # Combine evidence
            if finding.evidence:
                correlated.combined_evidence += f"\n[{finding.tool}]: {finding.evidence}"

            # Upgrade severity if this source found higher
            if SEVERITY_ORDER.index(finding.severity) < SEVERITY_ORDER.index(correlated.severity):
                correlated.severity = finding.severity

            # Increase confidence with each confirmation
            correlated.confidence = min(
                0.99,
                correlated.confidence + 0.1 * (1 - correlated.confidence),
            )

            # Mark as confirmed if 2+ tools agree
            if correlated.num_confirmations >= 2:
                correlated.status = FindingStatus.CONFIRMED

            return correlated

        # New finding — create correlation
        self._corr_counter += 1
        correlated = CorrelatedFinding(
            correlation_id=f"corr-{self._corr_counter}",
            title=finding.title,
            description=finding.description,
            severity=finding.severity,
            target=finding.target,
            sources=[finding.finding_id],
            tools_confirming=[finding.tool] if finding.tool else [],
            combined_evidence=f"[{finding.tool}]: {finding.evidence}" if finding.evidence else "",
            confidence=finding.confidence,
            cwe_id=finding.cwe_id,
            cvss_score=finding.cvss_score,
        )

        # Enrich
        self._enrich(correlated)

        # Calculate FP score
        correlated.false_positive_score = self._calculate_fp_score(correlated)

        self._correlated[correlated.correlation_id] = correlated
        self._fingerprint_map[fp] = correlated.correlation_id

        return correlated

    def _enrich(self, finding: CorrelatedFinding) -> None:
        """Enrich a finding with CWE and MITRE data."""
        if finding.cwe_id and finding.cwe_id in CWE_DATABASE:
            cwe_data = CWE_DATABASE[finding.cwe_id]
            finding.enrichment["cwe_name"] = cwe_data["name"]
            finding.enrichment["cwe_category"] = cwe_data["category"]

            if finding.cvss_score == 0:
                finding.cvss_score = cwe_data["base_cvss"]

        # MITRE ATT&CK mapping
        if finding.cwe_id in CWE_TO_MITRE:
            finding.mitre_techniques = CWE_TO_MITRE[finding.cwe_id]

    @staticmethod
    def _calculate_fp_score(finding: CorrelatedFinding) -> float:
        """Calculate false positive probability."""
        fp_score = 0.0
        text = f"{finding.title} {finding.description}".lower()

        for indicator in FP_INDICATORS:
            if re.search(indicator["pattern"], text):
                fp_score = max(fp_score, indicator["fp_score"])

        # Lower FP score if high confidence
        fp_score *= (1 - finding.confidence)

        # Lower FP score if multiple tools confirm
        if finding.num_confirmations >= 2:
            fp_score *= 0.5

        return min(1.0, fp_score)

    def group_findings(self, group_by: str = "target") -> list[FindingGroup]:
        """Group findings by target, severity, or type."""
        groups: dict[str, list[str]] = defaultdict(list)

        for corr in self._correlated.values():
            if corr.status == FindingStatus.DUPLICATE:
                continue

            if group_by == "target":
                key = corr.target
            elif group_by == "severity":
                key = corr.severity.value
            elif group_by == "cwe":
                key = corr.cwe_id or "unknown"
            else:
                key = corr.target

            groups[key].append(corr.correlation_id)

        result = []
        for key, ids in groups.items():
            self._group_counter += 1
            max_sev = FindingSeverity.INFO
            for cid in ids:
                corr = self._correlated.get(cid)
                if corr:
                    idx = SEVERITY_ORDER.index(corr.severity)
                    if idx < SEVERITY_ORDER.index(max_sev):
                        max_sev = corr.severity

            group = FindingGroup(
                group_id=f"grp-{self._group_counter}",
                group_by=group_by,
                key=key,
                finding_ids=ids,
                count=len(ids),
                max_severity=max_sev,
            )
            result.append(group)
            self._groups[group.group_id] = group

        result.sort(
            key=lambda g: SEVERITY_ORDER.index(g.max_severity)
        )
        return result

    def identify_chains(self) -> list[list[str]]:
        """Identify findings that form attack chains."""
        chains: list[list[str]] = []

        # Group findings by target
        by_target: dict[str, list[CorrelatedFinding]] = defaultdict(list)
        for corr in self._correlated.values():
            if corr.status != FindingStatus.DUPLICATE:
                by_target[corr.target].append(corr)

        for target, findings in by_target.items():
            if len(findings) < 2:
                continue

            # Sort by severity (most critical first)
            findings.sort(
                key=lambda f: SEVERITY_ORDER.index(f.severity)
            )

            # Look for chain patterns
            chain: list[str] = []
            categories_in_chain: set[str] = set()

            for finding in findings:
                category = finding.enrichment.get("cwe_category", "")
                if category and category not in categories_in_chain:
                    chain.append(finding.correlation_id)
                    categories_in_chain.add(category)
                    finding.status = FindingStatus.CHAIN_COMPONENT

            if len(chain) >= 2:
                chains.append(chain)
                for cid in chain:
                    corr = self._correlated.get(cid)
                    if corr:
                        corr.chain_with = [c for c in chain if c != cid]

        return chains

    def generate_correlation_prompt(self, finding_ids: list[str]) -> str:
        """Generate a prompt for LLM-based finding correlation."""
        findings_text = ""
        for fid in finding_ids[:10]:
            corr = self._correlated.get(fid)
            if not corr:
                continue
            findings_text += (
                f"- {corr.title} [{corr.severity.value}] on {corr.target}\n"
                f"  Evidence: {corr.combined_evidence[:100]}\n"
                f"  Tools: {', '.join(corr.tools_confirming)}\n\n"
            )

        return (
            f"Analyze these security findings for correlations:\n\n"
            f"{findings_text}\n"
            f"Questions:\n"
            f"1. Which findings are duplicates or related?\n"
            f"2. Can any findings be chained into an attack path?\n"
            f"3. Which findings are likely false positives?\n"
            f"4. What is the combined risk impact?\n"
        )

    def get_stats(self) -> dict[str, Any]:
        sev_counts: dict[str, int] = defaultdict(int)
        status_counts: dict[str, int] = defaultdict(int)
        for corr in self._correlated.values():
            sev_counts[corr.severity.value] += 1
            status_counts[corr.status.value] += 1
        return {
            "raw_findings": len(self._raw_findings),
            "correlated": len(self._correlated),
            "dedup_ratio": round(
                1 - len(self._correlated) / max(1, len(self._raw_findings)),
                2,
            ),
            "by_severity": dict(sev_counts),
            "by_status": dict(status_counts),
            "groups": len(self._groups),
        }
