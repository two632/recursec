"""Findings aggregator — deduplication, correlation, and prioritization of security findings.

When multiple agents and tools discover vulnerabilities, this engine:
1. Deduplicates findings from multiple sources
2. Merges related findings into unified reports
3. Correlates findings to build attack chains
4. Prioritizes by risk, exploitability, and business impact
5. Calculates CVSS-like scores
6. Groups findings by category, component, and severity
7. Detects false positives through cross-validation
8. Tracks finding lifecycle (new → confirmed → remediated)

The aggregator acts as the "single source of truth" for all
security findings discovered during an assessment.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from recursec.llm.router import ModelRouter

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
    ACCEPTED_RISK = "accepted_risk"
    REMEDIATED = "remediated"
    DUPLICATE = "duplicate"


class FindingCategory(str, Enum):
    INJECTION = "injection"
    BROKEN_AUTH = "broken_authentication"
    SENSITIVE_DATA = "sensitive_data_exposure"
    XXE = "xml_external_entities"
    BROKEN_ACCESS = "broken_access_control"
    SECURITY_MISCONFIG = "security_misconfiguration"
    XSS = "cross_site_scripting"
    INSECURE_DESER = "insecure_deserialization"
    VULNERABLE_COMPONENTS = "vulnerable_components"
    INSUFFICIENT_LOGGING = "insufficient_logging"
    SSRF = "server_side_request_forgery"
    CRYPTOGRAPHIC = "cryptographic_weakness"
    NETWORK = "network_vulnerability"
    CODE_QUALITY = "code_quality"
    INFORMATION_DISCLOSURE = "information_disclosure"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    OTHER = "other"


@dataclass
class Finding:
    """A unified security finding."""
    finding_id: str = ""
    title: str = ""
    description: str = ""
    severity: FindingSeverity = FindingSeverity.MEDIUM
    category: FindingCategory = FindingCategory.OTHER
    status: FindingStatus = FindingStatus.NEW
    confidence: float = 0.5  # 0.0-1.0

    # Target info
    affected_component: str = ""
    affected_url: str = ""
    affected_parameter: str = ""
    affected_file: str = ""
    affected_line: int = 0

    # Evidence
    evidence: str = ""
    reproduction_steps: list[str] = field(default_factory=list)
    request: str = ""
    response: str = ""

    # Scoring
    cvss_score: float = 0.0
    cvss_vector: str = ""
    exploitability: float = 0.0
    impact_score: float = 0.0

    # References
    cwe_ids: list[str] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    # Source tracking
    sources: list[str] = field(default_factory=list)  # Which tools/agents found this
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    confirmation_count: int = 1

    # Relationships
    related_findings: list[str] = field(default_factory=list)  # finding_ids
    part_of_chain: str = ""  # Attack chain ID

    # Metadata
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.finding_id:
            content = f"{self.title}:{self.affected_component}:{self.affected_url}:{self.category.value}"
            self.finding_id = hashlib.md5(content.encode()).hexdigest()[:12]

    @property
    def risk_score(self) -> float:
        """Combined risk score."""
        severity_weights = {
            FindingSeverity.CRITICAL: 10.0, FindingSeverity.HIGH: 7.5,
            FindingSeverity.MEDIUM: 5.0, FindingSeverity.LOW: 2.5,
            FindingSeverity.INFO: 0.5,
        }
        base = severity_weights.get(self.severity, 5.0)
        return base * self.confidence * (1.0 + self.exploitability * 0.5)

    def merge_with(self, other: Finding) -> None:
        """Merge another finding into this one (deduplication)."""
        # Add sources
        for src in other.sources:
            if src not in self.sources:
                self.sources.append(src)

        # Bump confidence when confirmed by multiple sources
        self.confirmation_count += other.confirmation_count
        self.confidence = min(0.99, self.confidence + 0.1 * other.confidence)

        # Keep better evidence
        if len(other.evidence) > len(self.evidence):
            self.evidence = other.evidence
        if other.reproduction_steps and not self.reproduction_steps:
            self.reproduction_steps = other.reproduction_steps

        # Merge references
        for ref in other.cwe_ids:
            if ref not in self.cwe_ids:
                self.cwe_ids.append(ref)
        for ref in other.cve_ids:
            if ref not in self.cve_ids:
                self.cve_ids.append(ref)

        self.last_seen = max(self.last_seen, other.last_seen)

        # Upgrade severity if other is higher
        severity_order = [FindingSeverity.INFO, FindingSeverity.LOW, FindingSeverity.MEDIUM, FindingSeverity.HIGH, FindingSeverity.CRITICAL]
        if severity_order.index(other.severity) > severity_order.index(self.severity):
            self.severity = other.severity

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.finding_id, "title": self.title,
            "description": self.description[:500],
            "severity": self.severity.value,
            "category": self.category.value,
            "status": self.status.value,
            "confidence": round(self.confidence, 2),
            "component": self.affected_component,
            "url": self.affected_url,
            "cvss": self.cvss_score,
            "exploitability": round(self.exploitability, 2),
            "risk_score": round(self.risk_score, 2),
            "sources": self.sources,
            "confirmations": self.confirmation_count,
            "cwe": self.cwe_ids,
            "cve": self.cve_ids,
        }


@dataclass
class FindingsReport:
    """Aggregated findings report."""
    target: str = ""
    total_findings: int = 0
    by_severity: dict[str, int] = field(default_factory=dict)
    by_category: dict[str, int] = field(default_factory=dict)
    by_status: dict[str, int] = field(default_factory=dict)
    critical_findings: list[dict[str, Any]] = field(default_factory=list)
    high_findings: list[dict[str, Any]] = field(default_factory=list)
    attack_chains: list[dict[str, Any]] = field(default_factory=list)
    false_positive_rate: float = 0.0
    coverage_score: float = 0.0
    risk_score: float = 0.0


# ── Prompt Templates ────────────────────────────────────────

DEDUPLICATE_PROMPT = """Compare these two security findings. Are they duplicates?

Finding A:
{finding_a}

Finding B:
{finding_b}

Respond as JSON:
{{
  "is_duplicate": true/false,
  "similarity": 0.X,
  "reasoning": "why they are/aren't duplicates",
  "merge_recommendation": "keep_a|keep_b|merge"
}}"""

CATEGORIZE_PROMPT = """Categorize this security finding.

Finding: {finding}

Categories: injection, broken_authentication, sensitive_data_exposure,
xml_external_entities, broken_access_control, security_misconfiguration,
cross_site_scripting, insecure_deserialization, vulnerable_components,
insufficient_logging, server_side_request_forgery, cryptographic_weakness,
network_vulnerability, code_quality, information_disclosure,
privilege_escalation, other

Respond as JSON:
{{
  "category": "category_name",
  "severity": "critical|high|medium|low|info",
  "cwe_ids": ["CWE-XXX"],
  "exploitability": 0.X,
  "impact": 0.X,
  "confidence": 0.X
}}"""

CORRELATE_PROMPT = """Analyze these findings for correlations and attack chains.

Findings: {findings}

Identify:
1. Findings that can be chained together
2. Root causes shared across findings
3. Cascading impacts
4. Attack paths from combining findings

Respond as JSON:
{{
  "chains": [
    {{
      "name": "chain description",
      "steps": ["finding_id1", "finding_id2"],
      "combined_impact": "critical|high|medium|low",
      "description": "how these chain together"
    }}
  ],
  "root_causes": [
    {{
      "cause": "description",
      "affected_findings": ["finding_ids"]
    }}
  ]
}}"""

FALSE_POSITIVE_PROMPT = """Evaluate if this finding is likely a false positive.

Finding: {finding}
Tool source: {source}
Evidence: {evidence}
Context: {context}

Consider:
1. Is the evidence strong enough?
2. Could this be a normal/expected behavior?
3. Are there common false positive patterns for this type?
4. Would manual verification confirm this?

Respond as JSON:
{{
  "is_false_positive": true/false,
  "confidence": 0.X,
  "reasoning": "why",
  "verification_steps": ["how to verify"]
}}"""


class FindingsAggregator:
    """Aggregates, deduplicates, and prioritizes security findings.

    The single source of truth for all discoveries during an assessment.
    """

    def __init__(self, model_router: ModelRouter | None = None) -> None:
        self._router = model_router
        self._findings: dict[str, Finding] = {}
        self._chains: list[dict[str, Any]] = []
        self._log = logger.bind(component="findings_aggregator")

    def add_finding(self, finding: Finding) -> str:
        """Add a finding, auto-deduplicating against existing ones."""
        # Check for duplicates using fingerprint
        duplicate = self._find_duplicate(finding)
        if duplicate:
            duplicate.merge_with(finding)
            self._log.info("finding_merged", id=duplicate.finding_id, sources=len(duplicate.sources))
            return duplicate.finding_id

        self._findings[finding.finding_id] = finding
        self._log.info(
            "finding_added",
            id=finding.finding_id,
            title=finding.title[:50],
            severity=finding.severity.value,
        )
        return finding.finding_id

    def add_from_tool_output(
        self,
        tool_name: str,
        raw_findings: list[dict[str, Any]],
    ) -> list[str]:
        """Add findings from parsed tool output."""
        ids = []
        for raw in raw_findings:
            finding = Finding(
                title=raw.get("title", raw.get("name", "")),
                description=raw.get("description", ""),
                severity=self._parse_severity(raw.get("severity", "medium")),
                affected_component=raw.get("host", raw.get("component", "")),
                affected_url=raw.get("url", raw.get("matched-at", "")),
                evidence=raw.get("evidence", raw.get("extracted-results", "")),
                sources=[tool_name],
                cve_ids=raw.get("cve_ids", []),
                cwe_ids=raw.get("cwe_ids", []),
                confidence=raw.get("confidence", 0.5),
            )

            # Auto-categorize based on tool and keywords
            finding.category = self._auto_categorize(finding)

            fid = self.add_finding(finding)
            ids.append(fid)
        return ids

    def get_finding(self, finding_id: str) -> Finding | None:
        return self._findings.get(finding_id)

    def get_all(self, min_severity: FindingSeverity | None = None) -> list[Finding]:
        """Get all findings, optionally filtered by minimum severity."""
        if not min_severity:
            return list(self._findings.values())

        severity_order = [FindingSeverity.INFO, FindingSeverity.LOW, FindingSeverity.MEDIUM, FindingSeverity.HIGH, FindingSeverity.CRITICAL]
        min_idx = severity_order.index(min_severity)
        return [
            f for f in self._findings.values()
            if severity_order.index(f.severity) >= min_idx
        ]

    def get_by_category(self, category: FindingCategory) -> list[Finding]:
        return [f for f in self._findings.values() if f.category == category]

    def get_by_component(self, component: str) -> list[Finding]:
        return [
            f for f in self._findings.values()
            if component.lower() in f.affected_component.lower()
        ]

    def mark_false_positive(self, finding_id: str, reason: str = "") -> bool:
        finding = self._findings.get(finding_id)
        if finding:
            finding.status = FindingStatus.FALSE_POSITIVE
            finding.metadata["fp_reason"] = reason
            return True
        return False

    def confirm_finding(self, finding_id: str) -> bool:
        finding = self._findings.get(finding_id)
        if finding:
            finding.status = FindingStatus.CONFIRMED
            finding.confidence = min(0.99, finding.confidence + 0.2)
            return True
        return False

    async def correlate_findings(self) -> list[dict[str, Any]]:
        """Use LLM to find correlations and attack chains."""
        if not self._router or len(self._findings) < 2:
            return []

        findings_desc = json.dumps([
            f.to_dict() for f in list(self._findings.values())[:20]
        ])[:4000]

        prompt = CORRELATE_PROMPT.format(findings=findings_desc)

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="reasoning",
            temperature=0.2,
            max_tokens=2048,
        )

        data = self._parse_json(response)
        self._chains = data.get("chains", [])

        # Link findings
        for chain in self._chains:
            for step_id in chain.get("steps", []):
                finding = self._findings.get(step_id)
                if finding:
                    finding.part_of_chain = chain.get("name", "")

        return self._chains

    async def check_false_positives(self) -> list[str]:
        """Check all findings for potential false positives."""
        if not self._router:
            return []

        fp_ids = []
        for finding in list(self._findings.values()):
            if finding.status != FindingStatus.NEW:
                continue

            prompt = FALSE_POSITIVE_PROMPT.format(
                finding=json.dumps(finding.to_dict()),
                source=", ".join(finding.sources),
                evidence=finding.evidence[:500],
                context="",
            )

            response = await self._router.generate(
                messages=[{"role": "user", "content": prompt}],
                task_type="reasoning",
                temperature=0.1,
                max_tokens=512,
            )

            data = self._parse_json(response)
            if data.get("is_false_positive") and data.get("confidence", 0) > 0.7:
                finding.status = FindingStatus.FALSE_POSITIVE
                finding.metadata["fp_reason"] = data.get("reasoning", "")
                fp_ids.append(finding.finding_id)

        return fp_ids

    def generate_report(self) -> FindingsReport:
        """Generate an aggregated findings report."""
        report = FindingsReport(target="")

        by_severity: dict[str, int] = defaultdict(int)
        by_category: dict[str, int] = defaultdict(int)
        by_status: dict[str, int] = defaultdict(int)

        for finding in self._findings.values():
            by_severity[finding.severity.value] += 1
            by_category[finding.category.value] += 1
            by_status[finding.status.value] += 1

        report.total_findings = len(self._findings)
        report.by_severity = dict(by_severity)
        report.by_category = dict(by_category)
        report.by_status = dict(by_status)

        # Top findings
        sorted_findings = sorted(self._findings.values(), key=lambda f: -f.risk_score)
        report.critical_findings = [
            f.to_dict() for f in sorted_findings
            if f.severity == FindingSeverity.CRITICAL
        ]
        report.high_findings = [
            f.to_dict() for f in sorted_findings
            if f.severity == FindingSeverity.HIGH
        ]

        # False positive rate
        total = len(self._findings)
        fp_count = sum(1 for f in self._findings.values() if f.status == FindingStatus.FALSE_POSITIVE)
        report.false_positive_rate = fp_count / max(1, total)

        # Overall risk
        report.risk_score = sum(f.risk_score for f in self._findings.values() if f.status != FindingStatus.FALSE_POSITIVE)

        report.attack_chains = self._chains

        return report

    def _find_duplicate(self, finding: Finding) -> Finding | None:
        """Find an existing duplicate finding."""
        for existing in self._findings.values():
            if self._is_duplicate(existing, finding):
                return existing
        return None

    def _is_duplicate(self, existing: Finding, candidate: Finding) -> bool:
        """Check if two findings are duplicates."""
        # Same title and component
        if (existing.title.lower() == candidate.title.lower()
                and existing.affected_component == candidate.affected_component):
            return True

        # Same URL and category
        if (existing.affected_url and existing.affected_url == candidate.affected_url
                and existing.category == candidate.category):
            return True

        # Same CVE
        if existing.cve_ids and candidate.cve_ids:
            if set(existing.cve_ids) & set(candidate.cve_ids):
                return True

        return False

    def _auto_categorize(self, finding: Finding) -> FindingCategory:
        """Auto-categorize a finding based on title/description keywords."""
        text = f"{finding.title} {finding.description}".lower()
        category_keywords: dict[FindingCategory, list[str]] = {
            FindingCategory.INJECTION: ["sql injection", "sqli", "command injection", "ldap injection", "nosql"],
            FindingCategory.XSS: ["xss", "cross-site scripting", "cross site scripting"],
            FindingCategory.BROKEN_AUTH: ["authentication", "login bypass", "session", "jwt", "cookie"],
            FindingCategory.BROKEN_ACCESS: ["idor", "access control", "authorization", "privilege"],
            FindingCategory.SENSITIVE_DATA: ["sensitive data", "cleartext", "unencrypted", "exposure"],
            FindingCategory.SECURITY_MISCONFIG: ["misconfiguration", "default", "unnecessary", "debug", "directory listing"],
            FindingCategory.SSRF: ["ssrf", "server-side request"],
            FindingCategory.CRYPTOGRAPHIC: ["weak cipher", "ssl", "tls", "certificate", "crypto"],
            FindingCategory.VULNERABLE_COMPONENTS: ["outdated", "vulnerable version", "cve-", "known vulnerability"],
            FindingCategory.INFORMATION_DISCLOSURE: ["information disclosure", "version disclosure", "error message"],
        }

        for category, keywords in category_keywords.items():
            if any(kw in text for kw in keywords):
                return category

        return FindingCategory.OTHER

    def _parse_severity(self, text: str) -> FindingSeverity:
        try:
            return FindingSeverity(text.lower())
        except ValueError:
            return FindingSeverity.MEDIUM

    def _parse_json(self, text: str) -> dict[str, Any]:
        try:
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]
            return json.loads(text.strip())
        except (json.JSONDecodeError, IndexError):
            return {}

    def get_stats(self) -> dict[str, Any]:
        return {
            "total": len(self._findings),
            "confirmed": sum(1 for f in self._findings.values() if f.status == FindingStatus.CONFIRMED),
            "false_positives": sum(1 for f in self._findings.values() if f.status == FindingStatus.FALSE_POSITIVE),
            "chains": len(self._chains),
            "risk_score": round(
                sum(f.risk_score for f in self._findings.values() if f.status != FindingStatus.FALSE_POSITIVE),
                1,
            ),
        }
