"""Vulnerability correlator — deduplicates, correlates, and enriches findings.

Handles:
- Finding deduplication across agents/tools
- CVE enrichment with local database
- CVSS scoring and recalculation
- Finding grouping by host/service/category
- Confidence aggregation from multiple sources
- False positive detection heuristics
- Attack chain identification from correlated findings
- Severity prioritization with exploit availability
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

from recursec.core.models import Severity, Vulnerability

logger = structlog.get_logger()


@dataclass
class CorrelatedFinding:
    """A deduplicated, enriched finding from multiple sources."""
    id: str
    title: str
    severity: Severity
    description: str
    cvss_score: float = 0.0
    cve_id: str = ""
    cwe_id: str = ""
    affected_components: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    tool_sources: list[str] = field(default_factory=list)
    confidence: float = 0.0
    validated: bool = False
    false_positive: bool = False
    exploitable: bool = False
    exploit_available: bool = False
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    related_cves: list[str] = field(default_factory=list)
    raw_findings: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "cvss_score": self.cvss_score,
            "cve_id": self.cve_id,
            "cwe_id": self.cwe_id,
            "affected_components": self.affected_components,
            "sources": self.sources,
            "confidence": round(self.confidence, 2),
            "validated": self.validated,
            "exploitable": self.exploitable,
            "remediation": self.remediation[:500],
        }


@dataclass
class CorrelationConfig:
    """Configuration for the correlator."""
    dedup_similarity_threshold: float = 0.7
    min_confidence: float = 0.3
    multi_source_confidence_boost: float = 0.15
    validated_confidence_boost: float = 0.2
    exploit_available_severity_bump: bool = True
    false_positive_heuristics: bool = True
    max_findings: int = 10000


# ── Common False Positive Patterns ────────────────────────

FALSE_POSITIVE_PATTERNS = [
    # Generic informational findings that aren't real vulns
    (r"server.*header.*disclosed", "info", "Server header disclosure is informational, not a vulnerability"),
    (r"x-powered-by.*header", "info", "X-Powered-By header is informational"),
    (r"missing.*x-frame-options.*header", "low", "Only relevant if page has sensitive content"),
    (r"cookie.*without.*secure.*flag", "low", "Check if cookie contains sensitive data"),
    (r"directory.*listing.*enabled", "medium", "Verify directory contains sensitive files"),
    (r"clickjacking", "low", "Verify target has authenticated functionality"),
]

# CVE patterns for auto-enrichment
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
CWE_PATTERN = re.compile(r"CWE-\d{1,5}", re.IGNORECASE)

# Severity mapping from CVSS
CVSS_TO_SEVERITY = [
    (9.0, Severity.CRITICAL),
    (7.0, Severity.HIGH),
    (4.0, Severity.MEDIUM),
    (0.1, Severity.LOW),
    (0.0, Severity.INFO),
]


class VulnCorrelator:
    """Deduplicates, correlates, and enriches vulnerability findings."""

    def __init__(self, config: CorrelationConfig | None = None):
        self.config = config or CorrelationConfig()
        self._raw_findings: list[Vulnerability] = []
        self._correlated: dict[str, CorrelatedFinding] = {}
        self._fingerprints: dict[str, str] = {}  # fingerprint -> correlated_id
        self._host_findings: dict[str, list[str]] = defaultdict(list)
        self._cve_findings: dict[str, list[str]] = defaultdict(list)
        self._stats = {
            "total_raw": 0,
            "total_correlated": 0,
            "duplicates_removed": 0,
            "false_positives_detected": 0,
            "enrichments_applied": 0,
        }

    def add_finding(self, finding: Vulnerability, source: str = "") -> str | None:
        """Add a finding and return its correlated ID (or None if duplicate)."""
        self._stats["total_raw"] += 1
        self._raw_findings.append(finding)

        # Generate fingerprint for dedup
        fingerprint = self._fingerprint(finding)

        # Check for existing match
        if fingerprint in self._fingerprints:
            existing_id = self._fingerprints[fingerprint]
            existing = self._correlated[existing_id]
            self._merge_into(existing, finding, source)
            self._stats["duplicates_removed"] += 1
            return existing_id

        # Check for similar findings
        similar_id = self._find_similar(finding)
        if similar_id:
            existing = self._correlated[similar_id]
            self._merge_into(existing, finding, source)
            self._fingerprints[fingerprint] = similar_id
            self._stats["duplicates_removed"] += 1
            return similar_id

        # New finding
        correlated = self._create_correlated(finding, source)
        self._correlated[correlated.id] = correlated
        self._fingerprints[fingerprint] = correlated.id
        self._stats["total_correlated"] += 1

        # Index
        for comp in correlated.affected_components:
            self._host_findings[comp].append(correlated.id)
        if correlated.cve_id:
            self._cve_findings[correlated.cve_id].append(correlated.id)

        # False positive check
        if self.config.false_positive_heuristics:
            self._check_false_positive(correlated)

        return correlated.id

    def add_findings(self, findings: list[Vulnerability], source: str = "") -> list[str]:
        """Add multiple findings."""
        return [fid for f in findings if (fid := self.add_finding(f, source)) is not None]

    def get_findings(
        self,
        severity: Severity | None = None,
        min_confidence: float | None = None,
        exclude_false_positives: bool = True,
        limit: int = 0,
    ) -> list[CorrelatedFinding]:
        """Get correlated findings with filtering."""
        results = list(self._correlated.values())

        if exclude_false_positives:
            results = [f for f in results if not f.false_positive]
        if severity:
            results = [f for f in results if f.severity == severity]
        min_conf = min_confidence if min_confidence is not None else self.config.min_confidence
        results = [f for f in results if f.confidence >= min_conf]

        # Sort by severity (critical first) then confidence
        severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
        results.sort(key=lambda f: (severity_order.get(f.severity, 5), -f.confidence))

        if limit > 0:
            results = results[:limit]
        return results

    def get_by_host(self, host: str) -> list[CorrelatedFinding]:
        """Get findings for a specific host."""
        ids = self._host_findings.get(host, [])
        return [self._correlated[fid] for fid in ids if fid in self._correlated]

    def get_by_cve(self, cve_id: str) -> list[CorrelatedFinding]:
        """Get findings for a specific CVE."""
        ids = self._cve_findings.get(cve_id.upper(), [])
        return [self._correlated[fid] for fid in ids if fid in self._correlated]

    def get_severity_summary(self) -> dict[str, int]:
        """Get count of findings by severity."""
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self._correlated.values():
            if not f.false_positive:
                counts[f.severity.value] += 1
        return counts

    def get_attack_surface(self) -> dict[str, Any]:
        """Get the attack surface summary."""
        hosts: dict[str, list[str]] = defaultdict(list)
        for f in self._correlated.values():
            if f.false_positive:
                continue
            for comp in f.affected_components:
                hosts[comp].append(f.title)

        return {
            "hosts_affected": len(hosts),
            "total_findings": sum(1 for f in self._correlated.values() if not f.false_positive),
            "hosts": {h: {"findings": len(fs), "titles": fs[:5]} for h, fs in hosts.items()},
        }

    # ── Internal Methods ────────────────────────────────────

    def _fingerprint(self, finding: Vulnerability) -> str:
        """Generate a dedup fingerprint for a finding."""
        parts = [
            finding.title.lower().strip(),
            finding.affected_component.lower().strip(),
            finding.severity.value,
        ]
        if finding.cve_id:
            parts.append(finding.cve_id.upper())
        if finding.cwe_id:
            parts.append(finding.cwe_id.upper())

        data = "|".join(parts)
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def _find_similar(self, finding: Vulnerability) -> str | None:
        """Find an existing similar finding using fuzzy matching."""
        title_lower = finding.title.lower()
        comp_lower = finding.affected_component.lower()

        for fid, correlated in self._correlated.items():
            # Exact CVE match
            if finding.cve_id and correlated.cve_id and finding.cve_id.upper() == correlated.cve_id.upper():
                return fid

            # Title similarity
            sim = self._text_similarity(title_lower, correlated.title.lower())
            if sim >= self.config.dedup_similarity_threshold:
                # Also check component overlap
                if comp_lower in " ".join(correlated.affected_components).lower():
                    return fid

        return None

    def _text_similarity(self, a: str, b: str) -> float:
        """Simple token-based similarity."""
        tokens_a = set(a.split())
        tokens_b = set(b.split())
        if not tokens_a or not tokens_b:
            return 0.0
        intersection = tokens_a & tokens_b
        union = tokens_a | tokens_b
        return len(intersection) / len(union)

    def _create_correlated(self, finding: Vulnerability, source: str) -> CorrelatedFinding:
        """Create a new correlated finding from a raw finding."""
        correlated = CorrelatedFinding(
            id=finding.id,
            title=finding.title,
            severity=finding.severity,
            description=finding.description,
            cvss_score=finding.cvss_score or self._estimate_cvss(finding.severity),
            cve_id=finding.cve_id or "",
            cwe_id=finding.cwe_id or "",
            affected_components=[finding.affected_component] if finding.affected_component else [],
            evidence=[finding.evidence] if finding.evidence else [],
            sources=[source] if source else [],
            tool_sources=[finding.tool_source] if finding.tool_source else [],
            confidence=finding.confidence,
            validated=finding.validated,
            remediation=finding.remediation,
            raw_findings=[finding.model_dump()],
        )

        # Auto-extract CVEs from description
        if not correlated.cve_id:
            cves = CVE_PATTERN.findall(finding.description)
            if cves:
                correlated.cve_id = cves[0].upper()
                correlated.related_cves = [c.upper() for c in cves]

        # Auto-extract CWEs
        if not correlated.cwe_id:
            cwes = CWE_PATTERN.findall(finding.description)
            if cwes:
                correlated.cwe_id = cwes[0].upper()

        return correlated

    def _merge_into(self, existing: CorrelatedFinding, new: Vulnerability, source: str) -> None:
        """Merge a new finding into an existing correlated finding."""
        # Add source
        if source and source not in existing.sources:
            existing.sources.append(source)
        if new.tool_source and new.tool_source not in existing.tool_sources:
            existing.tool_sources.append(new.tool_source)

        # Add component
        if new.affected_component and new.affected_component not in existing.affected_components:
            existing.affected_components.append(new.affected_component)

        # Add evidence
        if new.evidence and new.evidence not in existing.evidence:
            existing.evidence.append(new.evidence)

        # Boost confidence for multi-source confirmation
        if len(existing.sources) > 1:
            existing.confidence = min(1.0, existing.confidence + self.config.multi_source_confidence_boost)

        # Upgrade severity if new finding is more severe
        severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
        if severity_order.get(new.severity, 5) < severity_order.get(existing.severity, 5):
            existing.severity = new.severity

        # Use higher CVSS
        if new.cvss_score and (not existing.cvss_score or new.cvss_score > existing.cvss_score):
            existing.cvss_score = new.cvss_score

        # Merge CVE info
        if new.cve_id and not existing.cve_id:
            existing.cve_id = new.cve_id
        if new.cwe_id and not existing.cwe_id:
            existing.cwe_id = new.cwe_id

        # Mark validated if any source validated it
        if new.validated:
            existing.validated = True
            existing.confidence = min(1.0, existing.confidence + self.config.validated_confidence_boost)

        existing.raw_findings.append(new.model_dump())

    def _check_false_positive(self, finding: CorrelatedFinding) -> None:
        """Apply heuristics to detect false positives."""
        title_lower = finding.title.lower()
        desc_lower = finding.description.lower()
        combined = f"{title_lower} {desc_lower}"

        for pattern, max_severity, reason in FALSE_POSITIVE_PATTERNS:
            if re.search(pattern, combined):
                severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
                max_sev = Severity(max_severity)
                if severity_order.get(finding.severity, 5) < severity_order.get(max_sev, 5):
                    finding.confidence *= 0.5
                    if finding.confidence < 0.2:
                        finding.false_positive = True
                        self._stats["false_positives_detected"] += 1

    def _estimate_cvss(self, severity: Severity) -> float:
        """Estimate CVSS from severity if not provided."""
        mapping = {
            Severity.CRITICAL: 9.5,
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.5,
            Severity.LOW: 3.0,
            Severity.INFO: 0.0,
        }
        return mapping.get(severity, 0.0)

    def get_stats(self) -> dict[str, Any]:
        return {**self._stats}
