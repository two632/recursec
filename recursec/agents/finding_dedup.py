"""Finding deduplicator — identifies and merges duplicate findings.

Implements:
1. Exact match deduplication
2. Fuzzy similarity scoring
3. CWE/CVE-based correlation
4. Endpoint-level deduplication
5. Cross-tool finding correlation
6. Severity reconciliation for merged findings
7. Evidence aggregation
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class DedupStrategy(str, Enum):
    EXACT = "exact"             # Exact field match
    FUZZY = "fuzzy"             # Similarity-based
    CWE_BASED = "cwe_based"     # Same CWE + similar location
    ENDPOINT = "endpoint"       # Same endpoint + same vuln type


class MergeAction(str, Enum):
    KEEP_FIRST = "keep_first"
    KEEP_HIGHEST_SEVERITY = "keep_highest_severity"
    MERGE_EVIDENCE = "merge_evidence"
    DISCARD_DUPLICATE = "discard_duplicate"


@dataclass
class Finding:
    """A security finding."""
    finding_id: str = ""
    title: str = ""
    description: str = ""
    severity: str = "medium"
    confidence: float = 0.5
    cwe: str = ""
    cve: str = ""
    endpoint: str = ""
    parameter: str = ""
    tool: str = ""
    evidence: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)
    merged_from: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.finding_id[:10],
            "title": self.title[:30],
            "severity": self.severity,
            "confidence": round(self.confidence, 2),
            "cwe": self.cwe[:10],
            "endpoint": self.endpoint[:25],
        }


@dataclass
class DedupResult:
    """Result of deduplication."""
    unique_findings: list[Finding] = field(default_factory=list)
    duplicates_removed: int = 0
    merges_performed: int = 0
    original_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "unique": len(self.unique_findings),
            "duplicates": self.duplicates_removed,
            "merges": self.merges_performed,
            "original": self.original_count,
        }


# ── Severity ordering ────────────────────────────────────────

SEVERITY_ORDER: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


class FindingDeduplicator:
    """Identifies and merges duplicate security findings.

    Uses multiple strategies to detect duplicates
    and merge evidence while preserving highest
    severity assessments.
    """

    def __init__(
        self,
        similarity_threshold: float = 0.7,
    ) -> None:
        self._threshold = similarity_threshold
        self._log = logger.bind(component="finding_dedup")

    def deduplicate(
        self,
        findings: list[Finding],
        strategy: DedupStrategy = DedupStrategy.FUZZY,
    ) -> DedupResult:
        """Deduplicate a list of findings."""
        if not findings:
            return DedupResult()

        result = DedupResult(original_count=len(findings))

        if strategy == DedupStrategy.EXACT:
            unique = self._dedup_exact(findings)
        elif strategy == DedupStrategy.CWE_BASED:
            unique = self._dedup_cwe(findings)
        elif strategy == DedupStrategy.ENDPOINT:
            unique = self._dedup_endpoint(findings)
        else:
            unique = self._dedup_fuzzy(findings)

        result.unique_findings = unique
        result.duplicates_removed = len(findings) - len(unique)
        result.merges_performed = sum(
            len(f.merged_from) for f in unique if f.merged_from
        )

        return result

    def _dedup_exact(self, findings: list[Finding]) -> list[Finding]:
        """Exact match deduplication using hash."""
        seen: dict[str, Finding] = {}
        for finding in findings:
            key = self._finding_hash(finding)
            if key in seen:
                existing = seen[key]
                self._merge_into(existing, finding)
            else:
                seen[key] = finding
        return list(seen.values())

    def _dedup_fuzzy(self, findings: list[Finding]) -> list[Finding]:
        """Fuzzy similarity-based deduplication."""
        unique: list[Finding] = []

        for finding in findings:
            merged = False
            for existing in unique:
                similarity = self._similarity(existing, finding)
                if similarity >= self._threshold:
                    self._merge_into(existing, finding)
                    merged = True
                    break

            if not merged:
                unique.append(finding)

        return unique

    def _dedup_cwe(self, findings: list[Finding]) -> list[Finding]:
        """CWE-based deduplication."""
        groups: dict[str, list[Finding]] = {}
        no_cwe: list[Finding] = []

        for finding in findings:
            if finding.cwe:
                key = f"{finding.cwe}:{finding.endpoint}"
                groups.setdefault(key, []).append(finding)
            else:
                no_cwe.append(finding)

        unique: list[Finding] = []
        for group in groups.values():
            merged = group[0]
            for other in group[1:]:
                self._merge_into(merged, other)
            unique.append(merged)

        # Fuzzy dedup the no-CWE findings
        for finding in no_cwe:
            merged_flag = False
            for existing in unique:
                if self._similarity(existing, finding) >= self._threshold:
                    self._merge_into(existing, finding)
                    merged_flag = True
                    break
            if not merged_flag:
                unique.append(finding)

        return unique

    def _dedup_endpoint(self, findings: list[Finding]) -> list[Finding]:
        """Endpoint-level deduplication."""
        groups: dict[str, list[Finding]] = {}

        for finding in findings:
            key = f"{finding.endpoint}:{finding.severity}"
            groups.setdefault(key, []).append(finding)

        unique: list[Finding] = []
        for group in groups.values():
            merged = group[0]
            for other in group[1:]:
                self._merge_into(merged, other)
            unique.append(merged)

        return unique

    def _finding_hash(self, finding: Finding) -> str:
        """Create a hash for exact matching."""
        content = f"{finding.title}|{finding.cwe}|{finding.endpoint}|{finding.parameter}"
        return hashlib.md5(content.encode()).hexdigest()

    def _similarity(self, finding_a: Finding, finding_b: Finding) -> float:
        """Calculate similarity between two findings."""
        score = 0.0
        total_weight = 0.0

        # Title similarity (weight: 0.3)
        title_sim = self._text_similarity(finding_a.title, finding_b.title)
        score += title_sim * 0.3
        total_weight += 0.3

        # CWE match (weight: 0.25)
        if finding_a.cwe and finding_b.cwe:
            cwe_match = 1.0 if finding_a.cwe == finding_b.cwe else 0.0
            score += cwe_match * 0.25
        total_weight += 0.25

        # CVE match (weight: 0.2)
        if finding_a.cve and finding_b.cve:
            cve_match = 1.0 if finding_a.cve == finding_b.cve else 0.0
            score += cve_match * 0.2
        total_weight += 0.2

        # Endpoint similarity (weight: 0.15)
        if finding_a.endpoint and finding_b.endpoint:
            ep_sim = self._text_similarity(finding_a.endpoint, finding_b.endpoint)
            score += ep_sim * 0.15
        total_weight += 0.15

        # Severity match (weight: 0.1)
        sev_match = 1.0 if finding_a.severity == finding_b.severity else 0.3
        score += sev_match * 0.1
        total_weight += 0.1

        return score / max(0.001, total_weight)

    def _text_similarity(self, text_a: str, text_b: str) -> float:
        """Simple token-overlap similarity."""
        if not text_a or not text_b:
            return 0.0

        tokens_a = set(re.findall(r'\w+', text_a.lower()))
        tokens_b = set(re.findall(r'\w+', text_b.lower()))

        if not tokens_a or not tokens_b:
            return 0.0

        intersection = tokens_a & tokens_b
        union = tokens_a | tokens_b
        return len(intersection) / len(union)

    def _merge_into(self, target: Finding, source: Finding) -> None:
        """Merge source finding into target."""
        # Keep highest severity
        if SEVERITY_ORDER.get(source.severity, 0) > SEVERITY_ORDER.get(target.severity, 0):
            target.severity = source.severity

        # Keep highest confidence
        target.confidence = max(target.confidence, source.confidence)

        # Merge evidence
        for ev in source.evidence:
            if ev not in target.evidence:
                target.evidence.append(ev)

        # Merge tags
        for tag in source.tags:
            if tag not in target.tags:
                target.tags.append(tag)

        # Track merge
        target.merged_from.append(source.finding_id)

        # Keep CWE/CVE if target missing
        if not target.cwe and source.cwe:
            target.cwe = source.cwe
        if not target.cve and source.cve:
            target.cve = source.cve

    def get_duplicate_groups(
        self,
        findings: list[Finding],
        threshold: float = 0.0,
    ) -> list[list[Finding]]:
        """Find groups of duplicate findings."""
        thresh = threshold or self._threshold
        groups: list[list[Finding]] = []
        used = set()

        for idx, finding in enumerate(findings):
            if idx in used:
                continue

            group = [finding]
            used.add(idx)

            for jdx in range(idx + 1, len(findings)):
                if jdx in used:
                    continue
                if self._similarity(finding, findings[jdx]) >= thresh:
                    group.append(findings[jdx])
                    used.add(jdx)

            if len(group) > 1:
                groups.append(group)

        return groups
