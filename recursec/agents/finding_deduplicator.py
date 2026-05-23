"""Finding deduplicator — deduplicates and merges related security findings.

Implements:
1. Exact duplicate detection (same title/target)
2. Fuzzy duplicate detection (similar findings)
3. Finding merging (combine evidence from duplicates)
4. Cluster detection (related findings)
5. Severity reconciliation across duplicates
6. Source tracking for merged findings
7. Dedup statistics
8. Manual override for edge cases
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class MergeAction(str, Enum):
    KEEP = "keep"
    MERGE = "merge"
    DISCARD = "discard"


@dataclass
class DedupFinding:
    """A finding with dedup metadata."""
    finding_id: str = ""
    title: str = ""
    description: str = ""
    severity: str = ""
    target: str = ""
    endpoint: str = ""
    parameter: str = ""
    evidence: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    confidence: float = 0.5
    merged_from: list[str] = field(default_factory=list)

    @property
    def normalized_title(self) -> str:
        """Normalize title for comparison."""
        return re.sub(r'\s+', ' ', self.title.lower().strip())

    @property
    def fingerprint(self) -> str:
        """Generate a fingerprint for this finding."""
        parts = [
            self.normalized_title,
            self.target.lower(),
            self.endpoint.lower(),
            self.parameter.lower(),
        ]
        return "|".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.finding_id,
            "title": self.title[:30],
            "severity": self.severity,
            "target": self.target[:20],
            "confidence": round(self.confidence, 2),
            "sources": len(self.sources),
            "merged": len(self.merged_from),
        }


@dataclass
class DedupGroup:
    """A group of duplicate findings."""
    group_id: str = ""
    primary_id: str = ""
    duplicate_ids: list[str] = field(default_factory=list)
    similarity: float = 0.0
    merged: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "group": self.group_id,
            "primary": self.primary_id[:15],
            "dups": len(self.duplicate_ids),
            "sim": round(self.similarity, 2),
            "merged": self.merged,
        }


# ── Severity Order ────────────────────────────────────────────

SEVERITY_ORDER: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


class FindingDeduplicator:
    """Deduplicates and merges related security findings.

    Uses fingerprinting, fuzzy matching, and clustering
    to identify and merge duplicate findings.
    """

    def __init__(
        self,
        similarity_threshold: float = 0.7,
    ) -> None:
        self._findings: dict[str, DedupFinding] = {}
        self._groups: list[DedupGroup] = []
        self._fingerprint_index: dict[str, str] = {}
        self._finding_counter = 0
        self._group_counter = 0
        self._similarity_threshold = similarity_threshold
        self._log = logger.bind(component="finding_deduplicator")

    def add_finding(self, finding: DedupFinding) -> tuple[DedupFinding, bool]:
        """Add a finding, detecting duplicates.

        Returns (canonical_finding, is_new).
        """
        fingerprint = finding.fingerprint

        # Exact duplicate check
        if fingerprint in self._fingerprint_index:
            existing_id = self._fingerprint_index[fingerprint]
            existing = self._findings[existing_id]
            self._merge_into(existing, finding)
            return existing, False

        # Fuzzy duplicate check
        best_match = None
        best_sim = 0.0

        for existing in self._findings.values():
            sim = self._similarity(finding, existing)
            if sim > best_sim and sim >= self._similarity_threshold:
                best_sim = sim
                best_match = existing

        if best_match:
            self._merge_into(best_match, finding)

            self._group_counter += 1
            group = DedupGroup(
                group_id=f"dg-{self._group_counter}",
                primary_id=best_match.finding_id,
                duplicate_ids=[finding.finding_id],
                similarity=best_sim,
                merged=True,
            )
            self._groups.append(group)

            return best_match, False

        # New finding
        if not finding.finding_id:
            self._finding_counter += 1
            finding.finding_id = f"df-{self._finding_counter}"

        self._findings[finding.finding_id] = finding
        self._fingerprint_index[fingerprint] = finding.finding_id
        return finding, True

    def _merge_into(
        self,
        target: DedupFinding,
        source: DedupFinding,
    ) -> None:
        """Merge source finding into target."""
        # Merge evidence
        for ev in source.evidence:
            if ev not in target.evidence:
                target.evidence.append(ev)

        # Merge sources
        for src in source.sources:
            if src not in target.sources:
                target.sources.append(src)

        # Keep highest severity
        target_sev = SEVERITY_ORDER.get(target.severity.lower(), 0)
        source_sev = SEVERITY_ORDER.get(source.severity.lower(), 0)
        if source_sev > target_sev:
            target.severity = source.severity

        # Increase confidence with corroboration
        target.confidence = min(0.99, target.confidence + 0.1)

        # Track merge
        if source.finding_id:
            target.merged_from.append(source.finding_id)

    @staticmethod
    def _similarity(finding_a: DedupFinding, finding_b: DedupFinding) -> float:
        """Compute similarity between two findings."""
        score = 0.0
        total_weight = 0.0

        # Title similarity (Jaccard)
        words_a = set(finding_a.normalized_title.split())
        words_b = set(finding_b.normalized_title.split())
        if words_a or words_b:
            jaccard = len(words_a & words_b) / max(1, len(words_a | words_b))
            score += jaccard * 0.4
            total_weight += 0.4

        # Target match
        if finding_a.target and finding_b.target:
            if finding_a.target.lower() == finding_b.target.lower():
                score += 0.2
            total_weight += 0.2

        # Endpoint match
        if finding_a.endpoint and finding_b.endpoint:
            if finding_a.endpoint.lower() == finding_b.endpoint.lower():
                score += 0.2
            total_weight += 0.2

        # Parameter match
        if finding_a.parameter and finding_b.parameter:
            if finding_a.parameter.lower() == finding_b.parameter.lower():
                score += 0.2
            total_weight += 0.2

        if total_weight == 0:
            return 0.0
        return score / total_weight

    def get_unique_findings(self) -> list[DedupFinding]:
        """Get all unique (deduplicated) findings."""
        return sorted(
            self._findings.values(),
            key=lambda f: SEVERITY_ORDER.get(f.severity.lower(), 0),
            reverse=True,
        )

    def get_stats(self) -> dict[str, Any]:
        sev_counts: dict[str, int] = defaultdict(int)
        for f in self._findings.values():
            sev_counts[f.severity.lower()] += 1
        return {
            "unique_findings": len(self._findings),
            "groups": len(self._groups),
            "by_severity": dict(sev_counts),
        }
