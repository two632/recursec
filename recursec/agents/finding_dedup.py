"""Finding deduplicator — smart deduplication with similarity scoring.

Implements:
1. Exact match deduplication (same tool + target + type)
2. Fuzzy similarity scoring for near-duplicates
3. Grouping related findings into clusters
4. Canonical finding selection from duplicates
5. Finding merge (combine evidence from duplicates)
6. Dedup statistics and reporting
7. LLM prompt for dedup decisions
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class DedupStatus(str, Enum):
    UNIQUE = "unique"
    DUPLICATE = "duplicate"
    NEAR_DUPLICATE = "near_duplicate"
    MERGED = "merged"


class FindingType(str, Enum):
    VULNERABILITY = "vulnerability"
    MISCONFIGURATION = "misconfiguration"
    INFO_LEAK = "info_leak"
    WEAK_CRYPTO = "weak_crypto"
    ACCESS_CONTROL = "access_control"
    INJECTION = "injection"
    XSS = "xss"
    AUTHENTICATION = "authentication"
    EXPOSURE = "exposure"
    OTHER = "other"


@dataclass
class DedupFinding:
    """A finding with deduplication metadata."""
    finding_id: str = ""
    title: str = ""
    description: str = ""
    finding_type: FindingType = FindingType.OTHER
    severity: str = "medium"
    target: str = ""
    url: str = ""
    parameter: str = ""
    tool: str = ""
    evidence: list[str] = field(default_factory=list)
    cwe_id: str = ""
    cvss_score: float = 0.0

    # Dedup metadata
    dedup_status: DedupStatus = DedupStatus.UNIQUE
    canonical_id: str = ""     # Points to canonical finding if duplicate
    duplicate_ids: list[str] = field(default_factory=list)
    similarity_scores: dict[str, float] = field(default_factory=dict)
    cluster_id: str = ""

    created_at: float = field(default_factory=time.time)

    @property
    def dedup_key(self) -> str:
        """Generate key for exact dedup."""
        parts = [
            self.finding_type.value,
            self.target.lower(),
            self.url.lower() if self.url else "",
            self.parameter.lower() if self.parameter else "",
            self.cwe_id,
        ]
        return "|".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.finding_id[:10],
            "title": self.title[:25],
            "type": self.finding_type.value,
            "severity": self.severity,
            "status": self.dedup_status.value,
            "dupes": len(self.duplicate_ids),
        }


@dataclass
class FindingCluster:
    """A cluster of related findings."""
    cluster_id: str = ""
    canonical_id: str = ""     # Best representative finding
    finding_ids: list[str] = field(default_factory=list)
    common_type: str = ""
    common_target: str = ""
    avg_similarity: float = 0.0
    max_severity: str = "info"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.cluster_id[:8],
            "canonical": self.canonical_id[:10],
            "count": len(self.finding_ids),
            "type": self.common_type[:12],
            "severity": self.max_severity,
        }


class FindingDeduplicator:
    """Smart finding deduplication engine.

    Deduplicates findings using exact keys and
    fuzzy similarity scoring. Groups related findings
    into clusters and selects canonical representatives.
    """

    def __init__(
        self,
        similarity_threshold: float = 0.7,
        exact_dedup: bool = True,
    ) -> None:
        self._findings: dict[str, DedupFinding] = {}
        self._clusters: dict[str, FindingCluster] = {}
        self._dedup_index: dict[str, str] = {}  # dedup_key → finding_id
        self._similarity_threshold = similarity_threshold
        self._exact_dedup = exact_dedup
        self._counter = 0
        self._dedup_count = 0
        self._merge_count = 0
        self._log = logger.bind(component="finding_dedup")

    def add_finding(self, finding: DedupFinding) -> DedupFinding:
        """Add a finding, checking for duplicates."""
        # Exact dedup check
        if self._exact_dedup:
            key = finding.dedup_key
            existing_id = self._dedup_index.get(key)
            if existing_id and existing_id in self._findings:
                existing = self._findings[existing_id]
                finding.dedup_status = DedupStatus.DUPLICATE
                finding.canonical_id = existing_id
                existing.duplicate_ids.append(finding.finding_id)
                self._dedup_count += 1

                # Merge evidence
                for ev in finding.evidence:
                    if ev not in existing.evidence:
                        existing.evidence.append(ev)

                self._findings[finding.finding_id] = finding
                return finding

            self._dedup_index[key] = finding.finding_id

        # Fuzzy similarity check
        for existing in self._findings.values():
            if existing.dedup_status == DedupStatus.DUPLICATE:
                continue

            similarity = self._compute_similarity(finding, existing)
            if similarity >= self._similarity_threshold:
                finding.dedup_status = DedupStatus.NEAR_DUPLICATE
                finding.canonical_id = existing.finding_id
                finding.similarity_scores[existing.finding_id] = similarity
                existing.duplicate_ids.append(finding.finding_id)
                self._dedup_count += 1
                break

        self._findings[finding.finding_id] = finding
        return finding

    def merge_findings(
        self,
        finding_ids: list[str],
    ) -> DedupFinding | None:
        """Merge multiple findings into one."""
        findings = [self._findings[fid] for fid in finding_ids if fid in self._findings]
        if len(findings) < 2:
            return None

        # Pick canonical: highest severity, most evidence
        sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        canonical = max(findings, key=lambda f: (sev_order.get(f.severity, 0), len(f.evidence)))

        # Merge all evidence into canonical
        for f in findings:
            if f.finding_id == canonical.finding_id:
                continue
            for ev in f.evidence:
                if ev not in canonical.evidence:
                    canonical.evidence.append(ev)
            f.dedup_status = DedupStatus.MERGED
            f.canonical_id = canonical.finding_id
            canonical.duplicate_ids.append(f.finding_id)

        self._merge_count += 1
        return canonical

    def create_cluster(
        self,
        finding_ids: list[str],
    ) -> FindingCluster | None:
        """Create a cluster from related findings."""
        findings = [self._findings[fid] for fid in finding_ids if fid in self._findings]
        if not findings:
            return None

        self._counter += 1

        # Determine canonical
        sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        canonical = max(findings, key=lambda f: (sev_order.get(f.severity, 0), len(f.evidence)))
        max_severity = max(findings, key=lambda f: sev_order.get(f.severity, 0)).severity

        cluster = FindingCluster(
            cluster_id=f"cluster-{self._counter}",
            canonical_id=canonical.finding_id,
            finding_ids=finding_ids,
            common_type=canonical.finding_type.value,
            common_target=canonical.target,
            max_severity=max_severity,
        )

        # Update findings with cluster info
        for f in findings:
            f.cluster_id = cluster.cluster_id

        self._clusters[cluster.cluster_id] = cluster
        return cluster

    def get_unique_findings(self) -> list[DedupFinding]:
        """Get only unique (non-duplicate) findings."""
        return [
            f for f in self._findings.values()
            if f.dedup_status in (DedupStatus.UNIQUE, DedupStatus.MERGED)
        ]

    def build_dedup_prompt(self, max_findings: int = 10) -> str:
        """Build dedup context for LLM."""
        lines = ["## Finding Deduplication\n"]

        unique = self.get_unique_findings()
        lines.append(
            f"Total: {len(self._findings)} | Unique: {len(unique)} | "
            f"Deduped: {self._dedup_count} | Merged: {self._merge_count}"
        )

        if unique:
            lines.append("\nUnique findings:")
            sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
            sorted_findings = sorted(unique, key=lambda f: sev_order.get(f.severity, 0), reverse=True)
            for f in sorted_findings[:max_findings]:
                dupes = f"+{len(f.duplicate_ids)}" if f.duplicate_ids else ""
                lines.append(
                    f"  [{f.severity[0].upper()}] {f.title[:30]} "
                    f"({f.finding_type.value}) {dupes}"
                )

        if self._clusters:
            lines.append(f"\nClusters: {len(self._clusters)}")

        return "\n".join(lines)

    def _compute_similarity(
        self,
        a: DedupFinding,
        b: DedupFinding,
    ) -> float:
        """Compute similarity between two findings."""
        score = 0.0
        weights = 0.0

        # Type match
        if a.finding_type == b.finding_type:
            score += 0.3
        weights += 0.3

        # Target match
        if a.target and b.target and a.target.lower() == b.target.lower():
            score += 0.2
        weights += 0.2

        # CWE match
        if a.cwe_id and b.cwe_id and a.cwe_id == b.cwe_id:
            score += 0.2
        weights += 0.2

        # Title similarity (token overlap)
        a_tokens = set(a.title.lower().split())
        b_tokens = set(b.title.lower().split())
        if a_tokens and b_tokens:
            overlap = len(a_tokens & b_tokens)
            union = len(a_tokens | b_tokens)
            score += 0.3 * (overlap / union) if union else 0
        weights += 0.3

        return score / weights if weights else 0

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_findings": len(self._findings),
            "unique": len(self.get_unique_findings()),
            "duplicates_found": self._dedup_count,
            "merges": self._merge_count,
            "clusters": len(self._clusters),
        }
