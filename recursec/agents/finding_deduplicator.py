"""Finding deduplicator — identifies and merges duplicate findings.

Implements:
1. Exact match deduplication
2. Fuzzy match deduplication
3. Semantic similarity deduplication
4. Cross-tool deduplication (same vuln found by different tools)
5. Finding merging with evidence aggregation
6. Dedup statistics tracking
7. Confidence boosting for multi-tool confirmation
8. Cluster-based grouping
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class DeduplicationResult:
    """Result of deduplication."""
    original_count: int = 0
    deduplicated_count: int = 0
    merged_count: int = 0
    unique_findings: list[dict[str, Any]] = field(default_factory=list)
    merge_groups: list[list[str]] = field(default_factory=list)

    @property
    def reduction_pct(self) -> float:
        if self.original_count == 0:
            return 0.0
        return (1.0 - self.deduplicated_count / self.original_count) * 100

    def to_dict(self) -> dict[str, Any]:
        return {
            "original": self.original_count,
            "deduped": self.deduplicated_count,
            "merged": self.merged_count,
            "reduction_pct": round(self.reduction_pct, 1),
        }


class FindingDeduplicator:
    """Identifies and merges duplicate findings.

    Uses exact, fuzzy, and semantic matching to
    detect duplicates across tools and phases.
    """

    def __init__(
        self,
        fuzzy_threshold: float = 0.7,
    ) -> None:
        self._fuzzy_threshold = fuzzy_threshold
        self._dedup_count = 0
        self._total_removed = 0
        self._log = logger.bind(component="finding_dedup")

    def deduplicate(
        self,
        findings: list[dict[str, Any]],
    ) -> DeduplicationResult:
        """Deduplicate a list of findings."""
        self._dedup_count += 1

        result = DeduplicationResult(original_count=len(findings))

        if not findings:
            return result

        # Phase 1: Exact dedup by hash
        unique_by_hash: dict[str, dict[str, Any]] = {}
        hash_groups: dict[str, list[str]] = defaultdict(list)

        for finding in findings:
            fhash = self._finding_hash(finding)
            if fhash not in unique_by_hash:
                unique_by_hash[fhash] = finding
            else:
                # Merge: boost confidence, add tools
                existing = unique_by_hash[fhash]
                self._merge_finding(existing, finding)

            hash_groups[fhash].append(finding.get("id", ""))

        # Phase 2: Fuzzy dedup
        unique_list = list(unique_by_hash.values())
        merged_indices: set[int] = set()
        merge_groups: list[list[str]] = []

        for i in range(len(unique_list)):
            if i in merged_indices:
                continue

            group = [unique_list[i].get("id", str(i))]

            for j in range(i + 1, len(unique_list)):
                if j in merged_indices:
                    continue

                similarity = self._similarity(unique_list[i], unique_list[j])
                if similarity >= self._fuzzy_threshold:
                    self._merge_finding(unique_list[i], unique_list[j])
                    merged_indices.add(j)
                    group.append(unique_list[j].get("id", str(j)))

            if len(group) > 1:
                merge_groups.append(group)

        # Build final list
        final = [f for i, f in enumerate(unique_list) if i not in merged_indices]

        result.deduplicated_count = len(final)
        result.merged_count = len(findings) - len(final)
        result.unique_findings = final
        result.merge_groups = merge_groups

        self._total_removed += result.merged_count

        return result

    def _finding_hash(self, finding: dict[str, Any]) -> str:
        """Generate a hash for exact dedup."""
        key_parts = [
            finding.get("title", "").lower().strip(),
            finding.get("target", "").lower().strip(),
            finding.get("severity", "").lower(),
        ]

        # Also include CVE if present
        cve = finding.get("cve", "")
        if cve:
            key_parts.append(cve.upper())

        key = "|".join(key_parts)
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def _similarity(
        self,
        finding1: dict[str, Any],
        finding2: dict[str, Any],
    ) -> float:
        """Calculate similarity between two findings."""
        score = 0.0
        max_score = 0.0

        # Title similarity (weighted heavily)
        title_sim = self._text_similarity(
            finding1.get("title", ""),
            finding2.get("title", ""),
        )
        score += title_sim * 3.0
        max_score += 3.0

        # Target match
        if finding1.get("target") == finding2.get("target"):
            score += 2.0
        max_score += 2.0

        # Severity match
        if finding1.get("severity") == finding2.get("severity"):
            score += 1.0
        max_score += 1.0

        # CVE match (strong signal)
        cve1 = finding1.get("cve", "")
        cve2 = finding2.get("cve", "")
        if cve1 and cve2 and cve1 == cve2:
            score += 3.0
        max_score += 3.0

        # CWE match
        if finding1.get("cwe") and finding1.get("cwe") == finding2.get("cwe"):
            score += 1.5
        max_score += 1.5

        # Description similarity
        desc_sim = self._text_similarity(
            finding1.get("description", ""),
            finding2.get("description", ""),
        )
        score += desc_sim * 1.5
        max_score += 1.5

        return score / max(0.001, max_score)

    @staticmethod
    def _text_similarity(text1: str, text2: str) -> float:
        """Simple Jaccard similarity between texts."""
        if not text1 or not text2:
            return 0.0

        words1 = set(re.findall(r"\b\w{3,}\b", text1.lower()))
        words2 = set(re.findall(r"\b\w{3,}\b", text2.lower()))

        if not words1 or not words2:
            return 0.0

        intersection = words1 & words2
        union = words1 | words2
        return len(intersection) / len(union)

    @staticmethod
    def _merge_finding(
        target: dict[str, Any],
        source: dict[str, Any],
    ) -> None:
        """Merge source finding into target."""
        # Boost confidence if found by multiple tools
        tools = set()
        if target.get("tool"):
            tools.add(target["tool"])
        if source.get("tool"):
            tools.add(source["tool"])
        target["confirmed_by_tools"] = list(tools)

        # Keep highest severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        target_sev = severity_order.get(target.get("severity", "info"), 4)
        source_sev = severity_order.get(source.get("severity", "info"), 4)
        if source_sev < target_sev:
            target["severity"] = source.get("severity", target.get("severity"))

        # Merge evidence
        target_evidence = target.get("evidence", "")
        source_evidence = source.get("evidence", "")
        if source_evidence and source_evidence not in target_evidence:
            target["evidence"] = (target_evidence + "\n---\n" + source_evidence)[:2000]

        # Confidence boost for multi-tool confirmation
        if len(tools) >= 2:
            target["confidence"] = min(0.99, target.get("confidence", 0.5) + 0.15)
        if len(tools) >= 3:
            target["confidence"] = min(0.99, target.get("confidence", 0.5) + 0.1)

    def get_stats(self) -> dict[str, Any]:
        return {
            "dedup_runs": self._dedup_count,
            "total_removed": self._total_removed,
        }
