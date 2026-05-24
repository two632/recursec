"""Finding deduplicator — removes duplicate findings.

Implements:
1. Similarity scoring between findings
2. Fingerprint-based exact dedup
3. Semantic similarity (fuzzy dedup)
4. Cross-tool correlation
5. Finding merge (combine evidence)
6. Dedup prompt for LLM
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class Finding:
    """A security finding."""
    finding_id: str = ""
    title: str = ""
    description: str = ""
    severity: str = "medium"
    category: str = ""
    target: str = ""
    tool: str = ""
    agent_id: str = ""
    cve: str = ""
    evidence: list[str] = field(default_factory=list)
    fingerprint: str = ""
    merged_from: list[str] = field(default_factory=list)
    duplicate_of: str = ""
    confidence: float = 0.5
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.finding_id[:10],
            "title": self.title[:25],
            "severity": self.severity[:4],
            "target": self.target[:15],
            "dupe": bool(self.duplicate_of),
        }


class FindingDeduplicator:
    """Deduplicates findings from multiple agents/tools.

    Uses fingerprinting for exact matches and
    similarity scoring for fuzzy dedup. Merges
    evidence from duplicate findings.
    """

    def __init__(
        self,
        similarity_threshold: float = 0.8,
    ) -> None:
        self._findings: dict[str, Finding] = {}
        self._unique: dict[str, Finding] = {}
        self._fingerprint_index: dict[str, str] = {}  # fingerprint → finding_id
        self._finding_counter = 0
        self._similarity_threshold = similarity_threshold
        self._dedup_count = 0
        self._merge_count = 0
        self._log = logger.bind(component="dedup")

    def _compute_fingerprint(self, finding: Finding) -> str:
        """Compute a deterministic fingerprint."""
        key_parts = [
            finding.category.lower(),
            finding.target.lower(),
            finding.cve.lower() if finding.cve else "",
            finding.title.lower()[:50],
        ]
        key = "|".join(key_parts)
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def _similarity_score(self, a: Finding, b: Finding) -> float:
        """Calculate similarity between two findings."""
        score = 0.0
        weights_total = 0.0

        # Same CVE = very similar
        if a.cve and b.cve and a.cve == b.cve:
            score += 0.9
            weights_total += 1.0
        elif a.cve or b.cve:
            weights_total += 1.0

        # Same target
        if a.target and b.target:
            if a.target.lower() == b.target.lower():
                score += 0.3
            weights_total += 0.3

        # Same category
        if a.category and b.category:
            if a.category.lower() == b.category.lower():
                score += 0.2
            weights_total += 0.2

        # Same severity
        if a.severity == b.severity:
            score += 0.1
            weights_total += 0.1

        # Title similarity (Jaccard on words)
        a_words = set(a.title.lower().split())
        b_words = set(b.title.lower().split())
        if a_words and b_words:
            intersection = len(a_words & b_words)
            union = len(a_words | b_words)
            jaccard = intersection / union if union > 0 else 0
            score += jaccard * 0.4
            weights_total += 0.4

        if weights_total == 0:
            return 0.0
        return score / weights_total

    def add_finding(self, finding: Finding) -> tuple[Finding, bool]:
        """Add a finding, dedup if duplicate.

        Returns (finding, is_new) — finding may be
        existing if it was a duplicate.
        """
        self._finding_counter += 1
        if not finding.finding_id:
            finding.finding_id = f"find-{self._finding_counter}"

        # Compute fingerprint
        fingerprint = self._compute_fingerprint(finding)
        finding.fingerprint = fingerprint

        self._findings[finding.finding_id] = finding

        # Exact dedup via fingerprint
        if fingerprint in self._fingerprint_index:
            existing_id = self._fingerprint_index[fingerprint]
            existing = self._unique.get(existing_id)
            if existing:
                self._merge(existing, finding)
                self._dedup_count += 1
                finding.duplicate_of = existing_id
                return existing, False

        # Fuzzy dedup via similarity
        for uid, unique_finding in self._unique.items():
            sim = self._similarity_score(finding, unique_finding)
            if sim >= self._similarity_threshold:
                self._merge(unique_finding, finding)
                self._dedup_count += 1
                finding.duplicate_of = uid
                return unique_finding, False

        # New unique finding
        self._unique[finding.finding_id] = finding
        self._fingerprint_index[fingerprint] = finding.finding_id
        return finding, True

    def _merge(self, target: Finding, source: Finding) -> None:
        """Merge source evidence into target."""
        self._merge_count += 1

        # Merge evidence
        for ev in source.evidence:
            if ev not in target.evidence:
                target.evidence.append(ev)

        # Track merge
        target.merged_from.append(source.finding_id)

        # Take higher confidence
        if source.confidence > target.confidence:
            target.confidence = source.confidence

        # Take higher severity
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        if severity_order.get(source.severity, 0) > severity_order.get(target.severity, 0):
            target.severity = source.severity

    def get_unique_findings(self) -> list[Finding]:
        """Get all unique (deduplicated) findings."""
        return list(self._unique.values())

    def get_by_severity(self, severity: str) -> list[Finding]:
        """Get unique findings by severity."""
        return [
            f for f in self._unique.values()
            if f.severity.lower() == severity.lower()
        ]

    def build_dedup_prompt(self) -> str:
        """Build dedup context for LLM."""
        lines = ["## Finding Dedup\n"]
        lines.append(f"Total submitted: {len(self._findings)}")
        lines.append(f"Unique: {len(self._unique)}")
        lines.append(f"Duplicates: {self._dedup_count}")
        lines.append(f"Merges: {self._merge_count}")

        # Severity breakdown
        sev_counts: dict[str, int] = {}
        for f in self._unique.values():
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

        if sev_counts:
            lines.append("\nBy severity:")
            for sev in ["critical", "high", "medium", "low", "info"]:
                count = sev_counts.get(sev, 0)
                if count:
                    lines.append(f"  {sev}: {count}")

        # Recent unique findings
        recent = sorted(
            self._unique.values(),
            key=lambda f: f.timestamp,
            reverse=True,
        )[:5]
        if recent:
            lines.append(f"\nRecent ({len(recent)}):")
            for f in recent:
                merged = f" (+{len(f.merged_from)} merged)" if f.merged_from else ""
                lines.append(f"  [{f.severity[:4]}] {f.title[:30]}{merged}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        sev_counts: dict[str, int] = {}
        for f in self._unique.values():
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

        return {
            "submitted": len(self._findings),
            "unique": len(self._unique),
            "duplicates": self._dedup_count,
            "merges": self._merge_count,
            "by_severity": sev_counts,
            "dedup_rate": f"{self._dedup_count / max(1, len(self._findings)):.0%}",
        }
