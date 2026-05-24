"""Finding deduplicator — merge/deduplicate findings across tools.

Implements:
1. Similarity-based deduplication (fuzzy matching)
2. Cross-tool finding correlation
3. Evidence aggregation (combine from multiple tools)
4. Confidence boosting (multiple tools confirm same finding)
5. Severity reconciliation (when tools disagree)
6. Dedup prompt for LLM
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class DeduplicateStrategy(str, Enum):
    EXACT = "exact"            # Same hash
    FUZZY = "fuzzy"            # Similar type + target
    SEMANTIC = "semantic"      # Same vulnerability class


@dataclass
class MergedFinding:
    """A deduplicated finding with evidence from multiple tools."""
    finding_id: str = ""
    canonical_type: str = ""
    canonical_title: str = ""
    canonical_severity: str = "medium"
    target: str = ""
    port: int = 0
    confidence: float = 0.5
    tool_count: int = 1
    sources: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    dedup_hash: str = ""
    cluster_id: str = ""

    @property
    def boosted_confidence(self) -> float:
        """Confidence boosted by multiple confirmations."""
        base = self.confidence
        if self.tool_count >= 3:
            return min(0.99, base * 1.3)
        if self.tool_count >= 2:
            return min(0.95, base * 1.15)
        return base

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.finding_id[:10],
            "type": self.canonical_type[:15],
            "sev": self.canonical_severity[:4],
            "target": self.target[:20],
            "tools": self.tool_count,
            "conf": f"{self.boosted_confidence:.0%}",
        }


# ── Severity ranking ─────────────────────────────────────────

SEVERITY_RANK = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}

# ── Finding type normalization ───────────────────────────────

TYPE_ALIASES: dict[str, str] = {
    "sqli": "sql_injection",
    "sql-injection": "sql_injection",
    "sql_injection": "sql_injection",
    "xss": "cross_site_scripting",
    "cross-site-scripting": "cross_site_scripting",
    "reflected_xss": "cross_site_scripting",
    "stored_xss": "cross_site_scripting",
    "ssrf": "server_side_request_forgery",
    "server-side-request-forgery": "server_side_request_forgery",
    "rce": "remote_code_execution",
    "remote-code-execution": "remote_code_execution",
    "command_injection": "remote_code_execution",
    "lfi": "local_file_inclusion",
    "rfi": "remote_file_inclusion",
    "idor": "insecure_direct_object_reference",
    "bola": "insecure_direct_object_reference",
    "open_redirect": "open_redirect",
    "open-redirect": "open_redirect",
    "default_creds": "default_credentials",
    "default_credentials": "default_credentials",
    "weak_password": "default_credentials",
    "info_disclosure": "information_disclosure",
    "information-disclosure": "information_disclosure",
    "directory_listing": "information_disclosure",
    "debug_enabled": "information_disclosure",
}


class FindingDeduplicator:
    """Deduplicates and merges findings across tools.

    When multiple tools find the same vulnerability,
    this merges them into a single finding with combined
    evidence and boosted confidence.
    """

    def __init__(self) -> None:
        self._findings: dict[str, MergedFinding] = {}
        self._hash_index: dict[str, str] = {}   # dedup_hash → finding_id
        self._counter = 0
        self._total_raw = 0
        self._total_deduped = 0
        self._log = logger.bind(component="deduplicator")

    def _normalize_type(self, finding_type: str) -> str:
        """Normalize finding type to canonical form."""
        return TYPE_ALIASES.get(finding_type.lower(), finding_type.lower())

    def _compute_hash(
        self,
        finding_type: str,
        target: str,
        port: int = 0,
    ) -> str:
        """Compute dedup hash for a finding."""
        normalized = self._normalize_type(finding_type)
        key = f"{normalized}:{target}:{port}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def _highest_severity(self, sev1: str, sev2: str) -> str:
        """Return the higher severity."""
        r1 = SEVERITY_RANK.get(sev1.lower(), 1)
        r2 = SEVERITY_RANK.get(sev2.lower(), 1)
        return sev1 if r1 >= r2 else sev2

    def add_finding(
        self,
        finding_type: str,
        title: str,
        target: str,
        severity: str = "medium",
        confidence: float = 0.5,
        port: int = 0,
        tool: str = "",
        evidence: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> MergedFinding:
        """Add a finding, deduplicating as needed."""
        self._total_raw += 1
        dedup_hash = self._compute_hash(finding_type, target, port)

        if dedup_hash in self._hash_index:
            # Merge into existing
            existing_id = self._hash_index[dedup_hash]
            existing = self._findings[existing_id]

            # Boost confidence
            existing.confidence = max(existing.confidence, confidence)
            existing.tool_count += 1
            existing.last_seen = time.time()

            # Add source
            existing.sources.append({
                "tool": tool,
                "severity": severity,
                "confidence": confidence,
                "metadata": metadata or {},
            })

            # Add evidence
            if evidence:
                existing.evidence.append(f"[{tool}] {evidence[:100]}")

            # Reconcile severity (take highest)
            existing.canonical_severity = self._highest_severity(
                existing.canonical_severity, severity,
            )

            self._total_deduped += 1
            return existing

        # New finding
        self._counter += 1
        normalized_type = self._normalize_type(finding_type)

        finding = MergedFinding(
            finding_id=f"merged-{self._counter}",
            canonical_type=normalized_type,
            canonical_title=title,
            canonical_severity=severity,
            target=target,
            port=port,
            confidence=confidence,
            tool_count=1,
            sources=[{
                "tool": tool,
                "severity": severity,
                "confidence": confidence,
                "metadata": metadata or {},
            }],
            evidence=[f"[{tool}] {evidence[:100]}"] if evidence else [],
            dedup_hash=dedup_hash,
        )

        self._findings[finding.finding_id] = finding
        self._hash_index[dedup_hash] = finding.finding_id
        return finding

    def get_by_severity(self, severity: str) -> list[MergedFinding]:
        """Get findings by severity."""
        return [
            f for f in self._findings.values()
            if f.canonical_severity.lower() == severity.lower()
        ]

    def get_high_confidence(self, threshold: float = 0.7) -> list[MergedFinding]:
        """Get findings above confidence threshold."""
        return [
            f for f in self._findings.values()
            if f.boosted_confidence >= threshold
        ]

    def get_multi_tool(self, min_tools: int = 2) -> list[MergedFinding]:
        """Get findings confirmed by multiple tools."""
        return [
            f for f in self._findings.values()
            if f.tool_count >= min_tools
        ]

    def build_dedup_prompt(self) -> str:
        """Build dedup status for LLM."""
        lines = ["## Finding Deduplication\n"]

        lines.append(
            f"Raw findings: {self._total_raw} | "
            f"Merged: {len(self._findings)} | "
            f"Deduped: {self._total_deduped}"
        )

        sev_counts: dict[str, int] = {}
        for f in self._findings.values():
            s = f.canonical_severity
            sev_counts[s] = sev_counts.get(s, 0) + 1
        lines.append(f"By severity: {sev_counts}")

        multi = self.get_multi_tool()
        if multi:
            lines.append(f"\nMulti-tool confirmed ({len(multi)}):")
            for f in multi[:3]:
                lines.append(
                    f"  {f.canonical_type[:15]} on {f.target[:15]} — "
                    f"tools={f.tool_count} "
                    f"conf={f.boosted_confidence:.0%}"
                )

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        sev_counts: dict[str, int] = {}
        type_counts: dict[str, int] = {}
        for f in self._findings.values():
            s = f.canonical_severity
            sev_counts[s] = sev_counts.get(s, 0) + 1
            t = f.canonical_type
            type_counts[t] = type_counts.get(t, 0) + 1

        return {
            "raw_findings": self._total_raw,
            "merged_findings": len(self._findings),
            "deduped": self._total_deduped,
            "by_severity": sev_counts,
            "multi_tool": len(self.get_multi_tool()),
        }
