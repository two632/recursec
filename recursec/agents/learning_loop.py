"""Learning loop — continuous improvement from past assessments.

Implements:
1. Assessment result storage with indexing
2. Pattern extraction across findings
3. Correlation discovery (what tools find what)
4. Strategy refinement based on outcomes
5. Knowledge base enrichment from new findings
6. Target profile learning (similar targets → similar vulns)
7. Learning prompt for LLM context
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class PatternType(str, Enum):
    VULN_CORRELATION = "vuln_correlation"       # Vuln A often found with Vuln B
    TOOL_EFFECTIVENESS = "tool_effectiveness"    # Tool X best for finding Y
    TARGET_PROFILE = "target_profile"            # Target type → likely vulns
    STRATEGY_OUTCOME = "strategy_outcome"        # Strategy → success rate
    FALSE_POSITIVE = "false_positive"            # Common false positive patterns
    CHAIN_PATTERN = "chain_pattern"              # Exploitation chain patterns


@dataclass
class AssessmentRecord:
    """Record of a completed assessment."""
    record_id: str = ""
    target: str = ""
    target_type: str = ""        # e.g., web_app, network, cloud
    findings: list[dict[str, Any]] = field(default_factory=list)
    tools_used: list[str] = field(default_factory=list)
    models_used: list[str] = field(default_factory=list)
    strategies: list[str] = field(default_factory=list)
    duration_s: float = 0.0
    tokens_used: int = 0
    success_rate: float = 0.0
    false_positives: int = 0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.record_id[:10],
            "target": self.target[:15],
            "findings": len(self.findings),
            "tools": len(self.tools_used),
            "duration": f"{self.duration_s:.0f}s",
        }


@dataclass
class LearnedPattern:
    """A pattern learned from assessment history."""
    pattern_id: str = ""
    pattern_type: PatternType = PatternType.VULN_CORRELATION
    description: str = ""
    confidence: float = 0.5
    evidence_count: int = 0
    data: dict[str, Any] = field(default_factory=dict)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id[:10],
            "type": self.pattern_type.value[:12],
            "conf": round(self.confidence, 2),
            "evidence": self.evidence_count,
        }


class LearningLoop:
    """Continuous learning from assessment results.

    Stores results, extracts patterns, correlates findings,
    and provides recommendations for future assessments.
    """

    def __init__(self, max_records: int = 500) -> None:
        self._records: list[AssessmentRecord] = []
        self._patterns: dict[str, LearnedPattern] = {}
        self._max_records = max_records
        self._counter = 0
        self._log = logger.bind(component="learning_loop")

    def record_assessment(
        self,
        target: str,
        target_type: str,
        findings: list[dict[str, Any]],
        tools_used: list[str] | None = None,
        models_used: list[str] | None = None,
        strategies: list[str] | None = None,
        duration_s: float = 0.0,
        tokens_used: int = 0,
        false_positives: int = 0,
    ) -> AssessmentRecord:
        """Record a completed assessment."""
        self._counter += 1
        total = len(findings)
        success_rate = (total - false_positives) / total if total else 0.0

        record = AssessmentRecord(
            record_id=f"assess-{self._counter}",
            target=target,
            target_type=target_type,
            findings=findings,
            tools_used=tools_used or [],
            models_used=models_used or [],
            strategies=strategies or [],
            duration_s=duration_s,
            tokens_used=tokens_used,
            success_rate=success_rate,
            false_positives=false_positives,
        )

        self._records.append(record)

        # Evict old records
        while len(self._records) > self._max_records:
            self._records.pop(0)

        # Extract patterns from this assessment
        self._extract_patterns(record)

        return record

    def _extract_patterns(self, record: AssessmentRecord) -> None:
        """Extract patterns from a new assessment record."""
        # Tool effectiveness
        self._learn_tool_effectiveness(record)

        # Target profile
        self._learn_target_profile(record)

        # Vulnerability correlations
        self._learn_vuln_correlations(record)

    def _learn_tool_effectiveness(self, record: AssessmentRecord) -> None:
        """Learn which tools are effective for which finding types."""
        for tool in record.tools_used:
            pattern_id = f"tool-eff-{tool}"
            if pattern_id not in self._patterns:
                self._patterns[pattern_id] = LearnedPattern(
                    pattern_id=pattern_id,
                    pattern_type=PatternType.TOOL_EFFECTIVENESS,
                    description=f"Tool {tool} effectiveness",
                    data={"tool": tool, "finding_types": {}, "total_findings": 0},
                )
            pattern = self._patterns[pattern_id]
            pattern.evidence_count += 1
            pattern.last_seen = time.time()

            # Count findings by type
            for finding in record.findings:
                ftype = finding.get("type", "unknown")
                types = pattern.data.get("finding_types", {})
                types[ftype] = types.get(ftype, 0) + 1
                pattern.data["finding_types"] = types

            total = pattern.data.get("total_findings", 0)
            pattern.data["total_findings"] = total + len(record.findings)
            pattern.confidence = min(1.0, pattern.evidence_count / 10)

    def _learn_target_profile(self, record: AssessmentRecord) -> None:
        """Learn typical vulnerabilities for target types."""
        pattern_id = f"target-{record.target_type}"
        if pattern_id not in self._patterns:
            self._patterns[pattern_id] = LearnedPattern(
                pattern_id=pattern_id,
                pattern_type=PatternType.TARGET_PROFILE,
                description=f"Profile for {record.target_type}",
                data={"target_type": record.target_type, "vuln_types": {}, "count": 0},
            )
        pattern = self._patterns[pattern_id]
        pattern.evidence_count += 1
        pattern.last_seen = time.time()
        pattern.data["count"] = pattern.data.get("count", 0) + 1

        for finding in record.findings:
            ftype = finding.get("type", "unknown")
            vtypes = pattern.data.get("vuln_types", {})
            vtypes[ftype] = vtypes.get(ftype, 0) + 1
            pattern.data["vuln_types"] = vtypes

        pattern.confidence = min(1.0, pattern.evidence_count / 5)

    def _learn_vuln_correlations(self, record: AssessmentRecord) -> None:
        """Learn correlations between vulnerability types."""
        finding_types = list({f.get("type", "unknown") for f in record.findings})

        for i in range(len(finding_types)):
            for j in range(i + 1, len(finding_types)):
                pair = tuple(sorted([finding_types[i], finding_types[j]]))
                pattern_id = f"corr-{pair[0]}-{pair[1]}"

                if pattern_id not in self._patterns:
                    self._patterns[pattern_id] = LearnedPattern(
                        pattern_id=pattern_id,
                        pattern_type=PatternType.VULN_CORRELATION,
                        description=f"{pair[0]} correlates with {pair[1]}",
                        data={"vuln_a": pair[0], "vuln_b": pair[1]},
                    )
                pattern = self._patterns[pattern_id]
                pattern.evidence_count += 1
                pattern.last_seen = time.time()
                pattern.confidence = min(1.0, pattern.evidence_count / 5)

    def get_recommendations(
        self,
        target_type: str,
    ) -> dict[str, Any]:
        """Get recommendations based on learned patterns."""
        # Likely vulnerabilities for this target type
        profile_id = f"target-{target_type}"
        likely_vulns: dict[str, int] = {}
        if profile_id in self._patterns:
            likely_vulns = self._patterns[profile_id].data.get("vuln_types", {})

        # Best tools
        best_tools: list[dict[str, Any]] = []
        for pattern in self._patterns.values():
            if pattern.pattern_type != PatternType.TOOL_EFFECTIVENESS:
                continue
            total = pattern.data.get("total_findings", 0)
            if total > 0:
                best_tools.append({
                    "tool": pattern.data.get("tool", ""),
                    "findings": total,
                    "confidence": pattern.confidence,
                })
        best_tools.sort(key=lambda x: x["findings"], reverse=True)

        # Correlated vulns
        correlations: list[dict[str, Any]] = []
        for pattern in self._patterns.values():
            if pattern.pattern_type != PatternType.VULN_CORRELATION:
                continue
            if pattern.confidence >= 0.5:
                correlations.append({
                    "a": pattern.data.get("vuln_a", ""),
                    "b": pattern.data.get("vuln_b", ""),
                    "confidence": pattern.confidence,
                })

        return {
            "likely_vulns": likely_vulns,
            "best_tools": best_tools[:5],
            "correlations": correlations[:5],
        }

    def build_learning_prompt(self, target_type: str = "") -> str:
        """Build learning context for LLM."""
        lines = ["## Learning Data\n"]

        lines.append(
            f"Assessments: {len(self._records)} | "
            f"Patterns: {len(self._patterns)}"
        )

        if target_type:
            recs = self.get_recommendations(target_type)
            if recs["likely_vulns"]:
                sorted_vulns = sorted(
                    recs["likely_vulns"].items(),
                    key=lambda x: x[1],
                    reverse=True,
                )
                lines.append(f"\nLikely vulns for {target_type}:")
                for vtype, count in sorted_vulns[:5]:
                    lines.append(f"  {vtype}: {count} occurrences")

            if recs["best_tools"]:
                lines.append("\nBest tools:")
                for t in recs["best_tools"][:3]:
                    lines.append(
                        f"  {t['tool'][:12]}: {t['findings']} findings "
                        f"(conf={t['confidence']:.0%})"
                    )

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        pattern_types: dict[str, int] = {}
        for p in self._patterns.values():
            pt = p.pattern_type.value
            pattern_types[pt] = pattern_types.get(pt, 0) + 1

        return {
            "total_records": len(self._records),
            "total_patterns": len(self._patterns),
            "by_pattern_type": pattern_types,
            "total_findings": sum(len(r.findings) for r in self._records),
        }
