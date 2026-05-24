"""Experience replay — learning from past assessments.

Implements:
1. Assessment outcome storage
2. Strategy effectiveness tracking
3. Tool-vulnerability correlation learning
4. Target profile building
5. Adaptive strategy selection
6. Experience prompt for LLM
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class AssessmentOutcome:
    """Stored outcome of a past assessment."""
    outcome_id: str = ""
    target_type: str = ""          # web, network, cloud, etc.
    target_technologies: list[str] = field(default_factory=list)
    assessment_type: str = ""
    strategies_used: list[str] = field(default_factory=list)
    tools_used: list[str] = field(default_factory=list)
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    total_findings: int = 0
    success_rating: float = 0.0    # 0-1
    duration_s: float = 0.0
    tokens_used: int = 0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.outcome_id[:10],
            "type": self.target_type[:8],
            "findings": self.total_findings,
            "success": f"{self.success_rating:.0%}",
        }


@dataclass
class ToolEffectiveness:
    """Tracked effectiveness of a tool."""
    tool_name: str = ""
    total_uses: int = 0
    findings_produced: int = 0
    avg_severity: float = 0.0       # 0=info, 4=critical
    false_positive_rate: float = 0.0
    avg_runtime_s: float = 0.0
    best_against: list[str] = field(default_factory=list)

    @property
    def effectiveness_score(self) -> float:
        if self.total_uses == 0:
            return 0.0
        base = self.findings_produced / self.total_uses
        severity_bonus = self.avg_severity / 4.0
        fp_penalty = self.false_positive_rate
        return max(0, (base + severity_bonus) * (1 - fp_penalty))

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool_name[:12],
            "uses": self.total_uses,
            "findings": self.findings_produced,
            "score": f"{self.effectiveness_score:.2f}",
        }


@dataclass
class VulnCorrelation:
    """Correlation between target characteristics and vulnerabilities."""
    technology: str = ""
    vuln_types: dict[str, int] = field(default_factory=dict)
    total_findings: int = 0

    @property
    def top_vulns(self) -> list[tuple[str, int]]:
        return sorted(self.vuln_types.items(), key=lambda x: x[1], reverse=True)[:5]

    def to_dict(self) -> dict[str, Any]:
        return {
            "tech": self.technology[:12],
            "findings": self.total_findings,
            "top": [v[0] for v in self.top_vulns[:3]],
        }


class ExperienceReplay:
    """Learns from past assessments to improve future ones.

    Stores assessment outcomes, tracks tool effectiveness,
    builds target profiles, and provides data-driven
    strategy recommendations.
    """

    def __init__(self, max_outcomes: int = 500) -> None:
        self._outcomes: list[AssessmentOutcome] = []
        self._max_outcomes = max_outcomes
        self._tool_stats: dict[str, ToolEffectiveness] = {}
        self._correlations: dict[str, VulnCorrelation] = {}
        self._strategy_success: dict[str, list[float]] = defaultdict(list)
        self._outcome_counter = 0
        self._log = logger.bind(component="experience_replay")

    def record_outcome(
        self,
        target_type: str,
        target_technologies: list[str] | None = None,
        assessment_type: str = "",
        strategies_used: list[str] | None = None,
        tools_used: list[str] | None = None,
        findings_by_severity: dict[str, int] | None = None,
        success_rating: float = 0.0,
        duration_s: float = 0.0,
        tokens_used: int = 0,
    ) -> AssessmentOutcome:
        """Record an assessment outcome."""
        self._outcome_counter += 1

        outcome = AssessmentOutcome(
            outcome_id=f"exp-{self._outcome_counter}",
            target_type=target_type,
            target_technologies=target_technologies or [],
            assessment_type=assessment_type,
            strategies_used=strategies_used or [],
            tools_used=tools_used or [],
            findings_by_severity=findings_by_severity or {},
            total_findings=sum((findings_by_severity or {}).values()),
            success_rating=success_rating,
            duration_s=duration_s,
            tokens_used=tokens_used,
        )

        self._outcomes.append(outcome)

        # Trim old
        while len(self._outcomes) > self._max_outcomes:
            self._outcomes.pop(0)

        # Update tool stats
        self._update_tool_stats(outcome)

        # Update correlations
        self._update_correlations(outcome)

        # Update strategy tracking
        for strategy in outcome.strategies_used:
            self._strategy_success[strategy].append(success_rating)

        return outcome

    def _update_tool_stats(self, outcome: AssessmentOutcome) -> None:
        """Update tool effectiveness from outcome."""
        findings_per_tool = outcome.total_findings / max(1, len(outcome.tools_used))

        for tool in outcome.tools_used:
            if tool not in self._tool_stats:
                self._tool_stats[tool] = ToolEffectiveness(tool_name=tool)

            stats = self._tool_stats[tool]
            stats.total_uses += 1
            stats.findings_produced += int(findings_per_tool)

            # Track what types of targets this tool works against
            if outcome.success_rating > 0.6 and outcome.target_type not in stats.best_against:
                stats.best_against.append(outcome.target_type)

    def _update_correlations(self, outcome: AssessmentOutcome) -> None:
        """Update vulnerability correlations."""
        for tech in outcome.target_technologies:
            if tech not in self._correlations:
                self._correlations[tech] = VulnCorrelation(technology=tech)

            corr = self._correlations[tech]
            corr.total_findings += outcome.total_findings

    def recommend_tools(
        self,
        target_type: str = "",
        technologies: list[str] | None = None,
        top_n: int = 5,
    ) -> list[str]:
        """Recommend tools based on past effectiveness."""
        scored: list[tuple[float, str]] = []

        for name, stats in self._tool_stats.items():
            score = stats.effectiveness_score

            # Bonus if tool works well against this target type
            if target_type and target_type in stats.best_against:
                score *= 1.5

            scored.append((score, name))

        scored.sort(reverse=True)
        return [name for _, name in scored[:top_n]]

    def recommend_strategies(
        self,
        target_type: str = "",
        top_n: int = 3,
    ) -> list[tuple[str, float]]:
        """Recommend strategies based on past success rates."""
        strategy_scores: list[tuple[float, str]] = []

        for strategy, ratings in self._strategy_success.items():
            if not ratings:
                continue
            avg = sum(ratings) / len(ratings)
            strategy_scores.append((avg, strategy))

        strategy_scores.sort(reverse=True)
        return [(name, score) for score, name in strategy_scores[:top_n]]

    def get_target_profile(
        self,
        target_type: str = "",
        technologies: list[str] | None = None,
    ) -> dict[str, Any]:
        """Build a target profile from past experience."""
        relevant = [
            o for o in self._outcomes
            if (not target_type or o.target_type == target_type)
        ]

        if not relevant:
            return {"known": False}

        avg_findings = sum(o.total_findings for o in relevant) / len(relevant)
        avg_success = sum(o.success_rating for o in relevant) / len(relevant)
        common_tools = self.recommend_tools(target_type, technologies)

        return {
            "known": True,
            "past_assessments": len(relevant),
            "avg_findings": round(avg_findings, 1),
            "avg_success": round(avg_success, 2),
            "recommended_tools": common_tools[:5],
        }

    def build_experience_prompt(self, target_type: str = "") -> str:
        """Build experience context for LLM."""
        lines = ["## Experience Replay\n"]
        lines.append(f"Past assessments: {len(self._outcomes)}")
        lines.append(f"Tools tracked: {len(self._tool_stats)}")
        lines.append(f"Correlations: {len(self._correlations)}")

        # Top tools
        if self._tool_stats:
            sorted_tools = sorted(
                self._tool_stats.values(),
                key=lambda t: t.effectiveness_score,
                reverse=True,
            )
            lines.append("\nTop tools:")
            for t in sorted_tools[:5]:
                lines.append(
                    f"  {t.tool_name[:12]} — "
                    f"score={t.effectiveness_score:.2f} "
                    f"uses={t.total_uses}"
                )

        # Top strategies
        recs = self.recommend_strategies(target_type)
        if recs:
            lines.append("\nTop strategies:")
            for name, score in recs:
                lines.append(f"  {name[:20]} — success={score:.0%}")

        # Target profile
        if target_type:
            profile = self.get_target_profile(target_type)
            if profile.get("known"):
                lines.append(f"\n{target_type} profile:")
                lines.append(f"  Past: {profile['past_assessments']} assessments")
                lines.append(f"  Avg findings: {profile['avg_findings']}")
                lines.append(f"  Avg success: {profile['avg_success']:.0%}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_outcomes": len(self._outcomes),
            "tools_tracked": len(self._tool_stats),
            "correlations": len(self._correlations),
            "strategies": len(self._strategy_success),
        }
