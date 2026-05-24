"""Experience replay — learning from past operations.

Stores, indexes, and replays past task executions to
improve future performance:
1. Episode storage — full execution traces with outcomes
2. Pattern extraction — identify successful strategies
3. Failure analysis — learn from errors and dead ends
4. Strategy ranking — score approaches by effectiveness
5. Prompt enrichment — inject relevant past experience into LLM context
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class EpisodeOutcome(str, Enum):
    SUCCESS = "success"
    PARTIAL_SUCCESS = "partial_success"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    ERROR = "error"
    BLOCKED = "blocked"


class ActionType(str, Enum):
    TOOL_EXECUTION = "tool_execution"
    LLM_REASONING = "llm_reasoning"
    AGENT_SPAWN = "agent_spawn"
    KB_LOOKUP = "kb_lookup"
    STRATEGY_CHANGE = "strategy_change"
    FINDING_REPORT = "finding_report"
    VALIDATION = "validation"
    ESCALATION = "escalation"


@dataclass
class ActionRecord:
    """A single action within an episode."""
    action_id: str = ""
    action_type: ActionType = ActionType.TOOL_EXECUTION
    description: str = ""
    tool_name: str = ""
    input_summary: str = ""
    output_summary: str = ""
    duration_s: float = 0.0
    tokens_used: int = 0
    success: bool = True
    error_message: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.action_type.value[:8],
            "tool": self.tool_name[:10],
            "ok": self.success,
            "dur": f"{self.duration_s:.1f}s",
        }


@dataclass
class Episode:
    """A complete task execution episode."""
    episode_id: str = ""
    task_description: str = ""
    task_intent: str = ""
    target: str = ""
    actions: list[ActionRecord] = field(default_factory=list)
    outcome: EpisodeOutcome = EpisodeOutcome.SUCCESS
    findings_count: int = 0
    critical_findings: int = 0
    total_duration_s: float = 0.0
    total_tokens: int = 0
    kbs_used: list[str] = field(default_factory=list)
    models_used: list[str] = field(default_factory=list)
    tools_used: list[str] = field(default_factory=list)
    strategies_used: list[str] = field(default_factory=list)
    error_messages: list[str] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    completed_at: float = 0.0

    @property
    def success_rate(self) -> float:
        if not self.actions:
            return 0.0
        ok = sum(1 for a in self.actions if a.success)
        return ok / len(self.actions)

    @property
    def efficiency(self) -> float:
        if self.total_duration_s <= 0 or self.findings_count <= 0:
            return 0.0
        return self.findings_count / self.total_duration_s

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.episode_id[:8],
            "intent": self.task_intent[:12],
            "outcome": self.outcome.value[:8],
            "actions": len(self.actions),
            "findings": self.findings_count,
            "success_rate": f"{self.success_rate:.2f}",
        }


@dataclass
class StrategyScore:
    """Score for a particular strategy approach."""
    strategy_name: str = ""
    intent: str = ""
    uses: int = 0
    successes: int = 0
    failures: int = 0
    avg_findings: float = 0.0
    avg_duration_s: float = 0.0
    avg_tokens: float = 0.0

    @property
    def success_rate(self) -> float:
        if self.uses == 0:
            return 0.0
        return self.successes / self.uses

    @property
    def score(self) -> float:
        return (
            self.success_rate * 0.4
            + min(self.avg_findings / 10.0, 1.0) * 0.3
            + (1.0 - min(self.avg_duration_s / 600.0, 1.0)) * 0.15
            + (1.0 - min(self.avg_tokens / 50000.0, 1.0)) * 0.15
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy": self.strategy_name[:15],
            "uses": self.uses,
            "success": f"{self.success_rate:.2f}",
            "score": f"{self.score:.2f}",
        }


@dataclass
class PatternInsight:
    """An insight extracted from episode patterns."""
    insight_id: str = ""
    insight_type: str = ""
    description: str = ""
    confidence: float = 0.0
    supporting_episodes: int = 0
    recommendation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.insight_type[:10],
            "conf": f"{self.confidence:.2f}",
            "episodes": self.supporting_episodes,
        }


class ExperienceReplay:
    """Experience replay memory system.

    Stores past episodes and extracts patterns
    to improve future performance.
    """

    def __init__(self, max_episodes: int = 1000) -> None:
        self._episodes: list[Episode] = []
        self._max_episodes = max_episodes
        self._strategy_scores: dict[str, StrategyScore] = {}
        self._insights: list[PatternInsight] = []
        self._episode_counter = 0
        self._insight_counter = 0
        self._log = logger.bind(component="experience_replay")

    def store_episode(self, episode: Episode) -> None:
        """Store a completed episode."""
        self._episodes.append(episode)
        if len(self._episodes) > self._max_episodes:
            self._episodes = self._episodes[-self._max_episodes // 2:]

        # Update strategy scores
        for strategy in episode.strategies_used:
            key = f"{episode.task_intent}:{strategy}"
            score = self._strategy_scores.get(key)
            if not score:
                score = StrategyScore(
                    strategy_name=strategy,
                    intent=episode.task_intent,
                )
                self._strategy_scores[key] = score

            score.uses += 1
            if episode.outcome in (
                EpisodeOutcome.SUCCESS, EpisodeOutcome.PARTIAL_SUCCESS,
            ):
                score.successes += 1
            else:
                score.failures += 1

            # Running averages
            n = score.uses
            score.avg_findings = (
                score.avg_findings * (n - 1) + episode.findings_count
            ) / n
            score.avg_duration_s = (
                score.avg_duration_s * (n - 1) + episode.total_duration_s
            ) / n
            score.avg_tokens = (
                score.avg_tokens * (n - 1) + episode.total_tokens
            ) / n

    def get_best_strategies(
        self,
        intent: str,
        top_n: int = 5,
    ) -> list[StrategyScore]:
        """Get the best-scoring strategies for an intent."""
        relevant = [
            s for s in self._strategy_scores.values()
            if s.intent == intent and s.uses >= 2
        ]
        return sorted(relevant, key=lambda s: s.score, reverse=True)[:top_n]

    def get_similar_episodes(
        self,
        intent: str,
        target: str = "",
        top_n: int = 5,
    ) -> list[Episode]:
        """Find episodes with similar intent and target."""
        scored: list[tuple[float, Episode]] = []
        for ep in self._episodes:
            sim = 0.0
            if ep.task_intent == intent:
                sim += 0.6
            if target and ep.target and target in ep.target:
                sim += 0.3
            if ep.outcome == EpisodeOutcome.SUCCESS:
                sim += 0.1
            scored.append((sim, ep))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [ep for _, ep in scored[:top_n] if scored[0][0] > 0.3]

    def extract_insights(self) -> list[PatternInsight]:
        """Extract pattern insights from episode history."""
        insights: list[PatternInsight] = []

        # Insight: Tool effectiveness
        tool_success: dict[str, list[bool]] = {}
        for ep in self._episodes:
            for action in ep.actions:
                if action.action_type == ActionType.TOOL_EXECUTION:
                    if action.tool_name not in tool_success:
                        tool_success[action.tool_name] = []
                    tool_success[action.tool_name].append(action.success)

        for tool, results in tool_success.items():
            if len(results) < 3:
                continue
            rate = sum(results) / len(results)
            if rate < 0.5:
                self._insight_counter += 1
                insights.append(PatternInsight(
                    insight_id=f"insight-{self._insight_counter}",
                    insight_type="tool_reliability",
                    description=f"{tool} has low success rate ({rate:.0%})",
                    confidence=min(len(results) / 10.0, 1.0),
                    supporting_episodes=len(results),
                    recommendation=f"Consider alternatives to {tool}",
                ))

        # Insight: Intent-outcome patterns
        intent_outcomes: dict[str, list[EpisodeOutcome]] = {}
        for ep in self._episodes:
            if ep.task_intent not in intent_outcomes:
                intent_outcomes[ep.task_intent] = []
            intent_outcomes[ep.task_intent].append(ep.outcome)

        for intent, outcomes in intent_outcomes.items():
            if len(outcomes) < 3:
                continue
            fail_count = sum(
                1 for o in outcomes
                if o in (EpisodeOutcome.FAILURE, EpisodeOutcome.ERROR)
            )
            fail_rate = fail_count / len(outcomes)
            if fail_rate > 0.5:
                self._insight_counter += 1
                insights.append(PatternInsight(
                    insight_id=f"insight-{self._insight_counter}",
                    insight_type="intent_difficulty",
                    description=f"{intent} tasks fail frequently ({fail_rate:.0%})",
                    confidence=min(len(outcomes) / 10.0, 1.0),
                    supporting_episodes=len(outcomes),
                    recommendation=f"Use ensemble mode for {intent} tasks",
                ))

        # Insight: KB effectiveness
        kb_findings: dict[str, list[int]] = {}
        for ep in self._episodes:
            for kb in ep.kbs_used:
                if kb not in kb_findings:
                    kb_findings[kb] = []
                kb_findings[kb].append(ep.findings_count)

        for kb, findings in kb_findings.items():
            if len(findings) < 3:
                continue
            avg = sum(findings) / len(findings)
            if avg > 5:
                self._insight_counter += 1
                insights.append(PatternInsight(
                    insight_id=f"insight-{self._insight_counter}",
                    insight_type="kb_effectiveness",
                    description=f"{kb} correlates with high finding count (avg={avg:.1f})",
                    confidence=min(len(findings) / 10.0, 1.0),
                    supporting_episodes=len(findings),
                    recommendation=f"Prioritize {kb} in prompt assembly",
                ))

        self._insights = insights
        return insights

    def build_experience_prompt(
        self,
        intent: str,
        target: str = "",
        max_tokens: int = 1000,
    ) -> str:
        """Build LLM prompt enriched with relevant experience."""
        lines = ["## Past Experience\n"]

        # Best strategies
        strategies = self.get_best_strategies(intent, top_n=3)
        if strategies:
            lines.append("### Best Strategies")
            for strat in strategies:
                lines.append(
                    f"  - {strat.strategy_name}: "
                    f"success={strat.success_rate:.0%}, "
                    f"avg_findings={strat.avg_findings:.1f}"
                )
            lines.append("")

        # Similar episodes
        similar = self.get_similar_episodes(intent, target, top_n=3)
        if similar:
            lines.append("### Similar Past Tasks")
            for ep in similar:
                lines.append(
                    f"  - {ep.task_description[:40]}: "
                    f"{ep.outcome.value}, "
                    f"findings={ep.findings_count}"
                )
                if ep.tools_used:
                    lines.append(f"    Tools: {', '.join(ep.tools_used[:5])}")
            lines.append("")

        # Insights
        relevant_insights = [
            ins for ins in self._insights
            if intent in ins.description.lower() or ins.confidence > 0.7
        ]
        if relevant_insights:
            lines.append("### Learned Insights")
            for ins in relevant_insights[:3]:
                lines.append(f"  - {ins.recommendation}")
            lines.append("")

        result = "\n".join(lines)
        # Rough token estimation: ~4 chars per token
        if len(result) > max_tokens * 4:
            result = result[:max_tokens * 4] + "\n..."
        return result

    def get_stats(self) -> dict[str, Any]:
        """Get experience replay statistics."""
        outcome_counts: dict[str, int] = {}
        for ep in self._episodes:
            key = ep.outcome.value
            outcome_counts[key] = outcome_counts.get(key, 0) + 1

        return {
            "total_episodes": len(self._episodes),
            "strategy_scores": len(self._strategy_scores),
            "insights": len(self._insights),
            "outcomes": outcome_counts,
        }
