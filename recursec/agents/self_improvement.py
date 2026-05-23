"""Self-improvement engine — agent learns from past assessments.

Implements:
1. Strategy effectiveness tracking (which approaches work for which targets)
2. Tool success rate monitoring
3. Model performance comparison per task type
4. Automatic strategy recommendation based on history
5. Pattern recognition across assessments
6. Feedback loop from validation results
7. Self-improvement prompt for LLM context
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class OutcomeType(str, Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILURE = "failure"
    FALSE_POSITIVE = "false_positive"
    TIMEOUT = "timeout"


class TaskCategory(str, Enum):
    RECON = "recon"
    VULN_SCAN = "vuln_scan"
    WEB_AUDIT = "web_audit"
    CODE_AUDIT = "code_audit"
    EXPLOIT = "exploit"
    PRIVESC = "privesc"
    LATERAL = "lateral"
    CLOUD = "cloud"
    MOBILE = "mobile"
    NETWORK = "network"


@dataclass
class StrategyRecord:
    """Record of a strategy execution."""
    record_id: str = ""
    strategy: str = ""            # Strategy name/approach
    task_category: TaskCategory = TaskCategory.RECON
    target_type: str = ""         # e.g., "web_app", "network", "cloud"
    tools_used: list[str] = field(default_factory=list)
    model_used: str = ""
    outcome: OutcomeType = OutcomeType.FAILURE
    findings_count: int = 0
    time_taken_s: float = 0.0
    tokens_used: int = 0
    confidence: float = 0.0
    notes: str = ""
    timestamp: float = field(default_factory=time.time)

    @property
    def efficiency(self) -> float:
        """Findings per 1000 tokens."""
        if self.tokens_used == 0:
            return 0.0
        return (self.findings_count / self.tokens_used) * 1000

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.record_id[:10],
            "strategy": self.strategy[:15],
            "outcome": self.outcome.value[:6],
            "findings": self.findings_count,
            "efficiency": round(self.efficiency, 2),
        }


@dataclass
class ToolPerformance:
    """Tracked performance of a tool."""
    tool_name: str = ""
    runs: int = 0
    successes: int = 0
    failures: int = 0
    findings_total: int = 0
    avg_time_s: float = 0.0
    false_positives: int = 0

    @property
    def success_rate(self) -> float:
        if self.runs == 0:
            return 0.0
        return self.successes / self.runs

    @property
    def precision(self) -> float:
        total = self.findings_total
        if total == 0:
            return 1.0
        return (total - self.false_positives) / total

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool_name[:12],
            "runs": self.runs,
            "success": f"{self.success_rate:.0%}",
            "findings": self.findings_total,
        }


@dataclass
class ModelPerformance:
    """Tracked performance of a model."""
    model_id: str = ""
    task_counts: dict[str, int] = field(default_factory=dict)
    task_success: dict[str, int] = field(default_factory=dict)
    total_tokens: int = 0
    avg_confidence: float = 0.0

    def success_rate_for(self, task: str) -> float:
        total = self.task_counts.get(task, 0)
        if total == 0:
            return 0.0
        return self.task_success.get(task, 0) / total

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model_id[:15],
            "tasks": sum(self.task_counts.values()),
            "tokens": self.total_tokens,
        }


class SelfImprovementEngine:
    """Learns from past assessments to improve future ones.

    Tracks strategy effectiveness, tool success rates,
    and model performance. Recommends strategies based
    on historical data.
    """

    def __init__(self) -> None:
        self._records: list[StrategyRecord] = []
        self._tool_perf: dict[str, ToolPerformance] = {}
        self._model_perf: dict[str, ModelPerformance] = {}
        self._counter = 0
        self._log = logger.bind(component="self_improvement")

    def record_strategy(
        self,
        strategy: str,
        task_category: TaskCategory,
        target_type: str,
        outcome: OutcomeType,
        tools_used: list[str] | None = None,
        model_used: str = "",
        findings_count: int = 0,
        time_taken_s: float = 0.0,
        tokens_used: int = 0,
        confidence: float = 0.0,
        notes: str = "",
    ) -> StrategyRecord:
        """Record a strategy execution result."""
        self._counter += 1
        record = StrategyRecord(
            record_id=f"rec-{self._counter}",
            strategy=strategy,
            task_category=task_category,
            target_type=target_type,
            tools_used=tools_used or [],
            model_used=model_used,
            outcome=outcome,
            findings_count=findings_count,
            time_taken_s=time_taken_s,
            tokens_used=tokens_used,
            confidence=confidence,
            notes=notes,
        )
        self._records.append(record)

        # Update tool performance
        for tool in record.tools_used:
            self._update_tool_perf(tool, record)

        # Update model performance
        if model_used:
            self._update_model_perf(model_used, record)

        return record

    def recommend_strategy(
        self,
        task_category: TaskCategory,
        target_type: str = "",
        top_n: int = 3,
    ) -> list[dict[str, Any]]:
        """Recommend strategies based on history."""
        # Filter records
        relevant = [
            r for r in self._records
            if r.task_category == task_category
        ]
        if target_type:
            type_match = [r for r in relevant if r.target_type == target_type]
            if type_match:
                relevant = type_match

        if not relevant:
            return [{"strategy": "default", "reason": "no_history"}]

        # Score strategies
        strategy_scores: dict[str, dict[str, float]] = {}
        for r in relevant:
            if r.strategy not in strategy_scores:
                strategy_scores[r.strategy] = {
                    "success": 0, "total": 0,
                    "findings": 0, "efficiency": 0,
                }
            scores = strategy_scores[r.strategy]
            scores["total"] += 1
            if r.outcome in (OutcomeType.SUCCESS, OutcomeType.PARTIAL):
                scores["success"] += 1
            scores["findings"] += r.findings_count
            scores["efficiency"] += r.efficiency

        # Rank
        ranked: list[dict[str, Any]] = []
        for strat, scores in strategy_scores.items():
            if scores["total"] == 0:
                continue
            success_rate = scores["success"] / scores["total"]
            avg_findings = scores["findings"] / scores["total"]
            composite = success_rate * 0.4 + min(avg_findings / 10, 1.0) * 0.3 + min(scores["efficiency"] / scores["total"], 1.0) * 0.3

            ranked.append({
                "strategy": strat,
                "score": round(composite, 3),
                "success_rate": round(success_rate, 2),
                "avg_findings": round(avg_findings, 1),
                "sample_size": int(scores["total"]),
            })

        ranked.sort(key=lambda x: x["score"], reverse=True)
        return ranked[:top_n]

    def recommend_tool(
        self,
        task_category: TaskCategory,
        top_n: int = 3,
    ) -> list[dict[str, Any]]:
        """Recommend tools for a task category."""
        # Find tools used in this category
        tool_scores: dict[str, dict[str, float]] = {}
        for r in self._records:
            if r.task_category != task_category:
                continue
            for tool in r.tools_used:
                if tool not in tool_scores:
                    tool_scores[tool] = {"use": 0, "success": 0, "findings": 0}
                tool_scores[tool]["use"] += 1
                if r.outcome in (OutcomeType.SUCCESS, OutcomeType.PARTIAL):
                    tool_scores[tool]["success"] += 1
                tool_scores[tool]["findings"] += r.findings_count

        ranked: list[dict[str, Any]] = []
        for tool, scores in tool_scores.items():
            if scores["use"] == 0:
                continue
            ranked.append({
                "tool": tool,
                "uses": int(scores["use"]),
                "success_rate": round(scores["success"] / scores["use"], 2),
                "findings": int(scores["findings"]),
            })

        ranked.sort(key=lambda x: x["success_rate"], reverse=True)
        return ranked[:top_n]

    def recommend_model(
        self,
        task_category: TaskCategory,
    ) -> str:
        """Recommend best model for a task category."""
        best_model = ""
        best_rate = 0.0
        task = task_category.value

        for model_id, perf in self._model_perf.items():
            rate = perf.success_rate_for(task)
            if rate > best_rate:
                best_rate = rate
                best_model = model_id

        return best_model

    def build_improvement_prompt(self) -> str:
        """Build self-improvement context for LLM."""
        lines = ["## Self-Improvement Data\n"]

        lines.append(f"Strategy records: {len(self._records)}")

        # Overall success rates
        if self._records:
            successes = sum(
                1 for r in self._records
                if r.outcome in (OutcomeType.SUCCESS, OutcomeType.PARTIAL)
            )
            lines.append(f"Overall success rate: {successes / len(self._records):.0%}")

        # Top tools
        if self._tool_perf:
            lines.append("\nTop tools:")
            sorted_tools = sorted(
                self._tool_perf.values(),
                key=lambda t: t.success_rate,
                reverse=True,
            )
            for tp in sorted_tools[:5]:
                lines.append(
                    f"  {tp.tool_name[:12]}: {tp.success_rate:.0%} success, "
                    f"{tp.findings_total} findings"
                )

        # Top models per category
        if self._model_perf:
            lines.append("\nModel performance:")
            for model_id, perf in self._model_perf.items():
                tasks = sum(perf.task_counts.values())
                lines.append(f"  {model_id[:12]}: {tasks} tasks, avg_conf={perf.avg_confidence:.2f}")

        return "\n".join(lines)

    def _update_tool_perf(self, tool: str, record: StrategyRecord) -> None:
        """Update tool performance tracking."""
        if tool not in self._tool_perf:
            self._tool_perf[tool] = ToolPerformance(tool_name=tool)
        tp = self._tool_perf[tool]
        tp.runs += 1
        if record.outcome in (OutcomeType.SUCCESS, OutcomeType.PARTIAL):
            tp.successes += 1
        elif record.outcome == OutcomeType.FAILURE:
            tp.failures += 1
        elif record.outcome == OutcomeType.FALSE_POSITIVE:
            tp.false_positives += 1
        tp.findings_total += record.findings_count
        tp.avg_time_s = (
            (tp.avg_time_s * (tp.runs - 1) + record.time_taken_s)
            / tp.runs
        )

    def _update_model_perf(self, model_id: str, record: StrategyRecord) -> None:
        """Update model performance tracking."""
        if model_id not in self._model_perf:
            self._model_perf[model_id] = ModelPerformance(model_id=model_id)
        mp = self._model_perf[model_id]
        task = record.task_category.value
        mp.task_counts[task] = mp.task_counts.get(task, 0) + 1
        if record.outcome in (OutcomeType.SUCCESS, OutcomeType.PARTIAL):
            mp.task_success[task] = mp.task_success.get(task, 0) + 1
        mp.total_tokens += record.tokens_used
        total_tasks = sum(mp.task_counts.values())
        mp.avg_confidence = (
            (mp.avg_confidence * (total_tasks - 1) + record.confidence)
            / total_tasks
        )

    def get_stats(self) -> dict[str, Any]:
        outcomes: dict[str, int] = {}
        for r in self._records:
            outcomes[r.outcome.value] = outcomes.get(r.outcome.value, 0) + 1

        return {
            "total_records": len(self._records),
            "outcomes": outcomes,
            "tools_tracked": len(self._tool_perf),
            "models_tracked": len(self._model_perf),
        }
