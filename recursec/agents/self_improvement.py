"""Self-improvement engine — agent meta-learning.

Implements:
1. Performance tracking across sessions
2. Strategy effectiveness analysis
3. Model performance correlation
4. Tool combination discovery
5. Prompt optimization tracking
6. Weakness identification
7. Improvement suggestions
8. Configuration auto-tuning
"""

from __future__ import annotations

import json
import os
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ImprovementArea(str, Enum):
    STRATEGY_SELECTION = "strategy_selection"
    MODEL_ROUTING = "model_routing"
    TOOL_SELECTION = "tool_selection"
    PROMPT_QUALITY = "prompt_quality"
    COVERAGE = "coverage"
    FINDING_RATE = "finding_rate"
    TOKEN_EFFICIENCY = "token_efficiency"
    TIME_EFFICIENCY = "time_efficiency"


@dataclass
class PerformanceRecord:
    """A record of performance on a specific task."""
    record_id: str = ""
    session_id: str = ""
    target_type: str = ""
    strategy: str = ""
    model: str = ""
    tools_used: list[str] = field(default_factory=list)
    findings: int = 0
    tokens_used: int = 0
    duration_s: float = 0.0
    success: bool = True
    timestamp: float = field(default_factory=time.time)

    @property
    def efficiency(self) -> float:
        """Findings per 1000 tokens."""
        return (self.findings * 1000) / max(1, self.tokens_used)

    @property
    def speed(self) -> float:
        """Findings per minute."""
        return (self.findings * 60) / max(1, self.duration_s)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.record_id[:10],
            "target": self.target_type[:10],
            "strategy": self.strategy[:15],
            "findings": self.findings,
            "efficiency": round(self.efficiency, 2),
            "speed": round(self.speed, 2),
        }


@dataclass
class Improvement:
    """A suggested improvement."""
    area: ImprovementArea = ImprovementArea.STRATEGY_SELECTION
    description: str = ""
    priority: float = 0.5        # 0-1
    evidence: str = ""
    suggested_change: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "area": self.area.value,
            "desc": self.description[:40],
            "priority": round(self.priority, 2),
            "change": self.suggested_change[:50],
        }


@dataclass
class ToolCombination:
    """A discovered effective tool combination."""
    tools: tuple[str, ...] = ()
    target_type: str = ""
    avg_findings: float = 0.0
    use_count: int = 0
    score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "tools": list(self.tools)[:5],
            "target": self.target_type[:10],
            "avg_findings": round(self.avg_findings, 1),
            "uses": self.use_count,
            "score": round(self.score, 2),
        }


class SelfImprovementEngine:
    """Agent meta-learning and self-improvement.

    Analyzes past performance to identify weaknesses,
    discover effective strategies, and suggest configuration
    improvements.
    """

    def __init__(self, data_dir: str = "") -> None:
        self._records: list[PerformanceRecord] = []
        self._counter = 0
        self._data_dir = data_dir or os.path.expanduser("~/.recursec/performance")
        self._log = logger.bind(component="self_improvement")

        # Aggregated stats
        self._strategy_stats: dict[str, dict[str, float]] = defaultdict(
            lambda: {"findings": 0, "tokens": 0, "count": 0, "successes": 0}
        )
        self._model_stats: dict[str, dict[str, float]] = defaultdict(
            lambda: {"findings": 0, "tokens": 0, "count": 0, "successes": 0}
        )
        self._tool_stats: dict[str, dict[str, float]] = defaultdict(
            lambda: {"findings": 0, "count": 0, "successes": 0}
        )

    def record(
        self,
        session_id: str,
        target_type: str,
        strategy: str,
        model: str,
        tools_used: list[str],
        findings: int,
        tokens_used: int,
        duration_s: float,
        success: bool = True,
    ) -> PerformanceRecord:
        """Record a performance data point."""
        self._counter += 1
        record = PerformanceRecord(
            record_id=f"perf-{self._counter}",
            session_id=session_id,
            target_type=target_type,
            strategy=strategy,
            model=model,
            tools_used=tools_used,
            findings=findings,
            tokens_used=tokens_used,
            duration_s=duration_s,
            success=success,
        )
        self._records.append(record)

        # Update aggregated stats
        self._strategy_stats[strategy]["findings"] += findings
        self._strategy_stats[strategy]["tokens"] += tokens_used
        self._strategy_stats[strategy]["count"] += 1
        if success:
            self._strategy_stats[strategy]["successes"] += 1

        self._model_stats[model]["findings"] += findings
        self._model_stats[model]["tokens"] += tokens_used
        self._model_stats[model]["count"] += 1
        if success:
            self._model_stats[model]["successes"] += 1

        for tool in tools_used:
            self._tool_stats[tool]["findings"] += findings / max(1, len(tools_used))
            self._tool_stats[tool]["count"] += 1
            if success:
                self._tool_stats[tool]["successes"] += 1

        return record

    def analyze(self) -> list[Improvement]:
        """Analyze performance and generate improvements."""
        improvements = []

        # Strategy analysis
        strategy_improvements = self._analyze_strategies()
        improvements.extend(strategy_improvements)

        # Model analysis
        model_improvements = self._analyze_models()
        improvements.extend(model_improvements)

        # Tool combination discovery
        combo_improvements = self._analyze_tool_combinations()
        improvements.extend(combo_improvements)

        # Efficiency analysis
        efficiency_improvements = self._analyze_efficiency()
        improvements.extend(efficiency_improvements)

        # Sort by priority
        improvements.sort(key=lambda x: x.priority, reverse=True)
        return improvements

    def _analyze_strategies(self) -> list[Improvement]:
        """Analyze strategy effectiveness."""
        improvements = []

        best_strategy = ""
        best_efficiency = 0.0
        worst_strategy = ""
        worst_efficiency = float("inf")

        for strategy, stats in self._strategy_stats.items():
            if stats["count"] < 2:
                continue
            efficiency = stats["findings"] / max(1, stats["tokens"]) * 1000
            if efficiency > best_efficiency:
                best_efficiency = efficiency
                best_strategy = strategy
            if efficiency < worst_efficiency:
                worst_efficiency = efficiency
                worst_strategy = strategy

        if best_strategy and worst_strategy and best_strategy != worst_strategy:
            ratio = best_efficiency / max(0.001, worst_efficiency)
            if ratio > 2:
                improvements.append(Improvement(
                    area=ImprovementArea.STRATEGY_SELECTION,
                    description=f"Strategy '{best_strategy}' is {ratio:.1f}x more efficient than '{worst_strategy}'",
                    priority=min(1.0, 0.3 + ratio * 0.1),
                    evidence=f"Best: {best_efficiency:.2f} f/1Kt, Worst: {worst_efficiency:.2f} f/1Kt",
                    suggested_change=f"Prioritize '{best_strategy}' strategy",
                ))

        return improvements

    def _analyze_models(self) -> list[Improvement]:
        """Analyze model performance."""
        improvements = []

        model_efficiencies: dict[str, float] = {}
        for model, stats in self._model_stats.items():
            if stats["count"] < 2:
                continue
            model_efficiencies[model] = stats["findings"] / max(1, stats["tokens"]) * 1000

        if len(model_efficiencies) >= 2:
            sorted_models = sorted(model_efficiencies.items(), key=lambda x: x[1], reverse=True)
            best_model, best_eff = sorted_models[0]
            worst_model, worst_eff = sorted_models[-1]

            if best_eff > worst_eff * 2:
                improvements.append(Improvement(
                    area=ImprovementArea.MODEL_ROUTING,
                    description=f"Model '{best_model}' significantly outperforms '{worst_model}'",
                    priority=0.7,
                    evidence=f"Best: {best_eff:.2f}, Worst: {worst_eff:.2f}",
                    suggested_change=f"Increase weight for '{best_model}'",
                ))

        return improvements

    def _analyze_tool_combinations(self) -> list[Improvement]:
        """Discover effective tool combinations."""
        improvements = []

        # Find common tool pairs and their results
        combo_stats: dict[tuple[str, ...], dict[str, float]] = defaultdict(
            lambda: {"findings": 0, "count": 0}
        )

        for record in self._records:
            tools = sorted(record.tools_used)
            if len(tools) >= 2:
                for i in range(len(tools)):
                    for j in range(i + 1, len(tools)):
                        pair = (tools[i], tools[j])
                        combo_stats[pair]["findings"] += record.findings
                        combo_stats[pair]["count"] += 1

        best_combo = None
        best_avg = 0.0
        for combo, stats in combo_stats.items():
            if stats["count"] < 2:
                continue
            avg = stats["findings"] / stats["count"]
            if avg > best_avg:
                best_avg = avg
                best_combo = combo

        if best_combo:
            improvements.append(Improvement(
                area=ImprovementArea.TOOL_SELECTION,
                description=f"Tool combination {best_combo} averages {best_avg:.1f} findings",
                priority=0.5,
                evidence=f"Avg findings: {best_avg:.1f}, Uses: {combo_stats[best_combo]['count']}",
                suggested_change=f"Recommend {best_combo[0]} + {best_combo[1]} together",
            ))

        return improvements

    def _analyze_efficiency(self) -> list[Improvement]:
        """Analyze token and time efficiency."""
        improvements = []

        if len(self._records) < 5:
            return improvements

        # Check if efficiency is improving over time
        first_half = self._records[:len(self._records) // 2]
        second_half = self._records[len(self._records) // 2:]

        first_eff = sum(r.efficiency for r in first_half) / len(first_half)
        second_eff = sum(r.efficiency for r in second_half) / len(second_half)

        if second_eff < first_eff * 0.8:
            improvements.append(Improvement(
                area=ImprovementArea.TOKEN_EFFICIENCY,
                description="Token efficiency declining over time",
                priority=0.6,
                evidence=f"Early: {first_eff:.2f}, Recent: {second_eff:.2f}",
                suggested_change="Review prompt sizes, reduce context injection",
            ))

        return improvements

    def get_best_config(self, target_type: str) -> dict[str, Any]:
        """Get best configuration for a target type."""
        relevant = [r for r in self._records if r.target_type == target_type]
        if not relevant:
            return {}

        # Find best strategy
        strat_scores: dict[str, float] = defaultdict(float)
        strat_counts: dict[str, int] = defaultdict(int)
        for r in relevant:
            strat_scores[r.strategy] += r.efficiency
            strat_counts[r.strategy] += 1

        best_strategy = max(
            strat_scores.keys(),
            key=lambda s: strat_scores[s] / max(1, strat_counts[s]),
        ) if strat_scores else ""

        # Find best model
        model_scores: dict[str, float] = defaultdict(float)
        model_counts: dict[str, int] = defaultdict(int)
        for r in relevant:
            model_scores[r.model] += r.efficiency
            model_counts[r.model] += 1

        best_model = max(
            model_scores.keys(),
            key=lambda m: model_scores[m] / max(1, model_counts[m]),
        ) if model_scores else ""

        return {
            "strategy": best_strategy,
            "model": best_model,
            "records_analyzed": len(relevant),
        }

    def save(self) -> bool:
        """Save performance data to disk."""
        try:
            os.makedirs(self._data_dir, exist_ok=True)
            path = os.path.join(self._data_dir, "performance.jsonl")
            with open(path, "a") as f:
                for record in self._records:
                    f.write(json.dumps(record.to_dict()) + "\n")
            return True
        except OSError:
            return False

    def get_stats(self) -> dict[str, Any]:
        total_findings = sum(r.findings for r in self._records)
        total_tokens = sum(r.tokens_used for r in self._records)

        return {
            "records": len(self._records),
            "total_findings": total_findings,
            "total_tokens": total_tokens,
            "overall_efficiency": round(total_findings * 1000 / max(1, total_tokens), 2),
            "strategies_tracked": len(self._strategy_stats),
            "models_tracked": len(self._model_stats),
            "tools_tracked": len(self._tool_stats),
        }
