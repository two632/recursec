"""Model performance tracker — tracks per-model effectiveness.

Implements:
1. Per-model task tracking (latency, quality, tokens)
2. Model-task affinity scoring
3. Performance degradation detection
4. Routing recommendation engine
5. Model comparison reports
6. Performance prompt for LLM
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class TaskExecution:
    """Record of a model executing a task."""
    execution_id: str = ""
    model_id: str = ""
    task_type: str = ""        # recon, exploit, code_audit, etc.
    latency_ms: float = 0.0
    tokens_used: int = 0
    quality_score: float = 0.5  # 0-1 (from validation)
    success: bool = True
    findings_produced: int = 0
    false_positives: int = 0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model_id[:12],
            "task": self.task_type[:8],
            "latency": f"{self.latency_ms:.0f}ms",
            "quality": f"{self.quality_score:.1f}",
        }


@dataclass
class ModelStats:
    """Aggregate stats for a model."""
    model_id: str = ""
    total_executions: int = 0
    total_tokens: int = 0
    avg_latency_ms: float = 0.0
    avg_quality: float = 0.0
    success_rate: float = 0.0
    total_findings: int = 0
    total_false_positives: int = 0
    task_affinity: dict[str, float] = field(default_factory=dict)
    last_used: float = 0.0

    @property
    def efficiency_score(self) -> float:
        """Quality per 1000 tokens."""
        if self.total_tokens == 0:
            return 0.0
        return (self.avg_quality * 1000) / (self.total_tokens / max(1, self.total_executions))

    @property
    def false_positive_rate(self) -> float:
        total = self.total_findings + self.total_false_positives
        if total == 0:
            return 0.0
        return self.total_false_positives / total

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model_id[:12],
            "execs": self.total_executions,
            "quality": f"{self.avg_quality:.2f}",
            "efficiency": f"{self.efficiency_score:.2f}",
            "fp_rate": f"{self.false_positive_rate:.1%}",
        }


class ModelPerformanceTracker:
    """Tracks per-model effectiveness for routing.

    Records task executions per model, computes
    quality and efficiency metrics, and recommends
    optimal model assignments.
    """

    def __init__(self) -> None:
        self._executions: list[TaskExecution] = []
        self._model_stats: dict[str, ModelStats] = {}
        self._exec_counter = 0
        self._log = logger.bind(component="model_perf")

    def record_execution(
        self,
        model_id: str,
        task_type: str,
        latency_ms: float = 0.0,
        tokens_used: int = 0,
        quality_score: float = 0.5,
        success: bool = True,
        findings_produced: int = 0,
        false_positives: int = 0,
    ) -> TaskExecution:
        """Record a model task execution."""
        self._exec_counter += 1

        exe = TaskExecution(
            execution_id=f"exec-{self._exec_counter}",
            model_id=model_id,
            task_type=task_type,
            latency_ms=latency_ms,
            tokens_used=tokens_used,
            quality_score=quality_score,
            success=success,
            findings_produced=findings_produced,
            false_positives=false_positives,
        )
        self._executions.append(exe)

        # Update stats
        self._update_stats(exe)

        return exe

    def _update_stats(self, exe: TaskExecution) -> None:
        """Update aggregate stats for a model."""
        if exe.model_id not in self._model_stats:
            self._model_stats[exe.model_id] = ModelStats(model_id=exe.model_id)

        stats = self._model_stats[exe.model_id]
        n = stats.total_executions

        # Running averages
        stats.avg_latency_ms = (stats.avg_latency_ms * n + exe.latency_ms) / (n + 1)
        stats.avg_quality = (stats.avg_quality * n + exe.quality_score) / (n + 1)

        stats.total_executions += 1
        stats.total_tokens += exe.tokens_used
        stats.total_findings += exe.findings_produced
        stats.total_false_positives += exe.false_positives
        stats.last_used = time.time()

        # Success rate
        successful = sum(1 for e in self._executions if e.model_id == exe.model_id and e.success)
        stats.success_rate = successful / stats.total_executions

        # Task affinity
        task_execs = [
            e for e in self._executions
            if e.model_id == exe.model_id and e.task_type == exe.task_type
        ]
        if task_execs:
            stats.task_affinity[exe.task_type] = sum(
                e.quality_score for e in task_execs
            ) / len(task_execs)

    def recommend_model(self, task_type: str) -> str:
        """Recommend best model for a task type."""
        best_model = ""
        best_score = -1.0

        for model_id, stats in self._model_stats.items():
            affinity = stats.task_affinity.get(task_type, 0.0)
            score = (
                affinity * 0.4
                + stats.avg_quality * 0.3
                + stats.success_rate * 0.2
                + stats.efficiency_score * 0.1
            )
            if score > best_score:
                best_score = score
                best_model = model_id

        return best_model

    def get_model_ranking(self, task_type: str = "") -> list[tuple[str, float]]:
        """Get models ranked by performance for a task."""
        rankings = []

        for model_id, stats in self._model_stats.items():
            if task_type:
                score = stats.task_affinity.get(task_type, stats.avg_quality * 0.5)
            else:
                score = stats.avg_quality

            rankings.append((model_id, score))

        rankings.sort(key=lambda x: x[1], reverse=True)
        return rankings

    def detect_degradation(self, model_id: str, window: int = 10) -> bool:
        """Detect if model performance is degrading."""
        recent = [
            e for e in self._executions[-window * 2:]
            if e.model_id == model_id
        ]

        if len(recent) < window:
            return False

        mid = len(recent) // 2
        first_half = recent[:mid]
        second_half = recent[mid:]

        avg_first = sum(e.quality_score for e in first_half) / max(1, len(first_half))
        avg_second = sum(e.quality_score for e in second_half) / max(1, len(second_half))

        return avg_second < avg_first * 0.7

    def build_performance_prompt(self) -> str:
        """Build performance context for LLM."""
        lines = ["## Model Performance\n"]

        if not self._model_stats:
            lines.append("No executions recorded yet.")
            return "\n".join(lines)

        lines.append(f"Models tracked: {len(self._model_stats)}")
        lines.append(f"Total executions: {len(self._executions)}")

        # Top performers
        rankings = self.get_model_ranking()
        lines.append("\nRanking:")
        for model_id, score in rankings[:5]:
            stats = self._model_stats[model_id]
            lines.append(
                f"  {model_id[:15]}: quality={stats.avg_quality:.2f} "
                f"success={stats.success_rate:.0%} "
                f"efficiency={stats.efficiency_score:.2f}"
            )

        # Degradation warnings
        for model_id in self._model_stats:
            if self.detect_degradation(model_id):
                lines.append(f"\nDEGRADATION: {model_id[:15]}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            "models": len(self._model_stats),
            "executions": len(self._executions),
            "total_tokens": sum(s.total_tokens for s in self._model_stats.values()),
            "avg_quality": sum(s.avg_quality for s in self._model_stats.values()) / max(1, len(self._model_stats)),
        }
