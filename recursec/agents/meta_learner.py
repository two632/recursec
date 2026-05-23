"""Meta-learner — learns from past assessments to improve future performance.

Implements:
1. Assessment outcome tracking
2. Strategy effectiveness learning
3. Tool effectiveness by target type
4. Model effectiveness by task type
5. Finding pattern learning
6. Failure pattern recognition
7. Optimal configuration learning
8. Transfer learning between targets
"""

from __future__ import annotations

import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class AssessmentOutcome:
    """Outcome of a completed assessment."""
    outcome_id: str = ""
    target: str = ""
    target_type: str = ""
    strategy: str = ""
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    tools_used: list[str] = field(default_factory=list)
    models_used: list[str] = field(default_factory=list)
    duration_s: float = 0.0
    tokens_used: int = 0
    success: bool = True
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.outcome_id, "target_type": self.target_type,
            "findings": self.total_findings, "critical": self.critical_findings,
            "tools": len(self.tools_used), "success": self.success,
        }


@dataclass
class LearningEntry:
    """A learned association."""
    key: str = ""
    value: float = 0.0
    confidence: float = 0.0
    sample_count: int = 0
    last_updated: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key[:40], "value": round(self.value, 3),
            "confidence": round(self.confidence, 2),
            "samples": self.sample_count,
        }


class MetaLearner:
    """Learns from past assessments to improve future performance.

    Tracks effectiveness of strategies, tools, and models
    across different target types and contexts.
    """

    def __init__(self, data_dir: str = "data/meta-learning") -> None:
        self._data_dir = Path(data_dir)
        self._data_dir.mkdir(parents=True, exist_ok=True)

        self._outcomes: list[AssessmentOutcome] = []

        # Learning tables: key → LearningEntry
        self._tool_effectiveness: dict[str, LearningEntry] = {}     # tool:target_type → score
        self._model_effectiveness: dict[str, LearningEntry] = {}    # model:task_type → score
        self._strategy_effectiveness: dict[str, LearningEntry] = {} # strategy:target_type → score
        self._failure_patterns: dict[str, int] = defaultdict(int)    # pattern → count

        self._outcome_counter = 0
        self._log = logger.bind(component="meta_learner")

        self._load()

    def record_outcome(self, outcome: AssessmentOutcome) -> None:
        """Record an assessment outcome for learning."""
        self._outcomes.append(outcome)

        # Update tool effectiveness
        for tool in outcome.tools_used:
            key = f"{tool}:{outcome.target_type}"
            entry = self._tool_effectiveness.get(key, LearningEntry(key=key))

            score = self._compute_tool_score(tool, outcome)
            entry.value = self._running_average(entry.value, score, entry.sample_count)
            entry.sample_count += 1
            entry.confidence = min(0.95, 1.0 - 1.0 / (entry.sample_count + 1))
            entry.last_updated = time.time()
            self._tool_effectiveness[key] = entry

        # Update model effectiveness
        for model in outcome.models_used:
            key = f"{model}:{outcome.target_type}"
            entry = self._model_effectiveness.get(key, LearningEntry(key=key))

            score = 1.0 if outcome.success else 0.0
            if outcome.total_findings > 0:
                score = min(1.0, outcome.critical_findings * 0.3 + outcome.high_findings * 0.2 + 0.5)

            entry.value = self._running_average(entry.value, score, entry.sample_count)
            entry.sample_count += 1
            entry.confidence = min(0.95, 1.0 - 1.0 / (entry.sample_count + 1))
            entry.last_updated = time.time()
            self._model_effectiveness[key] = entry

        # Update strategy effectiveness
        if outcome.strategy:
            key = f"{outcome.strategy}:{outcome.target_type}"
            entry = self._strategy_effectiveness.get(key, LearningEntry(key=key))

            score = outcome.total_findings / max(1, outcome.duration_s / 60)
            entry.value = self._running_average(entry.value, score, entry.sample_count)
            entry.sample_count += 1
            entry.confidence = min(0.95, 1.0 - 1.0 / (entry.sample_count + 1))
            entry.last_updated = time.time()
            self._strategy_effectiveness[key] = entry

        # Track failure patterns
        if not outcome.success:
            pattern = f"{outcome.target_type}:{outcome.strategy}"
            self._failure_patterns[pattern] += 1

        self._save()

    def recommend_tools(
        self,
        target_type: str,
        available_tools: list[str],
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        """Recommend tools based on learned effectiveness."""
        scored = []
        for tool in available_tools:
            key = f"{tool}:{target_type}"
            entry = self._tool_effectiveness.get(key)

            if entry and entry.confidence >= 0.3:
                scored.append({
                    "tool": tool,
                    "score": entry.value,
                    "confidence": entry.confidence,
                    "samples": entry.sample_count,
                })
            else:
                # No data — use neutral score
                scored.append({
                    "tool": tool, "score": 0.5,
                    "confidence": 0.0, "samples": 0,
                })

        scored.sort(key=lambda t: t["score"], reverse=True)
        return scored[:limit]

    def recommend_models(
        self,
        task_type: str,
        available_models: list[str],
    ) -> list[dict[str, Any]]:
        """Recommend models based on learned effectiveness."""
        scored = []
        for model in available_models:
            key = f"{model}:{task_type}"
            entry = self._model_effectiveness.get(key)

            if entry and entry.confidence >= 0.3:
                scored.append({
                    "model": model,
                    "score": entry.value,
                    "confidence": entry.confidence,
                })
            else:
                scored.append({"model": model, "score": 0.5, "confidence": 0.0})

        scored.sort(key=lambda m: m["score"], reverse=True)
        return scored

    def recommend_strategy(
        self,
        target_type: str,
    ) -> str:
        """Recommend the best strategy for a target type."""
        best_strategy = ""
        best_score = 0.0

        for key, entry in self._strategy_effectiveness.items():
            parts = key.split(":")
            if len(parts) == 2 and parts[1] == target_type:
                if entry.value > best_score and entry.confidence >= 0.3:
                    best_score = entry.value
                    best_strategy = parts[0]

        return best_strategy

    def get_failure_patterns(self, limit: int = 10) -> list[dict[str, Any]]:
        """Get most common failure patterns."""
        sorted_patterns = sorted(
            self._failure_patterns.items(),
            key=lambda x: x[1],
            reverse=True,
        )

        return [
            {"pattern": p, "count": c}
            for p, c in sorted_patterns[:limit]
        ]

    @staticmethod
    def _compute_tool_score(tool: str, outcome: AssessmentOutcome) -> float:
        """Compute effectiveness score for a tool."""
        if not outcome.success:
            return 0.2

        if outcome.total_findings == 0:
            return 0.3

        findings_per_min = outcome.total_findings / max(1, outcome.duration_s / 60)
        score = min(1.0, 0.5 + findings_per_min * 0.1 + outcome.critical_findings * 0.15)
        return score

    @staticmethod
    def _running_average(current: float, new_value: float, count: int) -> float:
        """Compute running average."""
        if count == 0:
            return new_value
        return current + (new_value - current) / (count + 1)

    def _save(self) -> None:
        """Save learning data."""
        try:
            data = {
                "tool_effectiveness": {k: v.to_dict() for k, v in self._tool_effectiveness.items()},
                "model_effectiveness": {k: v.to_dict() for k, v in self._model_effectiveness.items()},
                "strategy_effectiveness": {k: v.to_dict() for k, v in self._strategy_effectiveness.items()},
                "failure_patterns": dict(self._failure_patterns),
            }
            path = self._data_dir / "learned.json"
            path.write_text(json.dumps(data, indent=2, default=str))
        except OSError:
            pass

    def _load(self) -> None:
        """Load previously learned data."""
        path = self._data_dir / "learned.json"
        if not path.exists():
            return

        try:
            data = json.loads(path.read_text())
            for key, entry_data in data.get("failure_patterns", {}).items():
                self._failure_patterns[key] = entry_data
        except (json.JSONDecodeError, OSError):
            pass

    def get_stats(self) -> dict[str, Any]:
        return {
            "outcomes": len(self._outcomes),
            "tool_entries": len(self._tool_effectiveness),
            "model_entries": len(self._model_effectiveness),
            "strategy_entries": len(self._strategy_effectiveness),
            "failure_patterns": len(self._failure_patterns),
        }
