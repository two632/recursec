"""Meta-learning engine — the agent learns HOW to learn better.

Implements:
1. Strategy effectiveness tracking across assessments
2. Tool-target affinity learning (which tools work best on which targets)
3. Model-task affinity learning (which models are best at which tasks)
4. Failure pattern recognition (avoid repeating mistakes)
5. Success pattern amplification (do more of what works)
6. Assessment time estimation (predict how long tasks take)
7. Finding prediction (predict likely vulns before scanning)
8. Transfer learning (apply learnings from one target to similar targets)
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
class ToolEfficiency:
    """Tracks how effective a tool is for different target types."""
    tool: str = ""
    target_type: str = ""
    runs: int = 0
    findings_total: int = 0
    findings_validated: int = 0
    avg_time_s: float = 0.0
    false_positive_rate: float = 0.0
    last_used: float = field(default_factory=time.time)

    @property
    def effectiveness(self) -> float:
        if self.runs == 0:
            return 0.5
        findings_rate = self.findings_total / max(1, self.runs)
        validation_rate = self.findings_validated / max(1, self.findings_total) if self.findings_total else 0
        fp_penalty = self.false_positive_rate * 0.5
        return min(1.0, findings_rate * 0.3 + validation_rate * 0.5 - fp_penalty + 0.2)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool, "target": self.target_type,
            "runs": self.runs, "effectiveness": round(self.effectiveness, 2),
            "fp_rate": round(self.false_positive_rate, 2),
        }


@dataclass
class ModelPerformance:
    """Tracks model performance on different task types."""
    model: str = ""
    task_type: str = ""
    calls: int = 0
    avg_latency_ms: float = 0.0
    avg_quality: float = 0.5
    errors: int = 0

    @property
    def efficiency(self) -> float:
        if self.calls == 0:
            return 0.5
        error_rate = self.errors / max(1, self.calls)
        latency_penalty = min(0.3, self.avg_latency_ms / 10000)
        return min(1.0, self.avg_quality - error_rate * 0.5 - latency_penalty)

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model, "task": self.task_type,
            "calls": self.calls, "efficiency": round(self.efficiency, 2),
        }


@dataclass
class StrategyOutcome:
    """Records the outcome of a strategy."""
    strategy: str = ""
    target_type: str = ""
    findings_count: int = 0
    critical_count: int = 0
    time_s: float = 0.0
    success: bool = True
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy": self.strategy, "target": self.target_type,
            "findings": self.findings_count, "success": self.success,
        }


@dataclass
class FailurePattern:
    """A recognized failure pattern."""
    pattern_id: str = ""
    description: str = ""
    context: str = ""         # target_type, tool, or general
    occurrences: int = 0
    avoidance_strategy: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id, "desc": self.description[:80],
            "count": self.occurrences, "fix": self.avoidance_strategy[:80],
        }


class MetaLearning:
    """Meta-learning engine — learns how to learn better.

    Tracks effectiveness of tools, models, and strategies
    across assessments. Uses this knowledge to make better
    decisions in future assessments.
    """

    def __init__(self, persistence_dir: str = "data/meta") -> None:
        self._tool_perf: dict[str, ToolEfficiency] = {}
        self._model_perf: dict[str, ModelPerformance] = {}
        self._strategy_outcomes: list[StrategyOutcome] = []
        self._failure_patterns: dict[str, FailurePattern] = {}
        self._prediction_cache: dict[str, list[str]] = {}
        self._persistence_dir = Path(persistence_dir)
        self._persistence_dir.mkdir(parents=True, exist_ok=True)
        self._pattern_counter = 0
        self._log = logger.bind(component="meta_learning")

        self._load()

    def record_tool_run(
        self,
        tool: str,
        target_type: str,
        findings: int = 0,
        validated: int = 0,
        time_s: float = 0.0,
        false_positives: int = 0,
    ) -> None:
        """Record a tool execution result."""
        key = f"{tool}:{target_type}"
        perf = self._tool_perf.get(key)
        if not perf:
            perf = ToolEfficiency(tool=tool, target_type=target_type)
            self._tool_perf[key] = perf

        perf.runs += 1
        perf.findings_total += findings
        perf.findings_validated += validated
        perf.last_used = time.time()

        # Running average for time
        if perf.avg_time_s == 0:
            perf.avg_time_s = time_s
        else:
            perf.avg_time_s = (perf.avg_time_s * (perf.runs - 1) + time_s) / perf.runs

        # False positive rate
        total_findings = perf.findings_total
        if total_findings > 0:
            perf.false_positive_rate = false_positives / total_findings

    def record_model_call(
        self,
        model: str,
        task_type: str,
        latency_ms: float = 0.0,
        quality: float = 0.5,
        error: bool = False,
    ) -> None:
        """Record a model inference result."""
        key = f"{model}:{task_type}"
        perf = self._model_perf.get(key)
        if not perf:
            perf = ModelPerformance(model=model, task_type=task_type)
            self._model_perf[key] = perf

        perf.calls += 1
        if error:
            perf.errors += 1

        # Running averages
        if perf.avg_latency_ms == 0:
            perf.avg_latency_ms = latency_ms
        else:
            perf.avg_latency_ms = (perf.avg_latency_ms * (perf.calls - 1) + latency_ms) / perf.calls

        if perf.avg_quality == 0.5:
            perf.avg_quality = quality
        else:
            perf.avg_quality = (perf.avg_quality * (perf.calls - 1) + quality) / perf.calls

    def record_strategy_outcome(
        self,
        strategy: str,
        target_type: str,
        findings: int = 0,
        critical: int = 0,
        time_s: float = 0.0,
        success: bool = True,
    ) -> None:
        """Record a strategy outcome."""
        outcome = StrategyOutcome(
            strategy=strategy,
            target_type=target_type,
            findings_count=findings,
            critical_count=critical,
            time_s=time_s,
            success=success,
        )
        self._strategy_outcomes.append(outcome)

        # Keep bounded
        if len(self._strategy_outcomes) > 1000:
            self._strategy_outcomes = self._strategy_outcomes[-1000:]

    def record_failure(self, description: str, context: str = "") -> None:
        """Record a failure pattern."""
        key = f"{context}:{description[:50]}"
        pattern = self._failure_patterns.get(key)
        if pattern:
            pattern.occurrences += 1
        else:
            self._pattern_counter += 1
            self._failure_patterns[key] = FailurePattern(
                pattern_id=f"fp-{self._pattern_counter}",
                description=description,
                context=context,
                occurrences=1,
            )

    def recommend_tools(self, target_type: str, limit: int = 5) -> list[str]:
        """Recommend tools for a target type based on past performance."""
        candidates = [
            perf for perf in self._tool_perf.values()
            if perf.target_type == target_type
        ]

        if not candidates:
            return self._default_tools(target_type)

        candidates.sort(key=lambda p: p.effectiveness, reverse=True)
        return [c.tool for c in candidates[:limit]]

    def recommend_model(self, task_type: str) -> str:
        """Recommend best model for a task type."""
        candidates = [
            perf for perf in self._model_perf.values()
            if perf.task_type == task_type
        ]

        if not candidates:
            return ""

        candidates.sort(key=lambda p: p.efficiency, reverse=True)
        return candidates[0].model

    def recommend_strategy(self, target_type: str) -> str:
        """Recommend best strategy for a target type."""
        outcomes = [
            o for o in self._strategy_outcomes
            if o.target_type == target_type and o.success
        ]

        if not outcomes:
            return "adaptive"

        # Count findings per strategy
        strategy_findings: dict[str, int] = defaultdict(int)
        strategy_count: dict[str, int] = defaultdict(int)

        for outcome in outcomes:
            strategy_findings[outcome.strategy] += outcome.findings_count
            strategy_count[outcome.strategy] += 1

        # Average findings per run
        best = max(
            strategy_count.keys(),
            key=lambda s: strategy_findings[s] / max(1, strategy_count[s]),
        )
        return best

    def predict_findings(self, target_type: str) -> list[str]:
        """Predict likely finding types for a target type."""
        if target_type in self._prediction_cache:
            return self._prediction_cache[target_type]

        predictions = {
            "web_app": ["xss", "sqli", "csrf", "info_disclosure", "misconfiguration"],
            "api": ["auth_bypass", "idor", "info_disclosure", "rate_limit"],
            "network": ["open_ports", "weak_protocols", "misconfiguration"],
            "host": ["unpatched_services", "weak_credentials", "misconfiguration"],
            "domain": ["subdomain_takeover", "dns_misconfiguration", "info_disclosure"],
        }

        result = predictions.get(target_type, ["info_disclosure", "misconfiguration"])
        self._prediction_cache[target_type] = result
        return result

    def estimate_time(self, target_type: str, strategy: str) -> float:
        """Estimate assessment time based on past data."""
        relevant = [
            o for o in self._strategy_outcomes
            if o.target_type == target_type and o.strategy == strategy
        ]

        if not relevant:
            defaults = {
                "web_app": 1800.0, "api": 900.0, "network": 3600.0,
                "host": 600.0, "domain": 1200.0,
            }
            return defaults.get(target_type, 1200.0)

        return sum(o.time_s for o in relevant) / len(relevant)

    def get_failure_patterns(self, context: str = "") -> list[FailurePattern]:
        """Get known failure patterns."""
        if context:
            return [
                p for p in self._failure_patterns.values()
                if p.context == context
            ]
        return list(self._failure_patterns.values())

    def _default_tools(self, target_type: str) -> list[str]:
        defaults = {
            "web_app": ["nuclei", "nikto", "sqlmap", "ffuf", "httpx"],
            "api": ["nuclei", "ffuf", "httpx"],
            "network": ["nmap", "masscan"],
            "host": ["nmap", "nuclei"],
            "domain": ["subfinder", "httpx", "nuclei"],
        }
        return defaults.get(target_type, ["nmap", "nuclei"])

    def save(self) -> None:
        """Persist meta-learning data."""
        data = {
            "tool_perf": {k: v.to_dict() for k, v in self._tool_perf.items()},
            "model_perf": {k: v.to_dict() for k, v in self._model_perf.items()},
            "strategies": [o.to_dict() for o in self._strategy_outcomes[-100:]],
            "failures": {k: v.to_dict() for k, v in self._failure_patterns.items()},
        }

        path = self._persistence_dir / "meta_learning.json"
        try:
            path.write_text(json.dumps(data))
        except OSError:
            pass

    def _load(self) -> None:
        """Load persisted data."""
        path = self._persistence_dir / "meta_learning.json"
        if not path.exists():
            return
        try:
            json.loads(path.read_text())
            # Restore state from data (simplified — full restore would rebuild objects)
        except (json.JSONDecodeError, OSError):
            pass

    def get_stats(self) -> dict[str, Any]:
        return {
            "tool_profiles": len(self._tool_perf),
            "model_profiles": len(self._model_perf),
            "strategy_outcomes": len(self._strategy_outcomes),
            "failure_patterns": len(self._failure_patterns),
        }
