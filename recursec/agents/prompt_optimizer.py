"""Prompt optimization engine — learns which prompts work best.

Tracks prompt performance and iteratively improves them:
1. A/B testing of prompt variants
2. Performance tracking per prompt template
3. Dynamic variable injection optimization
4. Model-specific prompt formatting
5. Temperature and parameter tuning
6. Few-shot example selection
7. Prompt compression for token efficiency
8. Chain-of-thought vs. direct prompting selection
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class PromptVariant:
    """A variant of a prompt template for A/B testing."""
    variant_id: str = ""
    template: str = ""
    variables: list[str] = field(default_factory=list)
    model_preference: str = ""
    temperature: float = 0.2
    max_tokens: int = 1024
    system_message: str = ""
    few_shot_examples: list[dict[str, str]] = field(default_factory=list)

    # Performance tracking
    times_used: int = 0
    total_quality: float = 0.0
    avg_quality: float = 0.0
    avg_latency_ms: float = 0.0
    avg_tokens_used: int = 0
    success_rate: float = 0.5

    @property
    def confidence(self) -> float:
        """Confidence in quality estimate based on sample size."""
        return min(1.0, self.times_used / 20)

    @property
    def ucb_score(self) -> float:
        """Upper confidence bound for variant selection."""
        if self.times_used == 0:
            return float("inf")
        exploitation = self.avg_quality
        exploration = (2 * (1 + self.times_used) / self.times_used) ** 0.5
        return exploitation + 0.5 * exploration

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.variant_id,
            "template_preview": self.template[:100],
            "times_used": self.times_used,
            "avg_quality": round(self.avg_quality, 3),
            "success_rate": round(self.success_rate, 3),
            "avg_latency_ms": round(self.avg_latency_ms, 1),
            "confidence": round(self.confidence, 2),
        }


@dataclass
class PromptExperiment:
    """An A/B test experiment for prompt optimization."""
    experiment_id: str = ""
    name: str = ""
    task_type: str = ""
    variants: list[PromptVariant] = field(default_factory=list)
    winner: str = ""            # variant_id of winner
    min_samples: int = 10       # Min samples before declaring winner
    created_at: float = field(default_factory=time.time)
    completed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.experiment_id,
            "name": self.name,
            "task_type": self.task_type,
            "variants": len(self.variants),
            "winner": self.winner,
            "completed": self.completed,
        }


@dataclass
class FewShotExample:
    """A few-shot example for prompt injection."""
    example_id: str = ""
    task_type: str = ""
    input_text: str = ""
    output_text: str = ""
    quality_score: float = 0.5
    times_used: int = 0
    avg_outcome: float = 0.5

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.example_id,
            "type": self.task_type,
            "quality": round(self.quality_score, 2),
            "used": self.times_used,
            "input_preview": self.input_text[:50],
        }


class PromptOptimizer:
    """Learns which prompts work best through experimentation.

    Tracks performance of prompt variants, runs A/B tests,
    and continuously improves prompt quality.
    """

    def __init__(self, storage_dir: str = "data/prompt_optimization") -> None:
        self._storage_dir = Path(storage_dir)
        self._storage_dir.mkdir(parents=True, exist_ok=True)

        self._experiments: dict[str, PromptExperiment] = {}
        self._active_variants: dict[str, list[PromptVariant]] = defaultdict(list)
        self._few_shot_library: dict[str, list[FewShotExample]] = defaultdict(list)
        self._performance_history: list[dict[str, Any]] = []

        self._log = logger.bind(component="prompt_optimizer")
        self._load()

    def register_variants(
        self,
        task_type: str,
        variants: list[PromptVariant],
        experiment_name: str = "",
    ) -> str:
        """Register prompt variants for A/B testing."""
        exp_id = hashlib.md5(f"{task_type}:{time.time()}".encode()).hexdigest()[:10]
        experiment = PromptExperiment(
            experiment_id=exp_id,
            name=experiment_name or f"{task_type}_experiment",
            task_type=task_type,
            variants=variants,
        )
        self._experiments[exp_id] = experiment
        self._active_variants[task_type].extend(variants)
        return exp_id

    def select_variant(self, task_type: str) -> PromptVariant | None:
        """Select the best prompt variant for a task type using UCB."""
        variants = self._active_variants.get(task_type, [])
        if not variants:
            return None

        # Use UCB to balance exploration/exploitation
        return max(variants, key=lambda v: v.ucb_score)

    def record_result(
        self,
        variant_id: str,
        quality: float,
        latency_ms: float = 0,
        tokens_used: int = 0,
        success: bool = True,
    ) -> None:
        """Record the result of using a prompt variant."""
        for variants in self._active_variants.values():
            for variant in variants:
                if variant.variant_id == variant_id:
                    variant.times_used += 1
                    variant.total_quality += quality
                    variant.avg_quality = variant.total_quality / variant.times_used

                    if latency_ms > 0:
                        n = variant.times_used
                        variant.avg_latency_ms = (
                            variant.avg_latency_ms * (n - 1) + latency_ms
                        ) / n

                    if tokens_used > 0:
                        variant.avg_tokens_used = (
                            (variant.avg_tokens_used * (variant.times_used - 1) + tokens_used)
                            // variant.times_used
                        )

                    total = variant.times_used
                    successes = variant.success_rate * (total - 1) + (1.0 if success else 0.0)
                    variant.success_rate = successes / total

                    self._performance_history.append({
                        "variant": variant_id,
                        "quality": quality,
                        "success": success,
                        "timestamp": time.time(),
                    })
                    break

        # Check if any experiments can be resolved
        self._check_experiments()

    def get_best_variant(self, task_type: str) -> PromptVariant | None:
        """Get the best performing variant for a task type."""
        variants = self._active_variants.get(task_type, [])
        if not variants:
            return None

        # Only consider variants with enough samples
        confident = [v for v in variants if v.times_used >= 5]
        if not confident:
            return variants[0]  # Not enough data, return first

        return max(confident, key=lambda v: v.avg_quality)

    # ── Few-Shot Example Management ──────────────────────

    def add_few_shot(
        self,
        task_type: str,
        input_text: str,
        output_text: str,
        quality_score: float = 0.5,
    ) -> str:
        """Add a few-shot example to the library."""
        example_id = hashlib.md5(
            f"{task_type}:{input_text[:50]}".encode()
        ).hexdigest()[:10]

        example = FewShotExample(
            example_id=example_id,
            task_type=task_type,
            input_text=input_text,
            output_text=output_text,
            quality_score=quality_score,
        )

        self._few_shot_library[task_type].append(example)
        return example_id

    def get_few_shots(
        self,
        task_type: str,
        max_examples: int = 3,
    ) -> list[FewShotExample]:
        """Get the best few-shot examples for a task type."""
        examples = self._few_shot_library.get(task_type, [])
        if not examples:
            return []

        # Sort by quality, prefer less-used examples for diversity
        scored = []
        for ex in examples:
            usage_penalty = min(1.0, ex.times_used * 0.1)
            score = ex.quality_score * (1 - usage_penalty * 0.3)
            scored.append((ex, score))

        scored.sort(key=lambda x: -x[1])
        selected = [ex for ex, _ in scored[:max_examples]]

        for ex in selected:
            ex.times_used += 1

        return selected

    # ── Prompt Compression ───────────────────────────────

    def compress_prompt(self, text: str, target_tokens: int) -> str:
        """Compress a prompt to fit within a token budget."""
        current_tokens = len(text.split()) * 2  # Rough estimate

        if current_tokens <= target_tokens:
            return text

        # Strategy 1: Remove redundant whitespace
        lines = text.split("\n")
        lines = [line.strip() for line in lines if line.strip()]
        text = "\n".join(lines)

        # Strategy 2: Truncate verbose sections
        if len(text.split()) * 2 > target_tokens:
            max_chars = target_tokens * 3
            text = text[:max_chars] + "\n[... truncated for token budget]"

        return text

    # ── Persistence ──────────────────────────────────────

    def save(self) -> None:
        """Persist optimization state."""
        try:
            data = {
                "variants": {
                    task_type: [
                        {
                            "id": v.variant_id,
                            "template": v.template[:500],
                            "times_used": v.times_used,
                            "avg_quality": v.avg_quality,
                            "success_rate": v.success_rate,
                        }
                        for v in variants
                    ]
                    for task_type, variants in self._active_variants.items()
                },
                "few_shots": {
                    task_type: [e.to_dict() for e in examples[:20]]
                    for task_type, examples in self._few_shot_library.items()
                },
            }
            path = self._storage_dir / "optimizer_state.json"
            path.write_text(json.dumps(data))
        except OSError as e:
            self._log.warning("save_failed", error=str(e))

    def _load(self) -> None:
        """Load persisted state."""
        path = self._storage_dir / "optimizer_state.json"
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text())
            # Restore variant stats
            for task_type, variants_data in data.get("variants", {}).items():
                for v_data in variants_data:
                    variant = PromptVariant(
                        variant_id=v_data.get("id", ""),
                        template=v_data.get("template", ""),
                        times_used=v_data.get("times_used", 0),
                        avg_quality=v_data.get("avg_quality", 0),
                        success_rate=v_data.get("success_rate", 0.5),
                    )
                    if variant.times_used > 0:
                        variant.total_quality = variant.avg_quality * variant.times_used
                    self._active_variants[task_type].append(variant)
        except (json.JSONDecodeError, OSError):
            pass

    def _check_experiments(self) -> None:
        """Check if any experiments have enough data to declare a winner."""
        for exp in self._experiments.values():
            if exp.completed:
                continue

            all_ready = all(
                v.times_used >= exp.min_samples for v in exp.variants
            )
            if not all_ready:
                continue

            # Declare winner
            best = max(exp.variants, key=lambda v: v.avg_quality)
            exp.winner = best.variant_id
            exp.completed = True

            self._log.info(
                "experiment_complete",
                experiment=exp.experiment_id,
                winner=best.variant_id,
                quality=round(best.avg_quality, 3),
            )

    def get_stats(self) -> dict[str, Any]:
        total_variants = sum(len(v) for v in self._active_variants.values())
        return {
            "experiments": len(self._experiments),
            "completed_experiments": sum(1 for e in self._experiments.values() if e.completed),
            "total_variants": total_variants,
            "task_types": list(self._active_variants.keys()),
            "few_shot_examples": sum(len(v) for v in self._few_shot_library.values()),
            "performance_records": len(self._performance_history),
        }
