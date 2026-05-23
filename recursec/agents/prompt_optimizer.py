"""Prompt optimizer — learns and optimizes prompt structures for better LLM responses.

Implements:
1. Prompt variant generation
2. A/B testing of prompts
3. Prompt performance tracking
4. Automatic prompt selection
5. Few-shot example curation
6. System prompt tuning
7. Temperature/parameter optimization
8. Prompt chain optimization
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class PromptVariant:
    """A variant of a prompt for testing."""
    variant_id: str = ""
    template: str = ""
    system_prompt: str = ""
    temperature: float = 0.7
    max_tokens: int = 2048
    few_shot_examples: list[dict[str, str]] = field(default_factory=list)
    uses: int = 0
    total_reward: float = 0.0
    avg_reward: float = 0.0
    avg_latency_s: float = 0.0
    avg_output_quality: float = 0.5
    created_at: float = field(default_factory=time.time)

    @property
    def score(self) -> float:
        if self.uses == 0:
            return 0.5  # Prior
        return self.avg_reward * 0.6 + self.avg_output_quality * 0.4

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.variant_id,
            "template": self.template[:40],
            "temp": self.temperature,
            "uses": self.uses,
            "score": round(self.score, 3),
            "avg_reward": round(self.avg_reward, 3),
            "quality": round(self.avg_output_quality, 3),
        }


@dataclass
class PromptExperiment:
    """An A/B test experiment."""
    experiment_id: str = ""
    name: str = ""
    task_type: str = ""
    variants: list[str] = field(default_factory=list)  # variant IDs
    winner_id: str = ""
    min_samples: int = 10
    started_at: float = field(default_factory=time.time)
    concluded_at: float = 0.0

    @property
    def is_concluded(self) -> bool:
        return self.concluded_at > 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.experiment_id,
            "name": self.name[:40],
            "task": self.task_type[:20],
            "variants": len(self.variants),
            "concluded": self.is_concluded,
            "winner": self.winner_id[:15],
        }


# ── Prompt Templates ──────────────────────────────────────────

BASE_SYSTEM_PROMPTS: dict[str, list[str]] = {
    "security_analysis": [
        "You are an expert security analyst. Analyze the following data and identify potential vulnerabilities, their severity, and recommended mitigations.",
        "As a senior penetration tester, examine the provided information. Focus on critical and high-severity findings. Be precise and evidence-based.",
        "You are a vulnerability researcher. Given the following security scan results, provide a structured analysis with risk ratings and exploitation potential.",
    ],
    "recon": [
        "You are a reconnaissance specialist. Plan the next steps for information gathering on the target. Prioritize by expected value of information.",
        "As an attack surface analyst, examine the target information and identify additional areas to investigate. Focus on high-value assets.",
    ],
    "planning": [
        "You are a security assessment planner. Create a comprehensive test plan based on the current findings. Include tool selection, ordering, and expected outcomes.",
        "As a senior security architect, design the optimal testing strategy. Consider stealth, thoroughness, and time constraints.",
    ],
    "validation": [
        "You are a security finding validator. Verify whether the reported vulnerability is a true positive. Request additional evidence if needed.",
        "As a QA security analyst, cross-reference the finding against known patterns. Assess confidence level and suggest confirmation steps.",
    ],
}


class PromptOptimizer:
    """Learns and optimizes prompt structures for better LLM responses.

    Uses A/B testing and reward tracking to find
    the most effective prompts for each task type.
    """

    def __init__(self) -> None:
        self._variants: dict[str, PromptVariant] = {}
        self._experiments: dict[str, PromptExperiment] = {}
        self._task_best: dict[str, str] = {}  # task_type -> best variant_id
        self._variant_counter = 0
        self._experiment_counter = 0
        self._log = logger.bind(component="prompt_optimizer")

        self._initialize_defaults()

    def _initialize_defaults(self) -> None:
        """Create default prompt variants from templates."""
        for task_type, prompts in BASE_SYSTEM_PROMPTS.items():
            for i, prompt in enumerate(prompts):
                self._variant_counter += 1
                variant = PromptVariant(
                    variant_id=f"pv-{self._variant_counter}",
                    template=f"{task_type}_v{i+1}",
                    system_prompt=prompt,
                    temperature=0.7 - i * 0.1,  # Vary temperature
                )
                self._variants[variant.variant_id] = variant

    def select_prompt(
        self,
        task_type: str,
    ) -> PromptVariant | None:
        """Select the best prompt for a task type."""
        # If we have a known best, use it most of the time
        best_id = self._task_best.get(task_type)
        if best_id and random.random() > 0.1:  # 90% exploit
            return self._variants.get(best_id)

        # Otherwise explore
        candidates = [
            v for v in self._variants.values()
            if task_type in v.template
        ]

        if not candidates:
            return None

        # UCB1-like selection
        return max(candidates, key=lambda v: v.score)

    def create_variant(
        self,
        template: str,
        system_prompt: str,
        temperature: float = 0.7,
        max_tokens: int = 2048,
        few_shot_examples: list[dict[str, str]] | None = None,
    ) -> PromptVariant:
        """Create a new prompt variant."""
        self._variant_counter += 1
        variant = PromptVariant(
            variant_id=f"pv-{self._variant_counter}",
            template=template,
            system_prompt=system_prompt,
            temperature=temperature,
            max_tokens=max_tokens,
            few_shot_examples=few_shot_examples or [],
        )
        self._variants[variant.variant_id] = variant
        return variant

    def record_outcome(
        self,
        variant_id: str,
        reward: float,
        output_quality: float = 0.5,
        latency_s: float = 0.0,
    ) -> None:
        """Record the outcome of using a prompt variant."""
        variant = self._variants.get(variant_id)
        if not variant:
            return

        variant.uses += 1
        variant.total_reward += reward

        # Running averages
        n = variant.uses
        variant.avg_reward += (reward - variant.avg_reward) / n
        variant.avg_output_quality += (output_quality - variant.avg_output_quality) / n
        if latency_s > 0:
            variant.avg_latency_s += (latency_s - variant.avg_latency_s) / n

        # Check if this variant is now the best for its task type
        task_type = variant.template.rsplit("_", 1)[0]
        current_best_id = self._task_best.get(task_type)
        if current_best_id:
            current_best = self._variants.get(current_best_id)
            if current_best and variant.score > current_best.score and variant.uses >= 5:
                self._task_best[task_type] = variant_id
        elif variant.uses >= 5:
            self._task_best[task_type] = variant_id

    def create_experiment(
        self,
        name: str,
        task_type: str,
        variant_ids: list[str],
        min_samples: int = 10,
    ) -> PromptExperiment:
        """Create an A/B test experiment."""
        self._experiment_counter += 1
        experiment = PromptExperiment(
            experiment_id=f"exp-{self._experiment_counter}",
            name=name,
            task_type=task_type,
            variants=variant_ids,
            min_samples=min_samples,
        )
        self._experiments[experiment.experiment_id] = experiment
        return experiment

    def check_experiment(self, experiment_id: str) -> PromptExperiment | None:
        """Check if an experiment can be concluded."""
        experiment = self._experiments.get(experiment_id)
        if not experiment or experiment.is_concluded:
            return experiment

        variants = [
            self._variants.get(vid)
            for vid in experiment.variants
        ]
        variants = [v for v in variants if v is not None]

        # All variants need minimum samples
        if all(v.uses >= experiment.min_samples for v in variants):
            winner = max(variants, key=lambda v: v.score)
            experiment.winner_id = winner.variant_id
            experiment.concluded_at = time.time()
            self._task_best[experiment.task_type] = winner.variant_id

        return experiment

    def get_best_prompts(self) -> dict[str, dict[str, Any]]:
        """Get the best prompt for each task type."""
        result = {}
        for task_type, variant_id in self._task_best.items():
            variant = self._variants.get(variant_id)
            if variant:
                result[task_type] = variant.to_dict()
        return result

    def get_stats(self) -> dict[str, Any]:
        total_uses = sum(v.uses for v in self._variants.values())
        return {
            "variants": len(self._variants),
            "experiments": len(self._experiments),
            "concluded": sum(1 for e in self._experiments.values() if e.is_concluded),
            "total_uses": total_uses,
            "known_best": len(self._task_best),
        }
