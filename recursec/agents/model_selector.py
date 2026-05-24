"""Model selection engine — intelligent per-task routing.

Implements:
1. Task-type → model mapping with weights
2. Performance tracking per model
3. Adaptive selection based on past success
4. Context-length-aware routing
5. Fallback chains
6. Model selection prompt for LLM
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class ModelProfile:
    """Profile of a model's capabilities."""
    name: str = ""
    strengths: list[str] = field(default_factory=list)
    context_length: int = 4096
    speed: float = 1.0        # Relative speed (1.0 = baseline)
    quality: float = 1.0      # Relative quality
    port: int = 0
    weight: float = 1.0
    success_count: int = 0
    failure_count: int = 0
    total_latency: float = 0.0
    invocations: int = 0

    @property
    def success_rate(self) -> float:
        total = self.success_count + self.failure_count
        if total == 0:
            return 0.5
        return self.success_count / total

    @property
    def avg_latency(self) -> float:
        if self.invocations == 0:
            return 0.0
        return self.total_latency / self.invocations

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name[:15],
            "strengths": self.strengths[:3],
            "ctx": self.context_length,
            "success": f"{self.success_rate:.0%}",
        }


# Your 16 local models with profiles
MODEL_CATALOG: list[dict[str, Any]] = [
    {
        "name": "WhiteRabbitNeo-7B", "port": 8100,
        "strengths": ["security", "exploit", "pentest", "vuln_analysis"],
        "context": 4096, "speed": 1.0, "quality": 1.3, "weight": 2.0,
    },
    {
        "name": "Qwen2.5-Coder-14B", "port": 8101,
        "strengths": ["code_audit", "code_gen", "exploit_dev", "static_analysis"],
        "context": 32768, "speed": 0.7, "quality": 1.5, "weight": 1.5,
    },
    {
        "name": "Qwen2.5-Coder-7B", "port": 8102,
        "strengths": ["code_audit", "code_gen", "validation"],
        "context": 32768, "speed": 1.0, "quality": 1.2, "weight": 1.0,
    },
    {
        "name": "DeepSeek-R1", "port": 8103,
        "strengths": ["reasoning", "planning", "chain_of_thought", "analysis"],
        "context": 32768, "speed": 0.8, "quality": 1.4, "weight": 1.5,
    },
    {
        "name": "Yi-9B-200K", "port": 8104,
        "strengths": ["long_context", "code_audit", "document_analysis"],
        "context": 200000, "speed": 0.6, "quality": 1.1, "weight": 1.0,
    },
    {
        "name": "Phi-3.5-mini", "port": 8105,
        "strengths": ["fast_triage", "classification", "routing"],
        "context": 4096, "speed": 2.0, "quality": 0.8, "weight": 0.8,
    },
    {
        "name": "Mistral-7B", "port": 8106,
        "strengths": ["general", "summarization", "reporting"],
        "context": 8192, "speed": 1.0, "quality": 1.0, "weight": 1.0,
    },
    {
        "name": "CodeLlama-13B", "port": 8107,
        "strengths": ["code_gen", "code_audit", "binary_analysis"],
        "context": 16384, "speed": 0.8, "quality": 1.3, "weight": 1.2,
    },
    {
        "name": "CodeLlama-7B", "port": 8108,
        "strengths": ["code_gen", "code_audit"],
        "context": 16384, "speed": 1.2, "quality": 1.0, "weight": 0.9,
    },
    {
        "name": "Hermes-4-14B", "port": 8109,
        "strengths": ["instruction", "planning", "orchestration"],
        "context": 16384, "speed": 0.7, "quality": 1.3, "weight": 1.2,
    },
    {
        "name": "Llama-3.1-8B", "port": 8110,
        "strengths": ["general", "summarization", "analysis"],
        "context": 8192, "speed": 1.0, "quality": 1.1, "weight": 1.0,
    },
    {
        "name": "Dolphin-2.9", "port": 8111,
        "strengths": ["uncensored", "security", "exploit"],
        "context": 8192, "speed": 1.0, "quality": 1.1, "weight": 1.2,
    },
    {
        "name": "DeepSeek-Math", "port": 8112,
        "strengths": ["math", "crypto", "logic", "calculation"],
        "context": 4096, "speed": 1.0, "quality": 1.2, "weight": 1.0,
    },
    {
        "name": "Nomic-Embed", "port": 8113,
        "strengths": ["embedding", "similarity", "search"],
        "context": 8192, "speed": 3.0, "quality": 1.0, "weight": 1.0,
    },
    {
        "name": "Llama-Guard-3", "port": 8114,
        "strengths": ["safety", "content_filter", "guardrails"],
        "context": 2048, "speed": 2.5, "quality": 1.0, "weight": 1.0,
    },
    {
        "name": "FunctionGemma", "port": 8115,
        "strengths": ["function_call", "tool_routing", "classification"],
        "context": 2048, "speed": 5.0, "quality": 0.7, "weight": 0.8,
    },
]


class ModelSelector:
    """Intelligent model selection per task.

    Routes tasks to optimal models based on
    task type, context needs, and past performance.
    """

    def __init__(self) -> None:
        self._models: dict[str, ModelProfile] = {}
        self._log = logger.bind(component="model_sel")
        self._load_catalog()

    def _load_catalog(self) -> None:
        """Load model catalog."""
        for data in MODEL_CATALOG:
            profile = ModelProfile(
                name=data["name"],
                strengths=data.get("strengths", []),
                context_length=data.get("context", 4096),
                speed=data.get("speed", 1.0),
                quality=data.get("quality", 1.0),
                port=data.get("port", 0),
                weight=data.get("weight", 1.0),
            )
            self._models[profile.name] = profile

    def select(
        self,
        task_type: str,
        context_needed: int = 0,
        prefer_speed: bool = False,
        prefer_quality: bool = False,
    ) -> str:
        """Select the best model for a task."""
        candidates: list[tuple[str, float]] = []

        for name, model in self._models.items():
            # Filter by context length
            if context_needed > 0 and model.context_length < context_needed:
                continue

            # Score: strength match + quality + speed + success
            score = 0.0

            # Strength match
            if task_type in model.strengths:
                score += 3.0 * model.weight

            # Quality/speed preference
            if prefer_quality:
                score += model.quality * 2.0
            elif prefer_speed:
                score += model.speed * 2.0
            else:
                score += model.quality + model.speed

            # Past success
            score += model.success_rate * 2.0

            candidates.append((name, score))

        if not candidates:
            return "Mistral-7B"  # Default fallback

        candidates.sort(key=lambda x: x[1], reverse=True)
        return candidates[0][0]

    def get_fallback_chain(self, task_type: str) -> list[str]:
        """Get ordered fallback chain for a task type."""
        scored = []
        for name, model in self._models.items():
            score = 0.0
            if task_type in model.strengths:
                score += 3.0
            score += model.quality
            scored.append((name, score))

        scored.sort(key=lambda x: x[1], reverse=True)
        return [name for name, _ in scored[:4]]

    def record_success(
        self,
        model_name: str,
        latency: float = 0.0,
    ) -> None:
        """Record a successful model invocation."""
        model = self._models.get(model_name)
        if model:
            model.success_count += 1
            model.invocations += 1
            model.total_latency += latency

    def record_failure(self, model_name: str) -> None:
        """Record a failed model invocation."""
        model = self._models.get(model_name)
        if model:
            model.failure_count += 1
            model.invocations += 1

    def build_model_prompt(self) -> str:
        """Build model selection context for LLM."""
        lines = ["## Models\n"]
        lines.append(f"Available: {len(self._models)}")

        # Top performers
        top = sorted(
            self._models.values(),
            key=lambda m: m.success_rate * m.quality,
            reverse=True,
        )[:5]

        for m in top:
            lines.append(
                f"  {m.name[:15]} "
                f"({m.success_rate:.0%} success, "
                f"ctx={m.context_length})"
            )

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        total_invocations = sum(
            m.invocations for m in self._models.values()
        )
        return {
            "models": len(self._models),
            "total_invocations": total_invocations,
            "top_model": max(
                self._models.values(),
                key=lambda m: m.success_rate * m.quality,
            ).name if self._models else "",
        }
