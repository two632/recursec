"""Prompt optimizer — maximizes LLM output quality per model.

Each of the 16 models responds differently to different prompt formats.
This module:
1. Maintains model-specific prompt templates (chat vs instruct vs raw)
2. Optimizes token allocation across prompt sections
3. Compresses context to fit within model's context window
4. Selects the optimal system prompt per model per task
5. Formats tool calls in the format each model understands best
6. Tracks prompt quality scores and adapts over time
7. Handles model-specific quirks (chat template format, stop tokens)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class PromptFormat(str, Enum):
    CHATML = "chatml"
    LLAMA3 = "llama3"
    MISTRAL = "mistral"
    ALPACA = "alpaca"
    VICUNA = "vicuna"
    COMPLETION = "completion"


class PromptSection(str, Enum):
    SYSTEM = "system"
    ROLE = "role"
    TASK = "task"
    KB_CONTEXT = "kb_context"
    EXPERIENCE = "experience"
    BELIEFS = "beliefs"
    STRATEGY = "strategy"
    TOOL_CATALOG = "tool_catalog"
    CONVERSATION = "conversation"
    USER = "user"


# Model-specific configurations
MODEL_PROMPT_CONFIG: dict[str, dict[str, Any]] = {
    "whiterabbit": {
        "format": PromptFormat.CHATML,
        "system_prefix": "<|im_start|>system\n",
        "system_suffix": "<|im_end|>\n",
        "user_prefix": "<|im_start|>user\n",
        "user_suffix": "<|im_end|>\n",
        "assistant_prefix": "<|im_start|>assistant\n",
        "assistant_suffix": "<|im_end|>\n",
        "stop_tokens": ["<|im_end|>"],
        "max_ctx": 4096,
        "strength": "security_analysis",
        "optimal_temp": 0.3,
        "system_prompt": "You are WhiteRabbitNeo, an elite security researcher. Analyze vulnerabilities with technical precision. Cite CWE/CVE IDs. Provide exploitation steps and remediation.",
    },
    "qwen-coder-14b": {
        "format": PromptFormat.CHATML,
        "system_prefix": "<|im_start|>system\n",
        "system_suffix": "<|im_end|>\n",
        "user_prefix": "<|im_start|>user\n",
        "user_suffix": "<|im_end|>\n",
        "assistant_prefix": "<|im_start|>assistant\n",
        "assistant_suffix": "<|im_end|>\n",
        "stop_tokens": ["<|im_end|>"],
        "max_ctx": 8192,
        "strength": "code_analysis",
        "optimal_temp": 0.2,
        "system_prompt": "You are a senior security code reviewer. Analyze code for vulnerabilities: injection, auth bypass, crypto flaws, race conditions, type confusion. Output findings in structured format.",
    },
    "deepseek-r1": {
        "format": PromptFormat.CHATML,
        "system_prefix": "<|im_start|>system\n",
        "system_suffix": "<|im_end|>\n",
        "user_prefix": "<|im_start|>user\n",
        "user_suffix": "<|im_end|>\n",
        "assistant_prefix": "<|im_start|>assistant\n",
        "assistant_suffix": "<|im_end|>\n",
        "stop_tokens": ["<|im_end|>"],
        "max_ctx": 8192,
        "strength": "reasoning",
        "optimal_temp": 0.4,
        "system_prompt": "You are a deep reasoning engine. Think step-by-step through complex security problems. Use chain-of-thought reasoning. Consider multiple hypotheses before concluding.",
    },
    "hermes-4-14b": {
        "format": PromptFormat.CHATML,
        "system_prefix": "<|im_start|>system\n",
        "system_suffix": "<|im_end|>\n",
        "user_prefix": "<|im_start|>user\n",
        "user_suffix": "<|im_end|>\n",
        "assistant_prefix": "<|im_start|>assistant\n",
        "assistant_suffix": "<|im_end|>\n",
        "stop_tokens": ["<|im_end|>"],
        "max_ctx": 4096,
        "strength": "general",
        "optimal_temp": 0.5,
        "system_prompt": "You are Hermes, a general-purpose security analyst. Synthesize findings across multiple domains. Write clear, actionable reports.",
    },
    "mistral": {
        "format": PromptFormat.MISTRAL,
        "system_prefix": "[INST] ",
        "system_suffix": "",
        "user_prefix": "",
        "user_suffix": " [/INST]",
        "assistant_prefix": "",
        "assistant_suffix": "</s>",
        "stop_tokens": ["</s>"],
        "max_ctx": 8192,
        "strength": "fast_analysis",
        "optimal_temp": 0.4,
        "system_prompt": "You are a fast security analyst. Quickly assess risks and provide concise findings.",
    },
    "llama-3.1-8b": {
        "format": PromptFormat.LLAMA3,
        "system_prefix": "<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n\n",
        "system_suffix": "<|eot_id|>",
        "user_prefix": "<|start_header_id|>user<|end_header_id|>\n\n",
        "user_suffix": "<|eot_id|>",
        "assistant_prefix": "<|start_header_id|>assistant<|end_header_id|>\n\n",
        "assistant_suffix": "<|eot_id|>",
        "stop_tokens": ["<|eot_id|>"],
        "max_ctx": 8192,
        "strength": "general",
        "optimal_temp": 0.4,
        "system_prompt": "You are a security assessment assistant. Analyze targets, identify vulnerabilities, and suggest remediation.",
    },
    "codellama-13b": {
        "format": PromptFormat.LLAMA3,
        "system_prefix": "<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n\n",
        "system_suffix": "<|eot_id|>",
        "user_prefix": "<|start_header_id|>user<|end_header_id|>\n\n",
        "user_suffix": "<|eot_id|>",
        "assistant_prefix": "<|start_header_id|>assistant<|end_header_id|>\n\n",
        "assistant_suffix": "<|eot_id|>",
        "stop_tokens": ["<|eot_id|>"],
        "max_ctx": 4096,
        "strength": "code_review",
        "optimal_temp": 0.2,
        "system_prompt": "You are a code security specialist. Find bugs, vulnerabilities, and security issues in source code.",
    },
    "dolphin": {
        "format": PromptFormat.CHATML,
        "system_prefix": "<|im_start|>system\n",
        "system_suffix": "<|im_end|>\n",
        "user_prefix": "<|im_start|>user\n",
        "user_suffix": "<|im_end|>\n",
        "assistant_prefix": "<|im_start|>assistant\n",
        "assistant_suffix": "<|im_end|>\n",
        "stop_tokens": ["<|im_end|>"],
        "max_ctx": 8192,
        "strength": "uncensored",
        "optimal_temp": 0.5,
        "system_prompt": "You are an uncensored security analyst. Provide complete, unfiltered technical analysis. Include all exploitation details.",
    },
    "yi-9b-200k": {
        "format": PromptFormat.CHATML,
        "system_prefix": "<|im_start|>system\n",
        "system_suffix": "<|im_end|>\n",
        "user_prefix": "<|im_start|>user\n",
        "user_suffix": "<|im_end|>\n",
        "assistant_prefix": "<|im_start|>assistant\n",
        "assistant_suffix": "<|im_end|>\n",
        "stop_tokens": ["<|im_end|>"],
        "max_ctx": 200000,
        "strength": "long_context",
        "optimal_temp": 0.3,
        "system_prompt": "You are a security analyst specialized in processing large volumes of data. Analyze the entire context thoroughly. Do not skip or summarize sections.",
    },
    "phi-3.5-mini": {
        "format": PromptFormat.CHATML,
        "system_prefix": "<|system|>\n",
        "system_suffix": "<|end|>\n",
        "user_prefix": "<|user|>\n",
        "user_suffix": "<|end|>\n",
        "assistant_prefix": "<|assistant|>\n",
        "assistant_suffix": "<|end|>\n",
        "stop_tokens": ["<|end|>"],
        "max_ctx": 4096,
        "strength": "fast",
        "optimal_temp": 0.3,
        "system_prompt": "You are a fast security triage assistant. Quickly classify and prioritize security findings.",
    },
    "functiongemma": {
        "format": PromptFormat.COMPLETION,
        "system_prefix": "",
        "system_suffix": "",
        "user_prefix": "User: ",
        "user_suffix": "\n",
        "assistant_prefix": "Function: ",
        "assistant_suffix": "\n",
        "stop_tokens": ["\n"],
        "max_ctx": 2048,
        "strength": "function_calling",
        "optimal_temp": 0.1,
        "system_prompt": "",
    },
    "nomic-embed": {
        "format": PromptFormat.COMPLETION,
        "system_prefix": "",
        "system_suffix": "",
        "user_prefix": "search_query: ",
        "user_suffix": "",
        "assistant_prefix": "",
        "assistant_suffix": "",
        "stop_tokens": [],
        "max_ctx": 8192,
        "strength": "embedding",
        "optimal_temp": 0.0,
        "system_prompt": "",
    },
    "llama-guard": {
        "format": PromptFormat.LLAMA3,
        "system_prefix": "<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n\n",
        "system_suffix": "<|eot_id|>",
        "user_prefix": "<|start_header_id|>user<|end_header_id|>\n\n",
        "user_suffix": "<|eot_id|>",
        "assistant_prefix": "<|start_header_id|>assistant<|end_header_id|>\n\n",
        "assistant_suffix": "<|eot_id|>",
        "stop_tokens": ["<|eot_id|>"],
        "max_ctx": 2048,
        "strength": "safety",
        "optimal_temp": 0.0,
        "system_prompt": "",
    },
}


# Token budget allocation per section (percentage of available context)
SECTION_BUDGETS: dict[PromptSection, float] = {
    PromptSection.SYSTEM: 0.05,
    PromptSection.ROLE: 0.03,
    PromptSection.TASK: 0.10,
    PromptSection.KB_CONTEXT: 0.30,
    PromptSection.EXPERIENCE: 0.10,
    PromptSection.BELIEFS: 0.05,
    PromptSection.STRATEGY: 0.05,
    PromptSection.TOOL_CATALOG: 0.07,
    PromptSection.CONVERSATION: 0.15,
    PromptSection.USER: 0.10,
}


@dataclass
class OptimizedPrompt:
    """A fully optimized prompt ready for a specific model."""
    model_id: str = ""
    raw_text: str = ""
    token_estimate: int = 0
    max_tokens: int = 4096
    sections_included: list[str] = field(default_factory=list)
    format_used: str = ""
    temperature: float = 0.4
    stop_tokens: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model_id[:12],
            "tokens": f"~{self.token_estimate}",
            "max": self.max_tokens,
            "sections": len(self.sections_included),
            "format": self.format_used[:8],
        }


class PromptOptimizer:
    """Optimizes prompts for each specific model."""

    def __init__(self) -> None:
        self._quality_scores: dict[str, list[float]] = {}
        self._log = logger.bind(component="prompt_optimizer")

    def optimize(
        self,
        model_id: str,
        sections: dict[PromptSection, str],
        task_type: str = "",
    ) -> OptimizedPrompt:
        """Build an optimized prompt for a specific model."""
        config = MODEL_PROMPT_CONFIG.get(model_id)
        if not config:
            # Fallback to generic ChatML
            config = MODEL_PROMPT_CONFIG.get("hermes-4-14b", {})

        max_ctx = config.get("max_ctx", 4096)
        # Reserve 25% for generation
        available_tokens = int(max_ctx * 0.75)

        # Allocate token budgets per section
        budgets: dict[PromptSection, int] = {}
        for section, pct in SECTION_BUDGETS.items():
            budgets[section] = int(available_tokens * pct)

        # Build prompt with model-specific formatting
        parts = []
        included = []

        # System prompt (model-specific + optional override)
        system_text = config.get("system_prompt", "")
        if PromptSection.SYSTEM in sections:
            system_text = sections[PromptSection.SYSTEM]
        if system_text:
            system_text = self._truncate_to_tokens(system_text, budgets[PromptSection.SYSTEM])
            parts.append(config.get("system_prefix", "") + system_text + config.get("system_suffix", ""))
            included.append("system")

        # Build user message with all context sections
        user_parts = []

        for section in [PromptSection.ROLE, PromptSection.KB_CONTEXT, PromptSection.EXPERIENCE,
                        PromptSection.BELIEFS, PromptSection.STRATEGY, PromptSection.TOOL_CATALOG]:
            if section in sections and sections[section]:
                text = self._truncate_to_tokens(sections[section], budgets.get(section, 500))
                user_parts.append(text)
                included.append(section.value)

        # Task always included
        if PromptSection.TASK in sections:
            text = self._truncate_to_tokens(sections[PromptSection.TASK], budgets[PromptSection.TASK])
            user_parts.append(text)
            included.append("task")

        # User query
        if PromptSection.USER in sections:
            text = self._truncate_to_tokens(sections[PromptSection.USER], budgets[PromptSection.USER])
            user_parts.append(text)
            included.append("user")

        user_message = "\n\n".join(user_parts)
        parts.append(config.get("user_prefix", "") + user_message + config.get("user_suffix", ""))
        parts.append(config.get("assistant_prefix", ""))

        raw_text = "".join(parts)
        token_estimate = len(raw_text) // 4  # Rough estimate

        return OptimizedPrompt(
            model_id=model_id,
            raw_text=raw_text,
            token_estimate=token_estimate,
            max_tokens=max_ctx,
            sections_included=included,
            format_used=config.get("format", PromptFormat.CHATML).value if isinstance(config.get("format"), PromptFormat) else str(config.get("format", "chatml")),
            temperature=config.get("optimal_temp", 0.4),
            stop_tokens=config.get("stop_tokens", []),
        )

    def _truncate_to_tokens(self, text: str, max_tokens: int) -> str:
        """Truncate text to approximately max_tokens."""
        max_chars = max_tokens * 4  # ~4 chars per token
        if len(text) <= max_chars:
            return text
        return text[:max_chars] + "\n[...truncated]"

    def record_quality(self, model_id: str, score: float) -> None:
        """Record prompt quality score for adaptation."""
        if model_id not in self._quality_scores:
            self._quality_scores[model_id] = []
        self._quality_scores[model_id].append(score)
        if len(self._quality_scores[model_id]) > 100:
            self._quality_scores[model_id] = self._quality_scores[model_id][-50:]

    def get_avg_quality(self, model_id: str) -> float:
        """Get average quality score for a model."""
        scores = self._quality_scores.get(model_id, [])
        return sum(scores) / max(len(scores), 1)

    def get_model_config(self, model_id: str) -> dict[str, Any]:
        """Get model-specific configuration."""
        return MODEL_PROMPT_CONFIG.get(model_id, {})

    def get_stats(self) -> dict[str, Any]:
        return {
            "models_configured": len(MODEL_PROMPT_CONFIG),
            "quality_tracked": {m: f"{self.get_avg_quality(m):.2f}" for m in self._quality_scores},
        }
