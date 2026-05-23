"""Prompt compiler — builds optimal prompts for LLM agents.

Implements:
1. Dynamic system prompt construction
2. Knowledge base injection into prompts
3. Context window management
4. Token budget allocation
5. Tool documentation injection
6. Finding context injection
7. Prompt templating and composition
8. Model-specific prompt formatting
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class PromptSection(str, Enum):
    SYSTEM = "system"
    ROLE = "role"
    GOAL = "goal"
    CONTEXT = "context"
    KNOWLEDGE = "knowledge"
    TOOLS = "tools"
    FINDINGS = "findings"
    CONSTRAINTS = "constraints"
    EXAMPLES = "examples"
    HISTORY = "history"
    OUTPUT_FORMAT = "output_format"


class ModelFormat(str, Enum):
    CHATML = "chatml"
    LLAMA = "llama"
    MISTRAL = "mistral"
    ALPACA = "alpaca"
    VICUNA = "vicuna"
    PHI = "phi"
    DEEPSEEK = "deepseek"
    GENERIC = "generic"


@dataclass
class PromptBlock:
    """A block of content in a prompt."""
    section: PromptSection = PromptSection.CONTEXT
    content: str = ""
    priority: int = 5            # 1-10, higher = more important
    token_estimate: int = 0
    required: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "section": self.section.value,
            "priority": self.priority,
            "tokens": self.token_estimate,
            "required": self.required,
        }


@dataclass
class CompiledPrompt:
    """A compiled prompt ready for LLM submission."""
    model: str = ""
    system_prompt: str = ""
    user_prompt: str = ""
    total_tokens_estimate: int = 0
    sections_included: list[str] = field(default_factory=list)
    sections_dropped: list[str] = field(default_factory=list)
    compiled_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model[:15],
            "tokens": self.total_tokens_estimate,
            "included": len(self.sections_included),
            "dropped": len(self.sections_dropped),
        }


# ── Model format templates ───────────────────────────────────

FORMAT_TEMPLATES: dict[str, dict[str, str]] = {
    "chatml": {
        "system_prefix": "<|im_start|>system\n",
        "system_suffix": "<|im_end|>\n",
        "user_prefix": "<|im_start|>user\n",
        "user_suffix": "<|im_end|>\n",
        "assistant_prefix": "<|im_start|>assistant\n",
        "assistant_suffix": "<|im_end|>\n",
    },
    "llama": {
        "system_prefix": "<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n\n",
        "system_suffix": "<|eot_id|>\n",
        "user_prefix": "<|start_header_id|>user<|end_header_id|>\n\n",
        "user_suffix": "<|eot_id|>\n",
        "assistant_prefix": "<|start_header_id|>assistant<|end_header_id|>\n\n",
        "assistant_suffix": "<|eot_id|>\n",
    },
    "mistral": {
        "system_prefix": "[INST] ",
        "system_suffix": " [/INST]\n",
        "user_prefix": "[INST] ",
        "user_suffix": " [/INST]\n",
        "assistant_prefix": "",
        "assistant_suffix": "</s>\n",
    },
    "phi": {
        "system_prefix": "<|system|>\n",
        "system_suffix": "<|end|>\n",
        "user_prefix": "<|user|>\n",
        "user_suffix": "<|end|>\n",
        "assistant_prefix": "<|assistant|>\n",
        "assistant_suffix": "<|end|>\n",
    },
    "deepseek": {
        "system_prefix": "<|begin▁of▁sentence|>",
        "system_suffix": "\n",
        "user_prefix": "User: ",
        "user_suffix": "\n",
        "assistant_prefix": "Assistant: ",
        "assistant_suffix": "\n",
    },
    "generic": {
        "system_prefix": "### System:\n",
        "system_suffix": "\n",
        "user_prefix": "### User:\n",
        "user_suffix": "\n",
        "assistant_prefix": "### Assistant:\n",
        "assistant_suffix": "\n",
    },
}

# ── Model→Format mapping ─────────────────────────────────────

MODEL_FORMATS: dict[str, str] = {
    "whiterabbitneo-7b": "chatml",
    "qwen-coder-14b": "chatml",
    "qwen-coder-7b": "chatml",
    "deepseek-r1-7b": "deepseek",
    "deepseek-math-7b": "deepseek",
    "hermes-14b": "chatml",
    "llama-3.1-8b": "llama",
    "dolphin-8b": "chatml",
    "mistral-7b": "mistral",
    "codellama-13b": "llama",
    "codellama-7b": "llama",
    "yi-9b-200k": "chatml",
    "phi-3.5-mini": "phi",
    "llama-guard-3": "llama",
    "functiongemma": "generic",
    "nomic-embed": "generic",
}


class PromptCompiler:
    """Builds optimal prompts for LLM agents.

    Manages prompt construction with:
    - Knowledge base injection
    - Context window fitting
    - Model-specific formatting
    - Priority-based section dropping
    """

    def __init__(self, default_max_tokens: int = 4096) -> None:
        self._default_max_tokens = default_max_tokens
        self._log = logger.bind(component="prompt_compiler")
        self._compile_count = 0

    def compile(
        self,
        blocks: list[PromptBlock],
        model: str = "",
        max_tokens: int = 0,
    ) -> CompiledPrompt:
        """Compile prompt blocks into a formatted prompt."""
        max_tokens = max_tokens or self._default_max_tokens
        self._compile_count += 1

        # Estimate tokens for each block (rough: 4 chars per token)
        for block in blocks:
            if block.token_estimate == 0:
                block.token_estimate = len(block.content) // 4

        # Sort by priority (required first, then by priority desc)
        sorted_blocks = sorted(
            blocks,
            key=lambda b: (not b.required, -b.priority),
        )

        # Fit blocks within token budget
        included: list[PromptBlock] = []
        dropped: list[PromptBlock] = []
        remaining_tokens = max_tokens

        for block in sorted_blocks:
            if block.token_estimate <= remaining_tokens:
                included.append(block)
                remaining_tokens -= block.token_estimate
            elif block.required:
                # Truncate required blocks to fit
                available_chars = remaining_tokens * 4
                block.content = block.content[:available_chars]
                block.token_estimate = remaining_tokens
                included.append(block)
                remaining_tokens = 0
            else:
                dropped.append(block)

        # Group by section
        section_content: dict[PromptSection, list[str]] = defaultdict(list)
        for block in included:
            section_content[block.section].append(block.content)

        # Build system prompt
        system_parts = []
        for section in [PromptSection.SYSTEM, PromptSection.ROLE,
                        PromptSection.CONSTRAINTS, PromptSection.TOOLS,
                        PromptSection.OUTPUT_FORMAT]:
            if section in section_content:
                system_parts.extend(section_content[section])

        # Build user prompt
        user_parts = []
        for section in [PromptSection.GOAL, PromptSection.CONTEXT,
                        PromptSection.KNOWLEDGE, PromptSection.FINDINGS,
                        PromptSection.EXAMPLES, PromptSection.HISTORY]:
            if section in section_content:
                user_parts.extend(section_content[section])

        # Apply model format
        system_prompt = "\n\n".join(system_parts)
        user_prompt = "\n\n".join(user_parts)

        if model:
            fmt_name = MODEL_FORMATS.get(model, "generic")
            fmt = FORMAT_TEMPLATES.get(fmt_name, FORMAT_TEMPLATES["generic"])
            system_prompt = fmt["system_prefix"] + system_prompt + fmt["system_suffix"]
            user_prompt = fmt["user_prefix"] + user_prompt + fmt["user_suffix"]

        return CompiledPrompt(
            model=model,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            total_tokens_estimate=max_tokens - remaining_tokens,
            sections_included=[b.section.value for b in included],
            sections_dropped=[b.section.value for b in dropped],
        )

    def build_security_prompt(
        self,
        role: str,
        goal: str,
        target: str,
        tools: list[str],
        findings: list[dict[str, Any]] | None = None,
        knowledge: str = "",
        history: str = "",
        model: str = "",
        max_tokens: int = 0,
    ) -> CompiledPrompt:
        """Build a complete security assessment prompt."""
        blocks = [
            PromptBlock(
                section=PromptSection.SYSTEM,
                content="You are a security assessment agent. Follow instructions precisely. Output structured findings.",
                priority=10,
                required=True,
            ),
            PromptBlock(
                section=PromptSection.ROLE,
                content=f"Role: {role}",
                priority=9,
                required=True,
            ),
            PromptBlock(
                section=PromptSection.GOAL,
                content=f"Goal: {goal}\nTarget: {target}",
                priority=9,
                required=True,
            ),
            PromptBlock(
                section=PromptSection.CONSTRAINTS,
                content=(
                    "Constraints:\n"
                    "- Only test authorized targets\n"
                    "- Minimize destructive actions\n"
                    "- Validate findings before reporting\n"
                    "- Use structured JSON output for findings"
                ),
                priority=8,
                required=True,
            ),
        ]

        # Tools
        if tools:
            tool_doc = "Available tools:\n" + "\n".join(f"- {t}" for t in tools)
            blocks.append(PromptBlock(
                section=PromptSection.TOOLS,
                content=tool_doc,
                priority=7,
            ))

        # Knowledge injection
        if knowledge:
            blocks.append(PromptBlock(
                section=PromptSection.KNOWLEDGE,
                content=knowledge,
                priority=6,
            ))

        # Existing findings
        if findings:
            finding_text = "Current findings:\n"
            for f in findings[:10]:
                finding_text += f"- [{f.get('severity', 'unknown')}] {f.get('title', '')}\n"
            blocks.append(PromptBlock(
                section=PromptSection.FINDINGS,
                content=finding_text,
                priority=5,
            ))

        # History
        if history:
            blocks.append(PromptBlock(
                section=PromptSection.HISTORY,
                content=history,
                priority=3,
            ))

        # Output format
        blocks.append(PromptBlock(
            section=PromptSection.OUTPUT_FORMAT,
            content=(
                "Output format:\n"
                "1. ANALYSIS: Brief analysis of current state\n"
                "2. NEXT_ACTION: What tool/command to run next\n"
                "3. RATIONALE: Why this action\n"
                "4. FINDINGS: Any new findings in JSON"
            ),
            priority=8,
        ))

        return self.compile(blocks, model=model, max_tokens=max_tokens)

    def build_reasoning_prompt(
        self,
        question: str,
        evidence: list[str],
        model: str = "",
        max_tokens: int = 0,
    ) -> CompiledPrompt:
        """Build a reasoning/chain-of-thought prompt."""
        blocks = [
            PromptBlock(
                section=PromptSection.SYSTEM,
                content=(
                    "You are a security reasoning engine. Think step by step.\n"
                    "For each step:\n"
                    "1. State what you observe\n"
                    "2. Form a hypothesis\n"
                    "3. Consider evidence for and against\n"
                    "4. Draw a conclusion with confidence level"
                ),
                priority=10,
                required=True,
            ),
            PromptBlock(
                section=PromptSection.GOAL,
                content=f"Question: {question}",
                priority=9,
                required=True,
            ),
        ]

        if evidence:
            ev_text = "Evidence:\n" + "\n".join(f"- {e}" for e in evidence)
            blocks.append(PromptBlock(
                section=PromptSection.CONTEXT,
                content=ev_text,
                priority=7,
            ))

        return self.compile(blocks, model=model, max_tokens=max_tokens)

    def build_validation_prompt(
        self,
        finding: dict[str, Any],
        model: str = "",
        max_tokens: int = 0,
    ) -> CompiledPrompt:
        """Build a finding validation prompt."""
        blocks = [
            PromptBlock(
                section=PromptSection.SYSTEM,
                content=(
                    "You are a security finding validator. Your job is to:\n"
                    "1. Assess if the finding is a true positive or false positive\n"
                    "2. Suggest verification steps\n"
                    "3. Rate confidence (0.0 to 1.0)\n"
                    "4. Suggest remediation if confirmed"
                ),
                priority=10,
                required=True,
            ),
            PromptBlock(
                section=PromptSection.GOAL,
                content=(
                    f"Finding to validate:\n"
                    f"Title: {finding.get('title', '')}\n"
                    f"Severity: {finding.get('severity', '')}\n"
                    f"Description: {finding.get('description', '')}\n"
                    f"Evidence: {finding.get('evidence', '')}"
                ),
                priority=9,
                required=True,
            ),
        ]

        return self.compile(blocks, model=model, max_tokens=max_tokens)

    def get_stats(self) -> dict[str, Any]:
        return {
            "compiles": self._compile_count,
            "supported_formats": list(FORMAT_TEMPLATES.keys()),
            "model_mappings": len(MODEL_FORMATS),
        }
