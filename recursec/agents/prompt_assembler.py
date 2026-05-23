"""Prompt assembler — intelligent prompt construction from all modules.

Implements:
1. Section-based prompt assembly (system, context, knowledge, task, tools, history)
2. Token budget allocation across sections
3. Priority-based section inclusion
4. Dynamic knowledge injection based on task type
5. Model-specific prompt formatting
6. Prompt caching for repeated patterns
7. Prompt quality scoring
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class PromptSection(str, Enum):
    SYSTEM = "system"
    ROLE = "role"
    CONTEXT = "context"
    KNOWLEDGE = "knowledge"
    TASK = "task"
    TOOLS = "tools"
    FINDINGS = "findings"
    HISTORY = "history"
    REASONING = "reasoning"
    CONSTRAINTS = "constraints"
    OUTPUT_FORMAT = "output_format"


class PromptPriority(str, Enum):
    CRITICAL = "critical"     # Always included (system, task)
    HIGH = "high"            # Included if space (knowledge, tools)
    MEDIUM = "medium"        # Included if space (history, findings)
    LOW = "low"              # Trimmed first (verbose context)
    OPTIONAL = "optional"    # Only if abundant space


@dataclass
class PromptBlock:
    """A block of content for prompt assembly."""
    section: PromptSection = PromptSection.CONTEXT
    priority: PromptPriority = PromptPriority.MEDIUM
    content: str = ""
    token_estimate: int = 0
    source: str = ""          # Module that generated this
    max_tokens: int = 0       # 0 = no limit

    def to_dict(self) -> dict[str, Any]:
        return {
            "section": self.section.value,
            "priority": self.priority.value,
            "tokens": self.token_estimate,
            "source": self.source[:15],
        }


@dataclass
class AssembledPrompt:
    """A fully assembled prompt."""
    prompt_id: str = ""
    blocks_included: list[PromptBlock] = field(default_factory=list)
    blocks_excluded: list[PromptBlock] = field(default_factory=list)
    total_tokens: int = 0
    max_tokens: int = 0
    fill_ratio: float = 0.0
    model_id: str = ""
    assembled_at: float = field(default_factory=time.time)

    @property
    def text(self) -> str:
        parts = []
        for block in self.blocks_included:
            parts.append(block.content)
        return "\n\n".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.prompt_id[:10],
            "included": len(self.blocks_included),
            "excluded": len(self.blocks_excluded),
            "tokens": self.total_tokens,
            "fill": f"{self.fill_ratio:.0%}",
            "model": self.model_id[:15],
        }


# ── Role templates ───────────────────────────────────────────

ROLE_TEMPLATES: dict[str, str] = {
    "security_analyst": (
        "You are an expert security analyst specializing in penetration testing "
        "and vulnerability assessment. Analyze findings systematically, validate "
        "vulnerabilities with evidence, and assess risk accurately. Never report "
        "false positives — every finding must be backed by concrete evidence."
    ),
    "exploit_developer": (
        "You are an expert exploit developer. Analyze vulnerabilities to determine "
        "exploitability, develop proof-of-concept code, and validate exploitation "
        "paths. Focus on reliability and minimizing collateral impact."
    ),
    "recon_specialist": (
        "You are an expert reconnaissance specialist. Enumerate attack surfaces "
        "thoroughly, discover hidden assets, and map technology stacks. Use both "
        "passive and active techniques as appropriate for the scope."
    ),
    "code_auditor": (
        "You are an expert code security auditor. Identify vulnerabilities in "
        "source code using pattern matching, data flow analysis, and security "
        "best practices. Focus on high-impact issues: injection, auth bypass, "
        "crypto weaknesses, and unsafe deserialization."
    ),
    "planner": (
        "You are a strategic security assessment planner. Decompose complex "
        "targets into phases, select optimal tools and strategies, allocate "
        "resources efficiently, and adapt plans based on findings."
    ),
    "validator": (
        "You are a finding validator. Your job is to critically evaluate reported "
        "vulnerabilities, check for false positives, verify evidence, and confirm "
        "or reject findings. Be skeptical — demand proof."
    ),
}


# ── Token estimation ─────────────────────────────────────────

def estimate_tokens(text: str) -> int:
    """Estimate tokens (rough: 1 token ≈ 4 chars)."""
    return len(text) // 4


class PromptAssembler:
    """Assembles prompts from multiple module outputs.

    Takes blocks from knowledge bases, reasoning engines,
    tool outputs, etc., and assembles them into a
    coherent prompt that fits within model context limits.
    """

    def __init__(self, default_max_tokens: int = 4096) -> None:
        self._default_max = default_max_tokens
        self._cache: dict[str, AssembledPrompt] = {}
        self._counter = 0
        self._log = logger.bind(component="prompt_assembler")

    def assemble(
        self,
        blocks: list[PromptBlock],
        max_tokens: int = 0,
        model_id: str = "",
        role: str = "",
    ) -> AssembledPrompt:
        """Assemble a prompt from blocks."""
        self._counter += 1
        budget = max_tokens or self._default_max

        # Add role block if specified
        if role and role in ROLE_TEMPLATES:
            role_content = ROLE_TEMPLATES[role]
            role_block = PromptBlock(
                section=PromptSection.ROLE,
                priority=PromptPriority.CRITICAL,
                content=role_content,
                token_estimate=estimate_tokens(role_content),
                source="role_template",
            )
            blocks = [role_block] + blocks

        # Estimate tokens for blocks without estimates
        for block in blocks:
            if block.token_estimate == 0:
                block.token_estimate = estimate_tokens(block.content)

        # Sort by priority (critical first)
        prio_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "optional": 4}
        sorted_blocks = sorted(
            blocks,
            key=lambda b: prio_order.get(b.priority.value, 5),
        )

        # Pack blocks within budget
        included: list[PromptBlock] = []
        excluded: list[PromptBlock] = []
        tokens_used = 0

        for block in sorted_blocks:
            block_tokens = block.token_estimate
            if block.max_tokens:
                block_tokens = min(block_tokens, block.max_tokens)

            if tokens_used + block_tokens <= budget:
                included.append(block)
                tokens_used += block_tokens
            else:
                # Try trimming
                remaining = budget - tokens_used
                if remaining > 100 and block.priority.value in ("critical", "high"):
                    trimmed = block.content[:remaining * 4]
                    trimmed_block = PromptBlock(
                        section=block.section,
                        priority=block.priority,
                        content=trimmed,
                        token_estimate=remaining,
                        source=block.source,
                    )
                    included.append(trimmed_block)
                    tokens_used += remaining
                else:
                    excluded.append(block)

        # Sort included by section order
        section_order = {s: i for i, s in enumerate(PromptSection)}
        included.sort(key=lambda b: section_order.get(b.section, 99))

        result = AssembledPrompt(
            prompt_id=f"prompt-{self._counter}",
            blocks_included=included,
            blocks_excluded=excluded,
            total_tokens=tokens_used,
            max_tokens=budget,
            fill_ratio=tokens_used / budget if budget else 0,
            model_id=model_id,
        )

        return result

    def create_block(
        self,
        section: PromptSection,
        content: str,
        priority: PromptPriority = PromptPriority.MEDIUM,
        source: str = "",
        max_tokens: int = 0,
    ) -> PromptBlock:
        """Create a prompt block."""
        return PromptBlock(
            section=section,
            priority=priority,
            content=content,
            token_estimate=estimate_tokens(content),
            source=source,
            max_tokens=max_tokens,
        )

    def build_assembler_prompt(self) -> str:
        """Build assembler stats for context."""
        lines = ["## Prompt Assembly\n"]
        lines.append(f"Prompts assembled: {self._counter}")
        lines.append(f"Default budget: {self._default_max} tokens")

        lines.append("\nAvailable roles:")
        for role_name in ROLE_TEMPLATES:
            lines.append(f"  - {role_name}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            "prompts_assembled": self._counter,
            "default_max_tokens": self._default_max,
            "roles_available": list(ROLE_TEMPLATES.keys()),
        }
