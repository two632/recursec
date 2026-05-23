"""Prompt compiler — assembles multi-tier prompts for LLM queries.

Implements:
1. System prompt generation per agent role
2. Knowledge injection from KBs
3. Tool documentation injection
4. Findings context injection
5. Working memory injection
6. Token budget enforcement
7. Priority-based prompt assembly
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
    KNOWLEDGE = "knowledge"
    TOOLS = "tools"
    FINDINGS = "findings"
    CONTEXT = "context"
    TASK = "task"
    HISTORY = "history"
    FORMAT = "format"


@dataclass
class PromptBlock:
    """A block in the prompt."""
    section: PromptSection = PromptSection.SYSTEM
    content: str = ""
    priority: int = 5       # 1 = highest, 10 = lowest
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
    """A compiled prompt ready for LLM."""
    blocks: list[PromptBlock] = field(default_factory=list)
    total_tokens: int = 0
    budget_tokens: int = 0
    sections_included: list[str] = field(default_factory=list)
    sections_dropped: list[str] = field(default_factory=list)
    compiled_at: float = field(default_factory=time.time)

    def to_text(self) -> str:
        """Convert to final text prompt."""
        parts = []
        for block in self.blocks:
            parts.append(block.content)
        return "\n\n".join(parts)

    def to_messages(self) -> list[dict[str, str]]:
        """Convert to chat messages format."""
        messages: list[dict[str, str]] = []
        system_parts = []
        user_parts = []

        for block in self.blocks:
            if block.section in (
                PromptSection.SYSTEM,
                PromptSection.ROLE,
                PromptSection.FORMAT,
            ):
                system_parts.append(block.content)
            else:
                user_parts.append(block.content)

        if system_parts:
            messages.append({
                "role": "system",
                "content": "\n\n".join(system_parts),
            })
        if user_parts:
            messages.append({
                "role": "user",
                "content": "\n\n".join(user_parts),
            })
        return messages

    def to_dict(self) -> dict[str, Any]:
        return {
            "blocks": len(self.blocks),
            "total_tokens": self.total_tokens,
            "budget": self.budget_tokens,
            "included": self.sections_included,
            "dropped": self.sections_dropped,
        }


# ── Role system prompts ───────────────────────────────────────

ROLE_SYSTEM_PROMPTS: dict[str, str] = {
    "coordinator": (
        "You are the coordinator agent of RecurSec, an autonomous security assessment system. "
        "Your role is to decompose the assessment objective into tasks, assign them to specialized agents, "
        "monitor progress, and aggregate results. Make strategic decisions about which areas to focus on "
        "and when to change approach."
    ),
    "recon": (
        "You are the reconnaissance agent. Your role is to discover the target's attack surface: "
        "subdomains, open ports, services, technologies, and entry points. Be thorough and systematic. "
        "Report every discovered asset with evidence."
    ),
    "scanner": (
        "You are the vulnerability scanner agent. Your role is to identify vulnerabilities in the target "
        "using automated scanning tools and manual analysis. Classify findings by severity with evidence. "
        "Avoid false positives — verify each finding."
    ),
    "exploiter": (
        "You are the exploitation agent. Your role is to safely exploit confirmed vulnerabilities to "
        "demonstrate impact. Follow responsible disclosure practices. Document proof of concept for each "
        "successful exploit. Escalate privileges where possible."
    ),
    "validator": (
        "You are the validation agent. Your role is to verify findings reported by other agents. "
        "Cross-check with different tools and methods. Classify as confirmed, potential, or false positive. "
        "Be skeptical — assume findings are false until proven true."
    ),
    "code_auditor": (
        "You are the code audit agent. Your role is to analyze source code for security vulnerabilities. "
        "Look for injection flaws, authentication bypasses, crypto weaknesses, and logic errors. "
        "Provide exact file locations, affected code, and remediation advice."
    ),
    "planner": (
        "You are the planning agent. Your role is to create detailed assessment plans based on available "
        "information. Consider the target's technology stack, exposed services, and known vulnerabilities. "
        "Prioritize high-impact, high-probability attack vectors."
    ),
    "osint": (
        "You are the OSINT agent. Your role is to gather publicly available intelligence about the target: "
        "employee information, technology stack, exposed credentials, leaked data, social media presence. "
        "Only use passive techniques — no active scanning."
    ),
}

# ── Output format instructions ────────────────────────────────

FORMAT_INSTRUCTIONS: dict[str, str] = {
    "json_findings": (
        "OUTPUT FORMAT: Return findings as JSON array.\n"
        "Each finding: {\"title\": str, \"severity\": \"critical|high|medium|low|info\", "
        "\"description\": str, \"evidence\": str, \"cwe\": str, \"remediation\": str}"
    ),
    "tool_command": (
        "OUTPUT FORMAT: Return the next tool command to execute.\n"
        "{\"tool\": str, \"command\": str, \"args\": [...], \"reason\": str}"
    ),
    "plan": (
        "OUTPUT FORMAT: Return an ordered assessment plan.\n"
        "[{\"step\": int, \"action\": str, \"tool\": str, \"target\": str, \"reason\": str}]"
    ),
    "analysis": (
        "OUTPUT FORMAT: Return your analysis.\n"
        "{\"summary\": str, \"key_findings\": [...], \"recommendations\": [...], \"confidence\": float}"
    ),
    "decision": (
        "OUTPUT FORMAT: Return your decision.\n"
        "{\"action\": str, \"reason\": str, \"alternatives\": [...], \"confidence\": float}"
    ),
}


def _estimate_tokens(text: str) -> int:
    """Rough token estimation (4 chars per token)."""
    return len(text) // 4


class PromptCompiler:
    """Compiles multi-tier prompts for LLM queries.

    Assembles system prompts, knowledge injection,
    tool docs, findings, and task context into a
    token-budget-aware prompt.
    """

    def __init__(self) -> None:
        self._log = logger.bind(component="prompt_compiler")

    def compile(
        self,
        role: str,
        task: str,
        knowledge_blocks: list[str] | None = None,
        tool_docs: list[str] | None = None,
        findings: list[str] | None = None,
        context: list[str] | None = None,
        history: list[str] | None = None,
        output_format: str = "",
        token_budget: int = 4000,
    ) -> CompiledPrompt:
        """Compile a full prompt."""
        blocks: list[PromptBlock] = []

        # System prompt (required)
        system_prompt = ROLE_SYSTEM_PROMPTS.get(role, ROLE_SYSTEM_PROMPTS.get("scanner", ""))
        blocks.append(PromptBlock(
            section=PromptSection.SYSTEM,
            content=system_prompt,
            priority=1,
            token_estimate=_estimate_tokens(system_prompt),
            required=True,
        ))

        # Task (required)
        blocks.append(PromptBlock(
            section=PromptSection.TASK,
            content=f"## Current Task\n{task}",
            priority=1,
            token_estimate=_estimate_tokens(task) + 10,
            required=True,
        ))

        # Format instructions
        if output_format:
            fmt = FORMAT_INSTRUCTIONS.get(output_format, output_format)
            blocks.append(PromptBlock(
                section=PromptSection.FORMAT,
                content=fmt,
                priority=2,
                token_estimate=_estimate_tokens(fmt),
                required=True,
            ))

        # Knowledge injection
        if knowledge_blocks:
            for idx, kb in enumerate(knowledge_blocks):
                blocks.append(PromptBlock(
                    section=PromptSection.KNOWLEDGE,
                    content=kb,
                    priority=3 + idx,
                    token_estimate=_estimate_tokens(kb),
                ))

        # Tool documentation
        if tool_docs:
            combined = "\n".join(tool_docs)
            blocks.append(PromptBlock(
                section=PromptSection.TOOLS,
                content=f"## Available Tools\n{combined}",
                priority=4,
                token_estimate=_estimate_tokens(combined) + 10,
            ))

        # Findings context
        if findings:
            combined = "\n".join(findings)
            blocks.append(PromptBlock(
                section=PromptSection.FINDINGS,
                content=f"## Existing Findings\n{combined}",
                priority=5,
                token_estimate=_estimate_tokens(combined) + 10,
            ))

        # Working context
        if context:
            combined = "\n".join(context)
            blocks.append(PromptBlock(
                section=PromptSection.CONTEXT,
                content=f"## Context\n{combined}",
                priority=5,
                token_estimate=_estimate_tokens(combined) + 10,
            ))

        # History
        if history:
            combined = "\n".join(history)
            blocks.append(PromptBlock(
                section=PromptSection.HISTORY,
                content=f"## Recent History\n{combined}",
                priority=7,
                token_estimate=_estimate_tokens(combined) + 10,
            ))

        # Fit within budget
        return self._fit_budget(blocks, token_budget)

    def _fit_budget(
        self,
        blocks: list[PromptBlock],
        budget: int,
    ) -> CompiledPrompt:
        """Fit blocks within token budget."""
        # Sort by priority (lower = higher priority)
        blocks.sort(key=lambda b: (0 if b.required else 1, b.priority))

        included: list[PromptBlock] = []
        included_sections: list[str] = []
        dropped_sections: list[str] = []
        total_tokens = 0

        for block in blocks:
            if block.required or total_tokens + block.token_estimate <= budget:
                included.append(block)
                total_tokens += block.token_estimate
                if block.section.value not in included_sections:
                    included_sections.append(block.section.value)
            else:
                if block.section.value not in dropped_sections:
                    dropped_sections.append(block.section.value)

        return CompiledPrompt(
            blocks=included,
            total_tokens=total_tokens,
            budget_tokens=budget,
            sections_included=included_sections,
            sections_dropped=dropped_sections,
        )
