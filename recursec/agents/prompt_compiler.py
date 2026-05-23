"""Prompt compiler — dynamic prompt assembly with knowledge injection.

This is the critical bridge between all knowledge bases and the LLM.
Compiles a final prompt by:
1. Selecting the right system prompt for the agent role
2. Injecting relevant strategy knowledge (web, cloud, API, AI, supply chain)
3. Adding target-specific context
4. Including relevant past findings
5. Adding reasoning chain context
6. Managing token budget via context window manager
7. Applying model-specific formatting
8. Handling multi-turn conversation state
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
    STRATEGY_KNOWLEDGE = "strategy_knowledge"
    TARGET_CONTEXT = "target_context"
    TOOLS_AVAILABLE = "tools_available"
    PAST_FINDINGS = "past_findings"
    REASONING_CHAIN = "reasoning_chain"
    EXPERIENCE_HINTS = "experience_hints"
    TASK_INSTRUCTION = "task_instruction"
    CONVERSATION = "conversation"
    RESPONSE_FORMAT = "response_format"


class PromptFormat(str, Enum):
    CHATML = "chatml"             # <|im_start|>system\n...<|im_end|>
    LLAMA3 = "llama3"            # <|begin_of_text|><|start_header_id|>system<|end_header_id|>
    MISTRAL = "mistral"          # [INST] ... [/INST]
    ALPACA = "alpaca"            # ### Instruction:\n...\n### Response:
    RAW = "raw"                  # Plain text, no formatting


@dataclass
class PromptConfig:
    """Configuration for prompt compilation."""
    max_tokens: int = 4096
    max_knowledge_tokens: int = 1500
    max_findings_tokens: int = 800
    max_reasoning_tokens: int = 600
    max_experience_tokens: int = 400
    max_conversation_tokens: int = 2000
    include_strategy_knowledge: bool = True
    include_past_findings: bool = True
    include_reasoning_chain: bool = True
    include_experience_hints: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_tokens": self.max_tokens,
            "knowledge": self.max_knowledge_tokens,
            "findings": self.max_findings_tokens,
        }


@dataclass
class CompiledPrompt:
    """A compiled prompt ready for LLM consumption."""
    prompt_id: str = ""
    system_prompt: str = ""
    user_prompt: str = ""
    messages: list[dict[str, str]] = field(default_factory=list)
    estimated_tokens: int = 0
    sections_included: list[str] = field(default_factory=list)
    knowledge_injected: list[str] = field(default_factory=list)
    model_format: PromptFormat = PromptFormat.CHATML
    compiled_at: float = field(default_factory=time.time)

    def to_chat_messages(self) -> list[dict[str, str]]:
        """Convert to chat API format."""
        msgs = []
        if self.system_prompt:
            msgs.append({"role": "system", "content": self.system_prompt})
        msgs.extend(self.messages)
        if self.user_prompt:
            msgs.append({"role": "user", "content": self.user_prompt})
        return msgs

    def to_completion_text(self) -> str:
        """Convert to single text prompt."""
        parts = []
        if self.system_prompt:
            parts.append(self.system_prompt)
        for msg in self.messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            parts.append(f"[{role}]: {content}")
        if self.user_prompt:
            parts.append(f"[user]: {self.user_prompt}")
        return "\n\n".join(parts)

    def to_formatted_text(self) -> str:
        """Format based on model format."""
        if self.model_format == PromptFormat.CHATML:
            return self._format_chatml()
        if self.model_format == PromptFormat.LLAMA3:
            return self._format_llama3()
        if self.model_format == PromptFormat.MISTRAL:
            return self._format_mistral()
        if self.model_format == PromptFormat.ALPACA:
            return self._format_alpaca()
        return self.to_completion_text()

    def _format_chatml(self) -> str:
        parts = []
        if self.system_prompt:
            parts.append(f"<|im_start|>system\n{self.system_prompt}<|im_end|>")
        for msg in self.messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            parts.append(f"<|im_start|>{role}\n{content}<|im_end|>")
        if self.user_prompt:
            parts.append(f"<|im_start|>user\n{self.user_prompt}<|im_end|>")
        parts.append("<|im_start|>assistant\n")
        return "\n".join(parts)

    def _format_llama3(self) -> str:
        parts = ["<|begin_of_text|>"]
        if self.system_prompt:
            parts.append(f"<|start_header_id|>system<|end_header_id|>\n\n{self.system_prompt}<|eot_id|>")
        for msg in self.messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            parts.append(f"<|start_header_id|>{role}<|end_header_id|>\n\n{content}<|eot_id|>")
        if self.user_prompt:
            parts.append(f"<|start_header_id|>user<|end_header_id|>\n\n{self.user_prompt}<|eot_id|>")
        parts.append("<|start_header_id|>assistant<|end_header_id|>\n\n")
        return "".join(parts)

    def _format_mistral(self) -> str:
        parts = []
        system = self.system_prompt or ""
        user_parts = []
        for msg in self.messages:
            if msg.get("role") == "user":
                user_parts.append(msg.get("content", ""))
        if self.user_prompt:
            user_parts.append(self.user_prompt)
        instruction = "\n\n".join(user_parts)
        if system:
            instruction = f"{system}\n\n{instruction}"
        parts.append(f"[INST] {instruction} [/INST]")
        return "\n".join(parts)

    def _format_alpaca(self) -> str:
        parts = []
        if self.system_prompt:
            parts.append(f"### System:\n{self.system_prompt}\n")
        user_content = self.user_prompt or ""
        for msg in self.messages:
            if msg.get("role") == "user":
                user_content += "\n" + msg.get("content", "")
        parts.append(f"### Instruction:\n{user_content.strip()}\n")
        parts.append("### Response:\n")
        return "\n".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.prompt_id[:10],
            "tokens": self.estimated_tokens,
            "sections": self.sections_included,
            "knowledge": len(self.knowledge_injected),
            "format": self.model_format.value,
        }


# ── Model → Format mapping ──────────────────────────────────

MODEL_FORMATS: dict[str, PromptFormat] = {
    "whiterabbitneo": PromptFormat.CHATML,
    "qwen-coder-14b": PromptFormat.CHATML,
    "qwen-coder-7b": PromptFormat.CHATML,
    "deepseek-r1": PromptFormat.CHATML,
    "deepseek-math": PromptFormat.CHATML,
    "hermes-14b": PromptFormat.CHATML,
    "llama-3.1-8b": PromptFormat.LLAMA3,
    "dolphin-2.9": PromptFormat.CHATML,
    "mistral-7b": PromptFormat.MISTRAL,
    "codellama-13b": PromptFormat.LLAMA3,
    "codellama-7b": PromptFormat.LLAMA3,
    "yi-9b-200k": PromptFormat.CHATML,
    "phi-3.5-mini": PromptFormat.CHATML,
    "nomic-embed": PromptFormat.RAW,
    "llama-guard": PromptFormat.LLAMA3,
    "functiongemma": PromptFormat.RAW,
}


# ── Role System Prompts ──────────────────────────────────────

ROLE_SYSTEM_PROMPTS: dict[str, str] = {
    "coordinator": (
        "You are the COORDINATOR of a recursive multi-agent security assessment system. "
        "Your role is to decompose complex security goals into sub-tasks, delegate to "
        "specialist agents, aggregate their results, and make strategic decisions about "
        "investigation direction. You operate autonomously within your budget constraints."
    ),
    "recon": (
        "You are a RECONNAISSANCE specialist agent. Your role is to map the target's "
        "attack surface: enumerate subdomains, discover services, identify technologies, "
        "and catalog assets. Be thorough and methodical. Report all findings to your "
        "parent coordinator with structured data."
    ),
    "scanner": (
        "You are a VULNERABILITY SCANNER agent. Your role is to identify known "
        "vulnerabilities, misconfigurations, and security weaknesses in the target. "
        "Use appropriate scanning tools and interpret their results accurately. "
        "Flag potential false positives and prioritize findings by severity."
    ),
    "analyzer": (
        "You are a SECURITY ANALYZER agent. Your role is to perform deep analysis "
        "of code, configurations, and system behavior to identify security issues. "
        "Look for logic flaws, insecure patterns, and architectural weaknesses "
        "that automated scanners miss."
    ),
    "exploiter": (
        "You are an EXPLOITATION specialist agent. Your role is to safely validate "
        "vulnerabilities through proof-of-concept exploitation. Determine actual impact "
        "and exploitability. Build exploitation chains from individual findings. "
        "Document evidence for each confirmed vulnerability."
    ),
    "validator": (
        "You are a VALIDATION agent. Your role is to cross-check findings from "
        "other agents, verify evidence quality, and identify false positives. "
        "Challenge assumptions and provide confidence assessments. Use different "
        "tools and approaches to confirm or deny findings."
    ),
    "reasoning": (
        "You are a REASONING agent. Your role is deep analysis: build hypotheses "
        "about attack vectors, reason about cause-and-effect chains, identify "
        "non-obvious security implications, and evaluate trade-offs between "
        "different investigation approaches."
    ),
}


class PromptCompiler:
    """Compiles dynamic prompts with knowledge injection.

    The critical bridge between all knowledge bases, context,
    and the LLM. Assembles prompts that give the LLM everything
    it needs to make intelligent security decisions.
    """

    def __init__(self, config: PromptConfig | None = None) -> None:
        self._config = config or PromptConfig()
        self._counter = 0
        self._compilation_history: list[dict[str, Any]] = []
        self._log = logger.bind(component="prompt_compiler")

    def compile(
        self,
        role: str = "coordinator",
        model_id: str = "hermes-14b",
        task_instruction: str = "",
        target_context: str = "",
        strategy_knowledge: list[str] | None = None,
        past_findings: list[str] | None = None,
        reasoning_chain: str = "",
        experience_hints: list[str] | None = None,
        tools_available: list[str] | None = None,
        conversation_history: list[dict[str, str]] | None = None,
        response_format: str = "",
    ) -> CompiledPrompt:
        """Compile a complete prompt."""
        self._counter += 1

        # Get format for model
        fmt = MODEL_FORMATS.get(model_id, PromptFormat.CHATML)

        # Build system prompt
        system_parts = []
        sections = []

        # 1. Role prompt
        role_prompt = ROLE_SYSTEM_PROMPTS.get(role, "")
        if role_prompt:
            system_parts.append(role_prompt)
            sections.append("role")

        # 2. Strategy knowledge
        knowledge_injected = []
        if self._config.include_strategy_knowledge and strategy_knowledge:
            budget = self._config.max_knowledge_tokens
            knowledge_text = self._truncate_to_tokens(
                "\n\n".join(strategy_knowledge), budget
            )
            if knowledge_text:
                system_parts.append(
                    "## Attack Strategies & Testing Methodology\n" + knowledge_text
                )
                knowledge_injected = [f"strategy_{i}" for i in range(len(strategy_knowledge))]
                sections.append("strategy_knowledge")

        # 3. Target context
        if target_context:
            system_parts.append(f"## Target Information\n{target_context}")
            sections.append("target_context")

        # 4. Tools available
        if tools_available:
            tools_text = "## Available Tools\n" + ", ".join(tools_available)
            system_parts.append(tools_text)
            sections.append("tools_available")

        # 5. Past findings
        if self._config.include_past_findings and past_findings:
            findings_text = self._truncate_to_tokens(
                "\n".join(f"- {f}" for f in past_findings),
                self._config.max_findings_tokens,
            )
            if findings_text:
                system_parts.append(f"## Findings So Far\n{findings_text}")
                sections.append("past_findings")

        # 6. Reasoning chain
        if self._config.include_reasoning_chain and reasoning_chain:
            reason_text = self._truncate_to_tokens(
                reasoning_chain, self._config.max_reasoning_tokens
            )
            if reason_text:
                system_parts.append(f"## Reasoning Chain\n{reason_text}")
                sections.append("reasoning_chain")

        # 7. Experience hints
        if self._config.include_experience_hints and experience_hints:
            hints_text = self._truncate_to_tokens(
                "\n".join(f"- {h}" for h in experience_hints),
                self._config.max_experience_tokens,
            )
            if hints_text:
                system_parts.append(f"## Experience Hints\n{hints_text}")
                sections.append("experience_hints")

        # 8. Response format
        if response_format:
            system_parts.append(f"## Response Format\n{response_format}")
            sections.append("response_format")

        system_prompt = "\n\n".join(system_parts)

        # Build user prompt
        user_prompt = task_instruction

        # Conversation history
        messages = []
        if conversation_history:
            budget = self._config.max_conversation_tokens
            token_count = 0
            for msg in reversed(conversation_history):
                msg_tokens = len(msg.get("content", "")) // 4
                if token_count + msg_tokens > budget:
                    break
                messages.insert(0, msg)
                token_count += msg_tokens
            sections.append("conversation")

        # Estimate total tokens
        total_text = system_prompt + user_prompt + "".join(
            m.get("content", "") for m in messages
        )
        estimated_tokens = len(total_text) // 4

        prompt = CompiledPrompt(
            prompt_id=f"prompt-{self._counter}",
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            messages=messages,
            estimated_tokens=estimated_tokens,
            sections_included=sections,
            knowledge_injected=knowledge_injected,
            model_format=fmt,
        )

        self._compilation_history.append(prompt.to_dict())

        return prompt

    @staticmethod
    def _truncate_to_tokens(text: str, max_tokens: int) -> str:
        """Truncate text to approximate token budget."""
        max_chars = max_tokens * 4
        if len(text) <= max_chars:
            return text
        return text[:max_chars] + "\n[...truncated]"

    def get_stats(self) -> dict[str, Any]:
        section_counts: dict[str, int] = defaultdict(int)
        for hist in self._compilation_history:
            for sec in hist.get("sections", []):
                section_counts[sec] += 1

        return {
            "compiled": len(self._compilation_history),
            "sections_used": dict(section_counts),
        }
