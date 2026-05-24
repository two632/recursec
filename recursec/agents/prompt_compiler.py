"""Prompt compiler — assembles final prompts from all subsystems.

Implements:
1. System prompt construction from agent role/config
2. Knowledge injection from selected KBs
3. Memory context injection (working + episodic)
4. Tool availability context
5. Budget/convergence state context
6. Reasoning chain context
7. Token-aware truncation
8. Prompt template management
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class PromptSection(str, Enum):
    SYSTEM = "system"                  # Core system prompt
    ROLE = "role"                      # Agent role definition
    KNOWLEDGE = "knowledge"            # Injected KB patterns
    MEMORY = "memory"                  # Past findings/context
    TOOLS = "tools"                    # Available tool descriptions
    STATE = "state"                    # Current assessment state
    BUDGET = "budget"                  # Token budget status
    CONVERGENCE = "convergence"        # Convergence status
    REASONING = "reasoning"            # Chain-of-thought hints
    LEARNING = "learning"              # Learned patterns
    TASK = "task"                      # Current task/objective
    CONSTRAINTS = "constraints"        # Safety constraints
    OUTPUT_FORMAT = "output_format"    # Expected output format


@dataclass
class PromptBlock:
    """A block of prompt content."""
    section: PromptSection = PromptSection.SYSTEM
    content: str = ""
    priority: int = 5       # 1=highest (always include)
    token_estimate: int = 0
    required: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "section": self.section.value[:10],
            "tokens": self.token_estimate,
            "priority": self.priority,
            "required": self.required,
        }


@dataclass
class CompiledPrompt:
    """A fully compiled prompt."""
    system_message: str = ""
    user_message: str = ""
    blocks_included: int = 0
    blocks_dropped: int = 0
    total_tokens_est: int = 0
    compile_time_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "sys_len": len(self.system_message),
            "user_len": len(self.user_message),
            "blocks": self.blocks_included,
            "dropped": self.blocks_dropped,
            "tokens_est": self.total_tokens_est,
        }


# ── Prompt templates ─────────────────────────────────────────

ROLE_TEMPLATES: dict[str, str] = {
    "coordinator": (
        "You are the COORDINATOR agent in RecurSec, a recursive multi-agent security framework.\n"
        "Your role is to decompose security tasks, delegate to specialist agents, and aggregate results.\n"
        "You make high-level strategic decisions about assessment approach.\n"
        "Think step-by-step. Consider multiple attack vectors. Prioritize by impact."
    ),
    "recon": (
        "You are the RECONNAISSANCE agent.\n"
        "Your role is to gather information about the target using passive and active techniques.\n"
        "Be thorough: enumerate subdomains, ports, services, technologies, personnel.\n"
        "Output structured data for downstream agents."
    ),
    "vuln_scan": (
        "You are the VULNERABILITY SCANNING agent.\n"
        "Your role is to identify vulnerabilities in discovered services.\n"
        "Run appropriate tools for each service type. Validate findings to reduce false positives.\n"
        "Classify by severity (Critical/High/Medium/Low/Info)."
    ),
    "web_audit": (
        "You are the WEB APPLICATION SECURITY agent.\n"
        "Your role is to perform deep web application testing following OWASP methodology.\n"
        "Test injection points, authentication, authorization, session management, file upload.\n"
        "Think like an attacker. Chain vulnerabilities."
    ),
    "exploit": (
        "You are the EXPLOITATION agent.\n"
        "Your role is to validate and exploit confirmed vulnerabilities.\n"
        "Start with lowest-risk exploits. Document proof-of-concept for each.\n"
        "Assess real-world impact. Consider chaining for deeper access."
    ),
    "code_audit": (
        "You are the CODE AUDIT agent.\n"
        "Your role is to review source code for security vulnerabilities.\n"
        "Look for injection sinks, auth bypass, hardcoded secrets, unsafe deserialization.\n"
        "Trace data flow from sources to sinks."
    ),
    "validator": (
        "You are the VALIDATION agent.\n"
        "Your role is to cross-validate findings from other agents.\n"
        "Verify each finding independently. Flag false positives.\n"
        "Use different tools/approaches than the original finder."
    ),
    "reporter": (
        "You are the REPORTING agent.\n"
        "Your role is to compile assessment findings into a structured report.\n"
        "Include executive summary, technical details, proof of concept, remediation.\n"
        "Classify by severity and business impact."
    ),
}

CONSTRAINT_TEMPLATE = (
    "CONSTRAINTS:\n"
    "- Stay within authorized scope: {scope}\n"
    "- Exclusions: {exclusions}\n"
    "- Do NOT perform destructive actions\n"
    "- Do NOT exfiltrate real data\n"
    "- Time limit: {time_limit}\n"
    "- Token budget: {token_budget}\n"
    "- Safety: verify commands before execution\n"
    "- Report all findings, even partial"
)

OUTPUT_FORMAT_TEMPLATE = (
    "OUTPUT FORMAT:\n"
    "Respond with structured JSON:\n"
    "{{\n"
    "  \"action\": \"run_tool|spawn_agent|report_finding|complete\",\n"
    "  \"tool\": \"tool_name (if action=run_tool)\",\n"
    "  \"args\": {{\"arg1\": \"val1\"}},\n"
    "  \"reasoning\": \"why this action\",\n"
    "  \"confidence\": 0.0-1.0,\n"
    "  \"next_steps\": [\"what to do after this\"]\n"
    "}}"
)


class PromptCompiler:
    """Compiles prompts from multiple subsystem contexts.

    Assembles system prompt, knowledge, memory, tools,
    and state into a final prompt that fits within
    the model's context window.
    """

    def __init__(
        self,
        max_tokens: int = 8000,
        chars_per_token: float = 3.5,
    ) -> None:
        self._max_tokens = max_tokens
        self._chars_per_token = chars_per_token
        self._blocks: list[PromptBlock] = []
        self._compile_count = 0
        self._log = logger.bind(component="prompt_compiler")

    def _estimate_tokens(self, text: str) -> int:
        """Rough token estimation."""
        return int(len(text) / self._chars_per_token)

    def add_block(
        self,
        section: PromptSection,
        content: str,
        priority: int = 5,
        required: bool = False,
    ) -> None:
        """Add a prompt block."""
        tokens = self._estimate_tokens(content)
        self._blocks.append(PromptBlock(
            section=section,
            content=content,
            priority=priority,
            token_estimate=tokens,
            required=required,
        ))

    def add_role(self, role: str) -> None:
        """Add role template."""
        template = ROLE_TEMPLATES.get(role, ROLE_TEMPLATES["coordinator"])
        self.add_block(
            PromptSection.ROLE,
            template,
            priority=1,
            required=True,
        )

    def add_constraints(
        self,
        scope: str = "*",
        exclusions: str = "none",
        time_limit: str = "1h",
        token_budget: str = "50000",
    ) -> None:
        """Add constraint block."""
        content = CONSTRAINT_TEMPLATE.format(
            scope=scope,
            exclusions=exclusions,
            time_limit=time_limit,
            token_budget=token_budget,
        )
        self.add_block(PromptSection.CONSTRAINTS, content, priority=2, required=True)

    def add_output_format(self) -> None:
        """Add output format block."""
        self.add_block(
            PromptSection.OUTPUT_FORMAT,
            OUTPUT_FORMAT_TEMPLATE,
            priority=2,
            required=True,
        )

    def add_knowledge(self, kb_prompt: str) -> None:
        """Add knowledge base content."""
        if kb_prompt:
            self.add_block(PromptSection.KNOWLEDGE, kb_prompt, priority=3)

    def add_memory(self, memory_prompt: str) -> None:
        """Add memory context."""
        if memory_prompt:
            self.add_block(PromptSection.MEMORY, memory_prompt, priority=4)

    def add_tools(self, tools_prompt: str) -> None:
        """Add tool descriptions."""
        if tools_prompt:
            self.add_block(PromptSection.TOOLS, tools_prompt, priority=3)

    def add_state(self, state_prompt: str) -> None:
        """Add current state context."""
        if state_prompt:
            self.add_block(PromptSection.STATE, state_prompt, priority=4)

    def add_task(self, task_description: str) -> None:
        """Add the current task/objective."""
        if task_description:
            self.add_block(
                PromptSection.TASK,
                f"TASK:\n{task_description}",
                priority=1,
                required=True,
            )

    def compile(self, user_message: str = "") -> CompiledPrompt:
        """Compile all blocks into a final prompt."""
        start = time.time()
        self._compile_count += 1

        # Separate required and optional blocks
        required = [b for b in self._blocks if b.required]
        optional = sorted(
            [b for b in self._blocks if not b.required],
            key=lambda b: b.priority,
        )

        # Required tokens
        required_tokens = sum(b.token_estimate for b in required)
        remaining = self._max_tokens - required_tokens

        # Fit optional blocks
        included_optional: list[PromptBlock] = []
        for block in optional:
            if block.token_estimate <= remaining:
                included_optional.append(block)
                remaining -= block.token_estimate

        # Build system message
        all_blocks = required + included_optional
        # Sort by section order
        section_order = list(PromptSection)
        all_blocks.sort(key=lambda b: section_order.index(b.section))

        system_parts: list[str] = []
        for block in all_blocks:
            system_parts.append(block.content)

        system_message = "\n\n".join(system_parts)

        compile_time = (time.time() - start) * 1000

        result = CompiledPrompt(
            system_message=system_message,
            user_message=user_message,
            blocks_included=len(all_blocks),
            blocks_dropped=len(self._blocks) - len(all_blocks),
            total_tokens_est=sum(b.token_estimate for b in all_blocks),
            compile_time_ms=compile_time,
        )

        # Clear blocks for next compilation
        self._blocks.clear()

        return result

    def build_compiler_prompt(self) -> str:
        """Build compiler stats for debugging."""
        lines = ["## Prompt Compiler\n"]
        lines.append(f"Max tokens: {self._max_tokens}")
        lines.append(f"Compiles: {self._compile_count}")
        lines.append(f"Pending blocks: {len(self._blocks)}")

        if self._blocks:
            by_section: dict[str, int] = {}
            for b in self._blocks:
                by_section[b.section.value] = by_section.get(b.section.value, 0) + 1
            lines.append(f"Sections: {by_section}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            "max_tokens": self._max_tokens,
            "compiles": self._compile_count,
            "pending_blocks": len(self._blocks),
        }
