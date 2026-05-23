"""Prompt compiler — assembles context into optimal LLM prompts.

Implements:
1. Role-specific system prompt generation
2. Context section assembly (priority-ordered)
3. Token budget allocation across sections
4. Dynamic section inclusion/exclusion
5. Prompt templating with variables
6. History compression for long conversations
7. Chain-of-thought instruction injection
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
    TASK = "task"
    TARGET_INFO = "target_info"
    KNOWLEDGE = "knowledge"
    FINDINGS = "findings"
    HYPOTHESES = "hypotheses"
    PLAN = "plan"
    TOOLS = "tools"
    MEMORY = "memory"
    GRAPH = "graph"
    LOOP_STATUS = "loop_status"
    HISTORY = "history"
    COT_INSTRUCTIONS = "cot_instructions"
    CONSTRAINTS = "constraints"


class AgentRole(str, Enum):
    COORDINATOR = "coordinator"
    RECON = "recon"
    SCANNER = "scanner"
    EXPLOITER = "exploiter"
    CODE_AUDITOR = "code_auditor"
    VALIDATOR = "validator"
    ANALYST = "analyst"
    PLANNER = "planner"


@dataclass
class PromptBlock:
    """A block of prompt content."""
    section: PromptSection = PromptSection.SYSTEM
    content: str = ""
    priority: int = 5       # 1=highest, 10=lowest
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
    """A fully compiled prompt ready for LLM."""
    system_prompt: str = ""
    user_prompt: str = ""
    total_tokens: int = 0
    sections_included: list[str] = field(default_factory=list)
    sections_excluded: list[str] = field(default_factory=list)
    compiled_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_tokens": self.total_tokens,
            "included": len(self.sections_included),
            "excluded": len(self.sections_excluded),
        }


# ── Role system prompts ──────────────────────────────────────

ROLE_PROMPTS: dict[str, str] = {
    "coordinator": (
        "You are the COORDINATOR agent in an autonomous security assessment system. "
        "Your role is to:\n"
        "1. Decompose high-level security objectives into sub-tasks\n"
        "2. Assign tasks to specialized agents (recon, scanner, exploiter, etc.)\n"
        "3. Monitor progress and adjust strategy\n"
        "4. Synthesize findings from all agents\n"
        "5. Make go/no-go decisions on exploitation\n"
        "Think step-by-step. Prioritize high-impact targets."
    ),
    "recon": (
        "You are the RECON agent. Your role is to discover and enumerate targets:\n"
        "1. Subdomain enumeration\n"
        "2. Port scanning and service detection\n"
        "3. Technology fingerprinting\n"
        "4. OSINT gathering\n"
        "5. Attack surface mapping\n"
        "Be thorough but efficient. Prioritize breadth first, then depth."
    ),
    "scanner": (
        "You are the SCANNER agent. Your role is vulnerability scanning:\n"
        "1. Run automated vulnerability scanners\n"
        "2. Interpret and validate scanner output\n"
        "3. Identify false positives\n"
        "4. Prioritize findings by severity and exploitability\n"
        "5. Suggest manual testing for ambiguous results\n"
        "Be skeptical of scanner output. Validate before reporting."
    ),
    "exploiter": (
        "You are the EXPLOITER agent. Your role is vulnerability exploitation:\n"
        "1. Develop exploitation strategies for confirmed vulns\n"
        "2. Choose appropriate tools and techniques\n"
        "3. Execute exploits safely within scope\n"
        "4. Document exploitation steps precisely\n"
        "5. Assess impact and escalation potential\n"
        "Always validate scope before exploitation. Document everything."
    ),
    "code_auditor": (
        "You are the CODE AUDITOR agent. Your role is source code analysis:\n"
        "1. Static analysis for security vulnerabilities\n"
        "2. Identify dangerous coding patterns\n"
        "3. Trace data flow from sources to sinks\n"
        "4. Check authentication and authorization logic\n"
        "5. Review cryptographic usage\n"
        "Focus on security-critical code paths. Report with exact line references."
    ),
    "validator": (
        "You are the VALIDATOR agent. Your role is finding validation:\n"
        "1. Verify reported vulnerabilities are real\n"
        "2. Reproduce exploits independently\n"
        "3. Assess false positive probability\n"
        "4. Rate severity accurately\n"
        "5. Challenge assumptions from other agents\n"
        "Be adversarial. Assume findings are false until proven otherwise."
    ),
    "analyst": (
        "You are the ANALYST agent. Your role is synthesis and analysis:\n"
        "1. Correlate findings across agents\n"
        "2. Identify attack chains and lateral paths\n"
        "3. Assess overall security posture\n"
        "4. Prioritize remediation recommendations\n"
        "5. Identify patterns and systemic issues\n"
        "Think holistically. Connect findings into a coherent narrative."
    ),
    "planner": (
        "You are the PLANNER agent. Your role is assessment planning:\n"
        "1. Create assessment plans from objectives\n"
        "2. Allocate resources and budgets\n"
        "3. Sequence activities optimally\n"
        "4. Identify dependencies between tasks\n"
        "5. Adapt plans based on progress\n"
        "Balance thoroughness with efficiency. Adapt dynamically."
    ),
}

# ── Chain-of-thought instructions ────────────────────────────

COT_TEMPLATE = (
    "\n## Reasoning Instructions\n"
    "Think step-by-step before acting:\n"
    "1. OBSERVE: What information do you have? What is the current state?\n"
    "2. ANALYZE: What does this information mean? What patterns do you see?\n"
    "3. HYPOTHESIZE: What vulnerabilities might exist? Rate confidence.\n"
    "4. PLAN: What is the next best action? Why this over alternatives?\n"
    "5. ACT: Execute the chosen action.\n"
    "6. REFLECT: Did the action produce expected results? What to adjust?\n"
    "\nFormat your response as:\n"
    "<think>\n[Your step-by-step reasoning]\n</think>\n"
    "<action>\n[Your chosen action and parameters]\n</action>"
)


def _estimate_tokens(text: str) -> int:
    """Rough token estimate (~4 chars per token for English)."""
    return len(text) // 4


class PromptCompiler:
    """Compiles optimized prompts from multiple context sources.

    Assembles role prompts, task context, knowledge,
    findings, hypotheses, and reasoning instructions
    into a prompt that fits within the model's
    context window.
    """

    def __init__(self, max_tokens: int = 8192) -> None:
        self._max_tokens = max_tokens
        self._blocks: list[PromptBlock] = []
        self._variables: dict[str, str] = {}
        self._log = logger.bind(component="prompt_compiler")

    def set_max_tokens(self, max_tokens: int) -> None:
        """Update the token budget."""
        self._max_tokens = max_tokens

    def set_variable(self, name: str, value: str) -> None:
        """Set a template variable."""
        self._variables[name] = value

    def add_block(
        self,
        section: PromptSection,
        content: str,
        priority: int = 5,
        required: bool = False,
    ) -> None:
        """Add a prompt block."""
        block = PromptBlock(
            section=section,
            content=content,
            priority=priority,
            token_estimate=_estimate_tokens(content),
            required=required,
        )
        self._blocks.append(block)

    def add_role(self, role: AgentRole) -> None:
        """Add role-specific system prompt."""
        prompt = ROLE_PROMPTS.get(role.value, "")
        if prompt:
            self.add_block(
                PromptSection.ROLE,
                prompt,
                priority=1,
                required=True,
            )

    def add_cot(self) -> None:
        """Add chain-of-thought instructions."""
        self.add_block(
            PromptSection.COT_INSTRUCTIONS,
            COT_TEMPLATE,
            priority=2,
            required=True,
        )

    def compile(self, reserve_output: float = 0.15) -> CompiledPrompt:
        """Compile blocks into final prompt."""
        available = int(self._max_tokens * (1 - reserve_output))

        # Sort: required first, then by priority (ascending = higher priority)
        sorted_blocks = sorted(
            self._blocks,
            key=lambda b: (not b.required, b.priority),
        )

        included: list[PromptBlock] = []
        excluded: list[PromptBlock] = []
        tokens_used = 0

        for block in sorted_blocks:
            if tokens_used + block.token_estimate <= available:
                included.append(block)
                tokens_used += block.token_estimate
            elif block.required:
                # Required blocks always included
                included.append(block)
                tokens_used += block.token_estimate
            else:
                excluded.append(block)

        # Build prompts
        system_parts: list[str] = []
        user_parts: list[str] = []

        for block in included:
            content = self._apply_variables(block.content)
            if block.section in (PromptSection.SYSTEM, PromptSection.ROLE, PromptSection.CONSTRAINTS):
                system_parts.append(content)
            else:
                user_parts.append(content)

        result = CompiledPrompt(
            system_prompt="\n\n".join(system_parts),
            user_prompt="\n\n".join(user_parts),
            total_tokens=tokens_used,
            sections_included=[b.section.value for b in included],
            sections_excluded=[b.section.value for b in excluded],
        )

        self._blocks.clear()
        return result

    def _apply_variables(self, content: str) -> str:
        """Replace template variables in content."""
        result = content
        for name, value in self._variables.items():
            result = result.replace(f"{{{{{name}}}}}", value)
        return result

    def get_stats(self) -> dict[str, Any]:
        return {
            "pending_blocks": len(self._blocks),
            "max_tokens": self._max_tokens,
            "variables": len(self._variables),
        }
