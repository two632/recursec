"""Prompt assembler — assembles all KBs into LLM prompts.

Master orchestrator that selects and composes
relevant knowledge bases into final LLM prompts
based on assessment phase, target type, and context.

Implements:
1. Phase-based KB selection
2. Token budget management across KBs
3. Priority-based knowledge injection
4. Dynamic prompt composition
5. Context-aware assembly
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class AssessmentPhase(str, Enum):
    PLANNING = "planning"
    RECON = "recon"
    ENUMERATION = "enumeration"
    VULN_SCAN = "vuln_scan"
    WEB_AUDIT = "web_audit"
    API_AUDIT = "api_audit"
    CODE_AUDIT = "code_audit"
    EXPLOITATION = "exploitation"
    POST_EXPLOIT = "post_exploit"
    LATERAL_MOVE = "lateral_move"
    PRIVESC = "privesc"
    CLOUD_AUDIT = "cloud_audit"
    CONTAINER_AUDIT = "container_audit"
    NETWORK_AUDIT = "network_audit"
    WIRELESS = "wireless"
    SOCIAL_ENG = "social_eng"
    REPORTING = "reporting"
    VALIDATION = "validation"


class TargetType(str, Enum):
    WEB_APP = "web_app"
    API = "api"
    NETWORK = "network"
    CLOUD = "cloud"
    INTERNAL = "internal"
    MOBILE = "mobile"
    IOT = "iot"
    CODE = "code"
    WIRELESS = "wireless"
    CONTAINER = "container"
    ACTIVE_DIRECTORY = "active_directory"
    GENERAL = "general"


# Phase → relevant KB modules (by build_*_prompt method name suffix)
PHASE_KB_MAP: dict[str, list[str]] = {
    "planning": ["mitre", "redteam", "compliance"],
    "recon": ["osint", "target_profile", "network_protocol"],
    "enumeration": ["osint", "network_protocol", "linux", "winsec"],
    "vuln_scan": ["web", "api", "network_protocol", "cloud"],
    "web_audit": ["web", "webadv", "api", "business_logic"],
    "api_audit": ["api", "webadv", "authentication"],
    "code_audit": ["supply_chain", "aiml"],
    "exploitation": ["postexploit", "redteam", "webadv"],
    "post_exploit": ["postexploit", "lateral_movement", "data_exfiltration"],
    "lateral_move": ["lateral_movement", "active_directory", "winsec"],
    "privesc": ["linux", "winsec", "container"],
    "cloud_audit": ["cloud", "container", "kubernetes"],
    "container_audit": ["container", "kubernetes", "supply_chain"],
    "network_audit": ["network_protocol", "wireless"],
    "wireless": ["wireless"],
    "social_eng": ["socialeng", "osint"],
    "reporting": ["compliance", "mitre"],
    "validation": ["web", "network_protocol"],
}

# Target type → additional KB modules
TARGET_KB_MAP: dict[str, list[str]] = {
    "web_app": ["web", "webadv", "authentication", "business_logic"],
    "api": ["api", "authentication", "graphql"],
    "network": ["network_protocol", "wireless"],
    "cloud": ["cloud", "container", "kubernetes"],
    "internal": ["active_directory", "lateral_movement", "winsec", "linux"],
    "mobile": ["mobile", "api"],
    "iot": ["iot", "firmware", "wireless"],
    "code": ["supply_chain", "aiml"],
    "wireless": ["wireless", "network_protocol"],
    "container": ["container", "kubernetes", "supply_chain"],
    "active_directory": ["active_directory", "winsec", "lateral_movement"],
    "general": ["web", "network_protocol", "osint"],
}


@dataclass
class PromptSection:
    """A section of the assembled prompt."""
    name: str = ""
    content: str = ""
    priority: int = 0       # Higher = more important
    token_estimate: int = 0
    source_kb: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name[:15],
            "tokens": self.token_estimate,
            "priority": self.priority,
        }


@dataclass
class AssembledPrompt:
    """A fully assembled prompt for LLM."""
    system_prompt: str = ""
    knowledge_context: str = ""
    memory_context: str = ""
    task_context: str = ""
    reasoning_context: str = ""
    total_tokens: int = 0
    sections_included: list[str] = field(default_factory=list)
    sections_truncated: list[str] = field(default_factory=list)
    assembled_at: float = field(default_factory=time.time)

    def to_full_prompt(self) -> str:
        """Assemble into full prompt string."""
        parts = [self.system_prompt]
        if self.knowledge_context:
            parts.append(self.knowledge_context)
        if self.memory_context:
            parts.append(self.memory_context)
        if self.task_context:
            parts.append(self.task_context)
        if self.reasoning_context:
            parts.append(self.reasoning_context)
        return "\n\n---\n\n".join(parts)


class PromptAssembler:
    """Master prompt assembler.

    Selects relevant KBs based on phase and target,
    manages token budgets, and composes final prompts
    for LLM inference.
    """

    def __init__(
        self,
        max_tokens: int = 4096,
        knowledge_budget_pct: float = 0.30,
        memory_budget_pct: float = 0.15,
        task_budget_pct: float = 0.20,
        system_budget_pct: float = 0.10,
        reasoning_budget_pct: float = 0.25,
    ) -> None:
        self._max_tokens = max_tokens
        self._knowledge_budget = int(max_tokens * knowledge_budget_pct)
        self._memory_budget = int(max_tokens * memory_budget_pct)
        self._task_budget = int(max_tokens * task_budget_pct)
        self._system_budget = int(max_tokens * system_budget_pct)
        self._reasoning_budget = int(max_tokens * reasoning_budget_pct)
        self._kb_builders: dict[str, Any] = {}
        self._assembly_count = 0
        self._log = logger.bind(component="prompt_assembler")

    def register_kb(self, kb_name: str, builder: Any) -> None:
        """Register a KB builder (must have build_*_prompt method)."""
        self._kb_builders[kb_name] = builder

    def _estimate_tokens(self, text: str) -> int:
        """Estimate token count (~4 chars per token)."""
        return len(text) // 4

    def _select_kbs(
        self,
        phase: AssessmentPhase,
        target_type: TargetType = TargetType.GENERAL,
    ) -> list[str]:
        """Select relevant KBs for phase and target."""
        kb_names: list[str] = []

        # Phase-based selection
        phase_kbs = PHASE_KB_MAP.get(phase.value, [])
        kb_names.extend(phase_kbs)

        # Target-based selection
        target_kbs = TARGET_KB_MAP.get(target_type.value, [])
        for kb in target_kbs:
            if kb not in kb_names:
                kb_names.append(kb)

        return kb_names

    def _build_kb_section(
        self,
        kb_name: str,
        max_tokens: int,
    ) -> PromptSection | None:
        """Build a section from a registered KB."""
        builder = self._kb_builders.get(kb_name)
        if not builder:
            return None

        # Try to find the build method
        method_names = [
            f"build_{kb_name}_prompt",
            f"build_{kb_name.replace('_', '')}_prompt",
        ]

        content = ""
        for method_name in method_names:
            method = getattr(builder, method_name, None)
            if method and callable(method):
                try:
                    content = method(max_patterns=3)
                except TypeError:
                    try:
                        content = method()
                    except Exception:
                        continue
                break

        if not content:
            return None

        tokens = self._estimate_tokens(content)

        # Truncate if over budget
        if tokens > max_tokens:
            char_budget = max_tokens * 4
            content = content[:char_budget] + "\n[truncated]"
            tokens = max_tokens

        return PromptSection(
            name=kb_name,
            content=content,
            priority=5,
            token_estimate=tokens,
            source_kb=kb_name,
        )

    def assemble(
        self,
        phase: AssessmentPhase,
        target_type: TargetType = TargetType.GENERAL,
        target: str = "",
        task: str = "",
        memory_context: str = "",
        reasoning_context: str = "",
        system_additions: str = "",
    ) -> AssembledPrompt:
        """Assemble a complete prompt."""
        self._assembly_count += 1

        prompt = AssembledPrompt()

        # 1. System prompt
        system_parts = [
            "You are an autonomous security assessment agent.",
            f"Phase: {phase.value}",
            f"Target type: {target_type.value}",
        ]
        if target:
            system_parts.append(f"Target: {target}")
        if system_additions:
            system_parts.append(system_additions)
        prompt.system_prompt = "\n".join(system_parts)

        # 2. Knowledge context from KBs
        kb_names = self._select_kbs(phase, target_type)
        knowledge_parts = []
        remaining_budget = self._knowledge_budget

        per_kb_budget = remaining_budget // max(1, len(kb_names))

        for kb_name in kb_names:
            section = self._build_kb_section(kb_name, per_kb_budget)
            if section:
                knowledge_parts.append(section.content)
                remaining_budget -= section.token_estimate
                prompt.sections_included.append(kb_name)

                if remaining_budget <= 0:
                    break

        prompt.knowledge_context = "\n\n".join(knowledge_parts)

        # 3. Memory context
        if memory_context:
            tokens = self._estimate_tokens(memory_context)
            if tokens > self._memory_budget:
                char_budget = self._memory_budget * 4
                memory_context = memory_context[:char_budget] + "\n[truncated]"
            prompt.memory_context = memory_context

        # 4. Task context
        if task:
            prompt.task_context = f"## Current Task\n\n{task}"

        # 5. Reasoning context
        if reasoning_context:
            prompt.reasoning_context = reasoning_context

        # Calculate total tokens
        prompt.total_tokens = self._estimate_tokens(prompt.to_full_prompt())

        return prompt

    def build_assembler_prompt(self) -> str:
        """Build assembler stats for LLM."""
        lines = ["## Prompt Assembler\n"]
        lines.append(f"Registered KBs: {len(self._kb_builders)}")
        lines.append(f"Assemblies: {self._assembly_count}")
        lines.append(f"Max tokens: {self._max_tokens}")
        lines.append(f"Knowledge budget: {self._knowledge_budget}")

        if self._kb_builders:
            lines.append("\nAvailable KBs:")
            for name in sorted(self._kb_builders.keys()):
                lines.append(f"  - {name}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            "registered_kbs": len(self._kb_builders),
            "assemblies": self._assembly_count,
            "max_tokens": self._max_tokens,
            "kb_names": sorted(self._kb_builders.keys()),
        }
