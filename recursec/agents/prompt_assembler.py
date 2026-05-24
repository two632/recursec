"""Dynamic prompt assembler — loads KBs and composes optimal prompts.

Wires together:
1. KB Registry → selects relevant KBs based on intent/tags
2. Prompt Templates → role-specific system prompts + phase instructions
3. Knowledge Graph → entity context from discovered graph
4. Experience Replay → past lessons for similar tasks
5. Strategy Optimizer → best strategies from bandit algorithms
6. LLM Connection Engine → model-specific context limits
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class AssembledPrompt:
    """A fully assembled prompt ready for LLM."""
    system_prompt: str = ""
    user_instruction: str = ""
    kb_context: str = ""
    experience_context: str = ""
    strategy_context: str = ""
    graph_context: str = ""
    output_format: str = ""
    total_tokens_estimate: int = 0
    model_id: str = ""
    kbs_loaded: list[str] = field(default_factory=list)
    truncated: bool = False

    @property
    def full_system(self) -> str:
        """Full system prompt with all context."""
        parts = [self.system_prompt]
        if self.kb_context:
            parts.append(self.kb_context)
        if self.experience_context:
            parts.append(self.experience_context)
        if self.strategy_context:
            parts.append(self.strategy_context)
        if self.graph_context:
            parts.append(self.graph_context)
        return "\n\n".join(parts)

    @property
    def full_user(self) -> str:
        """Full user message with instruction and format."""
        parts = [self.user_instruction]
        if self.output_format:
            parts.append(self.output_format)
        return "\n\n".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model_id[:12],
            "kbs": len(self.kbs_loaded),
            "tokens_est": self.total_tokens_estimate,
            "truncated": self.truncated,
            "system_len": len(self.system_prompt),
            "kb_len": len(self.kb_context),
        }


def _estimate_tokens(text: str) -> int:
    """Rough token estimate (1 token ~ 4 chars)."""
    return len(text) // 4


def _load_kb_prompt(module_path: str, func_name: str) -> str:
    """Dynamically load a KB module and call its build prompt function."""
    try:
        mod = importlib.import_module(module_path)
        build_func = getattr(mod, func_name, None)
        if build_func and callable(build_func):
            return build_func()
        return ""
    except (ImportError, AttributeError) as exc:
        logger.warning("kb_load_failed", module=module_path, error=str(exc))
        return ""


class PromptAssembler:
    """Assembles optimal prompts from all agent components."""

    def __init__(self, max_context_tokens: int = 8192) -> None:
        self._max_context = max_context_tokens
        self._assembly_count = 0
        self._log = logger.bind(component="prompt_assembler")

    def assemble(
        self,
        role: str = "coordinator",
        phase: str = "planning",
        intent: str = "",
        user_input: str = "",
        kb_domains: list[str] | None = None,
        model_context_size: int = 8192,
        include_experience: bool = True,
        include_strategy: bool = True,
        include_graph: bool = True,
    ) -> AssembledPrompt:
        """Assemble a full prompt from all components."""
        self._assembly_count += 1
        max_ctx = min(self._max_context, model_context_size)

        # 1. Get role system prompt
        system_prompt = self._get_role_prompt(role)

        # 2. Get phase instruction
        instruction = self._get_phase_instruction(phase, user_input)

        # 3. Load KB context
        kb_context, loaded_kbs = self._load_kb_context(
            kb_domains or [], max_kb_tokens=max_ctx // 3,
        )

        # 4. Load experience context
        experience_ctx = ""
        if include_experience:
            experience_ctx = self._get_experience_context(intent)

        # 5. Load strategy context
        strategy_ctx = ""
        if include_strategy:
            strategy_ctx = self._get_strategy_context(intent)

        # 6. Load graph context
        graph_ctx = ""
        if include_graph:
            graph_ctx = self._get_graph_context()

        # 7. Get output format
        output_fmt = self._get_output_format(phase)

        # 8. Calculate total and truncate if needed
        total = (
            _estimate_tokens(system_prompt)
            + _estimate_tokens(instruction)
            + _estimate_tokens(kb_context)
            + _estimate_tokens(experience_ctx)
            + _estimate_tokens(strategy_ctx)
            + _estimate_tokens(graph_ctx)
            + _estimate_tokens(output_fmt)
        )

        truncated = False
        if total > max_ctx * 0.8:
            # Truncate KB context first (largest component)
            excess = total - int(max_ctx * 0.75)
            chars_to_remove = excess * 4
            if len(kb_context) > chars_to_remove:
                kb_context = kb_context[:len(kb_context) - chars_to_remove]
                truncated = True
            # Then truncate experience
            elif experience_ctx:
                experience_ctx = experience_ctx[:len(experience_ctx) // 2]
                truncated = True

        result = AssembledPrompt(
            system_prompt=system_prompt,
            user_instruction=instruction,
            kb_context=kb_context,
            experience_context=experience_ctx,
            strategy_context=strategy_ctx,
            graph_context=graph_ctx,
            output_format=output_fmt,
            total_tokens_estimate=_estimate_tokens(
                system_prompt + instruction + kb_context + experience_ctx + strategy_ctx + graph_ctx + output_fmt
            ),
            kbs_loaded=loaded_kbs,
            truncated=truncated,
        )

        return result

    def _get_role_prompt(self, role: str) -> str:
        """Get role-specific system prompt."""
        try:
            from recursec.agents.prompt_templates import ROLE_SYSTEM_PROMPTS, PromptRole
            role_enum = PromptRole(role)
            return ROLE_SYSTEM_PROMPTS.get(role_enum, f"You are a {role} security agent.")
        except (ImportError, ValueError):
            return f"You are a {role} security agent. Think step-by-step."

    def _get_phase_instruction(self, phase: str, user_input: str) -> str:
        """Get phase-specific instruction."""
        try:
            from recursec.agents.prompt_templates import PHASE_INSTRUCTIONS, PromptPhase
            phase_enum = PromptPhase(phase)
            instruction = PHASE_INSTRUCTIONS.get(phase_enum, "Execute this phase.")
        except (ImportError, ValueError):
            instruction = "Execute this phase of the security assessment."

        if user_input:
            instruction = f"Task: {user_input}\n\n{instruction}"
        return instruction

    def _load_kb_context(
        self, domains: list[str], max_kb_tokens: int = 2000,
    ) -> tuple[str, list[str]]:
        """Load knowledge base context for selected domains."""
        try:
            from recursec.agents.kb_registry import KB_REGISTRY
        except ImportError:
            return "", []

        loaded: list[str] = []
        parts: list[str] = []
        current_tokens = 0

        # Sort by priority (highest first)
        sorted_domains = sorted(
            [d for d in domains if d in KB_REGISTRY],
            key=lambda d: KB_REGISTRY[d].priority,
            reverse=True,
        )

        for domain in sorted_domains:
            if current_tokens >= max_kb_tokens:
                break
            entry = KB_REGISTRY[domain]
            kb_text = _load_kb_prompt(entry.module_path, entry.build_func_name)
            if kb_text:
                tokens = _estimate_tokens(kb_text)
                if current_tokens + tokens <= max_kb_tokens:
                    parts.append(kb_text)
                    loaded.append(domain)
                    current_tokens += tokens
                else:
                    # Partial load
                    remaining = (max_kb_tokens - current_tokens) * 4
                    parts.append(kb_text[:remaining])
                    loaded.append(f"{domain}(partial)")
                    break

        return "\n\n".join(parts), loaded

    def _get_experience_context(self, intent: str) -> str:
        """Get experience replay context."""
        try:
            from recursec.agents.experience_replay import ExperienceReplay
            replay = ExperienceReplay()
            return replay.build_experience_prompt()
        except ImportError:
            return ""

    def _get_strategy_context(self, intent: str) -> str:
        """Get strategy optimizer context."""
        try:
            from recursec.agents.strategy_optimizer import StrategyOptimizer
            optimizer = StrategyOptimizer()
            return optimizer.build_optimizer_prompt()
        except ImportError:
            return ""

    def _get_graph_context(self) -> str:
        """Get knowledge graph context."""
        try:
            from recursec.agents.knowledge_graph import KnowledgeGraph
            graph = KnowledgeGraph()
            return graph.build_graph_prompt()
        except ImportError:
            return ""

    def _get_output_format(self, phase: str) -> str:
        """Get output format for a phase."""
        try:
            from recursec.agents.prompt_templates import OUTPUT_FORMATS, OutputFormat
            if phase in ("tool_execution", "tool_selection"):
                return OUTPUT_FORMATS.get(OutputFormat.TOOL_CALL, "")
            if phase == "reporting":
                return OUTPUT_FORMATS.get(OutputFormat.MARKDOWN, "")
            return OUTPUT_FORMATS.get(OutputFormat.STRUCTURED, "")
        except ImportError:
            return "Respond with structured findings."

    def get_stats(self) -> dict[str, Any]:
        """Get assembler statistics."""
        return {
            "assemblies": self._assembly_count,
            "max_context": self._max_context,
        }
