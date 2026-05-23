"""Reasoning chain engine — multi-step reasoning with chain-of-thought.

Implements:
1. Explicit reasoning steps (observe → analyze → hypothesize → plan → act → reflect)
2. Reasoning chain construction and tracking
3. Evidence linking between reasoning steps
4. Confidence propagation through chains
5. Reasoning about uncertainty
6. Self-critique and revision
7. Reasoning chain serialization for LLM context
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ReasoningStepType(str, Enum):
    OBSERVE = "observe"        # Gather raw information
    ANALYZE = "analyze"        # Interpret observations
    HYPOTHESIZE = "hypothesize"  # Form hypotheses
    PLAN = "plan"             # Create action plan
    ACT = "act"              # Execute action
    REFLECT = "reflect"       # Evaluate results
    CRITIQUE = "critique"     # Self-critique
    REVISE = "revise"        # Revise based on critique
    SYNTHESIZE = "synthesize"  # Combine multiple chains


class ChainStatus(str, Enum):
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    ABANDONED = "abandoned"
    BRANCHED = "branched"


@dataclass
class ReasoningStep:
    """A single step in a reasoning chain."""
    step_id: str = ""
    step_type: ReasoningStepType = ReasoningStepType.OBSERVE
    content: str = ""
    evidence: list[str] = field(default_factory=list)
    confidence: float = 0.5
    parent_step: str = ""     # Previous step in chain
    tool_used: str = ""
    model_used: str = ""
    tokens_used: int = 0
    duration_ms: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.step_id[:8],
            "type": self.step_type.value,
            "content": self.content[:30],
            "conf": round(self.confidence, 2),
            "evidence": len(self.evidence),
        }


@dataclass
class ReasoningChain:
    """A chain of reasoning steps."""
    chain_id: str = ""
    goal: str = ""
    status: ChainStatus = ChainStatus.IN_PROGRESS
    steps: list[ReasoningStep] = field(default_factory=list)
    parent_chain: str = ""    # If branched from another chain
    confidence: float = 0.5
    conclusion: str = ""
    created_at: float = field(default_factory=time.time)
    completed_at: float = 0.0

    @property
    def step_count(self) -> int:
        return len(self.steps)

    @property
    def last_step_type(self) -> ReasoningStepType | None:
        if not self.steps:
            return None
        return self.steps[-1].step_type

    @property
    def avg_confidence(self) -> float:
        if not self.steps:
            return 0.0
        return sum(s.confidence for s in self.steps) / len(self.steps)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.chain_id[:8],
            "goal": self.goal[:25],
            "steps": self.step_count,
            "status": self.status.value,
            "conf": round(self.confidence, 2),
        }


# ── Standard reasoning templates ─────────────────────────────

REASONING_TEMPLATES: dict[str, list[ReasoningStepType]] = {
    "vulnerability_analysis": [
        ReasoningStepType.OBSERVE,
        ReasoningStepType.ANALYZE,
        ReasoningStepType.HYPOTHESIZE,
        ReasoningStepType.PLAN,
        ReasoningStepType.ACT,
        ReasoningStepType.REFLECT,
    ],
    "finding_validation": [
        ReasoningStepType.OBSERVE,
        ReasoningStepType.ANALYZE,
        ReasoningStepType.CRITIQUE,
        ReasoningStepType.REVISE,
    ],
    "exploit_development": [
        ReasoningStepType.OBSERVE,
        ReasoningStepType.ANALYZE,
        ReasoningStepType.HYPOTHESIZE,
        ReasoningStepType.PLAN,
        ReasoningStepType.ACT,
        ReasoningStepType.REFLECT,
        ReasoningStepType.CRITIQUE,
    ],
    "quick_assessment": [
        ReasoningStepType.OBSERVE,
        ReasoningStepType.ANALYZE,
        ReasoningStepType.SYNTHESIZE,
    ],
}


class ReasoningChainEngine:
    """Manages multi-step reasoning chains.

    Creates and tracks structured reasoning
    through observe-analyze-hypothesize-plan-act-reflect
    steps. Supports branching, self-critique, and
    confidence propagation.
    """

    def __init__(self, max_chains: int = 100) -> None:
        self._chains: dict[str, ReasoningChain] = {}
        self._max_chains = max_chains
        self._counter = 0
        self._log = logger.bind(component="reasoning_chain")

    def start_chain(
        self,
        goal: str,
        template: str = "vulnerability_analysis",
        parent_chain: str = "",
    ) -> ReasoningChain:
        """Start a new reasoning chain."""
        self._counter += 1
        chain = ReasoningChain(
            chain_id=f"chain-{self._counter}",
            goal=goal,
            parent_chain=parent_chain,
        )
        self._chains[chain.chain_id] = chain

        # Evict oldest if over limit
        while len(self._chains) > self._max_chains:
            oldest = min(self._chains.values(), key=lambda c: c.created_at)
            del self._chains[oldest.chain_id]

        return chain

    def add_step(
        self,
        chain_id: str,
        step_type: ReasoningStepType,
        content: str,
        evidence: list[str] | None = None,
        confidence: float = 0.5,
        tool_used: str = "",
        model_used: str = "",
        tokens_used: int = 0,
        duration_ms: float = 0.0,
    ) -> ReasoningStep | None:
        """Add a reasoning step to a chain."""
        chain = self._chains.get(chain_id)
        if not chain or chain.status != ChainStatus.IN_PROGRESS:
            return None

        self._counter += 1
        parent_id = chain.steps[-1].step_id if chain.steps else ""

        step = ReasoningStep(
            step_id=f"step-{self._counter}",
            step_type=step_type,
            content=content,
            evidence=evidence or [],
            confidence=confidence,
            parent_step=parent_id,
            tool_used=tool_used,
            model_used=model_used,
            tokens_used=tokens_used,
            duration_ms=duration_ms,
        )
        chain.steps.append(step)

        # Propagate confidence
        chain.confidence = self._propagate_confidence(chain)

        return step

    def complete_chain(
        self,
        chain_id: str,
        conclusion: str,
    ) -> bool:
        """Complete a reasoning chain."""
        chain = self._chains.get(chain_id)
        if not chain:
            return False

        chain.status = ChainStatus.COMPLETED
        chain.conclusion = conclusion
        chain.completed_at = time.time()
        return True

    def branch_chain(
        self,
        chain_id: str,
        new_goal: str,
        branch_from_step: int = -1,
    ) -> ReasoningChain | None:
        """Branch a chain to explore an alternative."""
        parent = self._chains.get(chain_id)
        if not parent:
            return None

        parent.status = ChainStatus.BRANCHED
        new_chain = self.start_chain(
            goal=new_goal,
            parent_chain=chain_id,
        )

        # Copy steps up to branch point
        steps_to_copy = parent.steps[:branch_from_step] if branch_from_step >= 0 else parent.steps[:]
        for step in steps_to_copy:
            new_chain.steps.append(step)

        return new_chain

    def get_suggested_next_step(
        self,
        chain_id: str,
        template: str = "vulnerability_analysis",
    ) -> ReasoningStepType | None:
        """Suggest the next step type based on template."""
        chain = self._chains.get(chain_id)
        if not chain:
            return None

        template_steps = REASONING_TEMPLATES.get(template)
        if not template_steps:
            return None

        current_idx = len(chain.steps)
        if current_idx >= len(template_steps):
            return None

        return template_steps[current_idx]

    def build_reasoning_prompt(
        self,
        chain_id: str = "",
        max_steps: int = 10,
    ) -> str:
        """Build reasoning context for LLM."""
        lines = ["## Reasoning Chain\n"]

        if chain_id:
            chain = self._chains.get(chain_id)
            if chain:
                lines.append(f"Goal: {chain.goal}")
                lines.append(f"Confidence: {chain.confidence:.0%}")
                lines.append(f"Steps ({chain.step_count}):")
                for step in chain.steps[-max_steps:]:
                    lines.append(
                        f"  [{step.step_type.value[:5]}] {step.content[:40]} "
                        f"(conf={step.confidence:.0%})"
                    )

                suggested = self.get_suggested_next_step(chain_id)
                if suggested:
                    lines.append(f"\nNext step: {suggested.value}")
        else:
            # Summary of active chains
            active = [c for c in self._chains.values() if c.status == ChainStatus.IN_PROGRESS]
            lines.append(f"Active chains: {len(active)}")
            for chain in active[:5]:
                lines.append(
                    f"  [{chain.chain_id[:6]}] {chain.goal[:25]} "
                    f"({chain.step_count} steps, {chain.confidence:.0%})"
                )

        return "\n".join(lines)

    def _propagate_confidence(self, chain: ReasoningChain) -> float:
        """Propagate confidence through chain steps."""
        if not chain.steps:
            return 0.5

        # Weighted average, recent steps weighted more
        total_weight = 0.0
        weighted_conf = 0.0
        for i, step in enumerate(chain.steps):
            weight = 1.0 + (i * 0.2)  # Later steps weighted more
            weighted_conf += step.confidence * weight
            total_weight += weight

        return weighted_conf / total_weight if total_weight else 0.5

    def get_stats(self) -> dict[str, Any]:
        status_counts: dict[str, int] = {}
        for c in self._chains.values():
            status_counts[c.status.value] = status_counts.get(c.status.value, 0) + 1

        return {
            "chains": len(self._chains),
            "by_status": status_counts,
            "total_steps": sum(c.step_count for c in self._chains.values()),
            "avg_confidence": (
                sum(c.confidence for c in self._chains.values()) / len(self._chains)
                if self._chains else 0
            ),
        }
