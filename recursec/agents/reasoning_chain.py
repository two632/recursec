"""Reasoning chain tracker — tracks multi-step agent reasoning.

Implements:
1. Chain-of-thought step tracking
2. Branching exploration paths
3. Self-reflection checkpoints
4. Reasoning quality scoring
5. Backtracking on dead ends
6. Reasoning provenance
7. Multi-model reasoning aggregation
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ReasoningType(str, Enum):
    OBSERVATION = "observation"
    HYPOTHESIS = "hypothesis"
    DEDUCTION = "deduction"
    INDUCTION = "induction"
    ANALOGY = "analogy"
    TOOL_PLAN = "tool_plan"
    RESULT_ANALYSIS = "result_analysis"
    SELF_REFLECTION = "self_reflection"
    CONCLUSION = "conclusion"
    BACKTRACK = "backtrack"


class StepStatus(str, Enum):
    ACTIVE = "active"
    COMPLETED = "completed"
    DEAD_END = "dead_end"
    BRANCHED = "branched"
    BACKTRACKED = "backtracked"


@dataclass
class ReasoningStep:
    """A single step in a reasoning chain."""
    step_id: str = ""
    chain_id: str = ""
    step_type: ReasoningType = ReasoningType.OBSERVATION
    status: StepStatus = StepStatus.ACTIVE
    content: str = ""
    model_id: str = ""
    parent_step_id: str = ""       # For branching
    confidence: float = 0.5
    quality_score: float = 0.0     # Auto-assessed quality
    tokens_used: int = 0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.step_id[:10],
            "type": self.step_type.value,
            "status": self.status.value,
            "content": self.content[:30],
            "confidence": round(self.confidence, 2),
        }


@dataclass
class ReasoningChain:
    """A chain of reasoning steps."""
    chain_id: str = ""
    agent_id: str = ""
    goal: str = ""
    steps: list[ReasoningStep] = field(default_factory=list)
    branches: list[str] = field(default_factory=list)  # Branch chain IDs
    status: str = "active"
    total_tokens: int = 0
    started_at: float = field(default_factory=time.time)
    completed_at: float = 0.0

    @property
    def depth(self) -> int:
        return len(self.steps)

    @property
    def avg_confidence(self) -> float:
        if not self.steps:
            return 0.0
        return sum(s.confidence for s in self.steps) / len(self.steps)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.chain_id[:10],
            "goal": self.goal[:30],
            "steps": len(self.steps),
            "depth": self.depth,
            "avg_confidence": round(self.avg_confidence, 2),
            "status": self.status,
        }


# ── Quality heuristics ───────────────────────────────────────

QUALITY_INDICATORS: dict[str, list[str]] = {
    "good": [
        "based on", "evidence shows", "the output confirms",
        "this indicates", "specifically", "CVE-",
        "confirmed by", "validated", "because",
    ],
    "poor": [
        "might", "possibly", "I'm not sure", "unclear",
        "assume", "maybe", "probably", "I think",
        "I don't know", "cannot determine",
    ],
}

# ── Reflection prompts ───────────────────────────────────────

REFLECTION_PROMPTS: dict[str, str] = {
    "progress": (
        "Reflect on progress so far:\n"
        "1. What have we confirmed?\n"
        "2. What remains uncertain?\n"
        "3. Are we on the right track?\n"
        "4. Should we change approach?"
    ),
    "dead_end": (
        "This approach seems stuck:\n"
        "1. Why did this fail?\n"
        "2. What assumption was wrong?\n"
        "3. What alternative should we try?"
    ),
    "conclusion": (
        "Summarize the reasoning chain:\n"
        "1. Key findings and evidence\n"
        "2. Confidence level and gaps\n"
        "3. Recommended next actions"
    ),
}


def _assess_quality(content: str) -> float:
    """Heuristic quality assessment of reasoning content."""
    score = 0.5
    content_lower = content.lower()

    for indicator in QUALITY_INDICATORS.get("good", []):
        if indicator.lower() in content_lower:
            score += 0.05

    for indicator in QUALITY_INDICATORS.get("poor", []):
        if indicator.lower() in content_lower:
            score -= 0.05

    # Length bonus (more detailed reasoning is usually better)
    if len(content) > 200:
        score += 0.05
    if len(content) > 500:
        score += 0.05

    return max(0.0, min(1.0, score))


class ReasoningChainTracker:
    """Tracks and manages multi-step reasoning chains.

    Records reasoning steps, handles branching
    and backtracking, and provides quality
    assessments of reasoning.
    """

    def __init__(self) -> None:
        self._chains: dict[str, ReasoningChain] = {}
        self._chain_counter = 0
        self._step_counter = 0
        self._log = logger.bind(component="reasoning_chain")

    def start_chain(
        self,
        agent_id: str,
        goal: str,
    ) -> ReasoningChain:
        """Start a new reasoning chain."""
        self._chain_counter += 1
        chain = ReasoningChain(
            chain_id=f"rc-{self._chain_counter}",
            agent_id=agent_id,
            goal=goal,
        )
        self._chains[chain.chain_id] = chain
        return chain

    def add_step(
        self,
        chain_id: str,
        step_type: ReasoningType,
        content: str,
        model_id: str = "",
        confidence: float = 0.5,
        tokens_used: int = 0,
        parent_step_id: str = "",
    ) -> ReasoningStep | None:
        """Add a reasoning step."""
        chain = self._chains.get(chain_id)
        if not chain:
            return None

        self._step_counter += 1
        step = ReasoningStep(
            step_id=f"rs-{self._step_counter}",
            chain_id=chain_id,
            step_type=step_type,
            content=content,
            model_id=model_id,
            confidence=confidence,
            quality_score=_assess_quality(content),
            tokens_used=tokens_used,
            parent_step_id=parent_step_id,
        )
        chain.steps.append(step)
        chain.total_tokens += tokens_used

        return step

    def mark_dead_end(self, chain_id: str) -> None:
        """Mark the current chain path as a dead end."""
        chain = self._chains.get(chain_id)
        if not chain or not chain.steps:
            return

        chain.steps[-1].status = StepStatus.DEAD_END

    def branch(
        self,
        chain_id: str,
        alternative_goal: str,
    ) -> ReasoningChain | None:
        """Create a branch from current chain."""
        parent = self._chains.get(chain_id)
        if not parent:
            return None

        new_chain = self.start_chain(parent.agent_id, alternative_goal)
        parent.branches.append(new_chain.chain_id)

        if parent.steps:
            parent.steps[-1].status = StepStatus.BRANCHED

        return new_chain

    def backtrack(self, chain_id: str, to_step_id: str) -> bool:
        """Backtrack to a previous step."""
        chain = self._chains.get(chain_id)
        if not chain:
            return False

        found_idx = -1
        for idx, step in enumerate(chain.steps):
            if step.step_id == to_step_id:
                found_idx = idx
                break

        if found_idx < 0:
            return False

        for step in chain.steps[found_idx + 1:]:
            step.status = StepStatus.BACKTRACKED

        return True

    def should_reflect(self, chain_id: str, interval: int = 5) -> bool:
        """Check if chain should pause for reflection."""
        chain = self._chains.get(chain_id)
        if not chain:
            return False

        # Reflect every N steps
        if len(chain.steps) > 0 and len(chain.steps) % interval == 0:
            return True

        # Reflect if confidence is dropping
        if len(chain.steps) >= 3:
            recent = chain.steps[-3:]
            avg_recent = sum(s.confidence for s in recent) / 3
            if avg_recent < 0.3:
                return True

        return False

    def get_reflection_prompt(self, chain_id: str) -> str:
        """Get appropriate reflection prompt."""
        chain = self._chains.get(chain_id)
        if not chain or not chain.steps:
            return REFLECTION_PROMPTS["progress"]

        last_step = chain.steps[-1]
        if last_step.status == StepStatus.DEAD_END:
            return REFLECTION_PROMPTS["dead_end"]

        if chain.avg_confidence >= 0.8 and len(chain.steps) >= 5:
            return REFLECTION_PROMPTS["conclusion"]

        return REFLECTION_PROMPTS["progress"]

    def complete_chain(self, chain_id: str) -> None:
        """Mark a chain as completed."""
        chain = self._chains.get(chain_id)
        if chain:
            chain.status = "completed"
            chain.completed_at = time.time()

    def build_chain_prompt(
        self,
        chain_id: str,
        max_steps: int = 10,
    ) -> str:
        """Build reasoning history for LLM context."""
        chain = self._chains.get(chain_id)
        if not chain:
            return ""

        lines = [f"## Reasoning Chain: {chain.goal[:40]}\n"]

        # Show recent steps
        steps_to_show = chain.steps[-max_steps:]
        for step in steps_to_show:
            status_icon = {
                "active": "→",
                "completed": "✓",
                "dead_end": "✗",
                "branched": "⑂",
                "backtracked": "↩",
            }.get(step.status.value, "?")
            lines.append(
                f"  {status_icon} [{step.step_type.value}] "
                f"{step.content[:60]} "
                f"({step.confidence:.0%})"
            )

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        total_steps = sum(len(c.steps) for c in self._chains.values())
        completed = sum(1 for c in self._chains.values() if c.status == "completed")

        return {
            "total_chains": len(self._chains),
            "completed_chains": completed,
            "total_steps": total_steps,
            "total_tokens": sum(c.total_tokens for c in self._chains.values()),
        }
