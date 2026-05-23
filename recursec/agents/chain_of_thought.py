"""Chain-of-thought engine — structured reasoning for agents.

Implements:
1. Multi-step reasoning chains
2. Thought decomposition
3. Self-reflection and verification
4. Reasoning trace recording
5. Confidence scoring per step
6. Branching reasoning (explore alternatives)
7. Reasoning templates for security tasks
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ThoughtType(str, Enum):
    OBSERVATION = "observation"       # What we see
    HYPOTHESIS = "hypothesis"         # What we think
    DEDUCTION = "deduction"           # What we conclude
    PLAN = "plan"                     # What we'll do next
    REFLECTION = "reflection"         # Checking our reasoning
    REVISION = "revision"             # Correcting reasoning
    CONCLUSION = "conclusion"         # Final answer


class ReasoningStatus(str, Enum):
    IN_PROGRESS = "in_progress"
    COMPLETE = "complete"
    BRANCHED = "branched"
    REVISED = "revised"
    ABANDONED = "abandoned"


@dataclass
class Thought:
    """A single thought in a reasoning chain."""
    thought_id: str = ""
    step_number: int = 0
    thought_type: ThoughtType = ThoughtType.OBSERVATION
    content: str = ""
    evidence: str = ""
    confidence: float = 0.5
    parent_thought_id: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step_number,
            "type": self.thought_type.value,
            "content": self.content[:40],
            "confidence": round(self.confidence, 2),
        }


@dataclass
class ReasoningChain:
    """A complete chain of thoughts."""
    chain_id: str = ""
    goal: str = ""
    thoughts: list[Thought] = field(default_factory=list)
    status: ReasoningStatus = ReasoningStatus.IN_PROGRESS
    final_conclusion: str = ""
    overall_confidence: float = 0.5
    branches: list[str] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    completed_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.chain_id[:10],
            "goal": self.goal[:25],
            "steps": len(self.thoughts),
            "status": self.status.value,
            "confidence": round(self.overall_confidence, 2),
        }


# ── Reasoning templates ───────────────────────────────────────

REASONING_TEMPLATES: dict[str, list[dict[str, Any]]] = {
    "vulnerability_analysis": [
        {"type": "observation", "prompt": "What are the known facts about this target/service?"},
        {"type": "hypothesis", "prompt": "Based on these facts, what vulnerabilities might exist?"},
        {"type": "plan", "prompt": "What tools/tests will confirm or deny each hypothesis?"},
        {"type": "deduction", "prompt": "Based on test results, what is confirmed?"},
        {"type": "reflection", "prompt": "Are there false positives? Did we miss anything?"},
        {"type": "conclusion", "prompt": "Final assessment with severity and confidence."},
    ],
    "exploit_planning": [
        {"type": "observation", "prompt": "What vulnerability are we exploiting? What access do we have?"},
        {"type": "hypothesis", "prompt": "What exploitation technique is most likely to succeed?"},
        {"type": "plan", "prompt": "Step-by-step exploitation plan with tool commands."},
        {"type": "deduction", "prompt": "Based on each step's result, what happened?"},
        {"type": "reflection", "prompt": "Did exploitation succeed? Was it the right approach?"},
        {"type": "conclusion", "prompt": "Exploitation result with proof and impact assessment."},
    ],
    "reconnaissance_analysis": [
        {"type": "observation", "prompt": "What is the target's exposed attack surface?"},
        {"type": "hypothesis", "prompt": "What technologies and services are likely running?"},
        {"type": "plan", "prompt": "What additional recon will map the full surface?"},
        {"type": "deduction", "prompt": "What did additional recon reveal?"},
        {"type": "reflection", "prompt": "Is our surface map complete? What's missing?"},
        {"type": "conclusion", "prompt": "Complete attack surface map with priorities."},
    ],
    "false_positive_check": [
        {"type": "observation", "prompt": "What finding was reported? What evidence exists?"},
        {"type": "hypothesis", "prompt": "Is this a true positive, false positive, or informational?"},
        {"type": "plan", "prompt": "How can we verify this finding independently?"},
        {"type": "deduction", "prompt": "Based on verification, what's the verdict?"},
        {"type": "conclusion", "prompt": "Final classification with confidence."},
    ],
    "strategy_selection": [
        {"type": "observation", "prompt": "What do we know about the target so far?"},
        {"type": "hypothesis", "prompt": "What testing strategy will yield the most findings?"},
        {"type": "plan", "prompt": "Ordered list of strategies to try with expected outcomes."},
        {"type": "reflection", "prompt": "Are we considering non-obvious attack vectors?"},
        {"type": "conclusion", "prompt": "Selected strategy with rationale."},
    ],
}


class ChainOfThought:
    """Structured reasoning engine for agents.

    Guides LLM reasoning through structured
    thought chains with self-reflection,
    branching, and confidence tracking.
    """

    def __init__(self) -> None:
        self._chains: dict[str, ReasoningChain] = {}
        self._counter = 0
        self._log = logger.bind(component="chain_of_thought")

    def start_chain(
        self,
        goal: str,
        template: str = "",
    ) -> ReasoningChain:
        """Start a new reasoning chain."""
        self._counter += 1
        chain = ReasoningChain(
            chain_id=f"cot-{self._counter}",
            goal=goal,
        )
        self._chains[chain.chain_id] = chain
        return chain

    def add_thought(
        self,
        chain_id: str,
        thought_type: ThoughtType,
        content: str,
        evidence: str = "",
        confidence: float = 0.5,
        parent_thought_id: str = "",
    ) -> Thought | None:
        """Add a thought to a chain."""
        chain = self._chains.get(chain_id)
        if not chain:
            return None

        thought = Thought(
            thought_id=f"{chain_id}-t{len(chain.thoughts)}",
            step_number=len(chain.thoughts) + 1,
            thought_type=thought_type,
            content=content,
            evidence=evidence,
            confidence=confidence,
            parent_thought_id=parent_thought_id,
        )
        chain.thoughts.append(thought)

        # Update chain confidence (weighted average)
        if chain.thoughts:
            total_conf = sum(t.confidence for t in chain.thoughts)
            chain.overall_confidence = total_conf / len(chain.thoughts)

        return thought

    def branch_chain(
        self,
        chain_id: str,
        alternative_goal: str,
    ) -> ReasoningChain | None:
        """Create a branch from an existing chain."""
        parent_chain = self._chains.get(chain_id)
        if not parent_chain:
            return None

        branch = self.start_chain(alternative_goal)
        branch.status = ReasoningStatus.BRANCHED

        # Copy observations from parent
        for thought in parent_chain.thoughts:
            if thought.thought_type == ThoughtType.OBSERVATION:
                self.add_thought(
                    branch.chain_id,
                    ThoughtType.OBSERVATION,
                    thought.content,
                    thought.evidence,
                    thought.confidence,
                )

        parent_chain.branches.append(branch.chain_id)
        return branch

    def complete_chain(
        self,
        chain_id: str,
        conclusion: str,
        confidence: float = 0.5,
    ) -> ReasoningChain | None:
        """Complete a reasoning chain."""
        chain = self._chains.get(chain_id)
        if not chain:
            return None

        self.add_thought(
            chain_id,
            ThoughtType.CONCLUSION,
            conclusion,
            confidence=confidence,
        )

        chain.final_conclusion = conclusion
        chain.status = ReasoningStatus.COMPLETE
        chain.completed_at = time.time()
        return chain

    def get_template_prompts(
        self,
        template_name: str,
    ) -> list[dict[str, Any]]:
        """Get prompts for a reasoning template."""
        return REASONING_TEMPLATES.get(template_name, [])

    def build_cot_prompt(
        self,
        chain_id: str,
        template_name: str = "",
    ) -> str:
        """Build chain-of-thought prompt for LLM."""
        chain = self._chains.get(chain_id)
        if not chain:
            return ""

        lines = [f"## Chain of Thought: {chain.goal}\n"]

        # Add existing thoughts
        for thought in chain.thoughts:
            lines.append(
                f"Step {thought.step_number} [{thought.thought_type.value}] "
                f"(confidence: {thought.confidence:.0%}):"
            )
            lines.append(f"  {thought.content}")
            if thought.evidence:
                lines.append(f"  Evidence: {thought.evidence[:100]}")
            lines.append("")

        # Add next step from template
        if template_name:
            template = REASONING_TEMPLATES.get(template_name, [])
            next_step = len(chain.thoughts)
            if next_step < len(template):
                step = template[next_step]
                lines.append(f"\n## Next Step ({step['type']}):")
                lines.append(step["prompt"])

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        completed = sum(
            1 for c in self._chains.values()
            if c.status == ReasoningStatus.COMPLETE
        )
        total_thoughts = sum(len(c.thoughts) for c in self._chains.values())

        return {
            "chains": len(self._chains),
            "completed": completed,
            "total_thoughts": total_thoughts,
            "avg_confidence": round(
                sum(c.overall_confidence for c in self._chains.values()) /
                max(1, len(self._chains)), 2,
            ),
        }
