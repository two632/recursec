"""Reasoning chain engine — structured chain-of-thought with backtracking.

Implements:
1. Step-by-step reasoning chains
2. Branch and backtrack on dead ends
3. Evidence-based reasoning (link to findings)
4. Hypothesis tracking
5. Reasoning quality scoring
6. Reasoning prompt for LLM
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class StepType(str, Enum):
    OBSERVATION = "observation"
    HYPOTHESIS = "hypothesis"
    ACTION = "action"
    RESULT = "result"
    DEDUCTION = "deduction"
    BACKTRACK = "backtrack"
    CONCLUSION = "conclusion"


class StepStatus(str, Enum):
    ACTIVE = "active"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    BACKTRACKED = "backtracked"


@dataclass
class ReasoningStep:
    """A single step in a reasoning chain."""
    step_id: str = ""
    step_type: StepType = StepType.OBSERVATION
    content: str = ""
    status: StepStatus = StepStatus.ACTIVE
    parent_step: str = ""       # Parent step ID
    branch_id: str = "main"     # Branch identifier
    evidence: list[str] = field(default_factory=list)
    confidence: float = 0.5
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.step_id[:8],
            "type": self.step_type.value[:6],
            "status": self.status.value[:6],
            "branch": self.branch_id[:6],
            "conf": f"{self.confidence:.0%}",
        }


@dataclass
class Hypothesis:
    """A tracked hypothesis."""
    hyp_id: str = ""
    statement: str = ""
    confidence: float = 0.5
    supporting: list[str] = field(default_factory=list)     # Step IDs that support
    contradicting: list[str] = field(default_factory=list)  # Step IDs that contradict
    status: str = "active"    # active, confirmed, rejected

    @property
    def net_evidence(self) -> int:
        return len(self.supporting) - len(self.contradicting)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.hyp_id[:8],
            "statement": self.statement[:30],
            "conf": f"{self.confidence:.0%}",
            "for": len(self.supporting),
            "against": len(self.contradicting),
        }


@dataclass
class ReasoningChain:
    """A complete reasoning chain."""
    chain_id: str = ""
    task: str = ""
    steps: list[ReasoningStep] = field(default_factory=list)
    hypotheses: list[Hypothesis] = field(default_factory=list)
    current_branch: str = "main"
    branches: list[str] = field(default_factory=lambda: ["main"])
    quality_score: float = 0.0
    created_at: float = field(default_factory=time.time)
    completed_at: float = 0.0

    @property
    def active_steps(self) -> list[ReasoningStep]:
        return [s for s in self.steps if s.status == StepStatus.ACTIVE]

    @property
    def is_complete(self) -> bool:
        return any(s.step_type == StepType.CONCLUSION for s in self.steps)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.chain_id[:10],
            "steps": len(self.steps),
            "branches": len(self.branches),
            "hypotheses": len(self.hypotheses),
            "quality": f"{self.quality_score:.0%}",
        }


class ReasoningEngine:
    """Structured reasoning with chain-of-thought and backtracking.

    Manages reasoning chains that track observations,
    hypotheses, actions, and conclusions with the ability
    to branch and backtrack when reasoning paths fail.
    """

    def __init__(self) -> None:
        self._chains: dict[str, ReasoningChain] = {}
        self._chain_counter = 0
        self._step_counter = 0
        self._hyp_counter = 0
        self._log = logger.bind(component="reasoning")

    def create_chain(self, task: str) -> ReasoningChain:
        """Create a new reasoning chain."""
        self._chain_counter += 1
        chain = ReasoningChain(
            chain_id=f"chain-{self._chain_counter}",
            task=task,
        )
        self._chains[chain.chain_id] = chain
        return chain

    def add_step(
        self,
        chain_id: str,
        step_type: StepType,
        content: str,
        evidence: list[str] | None = None,
        confidence: float = 0.5,
    ) -> ReasoningStep | None:
        """Add a step to a reasoning chain."""
        chain = self._chains.get(chain_id)
        if not chain:
            return None

        self._step_counter += 1

        # Find parent (last step on current branch)
        parent_id = ""
        for step in reversed(chain.steps):
            if step.branch_id == chain.current_branch and step.status == StepStatus.ACTIVE:
                parent_id = step.step_id
                break

        step = ReasoningStep(
            step_id=f"step-{self._step_counter}",
            step_type=step_type,
            content=content,
            parent_step=parent_id,
            branch_id=chain.current_branch,
            evidence=evidence or [],
            confidence=confidence,
        )

        chain.steps.append(step)

        # Update hypotheses
        self._update_hypotheses(chain, step)

        return step

    def add_hypothesis(
        self,
        chain_id: str,
        statement: str,
        confidence: float = 0.5,
    ) -> Hypothesis | None:
        """Add a hypothesis to track."""
        chain = self._chains.get(chain_id)
        if not chain:
            return None

        self._hyp_counter += 1
        hyp = Hypothesis(
            hyp_id=f"hyp-{self._hyp_counter}",
            statement=statement,
            confidence=confidence,
        )
        chain.hypotheses.append(hyp)
        return hyp

    def _update_hypotheses(self, chain: ReasoningChain, step: ReasoningStep) -> None:
        """Update hypotheses based on new step."""
        if step.step_type == StepType.RESULT:
            for hyp in chain.hypotheses:
                if hyp.status != "active":
                    continue
                # Check if result supports or contradicts
                content_lower = step.content.lower()
                stmt_lower = hyp.statement.lower()

                # Simple keyword overlap heuristic
                stmt_words = set(stmt_lower.split())
                content_words = set(content_lower.split())
                overlap = stmt_words & content_words

                if len(overlap) >= 2:
                    if any(neg in content_lower for neg in ["not found", "failed", "no ", "denied"]):
                        hyp.contradicting.append(step.step_id)
                        hyp.confidence *= 0.8
                    else:
                        hyp.supporting.append(step.step_id)
                        hyp.confidence = min(0.99, hyp.confidence * 1.1)

    def branch(self, chain_id: str, reason: str = "") -> str | None:
        """Create a new reasoning branch."""
        chain = self._chains.get(chain_id)
        if not chain:
            return None

        branch_name = f"b{len(chain.branches)}"
        chain.branches.append(branch_name)
        chain.current_branch = branch_name

        self.add_step(
            chain_id,
            StepType.OBSERVATION,
            f"Branching: {reason}",
        )

        return branch_name

    def backtrack(self, chain_id: str, reason: str = "") -> bool:
        """Backtrack to previous branch."""
        chain = self._chains.get(chain_id)
        if not chain or len(chain.branches) < 2:
            return False

        # Mark current branch steps as backtracked
        current = chain.current_branch
        for step in chain.steps:
            if step.branch_id == current and step.status == StepStatus.ACTIVE:
                step.status = StepStatus.BACKTRACKED

        self._step_counter += 1
        bt_step = ReasoningStep(
            step_id=f"step-{self._step_counter}",
            step_type=StepType.BACKTRACK,
            content=f"Backtracking: {reason}",
            branch_id=current,
        )
        chain.steps.append(bt_step)

        # Switch to previous branch
        idx = chain.branches.index(current)
        chain.current_branch = chain.branches[idx - 1] if idx > 0 else "main"

        return True

    def conclude(
        self,
        chain_id: str,
        conclusion: str,
        confidence: float = 0.5,
    ) -> ReasoningStep | None:
        """Add a conclusion to end the chain."""
        chain = self._chains.get(chain_id)
        if not chain:
            return None

        step = self.add_step(
            chain_id,
            StepType.CONCLUSION,
            conclusion,
            confidence=confidence,
        )

        if step:
            chain.completed_at = time.time()
            chain.quality_score = self._score_chain(chain)

        return step

    def _score_chain(self, chain: ReasoningChain) -> float:
        """Score reasoning quality."""
        if not chain.steps:
            return 0.0

        score = 0.0

        # Has observations? (+0.2)
        if any(s.step_type == StepType.OBSERVATION for s in chain.steps):
            score += 0.2

        # Has hypotheses? (+0.15)
        if chain.hypotheses:
            score += 0.15

        # Has evidence-backed steps? (+0.2)
        evidence_steps = sum(1 for s in chain.steps if s.evidence)
        if evidence_steps > 0:
            score += min(0.2, evidence_steps * 0.05)

        # Has conclusions? (+0.2)
        if chain.is_complete:
            score += 0.2

        # Hypothesis resolution (+0.15)
        resolved = sum(1 for h in chain.hypotheses if h.status != "active")
        if chain.hypotheses:
            score += 0.15 * (resolved / len(chain.hypotheses))

        # Low backtrack ratio (+0.1)
        total = len(chain.steps)
        bt = sum(1 for s in chain.steps if s.status == StepStatus.BACKTRACKED)
        if total > 0:
            bt_ratio = bt / total
            score += 0.1 * max(0, 1 - bt_ratio * 2)

        return min(1.0, score)

    def build_reasoning_prompt(self, chain_id: str = "") -> str:
        """Build reasoning context for LLM."""
        lines = ["## Reasoning State\n"]

        if chain_id and chain_id in self._chains:
            chain = self._chains[chain_id]
            lines.append(f"Task: {chain.task[:50]}")
            lines.append(f"Steps: {len(chain.steps)} | Branches: {len(chain.branches)}")
            lines.append(f"Current branch: {chain.current_branch}")

            # Recent active steps
            active = [s for s in chain.steps if s.status == StepStatus.ACTIVE][-5:]
            if active:
                lines.append("\nRecent reasoning:")
                for s in active:
                    lines.append(f"  [{s.step_type.value[:6]}] {s.content[:50]}")

            # Active hypotheses
            active_hyps = [h for h in chain.hypotheses if h.status == "active"]
            if active_hyps:
                lines.append("\nHypotheses:")
                for h in active_hyps[:3]:
                    lines.append(
                        f"  {h.statement[:40]} "
                        f"(conf={h.confidence:.0%}, +"
                        f"{len(h.supporting)}/-{len(h.contradicting)})"
                    )
        else:
            lines.append(f"Active chains: {len(self._chains)}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        total_steps = sum(len(c.steps) for c in self._chains.values())
        total_hyps = sum(len(c.hypotheses) for c in self._chains.values())

        return {
            "total_chains": len(self._chains),
            "total_steps": total_steps,
            "total_hypotheses": total_hyps,
            "completed": sum(1 for c in self._chains.values() if c.is_complete),
        }
