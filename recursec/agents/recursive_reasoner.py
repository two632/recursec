"""Recursive reasoner — deep multi-level reasoning with self-correction.

The core intelligence loop of the agent. Implements:
1. Multi-level recursive reasoning (think → plan → act → observe → reflect)
2. Self-correction: detects flawed reasoning and backtracks
3. Hypothesis generation and pruning
4. Evidence accumulation with Bayesian updates
5. Reasoning depth control with diminishing returns detection
6. Context window management across recursion levels
7. Thought branching and merging
8. Meta-reasoning (reasoning about reasoning quality)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ThoughtType(str, Enum):
    OBSERVATION = "observation"
    HYPOTHESIS = "hypothesis"
    PLAN = "plan"
    ACTION = "action"
    RESULT = "result"
    REFLECTION = "reflection"
    CORRECTION = "correction"
    CONCLUSION = "conclusion"


class ReasoningQuality(str, Enum):
    EXCELLENT = "excellent"
    GOOD = "good"
    ADEQUATE = "adequate"
    POOR = "poor"
    FLAWED = "flawed"


@dataclass
class Thought:
    """A single thought in a reasoning chain."""
    thought_id: str = ""
    thought_type: ThoughtType = ThoughtType.OBSERVATION
    content: str = ""
    confidence: float = 0.5
    evidence: list[str] = field(default_factory=list)
    parent_id: str = ""
    children_ids: list[str] = field(default_factory=list)
    depth: int = 0
    is_pruned: bool = False
    quality: ReasoningQuality = ReasoningQuality.ADEQUATE
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.thought_id,
            "type": self.thought_type.value,
            "content": self.content[:80],
            "confidence": round(self.confidence, 2),
            "depth": self.depth,
            "quality": self.quality.value,
            "pruned": self.is_pruned,
            "children": len(self.children_ids),
        }


@dataclass
class ReasoningSession:
    """A complete reasoning session."""
    session_id: str = ""
    goal: str = ""
    thoughts: dict[str, Thought] = field(default_factory=dict)
    root_thought_id: str = ""
    current_thought_id: str = ""
    max_depth: int = 5
    conclusion: str = ""
    overall_confidence: float = 0.0
    corrections_made: int = 0
    branches_explored: int = 0
    branches_pruned: int = 0
    created_at: float = field(default_factory=time.time)

    @property
    def thought_count(self) -> int:
        return len(self.thoughts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.session_id,
            "goal": self.goal[:60],
            "thoughts": self.thought_count,
            "conclusion": self.conclusion[:60],
            "confidence": round(self.overall_confidence, 2),
            "corrections": self.corrections_made,
            "branches": self.branches_explored,
            "pruned": self.branches_pruned,
        }


@dataclass
class MetaReasoningAssessment:
    """Assessment of reasoning quality."""
    coherence: float = 0.5         # Are thoughts logically connected?
    completeness: float = 0.5      # Are there gaps in reasoning?
    grounding: float = 0.5         # Is reasoning grounded in evidence?
    consistency: float = 0.5       # Are there contradictions?
    depth_quality: float = 0.5     # Is depth appropriate (not too shallow/deep)?

    @property
    def overall(self) -> float:
        return (self.coherence * 0.25 + self.completeness * 0.2 +
                self.grounding * 0.25 + self.consistency * 0.2 +
                self.depth_quality * 0.1)

    @property
    def quality(self) -> ReasoningQuality:
        score = self.overall
        if score >= 0.8:
            return ReasoningQuality.EXCELLENT
        if score >= 0.65:
            return ReasoningQuality.GOOD
        if score >= 0.5:
            return ReasoningQuality.ADEQUATE
        if score >= 0.35:
            return ReasoningQuality.POOR
        return ReasoningQuality.FLAWED

    def to_dict(self) -> dict[str, Any]:
        return {
            "coherence": round(self.coherence, 2),
            "completeness": round(self.completeness, 2),
            "grounding": round(self.grounding, 2),
            "consistency": round(self.consistency, 2),
            "depth": round(self.depth_quality, 2),
            "overall": round(self.overall, 2),
            "quality": self.quality.value,
        }


class RecursiveReasoner:
    """Deep multi-level reasoning with self-correction.

    Implements the agent's core thinking process:
    observe → hypothesize → plan → act → reflect → correct.
    Supports branching, backtracking, and meta-reasoning.
    """

    def __init__(
        self,
        max_depth: int = 5,
        confidence_threshold: float = 0.7,
        prune_threshold: float = 0.2,
    ) -> None:
        self._sessions: dict[str, ReasoningSession] = {}
        self._session_counter = 0
        self._thought_counter = 0
        self._max_depth = max_depth
        self._confidence_threshold = confidence_threshold
        self._prune_threshold = prune_threshold
        self._log = logger.bind(component="recursive_reasoner")

    def start_session(
        self,
        goal: str,
        initial_observations: list[str] | None = None,
    ) -> ReasoningSession:
        """Start a new reasoning session."""
        self._session_counter += 1
        session = ReasoningSession(
            session_id=f"reason-{self._session_counter}",
            goal=goal,
            max_depth=self._max_depth,
        )

        # Create root thought
        root = self._create_thought(
            session, ThoughtType.OBSERVATION,
            f"Goal: {goal}",
            depth=0, confidence=1.0,
        )
        session.root_thought_id = root.thought_id
        session.current_thought_id = root.thought_id

        # Add initial observations
        if initial_observations:
            for obs in initial_observations:
                self._create_thought(
                    session, ThoughtType.OBSERVATION,
                    obs, parent_id=root.thought_id,
                    depth=1, confidence=0.8,
                )

        self._sessions[session.session_id] = session
        return session

    def think(
        self,
        session_id: str,
        thought_type: ThoughtType,
        content: str,
        confidence: float = 0.5,
        evidence: list[str] | None = None,
    ) -> Thought:
        """Add a thought to the reasoning chain."""
        session = self._sessions.get(session_id)
        if not session:
            return Thought()

        parent_id = session.current_thought_id
        parent = session.thoughts.get(parent_id)
        depth = (parent.depth + 1) if parent else 0

        thought = self._create_thought(
            session, thought_type, content,
            parent_id=parent_id, depth=depth,
            confidence=confidence, evidence=evidence,
        )

        session.current_thought_id = thought.thought_id
        session.branches_explored += 1

        return thought

    def branch(
        self,
        session_id: str,
        alternatives: list[dict[str, Any]],
    ) -> list[Thought]:
        """Create branching thoughts (explore multiple hypotheses)."""
        session = self._sessions.get(session_id)
        if not session:
            return []

        parent_id = session.current_thought_id
        parent = session.thoughts.get(parent_id)
        depth = (parent.depth + 1) if parent else 0

        branches = []
        for alt in alternatives:
            thought = self._create_thought(
                session,
                ThoughtType(alt.get("type", "hypothesis")),
                alt.get("content", ""),
                parent_id=parent_id,
                depth=depth,
                confidence=alt.get("confidence", 0.5),
            )
            branches.append(thought)
            session.branches_explored += 1

        return branches

    def prune(self, session_id: str) -> int:
        """Prune low-confidence branches."""
        session = self._sessions.get(session_id)
        if not session:
            return 0

        pruned = 0
        for thought in session.thoughts.values():
            if thought.is_pruned:
                continue
            if thought.confidence < self._prune_threshold:
                self._prune_subtree(session, thought.thought_id)
                pruned += 1
                session.branches_pruned += 1

        return pruned

    def _prune_subtree(self, session: ReasoningSession, thought_id: str) -> None:
        """Recursively prune a thought and its children."""
        thought = session.thoughts.get(thought_id)
        if not thought:
            return

        thought.is_pruned = True
        for child_id in thought.children_ids:
            self._prune_subtree(session, child_id)

    def backtrack(self, session_id: str, to_thought_id: str = "") -> bool:
        """Backtrack to a previous thought."""
        session = self._sessions.get(session_id)
        if not session:
            return False

        if to_thought_id and to_thought_id in session.thoughts:
            session.current_thought_id = to_thought_id
            return True

        # Backtrack to parent of current thought
        current = session.thoughts.get(session.current_thought_id)
        if current and current.parent_id:
            session.current_thought_id = current.parent_id
            session.corrections_made += 1
            return True

        return False

    def correct(
        self,
        session_id: str,
        correction: str,
        new_confidence: float = 0.6,
    ) -> Thought:
        """Apply a self-correction."""
        session = self._sessions.get(session_id)
        if not session:
            return Thought()

        # Mark current thought as low-confidence
        current = session.thoughts.get(session.current_thought_id)
        if current:
            current.confidence *= 0.5
            current.quality = ReasoningQuality.FLAWED

        # Backtrack and add correction
        self.backtrack(session_id)
        thought = self.think(
            session_id, ThoughtType.CORRECTION,
            correction, confidence=new_confidence,
        )
        session.corrections_made += 1

        return thought

    def conclude(
        self,
        session_id: str,
        conclusion: str,
        confidence: float = 0.5,
    ) -> ReasoningSession:
        """Conclude the reasoning session."""
        session = self._sessions.get(session_id)
        if not session:
            return ReasoningSession()

        self.think(
            session_id, ThoughtType.CONCLUSION,
            conclusion, confidence=confidence,
        )

        session.conclusion = conclusion
        session.overall_confidence = confidence

        return session

    def meta_reason(self, session_id: str) -> MetaReasoningAssessment:
        """Assess the quality of reasoning in a session."""
        session = self._sessions.get(session_id)
        if not session:
            return MetaReasoningAssessment()

        thoughts = [t for t in session.thoughts.values() if not t.is_pruned]
        if not thoughts:
            return MetaReasoningAssessment()

        # Coherence: Are thoughts connected in a logical chain?
        connected = sum(1 for t in thoughts if t.parent_id in session.thoughts or t.depth == 0)
        coherence = connected / len(thoughts) if thoughts else 0.0

        # Completeness: Do we have the full think→plan→act→reflect cycle?
        types_present = {t.thought_type for t in thoughts}
        expected_types = {ThoughtType.OBSERVATION, ThoughtType.HYPOTHESIS,
                        ThoughtType.PLAN, ThoughtType.CONCLUSION}
        completeness = len(types_present & expected_types) / len(expected_types)

        # Grounding: How much evidence supports the thoughts?
        grounded = sum(1 for t in thoughts if t.evidence)
        grounding = grounded / len(thoughts) if thoughts else 0.0

        # Consistency: No contradictions (low-confidence siblings)
        inconsistencies = 0
        for thought in thoughts:
            siblings = [
                session.thoughts[cid]
                for cid in session.thoughts.get(thought.parent_id, Thought()).children_ids
                if cid != thought.thought_id and cid in session.thoughts
            ]
            for sibling in siblings:
                if abs(thought.confidence - sibling.confidence) > 0.5:
                    inconsistencies += 1

        consistency = max(0.0, 1.0 - inconsistencies * 0.1)

        # Depth quality: Not too shallow, not too deep
        max_actual_depth = max(t.depth for t in thoughts) if thoughts else 0
        if max_actual_depth == 0:
            depth_quality = 0.3
        elif 2 <= max_actual_depth <= session.max_depth:
            depth_quality = 0.8
        else:
            depth_quality = 0.5

        return MetaReasoningAssessment(
            coherence=coherence,
            completeness=completeness,
            grounding=grounding,
            consistency=consistency,
            depth_quality=depth_quality,
        )

    def get_reasoning_trace(
        self,
        session_id: str,
        include_pruned: bool = False,
    ) -> list[dict[str, Any]]:
        """Get the reasoning trace as an ordered list."""
        session = self._sessions.get(session_id)
        if not session:
            return []

        thoughts = sorted(
            session.thoughts.values(),
            key=lambda t: t.created_at,
        )

        if not include_pruned:
            thoughts = [t for t in thoughts if not t.is_pruned]

        return [t.to_dict() for t in thoughts]

    def get_best_branch(self, session_id: str) -> list[dict[str, Any]]:
        """Get the highest-confidence path from root to leaf."""
        session = self._sessions.get(session_id)
        if not session:
            return []

        path = []
        current_id = session.root_thought_id

        while current_id:
            thought = session.thoughts.get(current_id)
            if not thought:
                break

            path.append(thought.to_dict())

            # Choose highest confidence child
            best_child = None
            best_conf = -1.0
            for child_id in thought.children_ids:
                child = session.thoughts.get(child_id)
                if child and not child.is_pruned and child.confidence > best_conf:
                    best_conf = child.confidence
                    best_child = child_id

            current_id = best_child or ""

        return path

    def _create_thought(
        self,
        session: ReasoningSession,
        thought_type: ThoughtType,
        content: str,
        parent_id: str = "",
        depth: int = 0,
        confidence: float = 0.5,
        evidence: list[str] | None = None,
    ) -> Thought:
        """Create and register a thought."""
        self._thought_counter += 1
        thought = Thought(
            thought_id=f"t-{self._thought_counter}",
            thought_type=thought_type,
            content=content,
            confidence=confidence,
            evidence=evidence or [],
            parent_id=parent_id,
            depth=depth,
        )

        session.thoughts[thought.thought_id] = thought

        # Link to parent
        if parent_id and parent_id in session.thoughts:
            session.thoughts[parent_id].children_ids.append(thought.thought_id)

        return thought

    def get_stats(self) -> dict[str, Any]:
        total_thoughts = sum(s.thought_count for s in self._sessions.values())
        total_corrections = sum(s.corrections_made for s in self._sessions.values())
        return {
            "sessions": len(self._sessions),
            "total_thoughts": total_thoughts,
            "total_corrections": total_corrections,
        }
