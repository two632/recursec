"""OODA loop engine — Observe→Orient→Decide→Act cycle.

Implements:
1. OODA phase management
2. Observation aggregation
3. Orientation analysis (threat modeling)
4. Decision matrix construction
5. Action execution tracking
6. Loop feedback integration
7. Phase transition rules
8. Stagnation recovery within OODA
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class OODAPhase(str, Enum):
    OBSERVE = "observe"
    ORIENT = "orient"
    DECIDE = "decide"
    ACT = "act"
    FEEDBACK = "feedback"      # Post-action feedback loop


class ObservationType(str, Enum):
    TOOL_OUTPUT = "tool_output"
    LLM_ANALYSIS = "llm_analysis"
    USER_INPUT = "user_input"
    ENVIRONMENTAL = "environmental"
    FINDING = "finding"
    ERROR = "error"
    ANOMALY = "anomaly"


@dataclass
class Observation:
    """An observation from the Observe phase."""
    obs_id: str = ""
    obs_type: ObservationType = ObservationType.TOOL_OUTPUT
    source: str = ""
    content: str = ""
    importance: float = 0.5      # 0-1
    actionable: bool = True
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.obs_id[:10],
            "type": self.obs_type.value,
            "source": self.source[:15],
            "content": self.content[:40],
            "importance": round(self.importance, 2),
        }


@dataclass
class Orientation:
    """Analysis from the Orient phase."""
    threats: list[str] = field(default_factory=list)
    opportunities: list[str] = field(default_factory=list)
    constraints: list[str] = field(default_factory=list)
    knowledge_gaps: list[str] = field(default_factory=list)
    attack_surface_changes: list[str] = field(default_factory=list)
    priority_shift: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "threats": len(self.threats),
            "opportunities": len(self.opportunities),
            "constraints": len(self.constraints),
            "gaps": len(self.knowledge_gaps),
            "priority": self.priority_shift[:30],
        }


@dataclass
class Decision:
    """A decision from the Decide phase."""
    decision_id: str = ""
    action_type: str = ""        # scan, exploit, analyze, validate, report
    target: str = ""
    tool: str = ""
    strategy: str = ""
    confidence: float = 0.5
    expected_value: float = 0.5
    alternatives: list[str] = field(default_factory=list)
    rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.decision_id[:10],
            "action": self.action_type[:12],
            "tool": self.tool[:10],
            "confidence": round(self.confidence, 2),
            "ev": round(self.expected_value, 2),
            "rationale": self.rationale[:30],
        }


@dataclass
class Action:
    """An action from the Act phase."""
    action_id: str = ""
    decision_id: str = ""
    tool: str = ""
    command: str = ""
    started_at: float = field(default_factory=time.time)
    completed_at: float = 0.0
    success: bool = False
    output_summary: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)

    @property
    def duration_s(self) -> float:
        if self.completed_at > 0:
            return self.completed_at - self.started_at
        return time.time() - self.started_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.action_id[:10],
            "tool": self.tool[:10],
            "success": self.success,
            "duration": round(self.duration_s, 1),
            "findings": len(self.findings),
        }


@dataclass
class OODACycle:
    """A complete OODA cycle."""
    cycle_id: str = ""
    cycle_num: int = 0
    phase: OODAPhase = OODAPhase.OBSERVE
    observations: list[Observation] = field(default_factory=list)
    orientation: Orientation = field(default_factory=Orientation)
    decisions: list[Decision] = field(default_factory=list)
    actions: list[Action] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    completed_at: float = 0.0

    @property
    def duration_s(self) -> float:
        if self.completed_at > 0:
            return self.completed_at - self.started_at
        return time.time() - self.started_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.cycle_id[:10],
            "num": self.cycle_num,
            "phase": self.phase.value,
            "observations": len(self.observations),
            "decisions": len(self.decisions),
            "actions": len(self.actions),
            "duration": round(self.duration_s, 1),
        }


class OODALoopEngine:
    """OODA loop engine for security assessment.

    Implements the Observe→Orient→Decide→Act cycle
    for systematic security testing with feedback.
    """

    def __init__(self, max_cycles: int = 50) -> None:
        self._cycles: list[OODACycle] = []
        self._current: OODACycle | None = None
        self._counter = 0
        self._max_cycles = max_cycles
        self._log = logger.bind(component="ooda_loop")

        # Phase transition rules
        self._phase_transitions: dict[OODAPhase, OODAPhase] = {
            OODAPhase.OBSERVE: OODAPhase.ORIENT,
            OODAPhase.ORIENT: OODAPhase.DECIDE,
            OODAPhase.DECIDE: OODAPhase.ACT,
            OODAPhase.ACT: OODAPhase.FEEDBACK,
            OODAPhase.FEEDBACK: OODAPhase.OBSERVE,
        }

    def start_cycle(self) -> OODACycle:
        """Start a new OODA cycle."""
        self._counter += 1
        cycle = OODACycle(
            cycle_id=f"ooda-{self._counter}",
            cycle_num=self._counter,
            phase=OODAPhase.OBSERVE,
        )
        self._current = cycle
        return cycle

    def add_observation(
        self,
        obs_type: ObservationType,
        source: str,
        content: str,
        importance: float = 0.5,
        actionable: bool = True,
    ) -> Observation | None:
        """Add an observation to the current cycle."""
        if not self._current or self._current.phase != OODAPhase.OBSERVE:
            return None

        self._counter += 1
        obs = Observation(
            obs_id=f"obs-{self._counter}",
            obs_type=obs_type,
            source=source,
            content=content,
            importance=importance,
            actionable=actionable,
        )
        self._current.observations.append(obs)
        return obs

    def orient(
        self,
        threats: list[str] | None = None,
        opportunities: list[str] | None = None,
        constraints: list[str] | None = None,
        knowledge_gaps: list[str] | None = None,
        priority_shift: str = "",
    ) -> Orientation | None:
        """Complete the Orient phase."""
        if not self._current:
            return None

        self._current.phase = OODAPhase.ORIENT
        orientation = Orientation(
            threats=threats or [],
            opportunities=opportunities or [],
            constraints=constraints or [],
            knowledge_gaps=knowledge_gaps or [],
            priority_shift=priority_shift,
        )
        self._current.orientation = orientation
        return orientation

    def decide(
        self,
        action_type: str,
        target: str = "",
        tool: str = "",
        strategy: str = "",
        confidence: float = 0.5,
        expected_value: float = 0.5,
        alternatives: list[str] | None = None,
        rationale: str = "",
    ) -> Decision | None:
        """Make a decision."""
        if not self._current:
            return None

        self._current.phase = OODAPhase.DECIDE
        self._counter += 1
        decision = Decision(
            decision_id=f"dec-{self._counter}",
            action_type=action_type,
            target=target,
            tool=tool,
            strategy=strategy,
            confidence=confidence,
            expected_value=expected_value,
            alternatives=alternatives or [],
            rationale=rationale,
        )
        self._current.decisions.append(decision)
        return decision

    def act(
        self,
        decision_id: str,
        tool: str,
        command: str = "",
    ) -> Action | None:
        """Start an action."""
        if not self._current:
            return None

        self._current.phase = OODAPhase.ACT
        self._counter += 1
        action = Action(
            action_id=f"act-{self._counter}",
            decision_id=decision_id,
            tool=tool,
            command=command,
        )
        self._current.actions.append(action)
        return action

    def complete_action(
        self,
        action_id: str,
        success: bool,
        output_summary: str = "",
        findings: list[dict[str, Any]] | None = None,
    ) -> bool:
        """Complete an action."""
        if not self._current:
            return False

        for action in self._current.actions:
            if action.action_id == action_id:
                action.success = success
                action.completed_at = time.time()
                action.output_summary = output_summary
                if findings:
                    action.findings.extend(findings)
                return True

        return False

    def complete_cycle(self) -> OODACycle | None:
        """Complete the current OODA cycle."""
        if not self._current:
            return None

        self._current.phase = OODAPhase.FEEDBACK
        self._current.completed_at = time.time()
        self._cycles.append(self._current)

        completed = self._current
        self._current = None
        return completed

    def should_continue(self) -> bool:
        """Check if we should continue cycling."""
        if len(self._cycles) >= self._max_cycles:
            return False

        # Check for diminishing returns
        if len(self._cycles) >= 5:
            recent = self._cycles[-5:]
            total_findings = sum(
                len(a.findings) for c in recent for a in c.actions
            )
            if total_findings == 0:
                return False

        return True

    def get_cycle_summary(self) -> dict[str, Any]:
        """Get summary of all cycles."""
        total_observations = sum(len(c.observations) for c in self._cycles)
        total_decisions = sum(len(c.decisions) for c in self._cycles)
        total_actions = sum(len(c.actions) for c in self._cycles)
        total_findings = sum(
            len(a.findings) for c in self._cycles for a in c.actions
        )

        return {
            "cycles": len(self._cycles),
            "observations": total_observations,
            "decisions": total_decisions,
            "actions": total_actions,
            "findings": total_findings,
            "avg_cycle_time": round(
                sum(c.duration_s for c in self._cycles) / max(1, len(self._cycles)),
                1,
            ),
        }

    def build_feedback_prompt(self) -> str:
        """Build a feedback prompt from the last cycle."""
        if not self._cycles:
            return ""

        last = self._cycles[-1]
        lines = ["## OODA Cycle Feedback\n"]
        lines.append(f"Cycle {last.cycle_num}:")

        # Observations
        if last.observations:
            lines.append(f"\nObservations ({len(last.observations)}):")
            for obs in last.observations[:5]:
                lines.append(f"  [{obs.obs_type.value}] {obs.content[:50]}")

        # Orientation
        orient = last.orientation
        if orient.threats:
            lines.append(f"\nThreats: {', '.join(orient.threats[:3])}")
        if orient.opportunities:
            lines.append(f"Opportunities: {', '.join(orient.opportunities[:3])}")
        if orient.knowledge_gaps:
            lines.append(f"Knowledge gaps: {', '.join(orient.knowledge_gaps[:3])}")

        # Actions
        if last.actions:
            lines.append(f"\nActions ({len(last.actions)}):")
            for act in last.actions:
                status = "OK" if act.success else "FAIL"
                lines.append(f"  [{status}] {act.tool}: {act.output_summary[:40]}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        summary = self.get_cycle_summary()
        summary["current_phase"] = self._current.phase.value if self._current else "none"
        summary["max_cycles"] = self._max_cycles
        return summary
