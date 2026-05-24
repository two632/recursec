"""Meta-reasoning engine — the agent reasons about its own reasoning.

This is the highest-level intelligence module. It:
1. Monitors reasoning quality across all tasks
2. Detects when the agent is stuck or going in circles
3. Switches reasoning strategies when current approach fails
4. Maintains beliefs about target state and updates them
5. Generates alternative hypotheses when primary fails
6. Evaluates confidence calibration (is the agent overconfident?)
7. Decides when to escalate vs continue autonomously
8. Tracks cognitive load and adjusts complexity

This feeds directly into the LLM prompts to make the agent
self-aware about its own reasoning process.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ReasoningStrategy(str, Enum):
    DEPTH_FIRST = "depth_first"
    BREADTH_FIRST = "breadth_first"
    HYPOTHESIS_DRIVEN = "hypothesis_driven"
    PATTERN_MATCHING = "pattern_matching"
    ELIMINATION = "elimination"
    ANALOGY = "analogy"
    DECOMPOSITION = "decomposition"
    ABSTRACTION = "abstraction"
    SIMULATION = "simulation"
    ADVERSARIAL = "adversarial"


class BeliefType(str, Enum):
    TECHNOLOGY = "technology"
    VULNERABILITY = "vulnerability"
    CONFIGURATION = "configuration"
    BEHAVIOR = "behavior"
    PROTECTION = "protection"
    ARCHITECTURE = "architecture"


class CognitiveState(str, Enum):
    EXPLORING = "exploring"
    FOCUSED = "focused"
    STUCK = "stuck"
    CONVERGING = "converging"
    DIVERGING = "diverging"
    VALIDATING = "validating"
    ESCALATING = "escalating"


@dataclass
class Belief:
    """A belief the agent holds about the target."""
    belief_id: str = ""
    belief_type: BeliefType = BeliefType.TECHNOLOGY
    subject: str = ""
    proposition: str = ""
    confidence: float = 0.5
    evidence: list[str] = field(default_factory=list)
    contradictions: list[str] = field(default_factory=list)
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.belief_type.value[:6],
            "subject": self.subject[:15],
            "prop": self.proposition[:30],
            "conf": f"{self.confidence:.2f}",
            "evidence": len(self.evidence),
        }


@dataclass
class ReasoningTrace:
    """A trace of a reasoning attempt."""
    trace_id: str = ""
    strategy: ReasoningStrategy = ReasoningStrategy.DEPTH_FIRST
    goal: str = ""
    steps_taken: int = 0
    success: bool = False
    duration_s: float = 0.0
    findings_produced: int = 0
    confidence_start: float = 0.5
    confidence_end: float = 0.5
    dead_ends: int = 0
    backtracks: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy": self.strategy.value[:8],
            "steps": self.steps_taken,
            "ok": self.success,
            "findings": self.findings_produced,
            "dead_ends": self.dead_ends,
        }


@dataclass
class StrategyPerformance:
    """Track performance of each reasoning strategy."""
    strategy: ReasoningStrategy = ReasoningStrategy.DEPTH_FIRST
    attempts: int = 0
    successes: int = 0
    total_findings: int = 0
    avg_duration_s: float = 0.0

    @property
    def success_rate(self) -> float:
        return self.successes / max(self.attempts, 1)

    @property
    def findings_per_attempt(self) -> float:
        return self.total_findings / max(self.attempts, 1)

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy": self.strategy.value[:10],
            "attempts": self.attempts,
            "success_rate": f"{self.success_rate:.2f}",
            "findings/attempt": f"{self.findings_per_attempt:.1f}",
        }


# Strategy selection rules based on task context
STRATEGY_RECOMMENDATIONS: dict[str, list[ReasoningStrategy]] = {
    "web_vuln_scan": [ReasoningStrategy.BREADTH_FIRST, ReasoningStrategy.HYPOTHESIS_DRIVEN, ReasoningStrategy.PATTERN_MATCHING],
    "code_audit": [ReasoningStrategy.DEPTH_FIRST, ReasoningStrategy.PATTERN_MATCHING, ReasoningStrategy.DECOMPOSITION],
    "network_pentest": [ReasoningStrategy.BREADTH_FIRST, ReasoningStrategy.ELIMINATION, ReasoningStrategy.DEPTH_FIRST],
    "exploit_dev": [ReasoningStrategy.HYPOTHESIS_DRIVEN, ReasoningStrategy.SIMULATION, ReasoningStrategy.ADVERSARIAL],
    "incident_response": [ReasoningStrategy.ELIMINATION, ReasoningStrategy.PATTERN_MATCHING, ReasoningStrategy.DECOMPOSITION],
    "threat_hunt": [ReasoningStrategy.HYPOTHESIS_DRIVEN, ReasoningStrategy.ANALOGY, ReasoningStrategy.ADVERSARIAL],
    "recon": [ReasoningStrategy.BREADTH_FIRST, ReasoningStrategy.DECOMPOSITION, ReasoningStrategy.PATTERN_MATCHING],
}

# Stuck detection patterns
STUCK_INDICATORS: list[dict[str, Any]] = [
    {"name": "no_new_findings", "threshold": 5, "description": "No new findings in N consecutive steps"},
    {"name": "repeated_actions", "threshold": 3, "description": "Same action repeated N times"},
    {"name": "confidence_plateau", "threshold": 0.05, "description": "Confidence change < threshold across 3 steps"},
    {"name": "excessive_duration", "threshold": 300, "description": "Single phase exceeding N seconds"},
    {"name": "high_dead_end_ratio", "threshold": 0.6, "description": "Dead ends > threshold of total paths explored"},
]


class MetaReasoningEngine:
    """Reasons about the agent's own reasoning."""

    def __init__(self) -> None:
        self._beliefs: dict[str, Belief] = {}
        self._traces: list[ReasoningTrace] = []
        self._strategy_perf: dict[ReasoningStrategy, StrategyPerformance] = {}
        self._cognitive_state = CognitiveState.EXPLORING
        self._current_strategy = ReasoningStrategy.BREADTH_FIRST
        self._belief_counter = 0
        self._trace_counter = 0
        self._stuck_counter = 0
        self._actions_history: list[str] = []
        self._findings_since_change = 0
        self._log = logger.bind(component="meta_reasoning")

    @property
    def cognitive_state(self) -> CognitiveState:
        return self._cognitive_state

    @property
    def current_strategy(self) -> ReasoningStrategy:
        return self._current_strategy

    def add_belief(
        self,
        belief_type: BeliefType,
        subject: str,
        proposition: str,
        confidence: float = 0.5,
        evidence: str = "",
    ) -> Belief:
        """Add or update a belief about the target."""
        self._belief_counter += 1
        # Check for existing belief about same subject+type
        existing_key = f"{belief_type.value}:{subject}"
        if existing_key in self._beliefs:
            belief = self._beliefs[existing_key]
            if evidence:
                belief.evidence.append(evidence)
            # Bayesian-like update: new evidence adjusts confidence
            old_conf = belief.confidence
            belief.confidence = old_conf * 0.7 + confidence * 0.3
            belief.updated_at = time.time()
            return belief

        belief = Belief(
            belief_id=f"belief-{self._belief_counter}",
            belief_type=belief_type,
            subject=subject,
            proposition=proposition,
            confidence=confidence,
            evidence=[evidence] if evidence else [],
        )
        self._beliefs[existing_key] = belief
        return belief

    def contradict_belief(
        self,
        belief_type: BeliefType,
        subject: str,
        contradiction: str,
        weight: float = 0.3,
    ) -> Belief | None:
        """Record evidence contradicting a belief."""
        key = f"{belief_type.value}:{subject}"
        belief = self._beliefs.get(key)
        if not belief:
            return None
        belief.contradictions.append(contradiction)
        belief.confidence = max(0.0, belief.confidence - weight)
        belief.updated_at = time.time()
        return belief

    def get_high_confidence_beliefs(self, min_confidence: float = 0.7) -> list[Belief]:
        """Get beliefs we're fairly certain about."""
        return [b for b in self._beliefs.values() if b.confidence >= min_confidence]

    def get_uncertain_beliefs(self, max_confidence: float = 0.5) -> list[Belief]:
        """Get beliefs we need more evidence for."""
        return [b for b in self._beliefs.values() if b.confidence <= max_confidence]

    def start_reasoning_trace(
        self,
        strategy: ReasoningStrategy,
        goal: str,
    ) -> ReasoningTrace:
        """Start tracking a reasoning attempt."""
        self._trace_counter += 1
        trace = ReasoningTrace(
            trace_id=f"trace-{self._trace_counter}",
            strategy=strategy,
            goal=goal,
            confidence_start=self._get_avg_belief_confidence(),
        )
        self._traces.append(trace)
        return trace

    def end_reasoning_trace(
        self,
        trace: ReasoningTrace,
        success: bool,
        findings_count: int = 0,
        dead_ends: int = 0,
    ) -> None:
        """End tracking a reasoning attempt."""
        trace.success = success
        trace.findings_produced = findings_count
        trace.dead_ends = dead_ends
        trace.confidence_end = self._get_avg_belief_confidence()
        trace.duration_s = time.time() - (trace.duration_s or time.time())

        # Update strategy performance
        perf = self._strategy_perf.get(trace.strategy)
        if not perf:
            perf = StrategyPerformance(strategy=trace.strategy)
            self._strategy_perf[trace.strategy] = perf
        perf.attempts += 1
        if success:
            perf.successes += 1
        perf.total_findings += findings_count
        n = perf.attempts
        perf.avg_duration_s = perf.avg_duration_s * (n - 1) / n + trace.duration_s / n

        self._findings_since_change += findings_count

    def record_action(self, action: str) -> None:
        """Record an action for stuck detection."""
        self._actions_history.append(action)
        if len(self._actions_history) > 100:
            self._actions_history = self._actions_history[-50:]

    def detect_stuck(self) -> bool:
        """Detect if the agent is stuck."""
        # Check for repeated actions
        if len(self._actions_history) >= 3:
            last_3 = self._actions_history[-3:]
            if len(set(last_3)) == 1:
                self._stuck_counter += 1
                return True

        # Check for no findings
        if self._findings_since_change == 0 and len(self._traces) >= 5:
            recent = self._traces[-5:]
            total = sum(t.findings_produced for t in recent)
            if total == 0:
                self._stuck_counter += 1
                return True

        # Check high dead-end ratio in recent traces
        if len(self._traces) >= 3:
            recent = self._traces[-3:]
            total_steps = sum(t.steps_taken for t in recent)
            total_dead = sum(t.dead_ends for t in recent)
            if total_steps > 0 and total_dead / total_steps > 0.6:
                self._stuck_counter += 1
                return True

        return False

    def select_strategy(self, task_type: str = "") -> ReasoningStrategy:
        """Select the best reasoning strategy based on performance and context."""
        # Get recommendations for task type
        recommended = STRATEGY_RECOMMENDATIONS.get(task_type, list(ReasoningStrategy))

        # If stuck, switch to a different strategy
        if self.detect_stuck():
            self._cognitive_state = CognitiveState.STUCK
            # Pick strategy with best performance that isn't current
            alternatives = [s for s in recommended if s != self._current_strategy]
            if alternatives:
                # Prefer strategies we haven't tried or that have better success
                best = alternatives[0]
                best_score = -1.0
                for strat in alternatives:
                    perf = self._strategy_perf.get(strat)
                    if not perf:
                        # Untried strategy gets bonus
                        score = 0.5
                    else:
                        score = perf.success_rate * 0.5 + perf.findings_per_attempt * 0.3
                    if score > best_score:
                        best_score = score
                        best = strat
                self._current_strategy = best
                self._findings_since_change = 0
                self._cognitive_state = CognitiveState.DIVERGING
                return best

        # Normal selection: use task type recommendations weighted by performance
        best = recommended[0] if recommended else ReasoningStrategy.BREADTH_FIRST
        best_score = -1.0
        for strat in recommended:
            perf = self._strategy_perf.get(strat)
            if not perf:
                score = 0.4  # Moderate score for untried
            else:
                score = perf.success_rate * 0.4 + perf.findings_per_attempt * 0.4 + (1.0 / max(perf.avg_duration_s, 0.1)) * 0.2
            if score > best_score:
                best_score = score
                best = strat

        self._current_strategy = best
        return best

    def should_escalate(self) -> bool:
        """Determine if the agent should escalate to a higher authority."""
        return self._stuck_counter >= 3

    def should_go_deeper(self) -> bool:
        """Determine if the agent should go deeper on current path."""
        if self._cognitive_state == CognitiveState.STUCK:
            return False
        uncertain = self.get_uncertain_beliefs()
        return len(uncertain) > 0

    def _get_avg_belief_confidence(self) -> float:
        if not self._beliefs:
            return 0.5
        return sum(b.confidence for b in self._beliefs.values()) / len(self._beliefs)

    def get_stats(self) -> dict[str, Any]:
        return {
            "cognitive_state": self._cognitive_state.value,
            "current_strategy": self._current_strategy.value,
            "beliefs": len(self._beliefs),
            "avg_confidence": f"{self._get_avg_belief_confidence():.2f}",
            "traces": len(self._traces),
            "stuck_count": self._stuck_counter,
            "strategy_perf": {
                s.value: p.to_dict() for s, p in self._strategy_perf.items()
            },
        }

    def build_meta_reasoning_prompt(self) -> str:
        """Build LLM prompt with meta-reasoning context.

        This is injected into the agent's system prompt so the LLM
        knows about its own reasoning state and can self-correct.
        """
        lines = ["## Meta-Reasoning State"]
        lines.append(f"Cognitive state: {self._cognitive_state.value}")
        lines.append(f"Current strategy: {self._current_strategy.value}")
        lines.append(f"Stuck counter: {self._stuck_counter}")

        # High confidence beliefs
        certain = self.get_high_confidence_beliefs(0.7)
        if certain:
            lines.append("\nKnown facts (high confidence):")
            for belief in certain[:5]:
                lines.append(f"  - {belief.subject}: {belief.proposition} ({belief.confidence:.0%})")

        # Uncertain beliefs that need investigation
        uncertain = self.get_uncertain_beliefs(0.4)
        if uncertain:
            lines.append("\nUncertain (needs investigation):")
            for belief in uncertain[:5]:
                lines.append(f"  - {belief.subject}: {belief.proposition} ({belief.confidence:.0%})")

        # Contradicted beliefs
        contradicted = [b for b in self._beliefs.values() if b.contradictions]
        if contradicted:
            lines.append("\nContradicted beliefs:")
            for belief in contradicted[:3]:
                lines.append(f"  - {belief.subject}: {belief.proposition} ← {belief.contradictions[-1]}")

        # Strategy guidance
        if self._cognitive_state == CognitiveState.STUCK:
            lines.append("\n⚠ STUCK: Switch approach. Try a completely different angle.")
            lines.append(f"Switched to: {self._current_strategy.value}")
        elif self._cognitive_state == CognitiveState.CONVERGING:
            lines.append("\nConverging: findings are consistent. Continue current approach.")
        elif self._cognitive_state == CognitiveState.DIVERGING:
            lines.append("\nDiverging: exploring new direction. Cast a wide net.")

        return "\n".join(lines)
