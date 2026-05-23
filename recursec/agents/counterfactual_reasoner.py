"""Counterfactual reasoner — alternative path analysis.

Implements:
1. "What if" reasoning about alternative actions
2. Constraint propagation for attack chains
3. Causal inference for vulnerability impact
4. Decision tree analysis
5. Path cost estimation
6. Risk-adjusted decision making
7. Regret minimization
8. Opportunity cost analysis
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class DecisionType(str, Enum):
    STRATEGY_CHOICE = "strategy_choice"
    TOOL_CHOICE = "tool_choice"
    TARGET_PRIORITY = "target_priority"
    DEPTH_VS_BREADTH = "depth_vs_breadth"
    EXPLOIT_VS_MOVE_ON = "exploit_vs_move_on"
    MANUAL_VS_AUTO = "manual_vs_auto"


class RiskLevel(str, Enum):
    NEGLIGIBLE = "negligible"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Alternative:
    """An alternative action that could have been taken."""
    alt_id: str = ""
    description: str = ""
    expected_reward: float = 0.0
    expected_risk: RiskLevel = RiskLevel.LOW
    expected_time_s: float = 0.0
    confidence: float = 0.5
    prerequisites: list[str] = field(default_factory=list)
    constraints: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.alt_id[:10],
            "desc": self.description[:30],
            "reward": round(self.expected_reward, 2),
            "risk": self.expected_risk.value,
            "confidence": round(self.confidence, 2),
        }


@dataclass
class Decision:
    """A decision point with alternatives considered."""
    decision_id: str = ""
    decision_type: DecisionType = DecisionType.STRATEGY_CHOICE
    context: str = ""
    chosen_action: str = ""
    chosen_reward: float = 0.0
    alternatives: list[Alternative] = field(default_factory=list)
    regret: float = 0.0           # reward lost vs best alternative
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.decision_id[:10],
            "type": self.decision_type.value,
            "chosen": self.chosen_action[:20],
            "reward": round(self.chosen_reward, 2),
            "regret": round(self.regret, 2),
            "alternatives": len(self.alternatives),
        }


@dataclass
class CausalLink:
    """A causal relationship between findings/actions."""
    cause: str = ""
    effect: str = ""
    strength: float = 0.5         # 0-1 causal strength
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cause": self.cause[:20],
            "effect": self.effect[:20],
            "strength": round(self.strength, 2),
        }


@dataclass
class AttackPath:
    """A potential attack path through vulnerabilities."""
    path_id: str = ""
    steps: list[str] = field(default_factory=list)
    total_probability: float = 0.0
    total_impact: float = 0.0
    risk_score: float = 0.0
    constraints_satisfied: list[str] = field(default_factory=list)
    constraints_violated: list[str] = field(default_factory=list)

    @property
    def is_feasible(self) -> bool:
        return len(self.constraints_violated) == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.path_id[:10],
            "steps": len(self.steps),
            "probability": round(self.total_probability, 3),
            "impact": round(self.total_impact, 2),
            "risk": round(self.risk_score, 2),
            "feasible": self.is_feasible,
        }


class CounterfactualReasoner:
    """Reasons about alternative actions and their consequences.

    Helps the agent make better decisions by considering:
    - What would have happened if we took a different action?
    - What is the opportunity cost of the current approach?
    - What causal chains lead to vulnerabilities?
    - What are the feasible attack paths?
    """

    def __init__(self) -> None:
        self._decisions: list[Decision] = []
        self._decision_counter = 0
        self._causal_links: list[CausalLink] = []
        self._attack_paths: list[AttackPath] = []
        self._path_counter = 0
        self._total_regret = 0.0
        self._log = logger.bind(component="counterfactual_reasoner")

    def evaluate_decision(
        self,
        decision_type: DecisionType,
        context: str,
        chosen_action: str,
        chosen_expected_reward: float,
        alternatives: list[dict[str, Any]],
    ) -> Decision:
        """Evaluate a decision and compute regret."""
        self._decision_counter += 1

        alt_objects = []
        best_alt_reward = chosen_expected_reward
        for i, alt_data in enumerate(alternatives):
            alt = Alternative(
                alt_id=f"alt-{self._decision_counter}-{i}",
                description=alt_data.get("description", ""),
                expected_reward=alt_data.get("reward", 0.0),
                expected_risk=RiskLevel(alt_data.get("risk", "low")),
                expected_time_s=alt_data.get("time_s", 0.0),
                confidence=alt_data.get("confidence", 0.5),
                prerequisites=alt_data.get("prerequisites", []),
                constraints=alt_data.get("constraints", []),
            )
            alt_objects.append(alt)
            if alt.expected_reward > best_alt_reward:
                best_alt_reward = alt.expected_reward

        regret = max(0, best_alt_reward - chosen_expected_reward)
        self._total_regret += regret

        decision = Decision(
            decision_id=f"dec-{self._decision_counter}",
            decision_type=decision_type,
            context=context,
            chosen_action=chosen_action,
            chosen_reward=chosen_expected_reward,
            alternatives=alt_objects,
            regret=regret,
        )

        self._decisions.append(decision)
        return decision

    def add_causal_link(
        self,
        cause: str,
        effect: str,
        strength: float = 0.5,
        evidence: list[str] | None = None,
    ) -> CausalLink:
        """Add a causal relationship."""
        link = CausalLink(
            cause=cause,
            effect=effect,
            strength=min(1.0, max(0.0, strength)),
            evidence=evidence or [],
        )
        self._causal_links.append(link)
        return link

    def build_attack_path(
        self,
        steps: list[str],
        step_probabilities: list[float],
        step_impacts: list[float],
        constraints: list[dict[str, Any]] | None = None,
    ) -> AttackPath:
        """Build and evaluate an attack path."""
        self._path_counter += 1

        # Joint probability
        total_prob = 1.0
        for p in step_probabilities:
            total_prob *= p

        # Maximum impact (usually the final step)
        total_impact = max(step_impacts) if step_impacts else 0.0

        # Risk = probability × impact
        risk_score = total_prob * total_impact

        # Evaluate constraints
        satisfied = []
        violated = []
        if constraints:
            for c in constraints:
                if c.get("met", False):
                    satisfied.append(c.get("name", ""))
                else:
                    violated.append(c.get("name", ""))

        path = AttackPath(
            path_id=f"path-{self._path_counter}",
            steps=steps,
            total_probability=total_prob,
            total_impact=total_impact,
            risk_score=risk_score,
            constraints_satisfied=satisfied,
            constraints_violated=violated,
        )

        self._attack_paths.append(path)
        return path

    def get_causal_chain(self, root_cause: str) -> list[CausalLink]:
        """Get all effects downstream from a root cause."""
        chain = []
        visited = set()

        def _traverse(cause: str) -> None:
            if cause in visited:
                return
            visited.add(cause)
            for link in self._causal_links:
                if link.cause == cause:
                    chain.append(link)
                    _traverse(link.effect)

        _traverse(root_cause)
        return chain

    def get_feasible_paths(self) -> list[AttackPath]:
        """Get all feasible attack paths, sorted by risk."""
        feasible = [p for p in self._attack_paths if p.is_feasible]
        feasible.sort(key=lambda p: p.risk_score, reverse=True)
        return feasible

    def compute_opportunity_cost(
        self,
        current_action: str,
        current_reward: float,
    ) -> float:
        """Compute opportunity cost of current action vs best known alternative."""
        # Find similar past decisions
        relevant = [
            d for d in self._decisions
            if d.chosen_action == current_action
        ]

        if not relevant:
            return 0.0

        # Average best alternative reward for similar decisions
        best_alt_rewards = []
        for d in relevant:
            if d.alternatives:
                best_alt = max(d.alternatives, key=lambda a: a.expected_reward)
                best_alt_rewards.append(best_alt.expected_reward)

        if not best_alt_rewards:
            return 0.0

        avg_best = sum(best_alt_rewards) / len(best_alt_rewards)
        return max(0, avg_best - current_reward)

    def get_high_regret_decisions(
        self,
        threshold: float = 1.0,
    ) -> list[Decision]:
        """Get decisions where regret exceeded threshold."""
        return [
            d for d in self._decisions
            if d.regret > threshold
        ]

    def get_stats(self) -> dict[str, Any]:
        type_counts: dict[str, int] = defaultdict(int)
        for d in self._decisions:
            type_counts[d.decision_type.value] += 1

        return {
            "decisions": len(self._decisions),
            "total_regret": round(self._total_regret, 2),
            "avg_regret": round(self._total_regret / max(1, len(self._decisions)), 3),
            "causal_links": len(self._causal_links),
            "attack_paths": len(self._attack_paths),
            "feasible_paths": len(self.get_feasible_paths()),
            "by_type": dict(type_counts),
        }
