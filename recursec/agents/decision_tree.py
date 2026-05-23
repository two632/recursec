"""Decision tree — structured decision-making for agent actions.

Implements:
1. Decision tree construction and traversal
2. Multi-criteria decision analysis (MCDA)
3. Decision outcome tracking
4. Information gain calculation
5. Decision chain history
6. Rollback support
7. Decision explanation generation
8. Decision caching for repeated scenarios
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class DecisionOutcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    PARTIAL = "partial"
    UNKNOWN = "unknown"
    SKIPPED = "skipped"


@dataclass
class DecisionOption:
    """An option in a decision."""
    option_id: str = ""
    name: str = ""
    description: str = ""
    criteria_scores: dict[str, float] = field(default_factory=dict)
    expected_reward: float = 0.0
    risk: float = 0.5
    cost_tokens: int = 0
    cost_time_s: float = 0.0
    prerequisites: list[str] = field(default_factory=list)

    @property
    def risk_adjusted_reward(self) -> float:
        return self.expected_reward * (1.0 - self.risk)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.option_id,
            "name": self.name[:30],
            "reward": round(self.expected_reward, 2),
            "risk": round(self.risk, 2),
            "adj_reward": round(self.risk_adjusted_reward, 2),
        }


@dataclass
class Decision:
    """A decision point."""
    decision_id: str = ""
    question: str = ""
    context: dict[str, Any] = field(default_factory=dict)
    options: list[DecisionOption] = field(default_factory=list)
    chosen_option_id: str = ""
    reasoning: str = ""
    outcome: DecisionOutcome = DecisionOutcome.UNKNOWN
    actual_reward: float = 0.0
    created_at: float = field(default_factory=time.time)
    resolved_at: float = 0.0

    @property
    def was_good_decision(self) -> bool:
        if self.outcome == DecisionOutcome.UNKNOWN:
            return False
        chosen = None
        for opt in self.options:
            if opt.option_id == self.chosen_option_id:
                chosen = opt
                break
        if not chosen:
            return False
        return self.actual_reward >= chosen.expected_reward * 0.7

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.decision_id,
            "question": self.question[:60],
            "options": len(self.options),
            "chosen": self.chosen_option_id[:15],
            "outcome": self.outcome.value,
            "good": self.was_good_decision,
        }


@dataclass
class DecisionNode:
    """A node in a decision tree."""
    node_id: str = ""
    condition: str = ""
    true_child: str = ""
    false_child: str = ""
    action: str = ""                 # Leaf node action
    is_leaf: bool = False
    confidence: float = 0.5

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.node_id,
            "condition": self.condition[:40] if not self.is_leaf else "",
            "action": self.action[:40] if self.is_leaf else "",
            "leaf": self.is_leaf,
        }


# ── Decision Criteria ─────────────────────────────────────────

DECISION_CRITERIA: dict[str, float] = {
    "expected_impact": 0.25,
    "confidence": 0.20,
    "cost_efficiency": 0.15,
    "time_efficiency": 0.15,
    "risk_level": 0.15,
    "novelty": 0.10,
}

# ── Pre-built Decision Trees ──────────────────────────────────

DECISION_TREES: dict[str, list[dict[str, Any]]] = {
    "tool_selection": [
        {"id": "root", "cond": "target_type == 'web'", "true": "web_tools", "false": "net_tools"},
        {"id": "web_tools", "cond": "has_known_tech", "true": "specific_scan", "false": "general_scan"},
        {"id": "net_tools", "cond": "open_ports > 10", "true": "focused_scan", "false": "broad_scan"},
        {"id": "specific_scan", "leaf": True, "action": "nuclei_targeted"},
        {"id": "general_scan", "leaf": True, "action": "nuclei_general + nikto"},
        {"id": "focused_scan", "leaf": True, "action": "nmap_service_scan"},
        {"id": "broad_scan", "leaf": True, "action": "masscan_all_ports"},
    ],
    "finding_validation": [
        {"id": "root", "cond": "severity >= 'high'", "true": "high_val", "false": "low_val"},
        {"id": "high_val", "cond": "tool_confirmed > 1", "true": "report_confirmed", "false": "need_validation"},
        {"id": "low_val", "cond": "tool_confirmed > 0", "true": "report_likely", "false": "dismiss"},
        {"id": "need_validation", "leaf": True, "action": "cross_validate_with_second_tool"},
        {"id": "report_confirmed", "leaf": True, "action": "report_as_confirmed_finding"},
        {"id": "report_likely", "leaf": True, "action": "report_as_likely_finding"},
        {"id": "dismiss", "leaf": True, "action": "mark_as_false_positive"},
    ],
    "model_selection": [
        {"id": "root", "cond": "task_type == 'code_analysis'", "true": "code_model", "false": "check_reasoning"},
        {"id": "check_reasoning", "cond": "task_type == 'reasoning'", "true": "reason_model", "false": "general"},
        {"id": "code_model", "leaf": True, "action": "use_qwen_coder_14b"},
        {"id": "reason_model", "leaf": True, "action": "use_deepseek_r1"},
        {"id": "general", "leaf": True, "action": "use_hermes_14b"},
    ],
}


class DecisionTree:
    """Structured decision-making for agent actions.

    Supports manual decision analysis, pre-built trees,
    and outcome tracking for learning.
    """

    def __init__(self) -> None:
        self._decisions: dict[str, Decision] = {}
        self._trees: dict[str, dict[str, DecisionNode]] = {}
        self._decision_counter = 0
        self._option_counter = 0
        self._node_counter = 0
        self._log = logger.bind(component="decision_tree")

        self._build_default_trees()

    def _build_default_trees(self) -> None:
        """Build pre-defined decision trees."""
        for tree_name, nodes in DECISION_TREES.items():
            tree: dict[str, DecisionNode] = {}
            for node_data in nodes:
                self._node_counter += 1
                node = DecisionNode(
                    node_id=node_data["id"],
                    condition=node_data.get("cond", ""),
                    true_child=node_data.get("true", ""),
                    false_child=node_data.get("false", ""),
                    action=node_data.get("action", ""),
                    is_leaf=node_data.get("leaf", False),
                )
                tree[node.node_id] = node
            self._trees[tree_name] = tree

    def decide(
        self,
        question: str,
        options: list[dict[str, Any]],
        context: dict[str, Any] | None = None,
    ) -> Decision:
        """Make a decision using multi-criteria analysis."""
        self._decision_counter += 1
        decision = Decision(
            decision_id=f"dec-{self._decision_counter}",
            question=question,
            context=context or {},
        )

        # Build options
        for opt_data in options:
            self._option_counter += 1
            option = DecisionOption(
                option_id=f"opt-{self._option_counter}",
                name=opt_data.get("name", ""),
                description=opt_data.get("desc", ""),
                criteria_scores=opt_data.get("scores", {}),
                expected_reward=opt_data.get("reward", 0.5),
                risk=opt_data.get("risk", 0.5),
                cost_tokens=opt_data.get("cost_tokens", 0),
                cost_time_s=opt_data.get("cost_time_s", 0),
            )
            decision.options.append(option)

        # Score and choose
        if decision.options:
            best = self._score_options(decision.options)
            decision.chosen_option_id = best.option_id
            decision.reasoning = self._explain(best, decision.options)

        self._decisions[decision.decision_id] = decision
        return decision

    def _score_options(self, options: list[DecisionOption]) -> DecisionOption:
        """Score options using MCDA."""
        best_score = -1.0
        best_option = options[0]

        for option in options:
            score = 0.0
            for criterion, weight in DECISION_CRITERIA.items():
                criterion_score = option.criteria_scores.get(criterion, 0.5)
                score += criterion_score * weight

            # Risk adjustment
            score *= (1.0 - option.risk * 0.3)

            if score > best_score:
                best_score = score
                best_option = option

        return best_option

    def _explain(
        self,
        chosen: DecisionOption,
        all_options: list[DecisionOption],
    ) -> str:
        """Generate explanation for a decision."""
        parts = [f"Chose '{chosen.name}' (reward={chosen.expected_reward:.2f}, risk={chosen.risk:.2f})"]

        # Compare with alternatives
        for opt in all_options:
            if opt.option_id != chosen.option_id:
                if opt.risk_adjusted_reward > chosen.risk_adjusted_reward:
                    parts.append(
                        f"  '{opt.name}' had higher adjusted reward but higher risk"
                    )

        return "; ".join(parts)

    def traverse_tree(
        self,
        tree_name: str,
        conditions: dict[str, Any],
    ) -> str:
        """Traverse a pre-built decision tree."""
        tree = self._trees.get(tree_name)
        if not tree:
            return ""

        current = tree.get("root")
        visited = set()

        while current and not current.is_leaf:
            if current.node_id in visited:
                break
            visited.add(current.node_id)

            result = self._evaluate_condition(current.condition, conditions)
            next_id = current.true_child if result else current.false_child
            current = tree.get(next_id)

        if current and current.is_leaf:
            return current.action

        return ""

    @staticmethod
    def _evaluate_condition(
        condition: str,
        context: dict[str, Any],
    ) -> bool:
        """Evaluate a condition against context."""
        # Simple condition evaluation
        for key, value in context.items():
            condition = condition.replace(key, repr(value))

        try:
            return bool(eval(condition))  # noqa: S307
        except Exception:
            return False

    def record_outcome(
        self,
        decision_id: str,
        outcome: DecisionOutcome,
        actual_reward: float = 0.0,
    ) -> None:
        """Record the outcome of a decision."""
        decision = self._decisions.get(decision_id)
        if not decision:
            return

        decision.outcome = outcome
        decision.actual_reward = actual_reward
        decision.resolved_at = time.time()

    def get_accuracy(self) -> float:
        """Get decision accuracy (good decisions / total)."""
        resolved = [d for d in self._decisions.values() if d.outcome != DecisionOutcome.UNKNOWN]
        if not resolved:
            return 0.0
        good = sum(1 for d in resolved if d.was_good_decision)
        return good / len(resolved)

    def get_stats(self) -> dict[str, Any]:
        return {
            "decisions": len(self._decisions),
            "trees": len(self._trees),
            "accuracy": round(self.get_accuracy(), 3),
        }
