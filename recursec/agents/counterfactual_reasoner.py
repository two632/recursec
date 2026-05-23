"""Counterfactual reasoner — reasons about what WOULD happen under different conditions.

Implements:
1. Counterfactual scenario generation
2. What-if analysis for attack paths
3. Impact estimation under different conditions
4. Defense effectiveness modeling
5. Alternative attack path exploration
6. Root cause verification via counterfactuals
7. Mitigation effectiveness simulation
8. Decision support through scenario comparison
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ScenarioType(str, Enum):
    ATTACK_PATH = "attack_path"
    DEFENSE_CHANGE = "defense_change"
    CONFIG_CHANGE = "config_change"
    MITIGATION = "mitigation"
    ESCALATION = "escalation"
    ALTERNATIVE_APPROACH = "alternative_approach"


class OutcomeType(str, Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    BLOCKED = "blocked"
    DETECTED = "detected"
    UNKNOWN = "unknown"


@dataclass
class Condition:
    """A condition in the scenario."""
    condition_id: str = ""
    name: str = ""
    original_value: Any = None
    counterfactual_value: Any = None
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.condition_id,
            "name": self.name[:25],
            "original": str(self.original_value)[:15],
            "counterfactual": str(self.counterfactual_value)[:15],
        }


@dataclass
class Outcome:
    """An outcome under a scenario."""
    outcome_id: str = ""
    outcome_type: OutcomeType = OutcomeType.UNKNOWN
    description: str = ""
    impact_score: float = 0.0      # 0-10
    probability: float = 0.5       # 0-1
    affected_assets: list[str] = field(default_factory=list)

    @property
    def expected_impact(self) -> float:
        return self.impact_score * self.probability

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.outcome_id,
            "type": self.outcome_type.value,
            "impact": round(self.impact_score, 1),
            "prob": round(self.probability, 2),
            "expected": round(self.expected_impact, 2),
        }


@dataclass
class CounterfactualScenario:
    """A complete counterfactual scenario."""
    scenario_id: str = ""
    name: str = ""
    scenario_type: ScenarioType = ScenarioType.ATTACK_PATH
    base_conditions: list[Condition] = field(default_factory=list)
    changed_conditions: list[Condition] = field(default_factory=list)
    original_outcome: Outcome | None = None
    counterfactual_outcome: Outcome | None = None
    analysis: str = ""
    model_used: str = ""
    created_at: float = field(default_factory=time.time)

    @property
    def impact_delta(self) -> float:
        orig = self.original_outcome.expected_impact if self.original_outcome else 0
        cf = self.counterfactual_outcome.expected_impact if self.counterfactual_outcome else 0
        return cf - orig

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.scenario_id,
            "name": self.name[:30],
            "type": self.scenario_type.value,
            "conditions_changed": len(self.changed_conditions),
            "impact_delta": round(self.impact_delta, 2),
        }


@dataclass
class MitigationAnalysis:
    """Analysis of mitigation effectiveness via counterfactuals."""
    mitigation_id: str = ""
    mitigation_name: str = ""
    scenario_without: str = ""
    scenario_with: str = ""
    risk_reduction: float = 0.0    # 0-1
    cost_estimate: str = ""
    implementation_difficulty: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.mitigation_id,
            "name": self.mitigation_name[:25],
            "risk_reduction": round(self.risk_reduction, 2),
            "difficulty": self.implementation_difficulty[:10],
        }


class CounterfactualReasoner:
    """Reasons about what would happen under different conditions.

    Creates and evaluates counterfactual scenarios to understand
    attack impact, defense effectiveness, and mitigation value.
    """

    def __init__(self) -> None:
        self._scenarios: dict[str, CounterfactualScenario] = {}
        self._mitigations: dict[str, MitigationAnalysis] = {}
        self._scenario_counter = 0
        self._condition_counter = 0
        self._outcome_counter = 0
        self._mitigation_counter = 0
        self._log = logger.bind(component="counterfactual_reasoner")

    def create_scenario(
        self,
        name: str,
        scenario_type: ScenarioType,
    ) -> CounterfactualScenario:
        """Create a new counterfactual scenario."""
        self._scenario_counter += 1
        scenario = CounterfactualScenario(
            scenario_id=f"cf-{self._scenario_counter}",
            name=name,
            scenario_type=scenario_type,
        )
        self._scenarios[scenario.scenario_id] = scenario
        return scenario

    def add_condition(
        self,
        scenario_id: str,
        name: str,
        original_value: Any,
        counterfactual_value: Any,
        description: str = "",
    ) -> Condition | None:
        """Add a condition to a scenario."""
        scenario = self._scenarios.get(scenario_id)
        if not scenario:
            return None

        self._condition_counter += 1
        condition = Condition(
            condition_id=f"cond-{self._condition_counter}",
            name=name,
            original_value=original_value,
            counterfactual_value=counterfactual_value,
            description=description,
        )
        scenario.changed_conditions.append(condition)
        return condition

    def set_original_outcome(
        self,
        scenario_id: str,
        outcome_type: OutcomeType,
        description: str = "",
        impact_score: float = 5.0,
        probability: float = 0.5,
        affected_assets: list[str] | None = None,
    ) -> Outcome | None:
        """Set the original outcome for a scenario."""
        scenario = self._scenarios.get(scenario_id)
        if not scenario:
            return None

        self._outcome_counter += 1
        outcome = Outcome(
            outcome_id=f"out-{self._outcome_counter}",
            outcome_type=outcome_type,
            description=description,
            impact_score=impact_score,
            probability=probability,
            affected_assets=affected_assets or [],
        )
        scenario.original_outcome = outcome
        return outcome

    def set_counterfactual_outcome(
        self,
        scenario_id: str,
        outcome_type: OutcomeType,
        description: str = "",
        impact_score: float = 5.0,
        probability: float = 0.5,
        affected_assets: list[str] | None = None,
    ) -> Outcome | None:
        """Set the counterfactual outcome for a scenario."""
        scenario = self._scenarios.get(scenario_id)
        if not scenario:
            return None

        self._outcome_counter += 1
        outcome = Outcome(
            outcome_id=f"out-{self._outcome_counter}",
            outcome_type=outcome_type,
            description=description,
            impact_score=impact_score,
            probability=probability,
            affected_assets=affected_assets or [],
        )
        scenario.counterfactual_outcome = outcome
        return outcome

    def analyze_mitigation(
        self,
        mitigation_name: str,
        scenario_without_id: str,
        scenario_with_id: str,
        cost_estimate: str = "",
        difficulty: str = "medium",
    ) -> MitigationAnalysis | None:
        """Analyze mitigation effectiveness by comparing scenarios."""
        scenario_without = self._scenarios.get(scenario_without_id)
        scenario_with = self._scenarios.get(scenario_with_id)
        if not scenario_without or not scenario_with:
            return None

        # Calculate risk reduction
        risk_without = 0.0
        if scenario_without.original_outcome:
            risk_without = scenario_without.original_outcome.expected_impact

        risk_with = 0.0
        if scenario_with.counterfactual_outcome:
            risk_with = scenario_with.counterfactual_outcome.expected_impact

        risk_reduction = (risk_without - risk_with) / max(0.001, risk_without)
        risk_reduction = max(0.0, min(1.0, risk_reduction))

        self._mitigation_counter += 1
        analysis = MitigationAnalysis(
            mitigation_id=f"mit-{self._mitigation_counter}",
            mitigation_name=mitigation_name,
            scenario_without=scenario_without_id,
            scenario_with=scenario_with_id,
            risk_reduction=risk_reduction,
            cost_estimate=cost_estimate,
            implementation_difficulty=difficulty,
        )
        self._mitigations[analysis.mitigation_id] = analysis
        return analysis

    def what_if_attack_path(
        self,
        current_access: str,
        additional_vuln: str,
        target_asset: str,
    ) -> CounterfactualScenario:
        """Create a what-if scenario for an attack path."""
        scenario = self.create_scenario(
            name=f"What if: {additional_vuln} exploited from {current_access}",
            scenario_type=ScenarioType.ATTACK_PATH,
        )

        self.add_condition(
            scenario.scenario_id,
            name="additional_vulnerability",
            original_value="not_exploited",
            counterfactual_value="exploited",
            description=f"What if {additional_vuln} is exploited",
        )

        self.set_original_outcome(
            scenario.scenario_id,
            outcome_type=OutcomeType.PARTIAL,
            description=f"Current access: {current_access}",
            impact_score=3.0,
            probability=1.0,
        )

        self.set_counterfactual_outcome(
            scenario.scenario_id,
            outcome_type=OutcomeType.SUCCESS,
            description=f"Reach {target_asset} via {additional_vuln}",
            impact_score=8.0,
            probability=0.6,
            affected_assets=[target_asset],
        )

        return scenario

    def what_if_defense_added(
        self,
        attack_name: str,
        defense_name: str,
    ) -> CounterfactualScenario:
        """Create a what-if scenario for adding a defense."""
        scenario = self.create_scenario(
            name=f"What if: {defense_name} deployed against {attack_name}",
            scenario_type=ScenarioType.DEFENSE_CHANGE,
        )

        self.add_condition(
            scenario.scenario_id,
            name="defense_deployed",
            original_value=False,
            counterfactual_value=True,
            description=f"Deploy {defense_name}",
        )

        self.set_original_outcome(
            scenario.scenario_id,
            outcome_type=OutcomeType.SUCCESS,
            description=f"Attack {attack_name} succeeds without defense",
            impact_score=7.0,
            probability=0.7,
        )

        self.set_counterfactual_outcome(
            scenario.scenario_id,
            outcome_type=OutcomeType.BLOCKED,
            description=f"Attack {attack_name} blocked by {defense_name}",
            impact_score=1.0,
            probability=0.8,
        )

        return scenario

    def compare_scenarios(
        self,
        scenario_ids: list[str],
    ) -> list[dict[str, Any]]:
        """Compare multiple scenarios side by side."""
        comparisons = []
        for sid in scenario_ids:
            scenario = self._scenarios.get(sid)
            if not scenario:
                continue

            comparisons.append({
                "scenario": scenario.name[:30],
                "type": scenario.scenario_type.value,
                "original_impact": (
                    scenario.original_outcome.expected_impact
                    if scenario.original_outcome else 0
                ),
                "counterfactual_impact": (
                    scenario.counterfactual_outcome.expected_impact
                    if scenario.counterfactual_outcome else 0
                ),
                "delta": round(scenario.impact_delta, 2),
                "conditions_changed": len(scenario.changed_conditions),
            })

        comparisons.sort(key=lambda x: abs(x["delta"]), reverse=True)
        return comparisons

    def generate_reasoning_prompt(
        self,
        scenario_id: str,
    ) -> str:
        """Generate a prompt for LLM-based counterfactual reasoning."""
        scenario = self._scenarios.get(scenario_id)
        if not scenario:
            return ""

        conditions_text = ""
        for cond in scenario.changed_conditions:
            conditions_text += (
                f"  - {cond.name}: {cond.original_value} → {cond.counterfactual_value}\n"
            )

        return (
            f"Counterfactual Analysis: {scenario.name}\n\n"
            f"Scenario type: {scenario.scenario_type.value}\n\n"
            f"Changed conditions:\n{conditions_text}\n"
            f"Question: Given these changes, what would the impact be?\n"
            f"Consider: probability of success, affected assets, blast radius, "
            f"detection likelihood, and remediation cost.\n\n"
            f"Provide your analysis with impact score (0-10) and probability (0-1)."
        )

    def get_stats(self) -> dict[str, Any]:
        type_counts: dict[str, int] = defaultdict(int)
        for scenario in self._scenarios.values():
            type_counts[scenario.scenario_type.value] += 1
        return {
            "scenarios": len(self._scenarios),
            "mitigations": len(self._mitigations),
            "by_type": dict(type_counts),
        }
