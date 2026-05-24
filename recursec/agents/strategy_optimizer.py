"""Strategy optimizer — adaptive strategy selection and tuning.

Optimizes agent behavior based on results:
1. Multi-armed bandit for strategy selection
2. Bayesian optimization for parameter tuning
3. Contextual bandits for target-aware selection
4. Exploration vs exploitation balancing
5. Strategy composition and chaining
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class AssessmentStrategy(str, Enum):
    ADAPTIVE = "adaptive"
    AGGRESSIVE = "aggressive"
    STEALTH = "stealth"
    QUICK = "quick"
    COMPREHENSIVE = "comprehensive"
    PASSIVE = "passive"


class StrategyDomain(str, Enum):
    SCANNING = "scanning"
    ENUMERATION = "enumeration"
    EXPLOITATION = "exploitation"
    EVASION = "evasion"
    ANALYSIS = "analysis"
    VALIDATION = "validation"
    REPORTING = "reporting"


class SelectionPolicy(str, Enum):
    UCB1 = "ucb1"
    EPSILON_GREEDY = "epsilon_greedy"
    THOMPSON_SAMPLING = "thompson_sampling"
    SOFTMAX = "softmax"
    CONTEXTUAL = "contextual"


@dataclass
class StrategyArm:
    """A strategy arm in the bandit model."""
    arm_id: str = ""
    strategy_name: str = ""
    domain: StrategyDomain = StrategyDomain.SCANNING
    pulls: int = 0
    total_reward: float = 0.0
    squared_reward: float = 0.0
    successes: int = 0
    failures: int = 0
    params: dict[str, Any] = field(default_factory=dict)

    @property
    def mean_reward(self) -> float:
        if self.pulls == 0:
            return 0.0
        return self.total_reward / self.pulls

    @property
    def variance(self) -> float:
        if self.pulls < 2:
            return 1.0
        mean = self.mean_reward
        return (self.squared_reward / self.pulls) - (mean * mean)

    @property
    def ucb1_score(self) -> float:
        if self.pulls == 0:
            return float("inf")
        return self.mean_reward + math.sqrt(
            2 * math.log(max(self.pulls + 1, 2)) / self.pulls
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.arm_id[:8],
            "name": self.strategy_name[:15],
            "pulls": self.pulls,
            "reward": f"{self.mean_reward:.3f}",
            "ucb1": f"{self.ucb1_score:.3f}",
        }


@dataclass
class StrategyChain:
    """A composition of strategies executed in sequence."""
    chain_id: str = ""
    name: str = ""
    steps: list[str] = field(default_factory=list)
    domain: StrategyDomain = StrategyDomain.SCANNING
    uses: int = 0
    avg_reward: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.chain_id[:8],
            "steps": len(self.steps),
            "reward": f"{self.avg_reward:.3f}",
        }


@dataclass
class OptimizationResult:
    """Result of strategy optimization."""
    selected_strategy: str = ""
    domain: StrategyDomain = StrategyDomain.SCANNING
    policy_used: SelectionPolicy = SelectionPolicy.UCB1
    expected_reward: float = 0.0
    exploration_factor: float = 0.0
    alternatives: list[tuple[str, float]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy": self.selected_strategy[:15],
            "policy": self.policy_used.value[:8],
            "expected": f"{self.expected_reward:.3f}",
            "explore": f"{self.exploration_factor:.2f}",
        }


# Pre-defined strategies per domain
DOMAIN_STRATEGIES: dict[StrategyDomain, list[dict[str, Any]]] = {
    StrategyDomain.SCANNING: [
        {"name": "broad_fast_scan", "desc": "Quick scan all ports, top 1000", "params": {"ports": "top1000", "timing": "T4"}},
        {"name": "deep_thorough_scan", "desc": "Full port range with version detection", "params": {"ports": "1-65535", "timing": "T3"}},
        {"name": "stealth_scan", "desc": "SYN scan with rate limiting", "params": {"ports": "top1000", "timing": "T2", "scan_type": "SYN"}},
        {"name": "udp_scan", "desc": "UDP service discovery", "params": {"ports": "top100", "protocol": "udp"}},
        {"name": "service_version_scan", "desc": "Focused version detection", "params": {"version_detect": True}},
    ],
    StrategyDomain.ENUMERATION: [
        {"name": "passive_enum", "desc": "OSINT-only enumeration", "params": {"passive": True}},
        {"name": "active_enum", "desc": "Active probing and brute force", "params": {"active": True}},
        {"name": "hybrid_enum", "desc": "Passive first, then targeted active", "params": {"hybrid": True}},
        {"name": "recursive_enum", "desc": "Recursive subdomain brute force", "params": {"recursive": True}},
        {"name": "wordlist_enum", "desc": "Custom wordlist-based enum", "params": {"wordlist": True}},
    ],
    StrategyDomain.EXPLOITATION: [
        {"name": "known_cve_exploit", "desc": "Match CVEs to known exploits", "params": {"cve_match": True}},
        {"name": "fuzzing_approach", "desc": "Fuzz parameters for crashes/errors", "params": {"fuzz": True}},
        {"name": "chain_exploit", "desc": "Chain low-sev vulns into high impact", "params": {"chain": True}},
        {"name": "credential_attack", "desc": "Credential stuffing/brute force", "params": {"creds": True}},
        {"name": "logic_exploit", "desc": "Business logic exploitation", "params": {"logic": True}},
    ],
    StrategyDomain.EVASION: [
        {"name": "encoding_evasion", "desc": "Payload encoding and obfuscation", "params": {"encode": True}},
        {"name": "timing_evasion", "desc": "Slow scan to avoid detection", "params": {"slow": True}},
        {"name": "fragmentation", "desc": "Packet fragmentation", "params": {"fragment": True}},
        {"name": "protocol_abuse", "desc": "Abuse allowed protocols (DNS, HTTP)", "params": {"protocol": True}},
        {"name": "proxy_chain", "desc": "Route through multiple proxies", "params": {"proxy": True}},
    ],
    StrategyDomain.ANALYSIS: [
        {"name": "single_model", "desc": "Use best model for analysis", "params": {"single": True}},
        {"name": "ensemble_analysis", "desc": "Multi-model consensus", "params": {"ensemble": True}},
        {"name": "chain_of_thought", "desc": "Deep reasoning chain", "params": {"cot": True}},
        {"name": "adversarial_review", "desc": "Model debates another model", "params": {"debate": True}},
        {"name": "hierarchical", "desc": "Fast triage then deep analysis", "params": {"hierarchical": True}},
    ],
    StrategyDomain.VALIDATION: [
        {"name": "cross_tool", "desc": "Validate with different tool", "params": {"cross_tool": True}},
        {"name": "cross_model", "desc": "Validate with different LLM", "params": {"cross_model": True}},
        {"name": "replay_validate", "desc": "Replay attack to confirm", "params": {"replay": True}},
        {"name": "manual_check", "desc": "Generate manual verification steps", "params": {"manual": True}},
        {"name": "evidence_chain", "desc": "Build evidence chain for finding", "params": {"evidence": True}},
    ],
    StrategyDomain.REPORTING: [
        {"name": "severity_first", "desc": "Report by severity descending", "params": {"by_severity": True}},
        {"name": "attack_chain", "desc": "Report as attack narratives", "params": {"narrative": True}},
        {"name": "compliance_map", "desc": "Map findings to compliance frameworks", "params": {"compliance": True}},
        {"name": "executive_summary", "desc": "High-level summary for leadership", "params": {"executive": True}},
        {"name": "technical_deep", "desc": "Detailed technical report", "params": {"technical": True}},
    ],
}


class StrategyOptimizer:
    """Adaptive strategy selection using bandit algorithms."""

    def __init__(
        self,
        policy: SelectionPolicy = SelectionPolicy.UCB1,
        epsilon: float = 0.1,
    ) -> None:
        self._policy = policy
        self._epsilon = epsilon
        self._arms: dict[str, StrategyArm] = {}
        self._chains: dict[str, StrategyChain] = {}
        self._total_pulls = 0
        self._arm_counter = 0
        self._chain_counter = 0
        self._log = logger.bind(component="strategy_optimizer")
        self._initialize_arms()

    def _initialize_arms(self) -> None:
        """Initialize strategy arms from domain definitions."""
        for domain, strategies in DOMAIN_STRATEGIES.items():
            for strat in strategies:
                self._arm_counter += 1
                arm_id = f"arm-{self._arm_counter}"
                self._arms[arm_id] = StrategyArm(
                    arm_id=arm_id,
                    strategy_name=strat["name"],
                    domain=domain,
                    params=strat.get("params", {}),
                )

    def select_strategy(
        self,
        domain: StrategyDomain,
        context: dict[str, Any] | None = None,
    ) -> OptimizationResult:
        """Select the best strategy for a domain."""
        domain_arms = [
            a for a in self._arms.values()
            if a.domain == domain
        ]
        if not domain_arms:
            return OptimizationResult(
                selected_strategy="default",
                domain=domain,
            )

        if self._policy == SelectionPolicy.UCB1:
            selected = self._ucb1_select(domain_arms)
        elif self._policy == SelectionPolicy.EPSILON_GREEDY:
            selected = self._epsilon_greedy_select(domain_arms)
        elif self._policy == SelectionPolicy.THOMPSON_SAMPLING:
            selected = self._thompson_select(domain_arms)
        elif self._policy == SelectionPolicy.SOFTMAX:
            selected = self._softmax_select(domain_arms)
        else:
            selected = self._ucb1_select(domain_arms)

        alternatives = [
            (a.strategy_name, a.mean_reward)
            for a in sorted(
                domain_arms,
                key=lambda a: a.mean_reward,
                reverse=True,
            )[:3]
            if a.arm_id != selected.arm_id
        ]

        return OptimizationResult(
            selected_strategy=selected.strategy_name,
            domain=domain,
            policy_used=self._policy,
            expected_reward=selected.mean_reward,
            exploration_factor=self._epsilon,
            alternatives=alternatives,
        )

    def _ucb1_select(
        self, arms: list[StrategyArm],
    ) -> StrategyArm:
        """UCB1 selection policy."""
        # Always try unpulled arms first
        unpulled = [a for a in arms if a.pulls == 0]
        if unpulled:
            return unpulled[0]

        total = sum(a.pulls for a in arms)
        best_arm = arms[0]
        best_score = -1.0

        for arm in arms:
            score = arm.mean_reward + math.sqrt(
                2 * math.log(total) / arm.pulls
            )
            if score > best_score:
                best_score = score
                best_arm = arm

        return best_arm

    def _epsilon_greedy_select(
        self, arms: list[StrategyArm],
    ) -> StrategyArm:
        """Epsilon-greedy selection."""
        if random.random() < self._epsilon:
            return random.choice(arms)
        return max(arms, key=lambda a: a.mean_reward)

    def _thompson_select(
        self, arms: list[StrategyArm],
    ) -> StrategyArm:
        """Thompson sampling using Beta distribution."""
        best_arm = arms[0]
        best_sample = -1.0

        for arm in arms:
            alpha = arm.successes + 1
            beta = arm.failures + 1
            sample = random.betavariate(alpha, beta)
            if sample > best_sample:
                best_sample = sample
                best_arm = arm

        return best_arm

    def _softmax_select(
        self, arms: list[StrategyArm],
    ) -> StrategyArm:
        """Softmax (Boltzmann) selection."""
        temperature = max(self._epsilon, 0.01)
        rewards = [a.mean_reward for a in arms]
        max_reward = max(rewards) if rewards else 0.0

        # Numerically stable softmax
        exp_rewards = [
            math.exp((r - max_reward) / temperature)
            for r in rewards
        ]
        total = sum(exp_rewards)
        probabilities = [e / total for e in exp_rewards]

        r = random.random()
        cumulative = 0.0
        for arm, prob in zip(arms, probabilities):
            cumulative += prob
            if r <= cumulative:
                return arm

        return arms[-1]

    def update_reward(
        self,
        strategy_name: str,
        domain: StrategyDomain,
        reward: float,
        success: bool = True,
    ) -> None:
        """Update an arm with observed reward."""
        for arm in self._arms.values():
            if arm.strategy_name == strategy_name and arm.domain == domain:
                arm.pulls += 1
                arm.total_reward += reward
                arm.squared_reward += reward * reward
                if success:
                    arm.successes += 1
                else:
                    arm.failures += 1
                self._total_pulls += 1
                return

    def create_chain(
        self,
        name: str,
        steps: list[str],
        domain: StrategyDomain,
    ) -> StrategyChain:
        """Create a strategy chain."""
        self._chain_counter += 1
        chain = StrategyChain(
            chain_id=f"chain-{self._chain_counter}",
            name=name,
            steps=steps,
            domain=domain,
        )
        self._chains[chain.chain_id] = chain
        return chain

    def get_domain_rankings(
        self, domain: StrategyDomain,
    ) -> list[StrategyArm]:
        """Get strategies ranked by reward for a domain."""
        domain_arms = [
            a for a in self._arms.values()
            if a.domain == domain and a.pulls > 0
        ]
        return sorted(
            domain_arms,
            key=lambda a: a.mean_reward,
            reverse=True,
        )

    def build_optimizer_prompt(
        self,
        domain: StrategyDomain | None = None,
    ) -> str:
        """Build LLM prompt with optimization context."""
        lines = ["## Strategy Optimization Context\n"]
        lines.append(f"Total strategy evaluations: {self._total_pulls}")
        lines.append(f"Selection policy: {self._policy.value}")
        lines.append(f"Exploration factor: {self._epsilon:.2f}\n")

        domains = [domain] if domain else list(StrategyDomain)
        for dom in domains:
            rankings = self.get_domain_rankings(dom)
            if rankings:
                lines.append(f"### {dom.value.title()} Strategies")
                for arm in rankings[:3]:
                    lines.append(
                        f"  {arm.strategy_name}: "
                        f"reward={arm.mean_reward:.3f}, "
                        f"pulls={arm.pulls}, "
                        f"success={arm.successes}/{arm.pulls}"
                    )
                lines.append("")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        """Get optimizer statistics."""
        domain_counts: dict[str, int] = {}
        for arm in self._arms.values():
            key = arm.domain.value
            domain_counts[key] = domain_counts.get(key, 0) + 1

        return {
            "total_arms": len(self._arms),
            "total_pulls": self._total_pulls,
            "total_chains": len(self._chains),
            "arms_per_domain": domain_counts,
            "policy": self._policy.value,
        }
