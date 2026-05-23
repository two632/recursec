"""Strategy selector — meta-reasoning for dynamic strategy selection.

Selects the optimal reasoning strategy, model, and approach for each
task based on:
- Task complexity analysis
- Target characteristics
- Historical performance data
- Resource availability
- Current assessment phase
- Confidence requirements

Implements a multi-armed bandit approach with Thompson sampling
for exploration/exploitation balance in strategy selection.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from recursec.agents.learning import LearningEngine

logger = structlog.get_logger()


class TaskComplexity(str, Enum):
    TRIVIAL = "trivial"      # Simple lookup, basic scan
    SIMPLE = "simple"        # Single tool, straightforward analysis
    MODERATE = "moderate"    # Multiple tools, some reasoning
    COMPLEX = "complex"      # Multi-step reasoning, chain analysis
    EXPERT = "expert"        # Novel attacks, zero-day analysis, deep reasoning


class TargetProfile(str, Enum):
    WEB_APP = "web_app"
    API = "api"
    NETWORK = "network"
    CLOUD = "cloud"
    MOBILE = "mobile"
    IOT = "iot"
    CODE = "code"
    INFRASTRUCTURE = "infrastructure"
    UNKNOWN = "unknown"


@dataclass
class TaskCharacteristics:
    """Analyzed characteristics of a task."""
    complexity: TaskComplexity = TaskComplexity.MODERATE
    target_profile: TargetProfile = TargetProfile.UNKNOWN
    requires_reasoning: bool = True
    requires_multi_model: bool = False
    requires_validation: bool = True
    estimated_steps: int = 5
    estimated_tokens: int = 5000
    risk_level: str = "medium"  # How risky is the operation
    novelty: float = 0.5  # How novel/unusual is this task (0=routine, 1=never seen)
    confidence_required: float = 0.7  # Minimum confidence needed


@dataclass
class StrategyRecommendation:
    """A recommended strategy with reasoning."""
    reasoning_strategy: str  # ReasoningStrategy value
    model_preference: str  # Preferred model type
    fallback_model: str = ""
    tool_sequence: list[str] = field(default_factory=list)
    max_steps: int = 10
    temperature: float = 0.3
    should_validate: bool = True
    should_debate: bool = False
    parallel_execution: bool = False
    confidence: float = 0.5
    reasoning: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy": self.reasoning_strategy,
            "model": self.model_preference,
            "fallback": self.fallback_model,
            "tools": self.tool_sequence[:5],
            "max_steps": self.max_steps,
            "temperature": self.temperature,
            "validate": self.should_validate,
            "debate": self.should_debate,
            "parallel": self.parallel_execution,
            "confidence": round(self.confidence, 2),
        }


@dataclass
class BanditArm:
    """A multi-armed bandit arm for strategy selection."""
    strategy: str
    alpha: float = 1.0  # Successes + 1
    beta: float = 1.0   # Failures + 1
    total_reward: float = 0.0
    pulls: int = 0

    @property
    def mean_reward(self) -> float:
        return self.total_reward / self.pulls if self.pulls > 0 else 0.0

    def sample(self) -> float:
        """Thompson sampling: draw from Beta distribution."""
        return random.betavariate(self.alpha, self.beta)

    def update(self, reward: float) -> None:
        self.pulls += 1
        self.total_reward += reward
        if reward >= 0.5:
            self.alpha += reward
        else:
            self.beta += (1.0 - reward)


# ── Complexity Analysis Heuristics ──────────────────────────

COMPLEXITY_KEYWORDS = {
    TaskComplexity.TRIVIAL: [
        "ping", "dns lookup", "whois", "port check", "header check",
    ],
    TaskComplexity.SIMPLE: [
        "scan", "enumerate", "discover", "fingerprint", "banner grab",
    ],
    TaskComplexity.MODERATE: [
        "vulnerability scan", "web scan", "api test", "fuzz",
        "credential test", "brute force",
    ],
    TaskComplexity.COMPLEX: [
        "exploit", "chain", "privilege escalation", "lateral movement",
        "bypass", "evasion", "post-exploitation",
    ],
    TaskComplexity.EXPERT: [
        "zero day", "novel", "unknown vulnerability", "reverse engineer",
        "custom exploit", "advanced persistent", "supply chain",
    ],
}

TARGET_INDICATORS = {
    TargetProfile.WEB_APP: ["http", "https", "web", "html", "javascript", "php", "asp"],
    TargetProfile.API: ["api", "rest", "graphql", "grpc", "endpoint", "swagger", "openapi"],
    TargetProfile.NETWORK: ["ip", "subnet", "port", "tcp", "udp", "icmp", "router", "switch"],
    TargetProfile.CLOUD: ["aws", "azure", "gcp", "s3", "ec2", "lambda", "cloud", "kubernetes"],
    TargetProfile.CODE: ["source", "code", "repository", "git", "function", "class", "module"],
    TargetProfile.IOT: ["iot", "firmware", "embedded", "mqtt", "zigbee", "bluetooth"],
}

# Strategy recommendations by complexity
STRATEGY_MAP = {
    TaskComplexity.TRIVIAL: {
        "reasoning_strategy": "chain_of_thought",
        "max_steps": 3, "temperature": 0.1, "should_validate": False,
        "should_debate": False,
    },
    TaskComplexity.SIMPLE: {
        "reasoning_strategy": "chain_of_thought",
        "max_steps": 5, "temperature": 0.2, "should_validate": False,
        "should_debate": False,
    },
    TaskComplexity.MODERATE: {
        "reasoning_strategy": "plan_and_solve",
        "max_steps": 10, "temperature": 0.3, "should_validate": True,
        "should_debate": False,
    },
    TaskComplexity.COMPLEX: {
        "reasoning_strategy": "tree_of_thought",
        "max_steps": 15, "temperature": 0.4, "should_validate": True,
        "should_debate": True,
    },
    TaskComplexity.EXPERT: {
        "reasoning_strategy": "consensus",
        "max_steps": 20, "temperature": 0.5, "should_validate": True,
        "should_debate": True,
    },
}

# Model preferences by target profile and complexity
MODEL_PREFERENCES = {
    TargetProfile.WEB_APP: {
        "primary": "security",   # WhiteRabbitNeo
        "reasoning": "reasoning",  # DeepSeek-R1
        "code": "code",           # Qwen-Coder
    },
    TargetProfile.CODE: {
        "primary": "code",
        "reasoning": "reasoning",
        "code": "code",
    },
    TargetProfile.NETWORK: {
        "primary": "security",
        "reasoning": "general",
        "code": "code",
    },
    TargetProfile.CLOUD: {
        "primary": "general",
        "reasoning": "reasoning",
        "code": "code",
    },
    TargetProfile.API: {
        "primary": "code",
        "reasoning": "reasoning",
        "code": "code",
    },
}


class StrategySelector:
    """Meta-reasoning engine for selecting optimal strategies.

    Uses a combination of:
    1. Task complexity analysis
    2. Target profiling
    3. Historical performance (learning engine)
    4. Multi-armed bandit (Thompson sampling) for exploration
    """

    def __init__(
        self,
        learning_engine: LearningEngine | None = None,
        exploration_rate: float = 0.1,
    ) -> None:
        self._learning = learning_engine
        self._exploration_rate = exploration_rate
        self._bandits: dict[str, BanditArm] = {}
        self._selection_history: list[dict[str, Any]] = []

    def analyze_task(self, objective: str, target: str = "", context: dict[str, Any] | None = None) -> TaskCharacteristics:
        """Analyze task characteristics for strategy selection."""
        chars = TaskCharacteristics()
        text = f"{objective} {target}".lower()

        # Determine complexity
        chars.complexity = self._classify_complexity(text)

        # Determine target profile
        chars.target_profile = self._classify_target(text, target)

        # Estimate requirements
        if chars.complexity in (TaskComplexity.COMPLEX, TaskComplexity.EXPERT):
            chars.requires_multi_model = True
            chars.estimated_steps = 15
            chars.estimated_tokens = 20000
            chars.confidence_required = 0.8
        elif chars.complexity == TaskComplexity.MODERATE:
            chars.estimated_steps = 8
            chars.estimated_tokens = 10000
        else:
            chars.estimated_steps = 3
            chars.estimated_tokens = 3000
            chars.confidence_required = 0.5

        # Check novelty using learning engine
        if self._learning:
            similar = self._learning.recommend_strategy(chars.target_profile.value)
            chars.novelty = 0.8 if not similar else 0.3

        return chars

    def select_strategy(
        self,
        characteristics: TaskCharacteristics,
        available_models: list[str] | None = None,
    ) -> StrategyRecommendation:
        """Select the optimal strategy for a task."""
        # Get base strategy from complexity mapping
        base = STRATEGY_MAP.get(characteristics.complexity, STRATEGY_MAP[TaskComplexity.MODERATE])

        # Get model preferences
        model_prefs = MODEL_PREFERENCES.get(characteristics.target_profile, {})
        primary_model = model_prefs.get("primary", "general")
        fallback_model = model_prefs.get("reasoning", "general")

        # Check if learning engine recommends something different
        if self._learning:
            learned_strategy = self._learning.recommend_strategy(
                characteristics.target_profile.value,
            )
            if learned_strategy:
                # Use bandit to decide between base and learned strategy
                strategy_name = self._bandit_select(
                    base["reasoning_strategy"],
                    learned_strategy,
                )
            else:
                strategy_name = base["reasoning_strategy"]

            learned_model = self._learning.recommend_model(characteristics.target_profile.value)
            if learned_model:
                primary_model = learned_model
        else:
            strategy_name = base["reasoning_strategy"]

        # Exploration: occasionally try a different strategy
        if random.random() < self._exploration_rate:
            all_strategies = ["chain_of_thought", "tree_of_thought", "self_consistency", "plan_and_solve", "debate"]
            strategy_name = random.choice(all_strategies)

        rec = StrategyRecommendation(
            reasoning_strategy=strategy_name,
            model_preference=primary_model,
            fallback_model=fallback_model,
            max_steps=base["max_steps"],
            temperature=base["temperature"],
            should_validate=base["should_validate"],
            should_debate=base.get("should_debate", False),
            parallel_execution=characteristics.complexity >= TaskComplexity.MODERATE,
            confidence=0.7,
            reasoning=f"Complexity={characteristics.complexity.value}, Target={characteristics.target_profile.value}",
        )

        # Get recommended tools from learning engine
        if self._learning:
            tools = self._learning.recommend_tools(characteristics.target_profile.value)
            rec.tool_sequence = [t for t, _ in tools]

        self._selection_history.append({
            "task_complexity": characteristics.complexity.value,
            "target_profile": characteristics.target_profile.value,
            "strategy": strategy_name,
            "model": primary_model,
            "timestamp": time.time(),
        })

        return rec

    def update_bandit(self, strategy: str, reward: float) -> None:
        """Update bandit arm with observed reward."""
        if strategy not in self._bandits:
            self._bandits[strategy] = BanditArm(strategy=strategy)
        self._bandits[strategy].update(reward)

    def _bandit_select(self, strategy_a: str, strategy_b: str) -> str:
        """Select between two strategies using Thompson sampling."""
        if strategy_a not in self._bandits:
            self._bandits[strategy_a] = BanditArm(strategy=strategy_a)
        if strategy_b not in self._bandits:
            self._bandits[strategy_b] = BanditArm(strategy=strategy_b)

        sample_a = self._bandits[strategy_a].sample()
        sample_b = self._bandits[strategy_b].sample()

        return strategy_a if sample_a >= sample_b else strategy_b

    def _classify_complexity(self, text: str) -> TaskComplexity:
        """Classify task complexity from text."""
        best_match = TaskComplexity.MODERATE
        best_score = 0

        for complexity, keywords in COMPLEXITY_KEYWORDS.items():
            score = sum(1 for kw in keywords if kw in text)
            if score > best_score:
                best_score = score
                best_match = complexity

        return best_match

    def _classify_target(self, text: str, target: str) -> TargetProfile:
        """Classify target type."""
        combined = f"{text} {target}".lower()
        best_match = TargetProfile.UNKNOWN
        best_score = 0

        for profile, indicators in TARGET_INDICATORS.items():
            score = sum(1 for ind in indicators if ind in combined)
            if score > best_score:
                best_score = score
                best_match = profile

        return best_match

    def get_stats(self) -> dict[str, Any]:
        """Get strategy selection statistics."""
        return {
            "total_selections": len(self._selection_history),
            "bandit_arms": {
                name: {
                    "pulls": arm.pulls,
                    "mean_reward": round(arm.mean_reward, 3),
                    "alpha": round(arm.alpha, 1),
                    "beta": round(arm.beta, 1),
                }
                for name, arm in self._bandits.items()
            },
            "recent_selections": self._selection_history[-10:],
        }
