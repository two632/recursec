"""Experience replay — learns from past assessment experiences.

Implements:
1. Experience recording (what worked, what didn't)
2. Priority-based replay (focus on high-value experiences)
3. Experience similarity matching
4. Strategy effectiveness tracking
5. Target fingerprint → experience mapping
6. Few-shot example generation from past successes
7. Anti-pattern library (what to avoid)
8. Experience compression for long-term storage
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ExperienceOutcome(str, Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILURE = "failure"
    FALSE_POSITIVE = "false_positive"
    TIMEOUT = "timeout"


class ExperiencePhase(str, Enum):
    RECON = "recon"
    SCANNING = "scanning"
    ANALYSIS = "analysis"
    EXPLOITATION = "exploitation"
    VALIDATION = "validation"
    REPORTING = "reporting"


@dataclass
class Experience:
    """A recorded experience from a past assessment."""
    experience_id: str = ""
    phase: ExperiencePhase = ExperiencePhase.RECON
    target_fingerprint: str = ""   # Hash of target characteristics
    strategy_used: str = ""
    tool_used: str = ""
    model_used: str = ""
    action_taken: str = ""
    outcome: ExperienceOutcome = ExperienceOutcome.SUCCESS
    finding_type: str = ""
    finding_severity: str = ""
    tokens_spent: int = 0
    duration_s: float = 0.0
    context_summary: str = ""
    notes: str = ""
    timestamp: float = field(default_factory=time.time)
    priority: float = 0.5         # 0-1, for replay prioritization

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.experience_id,
            "phase": self.phase.value,
            "strategy": self.strategy_used[:20],
            "outcome": self.outcome.value,
            "priority": round(self.priority, 2),
            "finding": self.finding_type[:15],
        }


@dataclass
class TargetFingerprint:
    """Fingerprint of a target for experience matching."""
    fingerprint_id: str = ""
    target_type: str = ""          # web_app, api, cloud, etc.
    technologies: list[str] = field(default_factory=list)
    has_waf: bool = False
    has_cdn: bool = False
    auth_type: str = ""
    api_style: str = ""
    cloud_provider: str = ""
    tags: list[str] = field(default_factory=list)

    @property
    def hash(self) -> str:
        data = json.dumps({
            "type": self.target_type,
            "tech": sorted(self.technologies),
            "waf": self.has_waf,
            "auth": self.auth_type,
            "api": self.api_style,
            "cloud": self.cloud_provider,
        }, sort_keys=True)
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.fingerprint_id,
            "type": self.target_type[:15],
            "tech": self.technologies[:3],
            "waf": self.has_waf,
            "auth": self.auth_type[:10],
        }


@dataclass
class StrategyEffectiveness:
    """Tracked effectiveness of a strategy."""
    strategy_name: str = ""
    total_uses: int = 0
    successes: int = 0
    failures: int = 0
    avg_tokens: float = 0.0
    avg_duration_s: float = 0.0
    target_types: list[str] = field(default_factory=list)

    @property
    def success_rate(self) -> float:
        if self.total_uses == 0:
            return 0.0
        return self.successes / self.total_uses

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy": self.strategy_name[:25],
            "uses": self.total_uses,
            "success_rate": round(self.success_rate, 2),
            "avg_tokens": round(self.avg_tokens),
        }


@dataclass
class AntiPattern:
    """Something that doesn't work — avoid repeating."""
    pattern_id: str = ""
    description: str = ""
    context: str = ""
    why_it_fails: str = ""
    occurrences: int = 1
    alternative: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "desc": self.description[:30],
            "occurrences": self.occurrences,
            "alternative": self.alternative[:25],
        }


class ExperienceReplay:
    """Learns from past assessment experiences.

    Records what worked and what didn't, enabling the agent
    to improve over time by replaying successful strategies
    and avoiding known anti-patterns.
    """

    def __init__(self, max_experiences: int = 10000) -> None:
        self._experiences: list[Experience] = []
        self._max_experiences = max_experiences
        self._fingerprints: dict[str, TargetFingerprint] = {}
        self._strategy_stats: dict[str, StrategyEffectiveness] = {}
        self._anti_patterns: dict[str, AntiPattern] = {}
        self._exp_counter = 0
        self._fp_counter = 0
        self._ap_counter = 0
        self._log = logger.bind(component="experience_replay")

    def record(
        self,
        phase: ExperiencePhase,
        strategy_used: str,
        action_taken: str,
        outcome: ExperienceOutcome,
        target_fingerprint: str = "",
        tool_used: str = "",
        model_used: str = "",
        finding_type: str = "",
        finding_severity: str = "",
        tokens_spent: int = 0,
        duration_s: float = 0.0,
        context_summary: str = "",
        notes: str = "",
    ) -> Experience:
        """Record a new experience."""
        self._exp_counter += 1

        # Calculate priority based on outcome and finding
        priority = self._calculate_priority(outcome, finding_severity)

        experience = Experience(
            experience_id=f"exp-{self._exp_counter}",
            phase=phase,
            target_fingerprint=target_fingerprint,
            strategy_used=strategy_used,
            tool_used=tool_used,
            model_used=model_used,
            action_taken=action_taken,
            outcome=outcome,
            finding_type=finding_type,
            finding_severity=finding_severity,
            tokens_spent=tokens_spent,
            duration_s=duration_s,
            context_summary=context_summary,
            notes=notes,
            priority=priority,
        )

        self._experiences.append(experience)

        # Evict old low-priority experiences if over limit
        if len(self._experiences) > self._max_experiences:
            self._experiences.sort(key=lambda e: e.priority, reverse=True)
            self._experiences = self._experiences[:self._max_experiences]

        # Update strategy stats
        self._update_strategy_stats(experience)

        # Detect anti-patterns
        if outcome == ExperienceOutcome.FAILURE:
            self._check_anti_pattern(experience)

        return experience

    def register_fingerprint(
        self,
        target_type: str = "",
        technologies: list[str] | None = None,
        has_waf: bool = False,
        auth_type: str = "",
        api_style: str = "",
        cloud_provider: str = "",
    ) -> TargetFingerprint:
        """Register a target fingerprint."""
        self._fp_counter += 1
        fp = TargetFingerprint(
            fingerprint_id=f"fp-{self._fp_counter}",
            target_type=target_type,
            technologies=technologies or [],
            has_waf=has_waf,
            auth_type=auth_type,
            api_style=api_style,
            cloud_provider=cloud_provider,
        )
        self._fingerprints[fp.hash] = fp
        return fp

    def get_similar_experiences(
        self,
        target_fingerprint: str,
        phase: ExperiencePhase | None = None,
        top_k: int = 10,
    ) -> list[Experience]:
        """Get experiences from similar targets."""
        matches = []

        for exp in self._experiences:
            if exp.target_fingerprint == target_fingerprint:
                if phase is None or exp.phase == phase:
                    matches.append(exp)

        # Sort by priority (replay high-value experiences first)
        matches.sort(key=lambda e: e.priority, reverse=True)
        return matches[:top_k]

    def get_successful_strategies(
        self,
        target_fingerprint: str = "",
        phase: ExperiencePhase | None = None,
    ) -> list[str]:
        """Get strategies that worked for similar targets."""
        successful = set()

        for exp in self._experiences:
            if exp.outcome == ExperienceOutcome.SUCCESS:
                if target_fingerprint and exp.target_fingerprint != target_fingerprint:
                    continue
                if phase and exp.phase != phase:
                    continue
                successful.add(exp.strategy_used)

        return sorted(successful)

    def generate_few_shot_examples(
        self,
        phase: ExperiencePhase,
        target_fingerprint: str = "",
        max_examples: int = 3,
    ) -> list[dict[str, str]]:
        """Generate few-shot examples from successful experiences."""
        successes = [
            exp for exp in self._experiences
            if exp.outcome == ExperienceOutcome.SUCCESS
            and exp.phase == phase
            and (not target_fingerprint or exp.target_fingerprint == target_fingerprint)
        ]

        successes.sort(key=lambda e: e.priority, reverse=True)

        examples = []
        for exp in successes[:max_examples]:
            examples.append({
                "role": "user",
                "content": f"Strategy: {exp.strategy_used}\nContext: {exp.context_summary}",
            })
            examples.append({
                "role": "assistant",
                "content": (
                    f"Action: {exp.action_taken}\n"
                    f"Tool: {exp.tool_used}\n"
                    f"Result: {exp.finding_type} ({exp.finding_severity})\n"
                    f"Notes: {exp.notes}"
                ),
            })

        return examples

    def get_anti_patterns(self) -> list[AntiPattern]:
        """Get known anti-patterns to avoid."""
        return sorted(
            self._anti_patterns.values(),
            key=lambda ap: ap.occurrences,
            reverse=True,
        )

    def get_strategy_rankings(self) -> list[StrategyEffectiveness]:
        """Get strategies ranked by effectiveness."""
        stats = list(self._strategy_stats.values())
        stats.sort(key=lambda s: s.success_rate, reverse=True)
        return stats

    @staticmethod
    def _calculate_priority(
        outcome: ExperienceOutcome,
        finding_severity: str,
    ) -> float:
        """Calculate replay priority based on outcome and severity."""
        outcome_weights = {
            ExperienceOutcome.SUCCESS: 0.8,
            ExperienceOutcome.PARTIAL: 0.5,
            ExperienceOutcome.FAILURE: 0.3,
            ExperienceOutcome.FALSE_POSITIVE: 0.6,
            ExperienceOutcome.TIMEOUT: 0.2,
        }

        severity_bonus = {
            "critical": 0.2,
            "high": 0.15,
            "medium": 0.1,
            "low": 0.05,
        }

        base = outcome_weights.get(outcome, 0.3)
        bonus = severity_bonus.get(finding_severity.lower(), 0.0)

        return min(1.0, base + bonus)

    def _update_strategy_stats(self, experience: Experience) -> None:
        """Update strategy effectiveness statistics."""
        name = experience.strategy_used
        if not name:
            return

        if name not in self._strategy_stats:
            self._strategy_stats[name] = StrategyEffectiveness(strategy_name=name)

        stats = self._strategy_stats[name]
        stats.total_uses += 1

        if experience.outcome == ExperienceOutcome.SUCCESS:
            stats.successes += 1
        elif experience.outcome == ExperienceOutcome.FAILURE:
            stats.failures += 1

        # Running average for tokens and duration
        old_total = stats.total_uses - 1
        stats.avg_tokens = (
            (stats.avg_tokens * old_total + experience.tokens_spent) / stats.total_uses
        )
        stats.avg_duration_s = (
            (stats.avg_duration_s * old_total + experience.duration_s) / stats.total_uses
        )

    def _check_anti_pattern(self, experience: Experience) -> None:
        """Check if a failure matches an anti-pattern."""
        key = f"{experience.strategy_used}:{experience.target_fingerprint}"

        if key in self._anti_patterns:
            self._anti_patterns[key].occurrences += 1
        else:
            # Check if this strategy has failed multiple times
            failures = sum(
                1 for e in self._experiences
                if e.strategy_used == experience.strategy_used
                and e.outcome == ExperienceOutcome.FAILURE
            )

            if failures >= 3:
                self._ap_counter += 1
                self._anti_patterns[key] = AntiPattern(
                    pattern_id=f"ap-{self._ap_counter}",
                    description=f"Strategy '{experience.strategy_used}' fails repeatedly",
                    context=experience.context_summary[:100],
                    why_it_fails=experience.notes[:100],
                    occurrences=failures,
                    alternative="Try different strategy or model",
                )

    def get_stats(self) -> dict[str, Any]:
        outcome_counts: dict[str, int] = defaultdict(int)
        for exp in self._experiences:
            outcome_counts[exp.outcome.value] += 1
        return {
            "total_experiences": len(self._experiences),
            "fingerprints": len(self._fingerprints),
            "strategies_tracked": len(self._strategy_stats),
            "anti_patterns": len(self._anti_patterns),
            "by_outcome": dict(outcome_counts),
        }
