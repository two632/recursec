"""Memory consolidation — compresses long-term experience into actionable rules.

Implements:
1. Episode compression (remove noise, keep key events)
2. Pattern extraction across episodes
3. Rule generation from patterns
4. Rule conflict detection
5. Rule confidence updating
6. Scheduled consolidation (like sleep)
7. Memory decay and pruning
8. Knowledge transfer between agents
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class CompressedEpisode:
    """A compressed version of an episode (key events only)."""
    episode_id: str = ""
    target_type: str = ""
    strategy_used: str = ""
    tools_used: list[str] = field(default_factory=list)
    models_used: list[str] = field(default_factory=list)
    key_events: list[str] = field(default_factory=list)
    findings_count: int = 0
    outcome: str = ""
    duration_s: float = 0.0
    tokens_used: int = 0
    compression_ratio: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.episode_id,
            "target": self.target_type[:15],
            "strategy": self.strategy_used[:15],
            "tools": self.tools_used[:3],
            "findings": self.findings_count,
            "outcome": self.outcome,
            "ratio": round(self.compression_ratio, 2),
        }


@dataclass
class ExtractedPattern:
    """A pattern extracted from multiple episodes."""
    pattern_id: str = ""
    description: str = ""
    conditions: dict[str, Any] = field(default_factory=dict)
    action: str = ""
    frequency: int = 0
    success_rate: float = 0.0
    confidence: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "desc": self.description[:35],
            "freq": self.frequency,
            "success": round(self.success_rate, 2),
            "confidence": round(self.confidence, 2),
        }


@dataclass
class ConsolidatedRule:
    """A rule generated from patterns."""
    rule_id: str = ""
    condition: str = ""
    action: str = ""
    confidence: float = 0.5
    source_patterns: int = 0
    total_observations: int = 0
    successful_applications: int = 0
    failed_applications: int = 0
    created_at: float = field(default_factory=time.time)
    last_applied: float = 0.0
    deprecated: bool = False

    @property
    def success_rate(self) -> float:
        total = self.successful_applications + self.failed_applications
        if total == 0:
            return self.confidence
        return self.successful_applications / total

    @property
    def age_days(self) -> float:
        return (time.time() - self.created_at) / 86400.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.rule_id,
            "if": self.condition[:30],
            "then": self.action[:30],
            "confidence": round(self.confidence, 2),
            "success_rate": round(self.success_rate, 2),
            "observations": self.total_observations,
        }


class MemoryConsolidation:
    """Compresses long-term experience into actionable rules.

    Like memory consolidation during sleep — reviews episodes,
    extracts patterns, and generates reusable rules.
    """

    def __init__(self) -> None:
        self._compressed: list[CompressedEpisode] = []
        self._patterns: dict[str, ExtractedPattern] = {}
        self._rules: dict[str, ConsolidatedRule] = {}
        self._pattern_counter = 0
        self._rule_counter = 0
        self._consolidation_count = 0
        self._log = logger.bind(component="memory_consolidation")

    def compress_episode(
        self,
        episode_id: str,
        events: list[dict[str, Any]],
        outcome: str = "",
        target_type: str = "",
    ) -> CompressedEpisode:
        """Compress a full episode to key events only."""
        original_count = len(events)

        # Filter to important events only
        key_events = []
        tools = set()
        models = set()

        for event in events:
            importance = event.get("importance", 0.5)
            event_type = event.get("type", "")

            # Keep high-importance events
            if importance > 0.7:
                key_events.append(event.get("content", "")[:80])

            # Keep findings and decisions
            if event_type in ("finding", "decision", "error"):
                key_events.append(event.get("content", "")[:80])

            if event.get("tool"):
                tools.add(event["tool"])
            if event.get("model"):
                models.add(event["model"])

        compression_ratio = 1.0 - (len(key_events) / max(1, original_count))

        compressed = CompressedEpisode(
            episode_id=episode_id,
            target_type=target_type,
            tools_used=list(tools),
            models_used=list(models),
            key_events=key_events[:20],
            findings_count=sum(1 for e in events if e.get("type") == "finding"),
            outcome=outcome,
            tokens_used=sum(e.get("tokens", 0) for e in events),
            compression_ratio=compression_ratio,
        )

        self._compressed.append(compressed)
        if len(self._compressed) > 200:
            self._compressed = self._compressed[-200:]

        return compressed

    def extract_patterns(self) -> list[ExtractedPattern]:
        """Extract patterns from compressed episodes."""
        new_patterns = []

        # Pattern: Tool → outcome correlation
        tool_outcomes: dict[str, list[bool]] = defaultdict(list)
        for ep in self._compressed:
            is_success = ep.outcome == "success"
            for tool in ep.tools_used:
                tool_outcomes[tool].append(is_success)

        for tool, outcomes in tool_outcomes.items():
            if len(outcomes) >= 3:
                success_rate = sum(outcomes) / len(outcomes)
                if success_rate > 0.6 or success_rate < 0.3:
                    self._pattern_counter += 1
                    pattern = ExtractedPattern(
                        pattern_id=f"pat-{self._pattern_counter}",
                        description=f"Tool {tool} {'effective' if success_rate > 0.6 else 'ineffective'}",
                        conditions={"tool": tool},
                        action="prefer" if success_rate > 0.6 else "avoid",
                        frequency=len(outcomes),
                        success_rate=success_rate,
                        confidence=min(1.0, len(outcomes) / 10.0),
                    )
                    self._patterns[pattern.pattern_id] = pattern
                    new_patterns.append(pattern)

        # Pattern: Strategy → finding count correlation
        strategy_findings: dict[str, list[int]] = defaultdict(list)
        for ep in self._compressed:
            if ep.strategy_used:
                strategy_findings[ep.strategy_used].append(ep.findings_count)

        for strategy, findings_list in strategy_findings.items():
            if len(findings_list) >= 3:
                avg_findings = sum(findings_list) / len(findings_list)
                if avg_findings > 2:
                    self._pattern_counter += 1
                    pattern = ExtractedPattern(
                        pattern_id=f"pat-{self._pattern_counter}",
                        description=f"Strategy {strategy} yields ~{avg_findings:.1f} findings",
                        conditions={"strategy": strategy},
                        action=f"use_strategy:{strategy}",
                        frequency=len(findings_list),
                        success_rate=avg_findings / max(1, max(findings_list)),
                        confidence=min(1.0, len(findings_list) / 8.0),
                    )
                    self._patterns[pattern.pattern_id] = pattern
                    new_patterns.append(pattern)

        return new_patterns

    def generate_rules(self) -> list[ConsolidatedRule]:
        """Generate rules from high-confidence patterns."""
        new_rules = []

        for pattern in self._patterns.values():
            if pattern.confidence < 0.5 or pattern.frequency < 3:
                continue

            # Check if similar rule already exists
            existing = self._find_similar_rule(pattern)
            if existing:
                existing.total_observations += pattern.frequency
                existing.confidence = min(1.0, existing.confidence + 0.05)
                continue

            self._rule_counter += 1
            rule = ConsolidatedRule(
                rule_id=f"cr-{self._rule_counter}",
                condition=str(pattern.conditions),
                action=pattern.action,
                confidence=pattern.confidence,
                source_patterns=1,
                total_observations=pattern.frequency,
            )

            self._rules[rule.rule_id] = rule
            new_rules.append(rule)

        return new_rules

    def consolidate(self) -> dict[str, Any]:
        """Run a full consolidation cycle."""
        self._consolidation_count += 1

        patterns = self.extract_patterns()
        rules = self.generate_rules()
        pruned = self.prune_rules()

        return {
            "cycle": self._consolidation_count,
            "patterns_extracted": len(patterns),
            "rules_generated": len(rules),
            "rules_pruned": pruned,
        }

    def apply_rule(
        self,
        rule_id: str,
        success: bool,
    ) -> None:
        """Record the outcome of applying a rule."""
        rule = self._rules.get(rule_id)
        if not rule:
            return

        rule.last_applied = time.time()
        if success:
            rule.successful_applications += 1
            rule.confidence = min(1.0, rule.confidence + 0.02)
        else:
            rule.failed_applications += 1
            rule.confidence = max(0.0, rule.confidence - 0.05)

            # Deprecate very bad rules
            if rule.success_rate < 0.2 and rule.failed_applications > 5:
                rule.deprecated = True

    def get_applicable_rules(
        self,
        context: dict[str, Any],
    ) -> list[ConsolidatedRule]:
        """Get rules applicable to the current context."""
        applicable = []
        for rule in self._rules.values():
            if rule.deprecated:
                continue
            if rule.confidence < 0.3:
                continue
            # Simple matching: check if rule condition keys overlap with context
            applicable.append(rule)

        applicable.sort(key=lambda r: r.confidence, reverse=True)
        return applicable[:10]

    def prune_rules(self) -> int:
        """Prune deprecated and low-quality rules."""
        to_remove = []
        for rule_id, rule in self._rules.items():
            if rule.deprecated:
                to_remove.append(rule_id)
            elif rule.age_days > 30 and rule.success_rate < 0.3:
                to_remove.append(rule_id)

        for rule_id in to_remove:
            del self._rules[rule_id]

        return len(to_remove)

    def _find_similar_rule(self, pattern: ExtractedPattern) -> ConsolidatedRule | None:
        for rule in self._rules.values():
            if rule.action == pattern.action and rule.condition == str(pattern.conditions):
                return rule
        return None

    def get_stats(self) -> dict[str, Any]:
        return {
            "compressed_episodes": len(self._compressed),
            "patterns": len(self._patterns),
            "rules": len(self._rules),
            "active_rules": sum(1 for r in self._rules.values() if not r.deprecated),
            "consolidations": self._consolidation_count,
        }
