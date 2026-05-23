"""Learning system — continuous improvement through experience.

Implements multi-level learning:
1. Episode learning: Learn from individual assessment episodes
2. Skill acquisition: Build new capabilities from experience
3. Strategy refinement: Improve decision-making strategies
4. Error pattern learning: Avoid repeating mistakes
5. Tool effectiveness tracking: Learn which tools work where
6. Model performance profiling: Learn which models excel at what
7. Target pattern recognition: Recognize similar targets
8. Transfer learning: Apply lessons from one target to another
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class Episode:
    """A learning episode from a complete assessment or phase."""
    episode_id: str = ""
    target_type: str = ""
    goal: str = ""
    actions_taken: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    total_tokens: int = 0
    total_time_s: float = 0.0
    success_rate: float = 0.0
    strategies_used: list[str] = field(default_factory=list)
    tools_used: list[str] = field(default_factory=list)
    models_used: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    lessons: list[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.episode_id,
            "target_type": self.target_type,
            "findings": len(self.findings),
            "success_rate": round(self.success_rate, 2),
            "lessons": self.lessons[:3],
        }


@dataclass
class Skill:
    """A learned skill/capability."""
    skill_id: str = ""
    name: str = ""
    description: str = ""
    applicable_to: list[str] = field(default_factory=list)  # Target types
    procedure: list[str] = field(default_factory=list)       # Steps
    tools: list[str] = field(default_factory=list)
    models: list[str] = field(default_factory=list)
    success_rate: float = 0.5
    times_used: int = 0
    avg_findings: float = 0.0
    learned_from: str = ""    # Episode ID

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.skill_id, "name": self.name[:100],
            "applicable": self.applicable_to[:3],
            "success_rate": round(self.success_rate, 2),
            "times_used": self.times_used,
        }


@dataclass
class ErrorPattern:
    """A recognized error pattern to avoid."""
    pattern_id: str = ""
    error_type: str = ""
    description: str = ""
    context: str = ""
    avoidance_strategy: str = ""
    occurrences: int = 0
    last_seen: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "type": self.error_type[:50],
            "occurrences": self.occurrences,
            "avoidance": self.avoidance_strategy[:100],
        }


@dataclass
class TargetProfile:
    """Profile of a target type learned from experience."""
    target_type: str = ""
    common_technologies: list[str] = field(default_factory=list)
    effective_tools: list[str] = field(default_factory=list)
    effective_strategies: list[str] = field(default_factory=list)
    common_vulns: list[str] = field(default_factory=list)
    avg_findings: float = 0.0
    avg_assessment_time_s: float = 0.0
    times_assessed: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.target_type,
            "tools": self.effective_tools[:5],
            "strategies": self.effective_strategies[:3],
            "common_vulns": self.common_vulns[:5],
            "assessed": self.times_assessed,
        }


class LearningSystem:
    """Continuous improvement through experience.

    Learns from assessments to improve future performance
    across skills, strategies, tool selection, and error avoidance.
    """

    def __init__(self, storage_dir: str = "data/learning") -> None:
        self._storage_dir = Path(storage_dir)
        self._storage_dir.mkdir(parents=True, exist_ok=True)

        self._episodes: list[Episode] = []
        self._skills: dict[str, Skill] = {}
        self._error_patterns: dict[str, ErrorPattern] = {}
        self._target_profiles: dict[str, TargetProfile] = {}
        self._tool_effectiveness: dict[str, dict[str, float]] = defaultdict(dict)
        self._model_performance: dict[str, dict[str, float]] = defaultdict(dict)
        self._episode_counter = 0
        self._skill_counter = 0
        self._error_counter = 0

        self._log = logger.bind(component="learning_system")
        self._load()

    # ── Episode Recording ────────────────────────────────

    def record_episode(self, episode: Episode) -> str:
        """Record a complete assessment episode."""
        self._episode_counter += 1
        episode.episode_id = f"ep-{self._episode_counter}"

        self._episodes.append(episode)
        if len(self._episodes) > 500:
            self._episodes = self._episodes[-500:]

        # Extract lessons
        self._extract_tool_lessons(episode)
        self._extract_strategy_lessons(episode)
        self._extract_error_patterns(episode)
        self._update_target_profile(episode)

        # Try to learn new skills
        self._attempt_skill_learning(episode)

        self._log.info(
            "episode_recorded",
            id=episode.episode_id,
            findings=len(episode.findings),
            lessons=len(episode.lessons),
        )

        return episode.episode_id

    # ── Skill Management ─────────────────────────────────

    def get_applicable_skills(self, target_type: str) -> list[Skill]:
        """Get skills applicable to a target type."""
        return [
            s for s in self._skills.values()
            if target_type in s.applicable_to or not s.applicable_to
        ]

    def record_skill_use(self, skill_id: str, success: bool, findings: int = 0) -> None:
        """Record a skill usage and its outcome."""
        skill = self._skills.get(skill_id)
        if not skill:
            return
        skill.times_used += 1
        n = skill.times_used
        skill.success_rate = (skill.success_rate * (n - 1) + (1.0 if success else 0.0)) / n
        skill.avg_findings = (skill.avg_findings * (n - 1) + findings) / n

    # ── Error Pattern Learning ───────────────────────────

    def check_error_patterns(self, context: dict[str, Any]) -> list[ErrorPattern]:
        """Check if current context matches known error patterns."""
        matches = []
        context_str = json.dumps(context).lower()

        for pattern in self._error_patterns.values():
            if pattern.error_type.lower() in context_str:
                matches.append(pattern)
            elif pattern.context.lower() in context_str:
                matches.append(pattern)

        return matches

    # ── Recommendations ──────────────────────────────────

    def recommend_tools(self, target_type: str) -> list[str]:
        """Recommend tools based on past effectiveness."""
        profile = self._target_profiles.get(target_type)
        if profile and profile.effective_tools:
            return profile.effective_tools[:5]

        # Fall back to general effectiveness
        tool_scores: dict[str, float] = defaultdict(float)
        for tool, type_scores in self._tool_effectiveness.items():
            for t_type, score in type_scores.items():
                if t_type == target_type or not target_type:
                    tool_scores[tool] += score

        sorted_tools = sorted(tool_scores.keys(), key=lambda t: -tool_scores[t])
        return sorted_tools[:5]

    def recommend_strategy(self, target_type: str) -> str:
        """Recommend a strategy based on past performance."""
        profile = self._target_profiles.get(target_type)
        if profile and profile.effective_strategies:
            return profile.effective_strategies[0]
        return "adaptive"

    def recommend_model(self, task_type: str) -> str:
        """Recommend a model based on past performance."""
        model_scores = self._model_performance.get(task_type, {})
        if model_scores:
            return max(model_scores, key=model_scores.get)
        return ""

    # ── Internal Learning ────────────────────────────────

    def _extract_tool_lessons(self, episode: Episode) -> None:
        """Learn tool effectiveness from episode."""
        for action in episode.actions_taken:
            tool = action.get("tool", "")
            success = action.get("success", False)
            findings = action.get("findings_count", 0)

            if tool:
                current = self._tool_effectiveness.get(tool, {}).get(episode.target_type, 0.5)
                outcome = 1.0 if success else 0.0
                # Exponential moving average
                self._tool_effectiveness[tool][episode.target_type] = current * 0.8 + outcome * 0.2

                if findings > 0:
                    self._tool_effectiveness[tool][episode.target_type] = min(
                        1.0,
                        self._tool_effectiveness[tool][episode.target_type] + 0.05 * findings,
                    )

    def _extract_strategy_lessons(self, episode: Episode) -> None:
        """Learn strategy effectiveness from episode."""
        for model in episode.models_used:
            for strategy in episode.strategies_used:
                current = self._model_performance.get(strategy, {}).get(model, 0.5)
                outcome = episode.success_rate
                self._model_performance[strategy][model] = current * 0.8 + outcome * 0.2

    def _extract_error_patterns(self, episode: Episode) -> None:
        """Learn error patterns from episode."""
        for error in episode.errors:
            error_hash = hashlib.md5(error[:100].encode()).hexdigest()[:8]

            if error_hash in self._error_patterns:
                pattern = self._error_patterns[error_hash]
                pattern.occurrences += 1
                pattern.last_seen = time.time()
            else:
                self._error_counter += 1
                self._error_patterns[error_hash] = ErrorPattern(
                    pattern_id=f"errpat-{self._error_counter}",
                    error_type=error[:100],
                    description=error[:200],
                    context=episode.target_type,
                    avoidance_strategy=f"Check for this issue before proceeding: {error[:50]}",
                    occurrences=1,
                )

    def _update_target_profile(self, episode: Episode) -> None:
        """Update target type profile from episode."""
        target_type = episode.target_type
        if not target_type:
            return

        profile = self._target_profiles.get(target_type)
        if not profile:
            profile = TargetProfile(target_type=target_type)
            self._target_profiles[target_type] = profile

        profile.times_assessed += 1
        n = profile.times_assessed
        profile.avg_findings = (profile.avg_findings * (n - 1) + len(episode.findings)) / n
        profile.avg_assessment_time_s = (
            profile.avg_assessment_time_s * (n - 1) + episode.total_time_s
        ) / n

        # Update effective tools
        for tool in episode.tools_used:
            if tool not in profile.effective_tools:
                profile.effective_tools.append(tool)

        # Update effective strategies
        if episode.success_rate > 0.5:
            for strategy in episode.strategies_used:
                if strategy not in profile.effective_strategies:
                    profile.effective_strategies.append(strategy)

        # Update common vulns
        for finding in episode.findings:
            vuln_type = finding.get("type", "")
            if vuln_type and vuln_type not in profile.common_vulns:
                profile.common_vulns.append(vuln_type)

    def _attempt_skill_learning(self, episode: Episode) -> None:
        """Try to extract reusable skills from a successful episode."""
        if episode.success_rate < 0.6 or len(episode.actions_taken) < 3:
            return

        # Extract action sequence as a potential skill
        action_names = [a.get("name", "") for a in episode.actions_taken[:10] if a.get("name")]
        if len(action_names) < 3:
            return

        skill_key = hashlib.md5("|".join(action_names).encode()).hexdigest()[:8]
        if skill_key in self._skills:
            return

        self._skill_counter += 1
        skill = Skill(
            skill_id=f"skill-{self._skill_counter}",
            name=f"Learned: {episode.goal[:50]}",
            description=f"Effective procedure for {episode.target_type}",
            applicable_to=[episode.target_type] if episode.target_type else [],
            procedure=action_names,
            tools=list(set(episode.tools_used))[:5],
            models=list(set(episode.models_used))[:3],
            success_rate=episode.success_rate,
            learned_from=episode.episode_id,
        )

        self._skills[skill.skill_id] = skill
        self._log.info("skill_learned", skill=skill.name[:50])

    # ── Persistence ──────────────────────────────────────

    def save(self) -> None:
        """Persist learning state."""
        try:
            data = {
                "skills": {sid: s.to_dict() for sid, s in self._skills.items()},
                "error_patterns": {pid: p.to_dict() for pid, p in self._error_patterns.items()},
                "target_profiles": {t: p.to_dict() for t, p in self._target_profiles.items()},
                "tool_effectiveness": dict(self._tool_effectiveness),
                "model_performance": dict(self._model_performance),
                "counters": {
                    "episode": self._episode_counter,
                    "skill": self._skill_counter,
                    "error": self._error_counter,
                },
            }
            path = self._storage_dir / "learning_state.json"
            path.write_text(json.dumps(data))
        except OSError as e:
            self._log.warning("save_failed", error=str(e))

    def _load(self) -> None:
        """Load persisted state."""
        path = self._storage_dir / "learning_state.json"
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text())
            counters = data.get("counters", {})
            self._episode_counter = counters.get("episode", 0)
            self._skill_counter = counters.get("skill", 0)
            self._error_counter = counters.get("error", 0)

            for tool, scores in data.get("tool_effectiveness", {}).items():
                self._tool_effectiveness[tool] = scores
            for task_type, scores in data.get("model_performance", {}).items():
                self._model_performance[task_type] = scores
        except (json.JSONDecodeError, OSError):
            pass

    def get_stats(self) -> dict[str, Any]:
        return {
            "episodes": len(self._episodes),
            "skills": len(self._skills),
            "error_patterns": len(self._error_patterns),
            "target_profiles": len(self._target_profiles),
            "tools_profiled": len(self._tool_effectiveness),
        }
