"""Tool effectiveness tracker — learns which tools work best.

Implements:
1. Per-tool success/failure tracking
2. Tool-target affinity scoring
3. Tool combination effectiveness
4. Recommendation engine
5. Effectiveness decay over time
6. Tool selection prompt for LLM
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class ToolExecution:
    """A single tool execution record."""
    exec_id: str = ""
    tool_name: str = ""
    target_type: str = ""
    phase: str = ""
    success: bool = False
    findings_count: int = 0
    execution_time_s: float = 0.0
    false_positive_count: int = 0
    error: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool_name[:12],
            "success": self.success,
            "findings": self.findings_count,
            "time_s": f"{self.execution_time_s:.1f}",
        }


@dataclass
class ToolProfile:
    """Aggregated profile for a tool."""
    tool_name: str = ""
    total_executions: int = 0
    successful_executions: int = 0
    total_findings: int = 0
    total_false_positives: int = 0
    avg_execution_time_s: float = 0.0
    target_affinity: dict[str, float] = field(default_factory=dict)
    phase_affinity: dict[str, float] = field(default_factory=dict)
    last_used: float = 0.0

    @property
    def success_rate(self) -> float:
        if self.total_executions == 0:
            return 0.0
        return self.successful_executions / self.total_executions

    @property
    def findings_per_exec(self) -> float:
        if self.total_executions == 0:
            return 0.0
        return self.total_findings / self.total_executions

    @property
    def fp_rate(self) -> float:
        total = self.total_findings + self.total_false_positives
        if total == 0:
            return 0.0
        return self.total_false_positives / total

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool_name[:12],
            "execs": self.total_executions,
            "success": f"{self.success_rate:.0%}",
            "findings/exec": f"{self.findings_per_exec:.1f}",
        }


@dataclass
class ToolCombo:
    """Effectiveness of a tool combination."""
    tools: tuple[str, ...] = ()
    uses: int = 0
    avg_findings: float = 0.0
    avg_unique_findings: float = 0.0
    synergy_score: float = 0.0


class ToolEffectivenessTracker:
    """Tracks tool effectiveness across assessments.

    Learns which tools work best for which targets,
    recommends optimal tools, and detects synergies.
    """

    def __init__(self, decay_factor: float = 0.95) -> None:
        self._executions: list[ToolExecution] = []
        self._profiles: dict[str, ToolProfile] = {}
        self._combos: dict[str, ToolCombo] = {}
        self._exec_counter = 0
        self._decay_factor = decay_factor
        self._log = logger.bind(component="tool_eff")

    def record_execution(
        self,
        tool_name: str,
        target_type: str = "",
        phase: str = "",
        success: bool = True,
        findings_count: int = 0,
        execution_time_s: float = 0.0,
        false_positive_count: int = 0,
        error: str = "",
    ) -> ToolExecution:
        """Record a tool execution."""
        self._exec_counter += 1

        execution = ToolExecution(
            exec_id=f"texec-{self._exec_counter}",
            tool_name=tool_name,
            target_type=target_type,
            phase=phase,
            success=success,
            findings_count=findings_count,
            execution_time_s=execution_time_s,
            false_positive_count=false_positive_count,
            error=error,
        )
        self._executions.append(execution)

        # Update profile
        self._update_profile(execution)

        return execution

    def _update_profile(self, execution: ToolExecution) -> None:
        """Update tool profile with new execution."""
        name = execution.tool_name

        if name not in self._profiles:
            self._profiles[name] = ToolProfile(tool_name=name)

        profile = self._profiles[name]
        n = profile.total_executions

        profile.total_executions += 1
        if execution.success:
            profile.successful_executions += 1
        profile.total_findings += execution.findings_count
        profile.total_false_positives += execution.false_positive_count
        profile.last_used = execution.timestamp

        # Running average of execution time
        if execution.execution_time_s > 0:
            profile.avg_execution_time_s = (
                profile.avg_execution_time_s * n + execution.execution_time_s
            ) / (n + 1)

        # Target affinity
        if execution.target_type:
            key = execution.target_type
            prev = profile.target_affinity.get(key, 0.5)
            result = 1.0 if execution.success and execution.findings_count > 0 else 0.0
            profile.target_affinity[key] = prev * 0.8 + result * 0.2

        # Phase affinity
        if execution.phase:
            key = execution.phase
            prev = profile.phase_affinity.get(key, 0.5)
            result = 1.0 if execution.success else 0.0
            profile.phase_affinity[key] = prev * 0.8 + result * 0.2

    def record_combo(
        self,
        tools: list[str],
        findings: int = 0,
        unique_findings: int = 0,
    ) -> None:
        """Record a tool combination result."""
        key = "|".join(sorted(tools))

        if key not in self._combos:
            self._combos[key] = ToolCombo(tools=tuple(sorted(tools)))

        combo = self._combos[key]
        n = combo.uses
        combo.uses += 1
        combo.avg_findings = (combo.avg_findings * n + findings) / (n + 1)
        combo.avg_unique_findings = (combo.avg_unique_findings * n + unique_findings) / (n + 1)

        # Synergy: unique findings > sum of individual averages
        individual_sum = sum(
            self._profiles.get(t, ToolProfile()).findings_per_exec
            for t in tools
        )
        if individual_sum > 0:
            combo.synergy_score = combo.avg_unique_findings / individual_sum
        else:
            combo.synergy_score = 1.0

    def recommend_tools(
        self,
        target_type: str = "",
        phase: str = "",
        max_tools: int = 5,
    ) -> list[tuple[str, float]]:
        """Recommend tools for a target/phase."""
        scores: list[tuple[str, float]] = []

        for name, profile in self._profiles.items():
            if profile.total_executions < 1:
                continue

            score = profile.success_rate * 0.3

            # Finding rate
            score += min(1.0, profile.findings_per_exec / 5) * 0.3

            # Low false positive rate
            score += (1 - profile.fp_rate) * 0.2

            # Target affinity
            if target_type and target_type in profile.target_affinity:
                score += profile.target_affinity[target_type] * 0.1

            # Phase affinity
            if phase and phase in profile.phase_affinity:
                score += profile.phase_affinity[phase] * 0.1

            # Recency decay
            age_days = (time.time() - profile.last_used) / 86400
            decay = self._decay_factor ** age_days
            score *= decay

            scores.append((name, score))

        scores.sort(key=lambda x: x[1], reverse=True)
        return scores[:max_tools]

    def get_best_combo(
        self,
        min_synergy: float = 1.0,
    ) -> list[ToolCombo]:
        """Get tool combinations with synergy."""
        combos = [
            c for c in self._combos.values()
            if c.synergy_score >= min_synergy and c.uses >= 2
        ]
        combos.sort(key=lambda c: c.synergy_score, reverse=True)
        return combos[:5]

    def build_effectiveness_prompt(
        self,
        target_type: str = "",
        phase: str = "",
    ) -> str:
        """Build tool effectiveness context for LLM."""
        lines = ["## Tool Effectiveness\n"]
        lines.append(f"Tools tracked: {len(self._profiles)}")
        lines.append(f"Executions: {len(self._executions)}")

        # Recommendations
        recs = self.recommend_tools(target_type, phase, 5)
        if recs:
            lines.append(f"\nRecommended{' for ' + target_type if target_type else ''}:")
            for tool, score in recs:
                profile = self._profiles[tool]
                lines.append(
                    f"  {tool[:12]}: score={score:.2f}, "
                    f"success={profile.success_rate:.0%}, "
                    f"findings/run={profile.findings_per_exec:.1f}"
                )

        # Best combos
        combos = self.get_best_combo()
        if combos:
            lines.append("\nSynergistic combos:")
            for c in combos[:3]:
                tools_str = " + ".join(t[:8] for t in c.tools)
                lines.append(f"  {tools_str}: synergy={c.synergy_score:.1f}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            "tools_tracked": len(self._profiles),
            "total_executions": len(self._executions),
            "combos": len(self._combos),
            "top_tools": [
                (name, p.success_rate)
                for name, p in sorted(
                    self._profiles.items(),
                    key=lambda x: x[1].success_rate,
                    reverse=True,
                )[:5]
            ],
        }
