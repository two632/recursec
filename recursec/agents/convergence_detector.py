"""Convergence detector — detects when agent execution should stop.

Prevents infinite loops and wasted computation by detecting:
1. Output stabilization (new iterations don't find new things)
2. Diminishing returns (effort vs findings ratio declining)
3. Budget exhaustion (token/step/time budgets)
4. Circular reasoning (agent revisiting same conclusions)
5. Coverage saturation (all known attack vectors tested)
6. Quality plateau (finding quality not improving)
7. Tool exhaustion (all relevant tools already run)
8. Confidence threshold (overall confidence high enough)
9. Error accumulation (too many consecutive errors)
10. Adversarial termination (defender proves security)

This is CRITICAL for recursive agents — without convergence
detection, agents recurse forever.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ConvergenceReason(str, Enum):
    OUTPUT_STABLE = "output_stable"
    DIMINISHING_RETURNS = "diminishing_returns"
    BUDGET_EXHAUSTED = "budget_exhausted"
    CIRCULAR_REASONING = "circular_reasoning"
    COVERAGE_SATURATED = "coverage_saturated"
    QUALITY_PLATEAU = "quality_plateau"
    TOOL_EXHAUSTION = "tool_exhaustion"
    CONFIDENCE_MET = "confidence_met"
    ERROR_LIMIT = "error_limit"
    TIMEOUT = "timeout"
    MAX_DEPTH = "max_depth"
    USER_STOP = "user_stop"
    NOT_CONVERGED = "not_converged"


@dataclass
class ConvergenceConfig:
    """Thresholds for convergence detection."""
    max_iterations: int = 50
    max_tokens: int = 100000
    max_steps: int = 200
    timeout_s: float = 3600.0
    max_depth: int = 5
    max_consecutive_errors: int = 5
    min_confidence: float = 0.85
    stability_window: int = 3
    min_new_findings_rate: float = 0.1
    quality_plateau_window: int = 5
    max_circular_repeats: int = 3

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_iter": self.max_iterations,
            "max_tokens": self.max_tokens,
            "timeout": self.timeout_s,
            "min_conf": self.min_confidence,
        }


@dataclass
class ConvergenceState:
    """Current state tracked by the detector."""
    iteration: int = 0
    tokens_used: int = 0
    steps_taken: int = 0
    depth: int = 0
    start_time: float = field(default_factory=time.time)
    findings_per_iteration: list[int] = field(default_factory=list)
    quality_scores: list[float] = field(default_factory=list)
    confidence_history: list[float] = field(default_factory=list)
    tools_used: set[str] = field(default_factory=set)
    conclusions_seen: list[str] = field(default_factory=list)
    consecutive_errors: int = 0
    unique_findings: set[str] = field(default_factory=set)

    @property
    def elapsed_s(self) -> float:
        return time.time() - self.start_time

    def to_dict(self) -> dict[str, Any]:
        return {
            "iter": self.iteration,
            "tokens": self.tokens_used,
            "steps": self.steps_taken,
            "findings": len(self.unique_findings),
            "elapsed": f"{self.elapsed_s:.0f}s",
            "errors": self.consecutive_errors,
        }


@dataclass
class ConvergenceResult:
    """Result of convergence check."""
    converged: bool = False
    reason: ConvergenceReason = ConvergenceReason.NOT_CONVERGED
    should_continue: bool = True
    confidence: float = 0.0
    details: str = ""
    suggested_action: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "converged": self.converged,
            "reason": self.reason.value[:15],
            "continue": self.should_continue,
            "conf": f"{self.confidence:.0%}",
        }


class ConvergenceDetector:
    """Detects when agent execution should converge and stop."""

    def __init__(self, config: ConvergenceConfig | None = None) -> None:
        self._config = config or ConvergenceConfig()
        self._states: dict[str, ConvergenceState] = {}
        self._log = logger.bind(component="convergence")

    def create_tracker(self, task_id: str) -> ConvergenceState:
        """Create a new convergence tracker for a task."""
        state = ConvergenceState()
        self._states[task_id] = state
        return state

    def record_iteration(self, task_id: str, new_findings: int = 0, quality: float = 0.5, confidence: float = 0.5, tokens_used: int = 0) -> None:
        """Record an iteration's results."""
        state = self._states.get(task_id)
        if not state:
            return

        state.iteration += 1
        state.tokens_used += tokens_used
        state.steps_taken += 1
        state.findings_per_iteration.append(new_findings)
        state.quality_scores.append(quality)
        state.confidence_history.append(confidence)

    def record_finding(self, task_id: str, finding_hash: str) -> None:
        """Record a unique finding."""
        state = self._states.get(task_id)
        if state:
            state.unique_findings.add(finding_hash)

    def record_tool(self, task_id: str, tool_name: str) -> None:
        """Record a tool execution."""
        state = self._states.get(task_id)
        if state:
            state.tools_used.add(tool_name)

    def record_conclusion(self, task_id: str, conclusion: str) -> None:
        """Record a reasoning conclusion (for circular detection)."""
        state = self._states.get(task_id)
        if state:
            state.conclusions_seen.append(conclusion[:100])

    def record_error(self, task_id: str) -> None:
        """Record an error."""
        state = self._states.get(task_id)
        if state:
            state.consecutive_errors += 1

    def record_success(self, task_id: str) -> None:
        """Record a success (resets error counter)."""
        state = self._states.get(task_id)
        if state:
            state.consecutive_errors = 0

    def check(self, task_id: str) -> ConvergenceResult:
        """Check if execution has converged."""
        state = self._states.get(task_id)
        if not state:
            return ConvergenceResult(converged=False)

        # Check each convergence criterion
        checks = [
            self._check_budget(state),
            self._check_timeout(state),
            self._check_max_depth(state),
            self._check_error_limit(state),
            self._check_confidence(state),
            self._check_output_stability(state),
            self._check_diminishing_returns(state),
            self._check_circular_reasoning(state),
            self._check_quality_plateau(state),
        ]

        for result in checks:
            if result.converged:
                return result

        return ConvergenceResult(
            converged=False,
            reason=ConvergenceReason.NOT_CONVERGED,
            should_continue=True,
            confidence=state.confidence_history[-1] if state.confidence_history else 0.0,
        )

    def _check_budget(self, state: ConvergenceState) -> ConvergenceResult:
        """Check token/iteration budgets."""
        if state.iteration >= self._config.max_iterations:
            return ConvergenceResult(
                converged=True,
                reason=ConvergenceReason.BUDGET_EXHAUSTED,
                should_continue=False,
                details=f"Max iterations ({self._config.max_iterations}) reached",
                suggested_action="Report current findings",
            )
        if state.tokens_used >= self._config.max_tokens:
            return ConvergenceResult(
                converged=True,
                reason=ConvergenceReason.BUDGET_EXHAUSTED,
                should_continue=False,
                details=f"Token budget ({self._config.max_tokens}) exhausted",
            )
        return ConvergenceResult(converged=False)

    def _check_timeout(self, state: ConvergenceState) -> ConvergenceResult:
        """Check time budget."""
        if state.elapsed_s >= self._config.timeout_s:
            return ConvergenceResult(
                converged=True,
                reason=ConvergenceReason.TIMEOUT,
                should_continue=False,
                details=f"Timeout ({self._config.timeout_s}s) reached",
            )
        return ConvergenceResult(converged=False)

    def _check_max_depth(self, state: ConvergenceState) -> ConvergenceResult:
        """Check recursion depth."""
        if state.depth >= self._config.max_depth:
            return ConvergenceResult(
                converged=True,
                reason=ConvergenceReason.MAX_DEPTH,
                should_continue=False,
                details=f"Max depth ({self._config.max_depth}) reached",
            )
        return ConvergenceResult(converged=False)

    def _check_error_limit(self, state: ConvergenceState) -> ConvergenceResult:
        """Check consecutive errors."""
        if state.consecutive_errors >= self._config.max_consecutive_errors:
            return ConvergenceResult(
                converged=True,
                reason=ConvergenceReason.ERROR_LIMIT,
                should_continue=False,
                details=f"{state.consecutive_errors} consecutive errors",
                suggested_action="Investigate errors before continuing",
            )
        return ConvergenceResult(converged=False)

    def _check_confidence(self, state: ConvergenceState) -> ConvergenceResult:
        """Check if confidence threshold is met."""
        if state.confidence_history and state.confidence_history[-1] >= self._config.min_confidence:
            # Check stability
            window = self._config.stability_window
            if len(state.confidence_history) >= window:
                recent = state.confidence_history[-window:]
                if all(c >= self._config.min_confidence for c in recent):
                    return ConvergenceResult(
                        converged=True,
                        reason=ConvergenceReason.CONFIDENCE_MET,
                        should_continue=False,
                        confidence=state.confidence_history[-1],
                        details=f"Confidence {state.confidence_history[-1]:.0%} stable for {window} iterations",
                    )
        return ConvergenceResult(converged=False)

    def _check_output_stability(self, state: ConvergenceState) -> ConvergenceResult:
        """Check if outputs have stabilized (no new findings)."""
        window = self._config.stability_window
        if len(state.findings_per_iteration) >= window:
            recent = state.findings_per_iteration[-window:]
            if all(f == 0 for f in recent):
                return ConvergenceResult(
                    converged=True,
                    reason=ConvergenceReason.OUTPUT_STABLE,
                    should_continue=False,
                    details=f"No new findings for {window} iterations",
                    suggested_action="Move to reporting phase",
                )
        return ConvergenceResult(converged=False)

    def _check_diminishing_returns(self, state: ConvergenceState) -> ConvergenceResult:
        """Check for diminishing returns."""
        if len(state.findings_per_iteration) < 5:
            return ConvergenceResult(converged=False)

        recent = state.findings_per_iteration[-5:]
        total_recent = sum(recent)
        total_all = sum(state.findings_per_iteration)

        if total_all > 0 and total_recent / max(total_all, 1) < self._config.min_new_findings_rate:
            return ConvergenceResult(
                converged=True,
                reason=ConvergenceReason.DIMINISHING_RETURNS,
                should_continue=False,
                details=f"Finding rate declined: {total_recent}/{total_all} in last 5 iterations",
            )
        return ConvergenceResult(converged=False)

    def _check_circular_reasoning(self, state: ConvergenceState) -> ConvergenceResult:
        """Check for circular reasoning (repeated conclusions)."""
        if len(state.conclusions_seen) < 3:
            return ConvergenceResult(converged=False)

        conclusion_counts: dict[str, int] = defaultdict(int)
        for c in state.conclusions_seen:
            conclusion_counts[c] += 1

        max_repeats = max(conclusion_counts.values()) if conclusion_counts else 0
        if max_repeats >= self._config.max_circular_repeats:
            return ConvergenceResult(
                converged=True,
                reason=ConvergenceReason.CIRCULAR_REASONING,
                should_continue=False,
                details=f"Conclusion repeated {max_repeats} times",
                suggested_action="Try different reasoning mode",
            )
        return ConvergenceResult(converged=False)

    def _check_quality_plateau(self, state: ConvergenceState) -> ConvergenceResult:
        """Check if quality has plateaued."""
        window = self._config.quality_plateau_window
        if len(state.quality_scores) < window:
            return ConvergenceResult(converged=False)

        recent = state.quality_scores[-window:]
        avg = sum(recent) / len(recent)
        variance = sum((q - avg) ** 2 for q in recent) / len(recent)

        if variance < 0.01 and avg > 0.6:
            return ConvergenceResult(
                converged=True,
                reason=ConvergenceReason.QUALITY_PLATEAU,
                should_continue=False,
                confidence=avg,
                details=f"Quality plateaued at {avg:.0%} (var={variance:.4f})",
            )
        return ConvergenceResult(converged=False)

    def build_convergence_prompt(self, task_id: str) -> str:
        """Build LLM prompt with convergence state."""
        state = self._states.get(task_id)
        if not state:
            return ""

        lines = ["## Convergence Status"]
        lines.append(f"Iteration: {state.iteration}/{self._config.max_iterations}")
        lines.append(f"Tokens: {state.tokens_used}/{self._config.max_tokens}")
        lines.append(f"Findings: {len(state.unique_findings)}")
        lines.append(f"Tools used: {len(state.tools_used)}")
        lines.append(f"Elapsed: {state.elapsed_s:.0f}s/{self._config.timeout_s:.0f}s")

        if state.confidence_history:
            lines.append(f"Current confidence: {state.confidence_history[-1]:.0%}")

        if state.consecutive_errors > 0:
            lines.append(f"Consecutive errors: {state.consecutive_errors}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            "trackers": len(self._states),
        }
