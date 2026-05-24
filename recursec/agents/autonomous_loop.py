"""Autonomous loop — the infinite reasoning loop.

Drives the agent's 24/7 autonomous operation:
1. Continuous task generation
2. Dynamic priority adjustment
3. Backoff/retry on failures
4. Convergence detection → stop or expand
5. Self-initiated exploration
6. Resource budget management
7. Multi-phase cycling
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class LoopState(str, Enum):
    STARTING = "starting"
    RUNNING = "running"
    PAUSED = "paused"
    BACKOFF = "backoff"
    EXPANDING = "expanding"  # Found something, go deeper
    CONVERGING = "converging"  # Diminishing returns
    COMPLETING = "completing"
    STOPPED = "stopped"


class ActionType(str, Enum):
    SCAN = "scan"
    ANALYZE = "analyze"
    EXPLOIT = "exploit"
    VALIDATE = "validate"
    EXPAND = "expand"         # Broaden scope
    DEEPEN = "deepen"         # Go deeper on existing
    CORRELATE = "correlate"
    REFLECT = "reflect"
    REPORT = "report"
    IDLE = "idle"


class TriggerCondition(str, Enum):
    NEW_FINDING = "new_finding"
    PHASE_COMPLETE = "phase_complete"
    NO_PROGRESS = "no_progress"
    TIME_ELAPSED = "time_elapsed"
    TOKEN_LOW = "token_low"
    HIGH_SEVERITY = "high_severity"
    COVERAGE_GAP = "coverage_gap"
    ERROR = "error"


@dataclass
class LoopIteration:
    """A single loop iteration."""
    iteration_id: int = 0
    action: ActionType = ActionType.IDLE
    trigger: TriggerCondition = TriggerCondition.TIME_ELAPSED
    started_at: float = 0.0
    completed_at: float = 0.0
    findings_before: int = 0
    findings_after: int = 0
    tokens_used: int = 0
    success: bool = True
    note: str = ""

    @property
    def duration_s(self) -> float:
        if self.completed_at:
            return self.completed_at - self.started_at
        return 0.0

    @property
    def new_findings(self) -> int:
        return self.findings_after - self.findings_before

    def to_dict(self) -> dict[str, Any]:
        return {
            "iter": self.iteration_id,
            "action": self.action.value[:8],
            "trigger": self.trigger.value[:10],
            "new": self.new_findings,
            "ok": self.success,
        }


@dataclass
class LoopConfig:
    """Configuration for the autonomous loop."""
    max_iterations: int = 1000
    max_duration_s: float = 86400.0  # 24 hours
    max_tokens: int = 500000
    backoff_initial_s: float = 5.0
    backoff_max_s: float = 300.0
    backoff_multiplier: float = 2.0
    convergence_window: int = 10
    convergence_threshold: float = 0.1
    expansion_trigger: int = 3       # New findings to trigger expansion
    reflection_interval: int = 20    # Reflect every N iterations
    idle_timeout_s: float = 30.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_iter": self.max_iterations,
            "max_time": f"{self.max_duration_s / 3600:.0f}h",
            "max_tokens": self.max_tokens,
        }


# Action selection rules based on state
STATE_ACTIONS: dict[LoopState, list[ActionType]] = {
    LoopState.STARTING: [ActionType.SCAN],
    LoopState.RUNNING: [
        ActionType.SCAN, ActionType.ANALYZE,
        ActionType.EXPLOIT, ActionType.VALIDATE,
    ],
    LoopState.EXPANDING: [
        ActionType.EXPAND, ActionType.DEEPEN,
        ActionType.SCAN,
    ],
    LoopState.CONVERGING: [
        ActionType.CORRELATE, ActionType.REFLECT,
        ActionType.REPORT,
    ],
    LoopState.COMPLETING: [
        ActionType.REPORT, ActionType.VALIDATE,
    ],
}

# Trigger → recommended action
TRIGGER_ACTION_MAP: dict[TriggerCondition, ActionType] = {
    TriggerCondition.NEW_FINDING: ActionType.VALIDATE,
    TriggerCondition.PHASE_COMPLETE: ActionType.ANALYZE,
    TriggerCondition.NO_PROGRESS: ActionType.EXPAND,
    TriggerCondition.TIME_ELAPSED: ActionType.SCAN,
    TriggerCondition.TOKEN_LOW: ActionType.REPORT,
    TriggerCondition.HIGH_SEVERITY: ActionType.DEEPEN,
    TriggerCondition.COVERAGE_GAP: ActionType.SCAN,
    TriggerCondition.ERROR: ActionType.REFLECT,
}


class AutonomousLoop:
    """The autonomous reasoning loop.

    Drives continuous, self-directed operation.
    The agent keeps working until converged,
    budget exhausted, or explicitly stopped.
    """

    def __init__(self, config: LoopConfig | None = None) -> None:
        self._config = config or LoopConfig()
        self._state = LoopState.STARTING
        self._iterations: list[LoopIteration] = []
        self._current_iter = 0
        self._total_tokens = 0
        self._total_findings = 0
        self._started_at = 0.0
        self._backoff_s = self._config.backoff_initial_s
        self._consecutive_empty = 0
        self._log = logger.bind(component="auto_loop")

    def start(self) -> None:
        """Start the autonomous loop."""
        self._state = LoopState.RUNNING
        self._started_at = time.time()

    def should_continue(self) -> bool:
        """Check if the loop should continue."""
        if self._state == LoopState.STOPPED:
            return False

        if self._current_iter >= self._config.max_iterations:
            return False

        elapsed = time.time() - self._started_at if self._started_at else 0
        if elapsed >= self._config.max_duration_s:
            return False

        if self._total_tokens >= self._config.max_tokens:
            return False

        return True

    def detect_trigger(self) -> TriggerCondition:
        """Detect what triggered this iteration."""
        # Check recent findings
        recent = self._iterations[-3:] if len(self._iterations) >= 3 else self._iterations
        recent_findings = sum(i.new_findings for i in recent)

        if recent_findings > 0:
            # Found something → validate
            return TriggerCondition.NEW_FINDING

        # Check convergence
        if self._is_converging():
            return TriggerCondition.NO_PROGRESS

        # Check token budget
        token_pct = self._total_tokens / max(1, self._config.max_tokens)
        if token_pct > 0.8:
            return TriggerCondition.TOKEN_LOW

        # Default: time elapsed
        return TriggerCondition.TIME_ELAPSED

    def select_action(
        self,
        trigger: TriggerCondition | None = None,
    ) -> ActionType:
        """Select the next action based on state and trigger."""
        if trigger is None:
            trigger = self.detect_trigger()

        # Check if we should reflect
        if (
            self._current_iter > 0
            and self._current_iter % self._config.reflection_interval == 0
        ):
            return ActionType.REFLECT

        # Trigger-specific action
        recommended = TRIGGER_ACTION_MAP.get(trigger, ActionType.SCAN)

        # State-allowed actions
        allowed = STATE_ACTIONS.get(self._state, [ActionType.SCAN])

        if recommended in allowed:
            return recommended

        # Fallback to first allowed
        return allowed[0] if allowed else ActionType.SCAN

    def begin_iteration(self) -> LoopIteration:
        """Start a new loop iteration."""
        self._current_iter += 1
        trigger = self.detect_trigger()
        action = self.select_action(trigger)

        iteration = LoopIteration(
            iteration_id=self._current_iter,
            action=action,
            trigger=trigger,
            started_at=time.time(),
            findings_before=self._total_findings,
        )

        return iteration

    def end_iteration(
        self,
        iteration: LoopIteration,
        findings_added: int = 0,
        tokens_used: int = 0,
        success: bool = True,
    ) -> None:
        """Complete a loop iteration."""
        iteration.completed_at = time.time()
        iteration.findings_after = self._total_findings + findings_added
        iteration.tokens_used = tokens_used
        iteration.success = success

        self._total_findings += findings_added
        self._total_tokens += tokens_used
        self._iterations.append(iteration)

        # Update state based on results
        self._update_state(iteration)

    def _update_state(self, iteration: LoopIteration) -> None:
        """Update loop state based on latest iteration."""
        if not iteration.success:
            # Backoff on failure
            self._backoff_s = min(
                self._backoff_s * self._config.backoff_multiplier,
                self._config.backoff_max_s,
            )
            self._state = LoopState.BACKOFF
            return

        # Reset backoff on success
        self._backoff_s = self._config.backoff_initial_s

        if iteration.new_findings >= self._config.expansion_trigger:
            # Found a lot → expand
            self._state = LoopState.EXPANDING
            self._consecutive_empty = 0
        elif iteration.new_findings > 0:
            # Found something → keep going
            self._state = LoopState.RUNNING
            self._consecutive_empty = 0
        else:
            # Nothing found
            self._consecutive_empty += 1

            if self._is_converging():
                self._state = LoopState.CONVERGING

    def _is_converging(self) -> bool:
        """Check if the loop is converging (diminishing returns)."""
        window = self._config.convergence_window
        if len(self._iterations) < window:
            return False

        recent = self._iterations[-window:]
        total_new = sum(i.new_findings for i in recent)

        rate = total_new / window
        return rate < self._config.convergence_threshold

    def stop(self) -> None:
        """Stop the loop."""
        self._state = LoopState.STOPPED

    def get_elapsed_s(self) -> float:
        """Get elapsed time."""
        if self._started_at:
            return time.time() - self._started_at
        return 0.0

    def get_progress(self) -> dict[str, Any]:
        """Get loop progress."""
        elapsed = self.get_elapsed_s()

        return {
            "state": self._state.value,
            "iteration": self._current_iter,
            "max_iterations": self._config.max_iterations,
            "findings": self._total_findings,
            "tokens": self._total_tokens,
            "elapsed": f"{elapsed / 60:.0f}min",
            "converging": self._is_converging(),
        }

    def build_loop_prompt(self) -> str:
        """Build loop state for LLM."""
        progress = self.get_progress()
        lines = ["## Autonomous Loop\n"]
        lines.append(f"State: {progress['state']}")
        lines.append(f"Iteration: {progress['iteration']}/{progress['max_iterations']}")
        lines.append(f"Findings: {progress['findings']}")
        lines.append(f"Tokens: {progress['tokens']}")
        lines.append(f"Elapsed: {progress['elapsed']}")

        if self._iterations:
            last = self._iterations[-1]
            lines.append(f"\nLast action: {last.action.value}")
            lines.append(f"Last trigger: {last.trigger.value}")
            lines.append(f"Last new findings: {last.new_findings}")

        if self._is_converging():
            lines.append("\nWARNING: Convergence detected")
            lines.append("Consider: expand scope or complete")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        action_counts: dict[str, int] = {}
        for i in self._iterations:
            action_counts[i.action.value] = (
                action_counts.get(i.action.value, 0) + 1
            )

        trigger_counts: dict[str, int] = {}
        for i in self._iterations:
            trigger_counts[i.trigger.value] = (
                trigger_counts.get(i.trigger.value, 0) + 1
            )

        return {
            "state": self._state.value,
            "iterations": self._current_iter,
            "findings": self._total_findings,
            "tokens": self._total_tokens,
            "elapsed_s": self.get_elapsed_s(),
            "by_action": action_counts,
            "by_trigger": trigger_counts,
        }
