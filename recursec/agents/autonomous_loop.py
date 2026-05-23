"""Autonomous execution loop — 24/7 agent operation engine.

Implements:
1. Continuous assessment cycle
2. Stagnation detection
3. Dynamic strategy adjustment
4. Sleep/wake scheduling
5. Finding deduplication
6. Progress tracking
7. Automatic recovery from failures
8. Resource budget management
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class LoopPhase(str, Enum):
    STARTING = "starting"
    RECON = "recon"
    SCANNING = "scanning"
    ANALYSIS = "analysis"
    EXPLOITATION = "exploitation"
    VALIDATION = "validation"
    REPORTING = "reporting"
    SLEEPING = "sleeping"
    RECOVERING = "recovering"
    STOPPED = "stopped"


class StagnationType(str, Enum):
    NO_NEW_FINDINGS = "no_new_findings"
    COVERAGE_PLATEAU = "coverage_plateau"
    REPEATED_FAILURES = "repeated_failures"
    BUDGET_LOW = "budget_low"


@dataclass
class LoopIteration:
    """One iteration of the autonomous loop."""
    iteration_id: int = 0
    phase: LoopPhase = LoopPhase.STARTING
    started_at: float = field(default_factory=time.time)
    completed_at: float = 0.0
    findings_count: int = 0
    tools_run: int = 0
    tokens_used: int = 0
    errors: int = 0
    stagnation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "iteration": self.iteration_id,
            "phase": self.phase.value,
            "findings": self.findings_count,
            "tools": self.tools_run,
            "tokens": self.tokens_used,
            "errors": self.errors,
        }


@dataclass
class LoopConfig:
    """Configuration for the autonomous loop."""
    max_iterations: int = 1000
    max_tokens_total: int = 10_000_000
    max_time_s: float = 86400.0  # 24 hours
    sleep_between_phases_s: float = 5.0
    stagnation_threshold: int = 5     # Iterations with no new findings
    min_findings_per_iteration: int = 0
    auto_strategy_switch: bool = True
    max_errors_before_stop: int = 10
    dedup_findings: bool = True
    checkpoint_interval: int = 5     # Checkpoint every N iterations

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_iterations": self.max_iterations,
            "max_tokens": self.max_tokens_total,
            "max_time_s": self.max_time_s,
            "stagnation_threshold": self.stagnation_threshold,
        }


@dataclass
class LoopState:
    """Current state of the autonomous loop."""
    current_iteration: int = 0
    current_phase: LoopPhase = LoopPhase.STARTING
    total_findings: int = 0
    total_tokens_used: int = 0
    total_tools_run: int = 0
    total_errors: int = 0
    started_at: float = field(default_factory=time.time)
    last_finding_at: float = 0.0
    stagnation_count: int = 0
    iterations: list[LoopIteration] = field(default_factory=list)
    unique_finding_hashes: set[str] = field(default_factory=set)

    def to_dict(self) -> dict[str, Any]:
        elapsed = time.time() - self.started_at
        return {
            "iteration": self.current_iteration,
            "phase": self.current_phase.value,
            "findings": self.total_findings,
            "tokens": self.total_tokens_used,
            "tools_run": self.total_tools_run,
            "errors": self.total_errors,
            "elapsed_s": round(elapsed, 0),
            "stagnation": self.stagnation_count,
        }


# ── Phase transition strategy ────────────────────────────────

PHASE_ORDER: list[LoopPhase] = [
    LoopPhase.RECON,
    LoopPhase.SCANNING,
    LoopPhase.ANALYSIS,
    LoopPhase.EXPLOITATION,
    LoopPhase.VALIDATION,
    LoopPhase.REPORTING,
]

PHASE_TOKEN_BUDGETS: dict[str, float] = {
    "recon": 0.15,
    "scanning": 0.30,
    "analysis": 0.20,
    "exploitation": 0.20,
    "validation": 0.10,
    "reporting": 0.05,
}

STAGNATION_STRATEGIES: dict[str, str] = {
    "no_new_findings": "switch_to_deeper_scan",
    "coverage_plateau": "try_different_tools",
    "repeated_failures": "reduce_scope",
    "budget_low": "prioritize_validation",
}


class AutonomousLoop:
    """24/7 autonomous execution engine.

    Manages continuous assessment cycles,
    detects stagnation, adjusts strategies,
    and ensures progress toward comprehensive
    coverage.
    """

    def __init__(
        self,
        config: LoopConfig | None = None,
    ) -> None:
        self._config = config or LoopConfig()
        self._state = LoopState()
        self._log = logger.bind(component="autonomous_loop")

    @property
    def state(self) -> LoopState:
        return self._state

    def should_continue(self) -> bool:
        """Check if the loop should continue."""
        # Max iterations
        if self._state.current_iteration >= self._config.max_iterations:
            self._log.info("loop_stop_max_iterations")
            return False

        # Max tokens
        if self._state.total_tokens_used >= self._config.max_tokens_total:
            self._log.info("loop_stop_max_tokens")
            return False

        # Max time
        elapsed = time.time() - self._state.started_at
        if elapsed >= self._config.max_time_s:
            self._log.info("loop_stop_max_time")
            return False

        # Max errors
        if self._state.total_errors >= self._config.max_errors_before_stop:
            self._log.info("loop_stop_max_errors")
            return False

        return True

    def start_iteration(self) -> LoopIteration:
        """Start a new iteration."""
        self._state.current_iteration += 1
        iteration = LoopIteration(
            iteration_id=self._state.current_iteration,
            phase=self._get_current_phase(),
        )
        self._state.iterations.append(iteration)
        self._state.current_phase = iteration.phase
        return iteration

    def complete_iteration(
        self,
        iteration: LoopIteration,
        findings_count: int = 0,
        tools_run: int = 0,
        tokens_used: int = 0,
        errors: int = 0,
    ) -> None:
        """Complete an iteration and update state."""
        iteration.completed_at = time.time()
        iteration.findings_count = findings_count
        iteration.tools_run = tools_run
        iteration.tokens_used = tokens_used
        iteration.errors = errors

        self._state.total_findings += findings_count
        self._state.total_tokens_used += tokens_used
        self._state.total_tools_run += tools_run
        self._state.total_errors += errors

        if findings_count > 0:
            self._state.last_finding_at = time.time()
            self._state.stagnation_count = 0
        else:
            self._state.stagnation_count += 1

    def check_stagnation(self) -> StagnationType | None:
        """Check if the loop is stagnating."""
        if self._state.stagnation_count >= self._config.stagnation_threshold:
            return StagnationType.NO_NEW_FINDINGS

        # Coverage plateau: last N iterations found same count
        recent = self._state.iterations[-5:]
        if len(recent) >= 5:
            findings_counts = [i.findings_count for i in recent]
            if all(c == findings_counts[0] for c in findings_counts):
                return StagnationType.COVERAGE_PLATEAU

        # Repeated failures
        recent_errors = sum(i.errors for i in self._state.iterations[-3:])
        if recent_errors > 5:
            return StagnationType.REPEATED_FAILURES

        # Budget low
        budget_used = self._state.total_tokens_used / max(1, self._config.max_tokens_total)
        if budget_used > 0.9:
            return StagnationType.BUDGET_LOW

        return None

    def get_stagnation_strategy(self, stagnation: StagnationType) -> str:
        """Get the strategy for handling stagnation."""
        return STAGNATION_STRATEGIES.get(stagnation.value, "continue")

    def is_duplicate_finding(self, finding_hash: str) -> bool:
        """Check if a finding is a duplicate."""
        if not self._config.dedup_findings:
            return False
        if finding_hash in self._state.unique_finding_hashes:
            return True
        self._state.unique_finding_hashes.add(finding_hash)
        return False

    def _get_current_phase(self) -> LoopPhase:
        """Determine the current phase based on iteration."""
        if not self._state.iterations:
            return LoopPhase.RECON

        phase_idx = (self._state.current_iteration - 1) % len(PHASE_ORDER)
        return PHASE_ORDER[phase_idx]

    def get_phase_budget(self, phase: LoopPhase) -> int:
        """Get token budget for a phase."""
        fraction = PHASE_TOKEN_BUDGETS.get(phase.value, 0.1)
        return int(self._config.max_tokens_total * fraction)

    def should_checkpoint(self) -> bool:
        """Check if we should save a checkpoint."""
        return (
            self._state.current_iteration > 0
            and self._state.current_iteration % self._config.checkpoint_interval == 0
        )

    def get_progress(self) -> dict[str, Any]:
        """Get overall progress metrics."""
        elapsed = time.time() - self._state.started_at
        token_pct = self._state.total_tokens_used / max(1, self._config.max_tokens_total) * 100
        iter_pct = self._state.current_iteration / max(1, self._config.max_iterations) * 100
        time_pct = elapsed / max(1, self._config.max_time_s) * 100

        return {
            "iteration_pct": round(iter_pct, 1),
            "token_pct": round(token_pct, 1),
            "time_pct": round(time_pct, 1),
            "findings_per_iteration": round(
                self._state.total_findings / max(1, self._state.current_iteration), 2,
            ),
            "tokens_per_finding": (
                round(self._state.total_tokens_used / max(1, self._state.total_findings), 0)
                if self._state.total_findings > 0 else 0
            ),
        }

    def get_stats(self) -> dict[str, Any]:
        return {
            "state": self._state.to_dict(),
            "progress": self.get_progress(),
            "config": self._config.to_dict(),
        }
