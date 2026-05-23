"""Autonomous loop — the core OODA (Observe-Orient-Decide-Act) execution loop.

Implements:
1. OODA loop cycle management
2. Observe phase (gather data from tools/models)
3. Orient phase (analyze and contextualize)
4. Decide phase (select next action)
5. Act phase (execute action)
6. Loop termination conditions
7. Phase timing and metrics
8. Fallback and recovery within loop
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Awaitable

import structlog

logger = structlog.get_logger()


class LoopPhase(str, Enum):
    OBSERVE = "observe"
    ORIENT = "orient"
    DECIDE = "decide"
    ACT = "act"
    REVIEW = "review"


class LoopStatus(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"


class StopReason(str, Enum):
    GOAL_ACHIEVED = "goal_achieved"
    BUDGET_EXHAUSTED = "budget_exhausted"
    CONVERGED = "converged"
    MAX_CYCLES = "max_cycles"
    USER_STOP = "user_stop"
    ERROR = "error"
    TIMEOUT = "timeout"


@dataclass
class LoopCycle:
    """Record of a single OODA cycle."""
    cycle_number: int = 0
    started_at: float = 0.0
    completed_at: float = 0.0
    phase_durations: dict[str, float] = field(default_factory=dict)
    observations: list[str] = field(default_factory=list)
    orientation: str = ""
    decision: str = ""
    action_taken: str = ""
    action_result: str = ""
    tokens_used: int = 0
    findings_this_cycle: int = 0
    error: str = ""

    @property
    def duration_s(self) -> float:
        end = self.completed_at or time.time()
        return end - self.started_at if self.started_at > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "cycle": self.cycle_number,
            "duration": round(self.duration_s, 1),
            "action": self.action_taken[:30],
            "findings": self.findings_this_cycle,
            "tokens": self.tokens_used,
        }


@dataclass
class LoopConfig:
    """Configuration for the autonomous loop."""
    max_cycles: int = 100
    max_tokens: int = 100000
    max_duration_s: int = 3600
    min_progress_per_cycle: float = 0.01
    stagnation_threshold: int = 5     # Cycles without progress before changing strategy
    observe_timeout_s: int = 120
    act_timeout_s: int = 300

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_cycles": self.max_cycles,
            "max_tokens": self.max_tokens,
            "max_duration": self.max_duration_s,
        }


@dataclass
class LoopState:
    """Current state of the loop."""
    status: LoopStatus = LoopStatus.IDLE
    current_phase: LoopPhase = LoopPhase.OBSERVE
    cycle_count: int = 0
    total_tokens: int = 0
    total_findings: int = 0
    started_at: float = 0.0
    stagnation_counter: int = 0
    last_progress_cycle: int = 0
    stop_reason: StopReason | None = None
    current_strategy: str = ""
    current_target: str = ""

    @property
    def elapsed_s(self) -> float:
        return time.time() - self.started_at if self.started_at > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "phase": self.current_phase.value,
            "cycles": self.cycle_count,
            "tokens": self.total_tokens,
            "findings": self.total_findings,
            "elapsed_m": round(self.elapsed_s / 60, 1),
            "stagnation": self.stagnation_counter,
        }


class AutonomousLoop:
    """The core OODA execution loop for autonomous operation.

    Runs observe-orient-decide-act cycles continuously,
    with termination conditions and recovery.
    """

    def __init__(
        self,
        config: LoopConfig | None = None,
    ) -> None:
        self._config = config or LoopConfig()
        self._state = LoopState()
        self._cycles: list[LoopCycle] = []
        self._observers: list[Callable[..., Awaitable[list[str]]]] = []
        self._orienters: list[Callable[..., Awaitable[str]]] = []
        self._deciders: list[Callable[..., Awaitable[str]]] = []
        self._actors: list[Callable[..., Awaitable[dict[str, Any]]]] = []
        self._log = logger.bind(component="autonomous_loop")

    def register_observer(self, fn: Callable[..., Awaitable[list[str]]]) -> None:
        self._observers.append(fn)

    def register_orienter(self, fn: Callable[..., Awaitable[str]]) -> None:
        self._orienters.append(fn)

    def register_decider(self, fn: Callable[..., Awaitable[str]]) -> None:
        self._deciders.append(fn)

    def register_actor(self, fn: Callable[..., Awaitable[dict[str, Any]]]) -> None:
        self._actors.append(fn)

    async def run(
        self,
        target: str = "",
        strategy: str = "",
    ) -> LoopState:
        """Run the autonomous OODA loop."""
        self._state.status = LoopStatus.RUNNING
        self._state.started_at = time.time()
        self._state.current_target = target
        self._state.current_strategy = strategy

        try:
            while self._should_continue():
                cycle = await self._execute_cycle()
                self._cycles.append(cycle)

                if cycle.error:
                    self._state.stagnation_counter += 1
                elif cycle.findings_this_cycle > 0:
                    self._state.stagnation_counter = 0
                    self._state.last_progress_cycle = self._state.cycle_count
                else:
                    self._state.stagnation_counter += 1

                # Stagnation handling
                if self._state.stagnation_counter >= self._config.stagnation_threshold:
                    self._state.current_strategy = "diversify"
                    self._state.stagnation_counter = 0

            if not self._state.stop_reason:
                self._state.stop_reason = StopReason.CONVERGED
            self._state.status = LoopStatus.COMPLETED

        except Exception as exc:
            self._state.status = LoopStatus.FAILED
            self._state.stop_reason = StopReason.ERROR
            self._log.error("loop_error", error=str(exc))

        return self._state

    def _should_continue(self) -> bool:
        """Check if the loop should continue."""
        if self._state.status != LoopStatus.RUNNING:
            return False

        if self._state.cycle_count >= self._config.max_cycles:
            self._state.stop_reason = StopReason.MAX_CYCLES
            return False

        if self._state.total_tokens >= self._config.max_tokens:
            self._state.stop_reason = StopReason.BUDGET_EXHAUSTED
            return False

        if self._state.elapsed_s >= self._config.max_duration_s:
            self._state.stop_reason = StopReason.TIMEOUT
            return False

        return True

    async def _execute_cycle(self) -> LoopCycle:
        """Execute a single OODA cycle."""
        self._state.cycle_count += 1
        cycle = LoopCycle(
            cycle_number=self._state.cycle_count,
            started_at=time.time(),
        )

        try:
            # OBSERVE
            phase_start = time.time()
            self._state.current_phase = LoopPhase.OBSERVE
            observations = await self._observe()
            cycle.observations = observations
            cycle.phase_durations["observe"] = time.time() - phase_start

            # ORIENT
            phase_start = time.time()
            self._state.current_phase = LoopPhase.ORIENT
            orientation = await self._orient(observations)
            cycle.orientation = orientation
            cycle.phase_durations["orient"] = time.time() - phase_start

            # DECIDE
            phase_start = time.time()
            self._state.current_phase = LoopPhase.DECIDE
            decision = await self._decide(orientation)
            cycle.decision = decision
            cycle.phase_durations["decide"] = time.time() - phase_start

            # ACT
            phase_start = time.time()
            self._state.current_phase = LoopPhase.ACT
            result = await self._act(decision)
            cycle.action_taken = decision
            cycle.action_result = str(result)[:200]
            cycle.tokens_used = result.get("tokens", 0)
            cycle.findings_this_cycle = result.get("findings", 0)
            cycle.phase_durations["act"] = time.time() - phase_start

            self._state.total_tokens += cycle.tokens_used
            self._state.total_findings += cycle.findings_this_cycle

        except Exception as exc:
            cycle.error = str(exc)[:200]

        cycle.completed_at = time.time()
        return cycle

    async def _observe(self) -> list[str]:
        """Gather observations from all registered observers."""
        observations = []
        for observer in self._observers:
            try:
                result = await asyncio.wait_for(
                    observer(),
                    timeout=self._config.observe_timeout_s,
                )
                observations.extend(result)
            except (asyncio.TimeoutError, Exception):
                pass
        return observations

    async def _orient(self, observations: list[str]) -> str:
        """Analyze and contextualize observations."""
        for orienter in self._orienters:
            try:
                return await orienter(observations)
            except Exception:
                pass
        return "; ".join(observations[:5])

    async def _decide(self, orientation: str) -> str:
        """Decide on next action."""
        for decider in self._deciders:
            try:
                return await decider(orientation, self._state.current_strategy)
            except Exception:
                pass
        return "continue_scanning"

    async def _act(self, decision: str) -> dict[str, Any]:
        """Execute the decided action."""
        for actor in self._actors:
            try:
                return await asyncio.wait_for(
                    actor(decision, self._state.current_target),
                    timeout=self._config.act_timeout_s,
                )
            except (asyncio.TimeoutError, Exception):
                pass
        return {"tokens": 0, "findings": 0}

    def stop(self, reason: StopReason = StopReason.USER_STOP) -> None:
        """Stop the loop."""
        self._state.status = LoopStatus.STOPPED
        self._state.stop_reason = reason

    def pause(self) -> None:
        self._state.status = LoopStatus.PAUSED

    def resume(self) -> None:
        self._state.status = LoopStatus.RUNNING

    def get_stats(self) -> dict[str, Any]:
        return {
            "state": self._state.to_dict(),
            "cycles": len(self._cycles),
            "config": self._config.to_dict(),
        }
