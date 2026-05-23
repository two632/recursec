"""Autonomous loop controller — main agent execution loop.

Implements:
1. Observe-Orient-Decide-Act (OODA) loop
2. Phase-based execution controller
3. Convergence-aware loop termination
4. Budget enforcement per iteration
5. Dynamic strategy selection
6. Self-reflection between iterations
7. Graceful degradation on failures
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class LoopPhase(str, Enum):
    OBSERVE = "observe"       # Gather information
    ORIENT = "orient"         # Analyze situation
    DECIDE = "decide"         # Choose action
    ACT = "act"              # Execute action
    REFLECT = "reflect"      # Self-evaluate


class LoopState(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    CONVERGED = "converged"
    BUDGET_EXHAUSTED = "budget_exhausted"
    ERROR = "error"
    COMPLETED = "completed"


class StopReason(str, Enum):
    CONVERGENCE = "convergence"
    BUDGET = "budget"
    TIME = "time"
    USER = "user"
    ERROR = "error"
    MAX_ITERATIONS = "max_iterations"


@dataclass
class LoopIteration:
    """A single iteration of the OODA loop."""
    iteration_id: int = 0
    phase: LoopPhase = LoopPhase.OBSERVE
    strategy_used: str = ""
    tool_used: str = ""
    findings_this_iter: int = 0
    tokens_used: int = 0
    duration_s: float = 0.0
    confidence: float = 0.5
    reflection: str = ""
    error: str = ""
    started_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "iter": self.iteration_id,
            "phase": self.phase.value,
            "strategy": self.strategy_used[:15],
            "findings": self.findings_this_iter,
            "tokens": self.tokens_used,
        }


@dataclass
class LoopConfig:
    """Configuration for the autonomous loop."""
    max_iterations: int = 100
    token_budget: int = 500000
    time_budget_s: float = 14400.0    # 4 hours
    convergence_window: int = 5       # No new findings in N iters
    min_confidence: float = 0.3
    reflection_interval: int = 5      # Reflect every N iterations
    strategy_switch_threshold: int = 3  # Switch after N unproductive iters

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_iters": self.max_iterations,
            "token_budget": self.token_budget,
            "time_budget_s": self.time_budget_s,
            "convergence_window": self.convergence_window,
        }


@dataclass
class LoopStatus:
    """Current status of the autonomous loop."""
    state: LoopState = LoopState.IDLE
    current_iteration: int = 0
    total_findings: int = 0
    total_tokens: int = 0
    started_at: float = 0.0
    elapsed_s: float = 0.0
    current_strategy: str = ""
    consecutive_empty: int = 0    # Iterations with no findings
    stop_reason: StopReason | None = None

    @property
    def findings_per_iteration(self) -> float:
        if self.current_iteration == 0:
            return 0.0
        return self.total_findings / self.current_iteration

    @property
    def tokens_per_finding(self) -> float:
        if self.total_findings == 0:
            return float('inf')
        return self.total_tokens / self.total_findings

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "iteration": self.current_iteration,
            "findings": self.total_findings,
            "tokens": self.total_tokens,
            "elapsed_s": round(self.elapsed_s, 1),
            "f_per_iter": round(self.findings_per_iteration, 2),
            "empty_streak": self.consecutive_empty,
        }


# ── Strategy pool ────────────────────────────────────────────

STRATEGY_POOL: list[dict[str, Any]] = [
    {"name": "passive_recon", "phase": "recon", "tools": ["subfinder", "httpx", "dig"]},
    {"name": "active_recon", "phase": "recon", "tools": ["nmap", "masscan"]},
    {"name": "web_vuln_scan", "phase": "scanning", "tools": ["nuclei", "nikto"]},
    {"name": "dir_discovery", "phase": "scanning", "tools": ["ffuf", "gobuster"]},
    {"name": "sqli_testing", "phase": "exploitation", "tools": ["sqlmap"]},
    {"name": "ssl_assessment", "phase": "scanning", "tools": ["testssl"]},
    {"name": "auth_testing", "phase": "exploitation", "tools": ["hydra"]},
    {"name": "code_audit", "phase": "analysis", "tools": ["semgrep", "bandit"]},
    {"name": "api_testing", "phase": "exploitation", "tools": ["ffuf", "nuclei"]},
    {"name": "manual_analysis", "phase": "analysis", "tools": []},
]


class AutonomousLoopController:
    """Controls the main autonomous execution loop.

    Implements OODA (Observe-Orient-Decide-Act) with
    convergence detection, budget enforcement,
    dynamic strategy selection, and self-reflection.
    """

    def __init__(self, config: LoopConfig | None = None) -> None:
        self._config = config or LoopConfig()
        self._status = LoopStatus()
        self._iterations: list[LoopIteration] = []
        self._strategies_tried: dict[str, int] = {}
        self._strategy_idx = 0
        self._log = logger.bind(component="autonomous_loop")

    def start(self) -> LoopStatus:
        """Initialize the loop."""
        self._status.state = LoopState.RUNNING
        self._status.started_at = time.time()
        self._status.current_strategy = STRATEGY_POOL[0]["name"]
        return self._status

    def should_continue(self) -> bool:
        """Check if the loop should continue."""
        if self._status.state != LoopState.RUNNING:
            return False

        # Max iterations
        if self._status.current_iteration >= self._config.max_iterations:
            self._stop(StopReason.MAX_ITERATIONS)
            return False

        # Token budget
        if self._status.total_tokens >= self._config.token_budget:
            self._stop(StopReason.BUDGET)
            return False

        # Time budget
        elapsed = time.time() - self._status.started_at
        if elapsed >= self._config.time_budget_s:
            self._stop(StopReason.TIME)
            return False

        # Convergence
        if self._status.consecutive_empty >= self._config.convergence_window:
            # Try switching strategy before giving up
            if not self._switch_strategy():
                self._stop(StopReason.CONVERGENCE)
                return False
            self._status.consecutive_empty = 0

        return True

    def begin_iteration(self) -> LoopIteration:
        """Start a new iteration."""
        self._status.current_iteration += 1
        iteration = LoopIteration(
            iteration_id=self._status.current_iteration,
            strategy_used=self._status.current_strategy,
        )
        return iteration

    def end_iteration(self, iteration: LoopIteration) -> None:
        """End an iteration and update status."""
        iteration.duration_s = time.time() - iteration.started_at
        self._iterations.append(iteration)

        self._status.total_findings += iteration.findings_this_iter
        self._status.total_tokens += iteration.tokens_used
        self._status.elapsed_s = time.time() - self._status.started_at

        if iteration.findings_this_iter > 0:
            self._status.consecutive_empty = 0
        else:
            self._status.consecutive_empty += 1

        # Track strategy usage
        strategy = iteration.strategy_used
        self._strategies_tried[strategy] = self._strategies_tried.get(strategy, 0) + 1

        # Check if strategy is exhausted
        if self._strategies_tried.get(strategy, 0) >= self._config.strategy_switch_threshold:
            if self._status.consecutive_empty >= 2:
                self._switch_strategy()

    def should_reflect(self) -> bool:
        """Check if it's time for self-reflection."""
        return (
            self._status.current_iteration > 0
            and self._status.current_iteration % self._config.reflection_interval == 0
        )

    def get_next_strategy(self) -> dict[str, Any]:
        """Get the current strategy details."""
        for s in STRATEGY_POOL:
            if s["name"] == self._status.current_strategy:
                return s
        return STRATEGY_POOL[0]

    def build_loop_prompt(self) -> str:
        """Build loop status context for LLM."""
        s = self._status
        lines = [
            "## Autonomous Loop Status\n",
            f"State: {s.state.value}",
            f"Iteration: {s.current_iteration}/{self._config.max_iterations}",
            f"Findings: {s.total_findings} ({s.findings_per_iteration:.1f}/iter)",
            f"Tokens: {s.total_tokens}/{self._config.token_budget}",
            f"Time: {s.elapsed_s:.0f}s/{self._config.time_budget_s:.0f}s",
            f"Strategy: {s.current_strategy}",
            f"Empty streak: {s.consecutive_empty}/{self._config.convergence_window}",
        ]

        if self.should_reflect():
            lines.append("\n** Time to reflect on progress and adjust strategy **")

        if s.consecutive_empty >= 2:
            lines.append(f"\nWARNING: No new findings for {s.consecutive_empty} iterations")
            lines.append("Consider switching strategy or deepening current approach")

        return "\n".join(lines)

    def _switch_strategy(self) -> bool:
        """Switch to next untried or least-tried strategy."""
        sorted_strategies = sorted(
            STRATEGY_POOL,
            key=lambda s: self._strategies_tried.get(s["name"], 0),
        )

        for s in sorted_strategies:
            if s["name"] != self._status.current_strategy:
                count = self._strategies_tried.get(s["name"], 0)
                if count < self._config.strategy_switch_threshold:
                    self._status.current_strategy = s["name"]
                    self._log.info(
                        "strategy_switch",
                        new_strategy=s["name"],
                        prev_uses=count,
                    )
                    return True
        return False

    def _stop(self, reason: StopReason) -> None:
        """Stop the loop."""
        self._status.state = LoopState.COMPLETED
        self._status.stop_reason = reason
        self._status.elapsed_s = time.time() - self._status.started_at

    def get_stats(self) -> dict[str, Any]:
        return {
            "iterations": self._status.current_iteration,
            "findings": self._status.total_findings,
            "tokens": self._status.total_tokens,
            "strategies_tried": dict(self._strategies_tried),
            "stop_reason": self._status.stop_reason.value if self._status.stop_reason else None,
        }
