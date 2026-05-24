"""Agent error recovery — self-healing for agent failures.

Implements:
1. Error categorization (transient/permanent/resource)
2. Retry strategies (exponential backoff, circuit breaker)
3. Fallback chains (alternative models/tools)
4. Error pattern detection (recurring failures)
5. Recovery action selection
6. Error context prompt for LLM
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ErrorCategory(str, Enum):
    TRANSIENT = "transient"       # Timeout, rate limit → retry
    PERMANENT = "permanent"       # Invalid input, auth failure → skip/fallback
    RESOURCE = "resource"         # OOM, disk full → reduce scope
    MODEL = "model"               # LLM error, hallucination → switch model
    TOOL = "tool"                 # Tool crash, timeout → alternative tool
    NETWORK = "network"           # Connection error → retry with backoff
    LOGIC = "logic"               # Agent stuck in loop → replan


class RetryStrategy(str, Enum):
    IMMEDIATE = "immediate"
    LINEAR_BACKOFF = "linear_backoff"
    EXPONENTIAL_BACKOFF = "exponential_backoff"
    CIRCUIT_BREAKER = "circuit_breaker"
    NO_RETRY = "no_retry"


class RecoveryAction(str, Enum):
    RETRY = "retry"
    SWITCH_MODEL = "switch_model"
    SWITCH_TOOL = "switch_tool"
    REDUCE_SCOPE = "reduce_scope"
    REPLAN = "replan"
    SKIP = "skip"
    ESCALATE = "escalate"


# Map error category to recovery actions
RECOVERY_MAP: dict[ErrorCategory, list[RecoveryAction]] = {
    ErrorCategory.TRANSIENT: [RecoveryAction.RETRY],
    ErrorCategory.PERMANENT: [RecoveryAction.SKIP, RecoveryAction.ESCALATE],
    ErrorCategory.RESOURCE: [RecoveryAction.REDUCE_SCOPE, RecoveryAction.RETRY],
    ErrorCategory.MODEL: [RecoveryAction.SWITCH_MODEL, RecoveryAction.RETRY],
    ErrorCategory.TOOL: [RecoveryAction.SWITCH_TOOL, RecoveryAction.SKIP],
    ErrorCategory.NETWORK: [RecoveryAction.RETRY],
    ErrorCategory.LOGIC: [RecoveryAction.REPLAN, RecoveryAction.SKIP],
}

# Error patterns for categorization
ERROR_PATTERNS: dict[str, ErrorCategory] = {
    "timeout": ErrorCategory.TRANSIENT,
    "rate_limit": ErrorCategory.TRANSIENT,
    "429": ErrorCategory.TRANSIENT,
    "connection_refused": ErrorCategory.NETWORK,
    "dns_resolution": ErrorCategory.NETWORK,
    "connection_reset": ErrorCategory.NETWORK,
    "out_of_memory": ErrorCategory.RESOURCE,
    "oom": ErrorCategory.RESOURCE,
    "disk_full": ErrorCategory.RESOURCE,
    "context_length_exceeded": ErrorCategory.RESOURCE,
    "auth_failure": ErrorCategory.PERMANENT,
    "403": ErrorCategory.PERMANENT,
    "401": ErrorCategory.PERMANENT,
    "invalid_input": ErrorCategory.PERMANENT,
    "hallucination": ErrorCategory.MODEL,
    "empty_response": ErrorCategory.MODEL,
    "malformed_json": ErrorCategory.MODEL,
    "tool_not_found": ErrorCategory.TOOL,
    "tool_crash": ErrorCategory.TOOL,
    "tool_timeout": ErrorCategory.TOOL,
    "infinite_loop": ErrorCategory.LOGIC,
    "no_progress": ErrorCategory.LOGIC,
}


@dataclass
class AgentError:
    """A recorded agent error."""
    error_id: str = ""
    agent_id: str = ""
    category: ErrorCategory = ErrorCategory.TRANSIENT
    message: str = ""
    action_taken: str = ""
    retry_count: int = 0
    resolved: bool = False
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.error_id[:8],
            "cat": self.category.value[:6],
            "msg": self.message[:20],
            "resolved": self.resolved,
        }


@dataclass
class CircuitState:
    """Circuit breaker state for a resource."""
    resource_id: str = ""
    failures: int = 0
    last_failure: float = 0.0
    open: bool = False       # True = circuit is open (blocking)
    half_open_at: float = 0.0

    @property
    def should_allow(self) -> bool:
        if not self.open:
            return True
        if time.time() >= self.half_open_at:
            return True  # Half-open: allow one attempt
        return False


class AgentErrorRecovery:
    """Self-healing error recovery for agents.

    Categorizes errors, selects recovery strategies,
    manages circuit breakers, and tracks error patterns.
    """

    def __init__(
        self,
        max_retries: int = 3,
        circuit_threshold: int = 5,
        circuit_timeout_s: float = 60.0,
    ) -> None:
        self._errors: list[AgentError] = []
        self._error_counter = 0
        self._max_retries = max_retries
        self._circuit_threshold = circuit_threshold
        self._circuit_timeout = circuit_timeout_s
        self._circuits: dict[str, CircuitState] = {}
        self._retry_counts: dict[str, int] = {}
        self._log = logger.bind(component="error_recovery")

    def categorize_error(self, message: str) -> ErrorCategory:
        """Categorize an error from its message."""
        lower = message.lower()
        for pattern, category in ERROR_PATTERNS.items():
            if pattern in lower:
                return category
        return ErrorCategory.TRANSIENT

    def handle_error(
        self,
        agent_id: str,
        error_message: str,
        resource_id: str = "",
    ) -> RecoveryAction:
        """Handle an error and return the recovery action."""
        self._error_counter += 1
        category = self.categorize_error(error_message)

        # Track retry count
        retry_key = f"{agent_id}:{resource_id}"
        self._retry_counts[retry_key] = self._retry_counts.get(retry_key, 0) + 1
        retry_count = self._retry_counts[retry_key]

        # Select recovery action
        action = self._select_action(category, retry_count, resource_id)

        error = AgentError(
            error_id=f"err-{self._error_counter}",
            agent_id=agent_id,
            category=category,
            message=error_message,
            action_taken=action.value,
            retry_count=retry_count,
        )
        self._errors.append(error)

        # Update circuit breaker
        if resource_id:
            self._update_circuit(resource_id)

        return action

    def _select_action(
        self,
        category: ErrorCategory,
        retry_count: int,
        resource_id: str = "",
    ) -> RecoveryAction:
        """Select best recovery action."""
        # Check circuit breaker
        if resource_id and resource_id in self._circuits:
            circuit = self._circuits[resource_id]
            if circuit.open and not circuit.should_allow:
                return RecoveryAction.SWITCH_MODEL if category == ErrorCategory.MODEL else RecoveryAction.SKIP

        # Max retries exceeded
        if retry_count >= self._max_retries:
            possible = RECOVERY_MAP.get(category, [RecoveryAction.SKIP])
            non_retry = [a for a in possible if a != RecoveryAction.RETRY]
            return non_retry[0] if non_retry else RecoveryAction.ESCALATE

        possible = RECOVERY_MAP.get(category, [RecoveryAction.RETRY])
        return possible[0]

    def _update_circuit(self, resource_id: str) -> None:
        """Update circuit breaker state."""
        if resource_id not in self._circuits:
            self._circuits[resource_id] = CircuitState(resource_id=resource_id)

        circuit = self._circuits[resource_id]
        circuit.failures += 1
        circuit.last_failure = time.time()

        if circuit.failures >= self._circuit_threshold:
            circuit.open = True
            circuit.half_open_at = time.time() + self._circuit_timeout

    def reset_circuit(self, resource_id: str) -> None:
        """Reset circuit breaker after success."""
        if resource_id in self._circuits:
            self._circuits[resource_id].failures = 0
            self._circuits[resource_id].open = False

    def get_backoff_seconds(self, retry_count: int, strategy: RetryStrategy = RetryStrategy.EXPONENTIAL_BACKOFF) -> float:
        """Calculate backoff delay."""
        if strategy == RetryStrategy.IMMEDIATE:
            return 0.0
        if strategy == RetryStrategy.LINEAR_BACKOFF:
            return retry_count * 2.0
        if strategy == RetryStrategy.EXPONENTIAL_BACKOFF:
            return min(60.0, 2.0 ** retry_count)
        return 0.0

    def get_error_patterns(self, agent_id: str = "") -> dict[str, int]:
        """Get error frequency by category."""
        counts: dict[str, int] = {}
        for err in self._errors:
            if agent_id and err.agent_id != agent_id:
                continue
            key = err.category.value
            counts[key] = counts.get(key, 0) + 1
        return counts

    def build_error_prompt(self, agent_id: str = "") -> str:
        """Build error context for LLM."""
        lines = ["## Error Recovery\n"]

        recent = [
            e for e in self._errors[-10:]
            if not agent_id or e.agent_id == agent_id
        ]

        if not recent:
            lines.append("No recent errors.")
            return "\n".join(lines)

        lines.append(f"Recent errors ({len(recent)}):")
        for err in recent:
            lines.append(
                f"  [{err.category.value[:6]}] {err.message[:25]} → {err.action_taken}"
            )

        # Patterns
        patterns = self.get_error_patterns(agent_id)
        if patterns:
            lines.append("\nPatterns:")
            for cat, count in sorted(patterns.items(), key=lambda x: x[1], reverse=True):
                lines.append(f"  {cat}: {count}")

        # Open circuits
        open_circuits = [c for c in self._circuits.values() if c.open]
        if open_circuits:
            lines.append(f"\nOpen circuits: {len(open_circuits)}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_errors": len(self._errors),
            "open_circuits": sum(1 for c in self._circuits.values() if c.open),
            "patterns": self.get_error_patterns(),
        }
