"""Error recovery engine — automatic failure detection and recovery strategies.

Implements:
1. Error classification (transient, permanent, resource, logic)
2. Automatic retry with backoff
3. Fallback strategy selection
4. Circuit breaker pattern
5. Error pattern learning
6. Recovery action suggestion
7. Error budget tracking
8. Cascading failure prevention
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ErrorCategory(str, Enum):
    TRANSIENT = "transient"       # Network timeout, temp failure
    PERMANENT = "permanent"       # Invalid config, missing capability
    RESOURCE = "resource"         # Out of tokens, memory, time
    LOGIC = "logic"               # Bug in reasoning, wrong approach
    EXTERNAL = "external"         # Tool failure, model down
    SAFETY = "safety"             # Safety filter blocked action


class RecoveryAction(str, Enum):
    RETRY = "retry"
    RETRY_WITH_BACKOFF = "retry_with_backoff"
    FALLBACK_MODEL = "fallback_model"
    FALLBACK_TOOL = "fallback_tool"
    SKIP = "skip"
    ESCALATE = "escalate"
    ABORT = "abort"
    REDUCE_SCOPE = "reduce_scope"
    INCREASE_BUDGET = "increase_budget"


class CircuitState(str, Enum):
    CLOSED = "closed"              # Normal operation
    OPEN = "open"                  # Failing, reject requests
    HALF_OPEN = "half_open"        # Testing if recovered


@dataclass
class ErrorRecord:
    """A recorded error."""
    error_id: str = ""
    category: ErrorCategory = ErrorCategory.TRANSIENT
    message: str = ""
    agent_id: str = ""
    tool: str = ""
    model: str = ""
    recovery_action: RecoveryAction = RecoveryAction.RETRY
    recovered: bool = False
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.error_id,
            "category": self.category.value,
            "message": self.message[:60],
            "action": self.recovery_action.value,
            "recovered": self.recovered,
        }


@dataclass
class CircuitBreaker:
    """Circuit breaker for a specific resource."""
    resource_id: str = ""
    state: CircuitState = CircuitState.CLOSED
    failure_count: int = 0
    success_count: int = 0
    failure_threshold: int = 5
    recovery_timeout_s: float = 60.0
    last_failure: float = 0.0
    last_success: float = 0.0
    half_open_attempts: int = 0

    @property
    def should_allow(self) -> bool:
        if self.state == CircuitState.CLOSED:
            return True
        if self.state == CircuitState.OPEN:
            if time.time() - self.last_failure > self.recovery_timeout_s:
                self.state = CircuitState.HALF_OPEN
                self.half_open_attempts = 0
                return True
            return False
        # Half-open: allow one request
        return self.half_open_attempts < 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource": self.resource_id[:20],
            "state": self.state.value,
            "failures": self.failure_count,
            "allow": self.should_allow,
        }


# ── Error Classification Rules ────────────────────────────────

ERROR_CLASSIFICATION_RULES: list[dict[str, Any]] = [
    {"patterns": ["timeout", "timed out", "deadline exceeded"], "category": "transient"},
    {"patterns": ["connection refused", "connection reset"], "category": "transient"},
    {"patterns": ["rate limit", "429", "too many requests"], "category": "transient"},
    {"patterns": ["500", "502", "503", "504"], "category": "transient"},
    {"patterns": ["out of memory", "oom", "memory error"], "category": "resource"},
    {"patterns": ["token limit", "context length", "max tokens"], "category": "resource"},
    {"patterns": ["budget exceeded", "quota exceeded"], "category": "resource"},
    {"patterns": ["not found", "404", "no such file"], "category": "permanent"},
    {"patterns": ["permission denied", "unauthorized", "403"], "category": "permanent"},
    {"patterns": ["invalid", "malformed", "parse error"], "category": "logic"},
    {"patterns": ["safety", "blocked", "harmful", "unsafe"], "category": "safety"},
    {"patterns": ["model unavailable", "server down"], "category": "external"},
]

# ── Recovery Strategies ───────────────────────────────────────

RECOVERY_STRATEGIES: dict[str, list[RecoveryAction]] = {
    "transient": [
        RecoveryAction.RETRY_WITH_BACKOFF,
        RecoveryAction.FALLBACK_MODEL,
        RecoveryAction.SKIP,
    ],
    "permanent": [
        RecoveryAction.SKIP,
        RecoveryAction.ESCALATE,
    ],
    "resource": [
        RecoveryAction.REDUCE_SCOPE,
        RecoveryAction.FALLBACK_MODEL,
        RecoveryAction.ABORT,
    ],
    "logic": [
        RecoveryAction.RETRY,
        RecoveryAction.FALLBACK_MODEL,
        RecoveryAction.ESCALATE,
    ],
    "external": [
        RecoveryAction.FALLBACK_TOOL,
        RecoveryAction.RETRY_WITH_BACKOFF,
        RecoveryAction.SKIP,
    ],
    "safety": [
        RecoveryAction.SKIP,
        RecoveryAction.REDUCE_SCOPE,
    ],
}

# ── Model Fallback Chain ──────────────────────────────────────

MODEL_FALLBACK_CHAIN: dict[str, list[str]] = {
    "whiterabbitneo-7b": ["dolphin-8b", "hermes-14b", "llama-8b"],
    "qwen-coder-14b": ["qwen-coder-7b", "codellama-13b", "codellama-7b"],
    "deepseek-r1-7b": ["hermes-14b", "deepseek-math-7b", "mistral-7b"],
    "hermes-14b": ["llama-8b", "mistral-7b", "dolphin-8b"],
    "llama-8b": ["mistral-7b", "dolphin-8b", "phi-3.5-mini"],
    "dolphin-8b": ["llama-8b", "mistral-7b"],
    "mistral-7b": ["llama-8b", "phi-3.5-mini"],
}


class ErrorRecovery:
    """Automatic failure detection and recovery strategies.

    Classifies errors, selects recovery actions,
    manages circuit breakers, and learns from error patterns.
    """

    def __init__(
        self,
        max_retries: int = 3,
        error_budget: int = 100,
    ) -> None:
        self._errors: list[ErrorRecord] = []
        self._circuit_breakers: dict[str, CircuitBreaker] = {}
        self._error_counter = 0
        self._max_retries = max_retries
        self._error_budget = error_budget
        self._errors_spent = 0
        self._pattern_counts: dict[str, int] = defaultdict(int)
        self._log = logger.bind(component="error_recovery")

    def handle_error(
        self,
        error_message: str,
        agent_id: str = "",
        tool: str = "",
        model: str = "",
    ) -> RecoveryAction:
        """Handle an error and return the recommended recovery action."""
        self._error_counter += 1
        self._errors_spent += 1

        # Classify
        category = self._classify(error_message)

        # Get circuit breaker state
        resource_id = tool or model or agent_id
        cb = self._get_circuit_breaker(resource_id)
        self._record_failure(cb)

        # Check if circuit is open
        if not cb.should_allow:
            action = RecoveryAction.FALLBACK_MODEL if model else RecoveryAction.FALLBACK_TOOL
        else:
            # Select recovery action
            actions = RECOVERY_STRATEGIES.get(category.value, [RecoveryAction.RETRY])
            action = actions[0] if actions else RecoveryAction.RETRY

        # Check error budget
        if self._errors_spent >= self._error_budget:
            action = RecoveryAction.ABORT

        # Record
        record = ErrorRecord(
            error_id=f"err-{self._error_counter}",
            category=category,
            message=error_message[:200],
            agent_id=agent_id,
            tool=tool,
            model=model,
            recovery_action=action,
        )
        self._errors.append(record)
        self._pattern_counts[category.value] += 1

        if len(self._errors) > 1000:
            self._errors = self._errors[-1000:]

        return action

    def record_recovery(self, error_id: str) -> None:
        """Record that an error was recovered."""
        for err in reversed(self._errors):
            if err.error_id == error_id:
                err.recovered = True
                break

    def record_success(self, resource_id: str) -> None:
        """Record a successful operation."""
        cb = self._get_circuit_breaker(resource_id)
        cb.success_count += 1
        cb.last_success = time.time()

        if cb.state == CircuitState.HALF_OPEN:
            cb.state = CircuitState.CLOSED
            cb.failure_count = 0

    def get_fallback_model(self, failed_model: str) -> str:
        """Get a fallback model."""
        chain = MODEL_FALLBACK_CHAIN.get(failed_model, [])
        for model in chain:
            cb = self._circuit_breakers.get(model)
            if not cb or cb.should_allow:
                return model
        return "mistral-7b"  # Ultimate fallback

    def _classify(self, message: str) -> ErrorCategory:
        """Classify an error message."""
        message_lower = message.lower()

        for rule in ERROR_CLASSIFICATION_RULES:
            for pattern in rule["patterns"]:
                if pattern in message_lower:
                    return ErrorCategory(rule["category"])

        return ErrorCategory.LOGIC  # Default

    def _get_circuit_breaker(self, resource_id: str) -> CircuitBreaker:
        """Get or create a circuit breaker."""
        if resource_id not in self._circuit_breakers:
            self._circuit_breakers[resource_id] = CircuitBreaker(
                resource_id=resource_id,
            )
        return self._circuit_breakers[resource_id]

    def _record_failure(self, cb: CircuitBreaker) -> None:
        """Record a failure on a circuit breaker."""
        cb.failure_count += 1
        cb.last_failure = time.time()

        if cb.state == CircuitState.HALF_OPEN:
            cb.state = CircuitState.OPEN
            cb.half_open_attempts += 1

        if cb.failure_count >= cb.failure_threshold and cb.state == CircuitState.CLOSED:
            cb.state = CircuitState.OPEN

    def get_health_report(self) -> dict[str, Any]:
        """Get error health report."""
        recent = self._errors[-10:] if self._errors else []
        open_circuits = [
            cb.to_dict() for cb in self._circuit_breakers.values()
            if cb.state != CircuitState.CLOSED
        ]

        return {
            "recent_errors": [e.to_dict() for e in recent],
            "open_circuits": open_circuits,
            "budget_remaining": self._error_budget - self._errors_spent,
        }

    def get_stats(self) -> dict[str, Any]:
        recovered = sum(1 for e in self._errors if e.recovered)
        return {
            "total_errors": self._error_counter,
            "recovered": recovered,
            "budget_remaining": self._error_budget - self._errors_spent,
            "patterns": dict(self._pattern_counts),
            "circuit_breakers": len(self._circuit_breakers),
        }
