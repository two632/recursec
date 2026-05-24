"""Self-healing module — automatic error recovery.

Implements:
1. Error categorization and classification
2. Recovery strategy selection
3. Circuit breaker pattern
4. Retry with backoff
5. Fallback chain execution
6. Self-healing prompt for LLM
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ErrorCategory(str, Enum):
    NETWORK = "network"           # Connectivity issues
    TIMEOUT = "timeout"           # Operation timeout
    AUTH = "auth"                  # Authentication failure
    PERMISSION = "permission"     # Authorization failure
    TOOL_FAILURE = "tool_failure"  # External tool crash
    MODEL_ERROR = "model_error"   # LLM inference error
    PARSE_ERROR = "parse_error"   # Output parsing failure
    RESOURCE = "resource"         # Memory/disk/CPU exhaustion
    VALIDATION = "validation"     # Invalid input/output
    UNKNOWN = "unknown"


class RecoveryAction(str, Enum):
    RETRY = "retry"                   # Simple retry
    RETRY_BACKOFF = "retry_backoff"   # Retry with exponential backoff
    SWITCH_TOOL = "switch_tool"       # Use alternative tool
    SWITCH_MODEL = "switch_model"     # Use alternative LLM
    REDUCE_SCOPE = "reduce_scope"     # Simplify the task
    SKIP = "skip"                     # Skip this step
    ESCALATE = "escalate"             # Escalate to parent agent
    RESTART = "restart"               # Restart from checkpoint


class CircuitState(str, Enum):
    CLOSED = "closed"       # Normal operation
    OPEN = "open"           # Tripped, blocking calls
    HALF_OPEN = "half_open"  # Testing if recovered


@dataclass
class ErrorRecord:
    """A recorded error."""
    error_id: str = ""
    category: ErrorCategory = ErrorCategory.UNKNOWN
    message: str = ""
    source: str = ""
    recovery_attempted: RecoveryAction = RecoveryAction.RETRY
    recovered: bool = False
    attempts: int = 1
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cat": self.category.value[:8],
            "recovered": self.recovered,
            "attempts": self.attempts,
        }


@dataclass
class CircuitBreaker:
    """Circuit breaker for a service."""
    name: str = ""
    state: CircuitState = CircuitState.CLOSED
    failure_count: int = 0
    success_count: int = 0
    failure_threshold: int = 3
    reset_timeout_s: float = 60.0
    last_failure_time: float = 0.0
    half_open_max: int = 1

    def should_allow(self) -> bool:
        """Check if request should be allowed."""
        if self.state == CircuitState.CLOSED:
            return True
        if self.state == CircuitState.OPEN:
            # Check if reset timeout has passed
            if time.time() - self.last_failure_time > self.reset_timeout_s:
                self.state = CircuitState.HALF_OPEN
                return True
            return False
        # Half-open: allow limited requests
        return self.success_count < self.half_open_max

    def record_success(self) -> None:
        """Record a successful call."""
        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.half_open_max:
                self.state = CircuitState.CLOSED
                self.failure_count = 0
                self.success_count = 0
        elif self.state == CircuitState.CLOSED:
            self.failure_count = max(0, self.failure_count - 1)

    def record_failure(self) -> None:
        """Record a failed call."""
        self.failure_count += 1
        self.last_failure_time = time.time()

        if self.state == CircuitState.HALF_OPEN:
            self.state = CircuitState.OPEN
            self.success_count = 0
        elif self.failure_count >= self.failure_threshold:
            self.state = CircuitState.OPEN


# Error category → recovery strategies (in order of preference)
RECOVERY_MAP: dict[ErrorCategory, list[RecoveryAction]] = {
    ErrorCategory.NETWORK: [RecoveryAction.RETRY_BACKOFF, RecoveryAction.SKIP],
    ErrorCategory.TIMEOUT: [RecoveryAction.RETRY_BACKOFF, RecoveryAction.REDUCE_SCOPE, RecoveryAction.SKIP],
    ErrorCategory.AUTH: [RecoveryAction.SKIP, RecoveryAction.ESCALATE],
    ErrorCategory.PERMISSION: [RecoveryAction.SKIP, RecoveryAction.ESCALATE],
    ErrorCategory.TOOL_FAILURE: [RecoveryAction.RETRY, RecoveryAction.SWITCH_TOOL, RecoveryAction.SKIP],
    ErrorCategory.MODEL_ERROR: [RecoveryAction.RETRY, RecoveryAction.SWITCH_MODEL],
    ErrorCategory.PARSE_ERROR: [RecoveryAction.RETRY, RecoveryAction.SWITCH_MODEL, RecoveryAction.SKIP],
    ErrorCategory.RESOURCE: [RecoveryAction.REDUCE_SCOPE, RecoveryAction.SKIP],
    ErrorCategory.VALIDATION: [RecoveryAction.RETRY, RecoveryAction.REDUCE_SCOPE],
    ErrorCategory.UNKNOWN: [RecoveryAction.RETRY, RecoveryAction.SKIP, RecoveryAction.ESCALATE],
}

# Error message patterns → category
ERROR_PATTERNS: list[tuple[str, ErrorCategory]] = [
    ("connection refused", ErrorCategory.NETWORK),
    ("connection reset", ErrorCategory.NETWORK),
    ("dns resolution", ErrorCategory.NETWORK),
    ("no route to host", ErrorCategory.NETWORK),
    ("timed out", ErrorCategory.TIMEOUT),
    ("timeout", ErrorCategory.TIMEOUT),
    ("deadline exceeded", ErrorCategory.TIMEOUT),
    ("401", ErrorCategory.AUTH),
    ("403", ErrorCategory.PERMISSION),
    ("permission denied", ErrorCategory.PERMISSION),
    ("access denied", ErrorCategory.PERMISSION),
    ("command not found", ErrorCategory.TOOL_FAILURE),
    ("segmentation fault", ErrorCategory.TOOL_FAILURE),
    ("core dumped", ErrorCategory.TOOL_FAILURE),
    ("out of memory", ErrorCategory.RESOURCE),
    ("disk full", ErrorCategory.RESOURCE),
    ("no space left", ErrorCategory.RESOURCE),
    ("json decode", ErrorCategory.PARSE_ERROR),
    ("invalid syntax", ErrorCategory.PARSE_ERROR),
    ("unexpected token", ErrorCategory.PARSE_ERROR),
    ("model not found", ErrorCategory.MODEL_ERROR),
    ("inference error", ErrorCategory.MODEL_ERROR),
    ("context length exceeded", ErrorCategory.MODEL_ERROR),
]


class SelfHealingEngine:
    """Automatic error recovery and self-healing.

    Classifies errors, selects recovery strategies,
    implements circuit breakers, and tracks recovery
    effectiveness.
    """

    def __init__(
        self,
        max_retries: int = 3,
        base_backoff_s: float = 1.0,
        max_backoff_s: float = 60.0,
    ) -> None:
        self._errors: list[ErrorRecord] = []
        self._circuits: dict[str, CircuitBreaker] = {}
        self._error_counter = 0
        self._max_retries = max_retries
        self._base_backoff = base_backoff_s
        self._max_backoff = max_backoff_s
        self._recovered_count = 0
        self._log = logger.bind(component="self_healing")

    def classify_error(self, message: str) -> ErrorCategory:
        """Classify an error by its message."""
        lower = message.lower()
        for pattern, category in ERROR_PATTERNS:
            if pattern in lower:
                return category
        return ErrorCategory.UNKNOWN

    def get_recovery_strategy(
        self,
        category: ErrorCategory,
        attempt: int = 1,
    ) -> RecoveryAction:
        """Get the best recovery strategy."""
        strategies = RECOVERY_MAP.get(category, [RecoveryAction.RETRY])

        if attempt <= 1:
            return strategies[0] if strategies else RecoveryAction.RETRY

        # Escalate through strategies based on attempt
        idx = min(attempt - 1, len(strategies) - 1)
        return strategies[idx]

    def record_error(
        self,
        message: str,
        source: str = "",
        category: ErrorCategory | None = None,
    ) -> tuple[ErrorRecord, RecoveryAction]:
        """Record an error and get recovery strategy."""
        self._error_counter += 1

        if category is None:
            category = self.classify_error(message)

        # Count recent similar errors
        recent_count = sum(
            1 for e in self._errors[-20:]
            if e.category == category and e.source == source
        )

        strategy = self.get_recovery_strategy(category, recent_count + 1)

        record = ErrorRecord(
            error_id=f"err-{self._error_counter}",
            category=category,
            message=message[:200],
            source=source,
            recovery_attempted=strategy,
            attempts=recent_count + 1,
        )
        self._errors.append(record)

        return record, strategy

    def record_recovery(self, error_id: str) -> None:
        """Record that an error was recovered from."""
        for e in reversed(self._errors):
            if e.error_id == error_id:
                e.recovered = True
                self._recovered_count += 1
                break

    def get_circuit(self, service_name: str) -> CircuitBreaker:
        """Get or create a circuit breaker."""
        if service_name not in self._circuits:
            self._circuits[service_name] = CircuitBreaker(name=service_name)
        return self._circuits[service_name]

    def calculate_backoff(self, attempt: int) -> float:
        """Calculate exponential backoff delay."""
        delay = self._base_backoff * (2 ** (attempt - 1))
        return min(delay, self._max_backoff)

    def get_alternative_tools(self, failed_tool: str) -> list[str]:
        """Suggest alternative tools."""
        alternatives: dict[str, list[str]] = {
            "nmap": ["masscan", "rustscan", "zmap"],
            "sqlmap": ["ghauri", "nosqlmap"],
            "nuclei": ["nikto", "wapiti"],
            "gobuster": ["ffuf", "dirsearch", "feroxbuster"],
            "hydra": ["medusa", "ncrack", "patator"],
            "nikto": ["nuclei", "wapiti", "w3af"],
            "burp": ["zap", "mitmproxy"],
            "metasploit": ["sliver", "covenant"],
            "aircrack-ng": ["bettercap", "wifite"],
            "john": ["hashcat"],
            "hashcat": ["john"],
        }
        return alternatives.get(failed_tool, [])

    def get_alternative_models(self, failed_model: str) -> list[str]:
        """Suggest alternative models."""
        alternatives: dict[str, list[str]] = {
            "WhiteRabbitNeo": ["Dolphin-2.9", "Hermes-4-14B"],
            "Qwen2.5-Coder-14B": ["CodeLlama-13B", "Qwen2.5-Coder-7B"],
            "DeepSeek-R1": ["Hermes-4-14B", "Mistral-7B"],
            "Yi-9B-200K": ["Hermes-4-14B", "Llama-3.1-8B"],
            "Phi-3.5-mini": ["Mistral-7B", "Llama-3.1-8B"],
            "Hermes-4-14B": ["Mistral-7B", "Llama-3.1-8B"],
        }
        return alternatives.get(failed_model, ["Mistral-7B"])

    def build_healing_prompt(self) -> str:
        """Build self-healing context for LLM."""
        lines = ["## Self-Healing\n"]
        lines.append(f"Errors: {len(self._errors)}")
        lines.append(f"Recovered: {self._recovered_count}")
        lines.append(f"Circuits: {len(self._circuits)}")

        # Error distribution
        cat_counts: dict[str, int] = {}
        for e in self._errors:
            cat_counts[e.category.value] = cat_counts.get(e.category.value, 0) + 1
        if cat_counts:
            lines.append("\nError distribution:")
            for cat, count in sorted(cat_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
                lines.append(f"  {cat}: {count}")

        # Circuit breakers
        open_circuits = [
            c for c in self._circuits.values()
            if c.state != CircuitState.CLOSED
        ]
        if open_circuits:
            lines.append("\nTripped circuits:")
            for c in open_circuits:
                lines.append(f"  {c.name[:15]}: {c.state.value}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        recovery_rate = (
            self._recovered_count / max(1, len(self._errors))
        )
        return {
            "total_errors": len(self._errors),
            "recovered": self._recovered_count,
            "recovery_rate": f"{recovery_rate:.0%}",
            "circuits": {
                c.name: c.state.value
                for c in self._circuits.values()
            },
        }
