"""Failure analyzer — post-failure analysis and recovery.

Implements:
1. Failure classification
2. Root cause analysis
3. Recovery strategy selection
4. Failure pattern learning
5. Retry policy management
6. Cascading failure detection
7. Failure-to-knowledge conversion
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class FailureType(str, Enum):
    TOOL_ERROR = "tool_error"           # External tool failed
    TIMEOUT = "timeout"                  # Operation timed out
    NETWORK = "network"                  # Network error
    AUTH = "auth"                         # Authentication failure
    PERMISSION = "permission"             # Permission denied
    RATE_LIMIT = "rate_limit"             # Rate limited
    MODEL_ERROR = "model_error"           # LLM error
    PARSE_ERROR = "parse_error"           # Output parsing failed
    LOGIC_ERROR = "logic_error"           # Logic/reasoning error
    RESOURCE = "resource"                 # Resource exhausted
    UNKNOWN = "unknown"


class RecoveryAction(str, Enum):
    RETRY = "retry"                      # Retry same action
    RETRY_DIFFERENT_MODEL = "retry_model"  # Retry with different model
    RETRY_DIFFERENT_TOOL = "retry_tool"    # Use alternative tool
    ESCALATE = "escalate"                  # Escalate to parent
    SKIP = "skip"                          # Skip this step
    REDUCE_SCOPE = "reduce_scope"          # Reduce operation scope
    INCREASE_TIMEOUT = "increase_timeout"  # Increase timeout
    BACKOFF = "backoff"                    # Wait and retry
    ABORT = "abort"                        # Abort operation


@dataclass
class Failure:
    """A failure event."""
    failure_id: str = ""
    failure_type: FailureType = FailureType.UNKNOWN
    operation: str = ""
    error_message: str = ""
    tool: str = ""
    model: str = ""
    target: str = ""
    attempt: int = 1
    max_attempts: int = 3
    timestamp: float = field(default_factory=time.time)
    context: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.failure_id[:10],
            "type": self.failure_type.value,
            "operation": self.operation[:20],
            "attempt": f"{self.attempt}/{self.max_attempts}",
        }


@dataclass
class RecoveryPlan:
    """A recovery plan for a failure."""
    plan_id: str = ""
    failure_id: str = ""
    actions: list[RecoveryAction] = field(default_factory=list)
    primary_action: RecoveryAction = RecoveryAction.RETRY
    wait_seconds: float = 0.0
    alternative_tool: str = ""
    alternative_model: str = ""
    explanation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.plan_id[:10],
            "primary": self.primary_action.value,
            "actions": len(self.actions),
            "wait": self.wait_seconds,
        }


@dataclass
class FailurePattern:
    """A learned failure pattern."""
    pattern_id: str = ""
    failure_type: FailureType = FailureType.UNKNOWN
    operation: str = ""
    tool: str = ""
    occurrences: int = 0
    successful_recovery: RecoveryAction = RecoveryAction.RETRY
    success_rate: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id[:10],
            "type": self.failure_type.value,
            "occurs": self.occurrences,
            "best_recovery": self.successful_recovery.value,
        }


# ── Failure→Recovery mapping ─────────────────────────────────

RECOVERY_MAP: dict[str, list[dict[str, Any]]] = {
    "tool_error": [
        {"action": "retry", "wait": 5, "max": 3, "desc": "Retry tool execution"},
        {"action": "retry_tool", "wait": 0, "desc": "Use alternative tool"},
        {"action": "skip", "wait": 0, "desc": "Skip and continue"},
    ],
    "timeout": [
        {"action": "increase_timeout", "wait": 0, "desc": "Double timeout and retry"},
        {"action": "reduce_scope", "wait": 0, "desc": "Reduce scan scope and retry"},
        {"action": "retry_tool", "wait": 0, "desc": "Use faster alternative tool"},
    ],
    "network": [
        {"action": "backoff", "wait": 30, "desc": "Wait and retry"},
        {"action": "retry", "wait": 10, "max": 5, "desc": "Retry with delay"},
        {"action": "abort", "wait": 0, "desc": "Target unreachable"},
    ],
    "auth": [
        {"action": "retry_model", "wait": 0, "desc": "Use different model for auth bypass"},
        {"action": "escalate", "wait": 0, "desc": "Escalate for credentials"},
        {"action": "skip", "wait": 0, "desc": "Skip authenticated testing"},
    ],
    "permission": [
        {"action": "reduce_scope", "wait": 0, "desc": "Reduce operation privileges"},
        {"action": "retry_tool", "wait": 0, "desc": "Use less invasive tool"},
        {"action": "skip", "wait": 0, "desc": "Skip privileged operation"},
    ],
    "rate_limit": [
        {"action": "backoff", "wait": 60, "desc": "Wait for rate limit reset"},
        {"action": "reduce_scope", "wait": 30, "desc": "Reduce request rate"},
        {"action": "retry_tool", "wait": 0, "desc": "Use tool with built-in throttling"},
    ],
    "model_error": [
        {"action": "retry_model", "wait": 0, "desc": "Use alternative model"},
        {"action": "retry", "wait": 5, "max": 2, "desc": "Retry same model"},
        {"action": "reduce_scope", "wait": 0, "desc": "Simplify prompt"},
    ],
    "parse_error": [
        {"action": "retry_model", "wait": 0, "desc": "Use model with better structured output"},
        {"action": "retry", "wait": 0, "max": 2, "desc": "Retry with explicit format instructions"},
        {"action": "skip", "wait": 0, "desc": "Use raw output"},
    ],
    "logic_error": [
        {"action": "retry_model", "wait": 0, "desc": "Use reasoning model (DeepSeek-R1)"},
        {"action": "escalate", "wait": 0, "desc": "Escalate to parent agent"},
        {"action": "skip", "wait": 0, "desc": "Skip reasoning step"},
    ],
    "resource": [
        {"action": "reduce_scope", "wait": 0, "desc": "Reduce resource requirements"},
        {"action": "backoff", "wait": 60, "desc": "Wait for resources to free up"},
        {"action": "abort", "wait": 0, "desc": "Cannot allocate resources"},
    ],
}

# ── Tool alternatives ────────────────────────────────────────

TOOL_ALTERNATIVES: dict[str, list[str]] = {
    "nmap": ["masscan", "rustscan"],
    "masscan": ["nmap"],
    "nuclei": ["nikto", "wapiti"],
    "nikto": ["nuclei"],
    "sqlmap": ["ghauri"],
    "gobuster": ["ffuf", "feroxbuster", "dirsearch"],
    "ffuf": ["gobuster", "feroxbuster"],
    "feroxbuster": ["ffuf", "gobuster"],
    "subfinder": ["amass", "assetfinder"],
    "amass": ["subfinder"],
    "hydra": ["medusa", "ncrack"],
    "dalfox": ["xsstrike"],
    "testssl": ["sslyze"],
    "wpscan": ["nuclei -t wordpress"],
    "semgrep": ["bandit"],
    "bandit": ["semgrep"],
    "trufflehog": ["gitleaks"],
    "gitleaks": ["trufflehog"],
    "trivy": ["grype"],
    "grype": ["trivy"],
}


class FailureAnalyzer:
    """Analyzes failures and generates recovery plans.

    Classifies failures, suggests recovery strategies,
    and learns from failure patterns.
    """

    def __init__(self) -> None:
        self._failures: dict[str, Failure] = {}
        self._patterns: dict[str, FailurePattern] = {}
        self._counter = 0
        self._log = logger.bind(component="failure_analyzer")

    def record_failure(
        self,
        operation: str,
        error_message: str,
        failure_type: str = "unknown",
        tool: str = "",
        model: str = "",
        target: str = "",
        attempt: int = 1,
    ) -> Failure:
        """Record a failure event."""
        self._counter += 1
        try:
            ftype = FailureType(failure_type)
        except ValueError:
            ftype = self._classify_failure(error_message)

        failure = Failure(
            failure_id=f"fail-{self._counter}",
            failure_type=ftype,
            operation=operation,
            error_message=error_message,
            tool=tool,
            model=model,
            target=target,
            attempt=attempt,
        )
        self._failures[failure.failure_id] = failure

        # Update patterns
        self._update_pattern(failure)

        return failure

    def _classify_failure(self, error_message: str) -> FailureType:
        """Classify a failure from its error message."""
        msg = error_message.lower()

        if any(kw in msg for kw in ["timeout", "timed out", "deadline"]):
            return FailureType.TIMEOUT
        if any(kw in msg for kw in ["connection refused", "network", "dns", "unreachable"]):
            return FailureType.NETWORK
        if any(kw in msg for kw in ["401", "403", "authentication", "unauthorized"]):
            return FailureType.AUTH
        if any(kw in msg for kw in ["permission", "access denied"]):
            return FailureType.PERMISSION
        if any(kw in msg for kw in ["429", "rate limit", "too many requests"]):
            return FailureType.RATE_LIMIT
        if any(kw in msg for kw in ["model", "llm", "inference"]):
            return FailureType.MODEL_ERROR
        if any(kw in msg for kw in ["parse", "json", "decode", "format"]):
            return FailureType.PARSE_ERROR
        if any(kw in msg for kw in ["memory", "disk", "resource"]):
            return FailureType.RESOURCE

        return FailureType.TOOL_ERROR

    def _update_pattern(self, failure: Failure) -> None:
        """Update failure patterns."""
        key = f"{failure.failure_type.value}:{failure.tool or failure.operation}"
        pattern = self._patterns.get(key)
        if pattern:
            pattern.occurrences += 1
        else:
            self._counter += 1
            self._patterns[key] = FailurePattern(
                pattern_id=f"pat-{self._counter}",
                failure_type=failure.failure_type,
                operation=failure.operation,
                tool=failure.tool,
                occurrences=1,
            )

    def get_recovery_plan(self, failure_id: str) -> RecoveryPlan:
        """Generate a recovery plan for a failure."""
        failure = self._failures.get(failure_id)
        if not failure:
            return RecoveryPlan()

        self._counter += 1
        recovery_options = RECOVERY_MAP.get(
            failure.failure_type.value,
            RECOVERY_MAP["tool_error"],
        )

        actions = [
            RecoveryAction(opt["action"])
            for opt in recovery_options
        ]

        primary = actions[0] if actions else RecoveryAction.RETRY
        wait = recovery_options[0].get("wait", 0) if recovery_options else 0

        # Check for alternative tool
        alt_tool = ""
        if primary == RecoveryAction.RETRY_DIFFERENT_TOOL and failure.tool:
            alts = TOOL_ALTERNATIVES.get(failure.tool, [])
            if alts:
                alt_tool = alts[0]

        # If max attempts reached, escalate
        if failure.attempt >= failure.max_attempts:
            primary = RecoveryAction.ESCALATE
            actions = [RecoveryAction.ESCALATE, RecoveryAction.SKIP]

        plan = RecoveryPlan(
            plan_id=f"plan-{self._counter}",
            failure_id=failure_id,
            actions=actions,
            primary_action=primary,
            wait_seconds=wait,
            alternative_tool=alt_tool,
            explanation=recovery_options[0].get("desc", "") if recovery_options else "",
        )

        return plan

    def get_failure_summary(self) -> str:
        """Get a summary of recent failures."""
        if not self._failures:
            return "No failures recorded."

        type_counts: dict[str, int] = defaultdict(int)
        for f in self._failures.values():
            type_counts[f.failure_type.value] += 1

        lines = ["## Failure Summary\n"]
        for ftype, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
            lines.append(f"- {ftype}: {count} occurrences")

        # Persistent failures
        persistent = [
            p for p in self._patterns.values()
            if p.occurrences >= 3
        ]
        if persistent:
            lines.append("\n### Persistent Failures")
            for p in persistent:
                lines.append(f"- {p.tool or p.operation}: {p.occurrences}x ({p.failure_type.value})")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        type_counts: dict[str, int] = defaultdict(int)
        for f in self._failures.values():
            type_counts[f.failure_type.value] += 1

        return {
            "total_failures": len(self._failures),
            "patterns": len(self._patterns),
            "by_type": dict(type_counts),
            "persistent": sum(1 for p in self._patterns.values() if p.occurrences >= 3),
        }
