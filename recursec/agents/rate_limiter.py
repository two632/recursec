"""Rate limiter — controls request rates to prevent detection and overload.

Implements:
1. Token bucket algorithm
2. Sliding window rate limiting
3. Per-target rate limits
4. Per-tool rate limits
5. Global rate limiting
6. Adaptive rate adjustment
7. Backoff strategies (exponential, linear, jitter)
8. Rate limit status tracking
"""

from __future__ import annotations

import asyncio
import random
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class TokenBucket:
    """Token bucket for rate limiting."""
    capacity: float = 10.0
    tokens: float = 10.0
    refill_rate: float = 1.0       # Tokens per second
    last_refill: float = field(default_factory=time.time)

    def consume(self, tokens: float = 1.0) -> bool:
        """Try to consume tokens. Returns True if successful."""
        self._refill()
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False

    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.time()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now

    @property
    def wait_time(self) -> float:
        """Time to wait until 1 token is available."""
        self._refill()
        if self.tokens >= 1.0:
            return 0.0
        return (1.0 - self.tokens) / self.refill_rate

    def to_dict(self) -> dict[str, Any]:
        self._refill()
        return {
            "tokens": round(self.tokens, 1),
            "capacity": self.capacity,
            "rate": self.refill_rate,
        }


@dataclass
class SlidingWindow:
    """Sliding window rate counter."""
    window_size_s: float = 60.0
    max_requests: int = 60
    timestamps: list[float] = field(default_factory=list)

    def can_proceed(self) -> bool:
        """Check if request is allowed."""
        self._cleanup()
        return len(self.timestamps) < self.max_requests

    def record(self) -> None:
        """Record a request."""
        self.timestamps.append(time.time())

    def _cleanup(self) -> None:
        """Remove expired timestamps."""
        cutoff = time.time() - self.window_size_s
        self.timestamps = [t for t in self.timestamps if t > cutoff]

    @property
    def current_rate(self) -> float:
        """Current requests per minute."""
        self._cleanup()
        if not self.timestamps:
            return 0.0
        return len(self.timestamps) * 60.0 / self.window_size_s

    def to_dict(self) -> dict[str, Any]:
        self._cleanup()
        return {
            "current": len(self.timestamps),
            "max": self.max_requests,
            "rate_rpm": round(self.current_rate, 1),
        }


@dataclass
class BackoffState:
    """Backoff state for a target/tool."""
    failures: int = 0
    last_failure: float = 0.0
    backoff_until: float = 0.0
    base_delay: float = 1.0
    max_delay: float = 300.0
    strategy: str = "exponential"     # exponential, linear, jitter

    def record_failure(self) -> float:
        """Record a failure and return backoff delay."""
        self.failures += 1
        self.last_failure = time.time()

        if self.strategy == "exponential":
            delay = self.base_delay * (2 ** min(self.failures, 8))
        elif self.strategy == "linear":
            delay = self.base_delay * self.failures
        else:  # jitter
            delay = self.base_delay * (2 ** min(self.failures, 8))
            delay *= (0.5 + random.random())

        delay = min(delay, self.max_delay)
        self.backoff_until = time.time() + delay
        return delay

    def record_success(self) -> None:
        """Record a success, reducing backoff."""
        self.failures = max(0, self.failures - 1)
        self.backoff_until = 0.0

    @property
    def is_backed_off(self) -> bool:
        return time.time() < self.backoff_until

    @property
    def remaining_s(self) -> float:
        return max(0.0, self.backoff_until - time.time())

    def to_dict(self) -> dict[str, Any]:
        return {
            "failures": self.failures,
            "backed_off": self.is_backed_off,
            "remaining_s": round(self.remaining_s, 1),
        }


class RateLimiter:
    """Controls request rates for targets and tools.

    Uses token bucket and sliding window algorithms
    with adaptive backoff strategies.
    """

    def __init__(
        self,
        global_rpm: int = 120,
        per_target_rpm: int = 30,
        per_tool_rpm: int = 60,
    ) -> None:
        # Global limits
        self._global_window = SlidingWindow(
            window_size_s=60.0, max_requests=global_rpm,
        )
        self._global_bucket = TokenBucket(
            capacity=float(global_rpm) / 6.0,   # burst allowance
            refill_rate=float(global_rpm) / 60.0,
        )

        # Per-target limits
        self._target_windows: dict[str, SlidingWindow] = defaultdict(
            lambda: SlidingWindow(window_size_s=60.0, max_requests=per_target_rpm),
        )
        self._target_buckets: dict[str, TokenBucket] = {}
        self._per_target_rpm = per_target_rpm

        # Per-tool limits
        self._tool_windows: dict[str, SlidingWindow] = defaultdict(
            lambda: SlidingWindow(window_size_s=60.0, max_requests=per_tool_rpm),
        )
        self._per_tool_rpm = per_tool_rpm

        # Backoff states
        self._backoffs: dict[str, BackoffState] = {}

        self._total_requests = 0
        self._total_blocked = 0
        self._log = logger.bind(component="rate_limiter")

    async def acquire(
        self,
        target: str = "",
        tool: str = "",
    ) -> bool:
        """Acquire permission to make a request. Waits if needed."""
        # Check backoff
        backoff_key = f"{target}:{tool}" if target and tool else target or tool
        if backoff_key and backoff_key in self._backoffs:
            backoff = self._backoffs[backoff_key]
            if backoff.is_backed_off:
                remaining = backoff.remaining_s
                if remaining > 0:
                    await asyncio.sleep(min(remaining, 30.0))

        # Check global rate
        if not self._global_window.can_proceed():
            wait = 60.0 / max(1, self._global_window.max_requests)
            await asyncio.sleep(wait)
            if not self._global_window.can_proceed():
                self._total_blocked += 1
                return False

        # Check per-target rate
        if target:
            target_window = self._target_windows[target]
            if not target_window.can_proceed():
                wait = 60.0 / max(1, self._per_target_rpm)
                await asyncio.sleep(wait)
                if not target_window.can_proceed():
                    self._total_blocked += 1
                    return False

        # Check per-tool rate
        if tool:
            tool_window = self._tool_windows[tool]
            if not tool_window.can_proceed():
                wait = 60.0 / max(1, self._per_tool_rpm)
                await asyncio.sleep(wait)
                if not tool_window.can_proceed():
                    self._total_blocked += 1
                    return False

        # Record the request
        self._global_window.record()
        if target:
            self._target_windows[target].record()
        if tool:
            self._tool_windows[tool].record()

        self._total_requests += 1
        return True

    def record_failure(
        self,
        target: str = "",
        tool: str = "",
        strategy: str = "exponential",
    ) -> float:
        """Record a failure and activate backoff."""
        key = f"{target}:{tool}" if target and tool else target or tool
        if not key:
            return 0.0

        if key not in self._backoffs:
            self._backoffs[key] = BackoffState(strategy=strategy)

        return self._backoffs[key].record_failure()

    def record_success(self, target: str = "", tool: str = "") -> None:
        """Record a success."""
        key = f"{target}:{tool}" if target and tool else target or tool
        if key and key in self._backoffs:
            self._backoffs[key].record_success()

    def set_target_limit(self, target: str, rpm: int) -> None:
        """Set custom rate limit for a target."""
        self._target_windows[target] = SlidingWindow(
            window_size_s=60.0, max_requests=rpm,
        )

    def set_tool_limit(self, tool: str, rpm: int) -> None:
        """Set custom rate limit for a tool."""
        self._tool_windows[tool] = SlidingWindow(
            window_size_s=60.0, max_requests=rpm,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_requests": self._total_requests,
            "total_blocked": self._total_blocked,
            "global_rate": round(self._global_window.current_rate, 1),
            "targets_tracked": len(self._target_windows),
            "tools_tracked": len(self._tool_windows),
            "backed_off": sum(
                1 for b in self._backoffs.values() if b.is_backed_off
            ),
        }
