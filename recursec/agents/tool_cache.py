"""Tool output cache — memoization for tool execution results.

Implements:
1. Command-hash based caching
2. TTL-aware expiration
3. LRU eviction when capacity exceeded
4. Cache hit/miss statistics
5. Partial match for similar commands
6. Cache invalidation by tool or target
7. Persistent cache to disk
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class CacheStatus(str, Enum):
    HIT = "hit"
    MISS = "miss"
    EXPIRED = "expired"
    EVICTED = "evicted"


@dataclass
class CacheEntry:
    """A cached tool output."""
    cache_key: str = ""
    tool_name: str = ""
    command: str = ""
    target: str = ""
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    created_at: float = field(default_factory=time.time)
    ttl_s: float = 3600.0  # 1 hour default
    hits: int = 0

    @property
    def is_expired(self) -> bool:
        return (time.time() - self.created_at) > self.ttl_s

    @property
    def age_s(self) -> float:
        return time.time() - self.created_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.cache_key[:12],
            "tool": self.tool_name,
            "target": self.target[:20],
            "age_s": round(self.age_s, 1),
            "hits": self.hits,
            "expired": self.is_expired,
        }


# ── TTL per tool type ────────────────────────────────────────

TOOL_TTL: dict[str, float] = {
    "nmap": 7200.0,          # 2 hours (ports don't change fast)
    "masscan": 7200.0,
    "subfinder": 14400.0,    # 4 hours (DNS changes slowly)
    "amass": 14400.0,
    "httpx": 3600.0,         # 1 hour
    "nuclei": 1800.0,        # 30 min (vuln status changes)
    "ffuf": 7200.0,          # 2 hours (dirs don't change)
    "gobuster": 7200.0,
    "nikto": 3600.0,
    "sqlmap": 900.0,         # 15 min (session-dependent)
    "semgrep": 86400.0,      # 24 hours (code is static)
    "bandit": 86400.0,
    "trivy": 3600.0,
    "testssl": 7200.0,
    "hydra": 300.0,          # 5 min (credentials)
    "dig": 3600.0,
    "whois": 86400.0,        # 24 hours
}


class ToolCache:
    """LRU cache for tool execution results.

    Caches tool outputs to avoid redundant
    executions. Supports TTL, LRU eviction,
    and per-tool cache policies.
    """

    def __init__(
        self,
        max_entries: int = 1000,
        max_size_bytes: int = 100 * 1024 * 1024,  # 100MB
    ) -> None:
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._max_entries = max_entries
        self._max_size = max_size_bytes
        self._current_size = 0
        self._stats = {"hits": 0, "misses": 0, "evictions": 0, "expirations": 0}
        self._log = logger.bind(component="tool_cache")

    def get(self, tool_name: str, command: str, target: str = "") -> CacheEntry | None:
        """Look up a cached result."""
        key = self._make_key(tool_name, command, target)

        entry = self._cache.get(key)
        if not entry:
            self._stats["misses"] += 1
            return None

        if entry.is_expired:
            self._stats["expirations"] += 1
            self._remove(key)
            return None

        # Move to end (most recently used)
        self._cache.move_to_end(key)
        entry.hits += 1
        self._stats["hits"] += 1
        return entry

    def put(
        self,
        tool_name: str,
        command: str,
        stdout: str,
        stderr: str = "",
        exit_code: int = 0,
        target: str = "",
        ttl_s: float = 0.0,
    ) -> CacheEntry:
        """Cache a tool result."""
        key = self._make_key(tool_name, command, target)

        # Determine TTL
        if ttl_s == 0:
            ttl_s = TOOL_TTL.get(tool_name, 3600.0)

        # Don't cache errors (except for useful error outputs)
        if exit_code != 0 and not stdout:
            entry = CacheEntry(
                cache_key=key,
                tool_name=tool_name,
                command=command,
                target=target,
                ttl_s=0,  # Immediately expired
            )
            return entry

        entry = CacheEntry(
            cache_key=key,
            tool_name=tool_name,
            command=command,
            target=target,
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            ttl_s=ttl_s,
        )

        # Size check
        entry_size = len(stdout.encode()) + len(stderr.encode())
        while self._current_size + entry_size > self._max_size and self._cache:
            self._evict_lru()

        # Capacity check
        while len(self._cache) >= self._max_entries:
            self._evict_lru()

        # Remove old entry if exists
        if key in self._cache:
            self._remove(key)

        self._cache[key] = entry
        self._current_size += entry_size

        return entry

    def invalidate_tool(self, tool_name: str) -> int:
        """Invalidate all cache entries for a tool."""
        to_remove = [
            key for key, entry in self._cache.items()
            if entry.tool_name == tool_name
        ]
        for key in to_remove:
            self._remove(key)
        return len(to_remove)

    def invalidate_target(self, target: str) -> int:
        """Invalidate all cache entries for a target."""
        to_remove = [
            key for key, entry in self._cache.items()
            if entry.target == target
        ]
        for key in to_remove:
            self._remove(key)
        return len(to_remove)

    def clear(self) -> None:
        """Clear the entire cache."""
        self._cache.clear()
        self._current_size = 0

    def cleanup_expired(self) -> int:
        """Remove all expired entries."""
        to_remove = [
            key for key, entry in self._cache.items()
            if entry.is_expired
        ]
        for key in to_remove:
            self._remove(key)
            self._stats["expirations"] += 1
        return len(to_remove)

    def save_to_file(self, path: str) -> int:
        """Persist cache to a JSON file."""
        data = []
        for entry in self._cache.values():
            if not entry.is_expired:
                data.append({
                    "key": entry.cache_key,
                    "tool": entry.tool_name,
                    "command": entry.command,
                    "target": entry.target,
                    "stdout": entry.stdout[:10000],
                    "stderr": entry.stderr[:1000],
                    "exit_code": entry.exit_code,
                    "created_at": entry.created_at,
                    "ttl_s": entry.ttl_s,
                })
        with open(path, "w") as f:
            json.dump(data, f)
        return len(data)

    def load_from_file(self, path: str) -> int:
        """Load cache from a JSON file."""
        try:
            with open(path) as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return 0

        loaded = 0
        for item in data:
            entry = CacheEntry(
                cache_key=item["key"],
                tool_name=item["tool"],
                command=item["command"],
                target=item.get("target", ""),
                stdout=item.get("stdout", ""),
                stderr=item.get("stderr", ""),
                exit_code=item.get("exit_code", 0),
                created_at=item.get("created_at", time.time()),
                ttl_s=item.get("ttl_s", 3600.0),
            )
            if not entry.is_expired:
                self._cache[entry.cache_key] = entry
                loaded += 1

        return loaded

    def build_cache_prompt(self, max_entries: int = 5) -> str:
        """Build cache status for LLM."""
        lines = ["## Tool Cache\n"]
        lines.append(
            f"Entries: {len(self._cache)} | "
            f"Hits: {self._stats['hits']} | "
            f"Misses: {self._stats['misses']}"
        )

        hit_rate = 0.0
        total = self._stats["hits"] + self._stats["misses"]
        if total > 0:
            hit_rate = self._stats["hits"] / total
        lines.append(f"Hit rate: {hit_rate:.1%}")

        # Recent entries
        recent = list(self._cache.values())[-max_entries:]
        if recent:
            lines.append("\nRecent cached results:")
            for entry in recent:
                lines.append(
                    f"  [{entry.tool_name}] {entry.target[:15]} "
                    f"(age={entry.age_s:.0f}s, hits={entry.hits})"
                )

        return "\n".join(lines)

    def _make_key(self, tool_name: str, command: str, target: str) -> str:
        """Generate a cache key."""
        raw = f"{tool_name}:{command}:{target}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def _remove(self, key: str) -> None:
        """Remove an entry from cache."""
        entry = self._cache.pop(key, None)
        if entry:
            self._current_size -= len(entry.stdout.encode()) + len(entry.stderr.encode())
            self._current_size = max(0, self._current_size)

    def _evict_lru(self) -> None:
        """Evict the least recently used entry."""
        if self._cache:
            key = next(iter(self._cache))
            self._remove(key)
            self._stats["evictions"] += 1

    def get_stats(self) -> dict[str, Any]:
        total = self._stats["hits"] + self._stats["misses"]
        return {
            "entries": len(self._cache),
            "size_bytes": self._current_size,
            "hits": self._stats["hits"],
            "misses": self._stats["misses"],
            "hit_rate": self._stats["hits"] / total if total else 0,
            "evictions": self._stats["evictions"],
        }
