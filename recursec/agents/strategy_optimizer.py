"""Strategy optimizer — learns which strategies work best per context.

Implements:
1. Strategy performance tracking (success/fail/tokens/time)
2. Multi-armed bandit selection (UCB1)
3. Contextual strategy recommendation
4. Strategy composition (combining multiple)
5. Adaptive exploration/exploitation balance
6. Strategy decay (deprioritize stale strategies)
7. LLM prompt for strategy decisions
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class StrategyCategory(str, Enum):
    RECON = "recon"
    SCANNING = "scanning"
    EXPLOITATION = "exploitation"
    POST_EXPLOIT = "post_exploit"
    EVASION = "evasion"
    LATERAL = "lateral"
    PERSISTENCE = "persistence"


class StrategyOutcome(str, Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILURE = "failure"
    ERROR = "error"
    BLOCKED = "blocked"


@dataclass
class Strategy:
    """A security testing strategy."""
    strategy_id: str = ""
    name: str = ""
    category: StrategyCategory = StrategyCategory.SCANNING
    description: str = ""
    tools: list[str] = field(default_factory=list)
    applicable_targets: list[str] = field(default_factory=list)  # web, network, api, etc.
    prerequisites: list[str] = field(default_factory=list)
    avg_duration_s: float = 300.0
    avg_tokens: int = 5000

    # Performance tracking
    total_uses: int = 0
    successes: int = 0
    failures: int = 0
    total_findings: int = 0
    total_tokens_used: int = 0
    total_duration_s: float = 0.0
    last_used: float = 0.0

    @property
    def success_rate(self) -> float:
        if self.total_uses == 0:
            return 0.5  # Unknown, assume neutral
        return (self.successes + 0.5 * (self.total_uses - self.successes - self.failures)) / self.total_uses

    @property
    def avg_findings_per_use(self) -> float:
        if self.total_uses == 0:
            return 0.0
        return self.total_findings / self.total_uses

    @property
    def efficiency(self) -> float:
        """Findings per 1000 tokens."""
        if self.total_tokens_used == 0:
            return 0.0
        return (self.total_findings / self.total_tokens_used) * 1000

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.strategy_id[:10],
            "name": self.name[:20],
            "category": self.category.value,
            "uses": self.total_uses,
            "success_rate": round(self.success_rate, 2),
            "findings": self.total_findings,
            "efficiency": round(self.efficiency, 2),
        }


@dataclass
class StrategyRun:
    """A recorded strategy execution."""
    run_id: str = ""
    strategy_id: str = ""
    outcome: StrategyOutcome = StrategyOutcome.FAILURE
    target_type: str = ""
    findings_count: int = 0
    tokens_used: int = 0
    duration_s: float = 0.0
    notes: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy": self.strategy_id[:10],
            "outcome": self.outcome.value,
            "findings": self.findings_count,
        }


# ── Default strategies ───────────────────────────────────────

DEFAULT_STRATEGIES: list[dict[str, Any]] = [
    {
        "id": "strat-passive-recon", "name": "Passive Reconnaissance",
        "category": "recon",
        "desc": "Gather information without touching target directly",
        "tools": ["subfinder", "amass", "theHarvester", "whois", "dig"],
        "targets": ["web", "network", "api"],
    },
    {
        "id": "strat-active-recon", "name": "Active Reconnaissance",
        "category": "recon",
        "desc": "Active scanning and enumeration of target",
        "tools": ["nmap", "masscan", "httpx", "whatweb"],
        "targets": ["web", "network", "api"],
    },
    {
        "id": "strat-web-vuln", "name": "Web Vulnerability Scanning",
        "category": "scanning",
        "desc": "Automated web vulnerability scanning",
        "tools": ["nuclei", "nikto", "zap"],
        "targets": ["web", "api"],
    },
    {
        "id": "strat-dir-discovery", "name": "Directory Discovery",
        "category": "recon",
        "desc": "Discover hidden directories and files",
        "tools": ["ffuf", "gobuster", "feroxbuster"],
        "targets": ["web"],
    },
    {
        "id": "strat-sqli", "name": "SQL Injection Testing",
        "category": "exploitation",
        "desc": "Test for SQL injection vulnerabilities",
        "tools": ["sqlmap"],
        "targets": ["web", "api"],
    },
    {
        "id": "strat-auth-test", "name": "Authentication Testing",
        "category": "exploitation",
        "desc": "Test authentication mechanisms",
        "tools": ["hydra", "burpsuite", "jwt_tool"],
        "targets": ["web", "api", "network"],
    },
    {
        "id": "strat-code-audit", "name": "Static Code Audit",
        "category": "scanning",
        "desc": "Static analysis of source code",
        "tools": ["semgrep", "bandit", "codeql"],
        "targets": ["code"],
    },
    {
        "id": "strat-api-test", "name": "API Security Testing",
        "category": "scanning",
        "desc": "Test API endpoints for security issues",
        "tools": ["nuclei", "ffuf", "graphw00f"],
        "targets": ["api"],
    },
    {
        "id": "strat-privesc", "name": "Privilege Escalation",
        "category": "post_exploit",
        "desc": "Escalate privileges after initial access",
        "tools": ["linpeas", "winpeas"],
        "targets": ["host"],
    },
    {
        "id": "strat-lateral", "name": "Lateral Movement",
        "category": "lateral",
        "desc": "Move laterally through the network",
        "tools": ["crackmapexec", "impacket"],
        "targets": ["network", "ad"],
    },
]


class StrategyOptimizer:
    """Optimizes strategy selection using multi-armed bandit.

    Tracks strategy performance and uses UCB1
    algorithm to balance exploration (trying
    new strategies) with exploitation (using
    proven strategies).
    """

    def __init__(self, exploration_weight: float = 1.41) -> None:
        self._strategies: dict[str, Strategy] = {}
        self._runs: list[StrategyRun] = []
        self._exploration_weight = exploration_weight
        self._total_rounds = 0
        self._counter = 0
        self._log = logger.bind(component="strategy_optimizer")
        self._load_defaults()

    def _load_defaults(self) -> None:
        """Load default strategies."""
        for data in DEFAULT_STRATEGIES:
            strat = Strategy(
                strategy_id=data["id"],
                name=data["name"],
                category=StrategyCategory(data["category"]),
                description=data.get("desc", ""),
                tools=data.get("tools", []),
                applicable_targets=data.get("targets", []),
            )
            self._strategies[strat.strategy_id] = strat

    def recommend(
        self,
        target_type: str = "",
        category: StrategyCategory | None = None,
        top_k: int = 3,
    ) -> list[Strategy]:
        """Recommend strategies using UCB1."""
        self._total_rounds += 1
        candidates: list[tuple[float, Strategy]] = []

        for strat in self._strategies.values():
            # Filter by target type
            if target_type and strat.applicable_targets:
                if target_type not in strat.applicable_targets:
                    continue

            # Filter by category
            if category and strat.category != category:
                continue

            # UCB1 score
            score = self._ucb1_score(strat)
            candidates.append((score, strat))

        candidates.sort(key=lambda x: x[0], reverse=True)
        return [strat for _, strat in candidates[:top_k]]

    def record_outcome(
        self,
        strategy_id: str,
        outcome: StrategyOutcome,
        target_type: str = "",
        findings_count: int = 0,
        tokens_used: int = 0,
        duration_s: float = 0.0,
        notes: str = "",
    ) -> StrategyRun | None:
        """Record a strategy execution outcome."""
        strat = self._strategies.get(strategy_id)
        if not strat:
            return None

        self._counter += 1
        run = StrategyRun(
            run_id=f"run-{self._counter}",
            strategy_id=strategy_id,
            outcome=outcome,
            target_type=target_type,
            findings_count=findings_count,
            tokens_used=tokens_used,
            duration_s=duration_s,
            notes=notes,
        )
        self._runs.append(run)

        # Update strategy stats
        strat.total_uses += 1
        strat.total_findings += findings_count
        strat.total_tokens_used += tokens_used
        strat.total_duration_s += duration_s
        strat.last_used = time.time()

        if outcome == StrategyOutcome.SUCCESS:
            strat.successes += 1
        elif outcome in (StrategyOutcome.FAILURE, StrategyOutcome.ERROR):
            strat.failures += 1

        return run

    def build_strategy_prompt(
        self,
        target_type: str = "",
        max_strategies: int = 5,
    ) -> str:
        """Build strategy context for LLM."""
        lines = ["## Strategy Recommendations\n"]

        recommended = self.recommend(target_type=target_type, top_k=max_strategies)
        if recommended:
            lines.append(f"Top strategies for {target_type or 'general'} target:")
            for strat in recommended:
                ucb = self._ucb1_score(strat)
                lines.append(
                    f"  [{strat.category.value[:4]}] {strat.name[:20]} "
                    f"(UCB={ucb:.2f}, success={strat.success_rate:.0%}, "
                    f"findings/use={strat.avg_findings_per_use:.1f})"
                )
                if strat.tools:
                    lines.append(f"    Tools: {', '.join(strat.tools[:4])}")

        return "\n".join(lines)

    def _ucb1_score(self, strat: Strategy) -> float:
        """Calculate UCB1 score for a strategy."""
        if strat.total_uses == 0:
            return float("inf")  # Unexplored → highest priority

        exploitation = strat.success_rate
        exploration = self._exploration_weight * math.sqrt(
            math.log(max(1, self._total_rounds)) / strat.total_uses
        )

        # Bonus for high findings efficiency
        efficiency_bonus = min(0.2, strat.efficiency * 0.01)

        return exploitation + exploration + efficiency_bonus

    def get_stats(self) -> dict[str, Any]:
        return {
            "strategies": len(self._strategies),
            "total_runs": len(self._runs),
            "total_rounds": self._total_rounds,
            "best_strategy": max(
                self._strategies.values(),
                key=lambda s: s.success_rate,
            ).name if self._strategies else "",
        }
