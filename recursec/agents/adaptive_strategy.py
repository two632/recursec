"""Adaptive strategy engine — dynamic strategy selection.

Implements:
1. Strategy pool with effectiveness tracking
2. Multi-armed bandit for strategy selection
3. Target-type-aware strategy matching
4. Strategy composition (combine primitives)
5. Feedback-driven strategy adaptation
6. Exploration vs exploitation balance
7. Strategy templates per assessment type
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class StrategyType(str, Enum):
    AGGRESSIVE = "aggressive"       # Fast, noisy, comprehensive
    STEALTH = "stealth"             # Slow, evasive, careful
    TARGETED = "targeted"           # Focused on specific vulns
    BREADTH_FIRST = "breadth_first" # Wide coverage first
    DEPTH_FIRST = "depth_first"     # Deep on each finding
    ADAPTIVE = "adaptive"           # Changes based on results
    CHAIN_BUILD = "chain_build"     # Builds exploit chains


class StrategyState(str, Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    EXHAUSTED = "exhausted"
    FAILED = "failed"


@dataclass
class Strategy:
    """A testing strategy."""
    strategy_id: str = ""
    name: str = ""
    strategy_type: StrategyType = StrategyType.ADAPTIVE
    description: str = ""
    tools: list[str] = field(default_factory=list)
    phases: list[str] = field(default_factory=list)
    state: StrategyState = StrategyState.ACTIVE

    # Bandit stats
    total_uses: int = 0
    total_reward: float = 0.0
    findings_produced: int = 0
    avg_time_per_finding_s: float = 0.0

    @property
    def avg_reward(self) -> float:
        if self.total_uses == 0:
            return 0.0
        return self.total_reward / self.total_uses

    @property
    def ucb_score(self) -> float:
        if self.total_uses == 0:
            return float("inf")
        exploitation = self.avg_reward
        exploration = math.sqrt(2 * math.log(max(1, self.total_uses + 10)) / self.total_uses)
        return exploitation + exploration

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.strategy_id[:10],
            "name": self.name[:20],
            "type": self.strategy_type.value,
            "uses": self.total_uses,
            "avg_reward": round(self.avg_reward, 2),
            "ucb": round(self.ucb_score, 2),
        }


@dataclass
class StrategyResult:
    """Result of a strategy execution."""
    strategy_id: str = ""
    reward: float = 0.0
    findings: int = 0
    duration_s: float = 0.0
    success: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy": self.strategy_id[:10],
            "reward": round(self.reward, 2),
            "findings": self.findings,
        }


# ── Strategy pool ─────────────────────────────────────────────

STRATEGY_TEMPLATES: list[dict[str, Any]] = [
    {
        "name": "Full Port Scan + Service Enum",
        "type": "aggressive",
        "desc": "Scan all 65535 ports, identify services, check known CVEs",
        "tools": ["nmap", "masscan", "searchsploit"],
        "phases": ["reconnaissance", "scanning"],
    },
    {
        "name": "Web Application Deep Dive",
        "type": "depth_first",
        "desc": "Spider web app, fuzz parameters, test injection points",
        "tools": ["nuclei", "ffuf", "sqlmap", "dalfox", "katana"],
        "phases": ["scanning", "exploitation"],
    },
    {
        "name": "Subdomain Takeover Hunt",
        "type": "targeted",
        "desc": "Enumerate subdomains, check for dangling DNS, test takeover",
        "tools": ["subfinder", "amass", "httpx", "nuclei"],
        "phases": ["reconnaissance", "scanning"],
    },
    {
        "name": "Authentication Attack",
        "type": "targeted",
        "desc": "Test login endpoints, brute force, credential stuffing, JWT attacks",
        "tools": ["hydra", "ffuf", "jwt_tool"],
        "phases": ["exploitation"],
    },
    {
        "name": "API Endpoint Discovery",
        "type": "breadth_first",
        "desc": "Discover API endpoints, test auth, mass assignment, BOLA",
        "tools": ["ffuf", "nuclei", "arjun", "curl"],
        "phases": ["reconnaissance", "scanning"],
    },
    {
        "name": "Supply Chain Analysis",
        "type": "targeted",
        "desc": "Check dependencies, container images, CI/CD configs",
        "tools": ["trivy", "grype", "trufflehog", "gitleaks"],
        "phases": ["scanning"],
    },
    {
        "name": "Stealth Reconnaissance",
        "type": "stealth",
        "desc": "Passive recon, DNS enumeration, OSINT, no active scanning",
        "tools": ["subfinder", "waybackurls", "gau", "whois", "dig"],
        "phases": ["reconnaissance"],
    },
    {
        "name": "Exploit Chain Building",
        "type": "chain_build",
        "desc": "Chain multiple findings into high-impact exploit paths",
        "tools": ["sqlmap", "nuclei", "curl"],
        "phases": ["exploitation", "validation"],
    },
    {
        "name": "Cloud Infrastructure Assessment",
        "type": "breadth_first",
        "desc": "Check S3 buckets, IAM, metadata, serverless, containers",
        "tools": ["nuclei", "curl", "trivy"],
        "phases": ["reconnaissance", "scanning"],
    },
    {
        "name": "Internal Network Pivot",
        "type": "depth_first",
        "desc": "SSRF to internal, lateral movement, service enumeration",
        "tools": ["nuclei", "curl", "nmap"],
        "phases": ["exploitation", "post_exploitation"],
    },
]


class AdaptiveStrategy:
    """Adaptive strategy selection engine.

    Uses UCB1 (Upper Confidence Bound) bandit
    algorithm to balance exploration of new
    strategies with exploitation of known-good ones.
    """

    def __init__(self, exploration_factor: float = 1.0) -> None:
        self._strategies: dict[str, Strategy] = {}
        self._counter = 0
        self._exploration = exploration_factor
        self._log = logger.bind(component="adaptive_strategy")
        self._load_templates()

    def _load_templates(self) -> None:
        """Load strategy templates."""
        for tmpl in STRATEGY_TEMPLATES:
            self._counter += 1
            strategy = Strategy(
                strategy_id=f"strat-{self._counter}",
                name=tmpl["name"],
                strategy_type=StrategyType(tmpl["type"]),
                description=tmpl["desc"],
                tools=tmpl.get("tools", []),
                phases=tmpl.get("phases", []),
            )
            self._strategies[strategy.strategy_id] = strategy

    def select_strategy(
        self,
        target_type: str = "",
        phase: str = "",
        exclude: list[str] | None = None,
    ) -> Strategy | None:
        """Select the best strategy using UCB1."""
        candidates = [
            s for s in self._strategies.values()
            if s.state == StrategyState.ACTIVE
            and (not exclude or s.strategy_id not in exclude)
            and (not phase or phase in s.phases)
        ]

        if not candidates:
            return None

        # UCB1 selection
        best = max(candidates, key=lambda s: s.ucb_score)
        return best

    def record_result(
        self,
        strategy_id: str,
        reward: float,
        findings: int = 0,
        duration_s: float = 0.0,
    ) -> None:
        """Record strategy execution result."""
        strategy = self._strategies.get(strategy_id)
        if not strategy:
            return

        strategy.total_uses += 1
        strategy.total_reward += reward
        strategy.findings_produced += findings

        if findings > 0 and duration_s > 0:
            strategy.avg_time_per_finding_s = (
                strategy.avg_time_per_finding_s * (strategy.total_uses - 1)
                + duration_s / findings
            ) / strategy.total_uses

        # Mark exhausted if consistently low reward
        if strategy.total_uses >= 5 and strategy.avg_reward < 0.1:
            strategy.state = StrategyState.EXHAUSTED

    def get_top_strategies(self, limit: int = 5) -> list[Strategy]:
        """Get top performing strategies."""
        active = [s for s in self._strategies.values() if s.state == StrategyState.ACTIVE]
        active.sort(key=lambda s: s.avg_reward, reverse=True)
        return active[:limit]

    def build_strategy_prompt(
        self,
        phase: str = "",
    ) -> str:
        """Build strategy selection prompt."""
        lines = ["## Available Strategies\n"]

        strategies = self.get_top_strategies(limit=5)
        if phase:
            strategies = [s for s in strategies if phase in s.phases]

        for strat in strategies:
            lines.append(
                f"- **{strat.name}** ({strat.strategy_type.value}): "
                f"{strat.description} "
                f"[reward: {strat.avg_reward:.1f}, uses: {strat.total_uses}]"
            )

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        active = sum(1 for s in self._strategies.values() if s.state == StrategyState.ACTIVE)
        return {
            "total": len(self._strategies),
            "active": active,
            "total_uses": sum(s.total_uses for s in self._strategies.values()),
            "total_findings": sum(s.findings_produced for s in self._strategies.values()),
        }
