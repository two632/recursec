"""Transfer learning — reuses learned strategies across different targets and tasks.

Implements:
1. Strategy library (learned effective approaches)
2. Target fingerprint matching
3. Cross-target strategy adaptation
4. Strategy composition from primitives
5. A/B testing of transferred strategies
6. Strategy versioning and evolution
7. Domain-specific strategy catalogs
8. Performance-based strategy ranking
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class StrategyDomain(str, Enum):
    WEB_APP = "web_app"
    API = "api"
    NETWORK = "network"
    INFRASTRUCTURE = "infrastructure"
    CODE = "code"
    CLOUD = "cloud"
    MOBILE = "mobile"
    IOT = "iot"


@dataclass
class TargetFingerprint:
    """Fingerprint of a target for matching."""
    technologies: list[str] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    has_waf: bool = False
    has_auth: bool = False
    domain: StrategyDomain = StrategyDomain.WEB_APP
    complexity: float = 0.5

    def to_dict(self) -> dict[str, Any]:
        return {
            "tech": self.technologies[:5],
            "ports": self.open_ports[:5],
            "services": self.services[:3],
            "waf": self.has_waf,
            "domain": self.domain.value,
        }


@dataclass
class LearnedStrategy:
    """A learned strategy that can be transferred."""
    strategy_id: str = ""
    name: str = ""
    domain: StrategyDomain = StrategyDomain.WEB_APP
    steps: list[dict[str, Any]] = field(default_factory=list)
    required_tools: list[str] = field(default_factory=list)
    recommended_models: list[str] = field(default_factory=list)
    fingerprint_match: TargetFingerprint = field(default_factory=TargetFingerprint)
    success_count: int = 0
    failure_count: int = 0
    avg_findings: float = 0.0
    avg_tokens: int = 0
    version: int = 1
    created_at: float = field(default_factory=time.time)
    last_used: float = 0.0

    @property
    def success_rate(self) -> float:
        total = self.success_count + self.failure_count
        if total == 0:
            return 0.5
        return self.success_count / total

    @property
    def effectiveness_score(self) -> float:
        """Score combining success rate, findings, and efficiency."""
        sr = self.success_rate
        findings_score = min(1.0, self.avg_findings / 5.0)
        efficiency = 1.0 / (1.0 + self.avg_tokens / 10000)
        return sr * 0.4 + findings_score * 0.4 + efficiency * 0.2

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.strategy_id,
            "name": self.name[:25],
            "domain": self.domain.value,
            "steps": len(self.steps),
            "success_rate": round(self.success_rate, 2),
            "effectiveness": round(self.effectiveness_score, 3),
            "version": self.version,
        }


@dataclass
class ABTest:
    """An A/B test between two strategies."""
    test_id: str = ""
    strategy_a_id: str = ""
    strategy_b_id: str = ""
    target_domain: StrategyDomain = StrategyDomain.WEB_APP
    results_a: list[float] = field(default_factory=list)
    results_b: list[float] = field(default_factory=list)
    min_samples: int = 5
    winner: str = ""

    @property
    def is_complete(self) -> bool:
        return len(self.results_a) >= self.min_samples and len(self.results_b) >= self.min_samples

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.test_id,
            "a": self.strategy_a_id[:15],
            "b": self.strategy_b_id[:15],
            "samples_a": len(self.results_a),
            "samples_b": len(self.results_b),
            "winner": self.winner[:15],
        }


# ── Default Strategy Library ──────────────────────────────────

DEFAULT_STRATEGIES: list[dict[str, Any]] = [
    {
        "name": "Standard web pentest",
        "domain": "web_app",
        "steps": [
            {"action": "subdomain_enum", "tool": "subfinder"},
            {"action": "port_scan", "tool": "nmap"},
            {"action": "http_probe", "tool": "httpx"},
            {"action": "tech_detect", "tool": "whatweb"},
            {"action": "dir_brute", "tool": "ffuf"},
            {"action": "vuln_scan", "tool": "nuclei"},
            {"action": "param_discovery", "tool": "arjun"},
            {"action": "xss_test", "tool": "dalfox"},
            {"action": "sqli_test", "tool": "sqlmap"},
        ],
        "tools": ["subfinder", "nmap", "httpx", "whatweb", "ffuf", "nuclei", "arjun", "dalfox", "sqlmap"],
        "models": ["whiterabbitneo-7b", "qwen-coder-14b"],
    },
    {
        "name": "API security assessment",
        "domain": "api",
        "steps": [
            {"action": "endpoint_discovery", "tool": "httpx"},
            {"action": "param_fuzz", "tool": "arjun"},
            {"action": "auth_test", "model": "whiterabbitneo-7b"},
            {"action": "injection_test", "tool": "sqlmap"},
            {"action": "rate_limit_test", "tool": "ffuf"},
        ],
        "tools": ["httpx", "arjun", "sqlmap", "ffuf"],
        "models": ["whiterabbitneo-7b"],
    },
    {
        "name": "Network infrastructure scan",
        "domain": "network",
        "steps": [
            {"action": "fast_scan", "tool": "masscan"},
            {"action": "service_detect", "tool": "nmap"},
            {"action": "vuln_scan", "tool": "nuclei"},
            {"action": "default_cred_check", "tool": "hydra"},
        ],
        "tools": ["masscan", "nmap", "nuclei", "hydra"],
        "models": ["hermes-14b"],
    },
    {
        "name": "Source code audit",
        "domain": "code",
        "steps": [
            {"action": "sast_scan", "tool": "semgrep"},
            {"action": "dep_audit", "tool": "trivy"},
            {"action": "python_check", "tool": "bandit"},
            {"action": "deep_review", "model": "qwen-coder-14b"},
            {"action": "long_file_review", "model": "yi-9b-200k"},
        ],
        "tools": ["semgrep", "trivy", "bandit"],
        "models": ["qwen-coder-14b", "yi-9b-200k"],
    },
]


class TransferLearning:
    """Reuses learned strategies across different targets and tasks.

    Maintains a library of effective strategies and matches
    them to new targets based on fingerprint similarity.
    """

    def __init__(self) -> None:
        self._strategies: dict[str, LearnedStrategy] = {}
        self._ab_tests: dict[str, ABTest] = {}
        self._strategy_counter = 0
        self._test_counter = 0
        self._log = logger.bind(component="transfer_learning")

        self._initialize_library()

    def _initialize_library(self) -> None:
        """Initialize default strategy library."""
        for data in DEFAULT_STRATEGIES:
            self._strategy_counter += 1
            strategy = LearnedStrategy(
                strategy_id=f"strat-{self._strategy_counter}",
                name=data["name"],
                domain=StrategyDomain(data["domain"]),
                steps=data["steps"],
                required_tools=data.get("tools", []),
                recommended_models=data.get("models", []),
            )
            self._strategies[strategy.strategy_id] = strategy

    def find_strategy(
        self,
        fingerprint: TargetFingerprint,
        limit: int = 3,
    ) -> list[LearnedStrategy]:
        """Find the best strategies for a target fingerprint."""
        scored: list[tuple[float, LearnedStrategy]] = []

        for strategy in self._strategies.values():
            score = self._match_score(strategy, fingerprint)
            if score > 0:
                scored.append((score, strategy))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [s for _, s in scored[:limit]]

    def _match_score(
        self,
        strategy: LearnedStrategy,
        fingerprint: TargetFingerprint,
    ) -> float:
        """Score how well a strategy matches a fingerprint."""
        score = 0.0

        # Domain match
        if strategy.domain == fingerprint.domain:
            score += 0.4

        # Technology overlap
        fp = strategy.fingerprint_match
        if fp.technologies and fingerprint.technologies:
            overlap = len(set(fp.technologies) & set(fingerprint.technologies))
            score += 0.2 * (overlap / max(1, len(fp.technologies)))

        # Performance history
        score += 0.3 * strategy.effectiveness_score

        # Recency bonus
        if strategy.last_used > 0:
            age_hours = (time.time() - strategy.last_used) / 3600
            recency = 1.0 / (1.0 + age_hours / 24)
            score += 0.1 * recency

        return score

    def record_outcome(
        self,
        strategy_id: str,
        success: bool,
        findings: int = 0,
        tokens_used: int = 0,
    ) -> None:
        """Record the outcome of using a strategy."""
        strategy = self._strategies.get(strategy_id)
        if not strategy:
            return

        if success:
            strategy.success_count += 1
        else:
            strategy.failure_count += 1

        n = strategy.success_count + strategy.failure_count
        strategy.avg_findings = ((n - 1) * strategy.avg_findings + findings) / n
        strategy.avg_tokens = int(((n - 1) * strategy.avg_tokens + tokens_used) / n)
        strategy.last_used = time.time()

    def create_strategy(
        self,
        name: str,
        domain: StrategyDomain,
        steps: list[dict[str, Any]],
        tools: list[str] | None = None,
        models: list[str] | None = None,
    ) -> LearnedStrategy:
        """Create a new strategy from experience."""
        self._strategy_counter += 1
        strategy = LearnedStrategy(
            strategy_id=f"strat-{self._strategy_counter}",
            name=name,
            domain=domain,
            steps=steps,
            required_tools=tools or [],
            recommended_models=models or [],
        )
        self._strategies[strategy.strategy_id] = strategy
        return strategy

    def start_ab_test(
        self,
        strategy_a_id: str,
        strategy_b_id: str,
        domain: StrategyDomain = StrategyDomain.WEB_APP,
    ) -> ABTest:
        """Start an A/B test between two strategies."""
        self._test_counter += 1
        test = ABTest(
            test_id=f"ab-{self._test_counter}",
            strategy_a_id=strategy_a_id,
            strategy_b_id=strategy_b_id,
            target_domain=domain,
        )
        self._ab_tests[test.test_id] = test
        return test

    def record_ab_result(
        self,
        test_id: str,
        variant: str,
        score: float,
    ) -> str | None:
        """Record A/B test result. Returns winner if test complete."""
        test = self._ab_tests.get(test_id)
        if not test or test.winner:
            return None

        if variant == "a":
            test.results_a.append(score)
        elif variant == "b":
            test.results_b.append(score)

        if test.is_complete:
            avg_a = sum(test.results_a) / len(test.results_a)
            avg_b = sum(test.results_b) / len(test.results_b)
            test.winner = test.strategy_a_id if avg_a >= avg_b else test.strategy_b_id
            return test.winner

        return None

    def get_stats(self) -> dict[str, Any]:
        domain_counts: dict[str, int] = defaultdict(int)
        for s in self._strategies.values():
            domain_counts[s.domain.value] += 1
        return {
            "strategies": len(self._strategies),
            "domains": dict(domain_counts),
            "ab_tests": len(self._ab_tests),
            "completed_tests": sum(1 for t in self._ab_tests.values() if t.winner),
        }
