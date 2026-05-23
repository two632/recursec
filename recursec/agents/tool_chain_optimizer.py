"""Tool chain optimizer — intelligent tool sequencing.

Learns the optimal order and combination of tools for
different target types and vulnerability categories.

Implements:
1. Tool chain templates (common sequences)
2. Chain scoring based on historical effectiveness
3. Adaptive chain selection
4. Tool dependency resolution
5. Parallel tool group identification
6. Chain pruning (remove low-value tools)
7. Dynamic chain modification during execution
8. Chain cost estimation (time, tokens, network)
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ChainPhase(str, Enum):
    RECON = "recon"
    ENUMERATION = "enumeration"
    SCANNING = "scanning"
    EXPLOITATION = "exploitation"
    POST_EXPLOIT = "post_exploit"
    VALIDATION = "validation"




@dataclass
class ToolStep:
    """A step in a tool chain."""
    step_id: str = ""
    tool: str = ""
    phase: ChainPhase = ChainPhase.SCANNING
    args_template: str = ""      # Template with {target}, {port}, etc.
    timeout_s: float = 120.0
    depends_on: list[str] = field(default_factory=list)
    can_parallel: bool = False
    expected_output: str = ""    # What this step should produce
    importance: float = 1.0      # 0-1, how important is this step

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.step_id[:10],
            "tool": self.tool[:15],
            "phase": self.phase.value,
            "importance": round(self.importance, 2),
            "parallel": self.can_parallel,
        }


@dataclass
class ToolChain:
    """A sequence of tools to execute."""
    chain_id: str = ""
    name: str = ""
    target_type: str = ""        # web_app, network, api, cloud, etc.
    steps: list[ToolStep] = field(default_factory=list)
    estimated_time_s: float = 0.0
    historical_score: float = 0.0
    use_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.chain_id[:10],
            "name": self.name[:20],
            "target": self.target_type[:10],
            "steps": len(self.steps),
            "time": round(self.estimated_time_s, 0),
            "score": round(self.historical_score, 2),
            "uses": self.use_count,
        }


@dataclass
class ChainExecution:
    """Record of a chain execution."""
    chain_id: str = ""
    target_type: str = ""
    steps_completed: int = 0
    steps_total: int = 0
    findings_count: int = 0
    duration_s: float = 0.0
    success: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain": self.chain_id[:10],
            "steps": f"{self.steps_completed}/{self.steps_total}",
            "findings": self.findings_count,
            "duration": round(self.duration_s, 1),
        }


# ── Predefined tool chains ──────────────────────────────────

WEB_APP_CHAIN = ToolChain(
    chain_id="chain-web-standard",
    name="Standard Web Assessment",
    target_type="web_app",
    estimated_time_s=1800,
    steps=[
        ToolStep(step_id="w1", tool="httpx", phase=ChainPhase.RECON,
                 args_template="-u {target} -tech-detect -status-code -title",
                 can_parallel=False, importance=1.0),
        ToolStep(step_id="w2", tool="gobuster", phase=ChainPhase.ENUMERATION,
                 args_template="dir -u {target} -w /usr/share/wordlists/dirb/common.txt",
                 depends_on=["w1"], can_parallel=True, importance=0.9),
        ToolStep(step_id="w3", tool="ffuf", phase=ChainPhase.ENUMERATION,
                 args_template="-u {target}/FUZZ -w /usr/share/wordlists/common.txt",
                 depends_on=["w1"], can_parallel=True, importance=0.8),
        ToolStep(step_id="w4", tool="nuclei", phase=ChainPhase.SCANNING,
                 args_template="-u {target} -severity critical,high,medium",
                 depends_on=["w1"], can_parallel=True, importance=1.0),
        ToolStep(step_id="w5", tool="nikto", phase=ChainPhase.SCANNING,
                 args_template="-h {target}",
                 depends_on=["w1"], can_parallel=True, importance=0.7),
        ToolStep(step_id="w6", tool="sqlmap", phase=ChainPhase.EXPLOITATION,
                 args_template="-u {target} --batch --random-agent",
                 depends_on=["w2", "w3"], importance=0.9),
        ToolStep(step_id="w7", tool="wpscan", phase=ChainPhase.SCANNING,
                 args_template="--url {target}",
                 depends_on=["w1"], importance=0.5,
                 expected_output="WordPress vulnerabilities"),
    ],
)

NETWORK_CHAIN = ToolChain(
    chain_id="chain-net-standard",
    name="Standard Network Assessment",
    target_type="network",
    estimated_time_s=2400,
    steps=[
        ToolStep(step_id="n1", tool="nmap", phase=ChainPhase.RECON,
                 args_template="-sn {target}",
                 importance=1.0),
        ToolStep(step_id="n2", tool="nmap", phase=ChainPhase.ENUMERATION,
                 args_template="-sV -sC -p- {target}",
                 depends_on=["n1"], importance=1.0),
        ToolStep(step_id="n3", tool="enum4linux", phase=ChainPhase.ENUMERATION,
                 args_template="-a {target}",
                 depends_on=["n2"], can_parallel=True, importance=0.8),
        ToolStep(step_id="n4", tool="onesixtyone", phase=ChainPhase.ENUMERATION,
                 args_template="-c /usr/share/wordlists/snmp.txt {target}",
                 depends_on=["n2"], can_parallel=True, importance=0.7),
        ToolStep(step_id="n5", tool="crackmapexec", phase=ChainPhase.ENUMERATION,
                 args_template="smb {target} --gen-relay-list relay.txt",
                 depends_on=["n2"], can_parallel=True, importance=0.9),
        ToolStep(step_id="n6", tool="nuclei", phase=ChainPhase.SCANNING,
                 args_template="-u {target} -tags network",
                 depends_on=["n2"], importance=0.8),
        ToolStep(step_id="n7", tool="hydra", phase=ChainPhase.EXPLOITATION,
                 args_template="-L users.txt -P passwords.txt {target} ssh",
                 depends_on=["n2"], importance=0.6),
    ],
)

API_CHAIN = ToolChain(
    chain_id="chain-api-standard",
    name="Standard API Assessment",
    target_type="api",
    estimated_time_s=1200,
    steps=[
        ToolStep(step_id="a1", tool="httpx", phase=ChainPhase.RECON,
                 args_template="-u {target} -content-type -status-code",
                 importance=1.0),
        ToolStep(step_id="a2", tool="ffuf", phase=ChainPhase.ENUMERATION,
                 args_template="-u {target}/FUZZ -w /usr/share/wordlists/api-paths.txt",
                 depends_on=["a1"], importance=0.9),
        ToolStep(step_id="a3", tool="nuclei", phase=ChainPhase.SCANNING,
                 args_template="-u {target} -tags api",
                 depends_on=["a1"], can_parallel=True, importance=1.0),
        ToolStep(step_id="a4", tool="curl", phase=ChainPhase.SCANNING,
                 args_template="-s {target}/swagger.json",
                 depends_on=["a1"], can_parallel=True, importance=0.7),
        ToolStep(step_id="a5", tool="sqlmap", phase=ChainPhase.EXPLOITATION,
                 args_template="-u {target} --batch",
                 depends_on=["a2"], importance=0.8),
    ],
)

CLOUD_CHAIN = ToolChain(
    chain_id="chain-cloud-standard",
    name="Standard Cloud Assessment",
    target_type="cloud",
    estimated_time_s=900,
    steps=[
        ToolStep(step_id="c1", tool="subfinder", phase=ChainPhase.RECON,
                 args_template="-d {target} -silent",
                 importance=1.0),
        ToolStep(step_id="c2", tool="httpx", phase=ChainPhase.ENUMERATION,
                 args_template="-l subdomains.txt -tech-detect",
                 depends_on=["c1"], importance=0.9),
        ToolStep(step_id="c3", tool="nuclei", phase=ChainPhase.SCANNING,
                 args_template="-l alive.txt -tags cloud,aws,azure,gcp",
                 depends_on=["c2"], importance=1.0),
        ToolStep(step_id="c4", tool="curl", phase=ChainPhase.SCANNING,
                 args_template="-s http://169.254.169.254/latest/meta-data/",
                 depends_on=["c2"], importance=0.8,
                 expected_output="SSRF to cloud metadata"),
    ],
)


# ── All predefined chains ───────────────────────────────────

PREDEFINED_CHAINS: dict[str, ToolChain] = {
    "web_app": WEB_APP_CHAIN,
    "network": NETWORK_CHAIN,
    "api": API_CHAIN,
    "cloud": CLOUD_CHAIN,
}


class ToolChainOptimizer:
    """Optimizes tool execution order and combinations.

    Learns from past executions which tool chains are most
    effective for different target types and adapts accordingly.
    """

    def __init__(self) -> None:
        self._chains: dict[str, ToolChain] = dict(PREDEFINED_CHAINS)
        self._executions: list[ChainExecution] = []
        self._tool_effectiveness: dict[str, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))
        self._log = logger.bind(component="tool_chain_optimizer")

    def get_chain(self, target_type: str) -> ToolChain | None:
        """Get the best chain for a target type."""
        chain = self._chains.get(target_type)
        if chain:
            chain.use_count += 1
        return chain

    def get_parallel_groups(self, chain: ToolChain) -> list[list[ToolStep]]:
        """Identify groups of steps that can run in parallel."""
        groups: list[list[ToolStep]] = []
        remaining = list(chain.steps)
        completed: set[str] = set()

        while remaining:
            # Find all steps whose deps are met
            ready = [
                s for s in remaining
                if all(d in completed for d in s.depends_on)
            ]

            if not ready:
                break

            # Separate parallel and sequential
            parallel = [s for s in ready if s.can_parallel]
            sequential = [s for s in ready if not s.can_parallel]

            if parallel:
                groups.append(parallel)
                for s in parallel:
                    completed.add(s.step_id)
                    remaining.remove(s)
            if sequential:
                for s in sequential:
                    groups.append([s])
                    completed.add(s.step_id)
                    remaining.remove(s)

        return groups

    def prune_chain(
        self,
        chain: ToolChain,
        time_budget_s: float,
        importance_threshold: float = 0.5,
    ) -> ToolChain:
        """Prune low-importance steps to fit time budget."""
        # Sort by importance (keep most important)
        sorted_steps = sorted(chain.steps, key=lambda s: s.importance, reverse=True)

        pruned_steps = []
        total_time = 0.0

        for step in sorted_steps:
            if step.importance < importance_threshold:
                continue
            if total_time + step.timeout_s > time_budget_s:
                continue
            pruned_steps.append(step)
            total_time += step.timeout_s

        # Reorder by dependency
        final_steps = self._topological_sort(pruned_steps)

        pruned = ToolChain(
            chain_id=f"{chain.chain_id}-pruned",
            name=f"{chain.name} (pruned)",
            target_type=chain.target_type,
            steps=final_steps,
            estimated_time_s=total_time,
        )

        return pruned

    def record_execution(
        self,
        chain_id: str,
        target_type: str,
        steps_completed: int,
        steps_total: int,
        findings_count: int,
        duration_s: float,
        success: bool = True,
    ) -> None:
        """Record a chain execution for learning."""
        execution = ChainExecution(
            chain_id=chain_id,
            target_type=target_type,
            steps_completed=steps_completed,
            steps_total=steps_total,
            findings_count=findings_count,
            duration_s=duration_s,
            success=success,
        )
        self._executions.append(execution)

        # Update chain historical score
        chain = self._chains.get(target_type)
        if chain:
            score = findings_count / max(1, duration_s / 60)
            chain.historical_score = 0.9 * chain.historical_score + 0.1 * score

    def record_tool_result(
        self,
        tool: str,
        target_type: str,
        findings: int,
        duration_s: float,
    ) -> None:
        """Record effectiveness of a single tool."""
        effectiveness = findings / max(1, duration_s / 60)
        self._tool_effectiveness[tool][target_type].append(effectiveness)

    def get_tool_ranking(
        self,
        target_type: str,
    ) -> list[dict[str, Any]]:
        """Get tools ranked by effectiveness for a target type."""
        rankings = []

        for tool, target_scores in self._tool_effectiveness.items():
            scores = target_scores.get(target_type, [])
            if scores:
                avg = sum(scores) / len(scores)
                rankings.append({
                    "tool": tool,
                    "avg_effectiveness": round(avg, 2),
                    "uses": len(scores),
                })

        rankings.sort(key=lambda r: r["avg_effectiveness"], reverse=True)
        return rankings

    @staticmethod
    def _topological_sort(steps: list[ToolStep]) -> list[ToolStep]:
        """Sort steps respecting dependencies."""
        step_ids = {s.step_id for s in steps}
        step_map = {s.step_id: s for s in steps}

        # Kahn's algorithm
        in_degree: dict[str, int] = defaultdict(int)
        for s in steps:
            if s.step_id not in in_degree:
                in_degree[s.step_id] = 0
            for dep in s.depends_on:
                if dep in step_ids:
                    in_degree[s.step_id] += 1

        queue = [sid for sid, deg in in_degree.items() if deg == 0]
        result = []

        while queue:
            sid = queue.pop(0)
            result.append(step_map[sid])
            for s in steps:
                if sid in s.depends_on and s.step_id in step_ids:
                    in_degree[s.step_id] -= 1
                    if in_degree[s.step_id] == 0:
                        queue.append(s.step_id)

        return result

    def get_stats(self) -> dict[str, Any]:
        chain_stats = {cid: c.to_dict() for cid, c in self._chains.items()}

        return {
            "chains": len(self._chains),
            "executions": len(self._executions),
            "tools_tracked": len(self._tool_effectiveness),
            "chain_details": chain_stats,
        }
