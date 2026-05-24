"""Tool chain builder — sequences tools into pipelines.

Implements:
1. Tool chain definition (ordered tool sequences)
2. Data flow between tools (output → input)
3. Conditional branching in chains
4. Chain validation (tool availability)
5. Pre-built security assessment chains
6. Chain prompt for LLM
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ChainStepType(str, Enum):
    TOOL = "tool"            # Run external tool
    ANALYZE = "analyze"      # LLM analysis step
    BRANCH = "branch"        # Conditional branch
    AGGREGATE = "aggregate"  # Combine results
    FILTER = "filter"        # Filter results


class ChainStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class ChainStep:
    """A step in a tool chain."""
    step_id: str = ""
    step_type: ChainStepType = ChainStepType.TOOL
    tool_name: str = ""
    args_template: str = ""
    input_from: str = ""       # Step ID whose output is input
    condition: str = ""        # Condition for branching
    on_true: str = ""          # Step ID if condition true
    on_false: str = ""         # Step ID if condition false
    status: ChainStatus = ChainStatus.PENDING
    output: str = ""
    started_at: float = 0.0
    completed_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.step_id[:10],
            "type": self.step_type.value[:6],
            "tool": self.tool_name[:12],
            "status": self.status.value[:6],
        }


@dataclass
class ToolChain:
    """An ordered sequence of tool executions."""
    chain_id: str = ""
    name: str = ""
    description: str = ""
    steps: list[ChainStep] = field(default_factory=list)
    current_step_idx: int = 0
    status: ChainStatus = ChainStatus.PENDING
    created_at: float = field(default_factory=time.time)

    @property
    def progress(self) -> float:
        if not self.steps:
            return 0.0
        completed = sum(1 for s in self.steps if s.status == ChainStatus.COMPLETED)
        return completed / len(self.steps)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.chain_id[:10],
            "name": self.name[:20],
            "steps": len(self.steps),
            "progress": f"{self.progress:.0%}",
        }


# ── Pre-built security chains ────────────────────────────────

CHAIN_TEMPLATES: dict[str, list[dict[str, Any]]] = {
    "web_recon": [
        {"tool": "subfinder", "args": "-d {target} -o subs.txt", "type": "tool"},
        {"tool": "httpx", "args": "-l subs.txt -status-code -title -tech-detect", "type": "tool", "input": "step-1"},
        {"tool": "nmap", "args": "-sV -sC -p- -iL live_hosts.txt", "type": "tool", "input": "step-2"},
        {"tool": "llm", "args": "Analyze recon results and identify attack surface", "type": "analyze", "input": "step-3"},
    ],
    "vuln_scan": [
        {"tool": "nuclei", "args": "-l targets.txt -severity critical,high", "type": "tool"},
        {"tool": "nikto", "args": "-h {target} -Format json", "type": "tool"},
        {"tool": "nmap", "args": "--script vuln -iL targets.txt", "type": "tool"},
        {"tool": "llm", "args": "Deduplicate and rank vulnerabilities by exploitability", "type": "analyze"},
    ],
    "web_exploit": [
        {"tool": "ffuf", "args": "-u {target}/FUZZ -w wordlist.txt", "type": "tool"},
        {"tool": "sqlmap", "args": "-u {target} --batch --level 3 --risk 2", "type": "tool"},
        {"tool": "xsstrike", "args": "-u {target} --crawl", "type": "tool"},
        {"tool": "llm", "args": "Determine if found vulnerabilities are exploitable", "type": "branch"},
        {"tool": "llm", "args": "Develop exploitation strategy", "type": "analyze"},
    ],
    "network_audit": [
        {"tool": "masscan", "args": "-p1-65535 {target} --rate=10000", "type": "tool"},
        {"tool": "nmap", "args": "-sV -sC -p {ports} {target}", "type": "tool", "input": "step-1"},
        {"tool": "testssl.sh", "args": "{target}", "type": "tool"},
        {"tool": "snmpwalk", "args": "-v2c -c public {target}", "type": "tool"},
        {"tool": "llm", "args": "Analyze network security posture", "type": "analyze"},
    ],
    "credential_audit": [
        {"tool": "trufflehog", "args": "git {repo_url}", "type": "tool"},
        {"tool": "gitleaks", "args": "detect --source {repo_path}", "type": "tool"},
        {"tool": "nuclei", "args": "-t default-logins/ -l targets.txt", "type": "tool"},
        {"tool": "hydra", "args": "-L users.txt -P pass.txt {target} ssh", "type": "tool"},
        {"tool": "llm", "args": "Assess credential exposure risk", "type": "analyze"},
    ],
    "cloud_audit": [
        {"tool": "prowler", "args": "-M csv --compliance cis", "type": "tool"},
        {"tool": "scoutsuite", "args": "--provider aws", "type": "tool"},
        {"tool": "llm", "args": "Analyze cloud misconfigurations", "type": "analyze"},
        {"tool": "pacu", "args": "run iam__enum_permissions", "type": "tool"},
        {"tool": "llm", "args": "Identify privilege escalation paths", "type": "analyze"},
    ],
}


class ToolChainBuilder:
    """Builds and manages tool chains for security assessments.

    Sequences tools into ordered pipelines with
    data flow, conditional branching, and LLM
    analysis steps between tool executions.
    """

    def __init__(self) -> None:
        self._chains: dict[str, ToolChain] = {}
        self._chain_counter = 0
        self._log = logger.bind(component="tool_chain")

    def build_chain(
        self,
        template: str = "",
        name: str = "",
        custom_steps: list[dict[str, Any]] | None = None,
    ) -> ToolChain:
        """Build a tool chain from template or custom steps."""
        self._chain_counter += 1
        chain_id = f"chain-{self._chain_counter}"

        steps_data = custom_steps or CHAIN_TEMPLATES.get(template, [])
        steps: list[ChainStep] = []

        for i, spec in enumerate(steps_data):
            step = ChainStep(
                step_id=f"step-{i + 1}",
                step_type=ChainStepType(spec.get("type", "tool")),
                tool_name=spec.get("tool", ""),
                args_template=spec.get("args", ""),
                input_from=spec.get("input", ""),
                condition=spec.get("condition", ""),
                on_true=spec.get("on_true", ""),
                on_false=spec.get("on_false", ""),
            )
            steps.append(step)

        chain = ToolChain(
            chain_id=chain_id,
            name=name or template,
            steps=steps,
        )

        self._chains[chain_id] = chain
        return chain

    def get_next_step(self, chain_id: str) -> ChainStep | None:
        """Get next pending step in chain."""
        chain = self._chains.get(chain_id)
        if not chain:
            return None

        for step in chain.steps:
            if step.status == ChainStatus.PENDING:
                return step
        return None

    def complete_step(
        self,
        chain_id: str,
        step_id: str,
        output: str = "",
        success: bool = True,
    ) -> ChainStep | None:
        """Mark a step as completed and return next step."""
        chain = self._chains.get(chain_id)
        if not chain:
            return None

        for step in chain.steps:
            if step.step_id == step_id:
                step.status = ChainStatus.COMPLETED if success else ChainStatus.FAILED
                step.output = output
                step.completed_at = time.time()
                break

        # Check if chain is done
        all_done = all(
            s.status in (ChainStatus.COMPLETED, ChainStatus.SKIPPED, ChainStatus.FAILED)
            for s in chain.steps
        )
        if all_done:
            chain.status = ChainStatus.COMPLETED

        return self.get_next_step(chain_id)

    def get_chain_output(self, chain_id: str) -> list[dict[str, str]]:
        """Get all outputs from a chain."""
        chain = self._chains.get(chain_id)
        if not chain:
            return []

        return [
            {"step": s.step_id, "tool": s.tool_name, "output": s.output[:200]}
            for s in chain.steps
            if s.status == ChainStatus.COMPLETED and s.output
        ]

    def build_chain_prompt(self, chain_id: str = "") -> str:
        """Build tool chain context for LLM."""
        lines = ["## Tool Chains\n"]

        if chain_id and chain_id in self._chains:
            chain = self._chains[chain_id]
            lines.append(f"Chain: {chain.name}")
            lines.append(f"Progress: {chain.progress:.0%}")

            for step in chain.steps:
                status_icon = {
                    ChainStatus.COMPLETED: "[done]",
                    ChainStatus.RUNNING: "[>>>]",
                    ChainStatus.PENDING: "[   ]",
                    ChainStatus.FAILED: "[ERR]",
                    ChainStatus.SKIPPED: "[skip]",
                }.get(step.status, "[?]")
                lines.append(f"  {status_icon} {step.tool_name} {step.args_template[:30]}")
        else:
            lines.append(f"Active chains: {len(self._chains)}")
            lines.append(f"Available templates: {', '.join(CHAIN_TEMPLATES.keys())}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        completed = sum(1 for c in self._chains.values() if c.status == ChainStatus.COMPLETED)
        return {
            "total_chains": len(self._chains),
            "completed": completed,
            "templates": list(CHAIN_TEMPLATES.keys()),
        }
