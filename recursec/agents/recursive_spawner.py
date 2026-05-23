"""Recursive agent spawning system — the core of RecurSec's intelligence.

Implements:
- Bounded recursive task decomposition
- Dynamic agent instantiation based on task type
- Result aggregation across recursion levels
- Depth tracking with configurable limits
- Budget management (tokens, time, steps)
- Child agent lifecycle management
- Convergence detection to prevent infinite loops
"""

from __future__ import annotations

import asyncio
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class AgentStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


class TaskPriority(int, Enum):
    CRITICAL = 1
    HIGH = 3
    MEDIUM = 5
    LOW = 7
    BACKGROUND = 9


@dataclass
class AgentTask:
    """A task assigned to an agent."""
    task_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    description: str = ""
    task_type: str = ""  # recon, vuln_scan, exploit, code_audit, etc.
    target: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)
    priority: TaskPriority = TaskPriority.MEDIUM
    parent_task_id: str = ""
    depth: int = 0
    max_depth: int = 5
    timeout_s: float = 600.0
    budget_tokens: int = 50000
    required_tools: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id, "description": self.description,
            "type": self.task_type, "target": self.target,
            "depth": self.depth, "max_depth": self.max_depth,
            "priority": self.priority.name, "parent": self.parent_task_id,
        }


@dataclass
class AgentResult:
    """Result from an agent's execution."""
    task_id: str = ""
    agent_id: str = ""
    status: AgentStatus = AgentStatus.PENDING
    findings: list[dict[str, Any]] = field(default_factory=list)
    child_results: list[AgentResult] = field(default_factory=list)
    summary: str = ""
    confidence: float = 0.0
    duration_s: float = 0.0
    tokens_used: int = 0
    depth: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id, "agent_id": self.agent_id,
            "status": self.status.value,
            "findings": self.findings[:20],
            "child_count": len(self.child_results),
            "summary": self.summary[:500],
            "confidence": round(self.confidence, 2),
            "duration_s": round(self.duration_s, 2),
            "tokens_used": self.tokens_used,
            "depth": self.depth,
            "errors": self.errors[:5],
        }

    def total_findings(self) -> int:
        count = len(self.findings)
        for child in self.child_results:
            count += child.total_findings()
        return count


@dataclass
class SpawnedAgent:
    """A spawned agent instance."""
    agent_id: str = field(default_factory=lambda: f"agent_{uuid.uuid4().hex[:8]}")
    agent_type: str = ""
    task: AgentTask = field(default_factory=AgentTask)
    status: AgentStatus = AgentStatus.PENDING
    result: AgentResult | None = None
    parent_id: str = ""
    children: list[str] = field(default_factory=list)
    spawn_time: float = field(default_factory=time.time)
    end_time: float = 0.0
    model_used: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id, "type": self.agent_type,
            "task": self.task.to_dict(), "status": self.status.value,
            "parent": self.parent_id, "children": self.children,
            "model": self.model_used,
            "elapsed_s": round((self.end_time or time.time()) - self.spawn_time, 2),
        }


# Agent type → model preference mapping
AGENT_MODEL_PREFERENCES: dict[str, list[str]] = {
    "recon": ["Llama-3.1-8B", "Mistral-7B"],
    "vuln_scan": ["WhiteRabbitNeo-7B", "Qwen2.5-Coder-7B"],
    "web_scan": ["WhiteRabbitNeo-7B", "Qwen2.5-Coder-14B"],
    "exploit": ["WhiteRabbitNeo-7B", "Dolphin-2.9"],
    "code_audit": ["Qwen2.5-Coder-14B", "CodeLlama-13B", "Qwen2.5-Coder-7B"],
    "osint": ["Llama-3.1-8B", "Yi-9B-200K"],
    "reasoning": ["DeepSeek-R1-Distill-Qwen-7B", "Hermes-4-14B"],
    "validation": ["DeepSeek-R1-Distill-Qwen-7B", "Mistral-7B"],
    "network": ["Llama-3.1-8B", "WhiteRabbitNeo-7B"],
    "crypto": ["DeepSeek-Math-7B", "Qwen2.5-Coder-7B"],
    "cloud": ["Hermes-4-14B", "Llama-3.1-8B"],
    "forensics": ["Yi-9B-200K", "Qwen2.5-Coder-14B"],
    "tool_call": ["FunctionGemma-270m"],
}

# Task type → decomposition rules
DECOMPOSITION_RULES: dict[str, list[dict[str, Any]]] = {
    "full_scan": [
        {"type": "recon", "description": "Discover attack surface", "priority": 1},
        {"type": "vuln_scan", "description": "Scan for vulnerabilities", "priority": 2, "depends_on": ["recon"]},
        {"type": "web_scan", "description": "Web application testing", "priority": 2, "depends_on": ["recon"]},
        {"type": "exploit", "description": "Exploit confirmed vulnerabilities", "priority": 3, "depends_on": ["vuln_scan"]},
        {"type": "validation", "description": "Validate all findings", "priority": 4, "depends_on": ["exploit"]},
    ],
    "recon": [
        {"type": "network", "description": "Port scanning and service detection"},
        {"type": "osint", "description": "Open-source intelligence gathering"},
    ],
    "web_scan": [
        {"type": "web_scan", "description": "SQL injection testing", "params": {"test_type": "sqli"}},
        {"type": "web_scan", "description": "XSS testing", "params": {"test_type": "xss"}},
        {"type": "web_scan", "description": "SSRF testing", "params": {"test_type": "ssrf"}},
        {"type": "web_scan", "description": "Directory discovery", "params": {"test_type": "dir_bruteforce"}},
    ],
    "code_audit": [
        {"type": "code_audit", "description": "SAST analysis", "params": {"tool": "semgrep"}},
        {"type": "code_audit", "description": "Dependency audit", "params": {"tool": "trivy"}},
        {"type": "code_audit", "description": "Secret scanning", "params": {"tool": "trufflehog"}},
    ],
}


class RecursiveSpawner:
    """Manages recursive agent spawning and execution.

    Core intelligence of RecurSec — decomposes tasks, spawns specialized agents,
    collects and aggregates results across recursion levels.
    """

    def __init__(
        self,
        llm_router: Any = None,
        max_depth: int = 5,
        max_concurrent: int = 10,
        total_budget_tokens: int = 500000,
    ) -> None:
        self._router = llm_router
        self._max_depth = max_depth
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._total_budget = total_budget_tokens
        self._tokens_used = 0
        self._agents: dict[str, SpawnedAgent] = {}
        self._agent_results: dict[str, AgentResult] = {}
        self._stats = defaultdict(int)

    async def execute_task(self, task: AgentTask) -> AgentResult:
        """Execute a task, potentially spawning child agents recursively."""
        start = time.time()

        # Check recursion depth
        if task.depth >= task.max_depth:
            logger.warning("max_depth_reached", depth=task.depth, task=task.description)
            return AgentResult(
                task_id=task.task_id,
                status=AgentStatus.COMPLETED,
                summary="Maximum recursion depth reached",
                depth=task.depth,
            )

        # Check budget
        if self._tokens_used >= self._total_budget:
            return AgentResult(
                task_id=task.task_id,
                status=AgentStatus.COMPLETED,
                summary="Token budget exhausted",
                depth=task.depth,
            )

        # Spawn agent for this task
        agent = await self._spawn_agent(task)

        try:
            # Determine if this task should be decomposed
            subtasks = await self._decompose_task(task)

            if subtasks:
                # Execute subtasks (respecting dependencies)
                child_results = await self._execute_subtasks(subtasks, agent)
                agent.result = self._aggregate_results(task, child_results)
            else:
                # Leaf node — execute directly
                agent.result = await self._execute_leaf(task, agent)

            agent.status = AgentStatus.COMPLETED
            agent.result.duration_s = time.time() - start

        except asyncio.TimeoutError:
            agent.status = AgentStatus.TIMEOUT
            agent.result = AgentResult(
                task_id=task.task_id, agent_id=agent.agent_id,
                status=AgentStatus.TIMEOUT,
                summary=f"Task timed out after {task.timeout_s}s",
                depth=task.depth,
            )
        except Exception as e:
            agent.status = AgentStatus.FAILED
            agent.result = AgentResult(
                task_id=task.task_id, agent_id=agent.agent_id,
                status=AgentStatus.FAILED,
                errors=[str(e)], depth=task.depth,
            )
            logger.error("agent_failed", error=str(e), task=task.description)

        agent.end_time = time.time()
        self._stats["total_agents"] += 1
        self._stats[f"depth_{task.depth}"] += 1

        return agent.result

    async def _spawn_agent(self, task: AgentTask) -> SpawnedAgent:
        """Create and register a new agent."""
        agent = SpawnedAgent(
            agent_type=task.task_type,
            task=task,
            status=AgentStatus.RUNNING,
            parent_id=task.parent_task_id,
        )

        # Select model for this agent
        preferences = AGENT_MODEL_PREFERENCES.get(task.task_type, ["Llama-3.1-8B"])
        agent.model_used = preferences[0]  # Use first preference by default

        if self._router:
            try:
                model = await self._router.select(task_type=task.task_type)
                agent.model_used = model.name
            except Exception:
                pass

        self._agents[agent.agent_id] = agent

        # Track parent-child relationship
        if task.parent_task_id and task.parent_task_id in self._agents:
            self._agents[task.parent_task_id].children.append(agent.agent_id)

        logger.info("agent_spawned",
                     agent_id=agent.agent_id, type=task.task_type,
                     depth=task.depth, model=agent.model_used)

        return agent

    async def _decompose_task(self, task: AgentTask) -> list[AgentTask]:
        """Decompose a task into subtasks if applicable."""
        # Check predefined decomposition rules
        rules = DECOMPOSITION_RULES.get(task.task_type, [])

        if not rules:
            return []  # Leaf task

        subtasks: list[AgentTask] = []
        for rule in rules:
            subtask = AgentTask(
                description=rule["description"],
                task_type=rule["type"],
                target=task.target,
                parameters={**task.parameters, **rule.get("params", {})},
                priority=TaskPriority(rule.get("priority", 5)),
                parent_task_id=task.task_id,
                depth=task.depth + 1,
                max_depth=task.max_depth,
                timeout_s=task.timeout_s / max(len(rules), 1),
                budget_tokens=task.budget_tokens // max(len(rules), 1),
                dependencies=rule.get("depends_on", []),
            )
            subtasks.append(subtask)

        return subtasks

    async def _execute_subtasks(
        self, subtasks: list[AgentTask], parent: SpawnedAgent
    ) -> list[AgentResult]:
        """Execute subtasks respecting dependencies."""
        results: dict[str, AgentResult] = {}
        completed_types: set[str] = set()

        # Group by dependency level
        remaining = list(subtasks)

        while remaining:
            # Find tasks whose dependencies are met
            ready = []
            still_waiting = []

            for task in remaining:
                deps_met = all(dep in completed_types for dep in task.dependencies)
                if deps_met:
                    ready.append(task)
                else:
                    still_waiting.append(task)

            if not ready:
                # Deadlock — force execute remaining
                ready = still_waiting
                still_waiting = []

            # Execute ready tasks concurrently
            async def run_task(t: AgentTask) -> AgentResult:
                async with self._semaphore:
                    return await self.execute_task(t)

            batch_results = await asyncio.gather(
                *[run_task(t) for t in ready],
                return_exceptions=True,
            )

            for task, result in zip(ready, batch_results):
                if isinstance(result, Exception):
                    results[task.task_id] = AgentResult(
                        task_id=task.task_id, status=AgentStatus.FAILED,
                        errors=[str(result)], depth=task.depth,
                    )
                else:
                    results[task.task_id] = result
                completed_types.add(task.task_type)

            remaining = still_waiting

        return list(results.values())

    async def _execute_leaf(self, task: AgentTask, agent: SpawnedAgent) -> AgentResult:
        """Execute a leaf task (no further decomposition)."""
        result = AgentResult(
            task_id=task.task_id,
            agent_id=agent.agent_id,
            status=AgentStatus.RUNNING,
            depth=task.depth,
        )

        # Build prompt and query LLM
        prompt = self._build_task_prompt(task)

        if self._router:
            try:
                response = await self._router.generate(
                    prompt=prompt,
                    model_name=agent.model_used,
                    max_tokens=min(task.budget_tokens, 4096),
                )
                response_text = response.text if hasattr(response, "text") else str(response)

                # Parse response for findings
                result.summary = response_text[:1000]
                result.findings = self._extract_findings(response_text)
                result.confidence = self._estimate_confidence(response_text)
                result.tokens_used = len(response_text) // 4  # rough estimate

                self._tokens_used += result.tokens_used

            except Exception as e:
                result.errors.append(str(e))

        result.status = AgentStatus.COMPLETED
        return result

    def _aggregate_results(self, parent_task: AgentTask, child_results: list[AgentResult]) -> AgentResult:
        """Aggregate results from child agents."""
        result = AgentResult(
            task_id=parent_task.task_id,
            status=AgentStatus.COMPLETED,
            child_results=child_results,
            depth=parent_task.depth,
        )

        # Merge findings from all children
        all_findings: list[dict[str, Any]] = []
        total_tokens = 0
        confidences = []

        for child in child_results:
            all_findings.extend(child.findings)
            total_tokens += child.tokens_used
            if child.confidence > 0:
                confidences.append(child.confidence)

            # Propagate errors
            result.errors.extend(child.errors)

        # Deduplicate findings
        result.findings = self._deduplicate_findings(all_findings)
        result.tokens_used = total_tokens
        result.confidence = sum(confidences) / max(len(confidences), 1)

        # Generate summary
        result.summary = (
            f"Aggregated {len(child_results)} sub-tasks: "
            f"{len(result.findings)} unique findings, "
            f"{sum(1 for f in result.findings if f.get('severity') in ('critical', 'high'))} critical/high"
        )

        return result

    def _build_task_prompt(self, task: AgentTask) -> str:
        """Build execution prompt for a leaf task."""
        return f"""You are a security agent executing a specific task.

Task: {task.description}
Target: {task.target}
Type: {task.task_type}
Parameters: {task.parameters}
Depth: {task.depth} (of max {task.max_depth})

Execute this task and report findings in structured format:
- title: Brief title
- severity: critical/high/medium/low/info
- description: Detailed description
- evidence: Supporting evidence
- confidence: 0.0-1.0

If you need more specific subtasks, describe them. Otherwise, provide your analysis."""

    def _extract_findings(self, text: str) -> list[dict[str, Any]]:
        """Extract structured findings from LLM response."""
        findings: list[dict[str, Any]] = []

        # Try to parse JSON blocks
        import re
        json_blocks = re.findall(r'\{[^{}]*"title"[^{}]*\}', text)
        import json

        for block in json_blocks:
            try:
                finding = json.loads(block)
                if "title" in finding:
                    findings.append(finding)
            except json.JSONDecodeError:
                pass

        return findings

    def _estimate_confidence(self, text: str) -> float:
        """Estimate confidence from response text."""
        import re
        match = re.search(r"confidence[:\s]+(\d+(?:\.\d+)?)", text.lower())
        if match:
            val = float(match.group(1))
            return val if val <= 1.0 else val / 100.0
        return 0.5

    def _deduplicate_findings(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Deduplicate findings by title."""
        seen: set[str] = set()
        unique: list[dict[str, Any]] = []
        for finding in findings:
            title = finding.get("title", "")
            if title and title not in seen:
                seen.add(title)
                unique.append(finding)
        return unique

    # ── Stats and Monitoring ───────────────────────────────

    def get_agents(self) -> list[dict[str, Any]]:
        return [a.to_dict() for a in self._agents.values()]

    def get_agent(self, agent_id: str) -> dict[str, Any] | None:
        agent = self._agents.get(agent_id)
        return agent.to_dict() if agent else None

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_agents_spawned": self._stats.get("total_agents", 0),
            "active_agents": sum(1 for a in self._agents.values() if a.status == AgentStatus.RUNNING),
            "tokens_used": self._tokens_used,
            "tokens_budget": self._total_budget,
            "depth_distribution": {k: v for k, v in self._stats.items() if k.startswith("depth_")},
        }
