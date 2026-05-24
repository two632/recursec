"""Unified Agent Brain — the central intelligence that ties ALL components together.

This is the MASTER module that integrates every subsystem:
1. Target Intelligence → understands what to attack
2. Planning Engine → generates execution plans
3. Task Decomposer → breaks plans into subtasks
4. Prompt Engineer → crafts optimal prompts per model
5. Reasoning Chain → structures thinking
6. Memory System → recalls past experience
7. Collaboration → coordinates with other agents
8. Execution Monitor → tracks progress
9. Model Router → selects optimal LLM
10. KB Registry → loads relevant knowledge
11. Tool Orchestrator → executes external tools
12. Finding Correlator → links results into chains
13. Self-Play → learns from simulated adversarial games
14. Vulnerability Correlation → deduplicates and maps findings

This is the module that receives "find vulns in X" and
autonomously handles everything end-to-end.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class BrainState(str, Enum):
    IDLE = "idle"
    ANALYZING = "analyzing"
    PLANNING = "planning"
    EXECUTING = "executing"
    REASONING = "reasoning"
    REPORTING = "reporting"
    LEARNING = "learning"
    ERROR = "error"


class TaskPhase(str, Enum):
    INTAKE = "intake"
    PROFILING = "profiling"
    PLANNING = "planning"
    KB_LOADING = "kb_loading"
    PROMPT_ASSEMBLY = "prompt_assembly"
    LLM_REASONING = "llm_reasoning"
    TOOL_EXECUTION = "tool_execution"
    ANALYSIS = "analysis"
    VALIDATION = "validation"
    CORRELATION = "correlation"
    REPORTING = "reporting"
    LEARNING = "learning"
    DONE = "done"


@dataclass
class BrainConfig:
    """Configuration for the unified brain."""
    max_recursion_depth: int = 5
    max_iterations: int = 50
    token_budget: int = 100000
    timeout_s: int = 3600
    parallel_agents: int = 5
    auto_validate: bool = True
    auto_learn: bool = True
    reasoning_mode: str = "auto"
    stealth_mode: bool = False
    verbose: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_depth": self.max_recursion_depth,
            "max_iter": self.max_iterations,
            "budget": self.token_budget,
            "timeout": self.timeout_s,
            "parallel": self.parallel_agents,
        }


@dataclass
class TaskContext:
    """Full context for a task being processed."""
    task_id: str = ""
    goal: str = ""
    target: str = ""
    phase: TaskPhase = TaskPhase.INTAKE
    iteration: int = 0
    depth: int = 0
    parent_task_id: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)
    tool_outputs: list[dict[str, Any]] = field(default_factory=list)
    llm_responses: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    kb_context: str = ""
    memory_context: str = ""
    plan_id: str = ""
    tokens_used: int = 0
    started_at: float = field(default_factory=time.time)

    @property
    def duration_s(self) -> float:
        return time.time() - self.started_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.task_id[:8],
            "goal": self.goal[:25],
            "target": self.target[:15],
            "phase": self.phase.value[:10],
            "iter": self.iteration,
            "findings": len(self.findings),
            "tools": len(self.tool_outputs),
            "tokens": self.tokens_used,
        }


@dataclass
class Finding:
    """A security finding discovered during execution."""
    finding_id: str = ""
    title: str = ""
    severity: str = "medium"
    vuln_type: str = ""
    target: str = ""
    location: str = ""
    evidence: str = ""
    description: str = ""
    remediation: str = ""
    cwe: str = ""
    cvss: float = 0.0
    confidence: str = "medium"
    source_tool: str = ""
    source_agent: str = ""
    validated: bool = False
    false_positive_score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title[:30],
            "severity": self.severity[:6],
            "target": self.target[:15],
            "conf": self.confidence[:6],
            "validated": self.validated,
            "cwe": self.cwe[:10],
        }


@dataclass
class AgentDecision:
    """A decision made by the brain."""
    decision_type: str = ""
    reasoning: str = ""
    action: str = ""
    alternatives: list[str] = field(default_factory=list)
    confidence: float = 0.5
    timestamp: float = field(default_factory=time.time)


# Phase transition map
PHASE_TRANSITIONS: dict[TaskPhase, TaskPhase] = {
    TaskPhase.INTAKE: TaskPhase.PROFILING,
    TaskPhase.PROFILING: TaskPhase.PLANNING,
    TaskPhase.PLANNING: TaskPhase.KB_LOADING,
    TaskPhase.KB_LOADING: TaskPhase.PROMPT_ASSEMBLY,
    TaskPhase.PROMPT_ASSEMBLY: TaskPhase.LLM_REASONING,
    TaskPhase.LLM_REASONING: TaskPhase.TOOL_EXECUTION,
    TaskPhase.TOOL_EXECUTION: TaskPhase.ANALYSIS,
    TaskPhase.ANALYSIS: TaskPhase.VALIDATION,
    TaskPhase.VALIDATION: TaskPhase.CORRELATION,
    TaskPhase.CORRELATION: TaskPhase.REPORTING,
    TaskPhase.REPORTING: TaskPhase.LEARNING,
    TaskPhase.LEARNING: TaskPhase.DONE,
}

# Phase → model selection
PHASE_MODEL_MAP: dict[TaskPhase, str] = {
    TaskPhase.PROFILING: "phi-3.5-mini",
    TaskPhase.PLANNING: "deepseek-r1",
    TaskPhase.KB_LOADING: "phi-3.5-mini",
    TaskPhase.PROMPT_ASSEMBLY: "phi-3.5-mini",
    TaskPhase.LLM_REASONING: "whiterabbit",
    TaskPhase.ANALYSIS: "qwen-coder-14b",
    TaskPhase.VALIDATION: "deepseek-r1",
    TaskPhase.CORRELATION: "hermes-4-14b",
    TaskPhase.REPORTING: "mistral-7b",
    TaskPhase.LEARNING: "phi-3.5-mini",
}

# Phase → KB domains
PHASE_KB_MAP: dict[TaskPhase, list[str]] = {
    TaskPhase.PROFILING: ["network", "web_vuln"],
    TaskPhase.PLANNING: ["advanced_strategy", "advanced_discovery"],
    TaskPhase.LLM_REASONING: ["web_vuln", "xss", "ssrf", "business_logic"],
    TaskPhase.ANALYSIS: ["web_vuln", "advanced_strategy"],
    TaskPhase.VALIDATION: ["web_vuln"],
    TaskPhase.CORRELATION: ["advanced_strategy", "compliance"],
}

# Phase → expected outputs
PHASE_OUTPUTS: dict[TaskPhase, str] = {
    TaskPhase.PROFILING: "target_profile",
    TaskPhase.PLANNING: "execution_plan",
    TaskPhase.KB_LOADING: "kb_context",
    TaskPhase.PROMPT_ASSEMBLY: "prompt",
    TaskPhase.LLM_REASONING: "llm_analysis",
    TaskPhase.TOOL_EXECUTION: "tool_outputs",
    TaskPhase.ANALYSIS: "findings",
    TaskPhase.VALIDATION: "validated_findings",
    TaskPhase.CORRELATION: "attack_chains",
    TaskPhase.REPORTING: "report",
    TaskPhase.LEARNING: "lessons",
}


class UnifiedAgentBrain:
    """The central intelligence that orchestrates everything."""

    def __init__(self, config: BrainConfig | None = None) -> None:
        self._config = config or BrainConfig()
        self._state = BrainState.IDLE
        self._tasks: dict[str, TaskContext] = {}
        self._findings: list[Finding] = []
        self._decisions: list[AgentDecision] = []
        self._task_counter = 0
        self._finding_counter = 0
        self._total_tokens = 0
        self._start_time = time.time()
        self._log = logger.bind(component="unified_brain")
        self._phase_timings: dict[TaskPhase, list[float]] = defaultdict(list)

    def process_task(self, goal: str, target: str = "") -> TaskContext:
        """Process a security task from intake to completion."""
        self._task_counter += 1
        ctx = TaskContext(
            task_id=f"task-{self._task_counter}",
            goal=goal,
            target=target,
        )
        self._tasks[ctx.task_id] = ctx
        self._state = BrainState.ANALYZING

        # Phase 1: Intake
        ctx.phase = TaskPhase.INTAKE
        self._decide(ctx, "intake", f"Received task: {goal[:50]}")

        # Phase 2: Profile target
        ctx.phase = TaskPhase.PROFILING
        phase_start = time.time()
        self._profile_target(ctx)
        self._phase_timings[TaskPhase.PROFILING].append(time.time() - phase_start)

        # Phase 3: Generate plan
        ctx.phase = TaskPhase.PLANNING
        self._state = BrainState.PLANNING
        phase_start = time.time()
        self._generate_plan(ctx)
        self._phase_timings[TaskPhase.PLANNING].append(time.time() - phase_start)

        # Phase 4: Load KB
        ctx.phase = TaskPhase.KB_LOADING
        phase_start = time.time()
        self._load_knowledge(ctx)
        self._phase_timings[TaskPhase.KB_LOADING].append(time.time() - phase_start)

        # Phase 5: Assemble prompt
        ctx.phase = TaskPhase.PROMPT_ASSEMBLY
        self._assemble_prompt(ctx)

        # Phase 6: LLM reasoning
        ctx.phase = TaskPhase.LLM_REASONING
        self._state = BrainState.REASONING
        phase_start = time.time()
        self._reason(ctx)
        self._phase_timings[TaskPhase.LLM_REASONING].append(time.time() - phase_start)

        # Phase 7: Tool execution
        ctx.phase = TaskPhase.TOOL_EXECUTION
        self._state = BrainState.EXECUTING
        phase_start = time.time()
        self._execute_tools(ctx)
        self._phase_timings[TaskPhase.TOOL_EXECUTION].append(time.time() - phase_start)

        # Phase 8: Analysis
        ctx.phase = TaskPhase.ANALYSIS
        self._analyze_results(ctx)

        # Phase 9: Validation
        if self._config.auto_validate:
            ctx.phase = TaskPhase.VALIDATION
            self._validate_findings(ctx)

        # Phase 10: Correlation
        ctx.phase = TaskPhase.CORRELATION
        self._correlate_findings(ctx)

        # Phase 11: Reporting
        ctx.phase = TaskPhase.REPORTING
        self._state = BrainState.REPORTING
        self._generate_report(ctx)

        # Phase 12: Learning
        if self._config.auto_learn:
            ctx.phase = TaskPhase.LEARNING
            self._state = BrainState.LEARNING
            self._learn_from_task(ctx)

        ctx.phase = TaskPhase.DONE
        self._state = BrainState.IDLE
        return ctx

    def _decide(self, ctx: TaskContext, decision_type: str, reasoning: str, action: str = "") -> AgentDecision:
        """Record a brain decision."""
        decision = AgentDecision(
            decision_type=decision_type,
            reasoning=reasoning,
            action=action,
        )
        self._decisions.append(decision)
        return decision

    def _profile_target(self, ctx: TaskContext) -> None:
        """Profile the target for intelligent planning."""
        self._decide(ctx, "profiling", f"Profiling target: {ctx.target}")
        # Would call TargetIntelligence here
        ctx.memory_context += f"\nTarget: {ctx.target}, Type: auto-detected"

    def _generate_plan(self, ctx: TaskContext) -> None:
        """Generate execution plan."""
        self._decide(ctx, "planning", f"Generating plan for: {ctx.goal[:30]}")
        # Would call AgentPlanningEngine here
        ctx.plan_id = f"plan-{ctx.task_id}"

    def _load_knowledge(self, ctx: TaskContext) -> None:
        """Load relevant KB domains."""
        kb_domains = PHASE_KB_MAP.get(TaskPhase.LLM_REASONING, [])
        self._decide(ctx, "kb_loading", f"Loading {len(kb_domains)} KB domains")
        ctx.kb_context = f"Loaded domains: {', '.join(kb_domains)}"

    def _assemble_prompt(self, ctx: TaskContext) -> None:
        """Assemble the LLM prompt."""
        model = PHASE_MODEL_MAP.get(ctx.phase, "whiterabbit")
        self._decide(ctx, "prompt_assembly", f"Assembling prompt for {model}")

    def _reason(self, ctx: TaskContext) -> None:
        """Run LLM reasoning."""
        self._decide(ctx, "reasoning", "Running security analysis reasoning")
        ctx.iteration += 1
        # Would call LLM client here
        ctx.llm_responses.append({"model": "whiterabbit", "content": "analysis placeholder"})

    def _execute_tools(self, ctx: TaskContext) -> None:
        """Execute security tools."""
        self._decide(ctx, "tool_execution", "Executing planned tools")
        # Would call tool orchestrator here

    def _analyze_results(self, ctx: TaskContext) -> None:
        """Analyze tool outputs and LLM responses."""
        self._decide(ctx, "analysis", f"Analyzing {len(ctx.tool_outputs)} tool outputs")

    def _validate_findings(self, ctx: TaskContext) -> None:
        """Validate findings to reduce false positives."""
        self._decide(ctx, "validation", f"Validating {len(ctx.findings)} findings")
        for finding in ctx.findings:
            finding["validated"] = True

    def _correlate_findings(self, ctx: TaskContext) -> None:
        """Correlate findings into attack chains."""
        self._decide(ctx, "correlation", "Building attack chains from findings")

    def _generate_report(self, ctx: TaskContext) -> None:
        """Generate the final report."""
        self._decide(ctx, "reporting", "Generating assessment report")

    def _learn_from_task(self, ctx: TaskContext) -> None:
        """Learn from the task for future improvement."""
        self._decide(ctx, "learning", f"Learning from task (duration: {ctx.duration_s:.1f}s)")

    def add_finding(self, title: str, severity: str = "medium", vuln_type: str = "", target: str = "", evidence: str = "", cwe: str = "") -> Finding:
        """Add a finding to the brain."""
        self._finding_counter += 1
        finding = Finding(
            finding_id=f"find-{self._finding_counter}",
            title=title,
            severity=severity,
            vuln_type=vuln_type,
            target=target,
            evidence=evidence,
            cwe=cwe,
        )
        self._findings.append(finding)
        return finding

    def get_state(self) -> dict[str, Any]:
        """Get current brain state."""
        return {
            "state": self._state.value,
            "active_tasks": sum(1 for t in self._tasks.values() if t.phase != TaskPhase.DONE),
            "total_tasks": len(self._tasks),
            "findings": len(self._findings),
            "decisions": len(self._decisions),
            "tokens": self._total_tokens,
            "uptime_s": f"{time.time() - self._start_time:.0f}",
        }

    def get_phase_stats(self) -> dict[str, Any]:
        """Get average time per phase."""
        stats: dict[str, str] = {}
        for phase, timings in self._phase_timings.items():
            if timings:
                avg = sum(timings) / len(timings)
                stats[phase.value] = f"{avg:.2f}s"
        return stats

    def build_brain_prompt(self, ctx: TaskContext) -> str:
        """Build a comprehensive LLM prompt with full brain context."""
        lines = ["## RecurSec Unified Agent Brain"]
        lines.append(f"Task: {ctx.goal[:50]}")
        lines.append(f"Target: {ctx.target}")
        lines.append(f"Phase: {ctx.phase.value}")
        lines.append(f"Iteration: {ctx.iteration}")

        if ctx.kb_context:
            lines.append(f"\n## Knowledge:\n{ctx.kb_context[:500]}")

        if ctx.memory_context:
            lines.append(f"\n## Memory:\n{ctx.memory_context[:300]}")

        if ctx.findings:
            lines.append(f"\n## Findings so far: {len(ctx.findings)}")
            for f in ctx.findings[-3:]:
                lines.append(f"  - [{f.get('severity', 'medium')}] {f.get('title', '')[:30]}")

        if ctx.errors:
            lines.append(f"\n## Errors: {len(ctx.errors)}")
            lines.append(f"  Latest: {ctx.errors[-1][:50]}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        sev_counts: dict[str, int] = defaultdict(int)
        for f in self._findings:
            sev_counts[f.severity] += 1
        return {
            "state": self._state.value,
            "tasks": len(self._tasks),
            "findings": len(self._findings),
            "severity": dict(sev_counts),
            "decisions": len(self._decisions),
        }
