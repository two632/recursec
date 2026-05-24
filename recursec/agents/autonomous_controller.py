"""Master autonomous controller — the main brain loop.

Ties ALL components together into a single autonomous loop:
1. Task intake → intent classification
2. KB selection → prompt assembly
3. Model routing → LLM reasoning
4. Tool selection → execution
5. Output analysis → finding correlation
6. Validation → learning
7. Strategy optimization → next iteration
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ControllerState(str, Enum):
    IDLE = "idle"
    INTAKE = "intake"
    PLANNING = "planning"
    KB_LOADING = "kb_loading"
    PROMPT_ASSEMBLY = "prompt_assembly"
    LLM_REASONING = "llm_reasoning"
    TOOL_EXECUTION = "tool_execution"
    OUTPUT_ANALYSIS = "output_analysis"
    CORRELATION = "correlation"
    VALIDATION = "validation"
    LEARNING = "learning"
    REPORTING = "reporting"
    COMPLETED = "completed"
    ERROR = "error"


class TaskPriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class TaskContext:
    """Full context for a task being executed."""
    task_id: str = ""
    user_input: str = ""
    intent: str = ""
    secondary_intents: list[str] = field(default_factory=list)
    extracted_entities: dict[str, list[str]] = field(default_factory=dict)
    selected_kbs: list[str] = field(default_factory=list)
    assembled_prompt: str = ""
    selected_model: str = ""
    selected_tools: list[str] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    tool_outputs: list[dict[str, Any]] = field(default_factory=list)
    llm_responses: list[str] = field(default_factory=list)
    attack_chains: list[dict[str, Any]] = field(default_factory=list)
    validation_results: list[dict[str, Any]] = field(default_factory=list)
    priority: TaskPriority = TaskPriority.MEDIUM
    depth: int = 0
    max_depth: int = 5
    token_budget: int = 32768
    tokens_used: int = 0
    started_at: float = field(default_factory=time.time)
    completed_at: float = 0.0
    state: ControllerState = ControllerState.IDLE
    error_message: str = ""
    parent_task_id: str = ""
    child_task_ids: list[str] = field(default_factory=list)

    @property
    def elapsed_s(self) -> float:
        end = self.completed_at if self.completed_at else time.time()
        return end - self.started_at

    @property
    def remaining_budget(self) -> int:
        return max(0, self.token_budget - self.tokens_used)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.task_id[:8],
            "intent": self.intent[:15],
            "state": self.state.value[:10],
            "findings": len(self.findings),
            "elapsed": f"{self.elapsed_s:.1f}s",
            "tokens": f"{self.tokens_used}/{self.token_budget}",
            "depth": f"{self.depth}/{self.max_depth}",
        }


@dataclass
class ExecutionStep:
    """A single step in the execution pipeline."""
    step_id: int = 0
    state: ControllerState = ControllerState.IDLE
    input_data: dict[str, Any] = field(default_factory=dict)
    output_data: dict[str, Any] = field(default_factory=dict)
    model_used: str = ""
    tools_used: list[str] = field(default_factory=list)
    tokens_used: int = 0
    duration_s: float = 0.0
    success: bool = True
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step_id,
            "state": self.state.value[:10],
            "model": self.model_used[:12],
            "tools": len(self.tools_used),
            "tokens": self.tokens_used,
            "ok": self.success,
        }


@dataclass
class AutonomousSession:
    """A full autonomous session with multiple tasks."""
    session_id: str = ""
    tasks: list[TaskContext] = field(default_factory=list)
    execution_log: list[ExecutionStep] = field(default_factory=list)
    total_findings: int = 0
    total_tokens: int = 0
    started_at: float = field(default_factory=time.time)
    config: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.session_id[:8],
            "tasks": len(self.tasks),
            "steps": len(self.execution_log),
            "findings": self.total_findings,
            "tokens": self.total_tokens,
        }


# State transition map — defines valid transitions
STATE_TRANSITIONS: dict[ControllerState, list[ControllerState]] = {
    ControllerState.IDLE: [ControllerState.INTAKE],
    ControllerState.INTAKE: [ControllerState.PLANNING, ControllerState.ERROR],
    ControllerState.PLANNING: [ControllerState.KB_LOADING, ControllerState.ERROR],
    ControllerState.KB_LOADING: [ControllerState.PROMPT_ASSEMBLY, ControllerState.ERROR],
    ControllerState.PROMPT_ASSEMBLY: [ControllerState.LLM_REASONING, ControllerState.ERROR],
    ControllerState.LLM_REASONING: [ControllerState.TOOL_EXECUTION, ControllerState.OUTPUT_ANALYSIS, ControllerState.ERROR],
    ControllerState.TOOL_EXECUTION: [ControllerState.OUTPUT_ANALYSIS, ControllerState.LLM_REASONING, ControllerState.ERROR],
    ControllerState.OUTPUT_ANALYSIS: [ControllerState.CORRELATION, ControllerState.TOOL_EXECUTION, ControllerState.LLM_REASONING, ControllerState.ERROR],
    ControllerState.CORRELATION: [ControllerState.VALIDATION, ControllerState.TOOL_EXECUTION, ControllerState.ERROR],
    ControllerState.VALIDATION: [ControllerState.LEARNING, ControllerState.TOOL_EXECUTION, ControllerState.ERROR],
    ControllerState.LEARNING: [ControllerState.REPORTING, ControllerState.PLANNING, ControllerState.ERROR],
    ControllerState.REPORTING: [ControllerState.COMPLETED, ControllerState.ERROR],
    ControllerState.COMPLETED: [ControllerState.IDLE],
    ControllerState.ERROR: [ControllerState.IDLE, ControllerState.PLANNING],
}


# Pipeline step configurations
PIPELINE_STEPS: list[dict[str, Any]] = [
    {
        "state": ControllerState.INTAKE,
        "description": "Parse user input, extract entities, classify intent",
        "component": "intent_classifier",
        "model_domain": "fast",
        "max_tokens": 512,
    },
    {
        "state": ControllerState.PLANNING,
        "description": "Create execution plan based on intent and entities",
        "component": "adaptive_planner",
        "model_domain": "reasoning",
        "max_tokens": 2048,
    },
    {
        "state": ControllerState.KB_LOADING,
        "description": "Load relevant knowledge bases for the task",
        "component": "kb_registry",
        "model_domain": None,
        "max_tokens": 0,
    },
    {
        "state": ControllerState.PROMPT_ASSEMBLY,
        "description": "Assemble full prompt with role, KB context, instructions",
        "component": "prompt_templates",
        "model_domain": None,
        "max_tokens": 0,
    },
    {
        "state": ControllerState.LLM_REASONING,
        "description": "LLM reasons about approach, generates tool calls",
        "component": "llm_connection_engine",
        "model_domain": "security",
        "max_tokens": 4096,
    },
    {
        "state": ControllerState.TOOL_EXECUTION,
        "description": "Execute selected tools against target",
        "component": "tool_orchestrator",
        "model_domain": None,
        "max_tokens": 0,
    },
    {
        "state": ControllerState.OUTPUT_ANALYSIS,
        "description": "Parse and analyze tool outputs",
        "component": "output_analyzer",
        "model_domain": "code",
        "max_tokens": 2048,
    },
    {
        "state": ControllerState.CORRELATION,
        "description": "Correlate findings, build attack chains",
        "component": "finding_correlator",
        "model_domain": "reasoning",
        "max_tokens": 2048,
    },
    {
        "state": ControllerState.VALIDATION,
        "description": "Validate findings with different tools/models",
        "component": "adversarial_validator",
        "model_domain": "security",
        "max_tokens": 2048,
    },
    {
        "state": ControllerState.LEARNING,
        "description": "Record experience, update strategy scores",
        "component": "experience_replay",
        "model_domain": None,
        "max_tokens": 0,
    },
    {
        "state": ControllerState.REPORTING,
        "description": "Generate findings report",
        "component": "reporter",
        "model_domain": "general",
        "max_tokens": 4096,
    },
]


class AutonomousController:
    """Master controller for autonomous security operations."""

    def __init__(self) -> None:
        self._sessions: dict[str, AutonomousSession] = {}
        self._task_counter = 0
        self._session_counter = 0
        self._step_counter = 0
        self._log = logger.bind(component="autonomous_controller")

    def create_session(self, config: dict[str, Any] | None = None) -> AutonomousSession:
        """Create a new autonomous session."""
        self._session_counter += 1
        session = AutonomousSession(
            session_id=f"session-{self._session_counter}",
            config=config or {},
        )
        self._sessions[session.session_id] = session
        return session

    def create_task(
        self,
        session_id: str,
        user_input: str,
        priority: TaskPriority = TaskPriority.MEDIUM,
        parent_task_id: str = "",
    ) -> TaskContext:
        """Create a new task within a session."""
        self._task_counter += 1
        session = self._sessions.get(session_id)
        if not session:
            session = self.create_session()

        task = TaskContext(
            task_id=f"task-{self._task_counter}",
            user_input=user_input,
            priority=priority,
            parent_task_id=parent_task_id,
            state=ControllerState.IDLE,
        )
        session.tasks.append(task)
        return task

    def transition_state(
        self,
        task: TaskContext,
        new_state: ControllerState,
    ) -> bool:
        """Transition task to a new state (validates transition)."""
        valid_next = STATE_TRANSITIONS.get(task.state, [])
        if new_state not in valid_next:
            self._log.warning(
                "invalid_transition",
                current=task.state.value,
                requested=new_state.value,
            )
            return False
        task.state = new_state
        return True

    def get_pipeline_step(self, state: ControllerState) -> dict[str, Any] | None:
        """Get pipeline step configuration for a state."""
        for step in PIPELINE_STEPS:
            if step["state"] == state:
                return step
        return None

    def record_step(
        self,
        session: AutonomousSession,
        task: TaskContext,
        output_data: dict[str, Any] | None = None,
        model_used: str = "",
        tools_used: list[str] | None = None,
        tokens_used: int = 0,
        success: bool = True,
        error: str = "",
    ) -> ExecutionStep:
        """Record an execution step."""
        self._step_counter += 1
        step = ExecutionStep(
            step_id=self._step_counter,
            state=task.state,
            output_data=output_data or {},
            model_used=model_used,
            tools_used=tools_used or [],
            tokens_used=tokens_used,
            success=success,
            error=error,
        )
        session.execution_log.append(step)
        task.tokens_used += tokens_used
        session.total_tokens += tokens_used
        return step

    def should_continue(self, task: TaskContext) -> bool:
        """Determine if task should continue iterating."""
        if task.state in (ControllerState.COMPLETED, ControllerState.ERROR):
            return False
        if task.remaining_budget <= 0:
            return False
        if task.depth >= task.max_depth:
            return False
        if task.elapsed_s > 3600:  # 1 hour max
            return False
        return True

    def should_go_deeper(self, task: TaskContext) -> bool:
        """Determine if we should spawn child tasks for deeper analysis."""
        if task.depth >= task.max_depth - 1:
            return False
        if task.remaining_budget < task.token_budget * 0.3:
            return False
        critical_findings = [
            f for f in task.findings
            if f.get("severity") in ("critical", "high")
        ]
        return len(critical_findings) > 0

    def select_next_state(self, task: TaskContext) -> ControllerState:
        """Intelligently select next state based on task progress."""
        current = task.state
        valid_next = STATE_TRANSITIONS.get(current, [])

        if not valid_next:
            return ControllerState.ERROR

        # If tool execution found results, analyze them
        if current == ControllerState.TOOL_EXECUTION and task.tool_outputs:
            return ControllerState.OUTPUT_ANALYSIS

        # If analysis found findings, correlate
        if current == ControllerState.OUTPUT_ANALYSIS and task.findings:
            return ControllerState.CORRELATION

        # If analysis found nothing, try different tools
        if current == ControllerState.OUTPUT_ANALYSIS and not task.findings:
            if task.remaining_budget > task.token_budget * 0.5:
                return ControllerState.LLM_REASONING
            return ControllerState.REPORTING

        # If correlation done, validate
        if current == ControllerState.CORRELATION:
            return ControllerState.VALIDATION

        # If validation done, learn and report
        if current == ControllerState.VALIDATION:
            return ControllerState.LEARNING

        # Default: follow pipeline order
        for step_cfg in PIPELINE_STEPS:
            if step_cfg["state"] in valid_next:
                return step_cfg["state"]

        return valid_next[0] if valid_next else ControllerState.ERROR

    def build_execution_summary(self, task: TaskContext) -> str:
        """Build a summary of task execution for reporting."""
        lines = [f"## Task Execution Summary: {task.task_id}"]
        lines.append(f"Intent: {task.intent}")
        lines.append(f"State: {task.state.value}")
        lines.append(f"Duration: {task.elapsed_s:.1f}s")
        lines.append(f"Tokens: {task.tokens_used}/{task.token_budget}")
        lines.append(f"Depth: {task.depth}/{task.max_depth}")
        lines.append(f"\nFindings: {len(task.findings)}")
        for f in task.findings[:10]:
            lines.append(f"  [{f.get('severity', '?')}] {f.get('title', 'Untitled')}")
        lines.append(f"\nAttack Chains: {len(task.attack_chains)}")
        lines.append(f"Validated: {len(task.validation_results)}")
        lines.append(f"Tools Used: {len(task.selected_tools)}")
        lines.append(f"KBs Loaded: {', '.join(task.selected_kbs[:5])}")
        lines.append(f"Model: {task.selected_model}")
        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        """Get controller statistics."""
        all_tasks = []
        for session in self._sessions.values():
            all_tasks.extend(session.tasks)

        state_counts: dict[str, int] = {}
        for task in all_tasks:
            key = task.state.value
            state_counts[key] = state_counts.get(key, 0) + 1

        return {
            "sessions": len(self._sessions),
            "total_tasks": len(all_tasks),
            "total_steps": self._step_counter,
            "by_state": state_counts,
            "total_findings": sum(len(t.findings) for t in all_tasks),
            "total_tokens": sum(t.tokens_used for t in all_tasks),
        }
