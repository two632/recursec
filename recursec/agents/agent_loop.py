"""Agent loop — the core agentic execution cycle.

Implements the fundamental agent loop:
1. Perceive: Gather context (target, findings, tool output, memory)
2. Think: Reason about what to do next (LLM inference)
3. Act: Execute chosen action (tool, delegation, analysis)
4. Observe: Collect and parse results
5. Reflect: Assess progress and quality
6. Repeat or terminate

Inspired by the best agent architectures:
- Claude Code: context → action → verify loop with course correction
- PentAGI: Flow → Task → Subtask → Action hierarchy
- Agent Zero: hierarchical delegation with full system access
- RecursiveMAS: recursive agent collaboration
- Qihoo 360 SEAF: self-evolving agent factory

The loop is the heart of the agent — everything else feeds into it.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from recursec.llm.router import ModelRouter

logger = structlog.get_logger()


class LoopPhase(str, Enum):
    PERCEIVE = "perceive"
    THINK = "think"
    ACT = "act"
    OBSERVE = "observe"
    REFLECT = "reflect"
    COMPLETE = "complete"
    ERROR = "error"


class ActionKind(str, Enum):
    RUN_TOOL = "run_tool"
    DELEGATE = "delegate"
    ANALYZE = "analyze"
    VALIDATE = "validate"
    REPORT_FINDING = "report_finding"
    ASK_HELP = "ask_help"
    PIVOT = "pivot"
    FINISH = "finish"
    WAIT = "wait"
    RETRY = "retry"


@dataclass
class AgentAction:
    """An action the agent wants to take."""
    kind: ActionKind = ActionKind.RUN_TOOL
    tool: str = ""
    command: str = ""
    arguments: dict[str, Any] = field(default_factory=dict)
    target: str = ""
    reasoning: str = ""
    confidence: float = 0.5
    delegate_to: str = ""
    delegate_task: str = ""
    finding: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "tool": self.tool,
            "command": self.command[:200] if self.command else "",
            "reasoning": self.reasoning[:200],
            "confidence": round(self.confidence, 2),
        }


@dataclass
class StepResult:
    """Result of a single loop step."""
    step_number: int = 0
    phase: LoopPhase = LoopPhase.PERCEIVE
    action: AgentAction | None = None
    tool_output: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)
    tokens_used: int = 0
    duration_s: float = 0.0
    error: str = ""
    should_continue: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step_number,
            "phase": self.phase.value,
            "action": self.action.to_dict() if self.action else None,
            "findings": len(self.findings),
            "tokens": self.tokens_used,
            "duration_s": round(self.duration_s, 1),
            "continue": self.should_continue,
        }


@dataclass
class LoopState:
    """Full state of the agent loop."""
    agent_id: str = ""
    role: str = ""
    target: str = ""
    goal: str = ""

    # Budgets
    max_steps: int = 100
    max_tokens: int = 50000
    max_time_s: float = 300.0

    # Current state
    current_step: int = 0
    current_phase: LoopPhase = LoopPhase.PERCEIVE
    tokens_used: int = 0
    started_at: float = field(default_factory=time.time)

    # History
    steps: list[StepResult] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    tool_outputs: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    # Context
    system_prompt: str = ""
    conversation: list[dict[str, str]] = field(default_factory=list)
    parent_context: dict[str, Any] = field(default_factory=dict)

    @property
    def elapsed_s(self) -> float:
        return time.time() - self.started_at

    @property
    def budget_exhausted(self) -> bool:
        return (
            self.current_step >= self.max_steps
            or self.tokens_used >= self.max_tokens
            or self.elapsed_s >= self.max_time_s
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent_id, "role": self.role,
            "step": self.current_step, "phase": self.current_phase.value,
            "findings": len(self.findings),
            "tokens": f"{self.tokens_used}/{self.max_tokens}",
            "time": f"{self.elapsed_s:.0f}s/{self.max_time_s:.0f}s",
        }


# ── Prompt Templates ─────────────────────────────────────────

THINK_PROMPT = """You are a {role} agent performing a security assessment.

Goal: {goal}
Target: {target}
Step: {step}/{max_steps}
Budget: {tokens_used}/{max_tokens} tokens, {time_remaining:.0f}s remaining
Findings so far: {findings_count}

Recent context:
{recent_context}

{tool_output_section}

Available actions:
- run_tool: Execute a security tool (nmap, nuclei, sqlmap, etc.)
- delegate: Assign a subtask to a specialist agent
- analyze: Analyze data without running a tool
- validate: Validate a previous finding
- report_finding: Report a new vulnerability finding
- pivot: Change approach/strategy
- finish: Mark assessment as complete

Based on the current state, what is the best next action?

Respond as JSON:
{{
  "action": "run_tool|delegate|analyze|validate|report_finding|pivot|finish",
  "tool": "tool name if run_tool",
  "command": "full command to run if run_tool",
  "arguments": {{}},
  "target": "specific target/URL",
  "reasoning": "why this action",
  "confidence": 0.X,
  "delegate_to": "role if delegate",
  "delegate_task": "task description if delegate",
  "finding": {{
    "title": "if report_finding",
    "severity": "critical|high|medium|low|info",
    "description": "details",
    "evidence": "proof"
  }}
}}"""


class AgentLoop:
    """The core agentic execution loop.

    Runs perceive → think → act → observe → reflect cycles
    until the goal is met or budget is exhausted.
    """

    def __init__(
        self,
        model_router: ModelRouter | None = None,
        tool_executor: Any = None,
        delegation_engine: Any = None,
        validator: Any = None,
    ) -> None:
        self._router = model_router
        self._tool_executor = tool_executor
        self._delegation = delegation_engine
        self._validator = validator
        self._log = logger.bind(component="agent_loop")

    async def run(self, state: LoopState) -> LoopState:
        """Run the full agent loop until completion or budget exhaustion."""
        self._log.info(
            "loop_start",
            agent=state.agent_id, role=state.role,
            target=state.target, goal=state.goal[:80],
        )

        while not state.budget_exhausted:
            step_result = await self._execute_step(state)
            state.steps.append(step_result)

            if not step_result.should_continue:
                state.current_phase = LoopPhase.COMPLETE
                break

            if step_result.error:
                state.errors.append(step_result.error)
                if len(state.errors) > 5:
                    # Too many consecutive errors — bail
                    state.current_phase = LoopPhase.ERROR
                    break

        self._log.info(
            "loop_end",
            agent=state.agent_id,
            steps=state.current_step,
            findings=len(state.findings),
            tokens=state.tokens_used,
            elapsed=f"{state.elapsed_s:.1f}s",
        )

        return state

    async def _execute_step(self, state: LoopState) -> StepResult:
        """Execute a single loop step."""
        start = time.time()
        state.current_step += 1

        result = StepResult(step_number=state.current_step)

        try:
            # 1. PERCEIVE — Gather context
            state.current_phase = LoopPhase.PERCEIVE
            context = self._build_context(state)

            # 2. THINK — Decide next action via LLM
            state.current_phase = LoopPhase.THINK
            action, tokens = await self._think(state, context)
            result.action = action
            result.tokens_used = tokens
            state.tokens_used += tokens

            # 3. ACT — Execute the action
            state.current_phase = LoopPhase.ACT
            output = await self._act(state, action)
            result.tool_output = output[:2000] if output else ""

            # 4. OBSERVE — Record results
            state.current_phase = LoopPhase.OBSERVE
            if output:
                state.tool_outputs.append(output[:2000])
                # Keep last 5 outputs in memory
                if len(state.tool_outputs) > 5:
                    state.tool_outputs = state.tool_outputs[-5:]

            # Record findings
            if action.kind == ActionKind.REPORT_FINDING and action.finding:
                state.findings.append(action.finding)
                result.findings.append(action.finding)

            # 5. REFLECT — Should we continue?
            state.current_phase = LoopPhase.REFLECT
            if action.kind == ActionKind.FINISH:
                result.should_continue = False

            # Update conversation
            if action.reasoning:
                state.conversation.append({
                    "role": "assistant",
                    "content": json.dumps(action.to_dict()),
                })
            if output:
                state.conversation.append({
                    "role": "user",
                    "content": f"Tool output:\n{output[:1000]}",
                })

        except Exception as e:
            result.error = str(e)[:200]
            self._log.warning("step_error", step=state.current_step, error=result.error)

        result.duration_s = time.time() - start
        return result

    def _build_context(self, state: LoopState) -> str:
        """Build context string for LLM."""
        parts = []

        # Recent conversation
        recent = state.conversation[-6:]
        for msg in recent:
            role = msg.get("role", "")
            content = msg.get("content", "")
            parts.append(f"[{role}] {content[:300]}")

        # Recent findings summary
        if state.findings:
            parts.append(f"Findings ({len(state.findings)} total):")
            for f in state.findings[-3:]:
                parts.append(f"  - [{f.get('severity', 'N/A')}] {f.get('title', 'N/A')}")

        return "\n".join(parts) if parts else "No previous context."

    async def _think(
        self,
        state: LoopState,
        context: str,
    ) -> tuple[AgentAction, int]:
        """Use LLM to decide next action."""
        if not self._router:
            # Fallback: return finish action
            return AgentAction(kind=ActionKind.FINISH, reasoning="No LLM available"), 0

        # Build tool output section
        tool_section = ""
        if state.tool_outputs:
            last_output = state.tool_outputs[-1]
            tool_section = f"Last tool output:\n```\n{last_output[:800]}\n```"

        prompt = THINK_PROMPT.format(
            role=state.role,
            goal=state.goal[:300],
            target=state.target,
            step=state.current_step,
            max_steps=state.max_steps,
            tokens_used=state.tokens_used,
            max_tokens=state.max_tokens,
            time_remaining=max(0, state.max_time_s - state.elapsed_s),
            findings_count=len(state.findings),
            recent_context=context[:1000],
            tool_output_section=tool_section,
        )

        messages = []
        if state.system_prompt:
            messages.append({"role": "system", "content": state.system_prompt})
        messages.append({"role": "user", "content": prompt})

        response = await self._router.generate(
            messages=messages,
            task_type="security",
            temperature=0.2,
            max_tokens=512,
        )

        # Estimate tokens used
        tokens = len(prompt) // 4 + len(response) // 4

        # Parse action
        action = self._parse_action(response)
        return action, tokens

    async def _act(self, state: LoopState, action: AgentAction) -> str:
        """Execute an action."""
        if action.kind == ActionKind.RUN_TOOL:
            return await self._run_tool(action)
        elif action.kind == ActionKind.DELEGATE:
            return await self._delegate(state, action)
        elif action.kind == ActionKind.ANALYZE:
            return f"Analysis: {action.reasoning}"
        elif action.kind == ActionKind.VALIDATE:
            return await self._validate(action)
        elif action.kind == ActionKind.REPORT_FINDING:
            return f"Finding reported: {action.finding.get('title', 'N/A')}"
        elif action.kind == ActionKind.PIVOT:
            return f"Pivoting strategy: {action.reasoning}"
        elif action.kind == ActionKind.FINISH:
            return "Assessment complete"
        return ""

    async def _run_tool(self, action: AgentAction) -> str:
        """Run a security tool."""
        if self._tool_executor:
            result = await self._tool_executor.execute(
                tool=action.tool,
                command=action.command,
                target=action.target,
            )
            return result.get("output", "") if isinstance(result, dict) else str(result)

        # Fallback: log what would run
        return f"[DRY RUN] Would execute: {action.tool} {action.command}"

    async def _delegate(self, state: LoopState, action: AgentAction) -> str:
        """Delegate a task to a specialist agent."""
        if self._delegation:
            result = await self._delegation.delegate(
                task=action.delegate_task,
                role=action.delegate_to,
                target=action.target or state.target,
            )
            return str(result)

        return f"[DELEGATION] Would delegate to {action.delegate_to}: {action.delegate_task}"

    async def _validate(self, action: AgentAction) -> str:
        """Validate a finding."""
        if self._validator and action.finding:
            result = await self._validator.validate(action.finding)
            return str(result)
        return "Validation: Not configured"

    def _parse_action(self, response: str) -> AgentAction:
        """Parse LLM response into an action."""
        data = self._parse_json(response)

        action_str = data.get("action", "analyze")
        kind_map = {
            "run_tool": ActionKind.RUN_TOOL,
            "delegate": ActionKind.DELEGATE,
            "analyze": ActionKind.ANALYZE,
            "validate": ActionKind.VALIDATE,
            "report_finding": ActionKind.REPORT_FINDING,
            "pivot": ActionKind.PIVOT,
            "finish": ActionKind.FINISH,
            "ask_help": ActionKind.ASK_HELP,
            "wait": ActionKind.WAIT,
            "retry": ActionKind.RETRY,
        }

        return AgentAction(
            kind=kind_map.get(action_str, ActionKind.ANALYZE),
            tool=data.get("tool", ""),
            command=data.get("command", ""),
            arguments=data.get("arguments", {}),
            target=data.get("target", ""),
            reasoning=data.get("reasoning", ""),
            confidence=data.get("confidence", 0.5),
            delegate_to=data.get("delegate_to", ""),
            delegate_task=data.get("delegate_task", ""),
            finding=data.get("finding", {}),
        )

    def _parse_json(self, text: str) -> dict[str, Any]:
        try:
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]
            return json.loads(text.strip())
        except (json.JSONDecodeError, IndexError):
            return {"action": "analyze", "reasoning": text[:200]}
