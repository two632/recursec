"""Autonomous decision loop — the core brain of RecurSec agents.

This is the primary execution loop that drives agent behavior. It implements
the observe-orient-decide-act (OODA) cycle with LLM-powered reasoning:

1. OBSERVE: Gather current state, findings, messages, tool outputs
2. ORIENT: Analyze situation, update mental model, assess threats
3. DECIDE: Use reasoning engine to select next action
4. ACT: Execute chosen action (tool call, spawn agent, report finding)

Features:
- Adaptive strategy selection (easy tasks get simple CoT, hard tasks get ToT/debate)
- Goal tracking with progress estimation
- Backtracking when approaches fail
- Exploration vs exploitation balance
- Token budget management
- Convergence detection (stop when no new information)
- Multi-model reasoning for critical decisions
- Self-correction through reflection
"""

from __future__ import annotations

import asyncio
import json
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

import structlog

from recursec.agents.state_machine import AgentState, AgentStateMachine

if TYPE_CHECKING:
    from recursec.agents.communication import MessageBus
    from recursec.agents.planner import HierarchicalPlanner, Plan
    from recursec.core.reasoning import ReasoningEngine, ReasoningStrategy
    from recursec.llm.router import ModelRouter
    from recursec.memory.store import MemoryStore
    from recursec.tools.registry import ToolRegistry

logger = structlog.get_logger()


class ActionType(str, Enum):
    TOOL_CALL = "tool_call"
    LLM_REASON = "llm_reason"
    SPAWN_AGENT = "spawn_agent"
    REPORT_FINDING = "report_finding"
    REQUEST_INFO = "request_info"
    DELEGATE = "delegate"
    WAIT = "wait"
    BACKTRACK = "backtrack"
    COMPLETE = "complete"
    FAIL = "fail"
    REPLAN = "replan"


class GoalStatus(str, Enum):
    ACTIVE = "active"
    ACHIEVED = "achieved"
    FAILED = "failed"
    ABANDONED = "abandoned"


@dataclass
class Goal:
    """A goal the agent is trying to achieve."""
    goal_id: str = ""
    description: str = ""
    success_criteria: str = ""
    status: GoalStatus = GoalStatus.ACTIVE
    progress: float = 0.0
    parent_goal_id: str | None = None
    sub_goals: list[str] = field(default_factory=list)
    attempts: int = 0
    max_attempts: int = 5
    evidence: list[str] = field(default_factory=list)


@dataclass
class Observation:
    """Current observation state for OODA cycle."""
    timestamp: float = field(default_factory=time.time)
    current_findings: list[dict[str, Any]] = field(default_factory=list)
    pending_messages: list[dict[str, Any]] = field(default_factory=list)
    recent_tool_outputs: list[dict[str, Any]] = field(default_factory=list)
    active_goals: list[Goal] = field(default_factory=list)
    agent_states: dict[str, str] = field(default_factory=dict)
    resource_usage: dict[str, float] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    new_information: bool = False


@dataclass
class Orientation:
    """Situation assessment from OODA cycle."""
    threat_level: str = "unknown"
    attack_surface_size: str = "unknown"
    progress_assessment: str = ""
    key_insights: list[str] = field(default_factory=list)
    recommended_focus: str = ""
    confidence: float = 0.5
    should_change_approach: bool = False
    approach_reason: str = ""


@dataclass
class Decision:
    """A decision from the OODA cycle."""
    action_type: ActionType = ActionType.TOOL_CALL
    action_params: dict[str, Any] = field(default_factory=dict)
    reasoning: str = ""
    confidence: float = 0.5
    expected_outcome: str = ""
    fallback_action: dict[str, Any] | None = None
    strategy_used: str = ""


@dataclass
class LoopMetrics:
    """Metrics for the autonomous loop."""
    total_cycles: int = 0
    total_actions: int = 0
    total_findings: int = 0
    total_tokens_used: int = 0
    total_time_s: float = 0.0
    actions_by_type: dict[str, int] = field(default_factory=dict)
    avg_cycle_time_s: float = 0.0
    convergence_score: float = 0.0
    backtrack_count: int = 0
    replan_count: int = 0


# ── Prompt Templates ────────────────────────────────────────

OBSERVE_PROMPT = """You are an autonomous security agent. Analyze the current state of your assessment.

Target: {target}
Current findings: {findings_summary}
Recent tool outputs: {tool_outputs}
Active goals: {goals}
Messages from other agents: {messages}
Errors encountered: {errors}

Summarize:
1. What have we discovered so far?
2. What is new since the last cycle?
3. Are there any urgent items requiring attention?
4. What information gaps exist?"""

ORIENT_PROMPT = """Based on the current observations, assess the situation.

Observations: {observations}
Target: {target}
Phase: {phase}
Progress: {progress}%

Assess:
1. Threat level (critical/high/medium/low) and why
2. Attack surface size (large/medium/small)
3. Key insights from current data
4. Should we change our approach? Why?
5. What should we focus on next?

Respond as JSON:
{{
  "threat_level": "...",
  "attack_surface": "...",
  "key_insights": ["..."],
  "should_change_approach": true/false,
  "approach_reason": "...",
  "recommended_focus": "...",
  "confidence": 0.X
}}"""

DECIDE_PROMPT = """Based on the situation assessment, decide the next action.

Assessment: {orientation}
Available tools: {tools}
Available agent types: {agent_types}
Current goals: {goals}
Budget remaining: tokens={tokens_left}, time={time_left}s, steps={steps_left}
Recent actions (avoid repeating): {recent_actions}

Choose ONE action. Respond as JSON:
{{
  "action_type": "tool_call|llm_reason|spawn_agent|report_finding|delegate|wait|backtrack|complete",
  "params": {{
    "tool": "tool_name",     // for tool_call
    "args": {{}},             // for tool_call
    "prompt": "...",         // for llm_reason
    "agent_type": "...",     // for spawn_agent
    "objective": "...",      // for spawn_agent/delegate
    "finding": {{}},          // for report_finding
    "reason": "..."          // for wait/backtrack/complete
  }},
  "reasoning": "why this action",
  "expected_outcome": "what we expect to learn",
  "confidence": 0.X
}}"""

CONVERGENCE_CHECK_PROMPT = """Are we making progress or stuck in a loop?

Recent actions (last 10):
{recent_actions}

Recent findings count: {findings_count}
New findings this cycle: {new_findings}
Cycle number: {cycle}

Respond as JSON:
{{
  "converging": true/false,
  "reason": "...",
  "recommendation": "continue|change_approach|escalate|conclude"
}}"""

SELF_CORRECTION_PROMPT = """Review the last action and its result for errors or missed opportunities.

Action taken: {action}
Result: {result}
Current goals: {goals}

Is there anything we missed or should correct? Respond as JSON:
{{
  "correction_needed": true/false,
  "correction": "what to fix",
  "missed_opportunity": "what we could have done better",
  "updated_priority": "what to focus on now"
}}"""


class AutonomousLoop:
    """The core autonomous decision-making loop.

    Implements OODA (Observe-Orient-Decide-Act) with:
    - Adaptive reasoning strategy selection
    - Goal tracking and progress estimation
    - Convergence detection
    - Self-correction through reflection
    - Budget management
    """

    def __init__(
        self,
        agent_id: str,
        model_router: ModelRouter,
        tool_registry: ToolRegistry,
        memory: MemoryStore,
        reasoning_engine: ReasoningEngine,
        message_bus: MessageBus | None = None,
        planner: HierarchicalPlanner | None = None,
        state_machine: AgentStateMachine | None = None,
        target: str = "",
        max_cycles: int = 100,
        max_tokens: int = 500000,
        max_time_s: float = 3600.0,
        convergence_threshold: int = 5,
    ) -> None:
        self.agent_id = agent_id
        self._router = model_router
        self._tools = tool_registry
        self._memory = memory
        self._reasoning = reasoning_engine
        self._bus = message_bus
        self._planner = planner
        self._sm = state_machine or AgentStateMachine(agent_id)
        self._target = target
        self._max_cycles = max_cycles
        self._max_tokens = max_tokens
        self._max_time_s = max_time_s
        self._convergence_threshold = convergence_threshold

        self._goals: dict[str, Goal] = {}
        self._findings: list[dict[str, Any]] = []
        self._action_history: deque[dict[str, Any]] = deque(maxlen=50)
        self._tool_outputs: deque[dict[str, Any]] = deque(maxlen=20)
        self._errors: list[str] = []
        self._metrics = LoopMetrics()
        self._tokens_used = 0
        self._start_time = 0.0
        self._cycles_without_progress = 0
        self._running = False
        self._plan: Plan | None = None
        self._log = logger.bind(agent=agent_id)

    def add_goal(self, description: str, success_criteria: str = "", parent_id: str | None = None) -> str:
        """Add a goal for the agent to pursue."""
        import uuid
        goal_id = str(uuid.uuid4())[:8]
        goal = Goal(
            goal_id=goal_id,
            description=description,
            success_criteria=success_criteria,
            parent_goal_id=parent_id,
        )
        self._goals[goal_id] = goal
        if parent_id and parent_id in self._goals:
            self._goals[parent_id].sub_goals.append(goal_id)
        return goal_id

    async def run(self) -> dict[str, Any]:
        """Main autonomous loop execution."""
        self._running = True
        self._start_time = time.time()
        await self._sm.transition(AgentState.INITIALIZING, reason="loop_start")

        self._log.info("autonomous_loop_started", target=self._target, max_cycles=self._max_cycles)

        try:
            # Create initial plan if planner is available
            if self._planner:
                await self._sm.transition(AgentState.PLANNING, reason="initial_planning")
                self._plan = await self._planner.create_plan(
                    objective=self._goals_summary(),
                    target=self._target,
                )

            await self._sm.transition(AgentState.EXECUTING, reason="begin_execution")

            while self._running and self._metrics.total_cycles < self._max_cycles:
                self._metrics.total_cycles += 1

                # Check budget
                if not self._check_budget():
                    self._log.info("budget_exhausted")
                    break

                # OODA Cycle
                cycle_start = time.time()

                # 1. OBSERVE
                observation = await self._observe()

                # 2. ORIENT
                orientation = await self._orient(observation)

                # 3. DECIDE
                decision = await self._decide(observation, orientation)

                # 4. ACT
                result = await self._act(decision)

                # Post-action processing
                await self._post_action(decision, result)

                # Update metrics
                cycle_time = time.time() - cycle_start
                self._metrics.total_time_s += cycle_time
                self._metrics.avg_cycle_time_s = (
                    self._metrics.total_time_s / self._metrics.total_cycles
                )

                # Convergence check
                if self._check_convergence():
                    self._log.info("convergence_detected", cycles=self._metrics.total_cycles)
                    break

                # Check for completion
                if decision.action_type == ActionType.COMPLETE:
                    break

        except Exception as e:
            self._log.error("loop_error", error=str(e))
            self._errors.append(str(e))
            await self._sm.transition(AgentState.FAILED, reason=str(e))

        if self._sm.state != AgentState.FAILED:
            await self._sm.transition(AgentState.COMPLETED, reason="loop_finished")

        return self._build_result()

    def stop(self) -> None:
        """Stop the autonomous loop."""
        self._running = False

    # ── OODA Implementation ──────────────────────────────────

    async def _observe(self) -> Observation:
        """Gather current state and new information."""
        obs = Observation()

        # Current findings
        obs.current_findings = list(self._findings)

        # Check messages from other agents
        if self._bus:
            messages = await self._bus.receive_all(self.agent_id)
            for msg in messages:
                obs.pending_messages.append(msg.to_dict())
                if msg.message_type.value == "finding":
                    self._findings.append(msg.body)
                    obs.new_information = True

        # Recent tool outputs
        obs.recent_tool_outputs = list(self._tool_outputs)

        # Active goals
        obs.active_goals = [g for g in self._goals.values() if g.status == GoalStatus.ACTIVE]

        # Check for new information
        if self._tool_outputs:
            obs.new_information = True

        obs.errors = list(self._errors[-5:])

        return obs

    async def _orient(self, observation: Observation) -> Orientation:
        """Assess the situation based on observations."""
        # For simple observations, use heuristic assessment
        if not observation.new_information and self._metrics.total_cycles <= 2:
            return Orientation(
                recommended_focus="initial_reconnaissance",
                confidence=0.5,
            )

        # Use LLM for situation assessment
        progress = self._estimate_progress()

        prompt = ORIENT_PROMPT.format(
            observations=json.dumps({
                "findings_count": len(observation.current_findings),
                "new_messages": len(observation.pending_messages),
                "errors": observation.errors,
                "new_info": observation.new_information,
            }),
            target=self._target,
            phase=self._sm.state.value,
            progress=round(progress, 1),
        )

        try:
            response = await self._router.generate(
                messages=[{"role": "user", "content": prompt}],
                task_type="reasoning",
                temperature=0.2,
                max_tokens=1024,
            )
            data = self._parse_json(response)
            return Orientation(
                threat_level=data.get("threat_level", "unknown"),
                attack_surface_size=data.get("attack_surface", "unknown"),
                key_insights=data.get("key_insights", []),
                recommended_focus=data.get("recommended_focus", ""),
                confidence=data.get("confidence", 0.5),
                should_change_approach=data.get("should_change_approach", False),
                approach_reason=data.get("approach_reason", ""),
            )
        except Exception as e:
            self._log.warning("orient_error", error=str(e))
            return Orientation(recommended_focus="continue_current_approach")

    async def _decide(self, observation: Observation, orientation: Orientation) -> Decision:
        """Decide the next action."""
        # Check if plan has ready nodes
        if self._plan:
            ready = self._plan.get_ready_nodes()
            if ready:
                node = ready[0]
                if node.tool_name:
                    return Decision(
                        action_type=ActionType.TOOL_CALL,
                        action_params={"tool": node.tool_name, "args": node.tool_args, "plan_node_id": node.node_id},
                        reasoning=f"Executing plan node: {node.name}",
                        confidence=0.7,
                    )
                if node.agent_type:
                    return Decision(
                        action_type=ActionType.SPAWN_AGENT,
                        action_params={"agent_type": node.agent_type, "objective": node.description, "plan_node_id": node.node_id},
                        reasoning=f"Spawning agent for plan node: {node.name}",
                        confidence=0.7,
                    )

        # Use LLM for decision-making
        tools_desc = ", ".join(self._get_available_tool_names()[:30])
        recent = [
            {"type": a["type"], "result_summary": str(a.get("result", ""))[:100]}
            for a in list(self._action_history)[-5:]
        ]

        prompt = DECIDE_PROMPT.format(
            orientation=json.dumps({
                "threat_level": orientation.threat_level,
                "focus": orientation.recommended_focus,
                "insights": orientation.key_insights[:5],
                "change_approach": orientation.should_change_approach,
            }),
            tools=tools_desc,
            agent_types="recon, vuln_scan, web_scan, exploit, code_audit, network, osint, forensics",
            goals=self._goals_summary(),
            tokens_left=self._max_tokens - self._tokens_used,
            time_left=round(self._max_time_s - (time.time() - self._start_time), 0),
            steps_left=self._max_cycles - self._metrics.total_cycles,
            recent_actions=json.dumps(recent),
        )

        # Use appropriate reasoning strategy based on complexity
        strategy = self._select_reasoning_strategy(orientation)

        try:
            if strategy:
                trace = await self._reasoning.reason(
                    question=prompt,
                    strategy=strategy,
                    task_type="planning",
                )
                response_text = trace.final_answer
            else:
                response_text = await self._router.generate(
                    messages=[{"role": "user", "content": prompt}],
                    task_type="planning",
                    temperature=0.3,
                    max_tokens=2048,
                )

            data = self._parse_json(response_text)

            action_type_str = data.get("action_type", "tool_call")
            try:
                action_type = ActionType(action_type_str)
            except ValueError:
                action_type = ActionType.TOOL_CALL

            return Decision(
                action_type=action_type,
                action_params=data.get("params", {}),
                reasoning=data.get("reasoning", ""),
                confidence=data.get("confidence", 0.5),
                expected_outcome=data.get("expected_outcome", ""),
                strategy_used=strategy.value if strategy else "direct",
            )

        except Exception as e:
            self._log.warning("decide_error", error=str(e))
            return Decision(
                action_type=ActionType.LLM_REASON,
                action_params={"prompt": f"Analyze target {self._target} and suggest next steps"},
                reasoning="Fallback to general analysis",
                confidence=0.3,
            )

    async def _act(self, decision: Decision) -> dict[str, Any]:
        """Execute the decided action."""
        self._metrics.total_actions += 1
        action_type = decision.action_type.value
        self._metrics.actions_by_type[action_type] = (
            self._metrics.actions_by_type.get(action_type, 0) + 1
        )

        result: dict[str, Any] = {"type": action_type, "success": False}

        try:
            if decision.action_type == ActionType.TOOL_CALL:
                result = await self._act_tool_call(decision)
            elif decision.action_type == ActionType.LLM_REASON:
                result = await self._act_llm_reason(decision)
            elif decision.action_type == ActionType.SPAWN_AGENT:
                result = await self._act_spawn_agent(decision)
            elif decision.action_type == ActionType.REPORT_FINDING:
                result = await self._act_report_finding(decision)
            elif decision.action_type == ActionType.DELEGATE:
                result = await self._act_delegate(decision)
            elif decision.action_type == ActionType.BACKTRACK:
                result = {"type": "backtrack", "success": True}
                self._metrics.backtrack_count += 1
            elif decision.action_type == ActionType.REPLAN:
                result = await self._act_replan(decision)
            elif decision.action_type == ActionType.COMPLETE:
                result = {"type": "complete", "success": True}
            elif decision.action_type == ActionType.WAIT:
                await asyncio.sleep(min(5.0, decision.action_params.get("seconds", 2.0)))
                result = {"type": "wait", "success": True}
            else:
                result = {"type": action_type, "success": False, "error": "Unknown action"}

        except Exception as e:
            result = {"type": action_type, "success": False, "error": str(e)}
            self._errors.append(f"Action {action_type} failed: {e}")
            self._log.error("action_error", type=action_type, error=str(e))

        # Record action in history
        self._action_history.append({
            "type": action_type, "params": decision.action_params,
            "result": result, "reasoning": decision.reasoning,
            "cycle": self._metrics.total_cycles,
        })

        return result

    async def _post_action(self, decision: Decision, result: dict[str, Any]) -> None:
        """Post-action processing: self-correction, goal updates, plan updates."""
        # Update plan node status if applicable
        plan_node_id = decision.action_params.get("plan_node_id")
        if plan_node_id and self._plan and plan_node_id in self._plan.nodes:
            node = self._plan.nodes[plan_node_id]
            if result.get("success"):
                node.status = "completed"
                node.result = result
            else:
                node.retry_count += 1
                if node.retry_count >= node.max_retries:
                    node.status = "failed"
                    node.error = result.get("error", "")
                    # Trigger replanning
                    if self._planner:
                        self._plan = await self._planner.replan(
                            self._plan, plan_node_id, node.error,
                        )
                        self._metrics.replan_count += 1

        # Track convergence
        if not result.get("success") or not result.get("new_info"):
            self._cycles_without_progress += 1
        else:
            self._cycles_without_progress = 0

        # Self-correction every 5 cycles
        if self._metrics.total_cycles % 5 == 0 and self._metrics.total_cycles > 0:
            await self._self_correct(decision, result)

    async def _self_correct(self, decision: Decision, result: dict[str, Any]) -> None:
        """Periodically review and correct approach."""
        prompt = SELF_CORRECTION_PROMPT.format(
            action=json.dumps({"type": decision.action_type.value, "params": decision.action_params}),
            result=json.dumps(result)[:1000],
            goals=self._goals_summary(),
        )

        try:
            response = await self._router.generate(
                messages=[{"role": "user", "content": prompt}],
                task_type="reasoning",
                temperature=0.2,
                max_tokens=512,
            )
            data = self._parse_json(response)
            if data.get("correction_needed"):
                self._log.info("self_correction", correction=data.get("correction", ""))
        except Exception:
            pass

    # ── Action Implementations ─────────────────────────────

    async def _act_tool_call(self, decision: Decision) -> dict[str, Any]:
        """Execute a tool call action."""
        tool_name = decision.action_params.get("tool", "")
        args = decision.action_params.get("args", {})

        tool = self._tools.get(tool_name)
        if not tool:
            return {"type": "tool_call", "success": False, "error": f"Tool {tool_name} not found"}

        try:
            result = await tool.execute(**args)
            output = {
                "type": "tool_call", "tool": tool_name,
                "success": result.exit_code == 0,
                "stdout": result.stdout[:3000] if result.stdout else "",
                "stderr": result.stderr[:1000] if result.stderr else "",
                "new_info": bool(result.stdout),
            }
            self._tool_outputs.append(output)

            # Store in memory
            await self._memory.store_context(f"tool_{self._metrics.total_cycles}", {
                "tool": tool_name, "args": args,
                "output": result.stdout[:2000] if result.stdout else "",
            })

            return output
        except Exception as e:
            return {"type": "tool_call", "success": False, "error": str(e)}

    async def _act_llm_reason(self, decision: Decision) -> dict[str, Any]:
        """Execute an LLM reasoning action."""
        prompt = decision.action_params.get("prompt", "")
        try:
            response = await self._router.generate(
                messages=[{"role": "user", "content": prompt}],
                task_type="reasoning",
                temperature=0.3,
                max_tokens=4096,
            )
            return {
                "type": "llm_reason", "success": True,
                "response": response[:3000], "new_info": True,
            }
        except Exception as e:
            return {"type": "llm_reason", "success": False, "error": str(e)}

    async def _act_spawn_agent(self, decision: Decision) -> dict[str, Any]:
        """Spawn a child agent."""
        agent_type = decision.action_params.get("agent_type", "")
        objective = decision.action_params.get("objective", "")

        # Send delegation message if bus is available
        if self._bus:
            from recursec.agents.communication import AgentMessage, MessageType
            msg = AgentMessage(
                sender_id=self.agent_id,
                message_type=MessageType.DELEGATION,
                subject=f"spawn_{agent_type}",
                body={"agent_type": agent_type, "objective": objective, "target": self._target},
            )
            await self._bus.send(msg)
            return {"type": "spawn_agent", "success": True, "agent_type": agent_type}

        return {"type": "spawn_agent", "success": False, "error": "No message bus available"}

    async def _act_report_finding(self, decision: Decision) -> dict[str, Any]:
        """Report a security finding."""
        finding = decision.action_params.get("finding", {})
        if not finding:
            return {"type": "report_finding", "success": False, "error": "No finding data"}

        self._findings.append(finding)
        self._metrics.total_findings += 1

        # Broadcast finding
        if self._bus:
            from recursec.agents.communication import AgentMessage
            msg = AgentMessage.finding(self.agent_id, finding, finding.get("severity", "medium"))
            await self._bus.send(msg)

        # Store in memory
        await self._memory.store_finding(self.agent_id, finding)

        return {"type": "report_finding", "success": True, "finding_id": finding.get("id", "")}

    async def _act_delegate(self, decision: Decision) -> dict[str, Any]:
        """Delegate a task to another agent."""
        if not self._bus:
            return {"type": "delegate", "success": False, "error": "No message bus"}

        from recursec.agents.communication import AgentMessage
        receiver = decision.action_params.get("receiver", "")
        task_data = {
            "objective": decision.action_params.get("objective", ""),
            "target": self._target,
        }
        msg = AgentMessage.delegation(self.agent_id, receiver, task_data)
        response = await self._bus.request_response(msg, timeout=60.0)

        if response:
            return {"type": "delegate", "success": True, "response": response.body}
        return {"type": "delegate", "success": False, "error": "No response from delegate"}

    async def _act_replan(self, decision: Decision) -> dict[str, Any]:
        """Trigger replanning."""
        if not self._planner or not self._plan:
            return {"type": "replan", "success": False, "error": "No planner/plan"}

        self._plan = await self._planner.create_plan(
            objective=self._goals_summary(),
            target=self._target,
        )
        self._metrics.replan_count += 1
        return {"type": "replan", "success": True}

    # ── Helper Methods ──────────────────────────────────────

    def _check_budget(self) -> bool:
        """Check if we're within budget."""
        if self._tokens_used >= self._max_tokens:
            return False
        if time.time() - self._start_time >= self._max_time_s:
            return False
        return True

    def _check_convergence(self) -> bool:
        """Check if we've stopped making progress."""
        return self._cycles_without_progress >= self._convergence_threshold

    def _select_reasoning_strategy(self, orientation: Orientation) -> ReasoningStrategy | None:
        """Select reasoning strategy based on situation complexity."""
        from recursec.core.reasoning import ReasoningStrategy

        if orientation.should_change_approach:
            return ReasoningStrategy.TREE_OF_THOUGHT
        if orientation.threat_level == "critical":
            return ReasoningStrategy.MULTI_MODEL_CONSENSUS
        if orientation.confidence < 0.3:
            return ReasoningStrategy.DEBATE
        if self._metrics.backtrack_count > 2:
            return ReasoningStrategy.STEP_BACK
        # Simple cases use direct LLM call (no strategy overhead)
        return None

    def _estimate_progress(self) -> float:
        """Estimate overall progress percentage."""
        if self._plan:
            return self._plan.completion_percentage()
        if not self._goals:
            return 0.0
        achieved = sum(1 for g in self._goals.values() if g.status == GoalStatus.ACHIEVED)
        return (achieved / len(self._goals)) * 100 if self._goals else 0.0

    def _goals_summary(self) -> str:
        """Get a summary of current goals."""
        if not self._goals:
            return f"Assess security of {self._target}"
        return "; ".join(
            f"{g.description} ({g.status.value}, {g.progress:.0f}%)"
            for g in self._goals.values()
            if g.status == GoalStatus.ACTIVE
        )

    def _summarize_findings(self) -> str:
        """Summarize current findings."""
        if not self._findings:
            return "No findings yet"
        by_severity: dict[str, int] = {}
        for f in self._findings:
            sev = f.get("severity", "info")
            by_severity[sev] = by_severity.get(sev, 0) + 1
        return json.dumps({"total": len(self._findings), "by_severity": by_severity})

    def _get_available_tool_names(self) -> list[str]:
        """Get list of available tool names."""
        return [t.name for t in self._tools.list_tools()]

    def _parse_json(self, text: str) -> dict[str, Any]:
        """Parse JSON from LLM response."""
        try:
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]
            return json.loads(text.strip())
        except (json.JSONDecodeError, IndexError):
            return {}

    def _build_result(self) -> dict[str, Any]:
        """Build the final result dictionary."""
        return {
            "agent_id": self.agent_id,
            "target": self._target,
            "findings": self._findings,
            "metrics": {
                "total_cycles": self._metrics.total_cycles,
                "total_actions": self._metrics.total_actions,
                "total_findings": self._metrics.total_findings,
                "actions_by_type": self._metrics.actions_by_type,
                "avg_cycle_time_s": round(self._metrics.avg_cycle_time_s, 2),
                "backtrack_count": self._metrics.backtrack_count,
                "replan_count": self._metrics.replan_count,
            },
            "goals": {
                gid: {"description": g.description, "status": g.status.value, "progress": g.progress}
                for gid, g in self._goals.items()
            },
            "state": self._sm.state.value,
            "state_history": self._sm.get_history(),
            "errors": self._errors,
        }
