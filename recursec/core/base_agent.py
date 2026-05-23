"""Base agent class — the foundation for all RecurSec agents."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

import structlog

from recursec.core.models import (
    AgentRole,
    AgentTask,
    TaskMessage,
    TaskStatus,
    ToolResult,
    Vulnerability,
)
from recursec.tools.parsers import parse_tool_output

if TYPE_CHECKING:
    from recursec.llm.router import ModelRouter
    from recursec.memory.store import MemoryStore
    from recursec.tools.registry import ToolRegistry

logger = structlog.get_logger()


class BaseAgent(ABC):
    """Base class for all agents in the RecurSec framework.

    Every agent has:
    - A role defining its specialization
    - Access to an LLM via the model router
    - Access to tools via the tool registry
    - Access to shared memory
    - The ability to spawn child agents (recursive)
    """

    def __init__(
        self,
        role: AgentRole,
        name: str,
        model_router: ModelRouter,
        tool_registry: ToolRegistry,
        memory: MemoryStore,
        system_prompt: str = "",
        max_steps: int = 50,
        max_depth: int = 5,
        tools_allowed: list[str] | None = None,
        custom_config: dict[str, Any] | None = None,
    ):
        self.role = role
        self.name = name
        self.model_router = model_router
        self.tool_registry = tool_registry
        self.memory = memory
        self.system_prompt = system_prompt or self._default_system_prompt()
        self.max_steps = max_steps
        self.max_depth = max_depth
        self.tools_allowed = tools_allowed
        self.custom_config = custom_config or {}
        self._child_agents: list[BaseAgent] = []
        self._log = logger.bind(agent=self.name, role=self.role.value)

    @abstractmethod
    def _default_system_prompt(self) -> str:
        """Return the default system prompt for this agent type."""

    @abstractmethod
    async def _plan(self, task: AgentTask) -> list[dict[str, Any]]:
        """Plan the next actions for the given task. Returns a list of action dicts."""

    @abstractmethod
    async def _execute_action(self, task: AgentTask, action: dict[str, Any]) -> dict[str, Any]:
        """Execute a single action and return the result."""

    @abstractmethod
    async def _should_recurse(self, task: AgentTask, action_result: dict[str, Any]) -> bool:
        """Determine if this action requires spawning a child agent."""

    async def run(self, task: AgentTask) -> AgentTask:
        """Main execution loop for the agent."""
        task.status = TaskStatus.RUNNING
        task.started_at = __import__("datetime").datetime.utcnow()
        self._log.info("agent_started", task_id=task.id, objective=task.objective[:100])

        try:
            # Add system message
            task.messages.append(TaskMessage(
                role="system",
                content=self.system_prompt,
            ))

            # Store initial context in memory
            await self.memory.store_context(task.id, {
                "role": self.role.value,
                "objective": task.objective,
                "target": task.target.model_dump() if task.target else None,
                "depth": task.depth,
            })

            while task.step_count < self.max_steps and task.status == TaskStatus.RUNNING:
                task.step_count += 1
                self._log.info("step", step=task.step_count, max=self.max_steps)

                # Plan next actions
                actions = await self._plan(task)

                if not actions:
                    self._log.info("no_more_actions", step=task.step_count)
                    break

                for action in actions:
                    action_type = action.get("type", "")

                    if action_type == "tool_call":
                        result = await self._execute_tool(task, action)
                        task.tool_results.append(result)
                        task.messages.append(TaskMessage(
                            role="tool",
                            content=result.stdout or result.stderr,
                            tool_results=[result],
                        ))

                    elif action_type == "spawn_agent":
                        if task.depth < self.max_depth:
                            child_result = await self._spawn_child(task, action)
                            task.child_task_ids.append(child_result.id)
                            # Inherit findings from child
                            task.findings.extend(child_result.findings)
                        else:
                            self._log.warning("max_depth_reached", depth=task.depth)

                    elif action_type == "llm_call":
                        result = await self._call_llm(task, action)
                        task.messages.append(TaskMessage(
                            role="assistant",
                            content=result,
                        ))

                    elif action_type == "report_finding":
                        vuln = self._parse_finding(action)
                        if vuln:
                            task.findings.append(vuln)
                            await self.memory.store_finding(task.id, vuln)
                            self._log.info("finding_reported", vuln_id=vuln.id, title=vuln.title, severity=vuln.severity.value)

                    elif action_type == "complete":
                        task.result = action.get("result", {})
                        task.status = TaskStatus.COMPLETED
                        break

                    elif action_type == "fail":
                        task.error = action.get("error", "Unknown error")
                        task.status = TaskStatus.FAILED
                        break

                    else:
                        result = await self._execute_action(task, action)
                        if result.get("status") == "error":
                            self._log.error("action_failed", action=action_type, error=result.get("error"))

            if task.status == TaskStatus.RUNNING:
                task.status = TaskStatus.COMPLETED

        except Exception as e:
            self._log.error("agent_error", error=str(e), exc_info=True)
            task.status = TaskStatus.FAILED
            task.error = str(e)

        task.completed_at = __import__("datetime").datetime.utcnow()
        self._log.info(
            "agent_finished",
            status=task.status.value,
            steps=task.step_count,
            findings=len(task.findings),
            children=len(task.child_task_ids),
        )
        return task

    async def _execute_tool(self, task: AgentTask, action: dict[str, Any]) -> ToolResult:
        """Execute a tool and return the result."""
        tool_name = action.get("tool", "")
        args = action.get("args", {})

        if self.tools_allowed and tool_name not in self.tools_allowed:
            return ToolResult(
                tool_name=tool_name,
                command=str(args),
                stderr=f"Tool '{tool_name}' not allowed for this agent",
                exit_code=1,
            )

        tool = self.tool_registry.get(tool_name)
        if not tool:
            return ToolResult(
                tool_name=tool_name,
                command=str(args),
                stderr=f"Tool '{tool_name}' not found in registry",
                exit_code=1,
            )

        start = time.monotonic()
        try:
            result = await tool.execute(**args)
            result.execution_time_s = time.monotonic() - start

            # Auto-parse tool output into structured data
            if result.stdout and result.exit_code == 0:
                parsed = parse_tool_output(tool_name, result.stdout)
                if parsed and parsed != {"raw": result.stdout[:5000]}:
                    result.parsed_data = parsed

            return result
        except Exception as e:
            return ToolResult(
                tool_name=tool_name,
                command=str(args),
                stderr=str(e),
                exit_code=1,
                execution_time_s=time.monotonic() - start,
            )

    async def _call_llm(self, task: AgentTask, action: dict[str, Any]) -> str:
        """Call the LLM and return the response."""
        messages = []
        for msg in task.messages:
            messages.append({"role": msg.role, "content": msg.content})

        prompt = action.get("prompt", "")
        if prompt:
            messages.append({"role": "user", "content": prompt})

        model_preference = action.get("model_preference", self.role.value)
        response = await self.model_router.generate(
            messages=messages,
            task_type=model_preference,
            temperature=action.get("temperature", 0.3),
            max_tokens=action.get("max_tokens", 4096),
        )
        return response

    async def _spawn_child(self, task: AgentTask, action: dict[str, Any]) -> AgentTask:
        """Spawn a child agent for a sub-task."""
        from recursec.agents.factory import AgentFactory

        child_role = AgentRole(action.get("child_role", "custom"))
        child_objective = action.get("objective", "")

        self._log.info("spawning_child", child_role=child_role.value, objective=child_objective[:80])

        child_agent = AgentFactory.create(
            role=child_role,
            model_router=self.model_router,
            tool_registry=self.tool_registry,
            memory=self.memory,
        )

        child_task = AgentTask(
            parent_task_id=task.id,
            agent_role=child_role,
            objective=child_objective,
            target=task.target,
            depth=task.depth + 1,
            max_depth=self.max_depth,
            context={**task.context, "parent_findings": [f.model_dump() for f in task.findings]},
        )

        result = await child_agent.run(child_task)
        self._child_agents.append(child_agent)
        return result

    def _parse_finding(self, action: dict[str, Any]) -> Vulnerability | None:
        """Parse a finding action into a Vulnerability."""
        try:
            return Vulnerability(
                title=action.get("title", "Unknown"),
                severity=action.get("severity", "info"),
                description=action.get("description", ""),
                evidence=action.get("evidence", ""),
                affected_component=action.get("affected_component", ""),
                confidence=action.get("confidence", 0.5),
                tool_source=action.get("tool_source", self.name),
                cvss_score=action.get("cvss_score"),
                cve_id=action.get("cve_id"),
                cwe_id=action.get("cwe_id"),
                reproduction_steps=action.get("reproduction_steps", []),
                remediation=action.get("remediation", ""),
            )
        except Exception as e:
            self._log.error("parse_finding_error", error=str(e))
            return None

    def get_available_tools(self) -> list[dict[str, Any]]:
        """Get tool descriptions for the LLM."""
        tools = self.tool_registry.list_tools(
            category=None,
            allowed=self.tools_allowed,
        )
        return [t.to_llm_schema() for t in tools]
