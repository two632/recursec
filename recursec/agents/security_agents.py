"""Specialized security agents — each one is a domain expert."""

from __future__ import annotations

import json
from typing import Any

import structlog

from recursec.agents.prompts import AGENT_PROMPTS
from recursec.core.base_agent import BaseAgent
from recursec.core.models import AgentRole, AgentTask

logger = structlog.get_logger()

# Map AgentRole to tool category filters
ROLE_TOOL_MAP: dict[AgentRole, list[str] | None] = {
    AgentRole.RECON: None,  # Recon gets all tools but prefers recon ones
    AgentRole.VULN_SCANNER: None,
    AgentRole.WEB_SCANNER: None,
    AgentRole.EXPLOIT: None,
    AgentRole.POST_EXPLOIT: None,
    AgentRole.CODE_AUDITOR: None,
    AgentRole.NETWORK_SCANNER: None,
    AgentRole.OSINT: None,
    AgentRole.FUZZER: None,
    AgentRole.CRYPTO_ANALYST: None,
    AgentRole.CLOUD_SCANNER: None,
    AgentRole.WIRELESS_SCANNER: None,
    AgentRole.FORENSICS: None,
    AgentRole.REPORT_WRITER: None,
    AgentRole.VALIDATOR: None,
}

# Task type to model preference
ROLE_MODEL_PREFERENCE: dict[AgentRole, str] = {
    AgentRole.ORCHESTRATOR: "reasoning",
    AgentRole.RECON: "general",
    AgentRole.VULN_SCANNER: "security",
    AgentRole.WEB_SCANNER: "security",
    AgentRole.EXPLOIT: "code",
    AgentRole.POST_EXPLOIT: "security",
    AgentRole.CODE_AUDITOR: "code",
    AgentRole.NETWORK_SCANNER: "general",
    AgentRole.OSINT: "general",
    AgentRole.FUZZER: "code",
    AgentRole.CRYPTO_ANALYST: "reasoning",
    AgentRole.CLOUD_SCANNER: "general",
    AgentRole.WIRELESS_SCANNER: "general",
    AgentRole.FORENSICS: "reasoning",
    AgentRole.REPORT_WRITER: "writing",
    AgentRole.VALIDATOR: "reasoning",
}


class SecurityAgent(BaseAgent):
    """Base implementation for all security-focused agents.

    Uses the ReAct (Reason + Act) pattern:
    1. Observe: Current state, previous results, task objective
    2. Think: What should I do next?
    3. Act: Execute a tool or spawn a child agent
    4. Repeat until objective is met
    """

    def _default_system_prompt(self) -> str:
        return AGENT_PROMPTS.get(self.role.value, AGENT_PROMPTS["orchestrator"])

    async def _plan(self, task: AgentTask) -> list[dict[str, Any]]:
        """Use the LLM to plan next actions (ReAct pattern)."""
        # Build context from previous actions
        context_parts = [
            f"OBJECTIVE: {task.objective}",
            f"TARGET: {task.target.value if task.target else 'Not specified'}",
            f"STEP: {task.step_count}/{self.max_steps}",
            f"DEPTH: {task.depth}/{self.max_depth}",
        ]

        if task.findings:
            context_parts.append(f"\nFINDINGS SO FAR ({len(task.findings)}):")
            for f in task.findings[-5:]:  # Last 5
                context_parts.append(f"  - [{f.severity.value}] {f.title}: {f.description[:100]}")

        if task.tool_results:
            context_parts.append("\nLAST TOOL RESULTS:")
            for tr in task.tool_results[-3:]:  # Last 3
                output = tr.stdout[:500] if tr.stdout else tr.stderr[:500]
                context_parts.append(f"  [{tr.tool_name}] exit={tr.exit_code}: {output}")

        if task.context.get("parent_findings"):
            context_parts.append("\nPARENT AGENT FINDINGS:")
            for pf in task.context["parent_findings"][-3:]:
                context_parts.append(f"  - {pf.get('title', 'Unknown')}")

        # Get available tools for the prompt
        tools = self.get_available_tools()
        tool_names = [t["function"]["name"] for t in tools[:50]]  # Limit to avoid context overflow
        context_parts.append(f"\nAVAILABLE TOOLS: {', '.join(tool_names)}")

        context_parts.append("""
Based on the above, decide your next action(s). Respond with a JSON array of actions.
Each action must have a "type" field. Valid types:
- {"type": "tool_call", "tool": "tool_name", "args": {"command": "full command"}}
- {"type": "spawn_agent", "child_role": "role_name", "objective": "what the child should do"}
- {"type": "report_finding", "title": "...", "severity": "critical|high|medium|low|info", "description": "...", "evidence": "...", "confidence": 0.0-1.0}
- {"type": "complete", "result": {"summary": "...", "key_findings": [...]}}
- {"type": "llm_call", "prompt": "question to reason about"}

Respond ONLY with a valid JSON array. No explanation text.""")

        prompt = "\n".join(context_parts)

        model_pref = ROLE_MODEL_PREFERENCE.get(self.role, "general")
        response = await self.model_router.generate(
            messages=[
                {"role": "system", "content": self.system_prompt},
                *[{"role": m.role, "content": m.content} for m in task.messages[-10:]],
                {"role": "user", "content": prompt},
            ],
            task_type=model_pref,
            temperature=0.3,
            max_tokens=4096,
        )

        return self._parse_actions(response)

    def _parse_actions(self, response: str) -> list[dict[str, Any]]:
        """Parse the LLM response into a list of actions."""
        # Try to extract JSON from the response
        response = response.strip()

        # Handle markdown code blocks
        if "```json" in response:
            start = response.index("```json") + 7
            end = response.index("```", start)
            response = response[start:end].strip()
        elif "```" in response:
            start = response.index("```") + 3
            end = response.index("```", start)
            response = response[start:end].strip()

        try:
            parsed = json.loads(response)
            if isinstance(parsed, list):
                return parsed
            if isinstance(parsed, dict):
                return [parsed]
        except json.JSONDecodeError:
            pass

        # Fallback: try to find JSON arrays/objects in the text
        for i, char in enumerate(response):
            if char in "[{":
                try:
                    parsed = json.loads(response[i:])
                    return parsed if isinstance(parsed, list) else [parsed]
                except json.JSONDecodeError:
                    continue

        # If all parsing fails, try to interpret as a completion
        if any(kw in response.lower() for kw in ["complete", "done", "finished", "no more"]):
            return [{"type": "complete", "result": {"summary": response}}]

        return []

    async def _execute_action(self, task: AgentTask, action: dict[str, Any]) -> dict[str, Any]:
        """Execute a generic action."""
        return {"status": "ok", "action": action}

    async def _should_recurse(self, task: AgentTask, action_result: dict[str, Any]) -> bool:
        """Check if we should recurse deeper."""
        return task.depth < self.max_depth


class OrchestratorAgent(SecurityAgent):
    """The DecisionBrain — decomposes targets and coordinates all other agents."""

    def __init__(self, **kwargs):
        super().__init__(role=AgentRole.ORCHESTRATOR, name="DecisionBrain", **kwargs)

    def _default_system_prompt(self) -> str:
        return AGENT_PROMPTS["orchestrator"]


class ReconAgent(SecurityAgent):
    def __init__(self, **kwargs):
        super().__init__(role=AgentRole.RECON, name="ReconAgent", **kwargs)

    def _default_system_prompt(self) -> str:
        return AGENT_PROMPTS["recon"]


class VulnScanAgent(SecurityAgent):
    def __init__(self, **kwargs):
        super().__init__(role=AgentRole.VULN_SCANNER, name="VulnScanAgent", **kwargs)

    def _default_system_prompt(self) -> str:
        return AGENT_PROMPTS["vuln_scanner"]


class WebScanAgent(SecurityAgent):
    def __init__(self, **kwargs):
        super().__init__(role=AgentRole.WEB_SCANNER, name="WebScanAgent", **kwargs)

    def _default_system_prompt(self) -> str:
        return AGENT_PROMPTS["web_scanner"]


class ExploitAgent(SecurityAgent):
    def __init__(self, **kwargs):
        super().__init__(role=AgentRole.EXPLOIT, name="ExploitAgent", **kwargs)

    def _default_system_prompt(self) -> str:
        return AGENT_PROMPTS["exploit"]


class PostExploitAgent(SecurityAgent):
    def __init__(self, **kwargs):
        super().__init__(role=AgentRole.POST_EXPLOIT, name="PostExploitAgent", **kwargs)

    def _default_system_prompt(self) -> str:
        return AGENT_PROMPTS["post_exploit"]


class CodeAuditAgent(SecurityAgent):
    def __init__(self, **kwargs):
        super().__init__(role=AgentRole.CODE_AUDITOR, name="CodeAuditAgent", **kwargs)

    def _default_system_prompt(self) -> str:
        return AGENT_PROMPTS["code_auditor"]


class NetworkAgent(SecurityAgent):
    def __init__(self, **kwargs):
        super().__init__(role=AgentRole.NETWORK_SCANNER, name="NetworkAgent", **kwargs)

    def _default_system_prompt(self) -> str:
        return AGENT_PROMPTS["network_scanner"]


class OSINTAgent(SecurityAgent):
    def __init__(self, **kwargs):
        super().__init__(role=AgentRole.OSINT, name="OSINTAgent", **kwargs)

    def _default_system_prompt(self) -> str:
        return AGENT_PROMPTS["osint"]


class FuzzerAgent(SecurityAgent):
    def __init__(self, **kwargs):
        super().__init__(role=AgentRole.FUZZER, name="FuzzerAgent", **kwargs)

    def _default_system_prompt(self) -> str:
        return AGENT_PROMPTS["fuzzer"]


class CryptoAgent(SecurityAgent):
    def __init__(self, **kwargs):
        super().__init__(role=AgentRole.CRYPTO_ANALYST, name="CryptoAgent", **kwargs)

    def _default_system_prompt(self) -> str:
        return AGENT_PROMPTS["crypto_analyst"]


class CloudAgent(SecurityAgent):
    def __init__(self, **kwargs):
        super().__init__(role=AgentRole.CLOUD_SCANNER, name="CloudAgent", **kwargs)

    def _default_system_prompt(self) -> str:
        return AGENT_PROMPTS["cloud_scanner"]


class ForensicsAgent(SecurityAgent):
    def __init__(self, **kwargs):
        super().__init__(role=AgentRole.FORENSICS, name="ForensicsAgent", **kwargs)

    def _default_system_prompt(self) -> str:
        return AGENT_PROMPTS["forensics"]


class ReportAgent(SecurityAgent):
    def __init__(self, **kwargs):
        super().__init__(role=AgentRole.REPORT_WRITER, name="ReportAgent", **kwargs)

    def _default_system_prompt(self) -> str:
        return AGENT_PROMPTS["report_writer"]


class ValidatorAgent(SecurityAgent):
    """Cross-validates findings from other agents to eliminate false positives."""

    def __init__(self, **kwargs):
        super().__init__(role=AgentRole.VALIDATOR, name="ValidatorAgent", **kwargs)

    def _default_system_prompt(self) -> str:
        return AGENT_PROMPTS["validator"]
