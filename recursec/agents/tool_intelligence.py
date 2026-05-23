"""Tool intelligence — smart tool selection, chaining, and output interpretation.

This module provides the intelligence layer between the agent brain and
external tools. Instead of blindly calling tools, it:

1. Selects the optimal tool for a given task context
2. Chains tools together (output of one feeds into next)
3. Interprets tool output using LLMs
4. Retries with different parameters on failure
5. Validates tool output for consistency
6. Builds tool execution plans (pipelines)
7. Learns which tool combinations work best

Tool chain examples:
- Recon: subfinder → httpx → nuclei (discover → probe → scan)
- Web: nmap → nikto → sqlmap (port scan → web scan → injection)
- Code: semgrep → bandit → grype (SAST → secrets → dependencies)
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from recursec.llm.router import ModelRouter
    from recursec.tools.registry import ToolRegistry

logger = structlog.get_logger()


@dataclass
class ToolChainStep:
    """A single step in a tool chain."""
    step_id: int = 0
    tool_name: str = ""
    args: dict[str, Any] = field(default_factory=dict)
    input_from: int | None = None  # step_id to take input from
    input_transform: str = ""  # How to transform input ("lines", "json_field", "regex")
    transform_params: dict[str, str] = field(default_factory=dict)
    condition: str = ""  # Only run if condition met ("has_output", "exit_0", "always")
    timeout_s: float = 120.0
    retry_count: int = 0
    max_retries: int = 1
    result: dict[str, Any] | None = None
    executed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step_id, "tool": self.tool_name,
            "args": self.args, "input_from": self.input_from,
            "condition": self.condition, "executed": self.executed,
            "has_result": self.result is not None,
        }


@dataclass
class ToolChain:
    """A sequence of tools to execute in order."""
    chain_id: str = ""
    name: str = ""
    description: str = ""
    steps: list[ToolChainStep] = field(default_factory=list)
    parallel_groups: list[list[int]] = field(default_factory=list)  # Steps that can run in parallel
    total_time_s: float = 0.0
    findings: list[dict[str, Any]] = field(default_factory=list)

    def add_step(
        self, tool_name: str, args: dict[str, Any] | None = None,
        input_from: int | None = None, condition: str = "always",
    ) -> int:
        step_id = len(self.steps)
        self.steps.append(ToolChainStep(
            step_id=step_id, tool_name=tool_name,
            args=args or {}, input_from=input_from,
            condition=condition,
        ))
        return step_id


# ── Predefined Tool Chains ──────────────────────────────────

PREDEFINED_CHAINS: dict[str, list[dict[str, Any]]] = {
    "web_recon": [
        {"tool": "subfinder", "args": {"flags": ["-silent"]}, "condition": "always"},
        {"tool": "httpx", "args": {"flags": ["-silent", "-status-code", "-title"]}, "input_from": 0, "input_transform": "lines"},
        {"tool": "nuclei", "args": {"flags": ["-severity", "critical,high"]}, "input_from": 1, "input_transform": "lines"},
    ],
    "web_scan": [
        {"tool": "nmap", "args": {"flags": ["-sV", "-sC", "--top-ports", "100"]}, "condition": "always"},
        {"tool": "nikto", "args": {}, "input_from": 0, "input_transform": "web_ports"},
        {"tool": "gobuster", "args": {"mode": "dir", "wordlist": "/usr/share/wordlists/dirb/common.txt"}, "condition": "always"},
    ],
    "vuln_scan": [
        {"tool": "nmap", "args": {"flags": ["-sV", "--script", "vuln"]}, "condition": "always"},
        {"tool": "nuclei", "args": {"flags": ["-as"]}, "condition": "always"},
    ],
    "code_audit": [
        {"tool": "semgrep", "args": {"flags": ["--config", "auto"]}, "condition": "always"},
        {"tool": "bandit", "args": {"flags": ["-r", "-f", "json"]}, "condition": "always"},
        {"tool": "trufflehog", "args": {}, "condition": "always"},
    ],
    "network_recon": [
        {"tool": "nmap", "args": {"flags": ["-sn"]}, "condition": "always"},
        {"tool": "nmap", "args": {"flags": ["-sV", "-O", "--top-ports", "1000"]}, "input_from": 0, "input_transform": "hosts"},
        {"tool": "masscan", "args": {"flags": ["-p0-65535", "--rate=1000"]}, "condition": "always"},
    ],
    "injection_test": [
        {"tool": "sqlmap", "args": {"flags": ["--batch", "--level=3", "--risk=2"]}, "condition": "always"},
        {"tool": "commix", "args": {"flags": ["--batch"]}, "condition": "always"},
    ],
}


# ── Prompt Templates ──────────────────────────────────────

SELECT_TOOL_PROMPT = """You are a security tool expert. Select the best tool for this task.

Task: {task}
Target: {target}
Target type: {target_type}
Available tools: {tools}
Previous tool results: {previous_results}
Constraints: {constraints}

Select the single best tool and its arguments. Respond as JSON:
{{
  "tool": "tool_name",
  "args": {{}},
  "reasoning": "why this tool",
  "expected_output": "what we expect"
}}"""

CHAIN_TOOLS_PROMPT = """Design a tool chain (sequence of tools) for this security task.

Task: {task}
Target: {target}
Available tools: {tools}
Context: {context}

Design a chain of 2-5 tools that should be run in sequence, where each tool's output
feeds into the next. Respond as JSON:
{{
  "chain_name": "descriptive name",
  "steps": [
    {{
      "tool": "tool_name",
      "args": {{}},
      "input_from_step": null or step_index,
      "input_transform": "lines|json_field|regex|none",
      "condition": "always|has_output|exit_0",
      "reason": "why this step"
    }}
  ],
  "parallel_groups": [[0, 1], [2, 3]]  // steps that can run in parallel
}}"""

INTERPRET_OUTPUT_PROMPT = """Interpret this tool output and extract security-relevant findings.

Tool: {tool}
Target: {target}
Raw output (truncated):
{output}

Extract:
1. Any vulnerabilities found (with severity)
2. Interesting information discovered
3. Recommendations for next steps
4. Potential false positives

Respond as JSON:
{{
  "findings": [
    {{
      "title": "...",
      "severity": "critical|high|medium|low|info",
      "description": "...",
      "evidence": "...",
      "confidence": 0.X,
      "affected_component": "..."
    }}
  ],
  "interesting_info": ["..."],
  "next_steps": ["..."],
  "potential_false_positives": ["..."]
}}"""

RETRY_STRATEGY_PROMPT = """A tool execution failed. Suggest a retry strategy.

Tool: {tool}
Original args: {args}
Error: {error}
Target: {target}
Available alternative tools: {alternatives}

Options:
1. Retry with different arguments
2. Use an alternative tool
3. Skip this step

Respond as JSON:
{{
  "action": "retry|alternative|skip",
  "tool": "tool_name",
  "args": {{}},
  "reasoning": "..."
}}"""


class ToolIntelligence:
    """Smart tool selection, chaining, and output interpretation."""

    def __init__(
        self,
        model_router: ModelRouter,
        tool_registry: ToolRegistry,
    ) -> None:
        self._router = model_router
        self._tools = tool_registry
        self._chain_history: list[dict[str, Any]] = []
        self._tool_success_rates: dict[str, dict[str, float]] = {}  # tool → target_type → rate
        self._log = logger.bind(component="tool_intelligence")

    async def select_tool(
        self,
        task: str,
        target: str,
        target_type: str = "",
        previous_results: list[dict[str, Any]] | None = None,
        constraints: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Select the best tool for a task using LLM reasoning."""
        available = [t.name for t in self._tools.list_tools()]

        prompt = SELECT_TOOL_PROMPT.format(
            task=task, target=target, target_type=target_type,
            tools=", ".join(available[:40]),
            previous_results=json.dumps(previous_results or [])[:1000],
            constraints=json.dumps(constraints or {}),
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="function_call",
            temperature=0.2,
            max_tokens=1024,
        )

        data = self._parse_json(response)
        tool_name = data.get("tool", "")

        # Validate tool exists
        if tool_name and self._tools.get(tool_name):
            return data

        # Fallback: use first available tool that matches task keywords
        return {"tool": available[0] if available else "", "args": {}, "reasoning": "fallback"}

    async def build_chain(
        self,
        task: str,
        target: str,
        context: dict[str, Any] | None = None,
    ) -> ToolChain:
        """Build a tool chain for a complex task."""
        available = [t.name for t in self._tools.list_tools()]

        # Check if there's a predefined chain that matches
        chain = self._match_predefined_chain(task)
        if chain:
            return chain

        # Use LLM to design a custom chain
        prompt = CHAIN_TOOLS_PROMPT.format(
            task=task, target=target,
            tools=", ".join(available[:40]),
            context=json.dumps(context or {})[:1000],
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="planning",
            temperature=0.3,
            max_tokens=2048,
        )

        data = self._parse_json(response)
        chain = ToolChain(
            name=data.get("chain_name", "custom_chain"),
            description=task,
        )

        for step_data in data.get("steps", []):
            chain.add_step(
                tool_name=step_data.get("tool", ""),
                args=step_data.get("args", {}),
                input_from=step_data.get("input_from_step"),
                condition=step_data.get("condition", "always"),
            )

        chain.parallel_groups = data.get("parallel_groups", [])
        return chain

    async def execute_chain(self, chain: ToolChain, target: str) -> ToolChain:
        """Execute a tool chain step by step."""
        start = time.time()

        for step in chain.steps:
            # Check condition
            if step.condition == "has_output" and step.input_from is not None:
                prev = chain.steps[step.input_from] if step.input_from < len(chain.steps) else None
                if not prev or not prev.result or not prev.result.get("stdout"):
                    continue

            # Prepare input from previous step
            args = dict(step.args)
            if step.input_from is not None and step.input_from < len(chain.steps):
                prev_result = chain.steps[step.input_from].result
                if prev_result and prev_result.get("stdout"):
                    transformed = self._transform_input(
                        prev_result["stdout"],
                        step.input_transform,
                        step.transform_params,
                    )
                    args["target"] = transformed

            if not args.get("target"):
                args["target"] = target

            # Execute tool
            tool = self._tools.get(step.tool_name)
            if not tool:
                step.result = {"success": False, "error": f"Tool {step.tool_name} not found"}
                continue

            try:
                result = await tool.execute(**args)
                step.result = {
                    "success": result.exit_code == 0,
                    "stdout": result.stdout[:5000] if result.stdout else "",
                    "stderr": result.stderr[:1000] if result.stderr else "",
                    "exit_code": result.exit_code,
                }
                step.executed = True

                # Interpret output if successful
                if result.exit_code == 0 and result.stdout:
                    findings = await self.interpret_output(
                        step.tool_name, target, result.stdout[:3000],
                    )
                    chain.findings.extend(findings)

            except Exception as e:
                step.result = {"success": False, "error": str(e)}

                # Try retry strategy
                if step.retry_count < step.max_retries:
                    retry = await self._get_retry_strategy(
                        step.tool_name, args, str(e), target,
                    )
                    if retry.get("action") == "retry":
                        step.retry_count += 1
                        step.args = retry.get("args", step.args)
                        # Re-execute would happen on next loop

        chain.total_time_s = time.time() - start
        return chain

    async def interpret_output(
        self,
        tool_name: str,
        target: str,
        output: str,
    ) -> list[dict[str, Any]]:
        """Use LLM to interpret tool output and extract findings."""
        prompt = INTERPRET_OUTPUT_PROMPT.format(
            tool=tool_name, target=target,
            output=output[:4000],
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="security",
            temperature=0.2,
            max_tokens=2048,
        )

        data = self._parse_json(response)
        findings = data.get("findings", [])

        # Add source metadata
        for finding in findings:
            finding["tool_source"] = tool_name
            finding["interpreted_by_llm"] = True

        return findings

    async def _get_retry_strategy(
        self,
        tool_name: str,
        args: dict[str, Any],
        error: str,
        target: str,
    ) -> dict[str, Any]:
        """Get retry strategy from LLM."""
        available = [t.name for t in self._tools.list_tools() if t.name != tool_name]

        prompt = RETRY_STRATEGY_PROMPT.format(
            tool=tool_name, args=json.dumps(args),
            error=error[:500], target=target,
            alternatives=", ".join(available[:20]),
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="planning",
            temperature=0.2,
            max_tokens=512,
        )

        return self._parse_json(response)

    def _match_predefined_chain(self, task: str) -> ToolChain | None:
        """Match task to a predefined chain."""
        task_lower = task.lower()
        for chain_name, steps_data in PREDEFINED_CHAINS.items():
            keywords = chain_name.replace("_", " ").split()
            if any(kw in task_lower for kw in keywords):
                chain = ToolChain(name=chain_name, description=task)
                for step_data in steps_data:
                    chain.add_step(
                        tool_name=step_data["tool"],
                        args=step_data.get("args", {}),
                        input_from=step_data.get("input_from"),
                        condition=step_data.get("condition", "always"),
                    )
                return chain
        return None

    def _transform_input(
        self,
        raw_output: str,
        transform: str,
        params: dict[str, str],
    ) -> str:
        """Transform tool output for the next tool's input."""
        if transform == "lines":
            lines = [line.strip() for line in raw_output.strip().splitlines() if line.strip()]
            return "\n".join(lines)
        if transform == "json_field":
            field_name = params.get("field", "")
            try:
                data = json.loads(raw_output)
                if isinstance(data, list):
                    return "\n".join(str(item.get(field_name, "")) for item in data)
                return str(data.get(field_name, ""))
            except json.JSONDecodeError:
                return raw_output
        if transform == "hosts":
            # Extract IP addresses from nmap-style output
            import re
            ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', raw_output)
            return "\n".join(sorted(set(ips)))
        if transform == "web_ports":
            # Extract host:port for web services
            import re
            ports = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+).*(?:http|https)', raw_output)
            return "\n".join(f"{ip}:{port}" for ip, port in ports)
        return raw_output

    def _parse_json(self, text: str) -> dict[str, Any]:
        try:
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]
            return json.loads(text.strip())
        except (json.JSONDecodeError, IndexError):
            return {}
