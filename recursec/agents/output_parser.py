"""Output parser — parses and structures LLM outputs for agent consumption.

Implements:
1. JSON extraction from LLM output
2. Structured data extraction
3. Action parsing (tool calls, decisions)
4. Confidence extraction
5. Finding extraction
6. Plan extraction
7. Error detection in outputs
8. Format validation and repair
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class ParsedAction:
    """A parsed action from LLM output."""
    action_type: str = ""        # tool_call, decision, delegate, report, think
    tool_name: str = ""
    tool_args: dict[str, Any] = field(default_factory=dict)
    reasoning: str = ""
    confidence: float = 0.5
    raw_text: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.action_type,
            "tool": self.tool_name[:30],
            "args": len(self.tool_args),
            "confidence": round(self.confidence, 2),
        }


@dataclass
class ParsedFinding:
    """A parsed security finding from LLM output."""
    title: str = ""
    severity: str = ""
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    confidence: float = 0.5
    cwe: str = ""
    cvss: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title[:40],
            "severity": self.severity,
            "confidence": round(self.confidence, 2),
        }


@dataclass
class ParsedPlan:
    """A parsed plan from LLM output."""
    steps: list[dict[str, str]] = field(default_factory=list)
    tools_needed: list[str] = field(default_factory=list)
    estimated_time_s: float = 0.0
    priority: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "steps": len(self.steps),
            "tools": self.tools_needed[:5],
            "priority": self.priority,
        }


@dataclass
class ParseResult:
    """Result of parsing LLM output."""
    success: bool = False
    actions: list[ParsedAction] = field(default_factory=list)
    findings: list[ParsedFinding] = field(default_factory=list)
    plan: ParsedPlan | None = None
    json_data: dict[str, Any] | None = None
    thinking: str = ""
    summary: str = ""
    errors: list[str] = field(default_factory=list)
    raw_text: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "actions": len(self.actions),
            "findings": len(self.findings),
            "has_plan": self.plan is not None,
            "has_json": self.json_data is not None,
            "errors": len(self.errors),
        }


# ── Extraction Patterns ───────────────────────────────────────

JSON_BLOCK_PATTERN = re.compile(r"```(?:json)?\s*\n?(.*?)\n?```", re.DOTALL)
JSON_OBJECT_PATTERN = re.compile(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", re.DOTALL)
TOOL_CALL_PATTERN = re.compile(
    r"(?:TOOL|ACTION|EXECUTE|RUN):\s*(\w+)\s*\((.*?)\)",
    re.IGNORECASE | re.DOTALL,
)
CONFIDENCE_PATTERN = re.compile(
    r"(?:confidence|certainty|probability)[\s:]*(\d+(?:\.\d+)?)\s*%?",
    re.IGNORECASE,
)
SEVERITY_PATTERN = re.compile(
    r"(?:severity|risk)[\s:]*(?:level\s*)?[\s:]*(critical|high|medium|low|info)",
    re.IGNORECASE,
)
THINKING_PATTERN = re.compile(
    r"<think(?:ing)?>(.*?)</think(?:ing)?>",
    re.DOTALL | re.IGNORECASE,
)
PLAN_STEP_PATTERN = re.compile(
    r"(?:^|\n)\s*(?:\d+[\.\)]\s*|[-*]\s*)(.*?)(?=\n|$)",
)


class OutputParser:
    """Parses and structures LLM outputs for agent consumption.

    Extracts actions, findings, plans, and structured data
    from free-form LLM responses.
    """

    def __init__(self) -> None:
        self._parse_counter = 0
        self._total_errors = 0
        self._log = logger.bind(component="output_parser")

    def parse(self, text: str) -> ParseResult:
        """Parse LLM output into structured data."""
        self._parse_counter += 1
        result = ParseResult(raw_text=text)

        if not text or not text.strip():
            result.errors.append("Empty output")
            return result

        # Extract thinking blocks
        thinking_match = THINKING_PATTERN.search(text)
        if thinking_match:
            result.thinking = thinking_match.group(1).strip()

        # Try JSON extraction
        json_data = self._extract_json(text)
        if json_data:
            result.json_data = json_data
            result.success = True

            # Parse structured fields from JSON
            if isinstance(json_data, dict):
                self._parse_json_fields(json_data, result)

        # Extract actions
        actions = self._extract_actions(text)
        if actions:
            result.actions = actions
            result.success = True

        # Extract findings
        findings = self._extract_findings(text)
        if findings:
            result.findings = findings
            result.success = True

        # Extract plan
        plan = self._extract_plan(text)
        if plan and plan.steps:
            result.plan = plan
            result.success = True

        # Generate summary
        if not result.success:
            result.summary = text[:200].strip()
            result.success = True  # Raw text is valid output

        if result.errors:
            self._total_errors += len(result.errors)

        return result

    def _extract_json(self, text: str) -> dict[str, Any] | list[Any] | None:
        """Extract JSON from text."""
        # Try code blocks first
        matches = JSON_BLOCK_PATTERN.findall(text)
        for match in matches:
            try:
                return json.loads(match.strip())
            except json.JSONDecodeError:
                continue

        # Try raw JSON objects
        matches = JSON_OBJECT_PATTERN.findall(text)
        for match in matches:
            try:
                return json.loads(match)
            except json.JSONDecodeError:
                continue

        # Try the whole text as JSON
        try:
            return json.loads(text.strip())
        except json.JSONDecodeError:
            return None

    def _extract_actions(self, text: str) -> list[ParsedAction]:
        """Extract tool call actions from text."""
        actions = []

        # Pattern-based extraction
        for match in TOOL_CALL_PATTERN.finditer(text):
            tool_name = match.group(1).strip()
            args_str = match.group(2).strip()

            # Parse arguments
            args = self._parse_tool_args(args_str)

            actions.append(ParsedAction(
                action_type="tool_call",
                tool_name=tool_name,
                tool_args=args,
                raw_text=match.group(0),
            ))

        # Check JSON for actions
        json_data = self._extract_json(text)
        if isinstance(json_data, dict):
            if "action" in json_data:
                action = json_data["action"]
                if isinstance(action, dict):
                    actions.append(ParsedAction(
                        action_type=action.get("type", "tool_call"),
                        tool_name=action.get("tool", action.get("name", "")),
                        tool_args=action.get("args", action.get("arguments", {})),
                        reasoning=action.get("reasoning", ""),
                    ))

            if "actions" in json_data and isinstance(json_data["actions"], list):
                for act in json_data["actions"]:
                    if isinstance(act, dict):
                        actions.append(ParsedAction(
                            action_type=act.get("type", "tool_call"),
                            tool_name=act.get("tool", act.get("name", "")),
                            tool_args=act.get("args", act.get("arguments", {})),
                        ))

        # Extract confidence
        conf_match = CONFIDENCE_PATTERN.search(text)
        if conf_match and actions:
            conf_val = float(conf_match.group(1))
            if conf_val > 1:
                conf_val /= 100
            for action in actions:
                action.confidence = conf_val

        return actions

    def _extract_findings(self, text: str) -> list[ParsedFinding]:
        """Extract security findings from text."""
        findings = []

        # Try JSON extraction
        json_data = self._extract_json(text)
        if isinstance(json_data, dict):
            finding_list = json_data.get("findings", json_data.get("vulnerabilities", []))
            if isinstance(finding_list, list):
                for item in finding_list:
                    if isinstance(item, dict):
                        findings.append(ParsedFinding(
                            title=item.get("title", item.get("name", "")),
                            severity=item.get("severity", "medium"),
                            description=item.get("description", item.get("desc", "")),
                            evidence=item.get("evidence", ""),
                            remediation=item.get("remediation", item.get("fix", "")),
                            confidence=item.get("confidence", 0.5),
                            cwe=item.get("cwe", ""),
                            cvss=item.get("cvss", 0.0),
                        ))

        # Pattern-based severity extraction
        if not findings:
            severity_matches = SEVERITY_PATTERN.finditer(text)
            for match in severity_matches:
                severity = match.group(1).lower()
                # Get surrounding context
                start = max(0, match.start() - 100)
                end = min(len(text), match.end() + 200)
                context = text[start:end].strip()

                findings.append(ParsedFinding(
                    title=context[:60],
                    severity=severity,
                    description=context,
                ))

        return findings

    def _extract_plan(self, text: str) -> ParsedPlan:
        """Extract a plan from text."""
        plan = ParsedPlan()

        # Try JSON
        json_data = self._extract_json(text)
        if isinstance(json_data, dict) and "steps" in json_data:
            steps = json_data["steps"]
            if isinstance(steps, list):
                for step in steps:
                    if isinstance(step, dict):
                        plan.steps.append(step)
                    elif isinstance(step, str):
                        plan.steps.append({"description": step})
                plan.tools_needed = json_data.get("tools", [])
                return plan

        # Pattern-based step extraction
        step_matches = PLAN_STEP_PATTERN.findall(text)
        for step_text in step_matches:
            step_text = step_text.strip()
            if len(step_text) > 10:  # Filter noise
                plan.steps.append({"description": step_text})

        return plan

    def _parse_json_fields(
        self,
        data: dict[str, Any],
        result: ParseResult,
    ) -> None:
        """Parse common fields from JSON data."""
        if "reasoning" in data:
            result.thinking = str(data["reasoning"])[:500]
        if "summary" in data:
            result.summary = str(data["summary"])[:200]

    @staticmethod
    def _parse_tool_args(args_str: str) -> dict[str, Any]:
        """Parse tool arguments from string."""
        args: dict[str, Any] = {}
        if not args_str:
            return args

        # Try JSON
        try:
            parsed = json.loads(args_str)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass

        # Try key=value pairs
        for part in args_str.split(","):
            part = part.strip()
            if "=" in part:
                key, _, value = part.partition("=")
                args[key.strip()] = value.strip().strip("\"'")
            elif part:
                args[f"arg{len(args)}"] = part.strip().strip("\"'")

        return args

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_parsed": self._parse_counter,
            "total_errors": self._total_errors,
        }
