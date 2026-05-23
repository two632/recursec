"""Output parser — parses LLM responses into structured data.

Implements:
1. JSON extraction from LLM output
2. Finding extraction from free text
3. Tool command extraction
4. Structured response parsing
5. Confidence score extraction
6. Action plan parsing
7. Error-tolerant parsing with fallbacks
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ParsedType(str, Enum):
    FINDING = "finding"
    TOOL_COMMAND = "tool_command"
    ANALYSIS = "analysis"
    PLAN = "plan"
    VERDICT = "verdict"
    RAW_TEXT = "raw_text"
    ERROR = "error"


@dataclass
class ParsedFinding:
    """A finding extracted from LLM output."""
    title: str = ""
    severity: str = "medium"
    description: str = ""
    cwe: str = ""
    cve: str = ""
    evidence: str = ""
    confidence: float = 0.5
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title[:30],
            "severity": self.severity,
            "cwe": self.cwe[:10],
            "confidence": round(self.confidence, 2),
        }


@dataclass
class ParsedCommand:
    """A tool command extracted from LLM output."""
    tool: str = ""
    command: str = ""
    args: list[str] = field(default_factory=list)
    purpose: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool[:10],
            "command": self.command[:30],
        }


@dataclass
class ParsedPlan:
    """An action plan extracted from LLM output."""
    steps: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "steps": len(self.steps),
            "tools": self.tools[:5],
        }


@dataclass
class ParseResult:
    """Result of parsing LLM output."""
    parsed_type: ParsedType = ParsedType.RAW_TEXT
    findings: list[ParsedFinding] = field(default_factory=list)
    commands: list[ParsedCommand] = field(default_factory=list)
    plan: ParsedPlan | None = None
    raw_text: str = ""
    json_data: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.5

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.parsed_type.value,
            "findings": len(self.findings),
            "commands": len(self.commands),
            "confidence": round(self.confidence, 2),
        }


# ── Parsing patterns ─────────────────────────────────────────

SEVERITY_PATTERNS = re.compile(
    r"\b(critical|high|medium|low|info(?:rmational)?)\b",
    re.IGNORECASE,
)

CWE_PATTERN = re.compile(r"CWE-(\d+)")
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")

TOOL_COMMAND_PATTERNS = [
    re.compile(r"```(?:bash|sh|shell)?\s*\n(.*?)```", re.DOTALL),
    re.compile(r"\$\s+(.+)"),
    re.compile(r"(?:run|execute|use):\s*(.+)", re.IGNORECASE),
]

FINDING_HEADER_PATTERNS = [
    re.compile(r"(?:finding|vulnerability|issue)\s*(?:\d+)?[:]\s*(.+)", re.IGNORECASE),
    re.compile(r"\*\*(?:Finding|Vulnerability)[:]\*\*\s*(.+)", re.IGNORECASE),
    re.compile(r"#{1,3}\s*(?:Finding|Vulnerability)\s*\d*[:]\s*(.+)", re.IGNORECASE),
]

PLAN_STEP_PATTERN = re.compile(r"(?:step\s+)?(\d+)[.)]\s*(.+)", re.IGNORECASE)

CONFIDENCE_PATTERNS = [
    re.compile(r"confidence[:]\s*(\d+(?:\.\d+)?)\s*%?", re.IGNORECASE),
    re.compile(r"(\d+(?:\.\d+)?)\s*%?\s*confiden(?:ce|t)", re.IGNORECASE),
]


class OutputParser:
    """Parses LLM responses into structured data.

    Extracts findings, tool commands, action plans,
    and other structured data from LLM text output.
    """

    def __init__(self) -> None:
        self._log = logger.bind(component="output_parser")

    def parse(self, text: str) -> ParseResult:
        """Parse LLM output into structured data."""
        result = ParseResult(raw_text=text)

        # Try JSON first
        json_data = self._extract_json(text)
        if json_data:
            result.json_data = json_data
            result.confidence = 0.9
            self._parse_json_response(json_data, result)
            return result

        # Extract findings
        findings = self._extract_findings(text)
        if findings:
            result.findings = findings
            result.parsed_type = ParsedType.FINDING
            result.confidence = 0.7

        # Extract commands
        commands = self._extract_commands(text)
        if commands:
            result.commands = commands
            if not findings:
                result.parsed_type = ParsedType.TOOL_COMMAND
                result.confidence = 0.8

        # Extract plan
        plan = self._extract_plan(text)
        if plan and plan.steps:
            result.plan = plan
            if not findings and not commands:
                result.parsed_type = ParsedType.PLAN
                result.confidence = 0.7

        return result

    def _extract_json(self, text: str) -> dict[str, Any] | None:
        """Extract JSON from text."""
        # Try full text
        try:
            return json.loads(text.strip())
        except json.JSONDecodeError:
            pass

        # Try JSON code block
        match = re.search(r"```(?:json)?\s*\n({.*?})\s*\n```", text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                pass

        # Try finding JSON object in text
        brace_start = text.find("{")
        if brace_start >= 0:
            depth = 0
            for i in range(brace_start, len(text)):
                if text[i] == "{":
                    depth += 1
                elif text[i] == "}":
                    depth -= 1
                    if depth == 0:
                        try:
                            return json.loads(text[brace_start:i + 1])
                        except json.JSONDecodeError:
                            break

        return None

    def _parse_json_response(
        self,
        data: dict[str, Any],
        result: ParseResult,
    ) -> None:
        """Parse a JSON response."""
        # Check for findings
        if "findings" in data:
            for f_data in data["findings"]:
                finding = ParsedFinding(
                    title=f_data.get("title", ""),
                    severity=f_data.get("severity", "medium"),
                    description=f_data.get("description", ""),
                    cwe=f_data.get("cwe", ""),
                    cve=f_data.get("cve", ""),
                    confidence=f_data.get("confidence", 0.5),
                )
                result.findings.append(finding)
            result.parsed_type = ParsedType.FINDING

        elif "verdict" in data:
            result.parsed_type = ParsedType.VERDICT

        elif "steps" in data or "plan" in data:
            steps = data.get("steps", data.get("plan", []))
            result.plan = ParsedPlan(
                steps=[str(s) for s in steps],
            )
            result.parsed_type = ParsedType.PLAN

    def _extract_findings(self, text: str) -> list[ParsedFinding]:
        """Extract findings from free text."""
        findings = []

        for pattern in FINDING_HEADER_PATTERNS:
            for match in pattern.finditer(text):
                title = match.group(1).strip()
                # Get surrounding text for context
                start = match.start()
                end = min(len(text), start + 500)
                context = text[start:end]

                finding = ParsedFinding(title=title)

                # Extract severity
                sev_match = SEVERITY_PATTERNS.search(context)
                if sev_match:
                    sev = sev_match.group(1).lower()
                    if sev == "informational":
                        sev = "info"
                    finding.severity = sev

                # Extract CWE
                cwe_match = CWE_PATTERN.search(context)
                if cwe_match:
                    finding.cwe = f"CWE-{cwe_match.group(1)}"

                # Extract CVE
                cve_match = CVE_PATTERN.search(context)
                if cve_match:
                    finding.cve = cve_match.group(0)

                # Extract confidence
                for conf_pat in CONFIDENCE_PATTERNS:
                    conf_match = conf_pat.search(context)
                    if conf_match:
                        val = float(conf_match.group(1))
                        finding.confidence = val / 100 if val > 1 else val
                        break

                findings.append(finding)

        return findings

    def _extract_commands(self, text: str) -> list[ParsedCommand]:
        """Extract tool commands from text."""
        commands = []

        for pattern in TOOL_COMMAND_PATTERNS:
            for match in pattern.finditer(text):
                cmd_text = match.group(1).strip()
                for line in cmd_text.split("\n"):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    tool = self._identify_tool(line)
                    if tool:
                        commands.append(ParsedCommand(
                            tool=tool,
                            command=line,
                        ))

        return commands

    def _identify_tool(self, command: str) -> str:
        """Identify the tool from a command string."""
        tools = [
            "nmap", "masscan", "nuclei", "nikto", "sqlmap", "dalfox",
            "ffuf", "gobuster", "feroxbuster", "subfinder", "amass",
            "httpx", "hydra", "crackmapexec", "enum4linux", "testssl",
            "wpscan", "trufflehog", "gitleaks", "semgrep", "bandit",
            "trivy", "grype", "curl", "dig", "whois", "searchsploit",
        ]

        cmd_lower = command.lower()
        for tool in tools:
            if tool in cmd_lower:
                return tool

        return ""

    def _extract_plan(self, text: str) -> ParsedPlan:
        """Extract an action plan from text."""
        plan = ParsedPlan()

        for match in PLAN_STEP_PATTERN.finditer(text):
            step = match.group(2).strip()
            if step:
                plan.steps.append(step)

        return plan

    def parse_tool_output(
        self,
        tool: str,
        output: str,
    ) -> list[ParsedFinding]:
        """Parse tool output into findings."""
        if tool == "nuclei":
            return self._parse_nuclei(output)
        elif tool == "nmap":
            return self._parse_nmap(output)
        return []

    def _parse_nuclei(self, output: str) -> list[ParsedFinding]:
        """Parse nuclei output."""
        findings = []
        for line in output.split("\n"):
            line = line.strip()
            if not line:
                continue

            # Try JSON line
            try:
                data = json.loads(line)
                findings.append(ParsedFinding(
                    title=data.get("info", {}).get("name", ""),
                    severity=data.get("info", {}).get("severity", "medium"),
                    description=data.get("matched-at", ""),
                    cve=data.get("info", {}).get("classification", {}).get("cve-id", ""),
                ))
            except json.JSONDecodeError:
                # Text format: [severity] [template-id] [protocol] matched-at
                match = re.match(r"\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(.*)", line)
                if match:
                    findings.append(ParsedFinding(
                        title=match.group(2),
                        severity=match.group(1).lower(),
                        description=match.group(4),
                    ))

        return findings

    def _parse_nmap(self, output: str) -> list[ParsedFinding]:
        """Parse nmap output for open ports."""
        findings = []
        port_pattern = re.compile(r"(\d+)/(\w+)\s+open\s+(\S+)(?:\s+(.+))?")

        for match in port_pattern.finditer(output):
            port = match.group(1)
            protocol = match.group(2)
            service = match.group(3)
            version = match.group(4) or ""

            findings.append(ParsedFinding(
                title=f"Open port {port}/{protocol}: {service}",
                severity="info",
                description=f"Service: {service} {version}".strip(),
            ))

        return findings
