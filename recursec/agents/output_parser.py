"""Output parser intelligence — structured LLM response parsing.

Implements:
1. Multi-format response parsing (JSON, YAML, Markdown, freetext)
2. Tool call extraction
3. Finding extraction from responses
4. Confidence extraction
5. Action plan parsing
6. Fallback parsing strategies
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ResponseFormat(str, Enum):
    JSON = "json"
    YAML = "yaml"
    MARKDOWN = "markdown"
    FREETEXT = "freetext"
    TOOL_CALL = "tool_call"
    CODE_BLOCK = "code_block"


class ParsedItemType(str, Enum):
    FINDING = "finding"
    TOOL_CALL = "tool_call"
    ACTION = "action"
    ANALYSIS = "analysis"
    QUESTION = "question"
    CODE = "code"


@dataclass
class ParsedItem:
    """A parsed item from LLM response."""
    item_type: ParsedItemType = ParsedItemType.ANALYSIS
    content: str = ""
    structured: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.5
    source_format: ResponseFormat = ResponseFormat.FREETEXT

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.item_type.value[:8],
            "content": self.content[:25],
            "conf": f"{self.confidence:.2f}",
        }


@dataclass
class ToolCallParsed:
    """A parsed tool call from LLM response."""
    tool_name: str = ""
    arguments: dict[str, Any] = field(default_factory=dict)
    raw_command: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool_name[:15],
            "args": len(self.arguments),
        }


@dataclass
class FindingParsed:
    """A parsed finding from LLM response."""
    title: str = ""
    severity: str = "medium"
    finding_type: str = ""
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    confidence: float = 0.5

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title[:20],
            "severity": self.severity[:6],
            "conf": f"{self.confidence:.2f}",
        }


# Severity keywords for extraction
SEVERITY_KEYWORDS: dict[str, list[str]] = {
    "critical": ["critical", "rce", "remote code execution", "unauthenticated"],
    "high": ["high", "sqli", "sql injection", "xss", "ssrf", "auth bypass"],
    "medium": ["medium", "information disclosure", "misconfig"],
    "low": ["low", "informational", "best practice"],
    "info": ["info", "note", "observation"],
}

# Tool patterns
TOOL_CALL_PATTERNS = [
    r'```(?:bash|sh|shell)?\s*\n((?:nmap|nuclei|sqlmap|ffuf|gobuster|nikto|masscan|hydra|curl|wget|dig|whois|subfinder|amass|httpx|wpscan|burp|metasploit|hashcat|john)\b[^\n]*)',
    r'(?:Run|Execute|Use):\s*((?:nmap|nuclei|sqlmap|ffuf|gobuster)\s+[^\n]+)',
    r'(?:TOOL|COMMAND|ACTION):\s*([^\n]+)',
]

# Finding patterns
FINDING_PATTERNS = [
    r'(?:FINDING|VULNERABILITY|VULN|BUG):\s*([^\n]+)',
    r'(?:Critical|High|Medium|Low):\s*([^\n]+)',
    r'(?:CVE-\d{4}-\d+)[^\n]*',
]


class OutputParser:
    """Parse LLM responses into structured data.

    Extracts findings, tool calls, actions,
    and analysis from model outputs.
    """

    def __init__(self) -> None:
        self._parse_count = 0
        self._success_count = 0
        self._log = logger.bind(component="parser")

    def parse(self, response: str) -> list[ParsedItem]:
        """Parse an LLM response into structured items."""
        self._parse_count += 1
        items: list[ParsedItem] = []

        # Try JSON first
        json_items = self._try_json(response)
        if json_items:
            items.extend(json_items)
            self._success_count += 1
            return items

        # Extract tool calls
        tool_calls = self.extract_tool_calls(response)
        for tc in tool_calls:
            items.append(ParsedItem(
                item_type=ParsedItemType.TOOL_CALL,
                content=tc.raw_command,
                structured={"tool": tc.tool_name, "args": tc.arguments},
                source_format=ResponseFormat.TOOL_CALL,
            ))

        # Extract findings
        findings = self.extract_findings(response)
        for finding in findings:
            items.append(ParsedItem(
                item_type=ParsedItemType.FINDING,
                content=finding.title,
                structured=finding.to_dict(),
                confidence=finding.confidence,
                source_format=ResponseFormat.FREETEXT,
            ))

        # Extract code blocks
        code_blocks = self._extract_code_blocks(response)
        for block in code_blocks:
            items.append(ParsedItem(
                item_type=ParsedItemType.CODE,
                content=block[:100],
                structured={"code": block},
                source_format=ResponseFormat.CODE_BLOCK,
            ))

        # If nothing structured, treat as analysis
        if not items:
            items.append(ParsedItem(
                item_type=ParsedItemType.ANALYSIS,
                content=response[:200],
                source_format=ResponseFormat.FREETEXT,
            ))

        self._success_count += 1
        return items

    def _try_json(self, text: str) -> list[ParsedItem]:
        """Try to parse as JSON."""
        items: list[ParsedItem] = []

        # Try full text as JSON
        stripped = text.strip()
        if stripped.startswith('{') or stripped.startswith('['):
            try:
                data = json.loads(stripped)
                items.append(ParsedItem(
                    item_type=ParsedItemType.ANALYSIS,
                    content=str(data)[:100],
                    structured=data if isinstance(data, dict) else {"data": data},
                    source_format=ResponseFormat.JSON,
                ))
                return items
            except json.JSONDecodeError:
                pass

        # Try extracting JSON blocks
        json_pattern = r'```json\s*\n(.*?)\n```'
        matches = re.findall(json_pattern, text, re.DOTALL)
        for match in matches:
            try:
                data = json.loads(match)
                items.append(ParsedItem(
                    item_type=ParsedItemType.ANALYSIS,
                    content=str(data)[:100],
                    structured=data if isinstance(data, dict) else {"data": data},
                    source_format=ResponseFormat.JSON,
                ))
            except json.JSONDecodeError:
                continue

        return items

    def extract_tool_calls(self, response: str) -> list[ToolCallParsed]:
        """Extract tool calls from response."""
        calls: list[ToolCallParsed] = []

        for pattern in TOOL_CALL_PATTERNS:
            matches = re.findall(pattern, response, re.MULTILINE)
            for match in matches:
                command = match.strip()
                parts = command.split()
                if parts:
                    tool_name = parts[0]
                    args_str = " ".join(parts[1:]) if len(parts) > 1 else ""
                    calls.append(ToolCallParsed(
                        tool_name=tool_name,
                        arguments={"raw_args": args_str},
                        raw_command=command,
                    ))

        return calls

    def extract_findings(self, response: str) -> list[FindingParsed]:
        """Extract findings from response."""
        findings: list[FindingParsed] = []

        for pattern in FINDING_PATTERNS:
            matches = re.findall(pattern, response, re.MULTILINE)
            for match in matches:
                severity = self._detect_severity(match)
                findings.append(FindingParsed(
                    title=match.strip()[:60],
                    severity=severity,
                    confidence=0.6,
                ))

        return findings

    def _detect_severity(self, text: str) -> str:
        """Detect severity from text."""
        lower = text.lower()
        for severity, keywords in SEVERITY_KEYWORDS.items():
            if any(kw in lower for kw in keywords):
                return severity
        return "medium"

    def _extract_code_blocks(self, text: str) -> list[str]:
        """Extract code blocks from response."""
        pattern = r'```(?:\w*)\s*\n(.*?)\n```'
        matches = re.findall(pattern, text, re.DOTALL)
        return matches

    def extract_confidence(self, response: str) -> float:
        """Extract confidence from response."""
        patterns = [
            r'confidence:\s*(\d+(?:\.\d+)?)',
            r'(\d+(?:\.\d+)?)\s*%?\s*confident',
            r'certainty:\s*(\d+(?:\.\d+)?)',
        ]

        for pattern in patterns:
            match = re.search(pattern, response, re.IGNORECASE)
            if match:
                value = float(match.group(1))
                if value > 1.0:
                    value /= 100.0
                return min(1.0, max(0.0, value))

        return 0.5

    def build_parser_prompt(self) -> str:
        """Build parser stats for LLM."""
        lines = ["## Parser\n"]
        lines.append(f"Parsed: {self._parse_count}")
        if self._parse_count > 0:
            rate = self._success_count / self._parse_count
            lines.append(f"Success: {rate:.0%}")
        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            "parsed": self._parse_count,
            "success": self._success_count,
            "rate": (
                f"{self._success_count / self._parse_count:.0%}"
                if self._parse_count > 0 else "0%"
            ),
        }
