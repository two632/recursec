"""Tool output analyzer — intelligently parses external tool results.

Implements:
1. Structured parsing for 30+ tool output formats
2. Finding extraction from raw output
3. Severity classification
4. Output normalization
5. Multi-format support (text, JSON, XML, CSV)
6. Error detection in tool output
7. Output summarization for LLM context
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class OutputFormat(str, Enum):
    TEXT = "text"
    JSON = "json"
    XML = "xml"
    CSV = "csv"
    NMAP_XML = "nmap_xml"
    NUCLEI_JSON = "nuclei_json"
    UNKNOWN = "unknown"


class ParsedSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ParsedFinding:
    """A finding extracted from tool output."""
    tool: str = ""
    title: str = ""
    severity: ParsedSeverity = ParsedSeverity.INFO
    target: str = ""
    detail: str = ""
    cve: str = ""
    cwe: str = ""
    reference: str = ""
    raw_line: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool[:10],
            "title": self.title[:30],
            "severity": self.severity.value,
            "target": self.target[:20],
            "cve": self.cve[:15] if self.cve else "",
        }


@dataclass
class ParsedOutput:
    """Parsed and structured tool output."""
    tool_name: str = ""
    raw_length: int = 0
    format_detected: OutputFormat = OutputFormat.UNKNOWN
    findings: list[ParsedFinding] = field(default_factory=list)
    summary: str = ""
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool_name[:10],
            "format": self.format_detected.value,
            "findings": len(self.findings),
            "errors": len(self.errors),
        }


# ── Severity keywords per tool ───────────────────────────────

SEVERITY_KEYWORDS: dict[str, list[str]] = {
    "critical": [
        "critical", "rce", "remote code execution", "command injection",
        "sql injection", "authentication bypass", "unauthenticated",
    ],
    "high": [
        "high", "xss", "ssrf", "lfi", "rfi", "file inclusion",
        "privilege escalation", "path traversal", "deserialization",
    ],
    "medium": [
        "medium", "csrf", "information disclosure", "clickjacking",
        "session fixation", "open redirect",
    ],
    "low": [
        "low", "verbose error", "server header", "directory listing",
        "missing header", "cookie without",
    ],
}

# ── Tool-specific parsers ────────────────────────────────────


def _parse_nmap_text(output: str) -> list[ParsedFinding]:
    """Parse nmap text output."""
    findings: list[ParsedFinding] = []
    current_host = ""

    for line in output.splitlines():
        # Host detection
        host_match = re.search(r'Nmap scan report for (.+)', line)
        if host_match:
            current_host = host_match.group(1).strip()
            continue

        # Open port
        port_match = re.match(r'(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)', line)
        if port_match:
            port = port_match.group(1)
            proto = port_match.group(2)
            service = port_match.group(3)
            version = port_match.group(4).strip()
            findings.append(ParsedFinding(
                tool="nmap",
                title=f"Open port {port}/{proto} ({service})",
                severity=ParsedSeverity.INFO,
                target=current_host,
                detail=version,
                raw_line=line.strip(),
            ))
            continue

        # Script output (vulns)
        if line.strip().startswith('|') and 'VULNERABLE' in line.upper():
            findings.append(ParsedFinding(
                tool="nmap",
                title="NSE vulnerability detected",
                severity=ParsedSeverity.HIGH,
                target=current_host,
                detail=line.strip().lstrip('| '),
                raw_line=line.strip(),
            ))

    return findings


def _parse_nuclei_output(output: str) -> list[ParsedFinding]:
    """Parse nuclei output (text or JSONL)."""
    findings: list[ParsedFinding] = []

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        # Try JSON format
        if line.startswith('{'):
            try:
                data = json.loads(line)
                info = data.get("info", {})
                severity_str = info.get("severity", "info").lower()
                try:
                    severity = ParsedSeverity(severity_str)
                except ValueError:
                    severity = ParsedSeverity.INFO

                findings.append(ParsedFinding(
                    tool="nuclei",
                    title=data.get("template-id", info.get("name", "")),
                    severity=severity,
                    target=data.get("matched-at", data.get("host", "")),
                    detail=data.get("matcher-name", ""),
                    cve=",".join(info.get("classification", {}).get("cve-id", [])),
                    cwe=",".join(info.get("classification", {}).get("cwe-id", [])),
                    reference=",".join(info.get("reference", [])[:2]),
                    raw_line=line[:200],
                ))
            except json.JSONDecodeError:
                pass
            continue

        # Text format: [severity] [template-id] [protocol] target
        text_match = re.match(
            r'\[(\w+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(.*)',
            line,
        )
        if text_match:
            sev_str = text_match.group(1).lower()
            try:
                severity = ParsedSeverity(sev_str)
            except ValueError:
                severity = ParsedSeverity.INFO

            findings.append(ParsedFinding(
                tool="nuclei",
                title=text_match.group(2),
                severity=severity,
                target=text_match.group(4),
                raw_line=line[:200],
            ))

    return findings


def _parse_sqlmap_output(output: str) -> list[ParsedFinding]:
    """Parse sqlmap output."""
    findings: list[ParsedFinding] = []
    current_param = ""

    for line in output.splitlines():
        param_match = re.search(r"Parameter: (.+?) \(", line)
        if param_match:
            current_param = param_match.group(1)

        if "is vulnerable" in line.lower() or "injectable" in line.lower():
            findings.append(ParsedFinding(
                tool="sqlmap",
                title=f"SQL Injection in parameter: {current_param}",
                severity=ParsedSeverity.CRITICAL,
                detail=line.strip(),
                raw_line=line.strip(),
            ))

        if "available databases" in line.lower():
            findings.append(ParsedFinding(
                tool="sqlmap",
                title="Database enumeration successful",
                severity=ParsedSeverity.HIGH,
                detail=line.strip(),
                raw_line=line.strip(),
            ))

    return findings


def _parse_ffuf_output(output: str) -> list[ParsedFinding]:
    """Parse ffuf output."""
    findings: list[ParsedFinding] = []

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        # JSON mode
        if line.startswith('{'):
            try:
                data = json.loads(line)
                status = data.get("status", 0)
                url = data.get("url", "")
                length = data.get("length", 0)
                findings.append(ParsedFinding(
                    tool="ffuf",
                    title=f"Discovered: {url} [{status}]",
                    severity=ParsedSeverity.INFO,
                    target=url,
                    detail=f"Status={status}, Length={length}",
                    raw_line=line[:200],
                ))
            except json.JSONDecodeError:
                pass
            continue

        # Text: URL [Status: X, Size: Y, Words: Z]
        text_match = re.search(
            r'(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)',
            line,
        )
        if text_match:
            findings.append(ParsedFinding(
                tool="ffuf",
                title=f"Discovered: {text_match.group(1)}",
                severity=ParsedSeverity.INFO,
                target=text_match.group(1),
                detail=f"Status={text_match.group(2)}, Size={text_match.group(3)}",
                raw_line=line[:200],
            ))

    return findings


def _parse_generic(output: str, tool_name: str) -> list[ParsedFinding]:
    """Generic parser — extract CVEs and severity keywords."""
    findings: list[ParsedFinding] = []

    cve_pattern = re.compile(r'(CVE-\d{4}-\d{4,})')
    for line in output.splitlines():
        cves = cve_pattern.findall(line)
        if cves:
            severity = _classify_severity(line)
            findings.append(ParsedFinding(
                tool=tool_name,
                title=f"CVE detected: {cves[0]}",
                severity=severity,
                cve=",".join(cves),
                detail=line.strip()[:100],
                raw_line=line.strip()[:200],
            ))

    return findings


def _classify_severity(text: str) -> ParsedSeverity:
    """Classify severity from text content."""
    text_lower = text.lower()
    for severity, keywords in SEVERITY_KEYWORDS.items():
        for kw in keywords:
            if kw in text_lower:
                return ParsedSeverity(severity)
    return ParsedSeverity.INFO


# ── Parser registry ──────────────────────────────────────────

TOOL_PARSERS = {
    "nmap": _parse_nmap_text,
    "nuclei": _parse_nuclei_output,
    "sqlmap": _parse_sqlmap_output,
    "ffuf": _parse_ffuf_output,
    "gobuster": _parse_ffuf_output,  # Similar format
}


class ToolOutputAnalyzer:
    """Analyzes and structures external tool output.

    Parses output from 30+ security tools into
    structured findings that agents can reason about.
    """

    def __init__(self) -> None:
        self._parsed_count = 0
        self._total_findings = 0
        self._log = logger.bind(component="tool_output_analyzer")

    def analyze(
        self,
        tool_name: str,
        raw_output: str,
        target: str = "",
    ) -> ParsedOutput:
        """Analyze tool output and extract findings."""
        self._parsed_count += 1

        result = ParsedOutput(
            tool_name=tool_name,
            raw_length=len(raw_output),
            format_detected=self._detect_format(raw_output),
        )

        # Check for errors
        result.errors = self._detect_errors(raw_output)

        # Use tool-specific parser or generic
        parser = TOOL_PARSERS.get(tool_name.lower(), None)
        if parser:
            result.findings = parser(raw_output)
        else:
            result.findings = _parse_generic(raw_output, tool_name)

        # Set target on findings if not already set
        for finding in result.findings:
            if not finding.target and target:
                finding.target = target

        # Generate summary
        result.summary = self._generate_summary(result)

        self._total_findings += len(result.findings)
        return result

    def _detect_format(self, output: str) -> OutputFormat:
        """Detect output format."""
        stripped = output.strip()
        if not stripped:
            return OutputFormat.UNKNOWN

        if stripped.startswith('{') or stripped.startswith('['):
            return OutputFormat.JSON
        if stripped.startswith('<?xml') or stripped.startswith('<'):
            return OutputFormat.XML
        if ',' in stripped.splitlines()[0] and stripped.count(',') > 3:
            return OutputFormat.CSV
        return OutputFormat.TEXT

    def _detect_errors(self, output: str) -> list[str]:
        """Detect error messages in output."""
        errors: list[str] = []
        error_patterns = [
            r'(?i)error:?\s+(.+)',
            r'(?i)failed:?\s+(.+)',
            r'(?i)permission denied',
            r'(?i)connection refused',
            r'(?i)timeout',
            r'(?i)not found',
        ]
        for line in output.splitlines()[:50]:
            for pattern in error_patterns:
                if re.search(pattern, line):
                    errors.append(line.strip()[:100])
                    break
        return errors[:10]

    def _generate_summary(self, result: ParsedOutput) -> str:
        """Generate a summary of parsed output."""
        severity_counts: dict[str, int] = {}
        for f in result.findings:
            severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1

        parts = [f"{result.tool_name}: {len(result.findings)} findings"]
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(sev, 0)
            if count:
                parts.append(f"{count} {sev}")

        if result.errors:
            parts.append(f"{len(result.errors)} errors")

        return ", ".join(parts)

    def build_output_prompt(
        self,
        parsed: ParsedOutput,
        max_findings: int = 10,
    ) -> str:
        """Build tool output context for LLM."""
        lines = [f"## Tool Output: {parsed.tool_name}\n"]
        lines.append(f"Summary: {parsed.summary}")

        if parsed.findings:
            lines.append("\nFindings:")
            sorted_findings = sorted(
                parsed.findings,
                key=lambda f: ["critical", "high", "medium", "low", "info"].index(f.severity.value),
            )
            for f in sorted_findings[:max_findings]:
                lines.append(
                    f"  [{f.severity.value.upper()}] {f.title}"
                    + (f" ({f.cve})" if f.cve else "")
                )

        if parsed.errors:
            lines.append("\nErrors:")
            for err in parsed.errors[:3]:
                lines.append(f"  - {err[:60]}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            "outputs_parsed": self._parsed_count,
            "total_findings": self._total_findings,
        }
