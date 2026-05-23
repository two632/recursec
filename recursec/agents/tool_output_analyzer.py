"""Tool output analyzer — structured parsing and insight extraction.

Implements:
1. Pattern-based extraction from raw tool outputs
2. Severity classification of findings
3. Cross-tool finding correlation
4. Output summarization for LLM consumption
5. Anomaly detection in tool results
6. Finding extraction rules per tool
7. Analyzer prompt for LLM context
"""

from __future__ import annotations

import re
import time
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


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ExtractedFinding:
    """A finding extracted from tool output."""
    finding_id: str = ""
    tool: str = ""
    severity: FindingSeverity = FindingSeverity.INFO
    title: str = ""
    description: str = ""
    target: str = ""
    port: int = 0
    protocol: str = ""
    evidence: str = ""
    cve_ids: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    confidence: float = 0.8
    raw_line: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.finding_id[:10],
            "tool": self.tool[:10],
            "sev": self.severity.value[:4],
            "title": self.title[:25],
            "target": self.target[:15],
            "cves": len(self.cve_ids),
        }


# ── Tool-specific extraction patterns ────────────────────────

EXTRACTION_RULES: dict[str, list[dict[str, Any]]] = {
    "nmap": [
        {
            "pattern": r"(\d+)/(\w+)\s+open\s+(\S+)",
            "fields": ["port", "protocol", "service"],
            "severity": "info",
            "title_template": "Open port {port}/{protocol} ({service})",
        },
        {
            "pattern": r"(\d+)/(\w+)\s+open\s+(\S+)\s+(.+)",
            "fields": ["port", "protocol", "service", "version"],
            "severity": "info",
            "title_template": "Service: {service} {version} on {port}/{protocol}",
        },
        {
            "pattern": r"VULNERABLE:\s*\n\s*(.+)",
            "fields": ["vuln_name"],
            "severity": "high",
            "title_template": "Nmap vulnerability: {vuln_name}",
        },
    ],
    "nuclei": [
        {
            "pattern": r"\[(\w+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(.+)",
            "fields": ["severity", "template_id", "protocol", "matched_url"],
            "severity": "dynamic",  # From captured group
            "title_template": "Nuclei: {template_id}",
        },
    ],
    "sqlmap": [
        {
            "pattern": r"Parameter:\s*(\S+)\s*\((.*?)\)",
            "fields": ["parameter", "injection_type"],
            "severity": "critical",
            "title_template": "SQL Injection in {parameter} ({injection_type})",
        },
        {
            "pattern": r"back-end DBMS:\s*(.+)",
            "fields": ["dbms"],
            "severity": "info",
            "title_template": "Database: {dbms}",
        },
    ],
    "ffuf": [
        {
            "pattern": r"(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)",
            "fields": ["path", "status", "size"],
            "severity": "low",
            "title_template": "Directory: {path} (HTTP {status})",
        },
    ],
    "nikto": [
        {
            "pattern": r"\+\s+OSVDB-(\d+):\s+(.+)",
            "fields": ["osvdb_id", "description"],
            "severity": "medium",
            "title_template": "Nikto: {description}",
        },
    ],
    "hydra": [
        {
            "pattern": r"\[(\d+)\]\[(\w+)\]\s+host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(\S+)",
            "fields": ["port", "service", "host", "login", "password"],
            "severity": "critical",
            "title_template": "Credential found: {login}:{password} on {service}:{port}",
        },
    ],
    "gobuster": [
        {
            "pattern": r"(/\S+)\s+\(Status:\s*(\d+)\)",
            "fields": ["path", "status"],
            "severity": "low",
            "title_template": "Path: {path} (HTTP {status})",
        },
    ],
    "semgrep": [
        {
            "pattern": r"(\S+):(\d+):\s+(\S+)\s+(.+)",
            "fields": ["file", "line", "rule_id", "message"],
            "severity": "medium",
            "title_template": "Code issue: {rule_id} in {file}:{line}",
        },
    ],
}

# CVE pattern for any tool output
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}")
CWE_PATTERN = re.compile(r"CWE-\d{1,4}")


class ToolOutputAnalyzer:
    """Analyzes and extracts findings from tool outputs.

    Parses raw CLI output from security tools,
    extracts structured findings, classifies
    severity, and prepares context for LLM.
    """

    def __init__(self) -> None:
        self._findings: list[ExtractedFinding] = []
        self._counter = 0
        self._tools_analyzed: dict[str, int] = {}
        self._log = logger.bind(component="tool_output_analyzer")

    def analyze(
        self,
        tool: str,
        output: str,
        target: str = "",
    ) -> list[ExtractedFinding]:
        """Analyze tool output and extract findings."""
        findings: list[ExtractedFinding] = []

        rules = EXTRACTION_RULES.get(tool.lower(), [])

        for line in output.split("\n"):
            line = line.strip()
            if not line:
                continue

            for rule in rules:
                match = re.search(rule["pattern"], line)
                if not match:
                    continue

                groups = match.groups()
                field_values: dict[str, str] = {}
                for i, field_name in enumerate(rule["fields"]):
                    if i < len(groups):
                        field_values[field_name] = groups[i]

                # Determine severity
                severity_str = rule["severity"]
                if severity_str == "dynamic" and "severity" in field_values:
                    severity_str = field_values["severity"].lower()

                try:
                    severity = FindingSeverity(severity_str)
                except ValueError:
                    severity = FindingSeverity.INFO

                # Build title
                title = rule["title_template"].format(**field_values)

                # Extract CVEs and CWEs
                cves = CVE_PATTERN.findall(line)
                cwes = CWE_PATTERN.findall(line)

                self._counter += 1
                finding = ExtractedFinding(
                    finding_id=f"ext-{self._counter}",
                    tool=tool,
                    severity=severity,
                    title=title,
                    target=target,
                    port=int(field_values.get("port", 0) or 0),
                    protocol=field_values.get("protocol", ""),
                    evidence=line[:200],
                    cve_ids=cves,
                    cwe_ids=cwes,
                    raw_line=line,
                )
                findings.append(finding)

        # Also extract CVEs from any line not matched by rules
        for line in output.split("\n"):
            cves = CVE_PATTERN.findall(line)
            for cve in cves:
                if not any(cve in f.cve_ids for f in findings):
                    self._counter += 1
                    findings.append(ExtractedFinding(
                        finding_id=f"ext-{self._counter}",
                        tool=tool,
                        severity=FindingSeverity.HIGH,
                        title=f"CVE reference: {cve}",
                        target=target,
                        cve_ids=[cve],
                        evidence=line.strip()[:200],
                        raw_line=line.strip(),
                    ))

        self._findings.extend(findings)
        self._tools_analyzed[tool] = self._tools_analyzed.get(tool, 0) + 1

        return findings

    def summarize(
        self,
        findings: list[ExtractedFinding] | None = None,
        max_findings: int = 20,
    ) -> str:
        """Summarize findings for LLM context."""
        items = findings or self._findings
        if not items:
            return "No findings extracted."

        # Count by severity
        sev_counts: dict[str, int] = {}
        for f in items:
            sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1

        lines = [
            f"Extracted {len(items)} findings from {len(self._tools_analyzed)} tools.",
            "Severity: " + " ".join(f"{k}={v}" for k, v in sev_counts.items()),
        ]

        # Sort by severity (critical first)
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_items = sorted(items, key=lambda f: sev_order.get(f.severity.value, 5))

        for f in sorted_items[:max_findings]:
            cve_str = f" [{','.join(f.cve_ids[:2])}]" if f.cve_ids else ""
            lines.append(
                f"  [{f.severity.value[0].upper()}] {f.title[:35]}{cve_str}"
            )

        return "\n".join(lines)

    def build_analyzer_prompt(self, max_findings: int = 15) -> str:
        """Build analyzer context for LLM."""
        lines = ["## Tool Output Analysis\n"]
        lines.append(self.summarize(max_findings=max_findings))

        # Tool breakdown
        if self._tools_analyzed:
            lines.append("\nTools analyzed:")
            for tool, count in self._tools_analyzed.items():
                tool_findings = [f for f in self._findings if f.tool == tool]
                lines.append(f"  {tool}: {count} runs, {len(tool_findings)} findings")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        sev_counts: dict[str, int] = {}
        for f in self._findings:
            sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1

        return {
            "total_findings": len(self._findings),
            "by_severity": sev_counts,
            "tools_analyzed": dict(self._tools_analyzed),
            "unique_cves": len(set(
                cve for f in self._findings for cve in f.cve_ids
            )),
        }
