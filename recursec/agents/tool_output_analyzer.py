"""Tool output analyzer — structured parsing for agent consumption.

Implements:
1. Pattern-based output parsing (regex + heuristics)
2. Finding extraction from tool output
3. Severity inference from output patterns
4. Cross-tool output normalization
5. Structured finding generation
6. Analyzer prompt for LLM
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingCategory(str, Enum):
    VULNERABILITY = "vulnerability"
    MISCONFIGURATION = "misconfiguration"
    INFORMATION = "information"
    CREDENTIAL = "credential"
    SERVICE = "service"
    TECHNOLOGY = "technology"


@dataclass
class ExtractedFinding:
    """A finding extracted from tool output."""
    tool: str = ""
    category: FindingCategory = FindingCategory.INFORMATION
    severity: FindingSeverity = FindingSeverity.INFO
    title: str = ""
    detail: str = ""
    target: str = ""
    port: int = 0
    protocol: str = ""
    confidence: float = 0.5
    raw_line: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool[:10],
            "sev": self.severity.value[:4],
            "title": self.title[:30],
            "target": self.target[:20],
            "port": self.port,
        }


# ── Tool-specific parsers ────────────────────────────────────

NMAP_PORT_RE = re.compile(
    r"(\d+)/(tcp|udp)\s+(open|filtered)\s+(\S+)\s*(.*)"
)

NMAP_VULN_RE = re.compile(
    r"(CVE-\d{4}-\d+)"
)

NUCLEI_RE = re.compile(
    r"\[(\w+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(.*)"
)

SQLMAP_VULN_RE = re.compile(
    r"(GET|POST)\s+parameter\s+'([^']+)'\s+is\s+vulnerable"
)

NIKTO_RE = re.compile(
    r"\+\s+([A-Z0-9-]+):\s+(.*)"
)

GOBUSTER_RE = re.compile(
    r"(/\S+)\s+\(Status:\s*(\d+)\)"
)

HYDRA_RE = re.compile(
    r"\[(\d+)\]\[(\w+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S+)"
)

SEMGREP_RE = re.compile(
    r"(\S+):(\d+)\s+.*?(error|warning|info)\s+(.+)"
)

FFUF_RE = re.compile(
    r"\|\s+(\S+)\s+\|\s+(\d+)\s+\|\s+\d+\s+\|"
)


class ToolOutputAnalyzer:
    """Analyzes tool output to extract structured findings.

    Parses raw CLI output from security tools into
    structured findings the agent can reason about.
    """

    def __init__(self) -> None:
        self._parsers: dict[str, Any] = {
            "nmap": self._parse_nmap,
            "nuclei": self._parse_nuclei,
            "sqlmap": self._parse_sqlmap,
            "nikto": self._parse_nikto,
            "gobuster": self._parse_gobuster,
            "ffuf": self._parse_ffuf,
            "hydra": self._parse_hydra,
            "semgrep": self._parse_semgrep,
        }
        self._total_parsed = 0
        self._log = logger.bind(component="tool_analyzer")

    def analyze(
        self,
        tool: str,
        output: str,
        target: str = "",
    ) -> list[ExtractedFinding]:
        """Analyze tool output and extract findings."""
        parser = self._parsers.get(tool.lower())
        if parser:
            findings = parser(output, target)
        else:
            findings = self._parse_generic(tool, output, target)

        self._total_parsed += 1
        return findings

    def _parse_nmap(self, output: str, target: str) -> list[ExtractedFinding]:
        """Parse nmap output."""
        findings: list[ExtractedFinding] = []

        for line in output.splitlines():
            m = NMAP_PORT_RE.match(line.strip())
            if m:
                port = int(m.group(1))
                proto = m.group(2)
                state = m.group(3)
                service = m.group(4)
                version = m.group(5).strip()

                findings.append(ExtractedFinding(
                    tool="nmap",
                    category=FindingCategory.SERVICE,
                    severity=FindingSeverity.INFO,
                    title=f"{service} on {port}/{proto}",
                    detail=f"{state} {service} {version}".strip(),
                    target=target,
                    port=port,
                    protocol=proto,
                    confidence=0.95,
                    raw_line=line.strip(),
                    metadata={"service": service, "version": version},
                ))

            # CVE detection
            cve_matches = NMAP_VULN_RE.findall(line)
            for cve in cve_matches:
                findings.append(ExtractedFinding(
                    tool="nmap",
                    category=FindingCategory.VULNERABILITY,
                    severity=FindingSeverity.HIGH,
                    title=cve,
                    detail=line.strip(),
                    target=target,
                    confidence=0.7,
                    raw_line=line.strip(),
                    metadata={"cve": cve},
                ))

        return findings

    def _parse_nuclei(self, output: str, target: str) -> list[ExtractedFinding]:
        """Parse nuclei output."""
        findings: list[ExtractedFinding] = []

        severity_map = {
            "critical": FindingSeverity.CRITICAL,
            "high": FindingSeverity.HIGH,
            "medium": FindingSeverity.MEDIUM,
            "low": FindingSeverity.LOW,
            "info": FindingSeverity.INFO,
        }

        for line in output.splitlines():
            m = NUCLEI_RE.match(line.strip())
            if m:
                sev_str = m.group(1).lower()
                template = m.group(2)
                proto = m.group(3)
                url = m.group(4).strip()

                findings.append(ExtractedFinding(
                    tool="nuclei",
                    category=FindingCategory.VULNERABILITY,
                    severity=severity_map.get(sev_str, FindingSeverity.INFO),
                    title=template,
                    detail=f"{proto}: {url}",
                    target=url or target,
                    confidence=0.8,
                    raw_line=line.strip(),
                    metadata={"template": template},
                ))

        return findings

    def _parse_sqlmap(self, output: str, target: str) -> list[ExtractedFinding]:
        """Parse sqlmap output."""
        findings: list[ExtractedFinding] = []

        for line in output.splitlines():
            m = SQLMAP_VULN_RE.search(line)
            if m:
                method = m.group(1)
                param = m.group(2)

                findings.append(ExtractedFinding(
                    tool="sqlmap",
                    category=FindingCategory.VULNERABILITY,
                    severity=FindingSeverity.CRITICAL,
                    title=f"SQL Injection in {param}",
                    detail=f"{method} parameter '{param}' is vulnerable",
                    target=target,
                    confidence=0.9,
                    raw_line=line.strip(),
                    metadata={"method": method, "parameter": param},
                ))

        return findings

    def _parse_nikto(self, output: str, target: str) -> list[ExtractedFinding]:
        """Parse nikto output."""
        findings: list[ExtractedFinding] = []

        for line in output.splitlines():
            m = NIKTO_RE.match(line.strip())
            if m:
                osvdb = m.group(1)
                detail = m.group(2)

                sev = FindingSeverity.LOW
                if any(kw in detail.lower() for kw in ["xss", "inject", "rce", "exec"]):
                    sev = FindingSeverity.HIGH
                elif any(kw in detail.lower() for kw in ["directory", "listing", "info"]):
                    sev = FindingSeverity.MEDIUM

                findings.append(ExtractedFinding(
                    tool="nikto",
                    category=FindingCategory.VULNERABILITY,
                    severity=sev,
                    title=f"Nikto: {osvdb}",
                    detail=detail[:100],
                    target=target,
                    confidence=0.6,
                    raw_line=line.strip(),
                ))

        return findings

    def _parse_gobuster(self, output: str, target: str) -> list[ExtractedFinding]:
        """Parse gobuster/ffuf output."""
        findings: list[ExtractedFinding] = []

        for line in output.splitlines():
            m = GOBUSTER_RE.search(line)
            if m:
                path = m.group(1)
                status = int(m.group(2))

                findings.append(ExtractedFinding(
                    tool="gobuster",
                    category=FindingCategory.INFORMATION,
                    severity=FindingSeverity.INFO,
                    title=f"Path: {path} ({status})",
                    detail=f"Discovered path {path} with status {status}",
                    target=f"{target}{path}",
                    confidence=0.95,
                    raw_line=line.strip(),
                    metadata={"path": path, "status": status},
                ))

        return findings

    def _parse_ffuf(self, output: str, target: str) -> list[ExtractedFinding]:
        """Parse ffuf output."""
        findings: list[ExtractedFinding] = []

        for line in output.splitlines():
            m = FFUF_RE.search(line)
            if m:
                word = m.group(1)
                status = int(m.group(2))

                findings.append(ExtractedFinding(
                    tool="ffuf",
                    category=FindingCategory.INFORMATION,
                    severity=FindingSeverity.INFO,
                    title=f"Fuzz: {word} ({status})",
                    detail=f"Found {word} with status {status}",
                    target=target,
                    confidence=0.9,
                    raw_line=line.strip(),
                    metadata={"word": word, "status": status},
                ))

        return findings

    def _parse_hydra(self, output: str, target: str) -> list[ExtractedFinding]:
        """Parse hydra output."""
        findings: list[ExtractedFinding] = []

        for line in output.splitlines():
            m = HYDRA_RE.search(line)
            if m:
                port = int(m.group(1))
                proto = m.group(2)
                host = m.group(3)
                login = m.group(4)
                password = m.group(5)

                findings.append(ExtractedFinding(
                    tool="hydra",
                    category=FindingCategory.CREDENTIAL,
                    severity=FindingSeverity.CRITICAL,
                    title=f"Credential found: {login}",
                    detail=f"{proto}://{host}:{port} — {login}:{password}",
                    target=host,
                    port=port,
                    protocol=proto,
                    confidence=0.95,
                    raw_line=line.strip(),
                    metadata={"login": login},
                ))

        return findings

    def _parse_semgrep(self, output: str, target: str) -> list[ExtractedFinding]:
        """Parse semgrep output."""
        findings: list[ExtractedFinding] = []

        for line in output.splitlines():
            m = SEMGREP_RE.search(line)
            if m:
                filepath = m.group(1)
                lineno = m.group(2)
                level = m.group(3)
                msg = m.group(4)

                sev_map = {
                    "error": FindingSeverity.HIGH,
                    "warning": FindingSeverity.MEDIUM,
                    "info": FindingSeverity.LOW,
                }

                findings.append(ExtractedFinding(
                    tool="semgrep",
                    category=FindingCategory.VULNERABILITY,
                    severity=sev_map.get(level, FindingSeverity.INFO),
                    title=f"Code issue: {msg[:40]}",
                    detail=f"{filepath}:{lineno} — {msg}",
                    target=filepath,
                    confidence=0.7,
                    raw_line=line.strip(),
                    metadata={"file": filepath, "line": lineno},
                ))

        return findings

    def _parse_generic(self, tool: str, output: str, target: str) -> list[ExtractedFinding]:
        """Generic parser for unknown tools."""
        findings: list[ExtractedFinding] = []

        severity_keywords = {
            FindingSeverity.CRITICAL: ["critical", "rce", "remote code execution", "sql injection"],
            FindingSeverity.HIGH: ["high", "vulnerability", "exploit", "xss", "injection"],
            FindingSeverity.MEDIUM: ["medium", "warning", "misconfiguration"],
            FindingSeverity.LOW: ["low", "info", "informational"],
        }

        for line in output.splitlines():
            line_lower = line.lower().strip()
            if not line_lower or line_lower.startswith("#"):
                continue

            detected_sev = FindingSeverity.INFO
            for sev, keywords in severity_keywords.items():
                if any(kw in line_lower for kw in keywords):
                    detected_sev = sev
                    break

            if detected_sev != FindingSeverity.INFO:
                findings.append(ExtractedFinding(
                    tool=tool,
                    category=FindingCategory.INFORMATION,
                    severity=detected_sev,
                    title=f"{tool}: {line.strip()[:40]}",
                    detail=line.strip()[:100],
                    target=target,
                    confidence=0.3,
                    raw_line=line.strip(),
                ))

        return findings

    def build_analyzer_prompt(self, findings: list[ExtractedFinding] | None = None) -> str:
        """Build analyzer status prompt."""
        lines = ["## Tool Output Analysis\n"]
        lines.append(f"Total analyses: {self._total_parsed}")
        lines.append(f"Supported tools: {', '.join(self._parsers.keys())}")

        if findings:
            by_sev: dict[str, int] = {}
            for f in findings:
                s = f.severity.value
                by_sev[s] = by_sev.get(s, 0) + 1
            lines.append(f"\nFindings: {len(findings)}")
            for sev, count in sorted(by_sev.items()):
                lines.append(f"  {sev}: {count}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_parsed": self._total_parsed,
            "supported_tools": list(self._parsers.keys()),
        }
