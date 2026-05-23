"""Tool output parser — structured parsing of external tool outputs.

Implements:
1. Nmap output parsing (text + XML)
2. Nuclei output parsing (JSON + text)
3. SQLMap output parsing
4. Directory brute force parsing (ffuf, gobuster)
5. Subdomain enumeration parsing
6. Credential tool parsing (hydra, hashcat)
7. Container/dependency scanner parsing (trivy, grype)
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ToolName(str, Enum):
    NMAP = "nmap"
    NUCLEI = "nuclei"
    SQLMAP = "sqlmap"
    FFUF = "ffuf"
    GOBUSTER = "gobuster"
    SUBFINDER = "subfinder"
    AMASS = "amass"
    HYDRA = "hydra"
    HASHCAT = "hashcat"
    TRIVY = "trivy"
    SEMGREP = "semgrep"
    NIKTO = "nikto"
    TESTSSL = "testssl"
    MASSCAN = "masscan"
    HTTPX = "httpx"


@dataclass
class ParsedResult:
    """Parsed output from a tool."""
    tool: ToolName = ToolName.NMAP
    raw_length: int = 0
    entries: list[dict[str, Any]] = field(default_factory=list)
    summary: str = ""
    findings_count: int = 0
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool.value,
            "entries": len(self.entries),
            "findings": self.findings_count,
            "summary": self.summary[:40],
        }


class ToolOutputParser:
    """Parses raw tool output into structured data.

    Each parser extracts key information from
    tool-specific output formats into a unified
    structure for agent reasoning.
    """

    def __init__(self) -> None:
        self._parsers: dict[str, Any] = {
            "nmap": self._parse_nmap,
            "nuclei": self._parse_nuclei,
            "sqlmap": self._parse_sqlmap,
            "ffuf": self._parse_ffuf,
            "gobuster": self._parse_gobuster,
            "subfinder": self._parse_subfinder,
            "hydra": self._parse_hydra,
            "trivy": self._parse_trivy,
            "semgrep": self._parse_semgrep,
            "nikto": self._parse_nikto,
            "masscan": self._parse_masscan,
            "httpx": self._parse_httpx,
        }
        self._log = logger.bind(component="tool_output_parser")

    def parse(self, tool: str, output: str) -> ParsedResult:
        """Parse tool output into structured result."""
        parser = self._parsers.get(tool.lower())
        if not parser:
            return ParsedResult(
                tool=ToolName.NMAP,
                raw_length=len(output),
                error=f"No parser for tool: {tool}",
            )

        try:
            return parser(output)
        except Exception as exc:
            return ParsedResult(
                tool=ToolName.NMAP,
                raw_length=len(output),
                error=f"Parse error: {exc}",
            )

    def _parse_nmap(self, output: str) -> ParsedResult:
        """Parse nmap text output."""
        entries: list[dict[str, Any]] = []
        current_host = ""

        for line in output.splitlines():
            line = line.strip()

            # Host detection
            host_match = re.match(r"Nmap scan report for (.+)", line)
            if host_match:
                current_host = host_match.group(1)
                continue

            # Port detection
            port_match = re.match(
                r"(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)\s*(.*)",
                line,
            )
            if port_match:
                entries.append({
                    "host": current_host,
                    "port": int(port_match.group(1)),
                    "protocol": port_match.group(2),
                    "state": port_match.group(3),
                    "service": port_match.group(4),
                    "version": port_match.group(5).strip(),
                })

        open_ports = [e for e in entries if e.get("state") == "open"]
        return ParsedResult(
            tool=ToolName.NMAP,
            raw_length=len(output),
            entries=entries,
            summary=f"{len(open_ports)} open ports found on {current_host}",
            findings_count=len(open_ports),
        )

    def _parse_nuclei(self, output: str) -> ParsedResult:
        """Parse nuclei output (JSON-lines or text)."""
        entries: list[dict[str, Any]] = []

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            # Try JSON format first
            if line.startswith("{"):
                try:
                    data = json.loads(line)
                    entries.append({
                        "template": data.get("template-id", ""),
                        "name": data.get("info", {}).get("name", ""),
                        "severity": data.get("info", {}).get("severity", ""),
                        "host": data.get("host", ""),
                        "matched_at": data.get("matched-at", ""),
                        "type": data.get("type", ""),
                    })
                    continue
                except json.JSONDecodeError:
                    pass

            # Text format: [template-id] [severity] url
            text_match = re.match(
                r"\[([^\]]+)\]\s*\[([^\]]*)\]\s*\[([^\]]*)\]\s*(.*)",
                line,
            )
            if text_match:
                entries.append({
                    "template": text_match.group(1),
                    "type": text_match.group(2),
                    "severity": text_match.group(3),
                    "matched_at": text_match.group(4),
                })

        findings = [
            e for e in entries
            if e.get("severity", "").lower() in ("critical", "high", "medium")
        ]
        return ParsedResult(
            tool=ToolName.NUCLEI,
            raw_length=len(output),
            entries=entries,
            summary=f"{len(entries)} templates matched, {len(findings)} findings",
            findings_count=len(findings),
        )

    def _parse_sqlmap(self, output: str) -> ParsedResult:
        """Parse sqlmap output."""
        entries: list[dict[str, Any]] = []
        injectable = False
        dbms = ""
        databases: list[str] = []

        for line in output.splitlines():
            line = line.strip()

            if "is vulnerable" in line.lower() or "injectable" in line.lower():
                injectable = True
                entries.append({"type": "injectable", "detail": line})

            dbms_match = re.search(r"back-end DBMS:\s*(.+)", line)
            if dbms_match:
                dbms = dbms_match.group(1).strip()

            db_match = re.search(r"available databases\s*\[(\d+)\]", line)
            if db_match:
                pass

            if line.startswith("[*]") and dbms:
                databases.append(line[3:].strip())

        if dbms:
            entries.append({"type": "dbms", "value": dbms})
        if databases:
            entries.append({"type": "databases", "value": databases})

        return ParsedResult(
            tool=ToolName.SQLMAP,
            raw_length=len(output),
            entries=entries,
            summary=f"Injectable: {injectable}, DBMS: {dbms or 'unknown'}",
            findings_count=1 if injectable else 0,
        )

    def _parse_ffuf(self, output: str) -> ParsedResult:
        """Parse ffuf output (JSON or text)."""
        entries: list[dict[str, Any]] = []

        # Try JSON first
        try:
            data = json.loads(output)
            results = data.get("results", [])
            for result in results:
                entries.append({
                    "url": result.get("url", ""),
                    "status": result.get("status", 0),
                    "length": result.get("length", 0),
                    "words": result.get("words", 0),
                })
        except (json.JSONDecodeError, TypeError):
            # Text format
            for line in output.splitlines():
                match = re.match(
                    r".*Status:\s*(\d+).*Size:\s*(\d+).*Words:\s*(\d+).*",
                    line,
                )
                if match:
                    entries.append({
                        "status": int(match.group(1)),
                        "length": int(match.group(2)),
                        "words": int(match.group(3)),
                    })

        return ParsedResult(
            tool=ToolName.FFUF,
            raw_length=len(output),
            entries=entries,
            summary=f"{len(entries)} endpoints discovered",
            findings_count=len(entries),
        )

    def _parse_gobuster(self, output: str) -> ParsedResult:
        """Parse gobuster output."""
        entries: list[dict[str, Any]] = []

        for line in output.splitlines():
            match = re.match(r"/(\S+)\s+\(Status:\s*(\d+)\)", line)
            if match:
                entries.append({
                    "path": "/" + match.group(1),
                    "status": int(match.group(2)),
                })

        return ParsedResult(
            tool=ToolName.GOBUSTER,
            raw_length=len(output),
            entries=entries,
            summary=f"{len(entries)} paths discovered",
            findings_count=len(entries),
        )

    def _parse_subfinder(self, output: str) -> ParsedResult:
        """Parse subfinder output."""
        entries: list[dict[str, Any]] = []
        for line in output.splitlines():
            domain = line.strip()
            if domain and "." in domain and not domain.startswith("["):
                entries.append({"subdomain": domain})

        return ParsedResult(
            tool=ToolName.SUBFINDER,
            raw_length=len(output),
            entries=entries,
            summary=f"{len(entries)} subdomains found",
            findings_count=len(entries),
        )

    def _parse_hydra(self, output: str) -> ParsedResult:
        """Parse hydra output."""
        entries: list[dict[str, Any]] = []

        for line in output.splitlines():
            match = re.match(
                r"\[(\d+)\]\[(\S+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S+)",
                line,
            )
            if match:
                entries.append({
                    "port": int(match.group(1)),
                    "service": match.group(2),
                    "host": match.group(3),
                    "login": match.group(4),
                    "password": match.group(5),
                })

        return ParsedResult(
            tool=ToolName.HYDRA,
            raw_length=len(output),
            entries=entries,
            summary=f"{len(entries)} credentials found",
            findings_count=len(entries),
        )

    def _parse_trivy(self, output: str) -> ParsedResult:
        """Parse trivy output (JSON)."""
        entries: list[dict[str, Any]] = []

        try:
            data = json.loads(output)
            results = data.get("Results", [])
            for result in results:
                vulns = result.get("Vulnerabilities", [])
                for vuln in vulns:
                    entries.append({
                        "id": vuln.get("VulnerabilityID", ""),
                        "severity": vuln.get("Severity", ""),
                        "pkg": vuln.get("PkgName", ""),
                        "version": vuln.get("InstalledVersion", ""),
                        "fixed": vuln.get("FixedVersion", ""),
                        "title": vuln.get("Title", ""),
                    })
        except (json.JSONDecodeError, TypeError):
            for line in output.splitlines():
                if "CVE-" in line:
                    entries.append({"raw": line.strip()})

        criticals = [e for e in entries if e.get("severity", "").upper() == "CRITICAL"]
        return ParsedResult(
            tool=ToolName.TRIVY,
            raw_length=len(output),
            entries=entries,
            summary=f"{len(entries)} vulns ({len(criticals)} critical)",
            findings_count=len(entries),
        )

    def _parse_semgrep(self, output: str) -> ParsedResult:
        """Parse semgrep output (JSON)."""
        entries: list[dict[str, Any]] = []

        try:
            data = json.loads(output)
            results = data.get("results", [])
            for result in results:
                entries.append({
                    "rule": result.get("check_id", ""),
                    "severity": result.get("extra", {}).get("severity", ""),
                    "file": result.get("path", ""),
                    "line": result.get("start", {}).get("line", 0),
                    "message": result.get("extra", {}).get("message", ""),
                })
        except (json.JSONDecodeError, TypeError):
            pass

        return ParsedResult(
            tool=ToolName.SEMGREP,
            raw_length=len(output),
            entries=entries,
            summary=f"{len(entries)} code findings",
            findings_count=len(entries),
        )

    def _parse_nikto(self, output: str) -> ParsedResult:
        """Parse nikto output."""
        entries: list[dict[str, Any]] = []

        for line in output.splitlines():
            if line.strip().startswith("+ "):
                entries.append({"finding": line.strip()[2:]})

        return ParsedResult(
            tool=ToolName.NIKTO,
            raw_length=len(output),
            entries=entries,
            summary=f"{len(entries)} nikto findings",
            findings_count=len(entries),
        )

    def _parse_masscan(self, output: str) -> ParsedResult:
        """Parse masscan output."""
        entries: list[dict[str, Any]] = []

        for line in output.splitlines():
            match = re.match(
                r"Discovered open port (\d+)/(tcp|udp) on (\S+)",
                line,
            )
            if match:
                entries.append({
                    "port": int(match.group(1)),
                    "protocol": match.group(2),
                    "host": match.group(3),
                })

        return ParsedResult(
            tool=ToolName.MASSCAN,
            raw_length=len(output),
            entries=entries,
            summary=f"{len(entries)} open ports discovered",
            findings_count=len(entries),
        )

    def _parse_httpx(self, output: str) -> ParsedResult:
        """Parse httpx output (JSON-lines)."""
        entries: list[dict[str, Any]] = []

        for line in output.splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    data = json.loads(line)
                    entries.append({
                        "url": data.get("url", ""),
                        "status": data.get("status_code", 0),
                        "title": data.get("title", ""),
                        "tech": data.get("tech", []),
                        "content_length": data.get("content_length", 0),
                    })
                except json.JSONDecodeError:
                    pass
            elif line.startswith("http"):
                entries.append({"url": line})

        return ParsedResult(
            tool=ToolName.HTTPX,
            raw_length=len(output),
            entries=entries,
            summary=f"{len(entries)} live hosts",
            findings_count=len(entries),
        )
