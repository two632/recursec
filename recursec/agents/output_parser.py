"""Output parser engine — structured extraction from tool output.

Implements:
1. Nmap output parsing (text + XML)
2. Nuclei output parsing (JSON + text)
3. SQLMap output parsing
4. Generic command output extraction
5. Error detection and classification
6. Finding extraction from raw output
7. JSON/JSONL parsing with error recovery
8. Pattern-based extraction
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class OutputFormat(str, Enum):
    TEXT = "text"
    JSON = "json"
    JSONL = "jsonl"
    XML = "xml"
    CSV = "csv"
    TABLE = "table"


class ExtractionType(str, Enum):
    PORT = "port"
    SERVICE = "service"
    VULNERABILITY = "vulnerability"
    CREDENTIAL = "credential"
    URL = "url"
    IP = "ip"
    HOSTNAME = "hostname"
    TECHNOLOGY = "technology"
    VERSION = "version"
    ERROR = "error"


@dataclass
class ExtractedItem:
    """An item extracted from tool output."""
    item_type: ExtractionType = ExtractionType.PORT
    value: str = ""
    source: str = ""
    confidence: float = 0.8
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.item_type.value,
            "value": self.value[:40],
            "source": self.source[:15],
            "confidence": round(self.confidence, 2),
        }


@dataclass
class ParseResult:
    """Result of parsing tool output."""
    tool: str = ""
    success: bool = True
    raw_length: int = 0
    items: list[ExtractedItem] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        type_counts: dict[str, int] = defaultdict(int)
        for item in self.items:
            type_counts[item.item_type.value] += 1
        return {
            "tool": self.tool[:15],
            "success": self.success,
            "items": len(self.items),
            "errors": len(self.errors),
            "by_type": dict(type_counts),
        }


# ── Regex patterns for extraction ────────────────────────────

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
CIDR_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b")
PORT_PATTERN = re.compile(r"\b(\d{1,5})/(?:tcp|udp)\s+(open|closed|filtered)\s+(.+)")
URL_PATTERN = re.compile(r"https?://[^\s<>\"']+")
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
VERSION_PATTERN = re.compile(r"(\w+(?:\s\w+)?)\s+(\d+\.\d+(?:\.\d+)*(?:-\w+)?)")
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")
HOSTNAME_PATTERN = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")


class OutputParserEngine:
    """Parses and extracts structured data from tool output.

    Handles multiple output formats and tools, extracting
    actionable findings and metadata for agent consumption.
    """

    def __init__(self) -> None:
        self._log = logger.bind(component="output_parser")
        self._parsers: dict[str, Any] = {
            "nmap": self._parse_nmap,
            "nuclei": self._parse_nuclei,
            "sqlmap": self._parse_sqlmap,
            "gobuster": self._parse_gobuster,
            "ffuf": self._parse_ffuf,
            "subfinder": self._parse_subdomain_tool,
            "amass": self._parse_subdomain_tool,
            "httpx": self._parse_httpx,
            "nikto": self._parse_nikto,
            "hydra": self._parse_hydra,
            "semgrep": self._parse_semgrep,
            "bandit": self._parse_bandit,
            "trivy": self._parse_trivy,
            "wpscan": self._parse_wpscan,
        }

    def parse(self, tool: str, output: str) -> ParseResult:
        """Parse tool output."""
        result = ParseResult(
            tool=tool,
            raw_length=len(output),
        )

        if not output.strip():
            result.success = False
            result.errors.append("Empty output")
            return result

        # Use tool-specific parser if available
        parser = self._parsers.get(tool.lower())
        if parser:
            try:
                items = parser(output)
                result.items = items
            except Exception as e:
                result.errors.append(f"Parser error: {str(e)[:50]}")
                # Fallback to generic extraction
                result.items = self._extract_generic(output)
        else:
            result.items = self._extract_generic(output)

        # Check for errors in output
        error_items = self._detect_errors(output)
        result.errors.extend(error_items)

        return result

    def _parse_nmap(self, output: str) -> list[ExtractedItem]:
        """Parse nmap text output."""
        items = []

        # Extract ports
        for match in PORT_PATTERN.finditer(output):
            port = match.group(1)
            state = match.group(2)
            service = match.group(3).strip()

            items.append(ExtractedItem(
                item_type=ExtractionType.PORT,
                value=port,
                source="nmap",
                confidence=0.95,
                metadata={"state": state, "service": service},
            ))

            # Extract service version
            if service and service != "unknown":
                items.append(ExtractedItem(
                    item_type=ExtractionType.SERVICE,
                    value=service,
                    source="nmap",
                    confidence=0.9,
                    metadata={"port": port},
                ))

        # Extract IPs
        for ip_match in re.finditer(r"Nmap scan report for (?:(\S+) \()?([\d.]+)\)?", output):
            hostname = ip_match.group(1) or ""
            ip = ip_match.group(2)
            items.append(ExtractedItem(
                item_type=ExtractionType.IP,
                value=ip,
                source="nmap",
                confidence=1.0,
                metadata={"hostname": hostname},
            ))

        # Extract OS detection
        os_match = re.search(r"OS details?:\s*(.+)", output)
        if os_match:
            items.append(ExtractedItem(
                item_type=ExtractionType.TECHNOLOGY,
                value=os_match.group(1).strip(),
                source="nmap",
                confidence=0.7,
            ))

        return items

    def _parse_nuclei(self, output: str) -> list[ExtractedItem]:
        """Parse nuclei output (JSON or text)."""
        items = []

        # Try JSON lines first
        for line in output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                severity = data.get("info", {}).get("severity", "unknown")
                items.append(ExtractedItem(
                    item_type=ExtractionType.VULNERABILITY,
                    value=data.get("info", {}).get("name", data.get("template-id", "")),
                    source="nuclei",
                    confidence=0.85,
                    metadata={
                        "severity": severity,
                        "template": data.get("template-id", ""),
                        "matched": data.get("matched-at", ""),
                        "curl": data.get("curl-command", ""),
                    },
                ))
            except json.JSONDecodeError:
                # Text format: [severity] [template-id] [protocol] url
                text_match = re.match(r"\[(\w+)\]\s+\[([^\]]+)\]\s+\[(\w+)\]\s+(.+)", line)
                if text_match:
                    items.append(ExtractedItem(
                        item_type=ExtractionType.VULNERABILITY,
                        value=text_match.group(2),
                        source="nuclei",
                        confidence=0.85,
                        metadata={
                            "severity": text_match.group(1),
                            "protocol": text_match.group(3),
                            "url": text_match.group(4),
                        },
                    ))

        return items

    def _parse_sqlmap(self, output: str) -> list[ExtractedItem]:
        """Parse sqlmap output."""
        items = []

        # Detect injectable parameters
        inject_match = re.findall(r"Parameter:\s+(\S+)\s+\((.+?)\)", output)
        for param, inject_type in inject_match:
            items.append(ExtractedItem(
                item_type=ExtractionType.VULNERABILITY,
                value=f"SQL Injection: {param}",
                source="sqlmap",
                confidence=0.95,
                metadata={"parameter": param, "type": inject_type},
            ))

        # Database info
        db_match = re.search(r"back-end DBMS:\s+(.+)", output)
        if db_match:
            items.append(ExtractedItem(
                item_type=ExtractionType.TECHNOLOGY,
                value=db_match.group(1).strip(),
                source="sqlmap",
                confidence=0.9,
            ))

        return items

    def _parse_gobuster(self, output: str) -> list[ExtractedItem]:
        """Parse gobuster output."""
        items = []
        for line in output.strip().split("\n"):
            # Format: /path (Status: 200) [Size: 1234]
            match = re.match(r"(/\S+)\s+\(Status:\s+(\d+)\)", line)
            if match:
                path = match.group(1)
                status = int(match.group(2))
                items.append(ExtractedItem(
                    item_type=ExtractionType.URL,
                    value=path,
                    source="gobuster",
                    confidence=0.9,
                    metadata={"status": status},
                ))
        return items

    def _parse_ffuf(self, output: str) -> list[ExtractedItem]:
        """Parse ffuf output."""
        items = []

        # Try JSON
        try:
            data = json.loads(output)
            for result in data.get("results", []):
                items.append(ExtractedItem(
                    item_type=ExtractionType.URL,
                    value=result.get("url", result.get("input", {}).get("FUZZ", "")),
                    source="ffuf",
                    confidence=0.9,
                    metadata={
                        "status": result.get("status", 0),
                        "length": result.get("length", 0),
                        "words": result.get("words", 0),
                    },
                ))
            return items
        except json.JSONDecodeError:
            pass

        # Text format
        for line in output.strip().split("\n"):
            match = re.match(r"(\S+)\s+\[Status:\s*(\d+)", line)
            if match:
                items.append(ExtractedItem(
                    item_type=ExtractionType.URL,
                    value=match.group(1),
                    source="ffuf",
                    confidence=0.9,
                    metadata={"status": int(match.group(2))},
                ))

        return items

    def _parse_subdomain_tool(self, output: str) -> list[ExtractedItem]:
        """Parse subfinder/amass output."""
        items = []
        for line in output.strip().split("\n"):
            line = line.strip()
            if line and "." in line and not line.startswith("["):
                items.append(ExtractedItem(
                    item_type=ExtractionType.HOSTNAME,
                    value=line,
                    source="subfinder",
                    confidence=0.9,
                ))
        return items

    def _parse_httpx(self, output: str) -> list[ExtractedItem]:
        """Parse httpx output."""
        items = []
        for line in output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue

            # Try JSON
            try:
                data = json.loads(line)
                items.append(ExtractedItem(
                    item_type=ExtractionType.URL,
                    value=data.get("url", data.get("input", "")),
                    source="httpx",
                    confidence=0.95,
                    metadata={
                        "status": data.get("status_code", 0),
                        "title": data.get("title", ""),
                        "tech": data.get("tech", []),
                        "webserver": data.get("webserver", ""),
                    },
                ))
            except json.JSONDecodeError:
                # Plain URL
                if line.startswith("http"):
                    items.append(ExtractedItem(
                        item_type=ExtractionType.URL,
                        value=line,
                        source="httpx",
                        confidence=0.9,
                    ))

        return items

    def _parse_nikto(self, output: str) -> list[ExtractedItem]:
        """Parse nikto output."""
        items = []
        for line in output.strip().split("\n"):
            if "+ " in line and "OSVDB" in line:
                items.append(ExtractedItem(
                    item_type=ExtractionType.VULNERABILITY,
                    value=line.split("+ ", 1)[-1].strip()[:80],
                    source="nikto",
                    confidence=0.6,
                ))
            elif "+ " in line and ("found" in line.lower() or "vulnerable" in line.lower()):
                items.append(ExtractedItem(
                    item_type=ExtractionType.VULNERABILITY,
                    value=line.split("+ ", 1)[-1].strip()[:80],
                    source="nikto",
                    confidence=0.5,
                ))
        return items

    def _parse_hydra(self, output: str) -> list[ExtractedItem]:
        """Parse hydra output."""
        items = []
        for line in output.strip().split("\n"):
            match = re.search(r"\[(\d+)\]\[(\w+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S+)", line)
            if match:
                items.append(ExtractedItem(
                    item_type=ExtractionType.CREDENTIAL,
                    value=f"{match.group(4)}:{match.group(5)}",
                    source="hydra",
                    confidence=0.95,
                    metadata={
                        "port": int(match.group(1)),
                        "service": match.group(2),
                        "host": match.group(3),
                    },
                ))
        return items

    def _parse_semgrep(self, output: str) -> list[ExtractedItem]:
        """Parse semgrep output."""
        items = []
        try:
            data = json.loads(output)
            for result in data.get("results", []):
                items.append(ExtractedItem(
                    item_type=ExtractionType.VULNERABILITY,
                    value=result.get("check_id", ""),
                    source="semgrep",
                    confidence=0.8,
                    metadata={
                        "severity": result.get("extra", {}).get("severity", ""),
                        "file": result.get("path", ""),
                        "line": result.get("start", {}).get("line", 0),
                        "message": result.get("extra", {}).get("message", "")[:60],
                    },
                ))
        except json.JSONDecodeError:
            pass
        return items

    def _parse_bandit(self, output: str) -> list[ExtractedItem]:
        """Parse bandit output."""
        items = []
        try:
            data = json.loads(output)
            for result in data.get("results", []):
                items.append(ExtractedItem(
                    item_type=ExtractionType.VULNERABILITY,
                    value=result.get("test_id", "") + ": " + result.get("test_name", ""),
                    source="bandit",
                    confidence=0.75,
                    metadata={
                        "severity": result.get("issue_severity", ""),
                        "confidence": result.get("issue_confidence", ""),
                        "file": result.get("filename", ""),
                        "line": result.get("line_number", 0),
                    },
                ))
        except json.JSONDecodeError:
            pass
        return items

    def _parse_trivy(self, output: str) -> list[ExtractedItem]:
        """Parse trivy output."""
        items = []
        try:
            data = json.loads(output)
            for result in data.get("Results", []):
                for vuln in result.get("Vulnerabilities", []):
                    items.append(ExtractedItem(
                        item_type=ExtractionType.VULNERABILITY,
                        value=vuln.get("VulnerabilityID", ""),
                        source="trivy",
                        confidence=0.9,
                        metadata={
                            "severity": vuln.get("Severity", ""),
                            "pkg": vuln.get("PkgName", ""),
                            "installed": vuln.get("InstalledVersion", ""),
                            "fixed": vuln.get("FixedVersion", ""),
                            "title": vuln.get("Title", "")[:60],
                        },
                    ))
        except json.JSONDecodeError:
            pass
        return items

    def _parse_wpscan(self, output: str) -> list[ExtractedItem]:
        """Parse wpscan output."""
        items = []
        try:
            data = json.loads(output)
            for vuln_data in data.get("vulnerabilities", []):
                items.append(ExtractedItem(
                    item_type=ExtractionType.VULNERABILITY,
                    value=vuln_data.get("title", ""),
                    source="wpscan",
                    confidence=0.85,
                    metadata={"type": vuln_data.get("vuln_type", "")},
                ))
            # Version
            wp_ver = data.get("version", {})
            if wp_ver:
                items.append(ExtractedItem(
                    item_type=ExtractionType.VERSION,
                    value=f"WordPress {wp_ver.get('number', '')}",
                    source="wpscan",
                    confidence=0.9,
                ))
        except json.JSONDecodeError:
            # Text mode
            for line in output.strip().split("\n"):
                if "| [!]" in line:
                    items.append(ExtractedItem(
                        item_type=ExtractionType.VULNERABILITY,
                        value=line.replace("| [!]", "").strip()[:60],
                        source="wpscan",
                        confidence=0.7,
                    ))
        return items

    def _extract_generic(self, output: str) -> list[ExtractedItem]:
        """Generic extraction using regex patterns."""
        items = []

        # IPs
        for match in IP_PATTERN.finditer(output):
            ip = match.group()
            if not ip.startswith("0.") and not ip.startswith("255."):
                items.append(ExtractedItem(
                    item_type=ExtractionType.IP,
                    value=ip,
                    source="generic",
                    confidence=0.6,
                ))

        # URLs
        seen_urls: set[str] = set()
        for match in URL_PATTERN.finditer(output):
            url = match.group()
            if url not in seen_urls:
                seen_urls.add(url)
                items.append(ExtractedItem(
                    item_type=ExtractionType.URL,
                    value=url,
                    source="generic",
                    confidence=0.7,
                ))

        # CVEs
        for match in CVE_PATTERN.finditer(output):
            items.append(ExtractedItem(
                item_type=ExtractionType.VULNERABILITY,
                value=match.group(),
                source="generic",
                confidence=0.8,
            ))

        return items

    def _detect_errors(self, output: str) -> list[str]:
        """Detect error patterns in output."""
        errors = []
        error_patterns = [
            (r"(?i)error[:\s]", "Error detected"),
            (r"(?i)permission denied", "Permission denied"),
            (r"(?i)connection refused", "Connection refused"),
            (r"(?i)timed? ?out", "Timeout"),
            (r"(?i)host unreachable", "Host unreachable"),
            (r"(?i)no route to host", "No route to host"),
        ]

        for pattern, msg in error_patterns:
            if re.search(pattern, output):
                errors.append(msg)

        return errors

    def get_stats(self) -> dict[str, Any]:
        return {
            "supported_tools": list(self._parsers.keys()),
            "total_parsers": len(self._parsers),
        }
