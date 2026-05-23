"""Output parser — parses structured output from security tools.

Implements:
1. Nmap output parsing (text + XML)
2. Nuclei output parsing (JSON + text)
3. SQLMap output parsing
4. Nikto output parsing
5. Gobuster/ffuf output parsing
6. SSLyze/testssl.sh output parsing
7. Hydra/Medusa output parsing
8. Semgrep output parsing
9. WPScan output parsing
10. Generic JSON/text parsers
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class ParsedHost:
    """A parsed host from tool output."""
    ip: str = ""
    hostname: str = ""
    os_guess: str = ""
    ports: list[dict[str, Any]] = field(default_factory=list)
    status: str = "up"

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "hostname": self.hostname[:30],
            "os": self.os_guess[:30],
            "ports": len(self.ports),
            "status": self.status,
        }


@dataclass
class ParsedVuln:
    """A parsed vulnerability from tool output."""
    vuln_id: str = ""
    title: str = ""
    severity: str = "medium"
    target: str = ""
    url: str = ""
    template: str = ""
    matcher: str = ""
    evidence: str = ""
    tool: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.vuln_id[:15],
            "title": self.title[:40],
            "severity": self.severity,
            "target": self.target[:25],
            "tool": self.tool[:10],
        }


@dataclass
class ParsedCredential:
    """A parsed credential from brute-force tool output."""
    host: str = ""
    port: int = 0
    service: str = ""
    username: str = ""
    password: str = ""
    tool: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host[:20],
            "port": self.port,
            "service": self.service[:10],
            "user": self.username[:15],
            "tool": self.tool[:10],
        }


@dataclass
class ParsedEndpoint:
    """A parsed endpoint from directory/content scanning."""
    url: str = ""
    status_code: int = 0
    size: int = 0
    content_type: str = ""
    redirect: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url[:50],
            "status": self.status_code,
            "size": self.size,
        }


@dataclass
class ParseResult:
    """Complete parsed result from a tool."""
    tool: str = ""
    success: bool = True
    hosts: list[ParsedHost] = field(default_factory=list)
    vulns: list[ParsedVuln] = field(default_factory=list)
    credentials: list[ParsedCredential] = field(default_factory=list)
    endpoints: list[ParsedEndpoint] = field(default_factory=list)
    raw_data: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool[:15],
            "success": self.success,
            "hosts": len(self.hosts),
            "vulns": len(self.vulns),
            "creds": len(self.credentials),
            "endpoints": len(self.endpoints),
            "errors": len(self.errors),
        }


class OutputParser:
    """Parses output from various security tools into structured data."""

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
            "wpscan": self._parse_wpscan,
            "testssl": self._parse_testssl,
            "subfinder": self._parse_subfinder,
            "httpx": self._parse_httpx,
        }
        self._log = logger.bind(component="output_parser")

    def parse(self, tool: str, output: str) -> ParseResult:
        """Parse tool output."""
        parser = self._parsers.get(tool.lower())
        if not parser:
            return self._parse_generic(tool, output)

        try:
            return parser(output)
        except Exception as e:
            return ParseResult(
                tool=tool,
                success=False,
                errors=[str(e)],
            )

    def _parse_nmap(self, output: str) -> ParseResult:
        """Parse nmap text output."""
        result = ParseResult(tool="nmap")
        current_host = None

        for line in output.split("\n"):
            line = line.strip()

            # Host discovery
            host_match = re.match(
                r"Nmap scan report for (\S+?)(?:\s+\((\d+\.\d+\.\d+\.\d+)\))?$",
                line,
            )
            if host_match:
                if current_host:
                    result.hosts.append(current_host)
                hostname = host_match.group(1)
                ip = host_match.group(2) or hostname
                current_host = ParsedHost(ip=ip, hostname=hostname)
                continue

            # Port line
            port_match = re.match(
                r"(\d+)/(tcp|udp)\s+(\S+)\s+(.*)$", line
            )
            if port_match and current_host:
                port_num = int(port_match.group(1))
                protocol = port_match.group(2)
                state = port_match.group(3)
                service = port_match.group(4).strip()
                current_host.ports.append({
                    "port": port_num,
                    "protocol": protocol,
                    "state": state,
                    "service": service,
                })
                continue

            # OS detection
            os_match = re.match(r"OS details?:\s+(.+)$", line)
            if os_match and current_host:
                current_host.os_guess = os_match.group(1)

            # Host status
            if "Host is up" in line and current_host:
                current_host.status = "up"
            elif "Host seems down" in line and current_host:
                current_host.status = "down"

        if current_host:
            result.hosts.append(current_host)

        total_ports = sum(len(h.ports) for h in result.hosts)
        result.summary = f"{len(result.hosts)} hosts, {total_ports} ports"

        return result

    def _parse_nuclei(self, output: str) -> ParseResult:
        """Parse nuclei output (JSON lines or text)."""
        result = ParseResult(tool="nuclei")

        for line in output.split("\n"):
            line = line.strip()
            if not line:
                continue

            # Try JSON parse first
            if line.startswith("{"):
                try:
                    data = json.loads(line)
                    vuln = ParsedVuln(
                        vuln_id=data.get("template-id", ""),
                        title=data.get("info", {}).get("name", ""),
                        severity=data.get("info", {}).get("severity", "medium"),
                        target=data.get("host", ""),
                        url=data.get("matched-at", ""),
                        template=data.get("template-id", ""),
                        matcher=data.get("matcher-name", ""),
                        evidence=data.get("extracted-results", [""])[0] if data.get("extracted-results") else "",
                        tool="nuclei",
                    )
                    result.vulns.append(vuln)
                    continue
                except json.JSONDecodeError:
                    pass

            # Text format: [severity] [template-id] [protocol] url
            text_match = re.match(
                r"\[(\w+)\]\s+\[([^\]]+)\]\s+\[(\w+)\]\s+(.+)$", line
            )
            if text_match:
                result.vulns.append(ParsedVuln(
                    severity=text_match.group(1).lower(),
                    template=text_match.group(2),
                    title=text_match.group(2),
                    target=text_match.group(4),
                    url=text_match.group(4),
                    tool="nuclei",
                ))

        result.summary = f"{len(result.vulns)} findings"
        return result

    def _parse_sqlmap(self, output: str) -> ParseResult:
        """Parse sqlmap output."""
        result = ParseResult(tool="sqlmap")

        # Find injectable parameters
        injectable_params: list[str] = []
        db_type = ""
        current_param = ""

        for line in output.split("\n"):
            line = line.strip()

            param_match = re.search(
                r"Parameter:\s+(\S+)\s+\((\w+)\)", line
            )
            if param_match:
                current_param = param_match.group(1)
                injectable_params.append(current_param)

            dbms_match = re.search(r"back-end DBMS:\s+(.+)$", line)
            if dbms_match:
                db_type = dbms_match.group(1)

            if "is vulnerable" in line.lower():
                result.vulns.append(ParsedVuln(
                    title=f"SQL Injection in {current_param}",
                    severity="critical",
                    evidence=line,
                    tool="sqlmap",
                ))

        if injectable_params:
            result.summary = (
                f"Injectable params: {', '.join(injectable_params)}"
                f"{f' (DB: {db_type})' if db_type else ''}"
            )
        else:
            result.summary = "No injection points found"

        return result

    def _parse_nikto(self, output: str) -> ParseResult:
        """Parse nikto output."""
        result = ParseResult(tool="nikto")

        for line in output.split("\n"):
            line = line.strip()
            if not line.startswith("+ "):
                continue

            content = line[2:]

            # Skip info lines
            if any(kw in content.lower() for kw in (
                "target ip:", "target hostname:", "target port:",
                "start time:", "end time:", "server:",
            )):
                continue

            # OSVDB reference
            osvdb_match = re.match(r"OSVDB-(\d+):\s+(.+)$", content)
            if osvdb_match:
                result.vulns.append(ParsedVuln(
                    vuln_id=f"OSVDB-{osvdb_match.group(1)}",
                    title=osvdb_match.group(2)[:80],
                    severity="medium",
                    evidence=content,
                    tool="nikto",
                ))
            elif "VULNERABLE" in content.upper():
                result.vulns.append(ParsedVuln(
                    title=content[:80],
                    severity="high",
                    evidence=content,
                    tool="nikto",
                ))

        result.summary = f"{len(result.vulns)} findings"
        return result

    def _parse_gobuster(self, output: str) -> ParseResult:
        """Parse gobuster output."""
        result = ParseResult(tool="gobuster")

        for line in output.split("\n"):
            line = line.strip()
            # Format: /path (Status: 200) [Size: 1234]
            match = re.match(
                r"(/\S*)\s+\(Status:\s+(\d+)\)\s+\[Size:\s+(\d+)\]", line
            )
            if match:
                result.endpoints.append(ParsedEndpoint(
                    url=match.group(1),
                    status_code=int(match.group(2)),
                    size=int(match.group(3)),
                ))

        result.summary = f"{len(result.endpoints)} endpoints"
        return result

    def _parse_ffuf(self, output: str) -> ParseResult:
        """Parse ffuf output (JSON or text)."""
        result = ParseResult(tool="ffuf")

        # Try JSON
        try:
            data = json.loads(output)
            for item in data.get("results", []):
                result.endpoints.append(ParsedEndpoint(
                    url=item.get("url", ""),
                    status_code=item.get("status", 0),
                    size=item.get("length", 0),
                    content_type=item.get("content-type", ""),
                    redirect=item.get("redirectlocation", ""),
                ))
            result.summary = f"{len(result.endpoints)} endpoints"
            return result
        except json.JSONDecodeError:
            pass

        # Text format
        for line in output.split("\n"):
            match = re.match(
                r"\S+\s+\[Status:\s+(\d+),\s+Size:\s+(\d+)", line
            )
            if match:
                result.endpoints.append(ParsedEndpoint(
                    url=line.split()[0] if line.split() else "",
                    status_code=int(match.group(1)),
                    size=int(match.group(2)),
                ))

        result.summary = f"{len(result.endpoints)} endpoints"
        return result

    def _parse_hydra(self, output: str) -> ParseResult:
        """Parse hydra output."""
        result = ParseResult(tool="hydra")

        for line in output.split("\n"):
            # [PORT][SERVICE] host:IP login:USER password:PASS
            match = re.search(
                r"\[(\d+)\]\[(\w+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S+)",
                line,
            )
            if match:
                result.credentials.append(ParsedCredential(
                    port=int(match.group(1)),
                    service=match.group(2),
                    host=match.group(3),
                    username=match.group(4),
                    password=match.group(5),
                    tool="hydra",
                ))

        result.summary = f"{len(result.credentials)} credentials found"
        return result

    def _parse_semgrep(self, output: str) -> ParseResult:
        """Parse semgrep output."""
        result = ParseResult(tool="semgrep")

        try:
            data = json.loads(output)
            for item in data.get("results", []):
                result.vulns.append(ParsedVuln(
                    vuln_id=item.get("check_id", ""),
                    title=item.get("extra", {}).get("message", "")[:80],
                    severity=item.get("extra", {}).get("severity", "medium").lower(),
                    target=item.get("path", ""),
                    evidence=item.get("extra", {}).get("lines", ""),
                    tool="semgrep",
                ))
        except json.JSONDecodeError:
            # Text format
            for line in output.split("\n"):
                if "error" in line.lower() or "warning" in line.lower():
                    result.vulns.append(ParsedVuln(
                        title=line[:80],
                        severity="medium",
                        tool="semgrep",
                    ))

        result.summary = f"{len(result.vulns)} code issues"
        return result

    def _parse_wpscan(self, output: str) -> ParseResult:
        """Parse WPScan output."""
        result = ParseResult(tool="wpscan")

        try:
            data = json.loads(output)

            # Interesting findings
            for finding in data.get("interesting_findings", []):
                result.vulns.append(ParsedVuln(
                    title=finding.get("to_s", "")[:80],
                    severity="info",
                    url=finding.get("url", ""),
                    tool="wpscan",
                ))

            # Vulnerabilities
            for vuln_list in data.get("plugins", {}).values():
                for vuln in vuln_list.get("vulnerabilities", []):
                    result.vulns.append(ParsedVuln(
                        vuln_id=vuln.get("references", {}).get("cve", [""])[0],
                        title=vuln.get("title", "")[:80],
                        severity="high",
                        tool="wpscan",
                    ))
        except json.JSONDecodeError:
            # Text format
            for line in output.split("\n"):
                if "| [!]" in line:
                    result.vulns.append(ParsedVuln(
                        title=line.replace("| [!]", "").strip()[:80],
                        severity="high",
                        tool="wpscan",
                    ))

        result.summary = f"{len(result.vulns)} findings"
        return result

    def _parse_testssl(self, output: str) -> ParseResult:
        """Parse testssl.sh output."""
        result = ParseResult(tool="testssl")

        severity_map = {
            "CRITICAL": "critical",
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
            "OK": "info",
            "INFO": "info",
        }

        for line in output.split("\n"):
            for sev_key, sev_val in severity_map.items():
                if sev_key in line and sev_val in ("critical", "high", "medium"):
                    result.vulns.append(ParsedVuln(
                        title=line.strip()[:80],
                        severity=sev_val,
                        tool="testssl",
                    ))
                    break

        result.summary = f"{len(result.vulns)} TLS issues"
        return result

    def _parse_subfinder(self, output: str) -> ParseResult:
        """Parse subfinder output."""
        result = ParseResult(tool="subfinder")

        for line in output.split("\n"):
            line = line.strip()
            if line and "." in line and not line.startswith("["):
                result.hosts.append(ParsedHost(
                    hostname=line,
                    status="discovered",
                ))

        result.summary = f"{len(result.hosts)} subdomains"
        return result

    def _parse_httpx(self, output: str) -> ParseResult:
        """Parse httpx output."""
        result = ParseResult(tool="httpx")

        for line in output.split("\n"):
            line = line.strip()
            if not line:
                continue

            # Try JSON
            try:
                data = json.loads(line)
                result.endpoints.append(ParsedEndpoint(
                    url=data.get("url", ""),
                    status_code=data.get("status_code", 0),
                    size=data.get("content_length", 0),
                    content_type=data.get("content_type", ""),
                ))
                continue
            except json.JSONDecodeError:
                pass

            # Text: URL [status] [size]
            match = re.match(r"(\S+)\s+\[(\d+)\]", line)
            if match:
                result.endpoints.append(ParsedEndpoint(
                    url=match.group(1),
                    status_code=int(match.group(2)),
                ))

        result.summary = f"{len(result.endpoints)} live URLs"
        return result

    def _parse_generic(self, tool: str, output: str) -> ParseResult:
        """Generic parser for unknown tools."""
        result = ParseResult(tool=tool)

        # Try JSON
        try:
            data = json.loads(output)
            result.raw_data = data
            result.summary = f"JSON with {len(data)} keys" if isinstance(data, dict) else f"JSON array with {len(data)} items"
            return result
        except (json.JSONDecodeError, TypeError):
            pass

        # Count interesting patterns
        lines = output.split("\n")
        result.raw_data = {"line_count": len(lines)}
        result.summary = f"{len(lines)} lines of output"

        return result

    def get_supported_tools(self) -> list[str]:
        return sorted(self._parsers.keys())
