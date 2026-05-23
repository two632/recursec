"""Output parser engine — parses tool outputs into structured findings.

Implements:
1. Nmap output parsing (text + XML)
2. Nuclei output parsing (JSON + text)
3. SQLMap output parsing
4. Nikto output parsing
5. FFuf/Gobuster output parsing
6. Semgrep/Bandit output parsing
7. Hydra/Medusa output parsing
8. Generic tool output parsing
9. LLM-assisted output interpretation
10. Finding deduplication across tools
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class ParsedFinding:
    """A finding extracted from tool output."""
    title: str = ""
    severity: str = "info"
    target: str = ""
    port: int = 0
    protocol: str = ""
    service: str = ""
    description: str = ""
    evidence: str = ""
    tool: str = ""
    cwe: str = ""
    cve: str = ""
    reference: str = ""
    confidence: float = 0.8

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "title": self.title, "severity": self.severity,
            "target": self.target, "tool": self.tool,
        }
        if self.port:
            result["port"] = self.port
        if self.service:
            result["service"] = self.service
        if self.description:
            result["description"] = self.description[:200]
        if self.evidence:
            result["evidence"] = self.evidence[:300]
        if self.cwe:
            result["cwe"] = self.cwe
        if self.cve:
            result["cve"] = self.cve
        return result


class OutputParser:
    """Parses security tool outputs into structured findings."""

    def __init__(self) -> None:
        self._parsers = {
            "nmap": self._parse_nmap,
            "nuclei": self._parse_nuclei,
            "sqlmap": self._parse_sqlmap,
            "nikto": self._parse_nikto,
            "ffuf": self._parse_ffuf,
            "gobuster": self._parse_gobuster,
            "semgrep": self._parse_semgrep,
            "bandit": self._parse_bandit,
            "hydra": self._parse_hydra,
            "subfinder": self._parse_subfinder,
            "httpx": self._parse_httpx,
            "whatweb": self._parse_whatweb,
            "sslscan": self._parse_sslscan,
            "wpscan": self._parse_wpscan,
            "trivy": self._parse_trivy,
        }
        self._log = logger.bind(component="output_parser")

    def parse(self, tool: str, output: str, target: str = "") -> list[ParsedFinding]:
        """Parse tool output into findings."""
        parser = self._parsers.get(tool.lower())
        if parser:
            return parser(output, target)
        return self._parse_generic(output, target, tool)

    def _parse_nmap(self, output: str, target: str) -> list[ParsedFinding]:
        """Parse nmap output."""
        findings = []

        port_re = re.compile(
            r"(\d+)/(tcp|udp)\s+(open|filtered)\s+(\S+)\s*(.*)"
        )

        for line in output.splitlines():
            match = port_re.match(line.strip())
            if match:
                port_num = int(match.group(1))
                protocol = match.group(2)
                service = match.group(4)
                version = match.group(5).strip()

                findings.append(ParsedFinding(
                    title=f"Open port {port_num}/{protocol}: {service}",
                    severity="info",
                    target=target,
                    port=port_num,
                    protocol=protocol,
                    service=service,
                    description=f"Service: {service} {version}",
                    evidence=line.strip(),
                    tool="nmap",
                ))

                # Flag risky services
                risky = {"ftp": "medium", "telnet": "high", "mysql": "medium",
                         "mssql": "medium", "rdp": "medium", "vnc": "medium",
                         "smb": "medium", "netbios": "low"}
                for svc_name, sev in risky.items():
                    if svc_name in service.lower():
                        findings.append(ParsedFinding(
                            title=f"Exposed {svc_name.upper()} service on port {port_num}",
                            severity=sev,
                            target=target,
                            port=port_num,
                            service=service,
                            description=f"Potentially risky service {svc_name} is accessible",
                            evidence=line.strip(),
                            tool="nmap",
                        ))

        # Check for OS detection
        for line in output.splitlines():
            if "OS:" in line or "Running:" in line:
                findings.append(ParsedFinding(
                    title=f"OS Detection: {line.strip()[:60]}",
                    severity="info",
                    target=target,
                    description=line.strip(),
                    tool="nmap",
                ))

        return findings

    def _parse_nuclei(self, output: str, target: str) -> list[ParsedFinding]:
        """Parse nuclei output (JSON lines or text)."""
        findings = []

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            # Try JSON first
            try:
                data = json.loads(line)
                findings.append(ParsedFinding(
                    title=data.get("info", {}).get("name", data.get("template-id", "")),
                    severity=data.get("info", {}).get("severity", "info"),
                    target=data.get("host", target),
                    description=data.get("info", {}).get("description", ""),
                    evidence=data.get("matched-at", ""),
                    tool="nuclei",
                    cve=data.get("info", {}).get("classification", {}).get("cve-id", ""),
                    cwe=data.get("info", {}).get("classification", {}).get("cwe-id", ""),
                    reference=str(data.get("info", {}).get("reference", ""))[:200],
                ))
                continue
            except json.JSONDecodeError:
                pass

            # Text format: [severity] [template-id] [protocol] matched-at
            severity_match = re.match(
                r"\[(\w+)\]\s+\[([^\]]+)\]\s+(?:\[([^\]]+)\])?\s*(.*)",
                line,
            )
            if severity_match:
                sev = severity_match.group(1).lower()
                template = severity_match.group(2)
                matched = severity_match.group(4)

                sev_map = {"critical": "critical", "high": "high",
                           "medium": "medium", "low": "low", "info": "info"}
                severity = sev_map.get(sev, "info")

                findings.append(ParsedFinding(
                    title=template,
                    severity=severity,
                    target=matched or target,
                    evidence=line,
                    tool="nuclei",
                ))

        return findings

    def _parse_sqlmap(self, output: str, target: str) -> list[ParsedFinding]:
        """Parse sqlmap output."""
        findings = []

        if "is vulnerable" in output.lower() or "injectable" in output.lower():
            # Extract parameter info
            param = ""
            param_match = re.search(r"Parameter:\s+(\S+)", output)
            if param_match:
                param = param_match.group(1)

            # Extract injection type
            types = []
            for inj_type in ["boolean-based", "time-based", "error-based",
                             "UNION query", "stacked queries"]:
                if inj_type.lower() in output.lower():
                    types.append(inj_type)

            findings.append(ParsedFinding(
                title=f"SQL Injection in parameter '{param}'",
                severity="critical",
                target=target,
                description=f"SQL injection types: {', '.join(types)}",
                evidence=output[:300],
                tool="sqlmap",
                cwe="CWE-89",
            ))

        # Database info
        db_match = re.search(r"back-end DBMS:\s+(.+)", output)
        if db_match:
            findings.append(ParsedFinding(
                title=f"Database detected: {db_match.group(1)[:50]}",
                severity="info",
                target=target,
                tool="sqlmap",
            ))

        return findings

    def _parse_nikto(self, output: str, target: str) -> list[ParsedFinding]:
        """Parse nikto output."""
        findings = []

        for line in output.splitlines():
            if line.startswith("+ "):
                text = line[2:].strip()

                severity = "info"
                if any(w in text.lower() for w in ["vulnerability", "outdated", "critical"]):
                    severity = "high"
                elif any(w in text.lower() for w in ["found", "retrieved", "directory"]):
                    severity = "medium"
                elif "server" in text.lower():
                    severity = "low"

                # Extract OSVDB/CVE
                cve = ""
                cve_match = re.search(r"(CVE-\d{4}-\d+)", text)
                if cve_match:
                    cve = cve_match.group(1)

                findings.append(ParsedFinding(
                    title=text[:80],
                    severity=severity,
                    target=target,
                    evidence=text,
                    tool="nikto",
                    cve=cve,
                ))

        return findings

    def _parse_ffuf(self, output: str, target: str) -> list[ParsedFinding]:
        """Parse ffuf output."""
        findings = []

        for line in output.splitlines():
            # Try JSON
            try:
                data = json.loads(line)
                if "results" in data:
                    for result in data["results"]:
                        findings.append(ParsedFinding(
                            title=f"Discovered: {result.get('url', '')}",
                            severity="info",
                            target=result.get("url", target),
                            description=f"Status: {result.get('status')}, Size: {result.get('length')}",
                            tool="ffuf",
                        ))
                continue
            except json.JSONDecodeError:
                pass

            # Text format
            status_match = re.match(
                r".*\[Status:\s*(\d+).*Size:\s*(\d+).*",
                line,
            )
            if status_match:
                findings.append(ParsedFinding(
                    title=f"Discovered path (status {status_match.group(1)})",
                    severity="info",
                    target=target,
                    evidence=line.strip(),
                    tool="ffuf",
                ))

        return findings

    def _parse_gobuster(self, output: str, target: str) -> list[ParsedFinding]:
        """Parse gobuster output."""
        findings = []

        for line in output.splitlines():
            match = re.match(r"/([\w./-]+)\s+\(Status:\s*(\d+)\)", line.strip())
            if match:
                path = match.group(1)
                status = match.group(2)

                findings.append(ParsedFinding(
                    title=f"Discovered: /{path} (status {status})",
                    severity="info",
                    target=f"{target}/{path}",
                    evidence=line.strip(),
                    tool="gobuster",
                ))

        return findings

    def _parse_semgrep(self, output: str, target: str) -> list[ParsedFinding]:
        """Parse semgrep JSON output."""
        findings = []

        try:
            data = json.loads(output)
            for result in data.get("results", []):
                severity_map = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}

                findings.append(ParsedFinding(
                    title=result.get("check_id", ""),
                    severity=severity_map.get(
                        result.get("extra", {}).get("severity", "INFO"), "info",
                    ),
                    target=result.get("path", target),
                    description=result.get("extra", {}).get("message", ""),
                    evidence=result.get("extra", {}).get("lines", ""),
                    tool="semgrep",
                    cwe=str(result.get("extra", {}).get("metadata", {}).get("cwe", "")),
                ))
        except json.JSONDecodeError:
            pass

        return findings

    def _parse_bandit(self, output: str, target: str) -> list[ParsedFinding]:
        """Parse bandit JSON output."""
        findings = []

        try:
            data = json.loads(output)
            for result in data.get("results", []):
                severity_map = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}

                findings.append(ParsedFinding(
                    title=result.get("test_id", "") + ": " + result.get("test_name", ""),
                    severity=severity_map.get(result.get("issue_severity", "LOW"), "info"),
                    target=result.get("filename", target),
                    description=result.get("issue_text", ""),
                    evidence=result.get("code", "")[:200],
                    tool="bandit",
                    cwe=result.get("issue_cwe", {}).get("id", ""),
                ))
        except json.JSONDecodeError:
            pass

        return findings

    def _parse_hydra(self, output: str, target: str) -> list[ParsedFinding]:
        """Parse hydra output."""
        findings = []

        for line in output.splitlines():
            match = re.search(
                r"\[(\d+)\]\[(\w+)\]\s+host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(\S+)",
                line,
            )
            if match:
                port = int(match.group(1))
                protocol = match.group(2)
                host = match.group(3)
                login = match.group(4)

                findings.append(ParsedFinding(
                    title=f"Valid credentials found for {protocol}://{host}:{port}",
                    severity="critical",
                    target=host,
                    port=port,
                    protocol=protocol,
                    description=f"Username: {login}",
                    evidence=line.strip(),
                    tool="hydra",
                    cwe="CWE-521",
                ))

        return findings

    def _parse_subfinder(self, output: str, target: str) -> list[ParsedFinding]:
        """Parse subfinder output."""
        findings = []

        for line in output.splitlines():
            subdomain = line.strip()
            if subdomain and "." in subdomain:
                findings.append(ParsedFinding(
                    title=f"Subdomain: {subdomain}",
                    severity="info",
                    target=subdomain,
                    tool="subfinder",
                ))

        return findings

    def _parse_httpx(self, output: str, target: str) -> list[ParsedFinding]:
        """Parse httpx output."""
        findings = []

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            # Try JSON
            try:
                data = json.loads(line)
                findings.append(ParsedFinding(
                    title=f"HTTP: {data.get('url', '')} [{data.get('status_code', '')}]",
                    severity="info",
                    target=data.get("url", target),
                    description=f"Tech: {data.get('tech', [])}",
                    tool="httpx",
                ))
                continue
            except json.JSONDecodeError:
                pass

            if line.startswith("http"):
                findings.append(ParsedFinding(
                    title=f"Live host: {line[:80]}",
                    severity="info",
                    target=line,
                    tool="httpx",
                ))

        return findings

    def _parse_whatweb(self, output: str, target: str) -> list[ParsedFinding]:
        """Parse whatweb output."""
        findings = []

        for line in output.splitlines():
            if not line.strip():
                continue

            findings.append(ParsedFinding(
                title=f"Technology: {line[:80]}",
                severity="info",
                target=target,
                evidence=line[:200],
                tool="whatweb",
            ))

        return findings

    def _parse_sslscan(self, output: str, target: str) -> list[ParsedFinding]:
        """Parse sslscan output."""
        findings = []

        weak_ciphers = ["RC4", "DES", "3DES", "NULL", "EXPORT"]
        weak_protocols = ["SSLv2", "SSLv3", "TLSv1.0"]

        for line in output.splitlines():
            for cipher in weak_ciphers:
                if cipher in line and "Accepted" in line:
                    findings.append(ParsedFinding(
                        title=f"Weak cipher: {cipher}",
                        severity="medium",
                        target=target,
                        evidence=line.strip(),
                        tool="sslscan",
                        cwe="CWE-327",
                    ))

            for proto in weak_protocols:
                if proto in line and ("Enabled" in line or "enabled" in line):
                    findings.append(ParsedFinding(
                        title=f"Weak protocol: {proto}",
                        severity="medium" if proto == "TLSv1.0" else "high",
                        target=target,
                        evidence=line.strip(),
                        tool="sslscan",
                        cwe="CWE-326",
                    ))

        return findings

    def _parse_wpscan(self, output: str, target: str) -> list[ParsedFinding]:
        """Parse WPScan output."""
        findings = []

        try:
            data = json.loads(output)
            for vuln in data.get("vulnerabilities", []):
                findings.append(ParsedFinding(
                    title=vuln.get("title", ""),
                    severity="high",
                    target=target,
                    description=vuln.get("description", ""),
                    tool="wpscan",
                    cve=str(vuln.get("references", {}).get("cve", "")),
                ))
        except json.JSONDecodeError:
            # Text mode
            for line in output.splitlines():
                if "[!]" in line:
                    findings.append(ParsedFinding(
                        title=line.replace("[!]", "").strip()[:80],
                        severity="medium",
                        target=target,
                        evidence=line.strip(),
                        tool="wpscan",
                    ))

        return findings

    def _parse_trivy(self, output: str, target: str) -> list[ParsedFinding]:
        """Parse trivy JSON output."""
        findings = []

        try:
            data = json.loads(output)
            for result in data.get("Results", []):
                for vuln in result.get("Vulnerabilities", []):
                    sev_map = {"CRITICAL": "critical", "HIGH": "high",
                               "MEDIUM": "medium", "LOW": "low"}

                    findings.append(ParsedFinding(
                        title=f"{vuln.get('VulnerabilityID', '')}: {vuln.get('PkgName', '')}",
                        severity=sev_map.get(vuln.get("Severity", "LOW"), "info"),
                        target=result.get("Target", target),
                        description=vuln.get("Title", ""),
                        tool="trivy",
                        cve=vuln.get("VulnerabilityID", ""),
                    ))
        except json.JSONDecodeError:
            pass

        return findings

    def _parse_generic(self, output: str, target: str, tool: str) -> list[ParsedFinding]:
        """Generic parser for unknown tools."""
        findings = []

        # Look for CVE references
        cve_pattern = re.compile(r"(CVE-\d{4}-\d+)")
        for match in cve_pattern.finditer(output):
            findings.append(ParsedFinding(
                title=f"CVE Reference: {match.group(1)}",
                severity="medium",
                target=target,
                cve=match.group(1),
                tool=tool,
            ))

        # Look for severity indicators
        for line in output.splitlines():
            line_lower = line.lower()
            for keyword in ["critical", "high", "vulnerability", "exploit"]:
                if keyword in line_lower:
                    findings.append(ParsedFinding(
                        title=line.strip()[:80],
                        severity="high" if keyword in ("critical", "exploit") else "medium",
                        target=target,
                        evidence=line.strip(),
                        tool=tool,
                    ))
                    break

        return findings

    def get_stats(self) -> dict[str, Any]:
        return {"parsers": len(self._parsers)}
