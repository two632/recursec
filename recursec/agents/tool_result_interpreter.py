"""Tool result interpreter — translates parsed tool outputs into agent actions.

Implements:
1. Finding extraction from parsed results
2. Next-step recommendations based on tool output
3. Gap analysis (what wasn't covered)
4. Confidence scoring for findings
5. Follow-up action generation
6. Cross-tool correlation triggers
7. Priority-based finding ranking
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

from recursec.agents.output_parser import ParseResult

logger = structlog.get_logger()


@dataclass
class InterpretedFinding:
    """An interpreted finding from tool output."""
    finding_id: str = ""
    title: str = ""
    severity: str = "medium"
    target: str = ""
    confidence: float = 0.5
    cwe_id: str = ""
    evidence: str = ""
    tool: str = ""
    follow_up_actions: list[str] = field(default_factory=list)
    cross_correlate_with: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.finding_id,
            "title": self.title[:40],
            "severity": self.severity,
            "confidence": round(self.confidence, 2),
            "actions": len(self.follow_up_actions),
        }


@dataclass
class GapAnalysis:
    """Analysis of coverage gaps after tool execution."""
    checked_areas: list[str] = field(default_factory=list)
    unchecked_areas: list[str] = field(default_factory=list)
    recommended_tools: list[str] = field(default_factory=list)
    coverage_pct: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "checked": len(self.checked_areas),
            "unchecked": len(self.unchecked_areas),
            "reco_tools": len(self.recommended_tools),
            "coverage": round(self.coverage_pct, 2),
        }


@dataclass
class InterpretationResult:
    """Complete interpretation of a tool's output."""
    tool: str = ""
    findings: list[InterpretedFinding] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)
    gap_analysis: GapAnalysis = field(default_factory=GapAnalysis)
    summary_for_llm: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool[:15],
            "findings": len(self.findings),
            "next_steps": len(self.next_steps),
            "gaps": self.gap_analysis.to_dict(),
        }


# ── Port → Service Vulnerability Hints ────────────────────────

PORT_VULN_HINTS: dict[int, dict[str, Any]] = {
    21: {"service": "FTP", "checks": ["anonymous_login", "brute_force"], "tools": ["hydra", "nmap"]},
    22: {"service": "SSH", "checks": ["brute_force", "weak_keys", "agent_forwarding"], "tools": ["ssh-audit", "hydra"]},
    23: {"service": "Telnet", "checks": ["cleartext_creds", "brute_force"], "tools": ["hydra"]},
    25: {"service": "SMTP", "checks": ["open_relay", "vrfy_enum", "spoofing"], "tools": ["nmap", "smtp-user-enum"]},
    53: {"service": "DNS", "checks": ["zone_transfer", "cache_poisoning"], "tools": ["dig", "dnsrecon"]},
    80: {"service": "HTTP", "checks": ["web_vulns", "directory_scan", "header_check"], "tools": ["nuclei", "gobuster", "nikto"]},
    110: {"service": "POP3", "checks": ["cleartext_creds", "brute_force"], "tools": ["hydra"]},
    135: {"service": "RPC", "checks": ["rpc_enum"], "tools": ["rpcclient"]},
    139: {"service": "NetBIOS", "checks": ["smb_enum", "null_session"], "tools": ["enum4linux"]},
    443: {"service": "HTTPS", "checks": ["web_vulns", "tls_config", "cert_check"], "tools": ["nuclei", "testssl", "gobuster"]},
    445: {"service": "SMB", "checks": ["smb_signing", "null_session", "known_cves"], "tools": ["crackmapexec", "smbclient"]},
    1433: {"service": "MSSQL", "checks": ["brute_force", "xp_cmdshell"], "tools": ["hydra", "mssqlclient"]},
    1521: {"service": "Oracle", "checks": ["brute_force", "tns_listener"], "tools": ["hydra", "odat"]},
    3306: {"service": "MySQL", "checks": ["brute_force", "udf_exploit"], "tools": ["hydra", "mysql"]},
    3389: {"service": "RDP", "checks": ["brute_force", "bluekeep"], "tools": ["hydra", "nmap"]},
    5432: {"service": "PostgreSQL", "checks": ["brute_force", "copy_to"], "tools": ["hydra", "psql"]},
    5900: {"service": "VNC", "checks": ["no_auth", "brute_force"], "tools": ["hydra", "nmap"]},
    6379: {"service": "Redis", "checks": ["no_auth", "rce_via_lua"], "tools": ["redis-cli", "nmap"]},
    8080: {"service": "HTTP-Alt", "checks": ["web_vulns", "admin_panels"], "tools": ["nuclei", "gobuster"]},
    8443: {"service": "HTTPS-Alt", "checks": ["web_vulns", "tls_config"], "tools": ["nuclei", "testssl"]},
    9200: {"service": "Elasticsearch", "checks": ["no_auth", "data_exposure"], "tools": ["curl"]},
    27017: {"service": "MongoDB", "checks": ["no_auth", "data_exposure"], "tools": ["mongosh"]},
}

# ── Severity → CWE Mapping Hints ─────────────────────────────

VULN_CWE_MAP: dict[str, str] = {
    "sql injection": "CWE-89",
    "sqli": "CWE-89",
    "xss": "CWE-79",
    "cross-site scripting": "CWE-79",
    "path traversal": "CWE-22",
    "directory traversal": "CWE-22",
    "command injection": "CWE-78",
    "os command": "CWE-78",
    "ssrf": "CWE-918",
    "server-side request": "CWE-918",
    "deserialization": "CWE-502",
    "open redirect": "CWE-601",
    "csrf": "CWE-352",
    "file upload": "CWE-434",
    "xxe": "CWE-611",
    "xml external": "CWE-611",
    "information disclosure": "CWE-200",
    "sensitive data": "CWE-200",
    "authentication bypass": "CWE-287",
    "missing auth": "CWE-862",
    "hard-coded": "CWE-798",
    "hardcoded": "CWE-798",
    "weak cipher": "CWE-327",
    "broken crypto": "CWE-327",
}


class ToolResultInterpreter:
    """Interprets tool results and generates actionable intelligence.

    Translates raw parsed output into findings, next steps,
    and gap analysis that the agent uses for decision-making.
    """

    def __init__(self) -> None:
        self._finding_counter = 0
        self._interpretations: list[InterpretationResult] = []
        self._log = logger.bind(component="tool_result_interpreter")

    def interpret(self, parsed: ParseResult) -> InterpretationResult:
        """Interpret a parsed tool result."""
        result = InterpretationResult(tool=parsed.tool)

        # Extract findings from vulnerabilities
        for vuln in parsed.vulns:
            self._finding_counter += 1
            finding = InterpretedFinding(
                finding_id=f"int-{self._finding_counter}",
                title=vuln.title,
                severity=vuln.severity,
                target=vuln.target,
                tool=vuln.tool,
                evidence=vuln.evidence,
            )

            # Auto CWE mapping
            finding.cwe_id = self._guess_cwe(vuln.title)

            # Confidence based on tool + evidence
            finding.confidence = self._estimate_confidence(vuln)

            # Generate follow-up actions
            finding.follow_up_actions = self._generate_followups(finding)

            # Cross-correlation hints
            finding.cross_correlate_with = self._correlation_hints(finding)

            result.findings.append(finding)

        # Generate next steps from hosts/ports
        for host in parsed.hosts:
            for port_info in host.ports:
                port = port_info.get("port", 0)
                state = port_info.get("state", "")
                if state == "open" and port in PORT_VULN_HINTS:
                    hint = PORT_VULN_HINTS[port]
                    for check in hint["checks"]:
                        result.next_steps.append(
                            f"Check {host.ip}:{port} ({hint['service']}) for {check}"
                        )

        # Generate next steps from endpoints
        interesting_codes = {200, 301, 302, 401, 403, 500}
        for ep in parsed.endpoints:
            if ep.status_code in interesting_codes:
                if ep.status_code == 401:
                    result.next_steps.append(f"Auth bypass test on {ep.url}")
                elif ep.status_code == 403:
                    result.next_steps.append(f"403 bypass test on {ep.url}")
                elif ep.status_code == 500:
                    result.next_steps.append(f"Error-based vuln test on {ep.url}")

        # Generate next steps from credentials
        for cred in parsed.credentials:
            result.next_steps.append(
                f"Use creds {cred.username}@{cred.host}:{cred.port} for lateral movement"
            )

        # Gap analysis
        result.gap_analysis = self._analyze_gaps(parsed)

        # LLM summary
        result.summary_for_llm = self._build_llm_summary(result)

        self._interpretations.append(result)
        return result

    @staticmethod
    def _guess_cwe(title: str) -> str:
        """Guess CWE from finding title."""
        title_lower = title.lower()
        for keyword, cwe in VULN_CWE_MAP.items():
            if keyword in title_lower:
                return cwe
        return ""

    @staticmethod
    def _estimate_confidence(vuln: Any) -> float:
        """Estimate finding confidence."""
        conf = 0.5

        # Higher confidence for well-known tools
        high_conf_tools = {"sqlmap", "nuclei", "semgrep", "testssl"}
        if vuln.tool in high_conf_tools:
            conf += 0.2

        # Higher if evidence provided
        if vuln.evidence:
            conf += 0.15

        # Higher for specific vuln IDs
        if vuln.vuln_id:
            conf += 0.1

        return min(0.95, conf)

    @staticmethod
    def _generate_followups(finding: InterpretedFinding) -> list[str]:
        """Generate follow-up actions for a finding."""
        actions: list[str] = []

        sev = finding.severity.lower()
        if sev in ("critical", "high"):
            actions.append(f"Validate with alternative tool: {finding.title}")
            actions.append(f"Attempt safe exploitation of {finding.title}")

        cwe = finding.cwe_id
        if cwe == "CWE-89":
            actions.append("Run sqlmap for full exploitation")
            actions.append("Check for WAF bypass needed")
        elif cwe == "CWE-79":
            actions.append("Test for stored XSS variants")
            actions.append("Check CSP bypass possibilities")
        elif cwe == "CWE-918":
            actions.append("Test SSRF to cloud metadata (169.254.169.254)")
            actions.append("Test SSRF to internal services")
        elif cwe == "CWE-78":
            actions.append("Test for blind command injection (time-based)")
            actions.append("Test for out-of-band exfiltration")
        elif cwe == "CWE-502":
            actions.append("Identify serialization format and version")
            actions.append("Generate safe PoC payload")

        return actions

    @staticmethod
    def _correlation_hints(finding: InterpretedFinding) -> list[str]:
        """Generate hints for cross-correlation."""
        hints: list[str] = []

        cwe = finding.cwe_id
        if cwe == "CWE-918":
            hints.append("Check for cloud metadata access")
            hints.append("Check for internal port scan via SSRF")
        elif cwe == "CWE-89":
            hints.append("Check for credential exposure via SQLi")
            hints.append("Check for file read via SQLi")
        elif cwe == "CWE-287":
            hints.append("Check for horizontal privilege escalation")
            hints.append("Check for vertical privilege escalation")

        return hints

    @staticmethod
    def _analyze_gaps(parsed: ParseResult) -> GapAnalysis:
        """Analyze what's covered and what's not."""
        checked: list[str] = []
        unchecked: list[str] = []
        reco: list[str] = []

        tool = parsed.tool.lower()

        all_areas = [
            "port_scan", "service_enum", "web_vulns", "tls_config",
            "directory_scan", "brute_force", "code_audit", "api_test",
            "waf_detection", "subdomain_enum", "dns_checks", "cloud_config",
        ]

        coverage_map = {
            "nmap": ["port_scan", "service_enum"],
            "nuclei": ["web_vulns"],
            "sqlmap": ["web_vulns"],
            "nikto": ["web_vulns", "waf_detection"],
            "gobuster": ["directory_scan"],
            "ffuf": ["directory_scan"],
            "hydra": ["brute_force"],
            "testssl": ["tls_config"],
            "semgrep": ["code_audit"],
            "subfinder": ["subdomain_enum"],
            "wpscan": ["web_vulns"],
        }

        checked = coverage_map.get(tool, [])
        unchecked = [a for a in all_areas if a not in checked]

        gap_tools = {
            "port_scan": "nmap",
            "web_vulns": "nuclei",
            "tls_config": "testssl",
            "directory_scan": "gobuster",
            "brute_force": "hydra",
            "code_audit": "semgrep",
            "subdomain_enum": "subfinder",
        }

        for gap in unchecked:
            if gap in gap_tools:
                reco.append(gap_tools[gap])

        coverage = len(checked) / max(1, len(all_areas))

        return GapAnalysis(
            checked_areas=checked,
            unchecked_areas=unchecked,
            recommended_tools=list(set(reco)),
            coverage_pct=coverage,
        )

    @staticmethod
    def _build_llm_summary(result: InterpretationResult) -> str:
        """Build a summary suitable for LLM context."""
        lines = [f"Tool: {result.tool}\n"]

        if result.findings:
            lines.append(f"Findings ({len(result.findings)}):")
            for f in result.findings[:10]:
                lines.append(
                    f"  [{f.severity.upper()}] {f.title} "
                    f"(conf: {f.confidence:.1f})"
                )

        if result.next_steps:
            lines.append(f"\nRecommended next steps ({len(result.next_steps)}):")
            for step in result.next_steps[:5]:
                lines.append(f"  - {step}")

        gaps = result.gap_analysis
        if gaps.unchecked_areas:
            lines.append(f"\nUnchecked areas: {', '.join(gaps.unchecked_areas[:5])}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        tool_counts: dict[str, int] = defaultdict(int)
        for interp in self._interpretations:
            tool_counts[interp.tool] += 1
        return {
            "interpretations": len(self._interpretations),
            "total_findings": self._finding_counter,
            "by_tool": dict(tool_counts),
        }
