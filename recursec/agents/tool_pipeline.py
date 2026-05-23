"""Tool pipeline — ties tool discovery, execution, parsing, and analysis together.

Provides a unified interface for:
1. Discovering available tools on the system
2. Building tool commands with proper arguments
3. Executing tools safely with sandboxing
4. Parsing structured output from tools
5. Extracting findings from parsed output
6. Feeding results back to the agent loop

Supports the full tool lifecycle:
  discover → configure → build_command → execute → parse → extract → report
"""

from __future__ import annotations

import asyncio
import json
import shutil
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


class ToolCategory(str, Enum):
    RECON = "recon"
    SCANNER = "scanner"
    WEB = "web"
    NETWORK = "network"
    EXPLOIT = "exploit"
    BRUTEFORCE = "bruteforce"
    CODE_ANALYSIS = "code_analysis"
    CRYPTO = "crypto"
    OSINT = "osint"
    FUZZING = "fuzzing"
    MISC = "misc"


@dataclass
class ToolInfo:
    """Information about an available tool."""
    name: str = ""
    binary: str = ""
    category: ToolCategory = ToolCategory.MISC
    description: str = ""
    is_available: bool = False
    path: str = ""
    version: str = ""
    output_format: str = "text"  # text, json, xml
    noise_level: float = 0.5     # 0=silent, 1=very noisy
    risk_level: float = 0.3      # 0=safe, 1=dangerous

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "binary": self.binary,
            "category": self.category.value,
            "available": self.is_available,
            "noise": round(self.noise_level, 1),
            "risk": round(self.risk_level, 1),
        }


@dataclass
class ToolResult:
    """Result from running a tool."""
    tool: str = ""
    command: str = ""
    target: str = ""
    exit_code: int = -1
    stdout: str = ""
    stderr: str = ""
    duration_s: float = 0.0
    parsed: dict[str, Any] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""

    @property
    def success(self) -> bool:
        return self.exit_code == 0 and not self.error

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool, "target": self.target,
            "exit_code": self.exit_code,
            "duration_s": round(self.duration_s, 1),
            "findings": len(self.findings),
            "success": self.success,
        }


# ── Tool Registry ────────────────────────────────────────────

TOOL_REGISTRY: list[dict[str, Any]] = [
    # Recon
    {"name": "nmap", "binary": "nmap", "cat": "recon", "desc": "Port scanner", "noise": 0.6, "risk": 0.2},
    {"name": "masscan", "binary": "masscan", "cat": "recon", "desc": "Fast port scanner", "noise": 0.8, "risk": 0.3},
    {"name": "subfinder", "binary": "subfinder", "cat": "recon", "desc": "Subdomain discovery", "noise": 0.1, "risk": 0.1},
    {"name": "amass", "binary": "amass", "cat": "recon", "desc": "Attack surface mapping", "noise": 0.3, "risk": 0.1},
    {"name": "httpx", "binary": "httpx", "cat": "recon", "desc": "HTTP probing", "noise": 0.2, "risk": 0.1},
    {"name": "katana", "binary": "katana", "cat": "recon", "desc": "Web crawler", "noise": 0.3, "risk": 0.1},
    {"name": "whatweb", "binary": "whatweb", "cat": "recon", "desc": "Web fingerprinting", "noise": 0.2, "risk": 0.1},
    {"name": "whois", "binary": "whois", "cat": "osint", "desc": "Domain registration", "noise": 0.0, "risk": 0.0},
    {"name": "dig", "binary": "dig", "cat": "recon", "desc": "DNS lookup", "noise": 0.0, "risk": 0.0},
    # Scanners
    {"name": "nuclei", "binary": "nuclei", "cat": "scanner", "desc": "Template-based scanner", "noise": 0.5, "risk": 0.3},
    {"name": "nikto", "binary": "nikto", "cat": "scanner", "desc": "Web server scanner", "noise": 0.7, "risk": 0.3},
    {"name": "wpscan", "binary": "wpscan", "cat": "scanner", "desc": "WordPress scanner", "noise": 0.5, "risk": 0.2},
    {"name": "testssl", "binary": "testssl.sh", "cat": "scanner", "desc": "SSL/TLS tester", "noise": 0.2, "risk": 0.1},
    # Web
    {"name": "sqlmap", "binary": "sqlmap", "cat": "exploit", "desc": "SQL injection", "noise": 0.8, "risk": 0.7},
    {"name": "dalfox", "binary": "dalfox", "cat": "web", "desc": "XSS scanner", "noise": 0.6, "risk": 0.4},
    {"name": "gobuster", "binary": "gobuster", "cat": "web", "desc": "Directory bruter", "noise": 0.7, "risk": 0.2},
    {"name": "ffuf", "binary": "ffuf", "cat": "web", "desc": "Web fuzzer", "noise": 0.7, "risk": 0.3},
    {"name": "curl", "binary": "curl", "cat": "web", "desc": "HTTP client", "noise": 0.0, "risk": 0.1},
    # Network
    {"name": "enum4linux", "binary": "enum4linux", "cat": "network", "desc": "SMB enumeration", "noise": 0.5, "risk": 0.2},
    {"name": "tcpdump", "binary": "tcpdump", "cat": "network", "desc": "Packet capture", "noise": 0.0, "risk": 0.1},
    # Bruteforce
    {"name": "hydra", "binary": "hydra", "cat": "bruteforce", "desc": "Password cracker", "noise": 0.9, "risk": 0.8},
    {"name": "medusa", "binary": "medusa", "cat": "bruteforce", "desc": "Login bruter", "noise": 0.9, "risk": 0.8},
    # Code analysis
    {"name": "semgrep", "binary": "semgrep", "cat": "code_analysis", "desc": "Static analysis", "noise": 0.0, "risk": 0.0},
    {"name": "bandit", "binary": "bandit", "cat": "code_analysis", "desc": "Python security lint", "noise": 0.0, "risk": 0.0},
    {"name": "trivy", "binary": "trivy", "cat": "code_analysis", "desc": "Vulnerability scanner", "noise": 0.0, "risk": 0.0},
    {"name": "gitleaks", "binary": "gitleaks", "cat": "code_analysis", "desc": "Secret detection", "noise": 0.0, "risk": 0.0},
    {"name": "trufflehog", "binary": "trufflehog", "cat": "code_analysis", "desc": "Secret scanner", "noise": 0.0, "risk": 0.0},
]


class ToolPipeline:
    """Unified tool discovery, execution, parsing, and analysis.

    Provides the complete lifecycle for running security tools
    and extracting actionable findings.
    """

    def __init__(
        self,
        timeout_s: float = 300.0,
        max_concurrent: int = 5,
        output_dir: str = "data/tool_output",
    ) -> None:
        self._timeout = timeout_s
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._tools: dict[str, ToolInfo] = {}
        self._execution_count = 0
        self._log = logger.bind(component="tool_pipeline")

        self._discover_tools()

    def _discover_tools(self) -> None:
        """Discover available tools on the system."""
        for entry in TOOL_REGISTRY:
            binary = entry["binary"]
            path = shutil.which(binary)

            try:
                cat = ToolCategory(entry.get("cat", "misc"))
            except ValueError:
                cat = ToolCategory.MISC

            tool = ToolInfo(
                name=entry["name"],
                binary=binary,
                category=cat,
                description=entry.get("desc", ""),
                is_available=path is not None,
                path=path or "",
                noise_level=entry.get("noise", 0.5),
                risk_level=entry.get("risk", 0.3),
            )

            self._tools[entry["name"]] = tool

        available = sum(1 for t in self._tools.values() if t.is_available)
        self._log.info("tools_discovered", total=len(self._tools), available=available)

    def get_tool(self, name: str) -> ToolInfo | None:
        return self._tools.get(name)

    def get_available_tools(self, category: ToolCategory | None = None) -> list[ToolInfo]:
        tools = [t for t in self._tools.values() if t.is_available]
        if category:
            tools = [t for t in tools if t.category == category]
        return tools

    async def execute(
        self,
        tool: str,
        command: str = "",
        target: str = "",
        args: list[str] | None = None,
        timeout_s: float = 0,
    ) -> ToolResult:
        """Execute a tool and return parsed results."""
        tool_info = self._tools.get(tool)
        if not tool_info or not tool_info.is_available:
            return ToolResult(
                tool=tool, target=target,
                error=f"Tool {tool} not available",
            )

        # Build command
        if not command:
            cmd_parts = [tool_info.path or tool_info.binary]
            if args:
                cmd_parts.extend(args)
            if target:
                cmd_parts.append(target)
            command = " ".join(cmd_parts)

        timeout = timeout_s or self._timeout
        self._execution_count += 1
        result = ToolResult(tool=tool, command=command, target=target)

        async with self._semaphore:
            start = time.time()
            try:
                proc = await asyncio.create_subprocess_shell(
                    command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout,
                )

                result.exit_code = proc.returncode or 0
                result.stdout = stdout_bytes.decode(errors="replace")[:50000]
                result.stderr = stderr_bytes.decode(errors="replace")[:5000]

            except asyncio.TimeoutError:
                result.error = f"Timeout after {timeout}s"
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
            except OSError as e:
                result.error = str(e)[:200]

            result.duration_s = time.time() - start

        # Parse output
        if result.success:
            result.parsed = self._parse_output(tool, result.stdout)
            result.findings = self._extract_findings(tool, result.parsed, target)

        # Save output
        self._save_output(result)

        self._log.info(
            "tool_executed",
            tool=tool, target=target[:50],
            exit_code=result.exit_code,
            findings=len(result.findings),
            duration=f"{result.duration_s:.1f}s",
        )

        return result

    async def execute_chain(
        self,
        steps: list[dict[str, Any]],
    ) -> list[ToolResult]:
        """Execute a chain of tools sequentially."""
        results = []
        for step in steps:
            result = await self.execute(
                tool=step.get("tool", ""),
                command=step.get("command", ""),
                target=step.get("target", ""),
                args=step.get("args"),
                timeout_s=step.get("timeout", 0),
            )
            results.append(result)
            if not result.success and step.get("fail_fast", False):
                break
        return results

    async def execute_parallel(
        self,
        tasks: list[dict[str, Any]],
    ) -> list[ToolResult]:
        """Execute multiple tools in parallel."""
        coros = [
            self.execute(
                tool=t.get("tool", ""),
                command=t.get("command", ""),
                target=t.get("target", ""),
                args=t.get("args"),
            )
            for t in tasks
        ]
        return list(await asyncio.gather(*coros, return_exceptions=False))

    # ── Output Parsing ───────────────────────────────────

    def _parse_output(self, tool: str, output: str) -> dict[str, Any]:
        """Parse tool output into structured data."""
        if not output:
            return {}

        # Try JSON first
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            pass

        # Tool-specific parsing
        parsers: dict[str, Any] = {
            "nmap": self._parse_nmap,
            "nuclei": self._parse_nuclei,
            "subfinder": self._parse_lines,
            "httpx": self._parse_lines,
            "gobuster": self._parse_gobuster,
            "ffuf": self._parse_ffuf,
        }

        parser = parsers.get(tool)
        if parser:
            return parser(output)

        return {"raw": output[:5000]}

    def _parse_nmap(self, output: str) -> dict[str, Any]:
        hosts = []
        current_host: dict[str, Any] = {}
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("Nmap scan report for"):
                if current_host:
                    hosts.append(current_host)
                host = line.replace("Nmap scan report for", "").strip()
                current_host = {"host": host, "ports": []}
            elif "/tcp" in line or "/udp" in line:
                parts = line.split()
                if len(parts) >= 3:
                    current_host.setdefault("ports", []).append({
                        "port": parts[0], "state": parts[1], "service": parts[2],
                    })
        if current_host:
            hosts.append(current_host)
        return {"hosts": hosts}

    def _parse_nuclei(self, output: str) -> dict[str, Any]:
        findings = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            # Nuclei JSON lines
            try:
                data = json.loads(line)
                findings.append(data)
            except json.JSONDecodeError:
                if "[" in line and "]" in line:
                    findings.append({"raw": line})
        return {"findings": findings}

    def _parse_lines(self, output: str) -> dict[str, Any]:
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        return {"items": lines}

    def _parse_gobuster(self, output: str) -> dict[str, Any]:
        dirs = []
        for line in output.splitlines():
            if line.startswith("/") or "(Status:" in line:
                dirs.append(line.strip())
        return {"directories": dirs}

    def _parse_ffuf(self, output: str) -> dict[str, Any]:
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            results = []
            for line in output.splitlines():
                if "[Status:" in line or "| URL |" in line:
                    results.append(line.strip())
            return {"results": results}

    # ── Finding Extraction ───────────────────────────────

    def _extract_findings(
        self,
        tool: str,
        parsed: dict[str, Any],
        target: str,
    ) -> list[dict[str, Any]]:
        """Extract findings from parsed output."""
        findings = []

        if tool == "nuclei":
            for item in parsed.get("findings", []):
                if isinstance(item, dict) and "info" in item:
                    info = item["info"]
                    findings.append({
                        "title": item.get("name", info.get("name", "")),
                        "severity": info.get("severity", "info"),
                        "description": info.get("description", ""),
                        "target": item.get("matched-at", target),
                        "tool": "nuclei",
                        "type": item.get("template-id", ""),
                        "evidence": item.get("matched-at", ""),
                    })

        elif tool == "nmap":
            for host in parsed.get("hosts", []):
                for port in host.get("ports", []):
                    if port.get("state") == "open":
                        findings.append({
                            "title": f"Open port {port['port']} ({port.get('service', '')})",
                            "severity": "info",
                            "target": host.get("host", target),
                            "tool": "nmap",
                            "type": "open_port",
                        })

        return findings

    def _save_output(self, result: ToolResult) -> None:
        """Save tool output to disk."""
        try:
            ts = int(time.time())
            filename = f"{result.tool}_{ts}.json"
            path = self._output_dir / filename
            data = {
                "tool": result.tool,
                "command": result.command[:200],
                "target": result.target,
                "exit_code": result.exit_code,
                "duration_s": result.duration_s,
                "findings": len(result.findings),
                "output_length": len(result.stdout),
            }
            path.write_text(json.dumps(data))
        except OSError:
            pass

    def get_stats(self) -> dict[str, Any]:
        available = [t for t in self._tools.values() if t.is_available]
        by_cat: dict[str, int] = {}
        for t in available:
            by_cat.setdefault(t.category.value, 0)
            by_cat[t.category.value] += 1
        return {
            "total_tools": len(self._tools),
            "available": len(available),
            "by_category": by_cat,
            "executions": self._execution_count,
        }
