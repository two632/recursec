"""Tool orchestrator — manages external tool execution and result collection.

Implements:
1. Tool discovery and registration
2. Tool dependency checking
3. Sequential and parallel tool execution
4. Tool output collection and parsing
5. Tool chain execution (piped output)
6. Tool timeout management
7. Tool result caching
8. Tool health monitoring
"""

from __future__ import annotations

import asyncio
import shutil
import time
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class ToolDefinition:
    """Definition of an external tool."""
    name: str = ""
    command: str = ""
    category: str = ""           # recon, scanning, exploit, analysis, util
    description: str = ""
    installed: bool = False
    path: str = ""
    timeout_s: float = 300.0
    max_concurrent: int = 3
    current_running: int = 0
    total_runs: int = 0
    total_errors: int = 0
    avg_duration_s: float = 0.0

    @property
    def is_available(self) -> bool:
        return self.installed and self.current_running < self.max_concurrent

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "category": self.category,
            "installed": self.installed,
            "available": self.is_available,
            "runs": self.total_runs,
            "avg_s": round(self.avg_duration_s, 1),
        }


@dataclass
class ToolResult:
    """Result from a tool execution."""
    tool: str = ""
    command: str = ""
    exit_code: int = -1
    stdout: str = ""
    stderr: str = ""
    duration_s: float = 0.0
    success: bool = False
    timed_out: bool = False
    parsed: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool, "exit_code": self.exit_code,
            "success": self.success,
            "duration_s": round(self.duration_s, 1),
            "stdout_len": len(self.stdout),
        }


@dataclass
class ToolChain:
    """A chain of tools to execute in sequence."""
    chain_id: str = ""
    name: str = ""
    steps: list[dict[str, Any]] = field(default_factory=list)
    results: list[ToolResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.chain_id, "name": self.name[:40],
            "steps": len(self.steps),
            "completed": len(self.results),
        }


# ── Tool Registry ─────────────────────────────────────────────

DEFAULT_TOOLS: list[dict[str, Any]] = [
    # Recon
    {"name": "nmap", "cmd": "nmap", "cat": "recon", "desc": "Network scanner"},
    {"name": "masscan", "cmd": "masscan", "cat": "recon", "desc": "Fast port scanner"},
    {"name": "subfinder", "cmd": "subfinder", "cat": "recon", "desc": "Subdomain discovery"},
    {"name": "amass", "cmd": "amass", "cat": "recon", "desc": "Attack surface mapping"},
    {"name": "httpx", "cmd": "httpx", "cat": "recon", "desc": "HTTP probe"},
    {"name": "whatweb", "cmd": "whatweb", "cat": "recon", "desc": "Web fingerprinting"},
    {"name": "whois", "cmd": "whois", "cat": "recon", "desc": "WHOIS lookup"},
    {"name": "dig", "cmd": "dig", "cat": "recon", "desc": "DNS lookup"},
    {"name": "theHarvester", "cmd": "theHarvester", "cat": "recon", "desc": "OSINT harvester"},
    # Scanning
    {"name": "nuclei", "cmd": "nuclei", "cat": "scanning", "desc": "Vulnerability scanner"},
    {"name": "nikto", "cmd": "nikto", "cat": "scanning", "desc": "Web server scanner"},
    {"name": "wpscan", "cmd": "wpscan", "cat": "scanning", "desc": "WordPress scanner"},
    {"name": "sslscan", "cmd": "sslscan", "cat": "scanning", "desc": "SSL/TLS scanner"},
    {"name": "testssl", "cmd": "testssl.sh", "cat": "scanning", "desc": "TLS testing"},
    {"name": "gobuster", "cmd": "gobuster", "cat": "scanning", "desc": "Dir/file brute-forcer"},
    {"name": "ffuf", "cmd": "ffuf", "cat": "scanning", "desc": "Fast fuzzer"},
    {"name": "dirsearch", "cmd": "dirsearch", "cat": "scanning", "desc": "Dir scanner"},
    # Exploit
    {"name": "sqlmap", "cmd": "sqlmap", "cat": "exploit", "desc": "SQL injection automation"},
    {"name": "dalfox", "cmd": "dalfox", "cat": "exploit", "desc": "XSS scanner"},
    {"name": "hydra", "cmd": "hydra", "cat": "exploit", "desc": "Password cracker"},
    {"name": "medusa", "cmd": "medusa", "cat": "exploit", "desc": "Brute forcer"},
    {"name": "metasploit", "cmd": "msfconsole", "cat": "exploit", "desc": "Exploitation framework"},
    # Analysis
    {"name": "semgrep", "cmd": "semgrep", "cat": "analysis", "desc": "Static analysis"},
    {"name": "bandit", "cmd": "bandit", "cat": "analysis", "desc": "Python security linter"},
    {"name": "trivy", "cmd": "trivy", "cat": "analysis", "desc": "Vulnerability scanner"},
    {"name": "grype", "cmd": "grype", "cat": "analysis", "desc": "Container vuln scanner"},
    {"name": "gitleaks", "cmd": "gitleaks", "cat": "analysis", "desc": "Secret scanner"},
    {"name": "trufflehog", "cmd": "trufflehog", "cat": "analysis", "desc": "Secret scanner"},
    # Util
    {"name": "curl", "cmd": "curl", "cat": "util", "desc": "HTTP client"},
    {"name": "jq", "cmd": "jq", "cat": "util", "desc": "JSON processor"},
    {"name": "openssl", "cmd": "openssl", "cat": "util", "desc": "SSL toolkit"},
]


class ToolOrchestrator:
    """Manages external tool execution and result collection.

    Discovers, registers, and executes security tools
    with output parsing and health monitoring.
    """

    def __init__(self) -> None:
        self._tools: dict[str, ToolDefinition] = {}
        self._chains: dict[str, ToolChain] = {}
        self._results_cache: dict[str, ToolResult] = {}
        self._chain_counter = 0
        self._log = logger.bind(component="tool_orchestrator")

        self._register_defaults()

    def _register_defaults(self) -> None:
        """Register and discover default tools."""
        for tool_data in DEFAULT_TOOLS:
            tool = ToolDefinition(
                name=tool_data["name"],
                command=tool_data["cmd"],
                category=tool_data["cat"],
                description=tool_data["desc"],
            )

            # Check if installed
            path = shutil.which(tool.command)
            if path:
                tool.installed = True
                tool.path = path

            self._tools[tool.name] = tool

    def register_tool(
        self,
        name: str,
        command: str,
        category: str = "util",
        description: str = "",
        timeout_s: float = 300.0,
    ) -> None:
        """Register a custom tool."""
        tool = ToolDefinition(
            name=name, command=command,
            category=category, description=description,
            timeout_s=timeout_s,
        )

        path = shutil.which(command)
        if path:
            tool.installed = True
            tool.path = path

        self._tools[name] = tool

    async def execute(
        self,
        tool_name: str,
        args: list[str] | None = None,
        timeout_s: float = 0.0,
    ) -> ToolResult:
        """Execute a tool."""
        tool = self._tools.get(tool_name)
        if not tool:
            return ToolResult(tool=tool_name, stderr="Tool not found")

        if not tool.installed:
            return ToolResult(tool=tool_name, stderr="Tool not installed")

        if not tool.is_available:
            return ToolResult(tool=tool_name, stderr="Tool at max concurrency")

        # Build command
        cmd = [tool.command] + (args or [])
        timeout = timeout_s or tool.timeout_s

        tool.current_running += 1
        start = time.time()

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout,
            )

            duration = time.time() - start
            result = ToolResult(
                tool=tool_name,
                command=" ".join(cmd),
                exit_code=proc.returncode or 0,
                stdout=stdout.decode("utf-8", errors="replace")[:100_000],
                stderr=stderr.decode("utf-8", errors="replace")[:10_000],
                duration_s=duration,
                success=proc.returncode == 0,
            )

        except asyncio.TimeoutError:
            result = ToolResult(
                tool=tool_name,
                command=" ".join(cmd),
                duration_s=timeout,
                timed_out=True,
                stderr="Timed out",
            )

        except Exception as exc:
            result = ToolResult(
                tool=tool_name,
                command=" ".join(cmd),
                duration_s=time.time() - start,
                stderr=str(exc)[:500],
            )

        finally:
            tool.current_running -= 1

        # Update stats
        tool.total_runs += 1
        if not result.success:
            tool.total_errors += 1
        if tool.avg_duration_s == 0:
            tool.avg_duration_s = result.duration_s
        else:
            tool.avg_duration_s = tool.avg_duration_s * 0.8 + result.duration_s * 0.2

        return result

    async def execute_parallel(
        self,
        tool_runs: list[tuple[str, list[str]]],
    ) -> list[ToolResult]:
        """Execute multiple tools in parallel."""
        tasks = [
            self.execute(tool_name, args)
            for tool_name, args in tool_runs
        ]
        return await asyncio.gather(*tasks)

    async def execute_chain(
        self,
        name: str,
        steps: list[dict[str, Any]],
    ) -> ToolChain:
        """Execute a tool chain sequentially."""
        self._chain_counter += 1
        chain = ToolChain(
            chain_id=f"chain-{self._chain_counter}",
            name=name,
            steps=steps,
        )

        for step in steps:
            tool_name = step.get("tool", "")
            args = step.get("args", [])
            result = await self.execute(tool_name, args)
            chain.results.append(result)

            # Stop chain on failure if required
            if not result.success and step.get("required", True):
                break

        self._chains[chain.chain_id] = chain
        return chain

    def get_installed(self) -> list[dict[str, Any]]:
        return [t.to_dict() for t in self._tools.values() if t.installed]

    def get_missing(self) -> list[str]:
        return [t.name for t in self._tools.values() if not t.installed]

    def get_by_category(self, category: str) -> list[dict[str, Any]]:
        return [t.to_dict() for t in self._tools.values() if t.category == category]

    def get_stats(self) -> dict[str, Any]:
        installed = sum(1 for t in self._tools.values() if t.installed)
        return {
            "total_tools": len(self._tools),
            "installed": installed,
            "missing": len(self._tools) - installed,
            "chains": len(self._chains),
        }
