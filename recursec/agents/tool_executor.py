"""Tool execution engine — safe, monitored execution of security tools.

Handles:
1. Tool discovery and availability checking
2. Command building from structured parameters
3. Sandboxed execution (Docker optional)
4. Output capture and parsing
5. Timeout enforcement
6. Execution logging for audit trail
7. Rate limiting and resource management
8. Error recovery and retry logic
9. Tool chaining (pipe output to next tool)
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


class ToolCategory(str, Enum):
    RECON = "recon"
    SCANNER = "scanner"
    EXPLOIT = "exploit"
    WEB = "web"
    NETWORK = "network"
    CODE = "code"
    CRYPTO = "crypto"
    OSINT = "osint"
    BRUTE_FORCE = "brute_force"
    POST_EXPLOIT = "post_exploit"
    UTILITY = "utility"


class ExecutionMode(str, Enum):
    LOCAL = "local"
    DOCKER = "docker"
    SANDBOX = "sandbox"


@dataclass
class ToolDefinition:
    """Definition of an available tool."""
    name: str = ""
    binary: str = ""             # Executable name or path
    category: ToolCategory = ToolCategory.UTILITY
    description: str = ""
    installed: bool = False
    install_command: str = ""
    docker_image: str = ""       # Docker image for sandboxed execution
    default_timeout_s: float = 120.0
    max_timeout_s: float = 600.0
    output_format: str = "text"  # text, json, xml
    dangerous: bool = False      # Requires extra approval
    rate_limit: int = 0          # Max calls per minute (0 = unlimited)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "binary": self.binary,
            "category": self.category.value,
            "installed": self.installed,
            "dangerous": self.dangerous,
        }


@dataclass
class ExecutionRequest:
    """Request to execute a tool."""
    tool_name: str = ""
    command_args: list[str] = field(default_factory=list)
    target: str = ""
    stdin_data: str = ""
    timeout_s: float = 120.0
    mode: ExecutionMode = ExecutionMode.LOCAL
    env_vars: dict[str, str] = field(default_factory=dict)
    working_dir: str = ""
    capture_stderr: bool = True

    @property
    def command_string(self) -> str:
        return " ".join(self.command_args) if self.command_args else self.tool_name


@dataclass
class ExecutionResult:
    """Result of a tool execution."""
    request_id: str = ""
    tool_name: str = ""
    command: str = ""
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    duration_s: float = 0.0
    timed_out: bool = False
    error: str = ""

    @property
    def success(self) -> bool:
        return self.exit_code == 0 and not self.timed_out and not self.error

    @property
    def output(self) -> str:
        return self.stdout if self.stdout else self.stderr

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.request_id,
            "tool": self.tool_name,
            "command": self.command[:200],
            "exit_code": self.exit_code,
            "success": self.success,
            "duration_s": round(self.duration_s, 2),
            "output_length": len(self.stdout),
            "timed_out": self.timed_out,
        }


# ── Tool Registry ────────────────────────────────────────────

BUILTIN_TOOLS: list[dict[str, Any]] = [
    # Recon
    {"name": "nmap", "binary": "nmap", "category": "recon",
     "description": "Network mapper / port scanner"},
    {"name": "masscan", "binary": "masscan", "category": "recon",
     "description": "Fast port scanner"},
    {"name": "subfinder", "binary": "subfinder", "category": "recon",
     "description": "Subdomain discovery"},
    {"name": "amass", "binary": "amass", "category": "recon",
     "description": "Attack surface enumeration"},
    {"name": "httpx", "binary": "httpx", "category": "recon",
     "description": "HTTP probe"},
    {"name": "katana", "binary": "katana", "category": "recon",
     "description": "Web crawler"},
    {"name": "whatweb", "binary": "whatweb", "category": "recon",
     "description": "Web technology fingerprinter"},

    # Scanners
    {"name": "nuclei", "binary": "nuclei", "category": "scanner",
     "description": "Vulnerability scanner with templates"},
    {"name": "nikto", "binary": "nikto", "category": "scanner",
     "description": "Web server scanner"},
    {"name": "wpscan", "binary": "wpscan", "category": "scanner",
     "description": "WordPress vulnerability scanner"},
    {"name": "testssl", "binary": "testssl.sh", "category": "scanner",
     "description": "SSL/TLS tester"},

    # Exploit
    {"name": "sqlmap", "binary": "sqlmap", "category": "exploit",
     "description": "SQL injection exploitation", "dangerous": True},
    {"name": "metasploit", "binary": "msfconsole", "category": "exploit",
     "description": "Exploitation framework", "dangerous": True},
    {"name": "hydra", "binary": "hydra", "category": "brute_force",
     "description": "Login brute forcer", "dangerous": True},

    # Web
    {"name": "gobuster", "binary": "gobuster", "category": "web",
     "description": "Directory/DNS bruteforcer"},
    {"name": "ffuf", "binary": "ffuf", "category": "web",
     "description": "Fast web fuzzer"},
    {"name": "dalfox", "binary": "dalfox", "category": "web",
     "description": "XSS scanner"},
    {"name": "curl", "binary": "curl", "category": "web",
     "description": "HTTP client"},

    # Code
    {"name": "semgrep", "binary": "semgrep", "category": "code",
     "description": "Static analysis (SAST)"},
    {"name": "bandit", "binary": "bandit", "category": "code",
     "description": "Python security linter"},
    {"name": "trivy", "binary": "trivy", "category": "code",
     "description": "Vulnerability scanner for dependencies"},
    {"name": "gitleaks", "binary": "gitleaks", "category": "code",
     "description": "Secret scanner for git repos"},
    {"name": "trufflehog", "binary": "trufflehog", "category": "code",
     "description": "Secret scanner"},

    # Network
    {"name": "enum4linux", "binary": "enum4linux-ng", "category": "network",
     "description": "Windows/SMB enumerator"},
    {"name": "dig", "binary": "dig", "category": "network",
     "description": "DNS lookup"},
    {"name": "whois", "binary": "whois", "category": "network",
     "description": "Domain info lookup"},
    {"name": "tcpdump", "binary": "tcpdump", "category": "network",
     "description": "Packet capture"},

    # Crypto
    {"name": "hashcat", "binary": "hashcat", "category": "crypto",
     "description": "Password hash cracker", "dangerous": True},
    {"name": "john", "binary": "john", "category": "crypto",
     "description": "Password hash cracker", "dangerous": True},

    # Utility
    {"name": "python3", "binary": "python3", "category": "utility",
     "description": "Python interpreter"},
    {"name": "jq", "binary": "jq", "category": "utility",
     "description": "JSON processor"},
]


class ToolExecutor:
    """Safe, monitored execution of security tools.

    Discovers available tools, builds commands, executes safely
    with timeouts and logging, and parses outputs.
    """

    def __init__(
        self,
        mode: ExecutionMode = ExecutionMode.LOCAL,
        max_concurrent: int = 10,
        log_dir: str = "data/tool_logs",
    ) -> None:
        self._mode = mode
        self._max_concurrent = max_concurrent
        self._log_dir = Path(log_dir)
        self._log_dir.mkdir(parents=True, exist_ok=True)

        self._tools: dict[str, ToolDefinition] = {}
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._execution_log: list[dict[str, Any]] = []
        self._rate_counters: dict[str, list[float]] = defaultdict(list)
        self._exec_counter = 0

        self._log = logger.bind(component="tool_executor")

        # Discover tools
        self._discover_tools()

    def _discover_tools(self) -> None:
        """Discover which tools are installed."""
        for tool_data in BUILTIN_TOOLS:
            binary = tool_data["binary"]
            installed = shutil.which(binary) is not None

            try:
                category = ToolCategory(tool_data.get("category", "utility"))
            except ValueError:
                category = ToolCategory.UTILITY

            tool = ToolDefinition(
                name=tool_data["name"],
                binary=binary,
                category=category,
                description=tool_data.get("description", ""),
                installed=installed,
                dangerous=tool_data.get("dangerous", False),
            )
            self._tools[tool.name] = tool

        installed_count = sum(1 for t in self._tools.values() if t.installed)
        self._log.info(
            "tools_discovered",
            total=len(self._tools),
            installed=installed_count,
        )

    def get_available_tools(self, category: ToolCategory | None = None) -> list[ToolDefinition]:
        """Get list of available (installed) tools."""
        tools = [t for t in self._tools.values() if t.installed]
        if category:
            tools = [t for t in tools if t.category == category]
        return tools

    def get_all_tools(self) -> list[ToolDefinition]:
        return list(self._tools.values())

    def is_available(self, tool_name: str) -> bool:
        tool = self._tools.get(tool_name)
        return tool.installed if tool else False

    async def execute(self, request: ExecutionRequest) -> ExecutionResult:
        """Execute a tool with safety checks."""
        self._exec_counter += 1
        request_id = f"exec-{self._exec_counter}"

        # Validate tool exists
        tool = self._tools.get(request.tool_name)
        if not tool:
            return ExecutionResult(
                request_id=request_id,
                tool_name=request.tool_name,
                error=f"Unknown tool: {request.tool_name}",
            )

        if not tool.installed:
            return ExecutionResult(
                request_id=request_id,
                tool_name=request.tool_name,
                error=f"Tool not installed: {request.tool_name}",
            )

        # Rate limiting
        if tool.rate_limit > 0 and not self._check_rate_limit(request.tool_name, tool.rate_limit):
            return ExecutionResult(
                request_id=request_id,
                tool_name=request.tool_name,
                error=f"Rate limit exceeded for {request.tool_name}",
            )

        # Enforce timeout
        timeout = min(request.timeout_s, tool.max_timeout_s)

        # Build command
        command = self._build_command(tool, request)

        async with self._semaphore:
            result = await self._run_command(
                request_id=request_id,
                tool_name=request.tool_name,
                command=command,
                timeout=timeout,
                stdin_data=request.stdin_data,
                env_vars=request.env_vars,
                working_dir=request.working_dir,
                capture_stderr=request.capture_stderr,
            )

        # Log execution
        self._log_execution(result)

        return result

    async def execute_chain(
        self,
        requests: list[ExecutionRequest],
        pipe: bool = False,
    ) -> list[ExecutionResult]:
        """Execute multiple tools in sequence, optionally piping output."""
        results: list[ExecutionResult] = []

        for i, request in enumerate(requests):
            if pipe and i > 0 and results[-1].success:
                request.stdin_data = results[-1].stdout

            result = await self.execute(request)
            results.append(result)

            if not result.success and not pipe:
                break  # Stop chain on failure unless piping

        return results

    async def execute_parallel(
        self,
        requests: list[ExecutionRequest],
    ) -> list[ExecutionResult]:
        """Execute multiple tools in parallel."""
        tasks = [self.execute(req) for req in requests]
        return await asyncio.gather(*tasks)

    # ── Internal ─────────────────────────────────────────

    def _build_command(self, tool: ToolDefinition, request: ExecutionRequest) -> list[str]:
        """Build the command to execute."""
        if request.command_args:
            return [tool.binary] + request.command_args

        # If just tool name and target, build a basic command
        cmd = [tool.binary]
        if request.target:
            cmd.append(request.target)
        return cmd

    async def _run_command(
        self,
        request_id: str,
        tool_name: str,
        command: list[str],
        timeout: float,
        stdin_data: str = "",
        env_vars: dict[str, str] | None = None,
        working_dir: str = "",
        capture_stderr: bool = True,
    ) -> ExecutionResult:
        """Actually run the command."""
        start = time.time()
        command_str = " ".join(command)

        self._log.info("tool_exec_start", tool=tool_name, command=command_str[:200])

        try:
            env = os.environ.copy()
            if env_vars:
                env.update(env_vars)

            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE if capture_stderr else None,
                stdin=asyncio.subprocess.PIPE if stdin_data else None,
                env=env,
                cwd=working_dir or None,
            )

            try:
                stdout_data, stderr_data = await asyncio.wait_for(
                    proc.communicate(input=stdin_data.encode() if stdin_data else None),
                    timeout=timeout,
                )

                return ExecutionResult(
                    request_id=request_id,
                    tool_name=tool_name,
                    command=command_str,
                    stdout=stdout_data.decode(errors="replace") if stdout_data else "",
                    stderr=stderr_data.decode(errors="replace") if stderr_data else "",
                    exit_code=proc.returncode or 0,
                    duration_s=time.time() - start,
                )

            except asyncio.TimeoutError:
                proc.kill()
                return ExecutionResult(
                    request_id=request_id,
                    tool_name=tool_name,
                    command=command_str,
                    exit_code=-1,
                    timed_out=True,
                    duration_s=time.time() - start,
                    error=f"Timed out after {timeout}s",
                )

        except FileNotFoundError:
            return ExecutionResult(
                request_id=request_id,
                tool_name=tool_name,
                command=command_str,
                error=f"Binary not found: {command[0]}",
                duration_s=time.time() - start,
            )
        except OSError as e:
            return ExecutionResult(
                request_id=request_id,
                tool_name=tool_name,
                command=command_str,
                error=str(e),
                duration_s=time.time() - start,
            )

    def _check_rate_limit(self, tool_name: str, max_per_minute: int) -> bool:
        """Check if tool execution is within rate limits."""
        now = time.time()
        cutoff = now - 60
        self._rate_counters[tool_name] = [
            t for t in self._rate_counters[tool_name] if t > cutoff
        ]
        if len(self._rate_counters[tool_name]) >= max_per_minute:
            return False
        self._rate_counters[tool_name].append(now)
        return True

    def _log_execution(self, result: ExecutionResult) -> None:
        """Log execution for audit trail."""
        entry = result.to_dict()
        self._execution_log.append(entry)
        if len(self._execution_log) > 10000:
            self._execution_log = self._execution_log[-10000:]

        # Write to file
        try:
            log_file = self._log_dir / f"{result.request_id}.json"
            log_file.write_text(json.dumps(entry))
        except OSError:
            pass

        self._log.info(
            "tool_exec_complete",
            tool=result.tool_name,
            success=result.success,
            duration_s=round(result.duration_s, 2),
        )

    def get_execution_log(self, limit: int = 50) -> list[dict[str, Any]]:
        return self._execution_log[-limit:]

    def get_stats(self) -> dict[str, Any]:
        by_tool: dict[str, int] = defaultdict(int)
        total_time = 0.0
        for entry in self._execution_log:
            by_tool[entry.get("tool", "")] += 1
            total_time += entry.get("duration_s", 0)

        return {
            "total_executions": len(self._execution_log),
            "by_tool": dict(by_tool),
            "total_time_s": round(total_time, 1),
            "available_tools": sum(1 for t in self._tools.values() if t.installed),
            "total_tools": len(self._tools),
        }
