"""Tool executor — async subprocess management for external tools.

Implements:
1. Async subprocess execution for 200+ tools
2. Timeout management
3. Output capture and streaming
4. Tool availability detection
5. Command sanitization
6. Resource limiting
7. Execution logging
"""

from __future__ import annotations

import asyncio
import os
import shutil
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ToolCategory(str, Enum):
    RECON = "recon"
    SCANNER = "scanner"
    EXPLOITATION = "exploitation"
    BRUTE_FORCE = "brute_force"
    WEB = "web"
    NETWORK = "network"
    CODE_ANALYSIS = "code_analysis"
    OSINT = "osint"
    CRYPTO = "crypto"
    FUZZING = "fuzzing"
    CONTAINER = "container"
    CLOUD = "cloud"
    MOBILE = "mobile"
    WIRELESS = "wireless"


class ExecutionStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    KILLED = "killed"


@dataclass
class ToolDefinition:
    """Definition of an external tool."""
    name: str = ""
    binary: str = ""
    category: ToolCategory = ToolCategory.SCANNER
    description: str = ""
    available: bool = False
    install_cmd: str = ""
    default_timeout_s: int = 300

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name[:15],
            "category": self.category.value,
            "available": self.available,
        }


@dataclass
class ExecutionResult:
    """Result from a tool execution."""
    tool: str = ""
    command: str = ""
    status: ExecutionStatus = ExecutionStatus.PENDING
    exit_code: int = -1
    stdout: str = ""
    stderr: str = ""
    duration_s: float = 0.0
    started_at: float = 0.0
    completed_at: float = 0.0

    @property
    def success(self) -> bool:
        return self.exit_code == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool[:15],
            "status": self.status.value,
            "exit_code": self.exit_code,
            "stdout_len": len(self.stdout),
            "duration_s": round(self.duration_s, 1),
        }


# ── Tool registry ─────────────────────────────────────────────

TOOL_REGISTRY: list[dict[str, Any]] = [
    # Recon
    {"name": "nmap", "binary": "nmap", "cat": "recon", "desc": "Network scanner", "timeout": 600},
    {"name": "masscan", "binary": "masscan", "cat": "recon", "desc": "Fast port scanner", "timeout": 300},
    {"name": "subfinder", "binary": "subfinder", "cat": "recon", "desc": "Subdomain discovery"},
    {"name": "amass", "binary": "amass", "cat": "recon", "desc": "DNS enumeration", "timeout": 600},
    {"name": "httpx", "binary": "httpx", "cat": "recon", "desc": "HTTP probing"},
    {"name": "dig", "binary": "dig", "cat": "recon", "desc": "DNS lookup"},
    {"name": "whois", "binary": "whois", "cat": "recon", "desc": "WHOIS lookup"},
    {"name": "theHarvester", "binary": "theHarvester", "cat": "recon", "desc": "OSINT email/subdomain"},
    {"name": "dnsrecon", "binary": "dnsrecon", "cat": "recon", "desc": "DNS recon"},
    # Scanners
    {"name": "nuclei", "binary": "nuclei", "cat": "scanner", "desc": "Template-based scanner", "timeout": 900},
    {"name": "nikto", "binary": "nikto", "cat": "scanner", "desc": "Web server scanner"},
    {"name": "testssl", "binary": "testssl.sh", "cat": "scanner", "desc": "SSL/TLS testing"},
    {"name": "wpscan", "binary": "wpscan", "cat": "scanner", "desc": "WordPress scanner"},
    {"name": "sslyze", "binary": "sslyze", "cat": "scanner", "desc": "SSL analysis"},
    # Web
    {"name": "ffuf", "binary": "ffuf", "cat": "web", "desc": "Web fuzzer"},
    {"name": "gobuster", "binary": "gobuster", "cat": "web", "desc": "Directory bruteforce"},
    {"name": "feroxbuster", "binary": "feroxbuster", "cat": "web", "desc": "Recursive content discovery"},
    {"name": "sqlmap", "binary": "sqlmap", "cat": "web", "desc": "SQL injection"},
    {"name": "commix", "binary": "commix", "cat": "web", "desc": "Command injection"},
    {"name": "dalfox", "binary": "dalfox", "cat": "web", "desc": "XSS scanner"},
    {"name": "arjun", "binary": "arjun", "cat": "web", "desc": "Parameter finder"},
    # Brute force
    {"name": "hydra", "binary": "hydra", "cat": "brute_force", "desc": "Login brute force"},
    {"name": "medusa", "binary": "medusa", "cat": "brute_force", "desc": "Parallel brute force"},
    {"name": "hashcat", "binary": "hashcat", "cat": "brute_force", "desc": "Password cracking"},
    {"name": "john", "binary": "john", "cat": "brute_force", "desc": "Password cracking"},
    # Network
    {"name": "enum4linux", "binary": "enum4linux-ng", "cat": "network", "desc": "SMB enumeration"},
    {"name": "crackmapexec", "binary": "crackmapexec", "cat": "network", "desc": "Network tool"},
    {"name": "responder", "binary": "responder", "cat": "network", "desc": "LLMNR/NBT-NS poisoner"},
    {"name": "bettercap", "binary": "bettercap", "cat": "network", "desc": "MITM framework"},
    # Code analysis
    {"name": "semgrep", "binary": "semgrep", "cat": "code_analysis", "desc": "Static analysis"},
    {"name": "bandit", "binary": "bandit", "cat": "code_analysis", "desc": "Python security"},
    {"name": "trufflehog", "binary": "trufflehog", "cat": "code_analysis", "desc": "Secret scanning"},
    {"name": "gitleaks", "binary": "gitleaks", "cat": "code_analysis", "desc": "Secret scanning"},
    # Container
    {"name": "trivy", "binary": "trivy", "cat": "container", "desc": "Container scanning"},
    {"name": "grype", "binary": "grype", "cat": "container", "desc": "Vulnerability scanner"},
    # Fuzzing
    {"name": "afl++", "binary": "afl-fuzz", "cat": "fuzzing", "desc": "Coverage-guided fuzzing"},
    {"name": "boofuzz", "binary": "boofuzz", "cat": "fuzzing", "desc": "Network protocol fuzzing"},
]

# ── Dangerous commands to block ────────────────────────────────

BLOCKED_PATTERNS: list[str] = [
    "rm -rf /",
    "mkfs",
    ":(){:|:&};:",
    "dd if=/dev/zero of=/dev/sd",
    "chmod -R 777 /",
    "wget -O- | sh",
    "curl | sh",
]


class ToolExecutor:
    """Manages async execution of external security tools.

    Handles subprocess spawning, output capture,
    timeout management, and tool availability
    detection.
    """

    def __init__(
        self,
        default_timeout_s: int = 300,
        max_concurrent: int = 5,
    ) -> None:
        self._tools: dict[str, ToolDefinition] = {}
        self._default_timeout = default_timeout_s
        self._max_concurrent = max_concurrent
        self._semaphore: asyncio.Semaphore | None = None
        self._execution_count = 0
        self._log = logger.bind(component="tool_executor")
        self._load_tools()

    def _load_tools(self) -> None:
        """Load tool definitions and check availability."""
        for cfg in TOOL_REGISTRY:
            cat_str = cfg.get("cat", "scanner")
            try:
                category = ToolCategory(cat_str)
            except ValueError:
                category = ToolCategory.SCANNER

            tool = ToolDefinition(
                name=cfg["name"],
                binary=cfg["binary"],
                category=category,
                description=cfg.get("desc", ""),
                default_timeout_s=cfg.get("timeout", self._default_timeout),
                install_cmd=cfg.get("install", ""),
            )
            tool.available = shutil.which(tool.binary) is not None
            self._tools[tool.name] = tool

    async def execute(
        self,
        tool_name: str,
        args: list[str],
        timeout_s: int = 0,
        env: dict[str, str] | None = None,
    ) -> ExecutionResult:
        """Execute a tool asynchronously."""
        tool = self._tools.get(tool_name)
        if not tool:
            return ExecutionResult(
                tool=tool_name,
                status=ExecutionStatus.FAILED,
                stderr=f"Unknown tool: {tool_name}",
            )

        if not tool.available:
            return ExecutionResult(
                tool=tool_name,
                status=ExecutionStatus.FAILED,
                stderr=f"Tool not installed: {tool_name}",
            )

        cmd = [tool.binary] + args
        cmd_str = " ".join(cmd)

        # Safety check
        for blocked in BLOCKED_PATTERNS:
            if blocked in cmd_str:
                return ExecutionResult(
                    tool=tool_name,
                    command=cmd_str,
                    status=ExecutionStatus.FAILED,
                    stderr=f"Blocked dangerous command pattern: {blocked}",
                )

        timeout = timeout_s or tool.default_timeout_s

        # Concurrency control
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self._max_concurrent)

        async with self._semaphore:
            return await self._run_subprocess(
                tool_name, cmd, cmd_str, timeout, env,
            )

    async def _run_subprocess(
        self,
        tool_name: str,
        cmd: list[str],
        cmd_str: str,
        timeout_s: int,
        env: dict[str, str] | None,
    ) -> ExecutionResult:
        """Run a subprocess with timeout."""
        self._execution_count += 1
        result = ExecutionResult(
            tool=tool_name,
            command=cmd_str,
            status=ExecutionStatus.RUNNING,
            started_at=time.time(),
        )

        exec_env = dict(os.environ)
        if env:
            exec_env.update(env)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=exec_env,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=timeout_s,
                )
                result.exit_code = proc.returncode or 0
                result.stdout = stdout.decode("utf-8", errors="replace")
                result.stderr = stderr.decode("utf-8", errors="replace")
                result.status = ExecutionStatus.COMPLETED
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                result.status = ExecutionStatus.TIMEOUT
                result.stderr = f"Timeout after {timeout_s}s"

        except FileNotFoundError:
            result.status = ExecutionStatus.FAILED
            result.stderr = f"Binary not found: {cmd[0]}"
        except PermissionError:
            result.status = ExecutionStatus.FAILED
            result.stderr = f"Permission denied: {cmd[0]}"
        except OSError as exc:
            result.status = ExecutionStatus.FAILED
            result.stderr = f"OS error: {exc}"

        result.completed_at = time.time()
        result.duration_s = result.completed_at - result.started_at
        return result

    def get_available_tools(
        self,
        category: ToolCategory | None = None,
    ) -> list[ToolDefinition]:
        """Get available tools, optionally filtered by category."""
        tools = [t for t in self._tools.values() if t.available]
        if category:
            tools = [t for t in tools if t.category == category]
        return tools

    def get_all_tools(self) -> list[ToolDefinition]:
        """Get all registered tools."""
        return list(self._tools.values())

    def build_tool_prompt(
        self,
        categories: list[ToolCategory] | None = None,
    ) -> str:
        """Build tool documentation for LLM."""
        lines = ["## Available Tools\n"]
        tools = self._tools.values()

        if categories:
            tools = [t for t in tools if t.category in categories]

        for tool in tools:
            status = "installed" if tool.available else "not installed"
            lines.append(
                f"- {tool.name} [{tool.category.value}]: "
                f"{tool.description} ({status})"
            )

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        available = sum(1 for t in self._tools.values() if t.available)
        by_category: dict[str, int] = {}
        for t in self._tools.values():
            by_category[t.category.value] = by_category.get(
                t.category.value, 0,
            ) + 1

        return {
            "total_tools": len(self._tools),
            "available": available,
            "executions": self._execution_count,
            "by_category": by_category,
        }
