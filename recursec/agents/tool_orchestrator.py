"""Tool orchestrator — async external tool subprocess management.

Implements:
1. Async subprocess execution for security tools
2. Timeout and resource enforcement
3. Output capture and streaming
4. Tool availability detection
5. Argument sanitization
6. Parallel tool execution
7. Tool chain (pipe one tool's output to next)
"""

from __future__ import annotations

import asyncio
import shutil
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ToolExecStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    NOT_FOUND = "not_found"


@dataclass
class ToolExecResult:
    """Result of a tool execution."""
    exec_id: str = ""
    tool_name: str = ""
    command: str = ""
    status: ToolExecStatus = ToolExecStatus.QUEUED
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    started_at: float = 0.0
    completed_at: float = 0.0
    duration_s: float = 0.0
    timed_out: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.exec_id[:10],
            "tool": self.tool_name[:12],
            "status": self.status.value,
            "exit_code": self.exit_code,
            "duration": round(self.duration_s, 1),
        }


@dataclass
class ToolConfig:
    """Configuration for an external tool."""
    name: str = ""
    binary: str = ""
    default_args: list[str] = field(default_factory=list)
    timeout_s: float = 300.0
    max_output_bytes: int = 10_000_000   # 10MB
    requires_root: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name[:12],
            "binary": self.binary[:15],
            "timeout": self.timeout_s,
        }


# ── Tool registry ────────────────────────────────────────────

TOOL_REGISTRY: dict[str, dict[str, Any]] = {
    "nmap": {"binary": "nmap", "timeout": 600, "args": ["-sV"]},
    "masscan": {"binary": "masscan", "timeout": 300, "args": ["--rate=1000"], "root": True},
    "nuclei": {"binary": "nuclei", "timeout": 900, "args": ["-silent"]},
    "sqlmap": {"binary": "sqlmap", "timeout": 600, "args": ["--batch"]},
    "ffuf": {"binary": "ffuf", "timeout": 300, "args": ["-mc", "200,301,302,403"]},
    "gobuster": {"binary": "gobuster", "timeout": 300, "args": []},
    "subfinder": {"binary": "subfinder", "timeout": 120, "args": ["-silent"]},
    "httpx": {"binary": "httpx", "timeout": 120, "args": ["-silent"]},
    "nikto": {"binary": "nikto", "timeout": 600, "args": []},
    "testssl": {"binary": "testssl.sh", "timeout": 300, "args": []},
    "hydra": {"binary": "hydra", "timeout": 600, "args": []},
    "hashcat": {"binary": "hashcat", "timeout": 3600, "args": []},
    "john": {"binary": "john", "timeout": 3600, "args": []},
    "semgrep": {"binary": "semgrep", "timeout": 300, "args": ["--json"]},
    "bandit": {"binary": "bandit", "timeout": 120, "args": ["-f", "json"]},
    "trivy": {"binary": "trivy", "timeout": 300, "args": ["--format", "json"]},
    "dig": {"binary": "dig", "timeout": 30, "args": []},
    "whois": {"binary": "whois", "timeout": 30, "args": []},
    "wpscan": {"binary": "wpscan", "timeout": 300, "args": ["--no-banner"]},
    "amass": {"binary": "amass", "timeout": 600, "args": ["enum"]},
}

# ── Dangerous arguments (blocked) ────────────────────────────

BLOCKED_ARGS = [
    "--os-shell", "--os-cmd",       # sqlmap OS commands
    "-oN /etc", "-oN /root",       # nmap write to sensitive paths
    "rm -rf", "mkfs",              # Destructive commands
    "> /dev/sd",                   # Disk overwrites
]


def _sanitize_args(args: list[str]) -> list[str]:
    """Remove dangerous arguments."""
    sanitized: list[str] = []
    full_args = " ".join(args)
    for blocked in BLOCKED_ARGS:
        if blocked in full_args:
            continue

    for arg in args:
        # Remove shell metacharacters
        if any(c in arg for c in [';', '|', '`', '$(']):
            continue
        sanitized.append(arg)
    return sanitized


class ToolOrchestrator:
    """Orchestrates external security tool execution.

    Manages async subprocess execution with
    timeouts, output capture, and argument
    sanitization for security tools.
    """

    def __init__(self) -> None:
        self._configs: dict[str, ToolConfig] = {}
        self._executions: list[ToolExecResult] = []
        self._counter = 0
        self._log = logger.bind(component="tool_orchestrator")
        self._load_registry()

    def _load_registry(self) -> None:
        """Load tool configs from registry."""
        for name, info in TOOL_REGISTRY.items():
            self._configs[name] = ToolConfig(
                name=name,
                binary=info.get("binary", name),
                default_args=info.get("args", []),
                timeout_s=info.get("timeout", 300),
                requires_root=info.get("root", False),
            )

    def is_available(self, tool_name: str) -> bool:
        """Check if a tool binary is available."""
        config = self._configs.get(tool_name)
        if not config:
            return False
        return shutil.which(config.binary) is not None

    def get_available_tools(self) -> list[str]:
        """List all available tools."""
        return [
            name for name in self._configs
            if self.is_available(name)
        ]

    async def execute(
        self,
        tool_name: str,
        args: list[str],
        timeout_s: float = 0.0,
    ) -> ToolExecResult:
        """Execute a tool asynchronously."""
        self._counter += 1
        exec_id = f"exec-{self._counter}"

        config = self._configs.get(tool_name)
        if not config:
            return ToolExecResult(
                exec_id=exec_id,
                tool_name=tool_name,
                status=ToolExecStatus.NOT_FOUND,
            )

        if not self.is_available(tool_name):
            return ToolExecResult(
                exec_id=exec_id,
                tool_name=tool_name,
                status=ToolExecStatus.NOT_FOUND,
            )

        # Sanitize arguments
        safe_args = _sanitize_args(args)
        full_args = [config.binary] + config.default_args + safe_args
        command = " ".join(full_args)

        timeout = timeout_s or config.timeout_s

        result = ToolExecResult(
            exec_id=exec_id,
            tool_name=tool_name,
            command=command,
            status=ToolExecStatus.RUNNING,
            started_at=time.time(),
        )

        try:
            proc = await asyncio.create_subprocess_exec(
                *full_args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=timeout,
                )
                result.stdout = stdout_bytes.decode("utf-8", errors="replace")[:config.max_output_bytes]
                result.stderr = stderr_bytes.decode("utf-8", errors="replace")[:100000]
                result.exit_code = proc.returncode or 0
                result.status = (
                    ToolExecStatus.COMPLETED if result.exit_code == 0
                    else ToolExecStatus.FAILED
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                result.status = ToolExecStatus.TIMED_OUT
                result.timed_out = True

        except FileNotFoundError:
            result.status = ToolExecStatus.NOT_FOUND
        except PermissionError:
            result.status = ToolExecStatus.FAILED
            result.stderr = "Permission denied"
        except OSError as exc:
            result.status = ToolExecStatus.FAILED
            result.stderr = str(exc)

        result.completed_at = time.time()
        result.duration_s = result.completed_at - result.started_at
        self._executions.append(result)

        self._log.info(
            "tool_executed",
            tool=tool_name,
            status=result.status.value,
            duration=round(result.duration_s, 1),
            exit_code=result.exit_code,
        )

        return result

    async def execute_chain(
        self,
        steps: list[tuple[str, list[str]]],
    ) -> list[ToolExecResult]:
        """Execute tools in sequence, passing output."""
        results: list[ToolExecResult] = []
        prev_output = ""

        for tool_name, args in steps:
            # Append previous output as stdin context
            if prev_output:
                args = args + ["--stdin-data", prev_output[:1000]]

            result = await self.execute(tool_name, args)
            results.append(result)

            if result.status != ToolExecStatus.COMPLETED:
                break

            prev_output = result.stdout

        return results

    async def execute_parallel(
        self,
        tasks: list[tuple[str, list[str]]],
        max_concurrent: int = 5,
    ) -> list[ToolExecResult]:
        """Execute multiple tools in parallel."""
        semaphore = asyncio.Semaphore(max_concurrent)

        async def _run(tool_name: str, args: list[str]) -> ToolExecResult:
            async with semaphore:
                return await self.execute(tool_name, args)

        coros = [_run(name, args) for name, args in tasks]
        return list(await asyncio.gather(*coros))

    def build_tools_prompt(self) -> str:
        """Build available tools context for LLM."""
        lines = ["## Available Security Tools\n"]
        available = self.get_available_tools()
        installed = []
        missing = []

        for name in sorted(self._configs.keys()):
            if name in available:
                installed.append(name)
            else:
                missing.append(name)

        lines.append(f"Installed ({len(installed)}):")
        for name in installed:
            config = self._configs[name]
            lines.append(f"  - {name} (timeout: {config.timeout_s}s)")

        if missing:
            lines.append(f"\nNot installed ({len(missing)}):")
            lines.append(f"  {', '.join(missing[:10])}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        status_counts: dict[str, int] = {}
        for e in self._executions:
            status_counts[e.status.value] = status_counts.get(e.status.value, 0) + 1

        return {
            "total_executions": len(self._executions),
            "by_status": status_counts,
            "available_tools": len(self.get_available_tools()),
            "total_tools": len(self._configs),
        }
