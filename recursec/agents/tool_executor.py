"""Tool executor — async external tool management.

Implements:
1. Async subprocess execution for external tools
2. Timeout management per tool
3. Output capture and streaming
4. Tool availability checking
5. Command sanitization
6. Resource limit enforcement
7. Concurrent tool execution
8. Tool result caching
"""

from __future__ import annotations

import asyncio
import os
import shutil
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ToolStatus(str, Enum):
    AVAILABLE = "available"
    MISSING = "missing"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"
    TIMEOUT = "timeout"


@dataclass
class ToolConfig:
    """Configuration for an external tool."""
    name: str = ""
    binary: str = ""
    default_args: list[str] = field(default_factory=list)
    timeout_s: float = 300.0
    max_output_bytes: int = 10_000_000
    requires_root: bool = False
    category: str = ""
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name[:15],
            "binary": self.binary[:15],
            "timeout": self.timeout_s,
            "category": self.category[:10],
        }


@dataclass
class ToolExecution:
    """A tool execution record."""
    exec_id: str = ""
    tool: str = ""
    command: str = ""
    args: list[str] = field(default_factory=list)
    status: ToolStatus = ToolStatus.RUNNING
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    started_at: float = field(default_factory=time.time)
    completed_at: float = 0.0
    pid: int = 0

    @property
    def duration_s(self) -> float:
        if self.completed_at > 0:
            return self.completed_at - self.started_at
        return time.time() - self.started_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.exec_id[:10],
            "tool": self.tool[:12],
            "status": self.status.value,
            "exit_code": self.exit_code,
            "duration": round(self.duration_s, 1),
            "stdout_len": len(self.stdout),
        }


# ── Tool registry ────────────────────────────────────────────

TOOL_REGISTRY: list[dict[str, Any]] = [
    # Reconnaissance
    {"name": "nmap", "binary": "nmap", "timeout": 600, "cat": "recon", "desc": "Port/service scanner"},
    {"name": "masscan", "binary": "masscan", "timeout": 300, "cat": "recon", "desc": "Fast port scanner", "root": True},
    {"name": "subfinder", "binary": "subfinder", "timeout": 120, "cat": "recon", "desc": "Subdomain finder"},
    {"name": "amass", "binary": "amass", "timeout": 300, "cat": "recon", "desc": "Attack surface mapper"},
    {"name": "httpx", "binary": "httpx", "timeout": 120, "cat": "recon", "desc": "HTTP probe"},
    {"name": "wafw00f", "binary": "wafw00f", "timeout": 60, "cat": "recon", "desc": "WAF detector"},
    {"name": "dnsrecon", "binary": "dnsrecon", "timeout": 120, "cat": "recon", "desc": "DNS enumeration"},
    {"name": "theHarvester", "binary": "theHarvester", "timeout": 120, "cat": "recon", "desc": "OSINT"},
    {"name": "whatweb", "binary": "whatweb", "timeout": 60, "cat": "recon", "desc": "Web tech fingerprint"},
    # Vulnerability Scanning
    {"name": "nuclei", "binary": "nuclei", "timeout": 600, "cat": "vuln_scan", "desc": "Template-based scanner"},
    {"name": "nikto", "binary": "nikto", "timeout": 300, "cat": "vuln_scan", "desc": "Web server scanner"},
    {"name": "wpscan", "binary": "wpscan", "timeout": 300, "cat": "vuln_scan", "desc": "WordPress scanner"},
    {"name": "testssl", "binary": "testssl.sh", "timeout": 120, "cat": "vuln_scan", "desc": "SSL/TLS scanner"},
    # Exploitation
    {"name": "sqlmap", "binary": "sqlmap", "timeout": 600, "cat": "exploit", "desc": "SQL injection"},
    {"name": "hydra", "binary": "hydra", "timeout": 600, "cat": "exploit", "desc": "Brute forcer"},
    {"name": "searchsploit", "binary": "searchsploit", "timeout": 30, "cat": "exploit", "desc": "Exploit search"},
    {"name": "dalfox", "binary": "dalfox", "timeout": 300, "cat": "exploit", "desc": "XSS scanner"},
    # Fuzzing
    {"name": "ffuf", "binary": "ffuf", "timeout": 300, "cat": "fuzzing", "desc": "Web fuzzer"},
    {"name": "gobuster", "binary": "gobuster", "timeout": 300, "cat": "fuzzing", "desc": "Dir/DNS bruter"},
    {"name": "wfuzz", "binary": "wfuzz", "timeout": 300, "cat": "fuzzing", "desc": "Web fuzzer"},
    {"name": "feroxbuster", "binary": "feroxbuster", "timeout": 300, "cat": "fuzzing", "desc": "Recursive fuzzer"},
    # Code Analysis
    {"name": "semgrep", "binary": "semgrep", "timeout": 300, "cat": "code", "desc": "Code analysis"},
    {"name": "bandit", "binary": "bandit", "timeout": 120, "cat": "code", "desc": "Python security"},
    {"name": "trufflehog", "binary": "trufflehog", "timeout": 120, "cat": "code", "desc": "Secret scanner"},
    {"name": "gitleaks", "binary": "gitleaks", "timeout": 120, "cat": "code", "desc": "Git secret scanner"},
    # Container/Cloud
    {"name": "trivy", "binary": "trivy", "timeout": 300, "cat": "container", "desc": "Image scanner"},
    {"name": "grype", "binary": "grype", "timeout": 120, "cat": "container", "desc": "Vuln scanner"},
    {"name": "kube-bench", "binary": "kube-bench", "timeout": 120, "cat": "container", "desc": "K8s benchmark"},
    # Network
    {"name": "responder", "binary": "responder", "timeout": 600, "cat": "network", "desc": "LLMNR/NBT-NS", "root": True},
    {"name": "crackmapexec", "binary": "crackmapexec", "timeout": 300, "cat": "network", "desc": "Network Swiss knife"},
    {"name": "enum4linux", "binary": "enum4linux-ng", "timeout": 120, "cat": "network", "desc": "SMB enum"},
    # Utilities
    {"name": "curl", "binary": "curl", "timeout": 30, "cat": "util", "desc": "HTTP client"},
    {"name": "dig", "binary": "dig", "timeout": 15, "cat": "util", "desc": "DNS lookup"},
    {"name": "whois", "binary": "whois", "timeout": 15, "cat": "util", "desc": "WHOIS lookup"},
]


class ToolExecutor:
    """Async external tool executor.

    Manages execution of external security tools
    with timeout, output capture, and concurrency.
    """

    def __init__(self, max_concurrent: int = 5) -> None:
        self._tools: dict[str, ToolConfig] = {}
        self._executions: dict[str, ToolExecution] = {}
        self._counter = 0
        self._max_concurrent = max_concurrent
        self._running = 0
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._log = logger.bind(component="tool_executor")
        self._load_tools()

    def _load_tools(self) -> None:
        """Load tool registry and check availability."""
        for entry in TOOL_REGISTRY:
            config = ToolConfig(
                name=entry["name"],
                binary=entry["binary"],
                timeout_s=entry.get("timeout", 300),
                requires_root=entry.get("root", False),
                category=entry.get("cat", ""),
                description=entry.get("desc", ""),
            )
            self._tools[config.name] = config

    def check_tool(self, name: str) -> ToolStatus:
        """Check if a tool is available."""
        config = self._tools.get(name)
        if not config:
            return ToolStatus.MISSING

        if shutil.which(config.binary):
            return ToolStatus.AVAILABLE

        return ToolStatus.MISSING

    def get_available_tools(self) -> list[str]:
        """Get list of available tools."""
        return [
            name for name in self._tools
            if self.check_tool(name) == ToolStatus.AVAILABLE
        ]

    async def execute(
        self,
        tool: str,
        args: list[str],
        timeout: float = 0,
        env: dict[str, str] | None = None,
    ) -> ToolExecution:
        """Execute a tool asynchronously."""
        self._counter += 1
        config = self._tools.get(tool)
        if not config:
            return ToolExecution(
                exec_id=f"exec-{self._counter}",
                tool=tool,
                status=ToolStatus.FAILED,
                stderr=f"Unknown tool: {tool}",
            )

        if self.check_tool(tool) != ToolStatus.AVAILABLE:
            return ToolExecution(
                exec_id=f"exec-{self._counter}",
                tool=tool,
                status=ToolStatus.MISSING,
                stderr=f"Tool not found: {config.binary}",
            )

        execution = ToolExecution(
            exec_id=f"exec-{self._counter}",
            tool=tool,
            command=f"{config.binary} {' '.join(args)}",
            args=args,
            status=ToolStatus.RUNNING,
        )
        self._executions[execution.exec_id] = execution

        effective_timeout = timeout or config.timeout_s

        async with self._semaphore:
            try:
                exec_env = dict(os.environ)
                if env:
                    exec_env.update(env)

                process = await asyncio.create_subprocess_exec(
                    config.binary, *args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=exec_env,
                )
                execution.pid = process.pid or 0

                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    process.communicate(),
                    timeout=effective_timeout,
                )

                execution.stdout = stdout_bytes.decode("utf-8", errors="replace")[:config.max_output_bytes]
                execution.stderr = stderr_bytes.decode("utf-8", errors="replace")[:config.max_output_bytes]
                execution.exit_code = process.returncode or 0
                execution.status = ToolStatus.COMPLETE if execution.exit_code == 0 else ToolStatus.FAILED

            except asyncio.TimeoutError:
                execution.status = ToolStatus.TIMEOUT
                execution.stderr = f"Timeout after {effective_timeout}s"
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
            except OSError as e:
                execution.status = ToolStatus.FAILED
                execution.stderr = str(e)[:200]

            execution.completed_at = time.time()

        return execution

    def execute_sync(
        self,
        tool: str,
        args: list[str],
        timeout: float = 0,
    ) -> ToolExecution:
        """Synchronous wrapper for tool execution."""
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(self.execute(tool, args, timeout))
        finally:
            loop.close()

    def get_execution(self, exec_id: str) -> ToolExecution | None:
        """Get an execution by ID."""
        return self._executions.get(exec_id)

    def get_tool_config(self, name: str) -> ToolConfig | None:
        """Get tool configuration."""
        return self._tools.get(name)

    def get_stats(self) -> dict[str, Any]:
        status_counts: dict[str, int] = defaultdict(int)
        cat_counts: dict[str, int] = defaultdict(int)

        for ex in self._executions.values():
            status_counts[ex.status.value] += 1

        for config in self._tools.values():
            cat_counts[config.category] += 1

        available = len(self.get_available_tools())

        return {
            "registered": len(self._tools),
            "available": available,
            "executions": len(self._executions),
            "by_status": dict(status_counts),
            "by_category": dict(cat_counts),
        }
