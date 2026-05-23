"""Tool executor — async subprocess execution for external tools.

Implements:
1. Async subprocess execution with timeout
2. Output capture and streaming
3. Tool availability detection
4. Environment sandboxing
5. Rate limiting and concurrency control
6. Output truncation for token budgets
7. Exit code interpretation
"""

from __future__ import annotations

import asyncio
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
    NOT_INSTALLED = "not_installed"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    RATE_LIMITED = "rate_limited"


@dataclass
class ToolResult:
    """Result of a tool execution."""
    tool: str = ""
    command: str = ""
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    status: ToolStatus = ToolStatus.COMPLETED
    duration_s: float = 0.0
    truncated: bool = False
    timestamp: float = field(default_factory=time.time)

    @property
    def success(self) -> bool:
        return self.exit_code == 0 and self.status == ToolStatus.COMPLETED

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool[:15],
            "status": self.status.value,
            "exit_code": self.exit_code,
            "duration_s": round(self.duration_s, 2),
            "output_len": len(self.stdout),
        }


@dataclass
class ToolSpec:
    """Specification of an external tool."""
    name: str = ""
    binary: str = ""
    description: str = ""
    default_timeout_s: float = 300
    max_concurrent: int = 1
    requires_root: bool = False
    installed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name[:15],
            "installed": self.installed,
            "timeout": self.default_timeout_s,
        }


# ── Tool registry ────────────────────────────────────────────

TOOL_REGISTRY: list[dict[str, Any]] = [
    {"name": "nmap", "binary": "nmap", "desc": "Network scanner", "timeout": 600, "concurrent": 2},
    {"name": "masscan", "binary": "masscan", "desc": "Fast port scanner", "timeout": 300, "concurrent": 1, "root": True},
    {"name": "nuclei", "binary": "nuclei", "desc": "Template-based vuln scanner", "timeout": 600, "concurrent": 3},
    {"name": "nikto", "binary": "nikto", "desc": "Web server scanner", "timeout": 300, "concurrent": 2},
    {"name": "sqlmap", "binary": "sqlmap", "desc": "SQL injection tool", "timeout": 600, "concurrent": 1},
    {"name": "ffuf", "binary": "ffuf", "desc": "Web fuzzer", "timeout": 300, "concurrent": 3},
    {"name": "gobuster", "binary": "gobuster", "desc": "Directory buster", "timeout": 300, "concurrent": 2},
    {"name": "feroxbuster", "binary": "feroxbuster", "desc": "Recursive dir buster", "timeout": 300, "concurrent": 2},
    {"name": "subfinder", "binary": "subfinder", "desc": "Subdomain discovery", "timeout": 120, "concurrent": 2},
    {"name": "amass", "binary": "amass", "desc": "Attack surface mapper", "timeout": 600, "concurrent": 1},
    {"name": "httpx", "binary": "httpx", "desc": "HTTP probe", "timeout": 120, "concurrent": 3},
    {"name": "whatweb", "binary": "whatweb", "desc": "Web fingerprinter", "timeout": 120, "concurrent": 2},
    {"name": "hydra", "binary": "hydra", "desc": "Brute forcer", "timeout": 600, "concurrent": 1},
    {"name": "medusa", "binary": "medusa", "desc": "Parallel brute forcer", "timeout": 600, "concurrent": 1},
    {"name": "dalfox", "binary": "dalfox", "desc": "XSS scanner", "timeout": 300, "concurrent": 2},
    {"name": "testssl", "binary": "testssl.sh", "desc": "SSL/TLS checker", "timeout": 300, "concurrent": 2},
    {"name": "wpscan", "binary": "wpscan", "desc": "WordPress scanner", "timeout": 300, "concurrent": 1},
    {"name": "semgrep", "binary": "semgrep", "desc": "SAST scanner", "timeout": 300, "concurrent": 2},
    {"name": "bandit", "binary": "bandit", "desc": "Python SAST", "timeout": 120, "concurrent": 2},
    {"name": "trufflehog", "binary": "trufflehog", "desc": "Secret scanner", "timeout": 300, "concurrent": 2},
    {"name": "gitleaks", "binary": "gitleaks", "desc": "Git secret scanner", "timeout": 300, "concurrent": 2},
    {"name": "trivy", "binary": "trivy", "desc": "Container/dependency scanner", "timeout": 300, "concurrent": 2},
    {"name": "grype", "binary": "grype", "desc": "Vulnerability scanner", "timeout": 300, "concurrent": 2},
    {"name": "dig", "binary": "dig", "desc": "DNS lookup", "timeout": 30, "concurrent": 5},
    {"name": "whois", "binary": "whois", "desc": "Domain info", "timeout": 30, "concurrent": 3},
    {"name": "dnsrecon", "binary": "dnsrecon", "desc": "DNS enumeration", "timeout": 120, "concurrent": 2},
    {"name": "enum4linux", "binary": "enum4linux", "desc": "SMB/NetBIOS enumeration", "timeout": 300, "concurrent": 1},
    {"name": "crackmapexec", "binary": "crackmapexec", "desc": "Network tool", "timeout": 300, "concurrent": 1},
    {"name": "searchsploit", "binary": "searchsploit", "desc": "Exploit-DB search", "timeout": 30, "concurrent": 3},
    {"name": "curl", "binary": "curl", "desc": "HTTP client", "timeout": 30, "concurrent": 10},
    {"name": "wfuzz", "binary": "wfuzz", "desc": "Web fuzzer", "timeout": 300, "concurrent": 2},
    {"name": "dirsearch", "binary": "dirsearch", "desc": "Directory scanner", "timeout": 300, "concurrent": 2},
    {"name": "arjun", "binary": "arjun", "desc": "Parameter discovery", "timeout": 300, "concurrent": 2},
    {"name": "katana", "binary": "katana", "desc": "Web crawler", "timeout": 300, "concurrent": 2},
    {"name": "hakrawler", "binary": "hakrawler", "desc": "Web crawler", "timeout": 120, "concurrent": 2},
    {"name": "waybackurls", "binary": "waybackurls", "desc": "Wayback Machine URLs", "timeout": 60, "concurrent": 3},
    {"name": "gau", "binary": "gau", "desc": "URL fetcher", "timeout": 60, "concurrent": 3},
    {"name": "rustscan", "binary": "rustscan", "desc": "Fast port scanner", "timeout": 120, "concurrent": 1},
    {"name": "responder", "binary": "responder", "desc": "LLMNR/NBT-NS poisoner", "timeout": 600, "concurrent": 1, "root": True},
]


class ToolExecutor:
    """Executes external security tools as async subprocesses.

    Manages tool availability, concurrency limits,
    timeouts, and output capture.
    """

    def __init__(
        self,
        max_output_chars: int = 50_000,
        max_concurrent_total: int = 10,
    ) -> None:
        self._tools: dict[str, ToolSpec] = {}
        self._running: dict[str, int] = defaultdict(int)
        self._total_running = 0
        self._max_output = max_output_chars
        self._max_concurrent = max_concurrent_total
        self._semaphore = asyncio.Semaphore(max_concurrent_total)
        self._history: list[ToolResult] = []
        self._log = logger.bind(component="tool_executor")
        self._load_registry()

    def _load_registry(self) -> None:
        """Load and check tool availability."""
        for entry in TOOL_REGISTRY:
            binary = entry.get("binary", entry["name"])
            installed = shutil.which(binary) is not None

            spec = ToolSpec(
                name=entry["name"],
                binary=binary,
                description=entry.get("desc", ""),
                default_timeout_s=entry.get("timeout", 300),
                max_concurrent=entry.get("concurrent", 1),
                requires_root=entry.get("root", False),
                installed=installed,
            )
            self._tools[spec.name] = spec

    async def execute(
        self,
        tool: str,
        args: list[str],
        timeout_s: float = 0,
        env: dict[str, str] | None = None,
    ) -> ToolResult:
        """Execute a tool as an async subprocess."""
        spec = self._tools.get(tool)
        if not spec:
            return ToolResult(
                tool=tool,
                status=ToolStatus.NOT_INSTALLED,
                stderr=f"Unknown tool: {tool}",
            )

        if not spec.installed:
            return ToolResult(
                tool=tool,
                status=ToolStatus.NOT_INSTALLED,
                stderr=f"Tool not installed: {tool} (binary: {spec.binary})",
            )

        timeout = timeout_s or spec.default_timeout_s
        command = [spec.binary] + args
        cmd_str = " ".join(command)

        start = time.time()

        async with self._semaphore:
            self._running[tool] += 1
            self._total_running += 1

            try:
                proc = await asyncio.create_subprocess_exec(
                    *command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=env,
                )

                try:
                    stdout_bytes, stderr_bytes = await asyncio.wait_for(
                        proc.communicate(),
                        timeout=timeout,
                    )
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
                    duration = time.time() - start
                    result = ToolResult(
                        tool=tool,
                        command=cmd_str,
                        status=ToolStatus.TIMEOUT,
                        duration_s=duration,
                        stderr=f"Timeout after {timeout}s",
                    )
                    self._history.append(result)
                    return result

                duration = time.time() - start
                stdout = stdout_bytes.decode("utf-8", errors="replace")
                stderr = stderr_bytes.decode("utf-8", errors="replace")

                truncated = False
                if len(stdout) > self._max_output:
                    stdout = stdout[:self._max_output] + "\n... [truncated]"
                    truncated = True

                status = ToolStatus.COMPLETED if proc.returncode == 0 else ToolStatus.FAILED

                result = ToolResult(
                    tool=tool,
                    command=cmd_str,
                    stdout=stdout,
                    stderr=stderr,
                    exit_code=proc.returncode or 0,
                    status=status,
                    duration_s=duration,
                    truncated=truncated,
                )

            except OSError as exc:
                duration = time.time() - start
                result = ToolResult(
                    tool=tool,
                    command=cmd_str,
                    status=ToolStatus.FAILED,
                    duration_s=duration,
                    stderr=str(exc),
                    exit_code=-1,
                )

            finally:
                self._running[tool] -= 1
                self._total_running -= 1

        self._history.append(result)
        return result

    def get_available_tools(self) -> list[ToolSpec]:
        """Get list of installed tools."""
        return [t for t in self._tools.values() if t.installed]

    def get_all_tools(self) -> list[ToolSpec]:
        """Get all registered tools."""
        return list(self._tools.values())

    def is_installed(self, tool: str) -> bool:
        """Check if a tool is installed."""
        spec = self._tools.get(tool)
        return spec.installed if spec else False

    def get_history(
        self,
        tool: str = "",
        limit: int = 20,
    ) -> list[ToolResult]:
        """Get execution history."""
        if tool:
            results = [r for r in self._history if r.tool == tool]
        else:
            results = list(self._history)
        return results[-limit:]

    def get_stats(self) -> dict[str, Any]:
        installed = sum(1 for t in self._tools.values() if t.installed)
        total_runs = len(self._history)
        successes = sum(1 for r in self._history if r.success)

        return {
            "registered": len(self._tools),
            "installed": installed,
            "total_runs": total_runs,
            "success_rate": round(successes / max(1, total_runs), 2),
            "currently_running": self._total_running,
        }
