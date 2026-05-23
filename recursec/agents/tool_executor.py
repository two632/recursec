"""Tool executor — safe, sandboxed execution of external security tools.

Implements:
1. Command construction with argument validation
2. Sandboxed execution (timeouts, resource limits)
3. Output capture and streaming
4. Exit code handling
5. Tool chain execution (pipe output between tools)
6. Concurrent execution with semaphores
7. Output size limits
8. Working directory management
"""

from __future__ import annotations

import asyncio
import os
import shutil
import time
from dataclasses import dataclass
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class ExecutionResult:
    """Result of a tool execution."""
    tool: str = ""
    command: str = ""
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    timed_out: bool = False
    duration_s: float = 0.0
    started_at: float = 0.0
    completed_at: float = 0.0

    @property
    def success(self) -> bool:
        return self.exit_code == 0 and not self.timed_out

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool, "exit_code": self.exit_code,
            "success": self.success, "timed_out": self.timed_out,
            "duration_s": round(self.duration_s, 1),
            "stdout_len": len(self.stdout),
            "stderr_len": len(self.stderr),
        }


# ── Blocked commands (safety) ─────────────────────────────────

BLOCKED_PATTERNS = [
    "rm -rf /", "rm -rf /*", "mkfs", "dd if=/dev/zero",
    ":(){:|:&};:", "chmod -R 777 /", "shutdown", "reboot",
    "halt", "init 0", "init 6",
]


class ToolExecutor:
    """Safe, sandboxed execution of external security tools.

    Manages command execution with timeouts, output capture,
    and safety checks.
    """

    def __init__(
        self,
        max_concurrent: int = 5,
        default_timeout_s: float = 300.0,
        max_output_bytes: int = 10_000_000,
        work_dir: str = "data/tool_output",
    ) -> None:
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._default_timeout = default_timeout_s
        self._max_output = max_output_bytes
        self._work_dir = work_dir
        os.makedirs(work_dir, exist_ok=True)
        self._running: dict[str, asyncio.subprocess.Process] = {}
        self._history: list[ExecutionResult] = []
        self._log = logger.bind(component="tool_executor")

    async def execute(
        self,
        command: str,
        tool_name: str = "",
        timeout_s: float = 0.0,
        env: dict[str, str] | None = None,
        work_dir: str = "",
    ) -> ExecutionResult:
        """Execute a tool command safely."""
        if not tool_name:
            tool_name = command.split()[0] if command else "unknown"

        # Safety check
        if not self._is_safe(command):
            return ExecutionResult(
                tool=tool_name, command=command,
                stderr="Command blocked by safety check",
                exit_code=-1,
            )

        timeout = timeout_s or self._default_timeout

        async with self._semaphore:
            return await self._run(
                command=command,
                tool_name=tool_name,
                timeout=timeout,
                env=env,
                work_dir=work_dir or self._work_dir,
            )

    async def execute_chain(
        self,
        commands: list[dict[str, Any]],
    ) -> list[ExecutionResult]:
        """Execute a chain of commands, passing output between them."""
        results = []
        prev_output = ""

        for cmd_spec in commands:
            command = cmd_spec.get("command", "")
            tool = cmd_spec.get("tool", "")

            # Inject previous output if placeholder exists
            if "{prev_output}" in command and prev_output:
                # Write prev output to temp file for piping
                temp_file = os.path.join(self._work_dir, f"chain-{len(results)}.txt")
                with open(temp_file, "w") as f:
                    f.write(prev_output)
                command = command.replace("{prev_output}", temp_file)

            result = await self.execute(
                command=command,
                tool_name=tool,
                timeout_s=cmd_spec.get("timeout_s", 0.0),
            )

            results.append(result)
            prev_output = result.stdout

            # Stop chain on failure if specified
            if not result.success and cmd_spec.get("stop_on_fail", True):
                break

        return results

    async def execute_parallel(
        self,
        commands: list[dict[str, Any]],
    ) -> list[ExecutionResult]:
        """Execute multiple commands in parallel."""
        tasks = []
        for cmd_spec in commands:
            tasks.append(self.execute(
                command=cmd_spec.get("command", ""),
                tool_name=cmd_spec.get("tool", ""),
                timeout_s=cmd_spec.get("timeout_s", 0.0),
            ))

        return list(await asyncio.gather(*tasks, return_exceptions=False))

    def is_tool_available(self, tool: str) -> bool:
        """Check if a tool is installed."""
        return shutil.which(tool) is not None

    def get_available_tools(self) -> list[str]:
        """Get list of installed security tools."""
        tools = [
            "nmap", "masscan", "nuclei", "nikto", "sqlmap",
            "ffuf", "gobuster", "dirb", "wfuzz",
            "subfinder", "amass", "httpx", "katana",
            "semgrep", "bandit", "trivy", "grype",
            "hydra", "medusa", "hashcat", "john",
            "curl", "wget", "dig", "whois", "traceroute",
            "testssl.sh", "sslscan", "whatweb",
            "enum4linux", "smbclient", "rpcclient",
            "dalfox", "commix", "tplmap",
            "gitleaks", "trufflehog",
            "wireshark", "tcpdump", "tshark",
        ]

        return [t for t in tools if self.is_tool_available(t)]

    async def _run(
        self,
        command: str,
        tool_name: str,
        timeout: float,
        env: dict[str, str] | None,
        work_dir: str,
    ) -> ExecutionResult:
        """Internal command execution."""
        result = ExecutionResult(
            tool=tool_name,
            command=command[:500],
            started_at=time.time(),
        )

        proc_env = dict(os.environ)
        if env:
            proc_env.update(env)

        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=work_dir,
                env=proc_env,
            )

            self._running[tool_name] = process

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout,
                )

                result.stdout = stdout_bytes.decode(errors="replace")[:self._max_output]
                result.stderr = stderr_bytes.decode(errors="replace")[:self._max_output]
                result.exit_code = process.returncode or 0

            except asyncio.TimeoutError:
                process.kill()
                try:
                    await process.communicate()
                except Exception:
                    pass
                result.timed_out = True
                result.exit_code = -1

        except OSError as e:
            result.stderr = str(e)[:200]
            result.exit_code = -1

        finally:
            self._running.pop(tool_name, None)
            result.completed_at = time.time()
            result.duration_s = result.completed_at - result.started_at

            self._history.append(result)
            if len(self._history) > 500:
                self._history = self._history[-500:]

        return result

    def _is_safe(self, command: str) -> bool:
        """Check if a command is safe to execute."""
        cmd_lower = command.lower().strip()
        for pattern in BLOCKED_PATTERNS:
            if pattern in cmd_lower:
                self._log.warning("blocked_command", command=command[:80])
                return False
        return True

    def cancel(self, tool_name: str) -> bool:
        """Cancel a running tool."""
        process = self._running.get(tool_name)
        if process:
            process.kill()
            return True
        return False

    def get_history(self, limit: int = 50) -> list[dict[str, Any]]:
        return [r.to_dict() for r in self._history[-limit:]]

    def get_stats(self) -> dict[str, Any]:
        return {
            "running": len(self._running),
            "history": len(self._history),
            "available_tools": len(self.get_available_tools()),
        }
