"""Base tool class and tool execution sandbox."""

from __future__ import annotations

import asyncio
import shutil
import time
from abc import ABC, abstractmethod
from typing import Any

import structlog

from recursec.core.models import ToolCategory, ToolResult

logger = structlog.get_logger()


class BaseTool(ABC):
    """Base class for all tools in RecurSec."""

    name: str = ""
    description: str = ""
    category: ToolCategory = ToolCategory.MISC
    binary_name: str = ""  # The CLI binary (e.g. "nmap", "sqlmap")
    install_command: str = ""  # How to install if missing
    requires_root: bool = False
    timeout: int = 300  # seconds
    dangerous: bool = False  # Requires approval

    def __init__(self, sandbox_mode: bool = True, docker_image: str | None = None):
        self.sandbox_mode = sandbox_mode
        self.docker_image = docker_image
        self._available: bool | None = None

    @abstractmethod
    async def execute(self, **kwargs: Any) -> ToolResult:
        """Execute the tool with given arguments."""

    @abstractmethod
    def build_command(self, **kwargs: Any) -> str:
        """Build the CLI command string."""

    def to_llm_schema(self) -> dict[str, Any]:
        """Return an OpenAI function-calling schema for this tool."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self._parameters_schema(),
            },
        }

    @abstractmethod
    def _parameters_schema(self) -> dict[str, Any]:
        """Return JSON Schema for this tool's parameters."""

    def is_available(self) -> bool:
        """Check if the tool binary is installed."""
        if self._available is not None:
            return self._available
        if self.binary_name:
            self._available = shutil.which(self.binary_name) is not None
        else:
            self._available = True
        return self._available

    async def _run_command(
        self,
        command: str,
        timeout: int | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
    ) -> ToolResult:
        """Execute a shell command and return the result."""
        timeout = timeout or self.timeout
        start = time.monotonic()

        if self.sandbox_mode and self.docker_image:
            command = self._wrap_in_docker(command)

        try:
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env=env,
            )
            stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            elapsed = time.monotonic() - start

            stdout = stdout_bytes.decode("utf-8", errors="replace") if stdout_bytes else ""
            stderr = stderr_bytes.decode("utf-8", errors="replace") if stderr_bytes else ""

            return ToolResult(
                tool_name=self.name,
                command=command,
                stdout=stdout,
                stderr=stderr,
                exit_code=proc.returncode or 0,
                execution_time_s=elapsed,
                raw_output=stdout + stderr,
            )
        except asyncio.TimeoutError:
            return ToolResult(
                tool_name=self.name,
                command=command,
                stderr=f"Command timed out after {timeout}s",
                exit_code=124,
                execution_time_s=time.monotonic() - start,
            )
        except Exception as e:
            return ToolResult(
                tool_name=self.name,
                command=command,
                stderr=str(e),
                exit_code=1,
                execution_time_s=time.monotonic() - start,
            )

    def _wrap_in_docker(self, command: str) -> str:
        """Wrap command in a Docker container for sandboxing."""
        return (
            f"docker run --rm --network=host "
            f"-v /tmp/recursec-workspace:/workspace "
            f"{self.docker_image} "
            f"bash -c {command!r}"
        )


class ShellTool(BaseTool):
    """Generic shell command execution tool."""

    name = "shell"
    description = "Execute an arbitrary shell command. Use for custom commands not covered by other tools."
    category = ToolCategory.MISC
    dangerous = True

    def build_command(self, **kwargs: Any) -> str:
        return kwargs.get("command", "")

    async def execute(self, command: str = "", timeout: int = 60, cwd: str | None = None, **kwargs: Any) -> ToolResult:
        return await self._run_command(command, timeout=timeout, cwd=cwd)

    def _parameters_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Shell command to execute"},
                "timeout": {"type": "integer", "description": "Timeout in seconds", "default": 60},
                "cwd": {"type": "string", "description": "Working directory"},
            },
            "required": ["command"],
        }
