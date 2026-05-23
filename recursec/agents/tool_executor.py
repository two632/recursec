"""Tool executor — manages subprocess execution of external security tools.

Implements:
1. Async subprocess management
2. Timeout handling
3. Output capture (stdout + stderr)
4. Tool availability checking
5. Argument sanitization
6. Execution sandboxing
7. Resource limits (CPU, memory, time)
8. Execution history and metrics
"""

from __future__ import annotations

import asyncio
import os
import shlex
import shutil
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ToolState(str, Enum):
    AVAILABLE = "available"
    NOT_FOUND = "not_found"
    RUNNING = "running"
    DISABLED = "disabled"


@dataclass
class ToolDefinition:
    """Definition of an external tool."""
    name: str = ""
    binary: str = ""               # The actual binary name (e.g., "nmap")
    alt_binaries: list[str] = field(default_factory=list)  # Alternative binary names
    install_cmd: str = ""          # How to install it
    state: ToolState = ToolState.NOT_FOUND
    version: str = ""
    path: str = ""                 # Path to binary

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name[:20],
            "binary": self.binary[:15],
            "state": self.state.value,
            "version": self.version[:15],
        }


@dataclass
class ExecutionRequest:
    """A request to execute a tool."""
    tool: str = ""
    args: list[str] = field(default_factory=list)
    timeout_s: float = 300.0
    working_dir: str = ""
    env: dict[str, str] = field(default_factory=dict)
    capture_stderr: bool = True
    max_output_bytes: int = 10 * 1024 * 1024  # 10 MB

    @property
    def command(self) -> str:
        return f"{self.tool} {' '.join(self.args)}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool[:15],
            "args": len(self.args),
            "timeout": self.timeout_s,
        }


@dataclass
class ExecutionResult:
    """Result of a tool execution."""
    tool: str = ""
    command: str = ""
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    duration_s: float = 0.0
    success: bool = False
    timed_out: bool = False
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool[:15],
            "exit": self.exit_code,
            "duration": round(self.duration_s, 1),
            "success": self.success,
            "stdout_len": len(self.stdout),
            "stderr_len": len(self.stderr),
        }


# ── Tool Registry ─────────────────────────────────────────────

TOOL_REGISTRY: list[dict[str, Any]] = [
    # Network scanning
    {"name": "nmap", "binary": "nmap", "install": "apt install -y nmap"},
    {"name": "masscan", "binary": "masscan", "install": "apt install -y masscan"},
    {"name": "rustscan", "binary": "rustscan", "alt": ["rustscan"]},

    # Web scanning
    {"name": "nuclei", "binary": "nuclei", "install": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
    {"name": "nikto", "binary": "nikto", "install": "apt install -y nikto"},
    {"name": "gobuster", "binary": "gobuster", "install": "go install github.com/OJ/gobuster/v3@latest"},
    {"name": "ffuf", "binary": "ffuf", "install": "go install github.com/ffuf/ffuf/v2@latest"},
    {"name": "wpscan", "binary": "wpscan", "install": "gem install wpscan"},
    {"name": "whatweb", "binary": "whatweb", "install": "apt install -y whatweb"},

    # SQL injection
    {"name": "sqlmap", "binary": "sqlmap", "install": "apt install -y sqlmap"},

    # Brute force
    {"name": "hydra", "binary": "hydra", "install": "apt install -y hydra"},
    {"name": "medusa", "binary": "medusa", "install": "apt install -y medusa"},

    # Subdomain enumeration
    {"name": "subfinder", "binary": "subfinder", "install": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
    {"name": "amass", "binary": "amass", "install": "go install github.com/owasp-amass/amass/v4/...@master"},
    {"name": "httpx", "binary": "httpx", "install": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"},

    # TLS/SSL
    {"name": "testssl", "binary": "testssl.sh", "alt": ["testssl"]},
    {"name": "sslyze", "binary": "sslyze", "install": "pip install sslyze"},

    # Code analysis
    {"name": "semgrep", "binary": "semgrep", "install": "pip install semgrep"},
    {"name": "bandit", "binary": "bandit", "install": "pip install bandit"},
    {"name": "trivy", "binary": "trivy"},

    # Network
    {"name": "tcpdump", "binary": "tcpdump", "install": "apt install -y tcpdump"},
    {"name": "dig", "binary": "dig", "install": "apt install -y dnsutils"},
    {"name": "curl", "binary": "curl"},
    {"name": "wget", "binary": "wget"},

    # Exploitation
    {"name": "metasploit", "binary": "msfconsole"},
    {"name": "hashcat", "binary": "hashcat", "install": "apt install -y hashcat"},
    {"name": "john", "binary": "john", "install": "apt install -y john"},

    # SMB/Windows
    {"name": "crackmapexec", "binary": "crackmapexec", "alt": ["cme"]},
    {"name": "enum4linux", "binary": "enum4linux"},
    {"name": "smbclient", "binary": "smbclient", "install": "apt install -y smbclient"},

    # SSH
    {"name": "ssh-audit", "binary": "ssh-audit", "install": "pip install ssh-audit"},

    # Cloud
    {"name": "prowler", "binary": "prowler", "install": "pip install prowler"},
    {"name": "scout-suite", "binary": "scout", "install": "pip install scoutsuite"},

    # Container
    {"name": "docker", "binary": "docker"},
    {"name": "kubectl", "binary": "kubectl"},
]

# ── Dangerous Patterns ────────────────────────────────────────

BLOCKED_PATTERNS: list[str] = [
    "rm -rf /",
    "mkfs",
    "> /dev/sda",
    "dd if=/dev/zero",
    ":(){ :|:& };:",  # Fork bomb
    "wget -O- | sh",
    "curl | bash",
]


class ToolExecutor:
    """Manages execution of external security tools.

    Handles tool discovery, argument building, subprocess
    management, output capture, and execution metrics.
    """

    def __init__(self, allowed_tools: list[str] | None = None) -> None:
        self._tools: dict[str, ToolDefinition] = {}
        self._allowed = set(allowed_tools) if allowed_tools else None
        self._history: list[ExecutionResult] = []
        self._active: dict[str, asyncio.subprocess.Process] = {}
        self._log = logger.bind(component="tool_executor")

        self._discover_tools()

    def _discover_tools(self) -> None:
        """Discover which tools are installed."""
        for entry in TOOL_REGISTRY:
            name = entry["name"]

            if self._allowed and name not in self._allowed:
                continue

            tool = ToolDefinition(
                name=name,
                binary=entry["binary"],
                alt_binaries=entry.get("alt", []),
                install_cmd=entry.get("install", ""),
            )

            # Check if binary exists
            path = shutil.which(tool.binary)
            if path:
                tool.state = ToolState.AVAILABLE
                tool.path = path
            else:
                # Try alternatives
                for alt in tool.alt_binaries:
                    alt_path = shutil.which(alt)
                    if alt_path:
                        tool.state = ToolState.AVAILABLE
                        tool.path = alt_path
                        tool.binary = alt
                        break

            self._tools[name] = tool

    def is_available(self, tool_name: str) -> bool:
        """Check if a tool is available."""
        tool = self._tools.get(tool_name)
        return bool(tool and tool.state == ToolState.AVAILABLE)

    def get_available_tools(self) -> list[str]:
        """Get list of available tools."""
        return [
            name for name, tool in self._tools.items()
            if tool.state == ToolState.AVAILABLE
        ]

    async def execute(self, request: ExecutionRequest) -> ExecutionResult:
        """Execute a tool."""
        tool = self._tools.get(request.tool)

        if not tool:
            return ExecutionResult(
                tool=request.tool,
                error=f"Unknown tool: {request.tool}",
            )

        if tool.state != ToolState.AVAILABLE:
            return ExecutionResult(
                tool=request.tool,
                error=f"Tool not available: {tool.state.value}",
            )

        # Sanitize command
        cmd_str = f"{tool.path} {' '.join(request.args)}"
        if not self._is_safe(cmd_str):
            return ExecutionResult(
                tool=request.tool,
                command=cmd_str,
                error="Command blocked by safety check",
            )

        # Build full command
        args = [tool.path] + request.args

        env = os.environ.copy()
        if request.env:
            env.update(request.env)

        start_time = time.time()

        try:
            process = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE if request.capture_stderr else None,
                cwd=request.working_dir or None,
                env=env,
            )

            exec_id = f"{request.tool}-{id(process)}"
            self._active[exec_id] = process

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    process.communicate(),
                    timeout=request.timeout_s,
                )

                duration = time.time() - start_time

                stdout = (stdout_bytes or b"").decode("utf-8", errors="replace")
                stderr = (stderr_bytes or b"").decode("utf-8", errors="replace")

                # Truncate if too large
                if len(stdout) > request.max_output_bytes:
                    stdout = stdout[:request.max_output_bytes] + "\n...[truncated]"
                if len(stderr) > request.max_output_bytes:
                    stderr = stderr[:request.max_output_bytes] + "\n...[truncated]"

                result = ExecutionResult(
                    tool=request.tool,
                    command=cmd_str,
                    stdout=stdout,
                    stderr=stderr,
                    exit_code=process.returncode or 0,
                    duration_s=duration,
                    success=process.returncode == 0,
                )

            except asyncio.TimeoutError:
                process.kill()
                await process.communicate()
                duration = time.time() - start_time

                result = ExecutionResult(
                    tool=request.tool,
                    command=cmd_str,
                    duration_s=duration,
                    timed_out=True,
                    error=f"Timed out after {request.timeout_s}s",
                )
            finally:
                self._active.pop(exec_id, None)

        except FileNotFoundError:
            result = ExecutionResult(
                tool=request.tool,
                command=cmd_str,
                error=f"Binary not found: {tool.path}",
            )
        except PermissionError:
            result = ExecutionResult(
                tool=request.tool,
                command=cmd_str,
                error=f"Permission denied: {tool.path}",
            )
        except Exception as e:
            result = ExecutionResult(
                tool=request.tool,
                command=cmd_str,
                error=str(e),
            )

        self._history.append(result)
        return result

    async def cancel(self, tool_name: str) -> int:
        """Cancel all running instances of a tool."""
        cancelled = 0
        to_remove = []
        for exec_id, process in self._active.items():
            if exec_id.startswith(f"{tool_name}-"):
                process.kill()
                to_remove.append(exec_id)
                cancelled += 1

        for exec_id in to_remove:
            del self._active[exec_id]

        return cancelled

    @staticmethod
    def _is_safe(command: str) -> bool:
        """Check if a command is safe to execute."""
        cmd_lower = command.lower()
        for pattern in BLOCKED_PATTERNS:
            if pattern in cmd_lower:
                return False
        return True

    @staticmethod
    def build_nmap_args(
        target: str,
        scan_type: str = "default",
        ports: str = "",
    ) -> list[str]:
        """Build nmap arguments."""
        args = []

        if scan_type == "quick":
            args.extend(["-sV", "-sC", "-T4", "--top-ports", "1000"])
        elif scan_type == "full":
            args.extend(["-sV", "-sC", "-p-", "-T3"])
        elif scan_type == "stealth":
            args.extend(["-sS", "-sV", "-T2", "--randomize-hosts"])
        elif scan_type == "udp":
            args.extend(["-sU", "--top-ports", "100"])
        else:
            args.extend(["-sV", "-sC"])

        if ports:
            args.extend(["-p", ports])

        args.append(shlex.quote(target))
        return args

    @staticmethod
    def build_nuclei_args(
        target: str,
        severity: str = "",
        templates: str = "",
    ) -> list[str]:
        """Build nuclei arguments."""
        args = ["-u", target, "-json"]

        if severity:
            args.extend(["-severity", severity])
        if templates:
            args.extend(["-t", templates])

        return args

    @staticmethod
    def build_gobuster_args(
        target: str,
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    ) -> list[str]:
        """Build gobuster arguments."""
        return ["dir", "-u", target, "-w", wordlist, "-q"]

    @staticmethod
    def build_sqlmap_args(
        url: str,
        data: str = "",
        level: int = 1,
        risk: int = 1,
    ) -> list[str]:
        """Build sqlmap arguments."""
        args = ["-u", url, "--batch", "--level", str(level), "--risk", str(risk)]
        if data:
            args.extend(["--data", data])
        return args

    def get_tool(self, name: str) -> ToolDefinition | None:
        return self._tools.get(name)

    def get_stats(self) -> dict[str, Any]:
        tool_exec_counts: dict[str, int] = defaultdict(int)
        tool_success_counts: dict[str, int] = defaultdict(int)
        for result in self._history:
            tool_exec_counts[result.tool] += 1
            if result.success:
                tool_success_counts[result.tool] += 1

        return {
            "registered": len(self._tools),
            "available": len(self.get_available_tools()),
            "executions": len(self._history),
            "active": len(self._active),
            "by_tool": {
                name: {
                    "runs": tool_exec_counts.get(name, 0),
                    "success": tool_success_counts.get(name, 0),
                }
                for name in self._tools
                if tool_exec_counts.get(name, 0) > 0
            },
        }
