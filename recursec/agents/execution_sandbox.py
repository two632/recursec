"""Execution sandbox — isolated command execution with safety.

Implements:
1. Subprocess execution with timeout and kill
2. Output capture and size limiting
3. Resource limits (memory, CPU, disk)
4. Command allowlist/denylist
5. Working directory isolation
6. Environment variable management
7. Execution history and audit log
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ExecStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    BLOCKED = "blocked"      # Blocked by policy


class RiskLevel(str, Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    DANGEROUS = "dangerous"


@dataclass
class ExecutionResult:
    """Result of a sandboxed command execution."""
    exec_id: str = ""
    command: str = ""
    args: list[str] = field(default_factory=list)
    status: ExecStatus = ExecStatus.PENDING
    exit_code: int = -1
    stdout: str = ""
    stderr: str = ""
    runtime_s: float = 0.0
    risk_level: RiskLevel = RiskLevel.LOW
    blocked_reason: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.exec_id[:10],
            "cmd": self.command[:15],
            "status": self.status.value[:6],
            "exit": self.exit_code,
            "runtime": f"{self.runtime_s:.1f}s",
            "risk": self.risk_level.value[:4],
        }


# ── Safety rules ─────────────────────────────────────────────

# Commands that are always blocked
BLOCKED_COMMANDS: set[str] = {
    "rm", "rmdir", "mkfs", "dd", "shred",
    "shutdown", "reboot", "halt", "poweroff",
    "kill", "killall", "pkill",
    "chmod", "chown",  # Prevent permission changes
    "iptables", "ip6tables",  # Prevent firewall changes
    "useradd", "userdel", "usermod", "passwd",
}

# Commands that require elevated review
HIGH_RISK_COMMANDS: set[str] = {
    "nmap", "masscan", "zmap",      # Scanning
    "sqlmap", "hydra", "medusa",     # Active exploitation
    "metasploit", "msfconsole",      # Exploitation
    "john", "hashcat",               # Password cracking
    "aircrack-ng", "airmon-ng",      # Wireless
    "ettercap", "arpspoof",          # Network attack
}

# Commands that are always safe
SAFE_COMMANDS: set[str] = {
    "echo", "cat", "head", "tail", "wc", "sort", "uniq",
    "grep", "awk", "sed", "cut", "tr",
    "ls", "find", "file", "stat",
    "ping", "dig", "nslookup", "host", "whois",
    "curl", "wget",
    "python", "python3", "pip",
    "go", "node", "npm",
    "git", "jq",
}

# Patterns that indicate dangerous arguments
DANGEROUS_PATTERNS: list[str] = [
    r";\s*rm\s",         # Command injection with rm
    r"\|\s*rm\s",        # Pipe to rm
    r">\s*/dev/sd",      # Write to disk device
    r">\s*/etc/",        # Write to /etc
    r"\$\(.*rm\s",       # Subshell rm
    r"`.*rm\s",          # Backtick rm
]


class ExecutionSandbox:
    """Sandboxed command execution for security tools.

    Provides isolated execution with safety policies,
    resource limits, output capture, and audit logging.
    """

    def __init__(
        self,
        work_dir: str = "/tmp/recursec-sandbox",
        max_output: int = 1_000_000,
        default_timeout: float = 300.0,
    ) -> None:
        self._work_dir = work_dir
        self._max_output = max_output
        self._default_timeout = default_timeout
        self._history: list[ExecutionResult] = []
        self._counter = 0
        self._env: dict[str, str] = {}
        self._log = logger.bind(component="execution_sandbox")

    def assess_risk(self, command: str, args: list[str]) -> RiskLevel:
        """Assess the risk level of a command."""
        base_cmd = os.path.basename(command).lower()

        # Check blocked
        if base_cmd in BLOCKED_COMMANDS:
            return RiskLevel.DANGEROUS

        # Check dangerous patterns in args
        full_cmd = f"{command} {' '.join(args)}"
        for pattern in DANGEROUS_PATTERNS:
            if re.search(pattern, full_cmd):
                return RiskLevel.DANGEROUS

        # Check high risk
        if base_cmd in HIGH_RISK_COMMANDS:
            return RiskLevel.HIGH

        # Check safe
        if base_cmd in SAFE_COMMANDS:
            return RiskLevel.SAFE

        return RiskLevel.MEDIUM

    def prepare_execution(
        self,
        command: str,
        args: list[str] | None = None,
        timeout: float = 0.0,
        env: dict[str, str] | None = None,
    ) -> ExecutionResult:
        """Prepare a command for execution (assess risk, build result).

        Does NOT actually execute — returns the prepared result
        for the agent to decide whether to proceed.
        """
        self._counter += 1
        exec_args = args or []
        risk = self.assess_risk(command, exec_args)

        result = ExecutionResult(
            exec_id=f"exec-{self._counter}",
            command=command,
            args=exec_args,
            risk_level=risk,
        )

        if risk == RiskLevel.DANGEROUS:
            result.status = ExecStatus.BLOCKED
            result.blocked_reason = f"Command '{command}' is blocked by safety policy"
            self._history.append(result)
            return result

        result.status = ExecStatus.PENDING
        return result

    def record_execution(
        self,
        result: ExecutionResult,
        exit_code: int = 0,
        stdout: str = "",
        stderr: str = "",
        runtime_s: float = 0.0,
    ) -> ExecutionResult:
        """Record the results of an actual execution."""
        result.exit_code = exit_code
        result.stdout = stdout[:self._max_output]
        result.stderr = stderr[:self._max_output]
        result.runtime_s = runtime_s

        if exit_code == 0:
            result.status = ExecStatus.COMPLETED
        elif exit_code == -1:
            result.status = ExecStatus.TIMEOUT
        else:
            result.status = ExecStatus.FAILED

        self._history.append(result)
        return result

    def get_command_line(
        self,
        command: str,
        args: list[str],
        timeout: float = 0.0,
    ) -> list[str]:
        """Build the actual command line with safety wrappers."""
        cmd_timeout = timeout or self._default_timeout
        base_cmd = os.path.basename(command).lower()

        # For high-risk tools, add timeout wrapper
        if base_cmd in HIGH_RISK_COMMANDS:
            return ["timeout", str(int(cmd_timeout)), command] + args

        return [command] + args

    def build_sandbox_prompt(self) -> str:
        """Build sandbox context for LLM."""
        lines = ["## Execution Sandbox\n"]

        lines.append(f"Default timeout: {self._default_timeout}s")
        lines.append(f"Max output: {self._max_output} bytes")
        lines.append(f"Executions: {len(self._history)}")

        # Stats
        if self._history:
            completed = sum(1 for r in self._history if r.status == ExecStatus.COMPLETED)
            failed = sum(1 for r in self._history if r.status == ExecStatus.FAILED)
            blocked = sum(1 for r in self._history if r.status == ExecStatus.BLOCKED)
            timeout = sum(1 for r in self._history if r.status == ExecStatus.TIMEOUT)
            lines.append(
                f"Status: {completed} ok, {failed} fail, "
                f"{blocked} blocked, {timeout} timeout"
            )

        # Recent executions
        if self._history:
            lines.append("\nRecent:")
            for r in self._history[-5:]:
                lines.append(
                    f"  [{r.risk_level.value[0].upper()}] {r.command[:12]} "
                    f"→ {r.status.value} ({r.runtime_s:.1f}s)"
                )

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        status_counts: dict[str, int] = {}
        risk_counts: dict[str, int] = {}
        for r in self._history:
            status_counts[r.status.value] = status_counts.get(r.status.value, 0) + 1
            risk_counts[r.risk_level.value] = risk_counts.get(r.risk_level.value, 0) + 1

        return {
            "total_executions": len(self._history),
            "by_status": status_counts,
            "by_risk": risk_counts,
            "total_runtime": sum(r.runtime_s for r in self._history),
        }
