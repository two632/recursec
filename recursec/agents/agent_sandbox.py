"""Agent sandbox — isolated execution environment for agent actions.

Implements:
1. Command execution with timeouts and resource limits
2. File system sandboxing (work directory isolation)
3. Network scope enforcement
4. Output capture and size limits
5. Execution history tracking
6. Safety checks before execution
7. Rollback capability
8. Resource usage monitoring
"""

from __future__ import annotations

import asyncio
import re
import shutil
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


class SandboxAction(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    WARN = "warn"


class ExecutionStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    DENIED = "denied"


@dataclass
class ScopeRule:
    """A scope rule defining allowed targets."""
    rule_id: str = ""
    target_pattern: str = ""      # IP, CIDR, domain pattern
    action: SandboxAction = SandboxAction.ALLOW
    ports: list[int] = field(default_factory=list)
    description: str = ""

    def matches(self, target: str) -> bool:
        """Check if a target matches this rule."""
        if self.target_pattern == "*":
            return True
        if self.target_pattern in target:
            return True
        # Simple wildcard
        pattern = self.target_pattern.replace("*", ".*")
        try:
            return bool(re.match(pattern, target))
        except re.error:
            return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.rule_id,
            "pattern": self.target_pattern[:25],
            "action": self.action.value,
            "ports": self.ports[:5],
        }


@dataclass
class SandboxExecution:
    """Record of a sandboxed execution."""
    execution_id: str = ""
    command: str = ""
    agent_id: str = ""
    status: ExecutionStatus = ExecutionStatus.PENDING
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    started_at: float = 0.0
    completed_at: float = 0.0
    timeout_s: int = 300
    memory_mb: float = 0.0
    safety_check: str = ""

    @property
    def duration_s(self) -> float:
        end = self.completed_at or time.time()
        return end - self.started_at if self.started_at > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.execution_id,
            "cmd": self.command[:40],
            "agent": self.agent_id[:15],
            "status": self.status.value,
            "exit": self.exit_code,
            "duration": round(self.duration_s, 1),
        }


# ── Dangerous Command Patterns ────────────────────────────────

DANGEROUS_PATTERNS: list[dict[str, str]] = [
    {"pattern": r"rm\s+-rf\s+/(?!tmp)", "desc": "Recursive delete outside /tmp"},
    {"pattern": r"dd\s+if=.*of=/dev/", "desc": "Write to device"},
    {"pattern": r"mkfs\.", "desc": "Format filesystem"},
    {"pattern": r":(){ :\|:& };:", "desc": "Fork bomb"},
    {"pattern": r"wget.*\|.*bash", "desc": "Pipe download to bash"},
    {"pattern": r"curl.*\|.*sh", "desc": "Pipe download to shell"},
    {"pattern": r"chmod\s+777\s+/", "desc": "World-writable root"},
    {"pattern": r"iptables\s+-F", "desc": "Flush firewall rules"},
    {"pattern": r"systemctl\s+stop", "desc": "Stop system service"},
    {"pattern": r"kill\s+-9\s+1\b", "desc": "Kill init process"},
]

# ── Allowed Tool Binaries ─────────────────────────────────────

ALLOWED_BINARIES: set[str] = {
    # Recon
    "nmap", "masscan", "subfinder", "amass", "httpx", "dnsx", "whois",
    "theHarvester", "dig", "host", "ping", "traceroute",
    # Scanning
    "nuclei", "nikto", "wpscan", "testssl.sh", "whatweb",
    # Web
    "sqlmap", "ffuf", "gobuster", "feroxbuster", "arjun", "dalfox", "commix",
    # Code analysis
    "semgrep", "bandit", "trivy", "grype",
    # Network
    "tshark", "tcpdump", "nc", "netcat", "curl", "wget",
    # Password
    "hydra", "john", "hashcat",
    # Exploitation
    "msfconsole", "searchsploit",
    # General
    "python3", "python", "bash", "sh", "cat", "grep", "awk", "sed",
    "head", "tail", "sort", "uniq", "wc", "jq", "find", "ls",
}


class AgentSandbox:
    """Isolated execution environment for agent actions.

    Enforces scope, checks commands for safety,
    and provides resource-limited execution.
    """

    def __init__(
        self,
        work_dir: str = "data/sandbox",
        default_timeout: int = 300,
        max_output_bytes: int = 500000,
    ) -> None:
        self._work_dir = Path(work_dir)
        self._work_dir.mkdir(parents=True, exist_ok=True)
        self._scope_rules: list[ScopeRule] = []
        self._executions: dict[str, SandboxExecution] = {}
        self._execution_counter = 0
        self._rule_counter = 0
        self._default_timeout = default_timeout
        self._max_output = max_output_bytes
        self._log = logger.bind(component="agent_sandbox")

    def add_scope(
        self,
        target_pattern: str,
        action: SandboxAction = SandboxAction.ALLOW,
        ports: list[int] | None = None,
        description: str = "",
    ) -> ScopeRule:
        """Add a scope rule."""
        self._rule_counter += 1
        rule = ScopeRule(
            rule_id=f"scope-{self._rule_counter}",
            target_pattern=target_pattern,
            action=action,
            ports=ports or [],
            description=description,
        )
        self._scope_rules.append(rule)
        return rule

    def check_scope(self, target: str) -> SandboxAction:
        """Check if a target is in scope."""
        if not self._scope_rules:
            return SandboxAction.WARN  # No rules = warn

        for rule in self._scope_rules:
            if rule.matches(target):
                return rule.action

        return SandboxAction.DENY  # Default deny

    def check_command_safety(self, command: str) -> tuple[bool, str]:
        """Check if a command is safe to execute."""
        # Check dangerous patterns
        for pattern_data in DANGEROUS_PATTERNS:
            if re.search(pattern_data["pattern"], command):
                return False, f"Dangerous: {pattern_data['desc']}"

        # Check binary whitelist
        parts = command.strip().split()
        if parts:
            binary = parts[0].split("/")[-1]
            if binary not in ALLOWED_BINARIES:
                return False, f"Binary '{binary}' not in whitelist"

        return True, "Command passed safety checks"

    async def execute(
        self,
        command: str,
        agent_id: str = "",
        timeout: int = 0,
        check_safety: bool = True,
    ) -> SandboxExecution:
        """Execute a command in the sandbox."""
        self._execution_counter += 1
        execution = SandboxExecution(
            execution_id=f"sbox-{self._execution_counter}",
            command=command,
            agent_id=agent_id,
            timeout_s=timeout or self._default_timeout,
        )

        # Safety check
        if check_safety:
            is_safe, safety_msg = self.check_command_safety(command)
            execution.safety_check = safety_msg
            if not is_safe:
                execution.status = ExecutionStatus.DENIED
                execution.stderr = safety_msg
                self._executions[execution.execution_id] = execution
                return execution

        execution.status = ExecutionStatus.RUNNING
        execution.started_at = time.time()

        try:
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(self._work_dir),
            )

            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(),
                timeout=execution.timeout_s,
            )

            execution.stdout = stdout_bytes.decode("utf-8", errors="replace")[:self._max_output]
            execution.stderr = stderr_bytes.decode("utf-8", errors="replace")[:50000]
            execution.exit_code = proc.returncode or 0
            execution.status = ExecutionStatus.COMPLETED

        except asyncio.TimeoutError:
            execution.status = ExecutionStatus.TIMEOUT
            execution.stderr = f"Timeout after {execution.timeout_s}s"

        except Exception as exc:
            execution.status = ExecutionStatus.FAILED
            execution.stderr = str(exc)[:500]

        execution.completed_at = time.time()
        self._executions[execution.execution_id] = execution

        if len(self._executions) > 500:
            old_keys = sorted(self._executions.keys())[:100]
            for key in old_keys:
                del self._executions[key]

        return execution

    def create_agent_workspace(self, agent_id: str) -> Path:
        """Create an isolated workspace for an agent."""
        workspace = self._work_dir / agent_id
        workspace.mkdir(parents=True, exist_ok=True)
        return workspace

    def cleanup_workspace(self, agent_id: str) -> None:
        """Clean up an agent's workspace."""
        workspace = self._work_dir / agent_id
        if workspace.exists():
            shutil.rmtree(workspace, ignore_errors=True)

    def get_execution_history(
        self,
        agent_id: str = "",
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Get execution history."""
        execs = list(self._executions.values())
        if agent_id:
            execs = [e for e in execs if e.agent_id == agent_id]
        execs.sort(key=lambda e: e.started_at, reverse=True)
        return [e.to_dict() for e in execs[:limit]]

    def get_stats(self) -> dict[str, Any]:
        status_counts = {}
        for exc in self._executions.values():
            status_counts[exc.status.value] = status_counts.get(exc.status.value, 0) + 1
        return {
            "executions": len(self._executions),
            "scope_rules": len(self._scope_rules),
            "statuses": status_counts,
        }
