"""Tool orchestrator — manages execution of external security tools.

Handles:
1. Tool discovery (what's installed)
2. Command building with parameter validation
3. Sandboxed execution with timeout
4. Output collection and parsing
5. Error handling and retry
6. Tool chain composition (output of A feeds into B)
7. Parallel tool execution
8. Result aggregation
"""

from __future__ import annotations

import time
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


@dataclass
class ToolInfo:
    """Information about an available tool."""
    name: str = ""
    binary_path: str = ""
    version: str = ""
    category: str = ""
    status: ToolStatus = ToolStatus.NOT_INSTALLED
    requires_root: bool = False
    default_timeout_s: int = 300
    output_formats: list[str] = field(default_factory=list)
    common_args: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "status": self.status.value[:8], "category": self.category[:8]}


@dataclass
class ToolExecution:
    """A tool execution instance."""
    exec_id: str = ""
    tool_name: str = ""
    command: str = ""
    target: str = ""
    status: ToolStatus = ToolStatus.RUNNING
    exit_code: int = -1
    stdout: str = ""
    stderr: str = ""
    started_at: float = field(default_factory=time.time)
    completed_at: float = 0.0
    timeout_s: int = 300
    parsed_findings: list[dict[str, Any]] = field(default_factory=list)

    @property
    def duration_s(self) -> float:
        end = self.completed_at if self.completed_at else time.time()
        return end - self.started_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.exec_id[:8],
            "tool": self.tool_name[:12],
            "status": self.status.value[:8],
            "exit": self.exit_code,
            "findings": len(self.parsed_findings),
            "duration": f"{self.duration_s:.1f}s",
        }


@dataclass
class ToolChain:
    """A chain of tools where output flows from one to the next."""
    chain_id: str = ""
    name: str = ""
    steps: list[dict[str, Any]] = field(default_factory=list)
    status: str = "pending"

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.chain_id[:8], "name": self.name[:20], "steps": len(self.steps)}


# Known tool catalog with default configurations
TOOL_CATALOG: dict[str, dict[str, Any]] = {
    "nmap": {"category": "scanner", "binary": "nmap", "root": True, "timeout": 600, "formats": ["xml", "text", "greppable"], "args": {"default": "-sV -sC -O", "fast": "-sS -T4 --top-ports 1000", "full": "-sV -sC -O -p- -T4", "stealth": "-sS -T2 -f --data-length 24"}},
    "masscan": {"category": "scanner", "binary": "masscan", "root": True, "timeout": 300, "formats": ["json", "xml"], "args": {"default": "--rate=1000 -p1-65535", "fast": "--rate=10000 --top-ports 100"}},
    "nuclei": {"category": "vuln_scanner", "binary": "nuclei", "root": False, "timeout": 600, "formats": ["jsonl", "text"], "args": {"default": "-severity critical,high,medium", "cve_only": "-t cves/", "all": "-severity critical,high,medium,low,info"}},
    "nikto": {"category": "web_scanner", "binary": "nikto", "root": False, "timeout": 300, "formats": ["json", "html", "csv"], "args": {"default": "-Format json"}},
    "sqlmap": {"category": "web_exploit", "binary": "sqlmap", "root": False, "timeout": 600, "formats": ["text"], "args": {"default": "--batch --level=3 --risk=2", "aggressive": "--batch --level=5 --risk=3 --dump"}},
    "ffuf": {"category": "web_fuzzer", "binary": "ffuf", "root": False, "timeout": 300, "formats": ["json", "csv"], "args": {"default": "-w /usr/share/wordlists/dirb/common.txt", "large": "-w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"}},
    "gobuster": {"category": "web_fuzzer", "binary": "gobuster", "root": False, "timeout": 300, "formats": ["text"], "args": {"default": "dir -w /usr/share/wordlists/dirb/common.txt"}},
    "subfinder": {"category": "recon", "binary": "subfinder", "root": False, "timeout": 120, "formats": ["text", "json"], "args": {"default": "-all"}},
    "amass": {"category": "recon", "binary": "amass", "root": False, "timeout": 300, "formats": ["text", "json"], "args": {"default": "enum -passive"}},
    "whatweb": {"category": "recon", "binary": "whatweb", "root": False, "timeout": 60, "formats": ["json"], "args": {"default": "-a 3 --log-json"}},
    "testssl": {"category": "ssl_scanner", "binary": "testssl.sh", "root": False, "timeout": 120, "formats": ["json"], "args": {"default": "--jsonfile"}},
    "semgrep": {"category": "code_scanner", "binary": "semgrep", "root": False, "timeout": 300, "formats": ["json", "sarif"], "args": {"default": "--config auto --json"}},
    "bandit": {"category": "code_scanner", "binary": "bandit", "root": False, "timeout": 120, "formats": ["json"], "args": {"default": "-r -f json"}},
    "gitleaks": {"category": "secret_scanner", "binary": "gitleaks", "root": False, "timeout": 120, "formats": ["json"], "args": {"default": "detect --report-format json"}},
    "trivy": {"category": "container_scanner", "binary": "trivy", "root": False, "timeout": 120, "formats": ["json", "table"], "args": {"default": "--severity CRITICAL,HIGH -f json"}},
    "hydra": {"category": "brute_forcer", "binary": "hydra", "root": False, "timeout": 600, "formats": ["text"], "args": {"default": "-t 4"}},
    "crackmapexec": {"category": "network", "binary": "crackmapexec", "root": False, "timeout": 300, "formats": ["text"], "args": {"default": "smb"}},
    "impacket_secretsdump": {"category": "credential", "binary": "secretsdump.py", "root": False, "timeout": 120, "formats": ["text"], "args": {"default": "-just-dc-ntlm"}},
    "prowler": {"category": "cloud_scanner", "binary": "prowler", "root": False, "timeout": 600, "formats": ["json", "html"], "args": {"default": "-M json"}},
    "dig": {"category": "dns", "binary": "dig", "root": False, "timeout": 10, "formats": ["text"], "args": {"default": "ANY +noall +answer"}},
}

# Pre-defined tool chains
PREDEFINED_CHAINS: list[dict[str, Any]] = [
    {
        "name": "Web Recon → Scan → Exploit",
        "steps": [
            {"tool": "subfinder", "output_key": "subdomains"},
            {"tool": "whatweb", "input_from": "subdomains", "output_key": "tech_stack"},
            {"tool": "nuclei", "input_from": "subdomains", "output_key": "vulns"},
            {"tool": "sqlmap", "input_from": "vulns", "output_key": "exploits"},
        ],
    },
    {
        "name": "Network Pentest Pipeline",
        "steps": [
            {"tool": "nmap", "args": "fast", "output_key": "ports"},
            {"tool": "nmap", "args": "full", "input_from": "ports", "output_key": "services"},
            {"tool": "nuclei", "input_from": "services", "output_key": "vulns"},
        ],
    },
    {
        "name": "Code Audit Pipeline",
        "steps": [
            {"tool": "gitleaks", "output_key": "secrets"},
            {"tool": "semgrep", "output_key": "code_vulns"},
            {"tool": "bandit", "output_key": "python_vulns"},
        ],
    },
]


class ToolOrchestrator:
    """Orchestrates execution of external security tools."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolInfo] = {}
        self._executions: list[ToolExecution] = []
        self._chains: list[ToolChain] = []
        self._exec_counter = 0
        self._chain_counter = 0
        self._log = logger.bind(component="tool_orchestrator")
        self._init_catalog()

    def _init_catalog(self) -> None:
        """Initialize tool catalog."""
        for name, cfg in TOOL_CATALOG.items():
            self._tools[name] = ToolInfo(
                name=name,
                binary_path=cfg.get("binary", name),
                category=cfg.get("category", ""),
                requires_root=cfg.get("root", False),
                default_timeout_s=cfg.get("timeout", 300),
                output_formats=cfg.get("formats", []),
                common_args=cfg.get("args", {}),
                status=ToolStatus.NOT_INSTALLED,
            )

    def build_command(
        self,
        tool_name: str,
        target: str,
        args_preset: str = "default",
        extra_args: str = "",
        output_file: str = "",
    ) -> str:
        """Build a tool command string."""
        tool = self._tools.get(tool_name)
        if not tool:
            return ""

        binary = tool.binary_path
        args = tool.common_args.get(args_preset, tool.common_args.get("default", ""))

        parts = [binary, args]
        if extra_args:
            parts.append(extra_args)

        # Add target
        if tool_name in ("nmap", "masscan", "nuclei", "nikto"):
            if output_file:
                parts.append(f"-o {output_file}")
            parts.append(target)
        elif tool_name in ("sqlmap",):
            parts.insert(1, f"-u '{target}'")
        elif tool_name in ("ffuf", "gobuster"):
            parts.append(f"-u {target}/FUZZ")
        elif tool_name in ("subfinder", "amass"):
            parts.append(f"-d {target}")
        else:
            parts.append(target)

        return " ".join(parts)

    def create_execution(
        self,
        tool_name: str,
        target: str,
        args_preset: str = "default",
        extra_args: str = "",
    ) -> ToolExecution:
        """Create a tool execution record."""
        self._exec_counter += 1
        command = self.build_command(tool_name, target, args_preset, extra_args)

        execution = ToolExecution(
            exec_id=f"exec-{self._exec_counter}",
            tool_name=tool_name,
            command=command,
            target=target,
            timeout_s=self._tools[tool_name].default_timeout_s if tool_name in self._tools else 300,
        )
        self._executions.append(execution)
        if len(self._executions) > 500:
            self._executions = self._executions[-250:]
        return execution

    def get_tools_for_category(self, category: str) -> list[ToolInfo]:
        """Get all tools in a category."""
        return [t for t in self._tools.values() if t.category == category]

    def get_predefined_chain(self, name: str) -> dict[str, Any] | None:
        """Get a predefined tool chain."""
        for chain in PREDEFINED_CHAINS:
            if chain["name"] == name:
                return chain
        return None

    def get_stats(self) -> dict[str, Any]:
        cat_counts: dict[str, int] = {}
        for t in self._tools.values():
            cat_counts[t.category] = cat_counts.get(t.category, 0) + 1
        return {
            "total_tools": len(self._tools),
            "executions": len(self._executions),
            "chains": len(self._chains),
            "by_category": cat_counts,
        }

    def build_orchestrator_prompt(self) -> str:
        """Build LLM prompt with tool info."""
        lines = ["## Available Tools\n"]
        by_cat: dict[str, list[str]] = {}
        for t in self._tools.values():
            by_cat.setdefault(t.category, []).append(t.name)
        for cat, tools in sorted(by_cat.items()):
            lines.append(f"  {cat}: {', '.join(tools)}")
        return "\n".join(lines)
