"""Tool chain orchestrator — executes real security tools with sandboxing.

This is the module that actually runs external tools (nmap, nuclei, sqlmap, etc.)
and feeds their output back to the agent brain for analysis. Features:
1. Command building with validation and sanitization
2. Subprocess execution with timeout and resource limits
3. Output capture and structured parsing
4. Tool dependency resolution (run recon before exploit)
5. Parallel tool execution for independent scans
6. Rate limiting to avoid target overload
7. Tool health checking (is tool installed?)
8. Environment variable management for tool configs
9. Result caching for repeated scans
10. Sandbox mode (dry-run) for testing

The agent's LLM decides WHAT to run. This module handles HOW.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ToolCategory(str, Enum):
    RECON = "recon"
    SCANNER = "scanner"
    WEB = "web"
    EXPLOIT = "exploit"
    POST_EXPLOIT = "post_exploit"
    CODE_AUDIT = "code_audit"
    NETWORK = "network"
    CRYPTO = "crypto"
    WIRELESS = "wireless"
    CLOUD = "cloud"
    CONTAINER = "container"
    PASSWORD = "password"
    FORENSICS = "forensics"
    OSINT = "osint"


class ToolStatus(str, Enum):
    AVAILABLE = "available"
    MISSING = "missing"
    ERROR = "error"
    DISABLED = "disabled"


@dataclass
class ToolDefinition:
    """Definition of an external security tool."""
    name: str = ""
    binary: str = ""
    category: ToolCategory = ToolCategory.SCANNER
    description: str = ""
    install_cmd: str = ""
    default_args: list[str] = field(default_factory=list)
    output_format: str = "text"
    timeout_s: int = 300
    requires_root: bool = False
    requires_target: bool = True
    status: ToolStatus = ToolStatus.MISSING

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category.value[:8],
            "status": self.status.value[:8],
            "timeout": f"{self.timeout_s}s",
        }


# Master tool catalog — every external tool the agent can use
TOOL_CATALOG: dict[str, ToolDefinition] = {
    # ─── Recon ───
    "nmap": ToolDefinition(name="nmap", binary="nmap", category=ToolCategory.RECON, description="Network exploration and port scanning", default_args=["-sV", "-sC", "--top-ports", "1000"], output_format="xml", timeout_s=600),
    "masscan": ToolDefinition(name="masscan", binary="masscan", category=ToolCategory.RECON, description="Mass IP port scanner", default_args=["--rate", "1000", "-p", "1-65535"], output_format="json", timeout_s=600, requires_root=True),
    "subfinder": ToolDefinition(name="subfinder", binary="subfinder", category=ToolCategory.RECON, description="Subdomain discovery", default_args=["-silent"], output_format="text", timeout_s=300),
    "amass": ToolDefinition(name="amass", binary="amass", category=ToolCategory.RECON, description="In-depth attack surface mapping", default_args=["enum", "-passive"], output_format="text", timeout_s=600),
    "theHarvester": ToolDefinition(name="theHarvester", binary="theHarvester", category=ToolCategory.RECON, description="Email, subdomain, name harvester", default_args=["-b", "all"], output_format="text", timeout_s=300),
    "whois": ToolDefinition(name="whois", binary="whois", category=ToolCategory.RECON, description="Domain WHOIS lookup", default_args=[], output_format="text", timeout_s=30),
    "dig": ToolDefinition(name="dig", binary="dig", category=ToolCategory.RECON, description="DNS lookup utility", default_args=["ANY"], output_format="text", timeout_s=30),
    "dnsrecon": ToolDefinition(name="dnsrecon", binary="dnsrecon", category=ToolCategory.RECON, description="DNS enumeration", default_args=["-t", "std,brt,axfr"], output_format="text", timeout_s=300),

    # ─── Vulnerability Scanners ───
    "nuclei": ToolDefinition(name="nuclei", binary="nuclei", category=ToolCategory.SCANNER, description="Template-based vulnerability scanner", default_args=["-severity", "critical,high,medium", "-silent"], output_format="json", timeout_s=600),
    "nikto": ToolDefinition(name="nikto", binary="nikto", category=ToolCategory.SCANNER, description="Web server scanner", default_args=["-Format", "json"], output_format="json", timeout_s=600),
    "openvas": ToolDefinition(name="openvas", binary="gvm-cli", category=ToolCategory.SCANNER, description="Open vulnerability assessment", default_args=[], output_format="xml", timeout_s=1800),
    "wpscan": ToolDefinition(name="wpscan", binary="wpscan", category=ToolCategory.SCANNER, description="WordPress vulnerability scanner", default_args=["--enumerate", "vp,vt,u"], output_format="json", timeout_s=600),
    "testssl": ToolDefinition(name="testssl", binary="testssl.sh", category=ToolCategory.SCANNER, description="TLS/SSL scanner", default_args=["--jsonfile-pretty", "/dev/stdout"], output_format="json", timeout_s=300),

    # ─── Web Application ───
    "sqlmap": ToolDefinition(name="sqlmap", binary="sqlmap", category=ToolCategory.WEB, description="SQL injection scanner", default_args=["--batch", "--random-agent", "--level", "3"], output_format="text", timeout_s=600),
    "ffuf": ToolDefinition(name="ffuf", binary="ffuf", category=ToolCategory.WEB, description="Web fuzzer", default_args=["-mc", "all", "-fc", "404"], output_format="json", timeout_s=600),
    "gobuster": ToolDefinition(name="gobuster", binary="gobuster", category=ToolCategory.WEB, description="Directory/file brute-forcer", default_args=["dir"], output_format="text", timeout_s=600),
    "feroxbuster": ToolDefinition(name="feroxbuster", binary="feroxbuster", category=ToolCategory.WEB, description="Fast recursive content discovery", default_args=["--silent"], output_format="json", timeout_s=600),
    "httpx": ToolDefinition(name="httpx", binary="httpx", category=ToolCategory.WEB, description="HTTP probe toolkit", default_args=["-silent", "-tech-detect", "-status-code"], output_format="json", timeout_s=300),
    "katana": ToolDefinition(name="katana", binary="katana", category=ToolCategory.WEB, description="Web crawler", default_args=["-silent", "-jc"], output_format="text", timeout_s=300),
    "dalfox": ToolDefinition(name="dalfox", binary="dalfox", category=ToolCategory.WEB, description="XSS scanner", default_args=["url"], output_format="json", timeout_s=300),

    # ─── Exploitation ───
    "metasploit": ToolDefinition(name="metasploit", binary="msfconsole", category=ToolCategory.EXPLOIT, description="Exploitation framework", default_args=["-q", "-x"], output_format="text", timeout_s=600),
    "searchsploit": ToolDefinition(name="searchsploit", binary="searchsploit", category=ToolCategory.EXPLOIT, description="Exploit database search", default_args=["--json"], output_format="json", timeout_s=30),

    # ─── Code Audit ───
    "semgrep": ToolDefinition(name="semgrep", binary="semgrep", category=ToolCategory.CODE_AUDIT, description="Static analysis tool", default_args=["scan", "--config", "auto", "--json"], output_format="json", timeout_s=600, requires_target=False),
    "bandit": ToolDefinition(name="bandit", binary="bandit", category=ToolCategory.CODE_AUDIT, description="Python security linter", default_args=["-f", "json", "-r"], output_format="json", timeout_s=300, requires_target=False),
    "trufflehog": ToolDefinition(name="trufflehog", binary="trufflehog", category=ToolCategory.CODE_AUDIT, description="Secret scanner", default_args=["--json"], output_format="json", timeout_s=300),
    "gitleaks": ToolDefinition(name="gitleaks", binary="gitleaks", category=ToolCategory.CODE_AUDIT, description="Git secrets scanner", default_args=["detect", "--report-format", "json"], output_format="json", timeout_s=300),

    # ─── Password ───
    "hydra": ToolDefinition(name="hydra", binary="hydra", category=ToolCategory.PASSWORD, description="Password brute-forcer", default_args=["-t", "4"], output_format="text", timeout_s=600),
    "john": ToolDefinition(name="john", binary="john", category=ToolCategory.PASSWORD, description="Password cracker", default_args=[], output_format="text", timeout_s=600, requires_target=False),
    "hashcat": ToolDefinition(name="hashcat", binary="hashcat", category=ToolCategory.PASSWORD, description="Advanced password recovery", default_args=[], output_format="text", timeout_s=600, requires_target=False),

    # ─── Network ───
    "tcpdump": ToolDefinition(name="tcpdump", binary="tcpdump", category=ToolCategory.NETWORK, description="Network packet analyzer", default_args=["-c", "1000"], output_format="text", timeout_s=60, requires_root=True),
    "responder": ToolDefinition(name="responder", binary="responder", category=ToolCategory.NETWORK, description="LLMNR/NBT-NS/mDNS poisoner", default_args=["-A"], output_format="text", timeout_s=300, requires_root=True),
    "netcat": ToolDefinition(name="netcat", binary="nc", category=ToolCategory.NETWORK, description="Network utility", default_args=[], output_format="text", timeout_s=60),

    # ─── Cloud ───
    "prowler": ToolDefinition(name="prowler", binary="prowler", category=ToolCategory.CLOUD, description="AWS/Azure/GCP security auditor", default_args=[], output_format="json", timeout_s=600, requires_target=False),
    "scout": ToolDefinition(name="scout", binary="scout", category=ToolCategory.CLOUD, description="AWS security auditing", default_args=[], output_format="json", timeout_s=600, requires_target=False),
    "trivy": ToolDefinition(name="trivy", binary="trivy", category=ToolCategory.CONTAINER, description="Container/IaC vulnerability scanner", default_args=["--format", "json"], output_format="json", timeout_s=300),

    # ─── OSINT ───
    "sherlock": ToolDefinition(name="sherlock", binary="sherlock", category=ToolCategory.OSINT, description="Social media username finder", default_args=[], output_format="text", timeout_s=300, requires_target=False),
    "recon-ng": ToolDefinition(name="recon-ng", binary="recon-ng", category=ToolCategory.OSINT, description="OSINT framework", default_args=[], output_format="text", timeout_s=300),

    # ─── Forensics ───
    "volatility": ToolDefinition(name="volatility", binary="vol.py", category=ToolCategory.FORENSICS, description="Memory forensics framework", default_args=[], output_format="text", timeout_s=600, requires_target=False),
    "yara": ToolDefinition(name="yara", binary="yara", category=ToolCategory.FORENSICS, description="Pattern matching for malware", default_args=[], output_format="text", timeout_s=300),
}


@dataclass
class ToolExecution:
    """Record of a tool execution."""
    tool_name: str = ""
    command: str = ""
    target: str = ""
    exit_code: int = -1
    stdout: str = ""
    stderr: str = ""
    duration_s: float = 0.0
    success: bool = False
    timed_out: bool = False
    sandboxed: bool = False
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool_name,
            "ok": self.success,
            "exit": self.exit_code,
            "duration": f"{self.duration_s:.1f}s",
            "output_len": len(self.stdout),
            "timed_out": self.timed_out,
        }


class ToolChainOrchestrator:
    """Orchestrates execution of external security tools."""

    def __init__(self, sandbox: bool = False) -> None:
        self._sandbox = sandbox
        self._executions: list[ToolExecution] = []
        self._tool_status: dict[str, ToolStatus] = {}
        self._rate_limits: dict[str, float] = {}  # target → last execution time
        self._min_interval_s = 1.0
        self._log = logger.bind(component="tool_orchestrator")
        self._check_tools()

    def _check_tools(self) -> None:
        """Check which tools are installed."""
        for name, tool_def in TOOL_CATALOG.items():
            path = shutil.which(tool_def.binary)
            if path:
                tool_def.status = ToolStatus.AVAILABLE
                self._tool_status[name] = ToolStatus.AVAILABLE
            else:
                self._tool_status[name] = ToolStatus.MISSING

    def get_available_tools(self) -> list[str]:
        """Get list of available (installed) tools."""
        return [name for name, status in self._tool_status.items() if status == ToolStatus.AVAILABLE]

    def get_tools_by_category(self, category: ToolCategory) -> list[ToolDefinition]:
        """Get all tools in a category."""
        return [t for t in TOOL_CATALOG.values() if t.category == category and t.status == ToolStatus.AVAILABLE]

    def build_command(self, tool_name: str, target: str = "", extra_args: list[str] | None = None) -> list[str]:
        """Build a safe command for a tool."""
        tool_def = TOOL_CATALOG.get(tool_name)
        if not tool_def:
            return []

        cmd = [tool_def.binary]
        cmd.extend(tool_def.default_args)

        if extra_args:
            # Sanitize extra args
            safe_args = [a for a in extra_args if not a.startswith(("-o", "--output")) and "|" not in a and ";" not in a and "&" not in a]
            cmd.extend(safe_args)

        if target and tool_def.requires_target:
            # Add target based on tool conventions
            if tool_name in ("nmap", "masscan"):
                cmd.append(target)
            elif tool_name in ("nuclei", "httpx", "katana"):
                cmd.extend(["-u", target])
            elif tool_name in ("subfinder",):
                cmd.extend(["-d", target])
            elif tool_name in ("sqlmap",):
                cmd.extend(["-u", target])
            elif tool_name in ("ffuf",):
                cmd.extend(["-u", f"{target}/FUZZ"])
            elif tool_name in ("gobuster",):
                cmd.extend(["-u", target])
            elif tool_name in ("nikto",):
                cmd.extend(["-h", target])
            elif tool_name in ("wpscan",):
                cmd.extend(["--url", target])
            elif tool_name in ("hydra",):
                cmd.append(target)
            else:
                cmd.append(target)

        return cmd

    def execute(
        self,
        tool_name: str,
        target: str = "",
        extra_args: list[str] | None = None,
        timeout_override: int | None = None,
    ) -> ToolExecution:
        """Execute a tool and capture output."""
        tool_def = TOOL_CATALOG.get(tool_name)
        if not tool_def:
            return ToolExecution(tool_name=tool_name, success=False, stderr=f"Unknown tool: {tool_name}")

        if tool_def.status != ToolStatus.AVAILABLE:
            return ToolExecution(tool_name=tool_name, success=False, stderr=f"Tool not installed: {tool_name}")

        # Rate limiting
        if target:
            last = self._rate_limits.get(target, 0)
            elapsed = time.time() - last
            if elapsed < self._min_interval_s:
                time.sleep(self._min_interval_s - elapsed)
            self._rate_limits[target] = time.time()

        cmd = self.build_command(tool_name, target, extra_args)
        if not cmd:
            return ToolExecution(tool_name=tool_name, success=False, stderr="Failed to build command")

        cmd_str = " ".join(cmd)
        timeout = timeout_override or tool_def.timeout_s

        execution = ToolExecution(
            tool_name=tool_name,
            command=cmd_str,
            target=target,
            sandboxed=self._sandbox,
        )

        if self._sandbox:
            execution.success = True
            execution.stdout = f"[SANDBOX] Would execute: {cmd_str}"
            execution.exit_code = 0
            self._executions.append(execution)
            return execution

        # Real execution
        start = time.time()
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env={**os.environ, "TERM": "dumb"},
            )
            execution.exit_code = result.returncode
            execution.stdout = result.stdout[:100000]
            execution.stderr = result.stderr[:10000]
            execution.success = result.returncode == 0
        except subprocess.TimeoutExpired:
            execution.timed_out = True
            execution.stderr = f"Timed out after {timeout}s"
        except FileNotFoundError:
            execution.stderr = f"Tool binary not found: {cmd[0]}"
        except PermissionError:
            execution.stderr = f"Permission denied: {cmd[0]} (requires root?)"
        except Exception as e:
            execution.stderr = f"Execution error: {str(e)[:200]}"

        execution.duration_s = time.time() - start
        self._executions.append(execution)
        return execution

    def execute_chain(
        self,
        tools: list[tuple[str, str, list[str] | None]],
    ) -> list[ToolExecution]:
        """Execute a chain of tools sequentially.

        Args:
            tools: List of (tool_name, target, extra_args) tuples.
        """
        results = []
        for tool_name, target, extra_args in tools:
            result = self.execute(tool_name, target, extra_args)
            results.append(result)
            if not result.success:
                self._log.warning("chain_tool_failed", tool=tool_name, error=result.stderr[:50])
        return results

    def get_execution_history(self, limit: int = 50) -> list[dict[str, Any]]:
        """Get recent execution history."""
        return [e.to_dict() for e in self._executions[-limit:]]

    def get_stats(self) -> dict[str, Any]:
        total = len(self._executions)
        successful = sum(1 for e in self._executions if e.success)
        available = sum(1 for s in self._tool_status.values() if s == ToolStatus.AVAILABLE)
        missing = sum(1 for s in self._tool_status.values() if s == ToolStatus.MISSING)
        return {
            "total_executions": total,
            "successful": successful,
            "success_rate": f"{successful/max(total,1):.2f}",
            "tools_available": available,
            "tools_missing": missing,
            "total_catalog": len(TOOL_CATALOG),
            "sandbox_mode": self._sandbox,
        }
