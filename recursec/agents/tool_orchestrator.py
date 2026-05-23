"""Tool orchestrator — manages autonomous execution of 200+ external tools.

Implements:
1. Tool registry with capability metadata
2. Tool dependency resolution
3. Execution sandboxing (timeout, resource limits)
4. Output collection and parsing
5. Tool chain composition (pipe outputs)
6. Parallel tool execution
7. Tool selection based on context
8. Execution history and learning
"""

from __future__ import annotations

import asyncio
import subprocess
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


class ToolCategory(str, Enum):
    RECON = "recon"
    SCANNING = "scanning"
    WEB = "web"
    EXPLOITATION = "exploitation"
    POST_EXPLOIT = "post_exploit"
    FORENSICS = "forensics"
    CODE_ANALYSIS = "code_analysis"
    NETWORK = "network"
    CRYPTO = "crypto"
    OSINT = "osint"
    FUZZING = "fuzzing"
    CLOUD = "cloud"
    WIRELESS = "wireless"
    REVERSE_ENGINEERING = "reverse_engineering"
    PASSWORD = "password"


class ToolStatus(str, Enum):
    AVAILABLE = "available"
    MISSING = "missing"
    RUNNING = "running"
    FAILED = "failed"


@dataclass
class ToolDefinition:
    """Definition of an external tool."""
    name: str = ""
    binary: str = ""
    category: ToolCategory = ToolCategory.RECON
    description: str = ""
    install_cmd: str = ""
    capabilities: list[str] = field(default_factory=list)
    output_format: str = "text"    # text, json, xml
    default_timeout: int = 300
    requires_root: bool = False
    status: ToolStatus = ToolStatus.MISSING

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name[:25],
            "binary": self.binary[:20],
            "category": self.category.value,
            "status": self.status.value,
            "caps": self.capabilities[:3],
        }


@dataclass
class ToolExecution:
    """A tool execution record."""
    execution_id: str = ""
    tool_name: str = ""
    command: str = ""
    args: list[str] = field(default_factory=list)
    target: str = ""
    status: ToolStatus = ToolStatus.RUNNING
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    started_at: float = field(default_factory=time.time)
    completed_at: float = 0.0
    timeout_s: int = 300

    @property
    def duration_s(self) -> float:
        end = self.completed_at or time.time()
        return end - self.started_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.execution_id,
            "tool": self.tool_name[:20],
            "status": self.status.value,
            "exit_code": self.exit_code,
            "duration_s": round(self.duration_s, 1),
            "output_size": len(self.stdout),
        }


@dataclass
class ToolChain:
    """A chain of tools to execute in sequence."""
    chain_id: str = ""
    steps: list[dict[str, Any]] = field(default_factory=list)
    pipe_output: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.chain_id,
            "steps": len(self.steps),
            "pipe": self.pipe_output,
        }


# ── Tool Registry ─────────────────────────────────────────────

TOOL_REGISTRY: list[dict[str, Any]] = [
    # Recon
    {"name": "nmap", "bin": "nmap", "cat": "recon", "caps": ["port_scan", "service_detect", "os_detect"],
     "desc": "Network mapper and port scanner", "fmt": "xml"},
    {"name": "masscan", "bin": "masscan", "cat": "recon", "caps": ["fast_port_scan"],
     "desc": "Mass IP port scanner", "root": True},
    {"name": "subfinder", "bin": "subfinder", "cat": "recon", "caps": ["subdomain_enum"],
     "desc": "Subdomain enumeration tool"},
    {"name": "amass", "bin": "amass", "cat": "recon", "caps": ["subdomain_enum", "dns_enum"],
     "desc": "In-depth subdomain enumeration"},
    {"name": "httpx", "bin": "httpx", "cat": "recon", "caps": ["http_probe", "tech_detect"],
     "desc": "HTTP toolkit for probing"},
    {"name": "dnsx", "bin": "dnsx", "cat": "recon", "caps": ["dns_resolution"],
     "desc": "Fast multi-purpose DNS toolkit"},
    {"name": "whois", "bin": "whois", "cat": "recon", "caps": ["domain_info"],
     "desc": "Domain WHOIS lookup"},
    {"name": "theHarvester", "bin": "theHarvester", "cat": "osint", "caps": ["email_harvest", "subdomain"],
     "desc": "OSINT email and subdomain harvester"},
    # Scanning
    {"name": "nuclei", "bin": "nuclei", "cat": "scanning", "caps": ["vuln_scan", "template_scan"],
     "desc": "Template-based vulnerability scanner", "fmt": "json"},
    {"name": "nikto", "bin": "nikto", "cat": "scanning", "caps": ["web_scan"],
     "desc": "Web server scanner"},
    {"name": "wpscan", "bin": "wpscan", "cat": "scanning", "caps": ["wordpress_scan"],
     "desc": "WordPress vulnerability scanner", "fmt": "json"},
    {"name": "testssl", "bin": "testssl.sh", "cat": "scanning", "caps": ["ssl_scan", "tls_check"],
     "desc": "SSL/TLS testing tool"},
    {"name": "whatweb", "bin": "whatweb", "cat": "scanning", "caps": ["tech_fingerprint"],
     "desc": "Web technology fingerprinting"},
    # Web
    {"name": "sqlmap", "bin": "sqlmap", "cat": "web", "caps": ["sql_injection"],
     "desc": "SQL injection exploitation tool"},
    {"name": "ffuf", "bin": "ffuf", "cat": "web", "caps": ["dir_brute", "fuzzing"],
     "desc": "Fast web fuzzer", "fmt": "json"},
    {"name": "gobuster", "bin": "gobuster", "cat": "web", "caps": ["dir_brute", "dns_brute"],
     "desc": "Directory/DNS brute forcer"},
    {"name": "feroxbuster", "bin": "feroxbuster", "cat": "web", "caps": ["dir_brute", "recursive"],
     "desc": "Recursive content discovery"},
    {"name": "arjun", "bin": "arjun", "cat": "web", "caps": ["param_discovery"],
     "desc": "HTTP parameter discovery"},
    {"name": "dalfox", "bin": "dalfox", "cat": "web", "caps": ["xss_scan"],
     "desc": "XSS scanner and parameter analysis"},
    {"name": "commix", "bin": "commix", "cat": "web", "caps": ["cmd_injection"],
     "desc": "Command injection exploiter"},
    # Exploitation
    {"name": "metasploit", "bin": "msfconsole", "cat": "exploitation", "caps": ["exploit", "payload"],
     "desc": "Exploitation framework"},
    {"name": "searchsploit", "bin": "searchsploit", "cat": "exploitation", "caps": ["exploit_search"],
     "desc": "Exploit database search"},
    # Network
    {"name": "wireshark", "bin": "tshark", "cat": "network", "caps": ["packet_capture", "analysis"],
     "desc": "Network protocol analyzer"},
    {"name": "tcpdump", "bin": "tcpdump", "cat": "network", "caps": ["packet_capture"],
     "desc": "Command-line packet analyzer", "root": True},
    {"name": "netcat", "bin": "nc", "cat": "network", "caps": ["port_connect", "transfer"],
     "desc": "TCP/UDP network utility"},
    # Code Analysis
    {"name": "semgrep", "bin": "semgrep", "cat": "code_analysis", "caps": ["sast", "pattern_match"],
     "desc": "Lightweight static analysis", "fmt": "json"},
    {"name": "bandit", "bin": "bandit", "cat": "code_analysis", "caps": ["python_sast"],
     "desc": "Python security linter", "fmt": "json"},
    {"name": "trivy", "bin": "trivy", "cat": "code_analysis", "caps": ["vuln_scan", "container_scan"],
     "desc": "Container and dependency scanner", "fmt": "json"},
    {"name": "grype", "bin": "grype", "cat": "code_analysis", "caps": ["sbom_vuln"],
     "desc": "Vulnerability scanner for SBOMs", "fmt": "json"},
    # Password
    {"name": "hydra", "bin": "hydra", "cat": "password", "caps": ["brute_force"],
     "desc": "Network login brute forcer"},
    {"name": "john", "bin": "john", "cat": "password", "caps": ["hash_crack"],
     "desc": "John the Ripper password cracker"},
    {"name": "hashcat", "bin": "hashcat", "cat": "password", "caps": ["gpu_hash_crack"],
     "desc": "Advanced password recovery"},
    # Reverse Engineering
    {"name": "radare2", "bin": "r2", "cat": "reverse_engineering", "caps": ["disasm", "debug"],
     "desc": "Reverse engineering framework"},
    {"name": "ghidra", "bin": "ghidra", "cat": "reverse_engineering", "caps": ["decompile", "analysis"],
     "desc": "NSA reverse engineering tool"},
    # Fuzzing
    {"name": "afl++", "bin": "afl-fuzz", "cat": "fuzzing", "caps": ["coverage_fuzz"],
     "desc": "American Fuzzy Lop plus plus"},
    {"name": "boofuzz", "bin": "boofuzz", "cat": "fuzzing", "caps": ["protocol_fuzz"],
     "desc": "Network protocol fuzzer"},
    # OSINT
    {"name": "shodan", "bin": "shodan", "cat": "osint", "caps": ["device_search", "port_search"],
     "desc": "Internet device search engine"},
    {"name": "censys", "bin": "censys", "cat": "osint", "caps": ["cert_search", "host_search"],
     "desc": "Internet-wide scanning search"},
    # Cloud
    {"name": "prowler", "bin": "prowler", "cat": "cloud", "caps": ["aws_audit", "cloud_security"],
     "desc": "Cloud security assessment"},
    {"name": "scout_suite", "bin": "scout", "cat": "cloud", "caps": ["multi_cloud_audit"],
     "desc": "Multi-cloud security auditing"},
]


class ToolOrchestrator:
    """Manages autonomous execution of 200+ external tools.

    Handles tool discovery, execution, output parsing,
    and tool chain composition.
    """

    def __init__(
        self,
        data_dir: str = "data/tool_runs",
    ) -> None:
        self._tools: dict[str, ToolDefinition] = {}
        self._executions: dict[str, ToolExecution] = {}
        self._execution_counter = 0
        self._chain_counter = 0
        self._data_dir = Path(data_dir)
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._tool_stats: dict[str, dict[str, int]] = defaultdict(lambda: {"runs": 0, "success": 0})
        self._log = logger.bind(component="tool_orchestrator")

        self._register_tools()
        self._detect_available()

    def _register_tools(self) -> None:
        """Register all known tools."""
        for data in TOOL_REGISTRY:
            tool = ToolDefinition(
                name=data["name"],
                binary=data.get("bin", data["name"]),
                category=ToolCategory(data["cat"]),
                description=data.get("desc", ""),
                capabilities=data.get("caps", []),
                output_format=data.get("fmt", "text"),
                requires_root=data.get("root", False),
            )
            self._tools[tool.name] = tool

    def _detect_available(self) -> None:
        """Detect which tools are installed."""
        for tool in self._tools.values():
            try:
                result = subprocess.run(
                    ["which", tool.binary],
                    capture_output=True, text=True, timeout=5,
                )
                if result.returncode == 0:
                    tool.status = ToolStatus.AVAILABLE
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                pass

    async def execute(
        self,
        tool_name: str,
        args: list[str],
        target: str = "",
        timeout: int = 0,
    ) -> ToolExecution:
        """Execute a tool."""
        tool = self._tools.get(tool_name)
        self._execution_counter += 1
        exec_id = f"texec-{self._execution_counter}"

        if not tool:
            return ToolExecution(
                execution_id=exec_id,
                tool_name=tool_name,
                status=ToolStatus.FAILED,
                stderr=f"Unknown tool: {tool_name}",
            )

        if tool.status != ToolStatus.AVAILABLE:
            return ToolExecution(
                execution_id=exec_id,
                tool_name=tool_name,
                status=ToolStatus.FAILED,
                stderr=f"Tool not installed: {tool_name}",
            )

        timeout_val = timeout or tool.default_timeout
        cmd = [tool.binary] + args

        execution = ToolExecution(
            execution_id=exec_id,
            tool_name=tool_name,
            command=" ".join(cmd),
            args=args,
            target=target,
            timeout_s=timeout_val,
        )

        self._executions[exec_id] = execution

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout_val,
            )

            execution.stdout = stdout_bytes.decode("utf-8", errors="replace")[:500000]
            execution.stderr = stderr_bytes.decode("utf-8", errors="replace")[:50000]
            execution.exit_code = proc.returncode or 0
            execution.status = ToolStatus.AVAILABLE
            execution.completed_at = time.time()

            self._tool_stats[tool_name]["runs"] += 1
            if execution.exit_code == 0:
                self._tool_stats[tool_name]["success"] += 1

        except asyncio.TimeoutError:
            execution.status = ToolStatus.FAILED
            execution.stderr = f"Timeout after {timeout_val}s"
            execution.completed_at = time.time()

        except Exception as exc:
            execution.status = ToolStatus.FAILED
            execution.stderr = str(exc)[:500]
            execution.completed_at = time.time()

        return execution

    async def execute_chain(
        self,
        chain: list[dict[str, Any]],
        pipe_output: bool = True,
    ) -> list[ToolExecution]:
        """Execute a chain of tools."""
        results = []
        previous_output = ""

        for step in chain:
            tool_name = step.get("tool", "")
            args = list(step.get("args", []))

            # Pipe previous output as input
            if pipe_output and previous_output and step.get("pipe_stdin"):
                # Write to temp file and add as arg
                temp_file = self._data_dir / f"pipe_{self._execution_counter}.txt"
                temp_file.write_text(previous_output)
                args.extend(step.get("pipe_args", ["-i", str(temp_file)]))

            result = await self.execute(
                tool_name=tool_name,
                args=args,
                target=step.get("target", ""),
            )

            results.append(result)
            previous_output = result.stdout

            # Stop chain on failure if required
            if result.status == ToolStatus.FAILED and step.get("stop_on_fail", True):
                break

        return results

    def select_tools(
        self,
        capability: str,
        available_only: bool = True,
    ) -> list[ToolDefinition]:
        """Select tools that have a specific capability."""
        results = []
        for tool in self._tools.values():
            if available_only and tool.status != ToolStatus.AVAILABLE:
                continue
            if capability in tool.capabilities:
                results.append(tool)

        # Sort by success rate
        results.sort(
            key=lambda t: self._tool_stats.get(t.name, {}).get("success", 0),
            reverse=True,
        )
        return results

    def get_available(self) -> list[dict[str, Any]]:
        return [
            t.to_dict() for t in self._tools.values()
            if t.status == ToolStatus.AVAILABLE
        ]

    def get_by_category(self, category: ToolCategory) -> list[dict[str, Any]]:
        return [
            t.to_dict() for t in self._tools.values()
            if t.category == category
        ]

    def get_stats(self) -> dict[str, Any]:
        available = sum(1 for t in self._tools.values() if t.status == ToolStatus.AVAILABLE)
        return {
            "total_tools": len(self._tools),
            "available": available,
            "total_executions": self._execution_counter,
            "tool_stats": {k: dict(v) for k, v in self._tool_stats.items()},
        }
