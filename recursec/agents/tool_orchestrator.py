"""Tool orchestrator — manages external tool execution.

Handles the full lifecycle of external tool usage:
1. Tool availability detection
2. Command construction with parameters
3. Execution with timeout/sandbox
4. Output capture and parsing
5. Tool chaining (output of one → input of next)
6. Parallel execution of independent tools
7. Result caching
"""

from __future__ import annotations

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
    NETWORK = "network"
    EXPLOIT = "exploit"
    POST_EXPLOIT = "post_exploit"
    CODE_ANALYSIS = "code_analysis"
    OSINT = "osint"
    CLOUD = "cloud"
    CONTAINER = "container"
    WIRELESS = "wireless"
    CRYPTO = "crypto"
    FORENSICS = "forensics"
    FUZZING = "fuzzing"
    REVERSE_ENG = "reverse_eng"
    PASSWORD = "password"
    UTILITY = "utility"


class ToolStatus(str, Enum):
    AVAILABLE = "available"
    NOT_INSTALLED = "not_installed"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


class OutputFormat(str, Enum):
    TEXT = "text"
    JSON = "json"
    XML = "xml"
    CSV = "csv"
    BINARY = "binary"


@dataclass
class ToolSpec:
    """Specification for an external tool."""
    name: str = ""
    binary: str = ""
    category: ToolCategory = ToolCategory.UTILITY
    description: str = ""
    install_cmd: str = ""
    check_cmd: str = ""
    output_format: OutputFormat = OutputFormat.TEXT
    timeout_s: int = 300
    needs_root: bool = False
    dangerous: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "cat": self.category.value[:8],
            "fmt": self.output_format.value[:4],
        }


@dataclass
class ToolExecution:
    """A single tool execution."""
    exec_id: str = ""
    tool_name: str = ""
    command: str = ""
    status: ToolStatus = ToolStatus.RUNNING
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    parsed_output: dict[str, Any] = field(default_factory=dict)
    started_at: float = 0.0
    completed_at: float = 0.0
    timeout_s: int = 300

    @property
    def duration_s(self) -> float:
        if self.completed_at:
            return self.completed_at - self.started_at
        if self.started_at:
            return time.time() - self.started_at
        return 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.exec_id[:8],
            "tool": self.tool_name[:12],
            "status": self.status.value[:8],
            "exit": self.exit_code,
            "time": f"{self.duration_s:.1f}s",
        }


@dataclass
class ToolChain:
    """A chain of tools where output flows forward."""
    chain_id: str = ""
    steps: list[str] = field(default_factory=list)
    current_step: int = 0
    results: list[ToolExecution] = field(default_factory=list)
    status: ToolStatus = ToolStatus.RUNNING

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.chain_id[:8],
            "steps": len(self.steps),
            "current": self.current_step,
            "status": self.status.value[:8],
        }


# Comprehensive tool registry
TOOL_REGISTRY: dict[str, dict[str, Any]] = {
    # Recon
    "nmap": {
        "binary": "nmap", "category": "recon",
        "desc": "Network mapper and port scanner",
        "install": "apt install -y nmap",
        "check": "nmap --version",
        "output": "xml",
        "timeout": 600,
        "templates": {
            "quick_scan": "nmap -sV -sC -T4 {target}",
            "full_scan": "nmap -sV -sC -p- -T4 {target}",
            "udp_scan": "nmap -sU --top-ports 100 {target}",
            "stealth": "nmap -sS -T2 {target}",
            "scripts": "nmap --script={scripts} {target}",
            "os_detect": "nmap -O -sV {target}",
            "vuln_scan": "nmap --script=vuln {target}",
        },
    },
    "masscan": {
        "binary": "masscan", "category": "recon",
        "desc": "Fastest port scanner",
        "install": "apt install -y masscan",
        "check": "masscan --version",
        "output": "json",
        "timeout": 300,
        "templates": {
            "fast": "masscan {target} -p1-65535 --rate=10000",
            "top_ports": "masscan {target} --top-ports 1000",
        },
    },
    "subfinder": {
        "binary": "subfinder", "category": "recon",
        "desc": "Subdomain discovery",
        "install": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "check": "subfinder -version",
        "output": "text",
        "timeout": 120,
        "templates": {
            "basic": "subfinder -d {domain} -silent",
            "recursive": "subfinder -d {domain} -recursive -silent",
        },
    },
    "httpx": {
        "binary": "httpx", "category": "recon",
        "desc": "HTTP probing and tech detection",
        "install": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "check": "httpx -version",
        "output": "json",
        "timeout": 120,
        "templates": {
            "probe": "httpx -l {input} -json -sc -cl -ct -title -tech-detect",
        },
    },
    "amass": {
        "binary": "amass", "category": "recon",
        "desc": "Attack surface mapping",
        "install": "go install -v github.com/owasp-amass/amass/v4/...@master",
        "check": "amass version",
        "output": "json",
        "timeout": 600,
        "templates": {
            "enum": "amass enum -d {domain}",
            "passive": "amass enum -passive -d {domain}",
        },
    },
    # Web vulnerability scanners
    "nuclei": {
        "binary": "nuclei", "category": "scanner",
        "desc": "Template-based vulnerability scanner",
        "install": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "check": "nuclei -version",
        "output": "json",
        "timeout": 600,
        "templates": {
            "default": "nuclei -u {target} -json",
            "critical": "nuclei -u {target} -severity critical,high -json",
            "cves": "nuclei -u {target} -t cves/ -json",
            "custom": "nuclei -u {target} -t {template} -json",
        },
    },
    "sqlmap": {
        "binary": "sqlmap", "category": "web",
        "desc": "SQL injection tool",
        "install": "pip install sqlmap",
        "check": "sqlmap --version",
        "output": "text",
        "timeout": 600,
        "dangerous": True,
        "templates": {
            "test": "sqlmap -u '{url}' --batch --level=3 --risk=2",
            "dump": "sqlmap -u '{url}' --batch --dump",
            "forms": "sqlmap -u '{url}' --forms --batch",
        },
    },
    "ffuf": {
        "binary": "ffuf", "category": "web",
        "desc": "Web fuzzer",
        "install": "go install github.com/ffuf/ffuf/v2@latest",
        "check": "ffuf -V",
        "output": "json",
        "timeout": 300,
        "templates": {
            "dirs": "ffuf -u {url}/FUZZ -w {wordlist} -mc 200,301,302,403",
            "params": "ffuf -u {url}?FUZZ=test -w {wordlist}",
            "vhosts": "ffuf -u {url} -H 'Host: FUZZ.{domain}' -w {wordlist}",
        },
    },
    "nikto": {
        "binary": "nikto", "category": "scanner",
        "desc": "Web server scanner",
        "install": "apt install -y nikto",
        "check": "nikto -Version",
        "output": "text",
        "timeout": 600,
        "templates": {
            "scan": "nikto -h {target}",
            "ssl": "nikto -h {target} -ssl",
        },
    },
    # Code analysis
    "semgrep": {
        "binary": "semgrep", "category": "code_analysis",
        "desc": "Static analysis",
        "install": "pip install semgrep",
        "check": "semgrep --version",
        "output": "json",
        "timeout": 300,
        "templates": {
            "auto": "semgrep --config=auto {path} --json",
            "security": "semgrep --config=p/security-audit {path} --json",
        },
    },
    "bandit": {
        "binary": "bandit", "category": "code_analysis",
        "desc": "Python security linter",
        "install": "pip install bandit",
        "check": "bandit --version",
        "output": "json",
        "timeout": 120,
        "templates": {
            "scan": "bandit -r {path} -f json",
        },
    },
    "gitleaks": {
        "binary": "gitleaks", "category": "code_analysis",
        "desc": "Secret scanner for git repos",
        "install": "go install github.com/gitleaks/gitleaks/v8@latest",
        "check": "gitleaks version",
        "output": "json",
        "timeout": 120,
        "templates": {
            "detect": "gitleaks detect -s {path} --report-format json",
        },
    },
    "trufflehog": {
        "binary": "trufflehog", "category": "code_analysis",
        "desc": "Credential scanner",
        "install": "pip install trufflehog",
        "check": "trufflehog --version",
        "output": "json",
        "timeout": 120,
        "templates": {
            "git": "trufflehog git file://{path} --json",
        },
    },
    # Network
    "responder": {
        "binary": "responder", "category": "network",
        "desc": "LLMNR/NBT-NS/mDNS poisoner",
        "install": "apt install -y responder",
        "check": "responder --version",
        "output": "text",
        "timeout": 300,
        "needs_root": True,
    },
    "crackmapexec": {
        "binary": "crackmapexec", "category": "network",
        "desc": "Network security assessment",
        "install": "pip install crackmapexec",
        "check": "crackmapexec --version",
        "output": "text",
        "timeout": 300,
        "templates": {
            "smb": "crackmapexec smb {target}",
            "ldap": "crackmapexec ldap {target}",
            "winrm": "crackmapexec winrm {target}",
        },
    },
    "bettercap": {
        "binary": "bettercap", "category": "network",
        "desc": "Network attack and monitoring",
        "install": "apt install -y bettercap",
        "check": "bettercap -version",
        "output": "text",
        "timeout": 300,
        "needs_root": True,
    },
    # Cloud
    "prowler": {
        "binary": "prowler", "category": "cloud",
        "desc": "AWS/Azure/GCP security auditor",
        "install": "pip install prowler",
        "check": "prowler -v",
        "output": "json",
        "timeout": 600,
        "templates": {
            "aws": "prowler aws --json",
            "azure": "prowler azure --json",
            "gcp": "prowler gcp --json",
        },
    },
    "scoutsuite": {
        "binary": "scout", "category": "cloud",
        "desc": "Multi-cloud security auditing",
        "install": "pip install scoutsuite",
        "check": "scout --version",
        "output": "json",
        "timeout": 600,
    },
    "trivy": {
        "binary": "trivy", "category": "container",
        "desc": "Container and IaC scanner",
        "install": "apt install -y trivy",
        "check": "trivy version",
        "output": "json",
        "timeout": 300,
        "templates": {
            "image": "trivy image {image} -f json",
            "fs": "trivy fs {path} -f json",
            "config": "trivy config {path} -f json",
        },
    },
    # Password
    "hydra": {
        "binary": "hydra", "category": "password",
        "desc": "Online password brute-forcer",
        "install": "apt install -y hydra",
        "check": "hydra -V",
        "output": "text",
        "timeout": 600,
        "dangerous": True,
        "templates": {
            "ssh": "hydra -L {users} -P {passwords} ssh://{target}",
            "http": "hydra -L {users} -P {passwords} {target} http-post-form '{form}'",
        },
    },
    "hashcat": {
        "binary": "hashcat", "category": "password",
        "desc": "Password recovery",
        "install": "apt install -y hashcat",
        "check": "hashcat --version",
        "output": "text",
        "timeout": 3600,
    },
    "john": {
        "binary": "john", "category": "password",
        "desc": "John the Ripper",
        "install": "apt install -y john",
        "check": "john --version",
        "output": "text",
        "timeout": 3600,
    },
    # OSINT
    "theHarvester": {
        "binary": "theHarvester", "category": "osint",
        "desc": "Email and subdomain gathering",
        "install": "pip install theHarvester",
        "check": "theHarvester -h",
        "output": "json",
        "timeout": 120,
        "templates": {
            "all": "theHarvester -d {domain} -b all",
        },
    },
    "sherlock": {
        "binary": "sherlock", "category": "osint",
        "desc": "Username search across platforms",
        "install": "pip install sherlock-project",
        "check": "sherlock --version",
        "output": "text",
        "timeout": 120,
    },
    # Forensics
    "volatility3": {
        "binary": "vol", "category": "forensics",
        "desc": "Memory forensics framework",
        "install": "pip install volatility3",
        "check": "vol --help",
        "output": "text",
        "timeout": 600,
    },
    "yara": {
        "binary": "yara", "category": "forensics",
        "desc": "Pattern matching for malware",
        "install": "apt install -y yara",
        "check": "yara --version",
        "output": "text",
        "timeout": 120,
    },
    # Reverse engineering
    "ghidra": {
        "binary": "ghidra", "category": "reverse_eng",
        "desc": "NSA reverse engineering tool",
        "install": "apt install -y ghidra",
        "check": "ghidra --version",
        "output": "text",
        "timeout": 600,
    },
    "radare2": {
        "binary": "r2", "category": "reverse_eng",
        "desc": "Reverse engineering framework",
        "install": "apt install -y radare2",
        "check": "r2 -v",
        "output": "text",
        "timeout": 300,
    },
    # Fuzzing
    "afl": {
        "binary": "afl-fuzz", "category": "fuzzing",
        "desc": "AFL++ fuzzer",
        "install": "apt install -y afl++",
        "check": "afl-fuzz --version",
        "output": "text",
        "timeout": 3600,
    },
}

# Common tool chains
TOOL_CHAINS: dict[str, list[dict[str, str]]] = {
    "web_recon": [
        {"tool": "subfinder", "template": "basic", "output": "subdomains.txt"},
        {"tool": "httpx", "template": "probe", "input": "subdomains.txt"},
        {"tool": "nuclei", "template": "default", "input": "httpx_output.txt"},
    ],
    "network_recon": [
        {"tool": "masscan", "template": "fast"},
        {"tool": "nmap", "template": "full_scan"},
    ],
    "code_audit": [
        {"tool": "gitleaks", "template": "detect"},
        {"tool": "semgrep", "template": "security"},
        {"tool": "bandit", "template": "scan"},
    ],
    "cloud_audit": [
        {"tool": "prowler", "template": "aws"},
        {"tool": "trivy", "template": "config"},
    ],
}


class ToolOrchestrator:
    """Orchestrate external tool execution.

    Manages discovery, execution, output parsing,
    chaining, and caching for all 200+ tools.
    """

    def __init__(self) -> None:
        self._executions: dict[str, ToolExecution] = {}
        self._chains: dict[str, ToolChain] = {}
        self._exec_counter = 0
        self._chain_counter = 0
        self._tool_status: dict[str, ToolStatus] = {}
        self._cache: dict[str, dict[str, Any]] = {}
        self._log = logger.bind(component="tool_orch")

    def get_tool_spec(self, name: str) -> ToolSpec | None:
        """Get tool specification."""
        data = TOOL_REGISTRY.get(name)
        if not data:
            return None

        return ToolSpec(
            name=name,
            binary=data.get("binary", name),
            category=ToolCategory(data.get("category", "utility")),
            description=data.get("desc", ""),
            install_cmd=data.get("install", ""),
            check_cmd=data.get("check", ""),
            output_format=OutputFormat(data.get("output", "text")),
            timeout_s=data.get("timeout", 300),
            needs_root=data.get("needs_root", False),
            dangerous=data.get("dangerous", False),
        )

    def build_command(
        self,
        tool_name: str,
        template: str = "",
        params: dict[str, str] | None = None,
    ) -> str:
        """Build a tool command from template."""
        data = TOOL_REGISTRY.get(tool_name, {})
        templates = data.get("templates", {})

        cmd_template = templates.get(template, "")
        if not cmd_template:
            return f"{data.get('binary', tool_name)}"

        cmd = cmd_template
        if params:
            for key, value in params.items():
                cmd = cmd.replace(f"{{{key}}}", value)

        return cmd

    def create_execution(
        self,
        tool_name: str,
        command: str,
    ) -> ToolExecution:
        """Create a tool execution record."""
        self._exec_counter += 1

        data = TOOL_REGISTRY.get(tool_name, {})
        timeout = data.get("timeout", 300)

        exe = ToolExecution(
            exec_id=f"exec-{self._exec_counter}",
            tool_name=tool_name,
            command=command,
            status=ToolStatus.RUNNING,
            started_at=time.time(),
            timeout_s=timeout,
        )
        self._executions[exe.exec_id] = exe
        return exe

    def complete_execution(
        self,
        exec_id: str,
        stdout: str = "",
        stderr: str = "",
        exit_code: int = 0,
        parsed: dict[str, Any] | None = None,
    ) -> None:
        """Complete a tool execution."""
        exe = self._executions.get(exec_id)
        if exe:
            exe.status = (
                ToolStatus.COMPLETED if exit_code == 0
                else ToolStatus.FAILED
            )
            exe.stdout = stdout
            exe.stderr = stderr
            exe.exit_code = exit_code
            exe.parsed_output = parsed or {}
            exe.completed_at = time.time()

    def create_chain(
        self,
        chain_name: str = "",
    ) -> ToolChain:
        """Create a tool chain from predefined chains."""
        self._chain_counter += 1

        steps = []
        chain_data = TOOL_CHAINS.get(chain_name, [])
        for step in chain_data:
            steps.append(step.get("tool", ""))

        chain = ToolChain(
            chain_id=f"chain-{self._chain_counter}",
            steps=steps,
        )
        self._chains[chain.chain_id] = chain
        return chain

    def get_tools_by_category(
        self,
        category: str,
    ) -> list[str]:
        """Get all tools in a category."""
        return [
            name for name, data in TOOL_REGISTRY.items()
            if data.get("category") == category
        ]

    def search_tools(self, query: str) -> list[str]:
        """Search for tools by name or description."""
        lower = query.lower()
        results: list[str] = []
        for name, data in TOOL_REGISTRY.items():
            if lower in name.lower() or lower in data.get("desc", "").lower():
                results.append(name)
        return results

    def build_tool_prompt(self, tools: list[str] | None = None) -> str:
        """Build tool availability prompt for LLM."""
        lines = ["## Available Tools\n"]

        target_tools = tools or list(TOOL_REGISTRY.keys())
        by_cat: dict[str, list[str]] = {}

        for name in target_tools:
            data = TOOL_REGISTRY.get(name, {})
            cat = data.get("category", "utility")
            by_cat.setdefault(cat, []).append(name)

        for cat, names in sorted(by_cat.items()):
            lines.append(f"### {cat.upper()}")
            for name in names:
                data = TOOL_REGISTRY.get(name, {})
                lines.append(f"  - {name}: {data.get('desc', '')[:40]}")
            lines.append("")

        lines.append(f"Total: {len(target_tools)} tools")
        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        completed = sum(
            1 for e in self._executions.values()
            if e.status == ToolStatus.COMPLETED
        )
        failed = sum(
            1 for e in self._executions.values()
            if e.status == ToolStatus.FAILED
        )

        return {
            "registered_tools": len(TOOL_REGISTRY),
            "executions": len(self._executions),
            "completed": completed,
            "failed": failed,
            "chains": len(self._chains),
        }
