"""Task execution pipeline — executes full security assessment tasks.

Connects all components into an end-to-end pipeline:
Intent → Plan → KB Load → Prompt → LLM → Tool → Analyze → Validate → Learn → Report

This is the module that makes the agent actually DO things.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ExecutionPhase(str, Enum):
    RECON = "recon"
    SCANNING = "scanning"
    ENUMERATION = "enumeration"
    VULNERABILITY = "vulnerability"
    EXPLOITATION = "exploitation"
    POST_EXPLOIT = "post_exploit"
    VALIDATION = "validation"
    REPORTING = "reporting"


class ToolCategory(str, Enum):
    RECON = "recon"
    SCANNER = "scanner"
    WEB = "web"
    NETWORK = "network"
    EXPLOIT = "exploit"
    CODE = "code"
    CLOUD = "cloud"
    CRYPTO = "crypto"
    OSINT = "osint"
    FORENSICS = "forensics"


@dataclass
class ToolSpec:
    """Specification for a tool to execute."""
    name: str = ""
    category: ToolCategory = ToolCategory.SCANNER
    command: str = ""
    args: dict[str, str] = field(default_factory=dict)
    timeout_s: int = 300
    output_parser: str = ""
    requires_root: bool = False
    requires_network: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "category": self.category.value, "timeout": self.timeout_s}


@dataclass
class ToolResult:
    """Result from tool execution."""
    tool_name: str = ""
    command: str = ""
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    duration_s: float = 0.0
    parsed_output: dict[str, Any] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)
    success: bool = True
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool_name[:15],
            "exit": self.exit_code,
            "findings": len(self.findings),
            "duration": f"{self.duration_s:.1f}s",
            "ok": self.success,
        }


@dataclass
class PhaseResult:
    """Result from executing a phase."""
    phase: ExecutionPhase = ExecutionPhase.RECON
    tools_executed: list[ToolResult] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    new_targets: list[str] = field(default_factory=list)
    duration_s: float = 0.0
    tokens_used: int = 0
    success: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "phase": self.phase.value[:10],
            "tools": len(self.tools_executed),
            "findings": len(self.findings),
            "new_targets": len(self.new_targets),
            "ok": self.success,
        }


@dataclass
class ExecutionPlan:
    """A full execution plan for a security task."""
    plan_id: str = ""
    target: str = ""
    scope: list[str] = field(default_factory=list)
    phases: list[ExecutionPhase] = field(default_factory=list)
    phase_tools: dict[str, list[str]] = field(default_factory=dict)
    phase_kbs: dict[str, list[str]] = field(default_factory=dict)
    phase_models: dict[str, str] = field(default_factory=dict)
    estimated_duration_s: float = 0.0
    token_budget: int = 32768
    priority_targets: list[str] = field(default_factory=list)
    constraints: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.plan_id[:8],
            "target": self.target[:20],
            "phases": len(self.phases),
            "budget": self.token_budget,
        }


# Default phase sequences for different task types
TASK_PHASE_MAP: dict[str, list[ExecutionPhase]] = {
    "full_pentest": [ExecutionPhase.RECON, ExecutionPhase.SCANNING, ExecutionPhase.ENUMERATION, ExecutionPhase.VULNERABILITY, ExecutionPhase.EXPLOITATION, ExecutionPhase.POST_EXPLOIT, ExecutionPhase.VALIDATION, ExecutionPhase.REPORTING],
    "web_vuln_scan": [ExecutionPhase.RECON, ExecutionPhase.SCANNING, ExecutionPhase.VULNERABILITY, ExecutionPhase.VALIDATION, ExecutionPhase.REPORTING],
    "recon": [ExecutionPhase.RECON, ExecutionPhase.REPORTING],
    "port_scan": [ExecutionPhase.SCANNING, ExecutionPhase.REPORTING],
    "code_audit": [ExecutionPhase.VULNERABILITY, ExecutionPhase.VALIDATION, ExecutionPhase.REPORTING],
    "cloud_audit": [ExecutionPhase.RECON, ExecutionPhase.SCANNING, ExecutionPhase.VULNERABILITY, ExecutionPhase.REPORTING],
    "network_pentest": [ExecutionPhase.RECON, ExecutionPhase.SCANNING, ExecutionPhase.ENUMERATION, ExecutionPhase.EXPLOITATION, ExecutionPhase.POST_EXPLOIT, ExecutionPhase.REPORTING],
    "red_team": [ExecutionPhase.RECON, ExecutionPhase.SCANNING, ExecutionPhase.ENUMERATION, ExecutionPhase.VULNERABILITY, ExecutionPhase.EXPLOITATION, ExecutionPhase.POST_EXPLOIT, ExecutionPhase.VALIDATION, ExecutionPhase.REPORTING],
    "bug_bounty": [ExecutionPhase.RECON, ExecutionPhase.SCANNING, ExecutionPhase.VULNERABILITY, ExecutionPhase.EXPLOITATION, ExecutionPhase.VALIDATION, ExecutionPhase.REPORTING],
}

# Tools for each phase
PHASE_TOOLS: dict[ExecutionPhase, list[ToolSpec]] = {
    ExecutionPhase.RECON: [
        ToolSpec(name="subfinder", category=ToolCategory.RECON, command="subfinder -d {target} -all -o {output}", timeout_s=120, output_parser="line_list"),
        ToolSpec(name="amass", category=ToolCategory.RECON, command="amass enum -d {target} -passive -o {output}", timeout_s=300, output_parser="line_list"),
        ToolSpec(name="whatweb", category=ToolCategory.RECON, command="whatweb -a 3 {target} --log-json={output}", timeout_s=60, output_parser="json"),
        ToolSpec(name="dig", category=ToolCategory.RECON, command="dig {target} ANY +noall +answer", timeout_s=10, output_parser="dns"),
        ToolSpec(name="whois", category=ToolCategory.RECON, command="whois {target}", timeout_s=15, output_parser="whois"),
    ],
    ExecutionPhase.SCANNING: [
        ToolSpec(name="nmap", category=ToolCategory.SCANNER, command="nmap -sV -sC -O -oX {output} {target}", timeout_s=600, output_parser="nmap_xml", requires_root=True),
        ToolSpec(name="masscan", category=ToolCategory.SCANNER, command="masscan {target} -p1-65535 --rate=1000 -oJ {output}", timeout_s=300, output_parser="json", requires_root=True),
        ToolSpec(name="testssl", category=ToolCategory.SCANNER, command="testssl.sh --jsonfile {output} {target}", timeout_s=120, output_parser="json"),
    ],
    ExecutionPhase.ENUMERATION: [
        ToolSpec(name="ffuf", category=ToolCategory.WEB, command="ffuf -w /usr/share/wordlists/dirb/common.txt -u https://{target}/FUZZ -o {output} -of json", timeout_s=300, output_parser="json"),
        ToolSpec(name="gobuster", category=ToolCategory.WEB, command="gobuster dir -u https://{target} -w /usr/share/wordlists/dirb/common.txt -o {output}", timeout_s=300, output_parser="gobuster"),
        ToolSpec(name="enum4linux", category=ToolCategory.NETWORK, command="enum4linux -a {target}", timeout_s=120, output_parser="text"),
    ],
    ExecutionPhase.VULNERABILITY: [
        ToolSpec(name="nuclei", category=ToolCategory.SCANNER, command="nuclei -u {target} -severity critical,high,medium -o {output} -jsonl", timeout_s=600, output_parser="jsonl"),
        ToolSpec(name="nikto", category=ToolCategory.WEB, command="nikto -h {target} -Format json -output {output}", timeout_s=300, output_parser="json"),
        ToolSpec(name="sqlmap", category=ToolCategory.WEB, command="sqlmap -u '{target}' --batch --level=3 --risk=2 --output-dir={output}", timeout_s=600, output_parser="sqlmap"),
        ToolSpec(name="semgrep", category=ToolCategory.CODE, command="semgrep --config auto --json -o {output} {target}", timeout_s=300, output_parser="json"),
    ],
    ExecutionPhase.EXPLOITATION: [
        ToolSpec(name="metasploit", category=ToolCategory.EXPLOIT, command="msfconsole -x 'search {target}; exit'", timeout_s=60, output_parser="text"),
        ToolSpec(name="sqlmap_exploit", category=ToolCategory.EXPLOIT, command="sqlmap -u '{target}' --batch --dump --level=5 --risk=3", timeout_s=600, output_parser="sqlmap"),
    ],
    ExecutionPhase.POST_EXPLOIT: [
        ToolSpec(name="linpeas", category=ToolCategory.EXPLOIT, command="./linpeas.sh -a", timeout_s=300, output_parser="text"),
        ToolSpec(name="winpeas", category=ToolCategory.EXPLOIT, command="winPEASany.exe quiet fast searchfast", timeout_s=300, output_parser="text"),
    ],
    ExecutionPhase.VALIDATION: [
        ToolSpec(name="curl", category=ToolCategory.WEB, command="curl -sk -o /dev/null -w '%{{http_code}}' {target}", timeout_s=10, output_parser="text"),
    ],
    ExecutionPhase.REPORTING: [],
}

# KB domains needed per phase
PHASE_KB_MAP: dict[ExecutionPhase, list[str]] = {
    ExecutionPhase.RECON: ["dns", "network"],
    ExecutionPhase.SCANNING: ["network", "web_vuln"],
    ExecutionPhase.ENUMERATION: ["web_vuln", "active_directory", "network"],
    ExecutionPhase.VULNERABILITY: ["web_vuln", "xss", "ssrf", "deserialization", "business_logic", "advanced_discovery"],
    ExecutionPhase.EXPLOITATION: ["binary_exploitation", "privesc", "red_team"],
    ExecutionPhase.POST_EXPLOIT: ["lateral_movement", "privesc", "windows", "linux"],
    ExecutionPhase.VALIDATION: ["advanced_discovery"],
    ExecutionPhase.REPORTING: ["threat_intel", "compliance"],
}

# Model selection per phase
PHASE_MODEL_MAP: dict[ExecutionPhase, str] = {
    ExecutionPhase.RECON: "phi-3.5-mini",  # Fast for recon
    ExecutionPhase.SCANNING: "phi-3.5-mini",  # Fast for scanning
    ExecutionPhase.ENUMERATION: "mistral-7b",  # General
    ExecutionPhase.VULNERABILITY: "whiterabbit",  # Security specialist
    ExecutionPhase.EXPLOITATION: "whiterabbit",  # Security specialist
    ExecutionPhase.POST_EXPLOIT: "whiterabbit",  # Security specialist
    ExecutionPhase.VALIDATION: "deepseek-r1",  # Careful reasoning
    ExecutionPhase.REPORTING: "hermes-4-14b",  # Good at writing
}


class TaskExecutor:
    """Executes security assessment tasks end-to-end."""

    def __init__(self) -> None:
        self._plans: list[ExecutionPlan] = []
        self._results: list[PhaseResult] = []
        self._plan_counter = 0
        self._log = logger.bind(component="task_executor")

    def create_plan(
        self,
        target: str,
        task_type: str = "full_pentest",
        token_budget: int = 32768,
        scope: list[str] | None = None,
        constraints: dict[str, Any] | None = None,
    ) -> ExecutionPlan:
        """Create an execution plan for a task."""
        self._plan_counter += 1

        phases = TASK_PHASE_MAP.get(task_type, TASK_PHASE_MAP["full_pentest"])

        phase_tools: dict[str, list[str]] = {}
        phase_kbs: dict[str, list[str]] = {}
        phase_models: dict[str, str] = {}

        for phase in phases:
            tools = PHASE_TOOLS.get(phase, [])
            phase_tools[phase.value] = [t.name for t in tools]
            phase_kbs[phase.value] = PHASE_KB_MAP.get(phase, [])
            phase_models[phase.value] = PHASE_MODEL_MAP.get(phase, "mistral-7b")

        plan = ExecutionPlan(
            plan_id=f"plan-{self._plan_counter}",
            target=target,
            scope=scope or [target],
            phases=phases,
            phase_tools=phase_tools,
            phase_kbs=phase_kbs,
            phase_models=phase_models,
            estimated_duration_s=len(phases) * 120.0,
            token_budget=token_budget,
            constraints=constraints or {},
        )
        self._plans.append(plan)
        return plan

    def get_tools_for_phase(self, phase: ExecutionPhase) -> list[ToolSpec]:
        """Get tool specifications for a phase."""
        return PHASE_TOOLS.get(phase, [])

    def get_kbs_for_phase(self, phase: ExecutionPhase) -> list[str]:
        """Get KB domains for a phase."""
        return PHASE_KB_MAP.get(phase, [])

    def get_model_for_phase(self, phase: ExecutionPhase) -> str:
        """Get recommended model for a phase."""
        return PHASE_MODEL_MAP.get(phase, "mistral-7b")

    def record_phase_result(
        self,
        phase: ExecutionPhase,
        tools_executed: list[ToolResult] | None = None,
        findings: list[dict[str, Any]] | None = None,
        new_targets: list[str] | None = None,
        duration_s: float = 0.0,
        tokens_used: int = 0,
    ) -> PhaseResult:
        """Record results from executing a phase."""
        result = PhaseResult(
            phase=phase,
            tools_executed=tools_executed or [],
            findings=findings or [],
            new_targets=new_targets or [],
            duration_s=duration_s,
            tokens_used=tokens_used,
        )
        self._results.append(result)
        return result

    def get_all_findings(self) -> list[dict[str, Any]]:
        """Get all findings across all phases."""
        findings = []
        for result in self._results:
            findings.extend(result.findings)
        return findings

    def get_execution_summary(self) -> dict[str, Any]:
        """Get summary of all executed phases."""
        return {
            "plans": len(self._plans),
            "phases_executed": len(self._results),
            "total_findings": sum(len(r.findings) for r in self._results),
            "total_tools": sum(len(r.tools_executed) for r in self._results),
            "total_duration": sum(r.duration_s for r in self._results),
            "total_tokens": sum(r.tokens_used for r in self._results),
            "new_targets": sum(len(r.new_targets) for r in self._results),
        }

    def build_executor_prompt(self) -> str:
        """Build LLM prompt with execution state."""
        summary = self.get_execution_summary()
        lines = ["## Task Execution State"]
        lines.append(f"Phases executed: {summary['phases_executed']}")
        lines.append(f"Findings: {summary['total_findings']}")
        lines.append(f"Tools run: {summary['total_tools']}")
        lines.append(f"Duration: {summary['total_duration']:.0f}s")
        return "\n".join(lines)
