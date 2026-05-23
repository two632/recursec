"""Attack chain builder — assembles exploitation paths from agent findings.

An attack chain links:
  Recon → Vuln Discovery → Exploitation → Post-Exploitation → Lateral Movement

Each step references the tools used, evidence gathered, and the
agent that performed the work.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog

from recursec.core.models import AgentTask, AttackChain, Severity, Vulnerability

logger = structlog.get_logger()


class ChainStep:
    """A single step in an attack chain."""

    def __init__(
        self,
        phase: str,
        description: str,
        tool: str = "",
        command: str = "",
        evidence: str = "",
        agent_role: str = "",
        task_id: str = "",
        vulnerabilities: list[Vulnerability] | None = None,
    ):
        self.id = str(uuid.uuid4())[:8]
        self.phase = phase  # recon, vuln_discovery, exploitation, post_exploit, lateral_movement
        self.description = description
        self.tool = tool
        self.command = command
        self.evidence = evidence
        self.agent_role = agent_role
        self.task_id = task_id
        self.vulnerabilities = vulnerabilities or []
        self.timestamp = time.time()
        self.success = False
        self.children: list[ChainStep] = []

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "phase": self.phase,
            "description": self.description,
            "tool": self.tool,
            "command": self.command,
            "evidence": self.evidence[:500],
            "agent_role": self.agent_role,
            "success": self.success,
            "vulnerabilities": [v.model_dump() for v in self.vulnerabilities],
            "children": [c.to_dict() for c in self.children],
        }


class AttackChainBuilder:
    """Builds attack chains from agent findings and tool results.

    The builder:
    1. Collects findings from all agents
    2. Links them by target/component
    3. Identifies exploitation paths
    4. Scores chains by impact and reliability
    """

    def __init__(self):
        self._chains: list[AttackChain] = []
        self._steps: list[ChainStep] = []
        self._findings_by_component: dict[str, list[Vulnerability]] = {}

    def add_finding(self, finding: Vulnerability, agent_role: str = "", task_id: str = "") -> None:
        """Add a finding to the chain builder."""
        component = finding.affected_component or "unknown"
        if component not in self._findings_by_component:
            self._findings_by_component[component] = []
        self._findings_by_component[component].append(finding)

        # Auto-create a chain step
        phase = _infer_phase(agent_role)
        step = ChainStep(
            phase=phase,
            description=finding.title,
            evidence=finding.evidence,
            agent_role=agent_role,
            task_id=task_id,
            vulnerabilities=[finding],
        )
        step.success = finding.validated and not finding.false_positive
        self._steps.append(step)

    def add_tool_result(
        self,
        tool_name: str,
        command: str,
        output: str,
        agent_role: str = "",
        task_id: str = "",
    ) -> None:
        """Add a tool execution result as a chain step."""
        phase = _infer_phase_from_tool(tool_name)
        step = ChainStep(
            phase=phase,
            description=f"Executed {tool_name}",
            tool=tool_name,
            command=command,
            evidence=output[:2000],
            agent_role=agent_role,
            task_id=task_id,
        )
        step.success = True
        self._steps.append(step)

    def build_chains(self) -> list[AttackChain]:
        """Assemble attack chains from collected steps and findings."""
        chains = []

        # Group steps by component
        for component, findings in self._findings_by_component.items():
            if not findings:
                continue

            # Sort by severity for impact scoring
            sorted_findings = sorted(
                findings,
                key=lambda f: ["critical", "high", "medium", "low", "info"].index(f.severity.value)
                if f.severity.value in ["critical", "high", "medium", "low", "info"]
                else 4,
            )

            # Build chain
            chain_steps = []
            for step in self._steps:
                for vuln in step.vulnerabilities:
                    if vuln.affected_component == component:
                        chain_steps.append(
                            AgentTask(
                                agent_role=__import__("recursec.core.models", fromlist=["AgentRole"]).AgentRole.CUSTOM,
                                objective=step.description,
                            )
                        )
                        break

            impact = _compute_impact(sorted_findings)

            chain = AttackChain(
                name=f"Chain: {component}",
                steps=chain_steps,
                vulnerabilities=sorted_findings,
                success=any(f.validated for f in sorted_findings),
                impact=impact,
            )
            chains.append(chain)

        self._chains = chains
        return chains

    def get_summary(self) -> dict[str, Any]:
        """Get a summary of all chains."""
        chains = self.build_chains() if not self._chains else self._chains
        return {
            "total_chains": len(chains),
            "successful_chains": sum(1 for c in chains if c.success),
            "total_findings": sum(len(c.vulnerabilities) for c in chains),
            "critical_findings": sum(
                1 for c in chains for v in c.vulnerabilities if v.severity == Severity.CRITICAL
            ),
            "chains": [
                {
                    "name": c.name,
                    "success": c.success,
                    "impact": c.impact,
                    "vuln_count": len(c.vulnerabilities),
                    "severities": [v.severity.value for v in c.vulnerabilities],
                }
                for c in chains
            ],
        }

    def generate_report_data(self) -> dict[str, Any]:
        """Generate structured data for report generation."""
        chains = self.build_chains() if not self._chains else self._chains
        all_vulns = []
        for chain in chains:
            all_vulns.extend(chain.vulnerabilities)

        # Deduplicate
        seen_ids = set()
        unique_vulns = []
        for v in all_vulns:
            if v.id not in seen_ids:
                seen_ids.add(v.id)
                unique_vulns.append(v)

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        unique_vulns.sort(key=lambda v: severity_order.get(v.severity.value, 4))

        return {
            "chains": [c.model_dump() for c in chains],
            "all_findings": [v.model_dump() for v in unique_vulns],
            "severity_summary": {
                sev: sum(1 for v in unique_vulns if v.severity.value == sev)
                for sev in ["critical", "high", "medium", "low", "info"]
            },
            "validated_count": sum(1 for v in unique_vulns if v.validated),
            "false_positive_count": sum(1 for v in unique_vulns if v.false_positive),
        }


def _infer_phase(agent_role: str) -> str:
    phase_map = {
        "recon": "recon",
        "vuln_scanner": "vuln_discovery",
        "web_scanner": "vuln_discovery",
        "exploit": "exploitation",
        "post_exploit": "post_exploit",
        "code_auditor": "vuln_discovery",
        "network_scanner": "recon",
        "osint": "recon",
        "fuzzer": "vuln_discovery",
        "crypto_analyst": "exploitation",
        "cloud_scanner": "vuln_discovery",
        "wireless_scanner": "recon",
        "forensics": "post_exploit",
    }
    return phase_map.get(agent_role, "unknown")


def _infer_phase_from_tool(tool_name: str) -> str:
    tool_phase_map = {
        "nmap": "recon", "masscan": "recon", "subfinder": "recon", "amass": "recon",
        "nuclei": "vuln_discovery", "nikto": "vuln_discovery", "wpscan": "vuln_discovery",
        "sqlmap": "exploitation", "metasploit": "exploitation",
        "linpeas": "post_exploit", "bloodhound": "post_exploit",
        "hashcat": "exploitation", "hydra": "exploitation",
    }
    return tool_phase_map.get(tool_name, "unknown")


def _compute_impact(findings: list[Vulnerability]) -> str:
    if any(f.severity == Severity.CRITICAL for f in findings):
        return "CRITICAL — Full system compromise possible"
    if any(f.severity == Severity.HIGH for f in findings):
        return "HIGH — Significant security risk"
    if any(f.severity == Severity.MEDIUM for f in findings):
        return "MEDIUM — Moderate security risk"
    return "LOW — Minor security concerns"
