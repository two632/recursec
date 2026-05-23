"""Prompt template engine — assembles agent prompts from components.

Implements:
1. Role-based system prompt templates
2. Task-specific instruction injection
3. Knowledge base integration
4. Tool selection context
5. Few-shot example injection
6. Dynamic prompt assembly
7. Token budget enforcement during assembly
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class PromptRole(str, Enum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


class TaskPhase(str, Enum):
    RECON = "recon"
    SCANNING = "scanning"
    ANALYSIS = "analysis"
    EXPLOITATION = "exploitation"
    VALIDATION = "validation"
    REPORTING = "reporting"
    PLANNING = "planning"
    REASONING = "reasoning"


@dataclass
class PromptMessage:
    """A single message in the prompt."""
    role: PromptRole = PromptRole.USER
    content: str = ""
    token_estimate: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role.value,
            "tokens": self.token_estimate,
        }


@dataclass
class PromptTemplate:
    """A reusable prompt template."""
    template_id: str = ""
    name: str = ""
    phase: TaskPhase = TaskPhase.PLANNING
    system_template: str = ""
    user_template: str = ""
    few_shot_examples: list[dict[str, str]] = field(default_factory=list)
    required_context: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.template_id[:10],
            "name": self.name[:20],
            "phase": self.phase.value,
            "examples": len(self.few_shot_examples),
        }


# ── Base system prompts ──────────────────────────────────────

BASE_SYSTEM_PROMPT = (
    "You are RecurSec, an autonomous security assessment agent. "
    "You analyze targets, discover vulnerabilities, and validate findings. "
    "You have access to security tools and can spawn sub-agents for specialized tasks.\n\n"
    "RULES:\n"
    "1. Only test targets explicitly in scope\n"
    "2. Document all findings with evidence\n"
    "3. Validate findings before reporting\n"
    "4. Use least-privilege tool options\n"
    "5. Stop if scope boundaries are unclear\n"
)

# ── Phase-specific templates ─────────────────────────────────

PHASE_TEMPLATES: dict[str, dict[str, str]] = {
    "recon": {
        "system_extra": (
            "CURRENT PHASE: Reconnaissance\n"
            "OBJECTIVE: Discover the attack surface.\n"
            "APPROACH:\n"
            "1. Enumerate subdomains and DNS records\n"
            "2. Discover open ports and services\n"
            "3. Identify web technologies and frameworks\n"
            "4. Map the network topology\n"
            "5. Collect OSINT data\n"
            "OUTPUT: Structured list of discovered assets."
        ),
        "user_template": (
            "Target: {target}\n"
            "Scope: {scope}\n\n"
            "Begin reconnaissance. Discover all assets, subdomains, "
            "open ports, and services. Report findings structured."
        ),
    },
    "scanning": {
        "system_extra": (
            "CURRENT PHASE: Vulnerability Scanning\n"
            "OBJECTIVE: Identify vulnerabilities in discovered assets.\n"
            "APPROACH:\n"
            "1. Run vulnerability scanners on discovered services\n"
            "2. Check for known CVEs\n"
            "3. Test web applications for OWASP Top 10\n"
            "4. Check SSL/TLS configuration\n"
            "5. Test authentication mechanisms\n"
            "OUTPUT: List of potential vulnerabilities with severity."
        ),
        "user_template": (
            "Assets to scan:\n{assets}\n\n"
            "Run targeted vulnerability scans. "
            "Report each finding with severity, evidence, and affected asset."
        ),
    },
    "analysis": {
        "system_extra": (
            "CURRENT PHASE: Analysis\n"
            "OBJECTIVE: Analyze findings and build attack chains.\n"
            "APPROACH:\n"
            "1. Correlate findings across tools\n"
            "2. Identify attack chains\n"
            "3. Assess exploitability\n"
            "4. Score risk (CVSS where applicable)\n"
            "5. Identify false positives\n"
            "OUTPUT: Prioritized findings with attack chains."
        ),
        "user_template": (
            "Current findings:\n{findings}\n\n"
            "Analyze these findings. Correlate results, identify attack chains, "
            "eliminate false positives, and assess real-world impact."
        ),
    },
    "exploitation": {
        "system_extra": (
            "CURRENT PHASE: Exploitation\n"
            "OBJECTIVE: Validate vulnerabilities through exploitation.\n"
            "APPROACH:\n"
            "1. Develop exploitation strategy for each confirmed vuln\n"
            "2. Execute exploits safely\n"
            "3. Document proof-of-concept\n"
            "4. Assess post-exploitation impact\n"
            "5. Test for lateral movement paths\n"
            "OUTPUT: Exploitation results with proof-of-concept."
        ),
        "user_template": (
            "Confirmed vulnerabilities:\n{vulnerabilities}\n\n"
            "Validate these through controlled exploitation. "
            "For each, provide proof-of-concept and impact assessment."
        ),
    },
    "validation": {
        "system_extra": (
            "CURRENT PHASE: Validation\n"
            "OBJECTIVE: Verify findings using independent methods.\n"
            "APPROACH:\n"
            "1. Re-test each finding with a different tool\n"
            "2. Cross-reference with known CVE databases\n"
            "3. Check for environmental factors\n"
            "4. Verify exploitability conditions\n"
            "5. Classify confidence level\n"
            "OUTPUT: Validated findings with confidence scores."
        ),
        "user_template": (
            "Findings to validate:\n{findings}\n\n"
            "Independently verify each finding. Use different tools and "
            "approaches than the original detection."
        ),
    },
    "planning": {
        "system_extra": (
            "CURRENT PHASE: Planning\n"
            "OBJECTIVE: Create an assessment plan.\n"
            "APPROACH:\n"
            "1. Analyze the target and scope\n"
            "2. Decompose into sub-tasks\n"
            "3. Assign specialist agents to each task\n"
            "4. Allocate budgets (tokens, time, tool calls)\n"
            "5. Define success criteria\n"
            "OUTPUT: Structured task plan with agent assignments."
        ),
        "user_template": (
            "Target: {target}\n"
            "Scope: {scope}\n"
            "Available tools: {tools}\n\n"
            "Create a comprehensive assessment plan. "
            "Break down into phases, assign tasks, allocate resources."
        ),
    },
    "reasoning": {
        "system_extra": (
            "CURRENT PHASE: Reasoning\n"
            "OBJECTIVE: Reason about security implications.\n"
            "APPROACH:\n"
            "1. Analyze the evidence step by step\n"
            "2. Consider alternative hypotheses\n"
            "3. Assess confidence in conclusions\n"
            "4. Identify gaps in analysis\n"
            "5. Recommend next actions\n"
            "OUTPUT: Structured reasoning with conclusions."
        ),
        "user_template": (
            "Context:\n{context}\n\n"
            "Reason about the security implications. "
            "Think step by step and provide structured analysis."
        ),
    },
}

# ── Few-shot examples ────────────────────────────────────────

FEW_SHOT_EXAMPLES: dict[str, list[dict[str, str]]] = {
    "tool_selection": [
        {
            "user": "I need to discover subdomains for example.com",
            "assistant": (
                "I'll use subfinder for passive subdomain enumeration:\n"
                "TOOL: subfinder -d example.com -silent\n"
                "REASONING: subfinder is fast, passive, and comprehensive."
            ),
        },
        {
            "user": "Check if the web server has SQL injection",
            "assistant": (
                "I'll use sqlmap for automated SQL injection testing:\n"
                "TOOL: sqlmap -u 'https://target.com/page?id=1' --batch --level=3\n"
                "REASONING: sqlmap handles all injection types and DBMS."
            ),
        },
    ],
    "finding_report": [
        {
            "user": "Report this finding: open admin panel at /admin",
            "assistant": (
                "FINDING: Exposed Administration Panel\n"
                "SEVERITY: High\n"
                "AFFECTED: https://target.com/admin\n"
                "EVIDENCE: HTTP 200 response with login form\n"
                "IMPACT: Admin panel accessible without IP restriction\n"
                "REMEDIATION: Restrict access by IP, add MFA"
            ),
        },
    ],
}


class PromptTemplateEngine:
    """Assembles prompts from templates and context.

    Combines system prompts, phase instructions,
    knowledge base content, and few-shot examples
    into complete prompts within token budgets.
    """

    def __init__(self) -> None:
        self._templates: dict[str, PromptTemplate] = {}
        self._assembly_count = 0
        self._log = logger.bind(component="prompt_templates")

    def assemble(
        self,
        phase: TaskPhase,
        context: dict[str, str],
        knowledge_prompt: str = "",
        findings_prompt: str = "",
        hypothesis_prompt: str = "",
        budget_prompt: str = "",
        include_few_shot: bool = True,
        max_tokens: int = 4096,
    ) -> list[PromptMessage]:
        """Assemble a complete prompt."""
        self._assembly_count += 1
        messages: list[PromptMessage] = []

        # System message
        system_parts = [BASE_SYSTEM_PROMPT]
        phase_tmpl = PHASE_TEMPLATES.get(phase.value, {})
        if phase_tmpl.get("system_extra"):
            system_parts.append(phase_tmpl["system_extra"])

        if knowledge_prompt:
            system_parts.append(knowledge_prompt)
        if findings_prompt:
            system_parts.append(findings_prompt)
        if hypothesis_prompt:
            system_parts.append(hypothesis_prompt)
        if budget_prompt:
            system_parts.append(budget_prompt)

        system_content = "\n\n".join(system_parts)
        system_tokens = max(1, len(system_content) // 4)

        # Truncate if over budget
        if system_tokens > max_tokens * 0.6:
            system_content = system_content[:int(max_tokens * 0.6 * 4)]
            system_tokens = max(1, len(system_content) // 4)

        messages.append(PromptMessage(
            role=PromptRole.SYSTEM,
            content=system_content,
            token_estimate=system_tokens,
        ))

        remaining = max_tokens - system_tokens

        # Few-shot examples
        if include_few_shot and remaining > 500:
            examples = FEW_SHOT_EXAMPLES.get("tool_selection", [])
            for ex in examples[:2]:
                ex_tokens = (len(ex.get("user", "")) + len(ex.get("assistant", ""))) // 4
                if remaining - ex_tokens < 200:
                    break
                messages.append(PromptMessage(
                    role=PromptRole.USER,
                    content=ex["user"],
                    token_estimate=len(ex["user"]) // 4,
                ))
                messages.append(PromptMessage(
                    role=PromptRole.ASSISTANT,
                    content=ex["assistant"],
                    token_estimate=len(ex["assistant"]) // 4,
                ))
                remaining -= ex_tokens

        # User message from template
        user_tmpl = phase_tmpl.get("user_template", "{context}")
        user_content = user_tmpl
        for key, value in context.items():
            user_content = user_content.replace("{" + key + "}", value)

        user_tokens = max(1, len(user_content) // 4)
        if user_tokens > remaining:
            user_content = user_content[:remaining * 4]
            user_tokens = max(1, len(user_content) // 4)

        messages.append(PromptMessage(
            role=PromptRole.USER,
            content=user_content,
            token_estimate=user_tokens,
        ))

        return messages

    def register_template(self, template: PromptTemplate) -> None:
        """Register a custom template."""
        self._templates[template.template_id] = template

    def get_stats(self) -> dict[str, Any]:
        return {
            "assemblies": self._assembly_count,
            "custom_templates": len(self._templates),
            "phases": len(PHASE_TEMPLATES),
        }
