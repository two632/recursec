"""Prompt compiler — assembles system prompts from components.

Implements:
1. Token-aware prompt assembly
2. Priority-based section inclusion
3. Knowledge injection from KBs
4. Context injection from memory
5. Task-specific prompt templates
6. Dynamic prompt optimization
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class SectionPriority(str, Enum):
    CRITICAL = "critical"    # Always included
    HIGH = "high"            # Included if space
    MEDIUM = "medium"        # Included if spare capacity
    LOW = "low"              # Only if plenty of space


class SectionType(str, Enum):
    SYSTEM = "system"
    TASK = "task"
    KNOWLEDGE = "knowledge"
    CONTEXT = "context"
    MEMORY = "memory"
    FINDINGS = "findings"
    REASONING = "reasoning"
    BUDGET = "budget"
    REFLECTION = "reflection"
    TOOLS = "tools"


@dataclass
class PromptSection:
    """A section of the assembled prompt."""
    section_id: str = ""
    section_type: SectionType = SectionType.SYSTEM
    priority: SectionPriority = SectionPriority.HIGH
    content: str = ""
    token_estimate: int = 0
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.section_id[:12],
            "type": self.section_type.value[:6],
            "priority": self.priority.value[:4],
            "tokens": self.token_estimate,
        }


@dataclass
class CompiledPrompt:
    """A fully compiled prompt ready for LLM."""
    sections: list[PromptSection] = field(default_factory=list)
    total_tokens: int = 0
    max_tokens: int = 4096
    truncated: bool = False
    compilation_time_ms: float = 0.0

    @property
    def text(self) -> str:
        return "\n\n".join(s.content for s in self.sections if s.content)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sections": len(self.sections),
            "tokens": self.total_tokens,
            "max": self.max_tokens,
            "truncated": self.truncated,
        }


# ── Agent role templates ──────────────────────────────────────

ROLE_TEMPLATES: dict[str, str] = {
    "coordinator": (
        "You are the COORDINATOR agent in RecurSec.\n"
        "Your role: decompose tasks, assign to specialist agents, "
        "synthesize results, make strategic decisions.\n"
        "Think step-by-step. Prioritize high-impact findings.\n"
        "Available sub-agents: recon, vuln_scan, web_audit, "
        "exploit, code_audit, network, cloud, forensics."
    ),
    "recon": (
        "You are a RECONNAISSANCE specialist agent.\n"
        "Your role: discover attack surface — subdomains, "
        "services, technologies, exposed data.\n"
        "Use external tools: subfinder, amass, httpx, nmap.\n"
        "Report: domains, IPs, ports, services, technologies."
    ),
    "vuln_scan": (
        "You are a VULNERABILITY SCANNER agent.\n"
        "Your role: identify known vulnerabilities using "
        "automated scanners.\n"
        "Use: nuclei, nikto, nmap NSE scripts, openvas.\n"
        "Classify findings by severity (critical/high/medium/low)."
    ),
    "web_audit": (
        "You are a WEB SECURITY AUDITOR agent.\n"
        "Your role: test web applications for OWASP Top 10, "
        "injection flaws, auth issues, business logic bugs.\n"
        "Use: Burp Suite, sqlmap, XSS scanners, ffuf.\n"
        "Focus on exploitable vulnerabilities."
    ),
    "exploit": (
        "You are an EXPLOITATION specialist agent.\n"
        "Your role: validate and exploit confirmed vulnerabilities.\n"
        "Use: metasploit, custom scripts, PoC exploits.\n"
        "Prove impact with evidence. Minimize damage.\n"
        "Report: vulnerability, exploit, impact, evidence."
    ),
    "code_audit": (
        "You are a CODE AUDITOR agent.\n"
        "Your role: review source code for security vulnerabilities.\n"
        "Use: semgrep, CodeQL patterns, manual review.\n"
        "Focus: injection, auth, crypto, deserialization, "
        "hardcoded secrets, race conditions."
    ),
    "network": (
        "You are a NETWORK SECURITY agent.\n"
        "Your role: assess network security posture.\n"
        "Use: nmap, masscan, responder, bettercap.\n"
        "Test: segmentation, protocols, services, firewall rules."
    ),
    "cloud": (
        "You are a CLOUD SECURITY agent.\n"
        "Your role: assess cloud infrastructure security.\n"
        "Use: prowler, ScoutSuite, custom queries.\n"
        "Focus: IAM, storage, network, serverless, K8s."
    ),
    "forensics": (
        "You are a DIGITAL FORENSICS agent.\n"
        "Your role: collect and analyze evidence.\n"
        "Use: volatility, autopsy, log analysis tools.\n"
        "Preserve chain of custody. Document everything."
    ),
    "validator": (
        "You are a VALIDATION agent.\n"
        "Your role: verify findings from other agents.\n"
        "Cross-check using different tools and methods.\n"
        "Reject false positives. Confirm true positives.\n"
        "Assign final severity and confidence scores."
    ),
    "reporter": (
        "You are a REPORTING agent.\n"
        "Your role: synthesize findings into reports.\n"
        "Structure: executive summary, findings by severity, "
        "technical details, remediation recommendations.\n"
        "Be clear, concise, and actionable."
    ),
}


class PromptCompiler:
    """Assembles system prompts from knowledge, context, and task.

    Takes all available prompt sections (KB patterns,
    memory, context, task description, budget status)
    and compiles them into a token-budget-aware prompt.
    """

    def __init__(self, chars_per_token: float = 3.5) -> None:
        self._chars_per_token = chars_per_token
        self._compile_count = 0
        self._log = logger.bind(component="prompt_compiler")

    def compile(
        self,
        role: str = "coordinator",
        task: str = "",
        knowledge_sections: list[str] | None = None,
        context_text: str = "",
        memory_text: str = "",
        findings_text: str = "",
        reasoning_text: str = "",
        budget_text: str = "",
        reflection_text: str = "",
        tools_text: str = "",
        max_tokens: int = 4096,
    ) -> CompiledPrompt:
        """Compile a full prompt from all available sections."""
        start = time.time()
        self._compile_count += 1

        sections: list[PromptSection] = []
        section_counter = 0

        # 1. System role (CRITICAL)
        role_text = ROLE_TEMPLATES.get(role, ROLE_TEMPLATES["coordinator"])
        section_counter += 1
        sections.append(PromptSection(
            section_id=f"sec-{section_counter}",
            section_type=SectionType.SYSTEM,
            priority=SectionPriority.CRITICAL,
            content=role_text,
            token_estimate=self._estimate_tokens(role_text),
            source="role_template",
        ))

        # 2. Task (CRITICAL)
        if task:
            section_counter += 1
            task_text = f"## Current Task\n{task}"
            sections.append(PromptSection(
                section_id=f"sec-{section_counter}",
                section_type=SectionType.TASK,
                priority=SectionPriority.CRITICAL,
                content=task_text,
                token_estimate=self._estimate_tokens(task_text),
                source="task",
            ))

        # 3. Knowledge (HIGH)
        if knowledge_sections:
            for i, kb_text in enumerate(knowledge_sections):
                section_counter += 1
                sections.append(PromptSection(
                    section_id=f"sec-{section_counter}",
                    section_type=SectionType.KNOWLEDGE,
                    priority=SectionPriority.HIGH,
                    content=kb_text,
                    token_estimate=self._estimate_tokens(kb_text),
                    source=f"kb-{i}",
                ))

        # 4. Context (HIGH)
        if context_text:
            section_counter += 1
            sections.append(PromptSection(
                section_id=f"sec-{section_counter}",
                section_type=SectionType.CONTEXT,
                priority=SectionPriority.HIGH,
                content=context_text,
                token_estimate=self._estimate_tokens(context_text),
                source="context",
            ))

        # 5. Findings (HIGH)
        if findings_text:
            section_counter += 1
            sections.append(PromptSection(
                section_id=f"sec-{section_counter}",
                section_type=SectionType.FINDINGS,
                priority=SectionPriority.HIGH,
                content=findings_text,
                token_estimate=self._estimate_tokens(findings_text),
                source="findings",
            ))

        # 6. Memory (MEDIUM)
        if memory_text:
            section_counter += 1
            sections.append(PromptSection(
                section_id=f"sec-{section_counter}",
                section_type=SectionType.MEMORY,
                priority=SectionPriority.MEDIUM,
                content=memory_text,
                token_estimate=self._estimate_tokens(memory_text),
                source="memory",
            ))

        # 7. Reasoning (MEDIUM)
        if reasoning_text:
            section_counter += 1
            sections.append(PromptSection(
                section_id=f"sec-{section_counter}",
                section_type=SectionType.REASONING,
                priority=SectionPriority.MEDIUM,
                content=reasoning_text,
                token_estimate=self._estimate_tokens(reasoning_text),
                source="reasoning",
            ))

        # 8. Tools (MEDIUM)
        if tools_text:
            section_counter += 1
            sections.append(PromptSection(
                section_id=f"sec-{section_counter}",
                section_type=SectionType.TOOLS,
                priority=SectionPriority.MEDIUM,
                content=tools_text,
                token_estimate=self._estimate_tokens(tools_text),
                source="tools",
            ))

        # 9. Budget (LOW)
        if budget_text:
            section_counter += 1
            sections.append(PromptSection(
                section_id=f"sec-{section_counter}",
                section_type=SectionType.BUDGET,
                priority=SectionPriority.LOW,
                content=budget_text,
                token_estimate=self._estimate_tokens(budget_text),
                source="budget",
            ))

        # 10. Reflection (LOW)
        if reflection_text:
            section_counter += 1
            sections.append(PromptSection(
                section_id=f"sec-{section_counter}",
                section_type=SectionType.REFLECTION,
                priority=SectionPriority.LOW,
                content=reflection_text,
                token_estimate=self._estimate_tokens(reflection_text),
                source="reflection",
            ))

        # Fit within token budget
        compiled = self._fit_to_budget(sections, max_tokens)

        compiled.compilation_time_ms = (time.time() - start) * 1000
        return compiled

    def _fit_to_budget(
        self,
        sections: list[PromptSection],
        max_tokens: int,
    ) -> CompiledPrompt:
        """Fit sections within token budget by priority."""
        # Priority order
        priority_order = [
            SectionPriority.CRITICAL,
            SectionPriority.HIGH,
            SectionPriority.MEDIUM,
            SectionPriority.LOW,
        ]

        included: list[PromptSection] = []
        used_tokens = 0
        truncated = False

        for priority in priority_order:
            for section in sections:
                if section.priority != priority:
                    continue

                if used_tokens + section.token_estimate <= max_tokens:
                    included.append(section)
                    used_tokens += section.token_estimate
                else:
                    # Try to include truncated
                    remaining = max_tokens - used_tokens
                    if remaining > 50 and priority in (
                        SectionPriority.CRITICAL,
                        SectionPriority.HIGH,
                    ):
                        # Truncate content
                        max_chars = int(remaining * self._chars_per_token)
                        truncated_content = section.content[:max_chars] + "\n...[truncated]"
                        section.content = truncated_content
                        section.token_estimate = remaining
                        included.append(section)
                        used_tokens += remaining
                        truncated = True
                    else:
                        truncated = True

        return CompiledPrompt(
            sections=included,
            total_tokens=used_tokens,
            max_tokens=max_tokens,
            truncated=truncated,
        )

    def _estimate_tokens(self, text: str) -> int:
        """Estimate token count from text."""
        return max(1, int(len(text) / self._chars_per_token))

    def get_stats(self) -> dict[str, Any]:
        return {
            "compilations": self._compile_count,
        }
