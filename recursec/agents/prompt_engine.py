"""Prompt engineering engine — dynamic prompt construction and optimization.

Implements:
1. Role-based prompt templates for each agent type
2. Dynamic system prompt construction
3. Few-shot example injection
4. Context-aware prompt adaptation
5. Prompt compression for token efficiency
6. Output format enforcement (JSON, structured)
7. Chain-of-thought prompt strategies
8. Prompt caching and reuse
9. Model-specific prompt formatting
10. Safety guardrail injection
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class PromptRole(str, Enum):
    RECON = "recon"
    VULN_SCANNER = "vuln_scanner"
    EXPLOIT_DEV = "exploit_dev"
    CODE_AUDITOR = "code_auditor"
    NETWORK_ANALYST = "network_analyst"
    WEB_TESTER = "web_tester"
    OSINT = "osint"
    FORENSICS = "forensics"
    PLANNER = "planner"
    VALIDATOR = "validator"
    REPORTER = "reporter"
    COORDINATOR = "coordinator"


class OutputFormat(str, Enum):
    JSON = "json"
    TEXT = "text"
    MARKDOWN = "markdown"
    STRUCTURED = "structured"


class PromptStrategy(str, Enum):
    DIRECT = "direct"                   # Simple instruction
    CHAIN_OF_THOUGHT = "chain_of_thought"  # Step-by-step reasoning
    FEW_SHOT = "few_shot"               # Examples provided
    TREE_OF_THOUGHT = "tree_of_thought" # Multiple reasoning paths
    REACT = "react"                     # Reasoning + Acting
    EXPERT_PANEL = "expert_panel"       # Multiple perspectives


@dataclass
class PromptTemplate:
    """A reusable prompt template."""
    name: str = ""
    role: PromptRole = PromptRole.COORDINATOR
    system_prompt: str = ""
    user_template: str = ""
    output_format: OutputFormat = OutputFormat.JSON
    strategy: PromptStrategy = PromptStrategy.DIRECT
    few_shot_examples: list[dict[str, str]] = field(default_factory=list)
    max_tokens: int = 1024
    temperature: float = 0.3
    stop_sequences: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "role": self.role.value,
            "format": self.output_format.value,
            "strategy": self.strategy.value,
            "examples": len(self.few_shot_examples),
        }


@dataclass
class ConstructedPrompt:
    """A fully constructed prompt ready for LLM."""
    system: str = ""
    messages: list[dict[str, str]] = field(default_factory=list)
    max_tokens: int = 1024
    temperature: float = 0.3
    stop_sequences: list[str] = field(default_factory=list)
    estimated_tokens: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "messages": len(self.messages),
            "tokens_est": self.estimated_tokens,
        }


# ── System Prompts ────────────────────────────────────────────

SYSTEM_PROMPTS: dict[str, str] = {
    "recon": """You are a reconnaissance specialist in a security assessment team.
Your role is to gather information about targets: subdomains, open ports, services,
technologies, and any publicly available information. Be thorough and systematic.
Report findings in structured JSON format. Flag anything unusual or high-risk.""",

    "vuln_scanner": """You are a vulnerability analysis specialist. You analyze tool outputs
from scanners (nmap, nuclei, nikto) and identify real vulnerabilities. Distinguish between
true positives and false positives. Rate severity using CVSS methodology. Provide evidence
for each finding. Be precise — false positives waste resources.""",

    "exploit_dev": """You are an exploitation specialist. You develop and execute safe proof-of-concept
exploits to demonstrate vulnerability impact. Always work within authorized scope.
Use the minimum force necessary to prove exploitability. Document every step.""",

    "code_auditor": """You are a code security auditor. You review source code for vulnerabilities:
injection flaws, authentication issues, authorization bypasses, crypto weaknesses,
insecure deserialization, and more. Map findings to CWE IDs. Provide line numbers
and remediation guidance.""",

    "network_analyst": """You are a network security analyst. You analyze network configurations,
protocols, traffic patterns, and firewall rules. Identify misconfigurations, weak protocols,
and potential attack paths. Map findings to network topology.""",

    "web_tester": """You are a web application security tester. You test for OWASP Top 10
vulnerabilities: injection, broken auth, sensitive data exposure, XXE, broken access control,
security misconfiguration, XSS, insecure deserialization, known vulnerable components,
and insufficient logging.""",

    "osint": """You are an OSINT (Open Source Intelligence) specialist. You gather publicly
available information about targets: email addresses, employee names, technology stacks,
leaked credentials, social media presence, and corporate relationships.""",

    "forensics": """You are a digital forensics analyst. You analyze system artifacts, logs,
and evidence to understand security incidents. Follow evidence preservation best practices.
Document chain of custody. Identify indicators of compromise.""",

    "planner": """You are a security assessment planner. You create comprehensive assessment
plans with phases, milestones, and resource allocation. Prioritize actions based on risk
and available time. Adapt plans based on findings.""",

    "validator": """You are a finding validator. You independently verify vulnerability findings
using different tools and techniques. Cross-reference findings with known vulnerability
databases. Challenge assumptions and look for false positives. Be skeptical — only confirm
findings with strong evidence.""",

    "reporter": """You are a security report writer. You create clear, actionable reports
for technical and executive audiences. Prioritize findings by risk. Include remediation
recommendations with estimated effort.""",

    "coordinator": """You are the security assessment coordinator. You manage the team of
specialist agents, allocate resources, resolve conflicts, and ensure comprehensive coverage.
Track progress and adapt strategy based on findings.""",
}


# ── Few-Shot Examples ─────────────────────────────────────────

FEW_SHOT_VULN_ANALYSIS: list[dict[str, str]] = [
    {
        "user": "Analyze this nmap output:\nPORT STATE SERVICE VERSION\n22/tcp open ssh OpenSSH 7.4\n80/tcp open http Apache 2.4.6\n443/tcp open ssl/http Apache 2.4.6\n3306/tcp open mysql MySQL 5.7.38",
        "assistant": '{"findings": [{"port": 22, "service": "ssh", "version": "OpenSSH 7.4", "risk": "medium", "note": "OpenSSH 7.4 has known vulnerabilities (CVE-2017-15906). Upgrade recommended."}, {"port": 3306, "service": "mysql", "risk": "high", "note": "MySQL exposed to network. Should be firewalled to localhost only."}], "recommendations": ["Upgrade OpenSSH to latest", "Restrict MySQL to 127.0.0.1", "Check Apache mod_security"]}',
    },
    {
        "user": "Is this XSS finding valid?\nURL: https://example.com/search?q=<script>alert(1)</script>\nResponse contains: <script>alert(1)</script>",
        "assistant": '{"valid": true, "confidence": 0.9, "type": "reflected_xss", "severity": "medium", "evidence": "User input reflected unescaped in response body", "cwe": "CWE-79", "remediation": "Implement output encoding. Use Content-Security-Policy header."}',
    },
]

FEW_SHOT_RECON: list[dict[str, str]] = [
    {
        "user": "What can you determine about this target from the headers?\nServer: nginx/1.18.0\nX-Powered-By: PHP/7.4.3\nSet-Cookie: PHPSESSID=abc123; path=/\nX-Frame-Options: DENY",
        "assistant": '{"tech_stack": {"server": "nginx 1.18.0", "language": "PHP 7.4.3", "session": "PHP native sessions"}, "security_headers": {"x_frame_options": "present", "csp": "missing", "hsts": "missing"}, "findings": [{"item": "PHP version exposed", "risk": "low", "note": "Remove X-Powered-By header"}, {"item": "Missing HSTS", "risk": "medium"}, {"item": "Missing CSP", "risk": "medium"}]}',
    },
]


# ── Output Format Templates ──────────────────────────────────

OUTPUT_FORMATS = {
    "json": "\n\nRespond ONLY with valid JSON. No markdown, no explanation, just JSON.",
    "structured": "\n\nRespond with structured data:\n- Use bullet points for lists\n- Use headers for sections\n- Include severity ratings",
    "markdown": "\n\nRespond in Markdown format with headers, lists, and code blocks as needed.",
    "text": "",
}


# ── Safety Guardrails ────────────────────────────────────────

SAFETY_SUFFIX = """

SAFETY RULES:
- Only operate within authorized scope
- Do not access or modify data outside the assessment
- Use the least-destructive technique to demonstrate impact
- Stop immediately if you detect you're affecting production systems
- Report any accidental findings outside scope immediately"""


class PromptEngine:
    """Dynamic prompt construction and optimization.

    Builds context-aware, role-specific prompts with
    few-shot examples, safety guardrails, and format
    enforcement.
    """

    def __init__(self) -> None:
        self._templates: dict[str, PromptTemplate] = {}
        self._cache: dict[str, ConstructedPrompt] = {}
        self._log = logger.bind(component="prompt_engine")

        self._init_templates()

    def _init_templates(self) -> None:
        """Initialize built-in prompt templates."""
        for role_name, system_prompt in SYSTEM_PROMPTS.items():
            try:
                role = PromptRole(role_name)
            except ValueError:
                continue

            template = PromptTemplate(
                name=role_name,
                role=role,
                system_prompt=system_prompt,
                output_format=OutputFormat.JSON,
                strategy=PromptStrategy.CHAIN_OF_THOUGHT,
            )

            # Add few-shot examples for specific roles
            if role_name == "vuln_scanner":
                template.few_shot_examples = FEW_SHOT_VULN_ANALYSIS
            elif role_name == "recon":
                template.few_shot_examples = FEW_SHOT_RECON

            self._templates[role_name] = template

    def construct(
        self,
        role: str,
        user_message: str,
        context: str = "",
        target: str = "",
        output_format: OutputFormat = OutputFormat.JSON,
        strategy: PromptStrategy = PromptStrategy.CHAIN_OF_THOUGHT,
        include_safety: bool = True,
        model_name: str = "",
    ) -> ConstructedPrompt:
        """Construct a complete prompt."""
        template = self._templates.get(role)
        system = template.system_prompt if template else SYSTEM_PROMPTS.get("coordinator", "")

        # Add context
        if context:
            system += f"\n\nCurrent context:\n{context[:500]}"

        # Add target info
        if target:
            system += f"\n\nTarget: {target}"

        # Strategy-specific additions
        if strategy == PromptStrategy.CHAIN_OF_THOUGHT:
            system += "\n\nThink step-by-step. Show your reasoning before your conclusion."
        elif strategy == PromptStrategy.REACT:
            system += "\n\nUse the ReAct pattern: Thought → Action → Observation → Thought → ..."
        elif strategy == PromptStrategy.TREE_OF_THOUGHT:
            system += "\n\nConsider multiple approaches. Evaluate each before choosing the best."

        # Output format
        system += OUTPUT_FORMATS.get(output_format.value, "")

        # Safety
        if include_safety:
            system += SAFETY_SUFFIX

        # Model-specific formatting
        system = self._format_for_model(system, model_name)

        # Build messages
        messages: list[dict[str, str]] = [{"role": "system", "content": system}]

        # Few-shot examples
        if template and template.few_shot_examples:
            for example in template.few_shot_examples[:3]:
                messages.append({"role": "user", "content": example["user"]})
                messages.append({"role": "assistant", "content": example["assistant"]})

        # User message
        messages.append({"role": "user", "content": user_message})

        # Estimate tokens
        total_chars = sum(len(m["content"]) for m in messages)
        est_tokens = total_chars // 4

        return ConstructedPrompt(
            system=system,
            messages=messages,
            max_tokens=template.max_tokens if template else 1024,
            temperature=template.temperature if template else 0.3,
            estimated_tokens=est_tokens,
        )

    def _format_for_model(self, system: str, model_name: str) -> str:
        """Apply model-specific formatting."""
        model_lower = model_name.lower()

        if "llama" in model_lower:
            pass  # Llama uses standard chat format
        elif "qwen" in model_lower:
            pass  # Qwen uses standard chat format
        elif "deepseek" in model_lower:
            # DeepSeek benefits from explicit step numbering
            if "step-by-step" not in system.lower():
                system += "\n\nPlease reason carefully, step by step."
        elif "dolphin" in model_lower:
            # Dolphin is uncensored — can be more direct
            system = system.replace(SAFETY_SUFFIX, "")
        elif "phi" in model_lower:
            # Phi is small — keep prompts concise
            lines = system.split("\n")
            system = "\n".join(line for line in lines if line.strip())

        return system

    def add_template(self, template: PromptTemplate) -> None:
        self._templates[template.name] = template

    def get_template(self, name: str) -> PromptTemplate | None:
        return self._templates.get(name)

    def list_templates(self) -> list[str]:
        return list(self._templates.keys())

    def compress_prompt(self, text: str, max_tokens: int = 2000) -> str:
        """Compress a prompt to fit within token limits."""
        est_tokens = len(text) // 4

        if est_tokens <= max_tokens:
            return text

        # Strategy 1: Remove empty lines
        lines = [line for line in text.split("\n") if line.strip()]
        text = "\n".join(lines)

        est_tokens = len(text) // 4
        if est_tokens <= max_tokens:
            return text

        # Strategy 2: Truncate from the middle
        target_chars = max_tokens * 4
        if len(text) > target_chars:
            half = target_chars // 2
            text = text[:half] + "\n...[truncated]...\n" + text[-half:]

        return text

    def get_stats(self) -> dict[str, Any]:
        return {
            "templates": len(self._templates),
            "roles": [r.value for r in PromptRole],
        }
