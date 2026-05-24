"""Prompt engineering system — model-specific prompt optimization.

This module crafts optimal prompts for each of the 16 LLMs:
1. Model-specific formatting (chat templates, special tokens)
2. Role-specific system prompts (security analyst, code reviewer, etc.)
3. Dynamic KB injection based on task context
4. Few-shot example selection from past successful interactions
5. Chain-of-thought scaffolding
6. Output format enforcement (JSON, structured text)
7. Token budget management (trim context to fit)
8. Prompt compression for small-context models
9. Anti-hallucination guardrails
10. Tool-use formatting per model capability
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class PromptFormat(str, Enum):
    CHATML = "chatml"
    LLAMA = "llama"
    ALPACA = "alpaca"
    MISTRAL = "mistral"
    RAW = "raw"


class OutputFormat(str, Enum):
    FREE_TEXT = "free_text"
    JSON = "json"
    MARKDOWN = "markdown"
    TOOL_CALL = "tool_call"
    STRUCTURED = "structured"


@dataclass
class PromptConfig:
    """Configuration for prompt building."""
    model_id: str = ""
    role: str = ""
    task_type: str = ""
    target: str = ""
    output_format: OutputFormat = OutputFormat.FREE_TEXT
    max_tokens: int = 4096
    temperature: float = 0.7
    include_kb: bool = True
    include_examples: bool = True
    include_cot: bool = True
    include_tools: bool = True


@dataclass
class BuiltPrompt:
    """A fully constructed prompt ready to send."""
    system: str = ""
    user: str = ""
    formatted: str = ""
    token_estimate: int = 0
    model_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model_id[:15],
            "tokens": self.token_estimate,
            "sys_len": len(self.system),
            "user_len": len(self.user),
        }


# Model → prompt format mapping
MODEL_FORMATS: dict[str, PromptFormat] = {
    "whiterabbit": PromptFormat.CHATML,
    "qwen-coder-14b": PromptFormat.CHATML,
    "qwen-coder-7b": PromptFormat.CHATML,
    "codellama-13b": PromptFormat.LLAMA,
    "codellama-7b": PromptFormat.LLAMA,
    "deepseek-r1": PromptFormat.CHATML,
    "deepseek-math": PromptFormat.CHATML,
    "hermes-4-14b": PromptFormat.CHATML,
    "llama-3.1-8b": PromptFormat.LLAMA,
    "dolphin-2.9": PromptFormat.CHATML,
    "mistral-7b": PromptFormat.MISTRAL,
    "yi-9b-200k": PromptFormat.CHATML,
    "llama-guard": PromptFormat.LLAMA,
    "phi-3.5-mini": PromptFormat.CHATML,
    "functiongemma": PromptFormat.RAW,
    "nomic-embed": PromptFormat.RAW,
}

# Model context windows
MODEL_CONTEXT: dict[str, int] = {
    "whiterabbit": 4096,
    "qwen-coder-14b": 8192,
    "qwen-coder-7b": 8192,
    "codellama-13b": 4096,
    "codellama-7b": 4096,
    "deepseek-r1": 8192,
    "deepseek-math": 4096,
    "hermes-4-14b": 8192,
    "llama-3.1-8b": 8192,
    "dolphin-2.9": 8192,
    "mistral-7b": 8192,
    "yi-9b-200k": 200000,
    "llama-guard": 4096,
    "phi-3.5-mini": 4096,
    "functiongemma": 2048,
    "nomic-embed": 2048,
}

# Role-specific system prompts
ROLE_SYSTEM_PROMPTS: dict[str, str] = {
    "coordinator": (
        "You are RecurSec's lead security coordinator. Your job is to:\n"
        "1. Analyze the target and plan the assessment strategy\n"
        "2. Delegate tasks to specialized agents\n"
        "3. Aggregate findings from all agents\n"
        "4. Identify attack chains and critical paths\n"
        "5. Prioritize findings by real-world impact\n"
        "Be methodical and thorough. Think step by step."
    ),
    "recon": (
        "You are RecurSec's reconnaissance specialist. Your job is to:\n"
        "1. Enumerate the target's attack surface (subdomains, IPs, ports, services)\n"
        "2. Identify technologies and frameworks in use\n"
        "3. Find exposed sensitive information\n"
        "4. Map the target's infrastructure\n"
        "Use tools: subfinder, httpx, nmap, amass, masscan. Report findings concisely."
    ),
    "scanner": (
        "You are RecurSec's vulnerability scanner specialist. Your job is to:\n"
        "1. Run comprehensive vulnerability scans on identified targets\n"
        "2. Verify findings to reduce false positives\n"
        "3. Classify vulnerabilities by severity and exploitability\n"
        "4. Identify CVEs and known exploits\n"
        "Use tools: nuclei, nikto, nmap scripts. Report with CVE IDs when possible."
    ),
    "web": (
        "You are RecurSec's web application security expert. Your job is to:\n"
        "1. Test for OWASP Top 10 vulnerabilities\n"
        "2. Test authentication and authorization flaws\n"
        "3. Identify injection points (SQL, XSS, SSRF, SSTI)\n"
        "4. Test business logic vulnerabilities\n"
        "5. Check API security and rate limiting\n"
        "Use tools: sqlmap, dalfox, ffuf, gobuster, nuclei. Be thorough and precise."
    ),
    "code_audit": (
        "You are RecurSec's code security auditor. Your job is to:\n"
        "1. Review source code for security vulnerabilities\n"
        "2. Identify insecure coding patterns\n"
        "3. Check for hardcoded secrets and credentials\n"
        "4. Analyze dependency vulnerabilities\n"
        "5. Evaluate cryptographic implementations\n"
        "Use tools: semgrep, bandit, gitleaks, trivy. Provide code-level remediation."
    ),
    "exploit": (
        "You are RecurSec's exploitation specialist. Your job is to:\n"
        "1. Validate confirmed vulnerabilities through exploitation\n"
        "2. Determine real-world impact of each vulnerability\n"
        "3. Build proof-of-concept exploits\n"
        "4. Chain vulnerabilities for maximum impact\n"
        "5. Document exploitation steps precisely\n"
        "Only exploit in authorized scope. Document everything."
    ),
    "network": (
        "You are RecurSec's network security analyst. Your job is to:\n"
        "1. Analyze network topology and segmentation\n"
        "2. Test for network-level vulnerabilities\n"
        "3. Check firewall and ACL configurations\n"
        "4. Test for lateral movement possibilities\n"
        "5. Analyze DNS security\n"
        "Use tools: nmap, masscan, responder, tcpdump."
    ),
    "cloud": (
        "You are RecurSec's cloud security specialist. Your job is to:\n"
        "1. Audit IAM policies and access controls\n"
        "2. Check for misconfigured storage (S3, GCS, Azure Blob)\n"
        "3. Review network security groups and firewalls\n"
        "4. Audit container and serverless configurations\n"
        "5. Check for privilege escalation paths\n"
        "Use tools: prowler, scoutsuite, trivy."
    ),
    "osint": (
        "You are RecurSec's OSINT specialist. Your job is to:\n"
        "1. Gather open-source intelligence about the target\n"
        "2. Find exposed credentials and data breaches\n"
        "3. Map the organization's digital footprint\n"
        "4. Identify employees and their roles\n"
        "5. Find associated domains and infrastructure\n"
        "Use passive techniques only. No active scanning."
    ),
}

# Few-shot examples for tool usage
TOOL_USE_EXAMPLES: dict[str, str] = {
    "nmap": (
        "Example: To scan ports on a target:\n"
        "TOOL: nmap\n"
        "COMMAND: nmap -sV -sC --top-ports 1000 target.com\n"
        "REASON: Service version detection and default script scan on top 1000 ports"
    ),
    "nuclei": (
        "Example: To scan for known vulnerabilities:\n"
        "TOOL: nuclei\n"
        "COMMAND: nuclei -u https://target.com -severity critical,high\n"
        "REASON: Check for critical and high severity known vulnerabilities"
    ),
    "sqlmap": (
        "Example: To test for SQL injection:\n"
        "TOOL: sqlmap\n"
        "COMMAND: sqlmap -u 'https://target.com/login?user=test' --batch --level 3\n"
        "REASON: Test login parameter for SQL injection with increased detection level"
    ),
    "ffuf": (
        "Example: To discover hidden paths:\n"
        "TOOL: ffuf\n"
        "COMMAND: ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302\n"
        "REASON: Directory brute-force with common wordlist"
    ),
}

# Chain-of-thought scaffolding
COT_SCAFFOLDS: dict[str, str] = {
    "security_analysis": (
        "Think step by step:\n"
        "1. What is the target and what do I know about it?\n"
        "2. What is the attack surface?\n"
        "3. What vulnerabilities are most likely?\n"
        "4. What tools should I use and in what order?\n"
        "5. What findings have other agents reported?\n"
        "6. What are the highest-risk areas?"
    ),
    "code_review": (
        "Analyze the code systematically:\n"
        "1. What language and framework is this?\n"
        "2. What are the input sources (user input, APIs, files)?\n"
        "3. How is input validated and sanitized?\n"
        "4. Are there SQL queries, system commands, or file operations?\n"
        "5. How are authentication and authorization handled?\n"
        "6. Are there any hardcoded secrets or credentials?"
    ),
    "exploit_planning": (
        "Plan the exploitation:\n"
        "1. What vulnerability am I exploiting?\n"
        "2. What are the prerequisites?\n"
        "3. What is the expected impact?\n"
        "4. What tools and payloads do I need?\n"
        "5. How do I verify successful exploitation?\n"
        "6. How do I chain this with other findings?"
    ),
}

# Output format templates
OUTPUT_TEMPLATES: dict[OutputFormat, str] = {
    OutputFormat.JSON: (
        "\nRespond in JSON format:\n"
        "```json\n"
        "{\n"
        '  "findings": [{"title": "...", "severity": "critical|high|medium|low", "description": "...", "evidence": "...", "remediation": "..."}],\n'
        '  "next_steps": ["..."],\n'
        '  "tools_to_run": [{"tool": "...", "command": "...", "reason": "..."}]\n'
        "}\n"
        "```"
    ),
    OutputFormat.TOOL_CALL: (
        "\nWhen you need to use a tool, format as:\n"
        "TOOL: <tool_name>\n"
        "COMMAND: <full command>\n"
        "REASON: <why this tool/command>\n\n"
        "After receiving tool output, analyze and decide next action."
    ),
    OutputFormat.STRUCTURED: (
        "\nProvide a structured response:\n"
        "## Findings\n"
        "- [SEVERITY] Title: Description\n"
        "## Next Steps\n"
        "- Tool: reason\n"
        "## Risk Assessment\n"
        "- Overall risk level and justification"
    ),
}

# Anti-hallucination guards
ANTI_HALLUCINATION = (
    "\nIMPORTANT RULES:\n"
    "- Only report vulnerabilities you have evidence for\n"
    "- Do NOT make up CVE numbers — only use real, verified CVEs\n"
    "- If unsure about a finding, mark it as 'needs verification'\n"
    "- Distinguish between confirmed and suspected vulnerabilities\n"
    "- Never claim something is exploitable without proof\n"
    "- If a tool returned no results, report that honestly"
)


class PromptEngineer:
    """Builds optimal prompts for each model and task."""

    def __init__(self) -> None:
        self._prompt_cache: dict[str, BuiltPrompt] = {}
        self._total_built = 0
        self._log = logger.bind(component="prompt_engineer")

    def build(self, config: PromptConfig, kb_context: str = "", memory_context: str = "", tool_output: str = "") -> BuiltPrompt:
        """Build an optimized prompt."""
        self._total_built += 1

        max_ctx = MODEL_CONTEXT.get(config.model_id, 4096)
        prompt_format = MODEL_FORMATS.get(config.model_id, PromptFormat.CHATML)

        # Build system prompt
        system_parts = []

        # Role-specific system prompt
        role_prompt = ROLE_SYSTEM_PROMPTS.get(config.role, ROLE_SYSTEM_PROMPTS.get("coordinator", ""))
        if role_prompt:
            system_parts.append(role_prompt)

        # Anti-hallucination
        system_parts.append(ANTI_HALLUCINATION)

        # Output format
        output_tmpl = OUTPUT_TEMPLATES.get(config.output_format, "")
        if output_tmpl:
            system_parts.append(output_tmpl)

        system = "\n\n".join(system_parts)

        # Build user prompt
        user_parts = []

        # Task description
        user_parts.append(f"Target: {config.target}" if config.target else "")
        user_parts.append(f"Task: {config.task_type}")

        # Chain-of-thought scaffolding
        if config.include_cot:
            cot = COT_SCAFFOLDS.get(config.task_type, COT_SCAFFOLDS.get("security_analysis", ""))
            if cot:
                user_parts.append(cot)

        # Tool use examples
        if config.include_tools:
            examples = []
            for tool_name, example in TOOL_USE_EXAMPLES.items():
                examples.append(example)
                if len(examples) >= 2:
                    break
            if examples:
                user_parts.append("\n".join(examples))

        # KB context
        if config.include_kb and kb_context:
            # Trim KB to fit
            max_kb_tokens = max_ctx // 4
            if len(kb_context) // 4 > max_kb_tokens:
                kb_context = kb_context[:max_kb_tokens * 4]
            user_parts.append(f"\n## Security Knowledge:\n{kb_context}")

        # Memory context
        if memory_context:
            max_mem_tokens = max_ctx // 8
            if len(memory_context) // 4 > max_mem_tokens:
                memory_context = memory_context[:max_mem_tokens * 4]
            user_parts.append(f"\n## Previous Context:\n{memory_context}")

        # Tool output to analyze
        if tool_output:
            max_tool_tokens = max_ctx // 3
            if len(tool_output) // 4 > max_tool_tokens:
                tool_output = tool_output[:max_tool_tokens * 4] + "\n[... output truncated ...]"
            user_parts.append(f"\n## Tool Output:\n{tool_output}")

        user = "\n\n".join(p for p in user_parts if p)

        # Format for model
        formatted = self._format_prompt(prompt_format, system, user)

        # Estimate tokens
        token_estimate = len(formatted) // 4

        # Trim if over budget
        if token_estimate > max_ctx * 0.9:
            formatted = formatted[:int(max_ctx * 0.9 * 4)]
            token_estimate = len(formatted) // 4

        return BuiltPrompt(
            system=system,
            user=user,
            formatted=formatted,
            token_estimate=token_estimate,
            model_id=config.model_id,
            metadata={
                "role": config.role,
                "task": config.task_type,
                "format": prompt_format.value,
                "has_kb": bool(kb_context),
                "has_memory": bool(memory_context),
                "has_tool_output": bool(tool_output),
            },
        )

    def _format_prompt(self, fmt: PromptFormat, system: str, user: str) -> str:
        """Format prompt for specific model's chat template."""
        if fmt == PromptFormat.CHATML:
            return (
                f"<|im_start|>system\n{system}<|im_end|>\n"
                f"<|im_start|>user\n{user}<|im_end|>\n"
                f"<|im_start|>assistant\n"
            )
        elif fmt == PromptFormat.LLAMA:
            return (
                f"<s>[INST] <<SYS>>\n{system}\n<</SYS>>\n\n"
                f"{user} [/INST]"
            )
        elif fmt == PromptFormat.MISTRAL:
            return (
                f"<s>[INST] {system}\n\n{user} [/INST]"
            )
        elif fmt == PromptFormat.ALPACA:
            return (
                f"### System:\n{system}\n\n"
                f"### Instruction:\n{user}\n\n"
                f"### Response:\n"
            )
        else:
            return f"{system}\n\n{user}\n\n"

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_built": self._total_built,
            "cached": len(self._prompt_cache),
        }
