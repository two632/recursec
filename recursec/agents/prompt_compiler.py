"""Prompt compiler — assembles dynamic prompts for LLMs.

Implements:
1. System prompt construction per model
2. Context injection from knowledge bases
3. Token-budget-aware truncation
4. Model-specific format templates
5. Dynamic few-shot example selection
6. Role-specific prompt assembly
7. Tool documentation injection
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class PromptFormat(str, Enum):
    CHATML = "chatml"           # <|im_start|> format
    LLAMA = "llama"             # [INST] format
    MISTRAL = "mistral"         # [INST] format (Mistral variant)
    PHI = "phi"                 # <|system|> format
    DEEPSEEK = "deepseek"       # DeepSeek format
    PLAIN = "plain"             # No special tokens


class PromptSection(str, Enum):
    SYSTEM = "system"
    ROLE = "role"
    CONTEXT = "context"
    KNOWLEDGE = "knowledge"
    TOOLS = "tools"
    TASK = "task"
    CONSTRAINTS = "constraints"
    EXAMPLES = "examples"
    HISTORY = "history"


@dataclass
class PromptBlock:
    """A block of content for prompt assembly."""
    section: PromptSection = PromptSection.SYSTEM
    content: str = ""
    priority: int = 0       # Higher = more important
    token_estimate: int = 0
    required: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "section": self.section.value,
            "priority": self.priority,
            "tokens": self.token_estimate,
            "required": self.required,
        }


@dataclass
class CompiledPrompt:
    """A fully compiled prompt."""
    system_prompt: str = ""
    user_prompt: str = ""
    format_used: PromptFormat = PromptFormat.CHATML
    total_tokens_estimate: int = 0
    sections_included: list[str] = field(default_factory=list)
    sections_dropped: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.format_used.value,
            "tokens_est": self.total_tokens_estimate,
            "included": len(self.sections_included),
            "dropped": len(self.sections_dropped),
        }


# ── Model format mappings ────────────────────────────────────

MODEL_FORMATS: dict[str, PromptFormat] = {
    "whiterabbitneo-7b": PromptFormat.CHATML,
    "qwen-coder-14b": PromptFormat.CHATML,
    "qwen-coder-7b": PromptFormat.CHATML,
    "deepseek-r1-7b": PromptFormat.DEEPSEEK,
    "deepseek-math-7b": PromptFormat.DEEPSEEK,
    "hermes-14b": PromptFormat.CHATML,
    "llama-3.1-8b": PromptFormat.LLAMA,
    "dolphin-8b": PromptFormat.CHATML,
    "mistral-7b": PromptFormat.MISTRAL,
    "codellama-13b": PromptFormat.LLAMA,
    "codellama-7b": PromptFormat.LLAMA,
    "yi-9b-200k": PromptFormat.CHATML,
    "phi-3.5-mini": PromptFormat.PHI,
    "nomic-embed": PromptFormat.PLAIN,
    "llama-guard-3": PromptFormat.LLAMA,
    "functiongemma": PromptFormat.PLAIN,
}


# ── Base system prompts ──────────────────────────────────────

ROLE_SYSTEM_PROMPTS: dict[str, str] = {
    "coordinator": (
        "You are RecurSec Coordinator, an autonomous security assessment orchestrator. "
        "Your role is to decompose targets into subtasks, assign work to specialized agents, "
        "and synthesize findings. You reason about attack surfaces, prioritize testing paths, "
        "and make strategic decisions about tool and technique selection."
    ),
    "recon": (
        "You are RecurSec Recon Agent, specializing in target reconnaissance. "
        "Map the complete attack surface: subdomains, ports, services, technologies, "
        "and entry points. Be thorough and systematic."
    ),
    "scanner": (
        "You are RecurSec Scanner Agent, specializing in vulnerability discovery. "
        "Run comprehensive scans, interpret results, correlate findings, "
        "and identify both known CVEs and novel vulnerabilities."
    ),
    "exploiter": (
        "You are RecurSec Exploit Agent, specializing in vulnerability exploitation. "
        "Develop and execute exploit chains with minimal impact. "
        "Document reproduction steps and assess real-world impact."
    ),
    "validator": (
        "You are RecurSec Validator Agent, specializing in finding verification. "
        "Cross-check all findings using alternative tools and methods. "
        "Eliminate false positives and confirm true vulnerabilities."
    ),
    "code_auditor": (
        "You are RecurSec Code Auditor, specializing in source code security analysis. "
        "Identify vulnerabilities through static analysis, taint tracking, "
        "and pattern matching across multiple languages."
    ),
    "planner": (
        "You are RecurSec Planner Agent, specializing in strategic planning. "
        "Analyze targets, generate hypotheses, plan attack chains, "
        "and optimize testing coverage."
    ),
}


# ── Tool documentation snippets ──────────────────────────────

TOOL_DOCS: dict[str, str] = {
    "nmap": "nmap: Network scanner. Usage: nmap [flags] <target>. Key flags: -sV (version), -sC (scripts), -p- (all ports), -O (OS), --script=<name>",
    "nuclei": "nuclei: Template-based vuln scanner. Usage: nuclei -u <url> -t <templates>. Key: -severity critical,high -json -silent",
    "sqlmap": "sqlmap: SQL injection tool. Usage: sqlmap -u <url> --batch --level=5 --risk=3. Key: --dbs --tables --dump --os-shell",
    "ffuf": "ffuf: Web fuzzer. Usage: ffuf -u <url>/FUZZ -w <wordlist>. Key: -mc 200,301,302 -fc 404 -fs <size>",
    "subfinder": "subfinder: Subdomain discovery. Usage: subfinder -d <domain> -silent. Key: -all -recursive",
    "httpx": "httpx: HTTP probe. Usage: httpx -l <urls> -status-code -title -tech-detect. Key: -json -silent",
    "hydra": "hydra: Brute forcer. Usage: hydra -l <user> -P <wordlist> <target> <service>. Key: -t 4 -vV",
    "semgrep": "semgrep: SAST scanner. Usage: semgrep scan --config=auto <path>. Key: --severity=ERROR --json",
    "trivy": "trivy: Container/dependency scanner. Usage: trivy image <image> or trivy fs <path>. Key: --severity CRITICAL,HIGH",
    "testssl": "testssl: SSL/TLS checker. Usage: testssl.sh <target>. Key: --json --severity HIGH",
    "gobuster": "gobuster: Directory buster. Usage: gobuster dir -u <url> -w <wordlist>. Key: -t 50 -x php,html",
    "dalfox": "dalfox: XSS scanner. Usage: dalfox url <target>. Key: --blind <callback> --mining-dict",
    "masscan": "masscan: Fast port scanner. Usage: masscan <target> -p0-65535 --rate=10000. Key: --banners -oJ",
    "amass": "amass: Attack surface mapper. Usage: amass enum -d <domain>. Key: -passive -active -brute",
    "nikto": "nikto: Web server scanner. Usage: nikto -h <target>. Key: -Tuning x -Format json",
    "wpscan": "wpscan: WordPress scanner. Usage: wpscan --url <target>. Key: --enumerate vp,vt,u --plugins-detection aggressive",
    "trufflehog": "trufflehog: Secret scanner. Usage: trufflehog git <repo-url>. Key: --json --only-verified",
    "gitleaks": "gitleaks: Git secret scanner. Usage: gitleaks detect --source=<path>. Key: --report-format json",
}


class PromptCompiler:
    """Assembles dynamic prompts for LLM queries.

    Constructs system and user prompts with
    knowledge injection, tool docs, and
    model-specific formatting.
    """

    def __init__(self, max_tokens: int = 4096) -> None:
        self._max_tokens = max_tokens
        self._log = logger.bind(component="prompt_compiler")

    def compile(
        self,
        role: str,
        task: str,
        model_id: str = "",
        knowledge_sections: list[str] | None = None,
        tool_names: list[str] | None = None,
        context: str = "",
        constraints: str = "",
        examples: list[str] | None = None,
        history: str = "",
    ) -> CompiledPrompt:
        """Compile a full prompt from components."""
        fmt = MODEL_FORMATS.get(model_id, PromptFormat.CHATML)

        blocks: list[PromptBlock] = []

        # System/role prompt (required)
        system = ROLE_SYSTEM_PROMPTS.get(role, ROLE_SYSTEM_PROMPTS.get("coordinator", ""))
        blocks.append(PromptBlock(
            section=PromptSection.SYSTEM,
            content=system,
            priority=100,
            token_estimate=self._estimate_tokens(system),
            required=True,
        ))

        # Context
        if context:
            blocks.append(PromptBlock(
                section=PromptSection.CONTEXT,
                content=context,
                priority=80,
                token_estimate=self._estimate_tokens(context),
            ))

        # Knowledge sections
        for kb_text in (knowledge_sections or []):
            blocks.append(PromptBlock(
                section=PromptSection.KNOWLEDGE,
                content=kb_text,
                priority=60,
                token_estimate=self._estimate_tokens(kb_text),
            ))

        # Tool documentation
        if tool_names:
            tool_text = self._build_tool_docs(tool_names)
            blocks.append(PromptBlock(
                section=PromptSection.TOOLS,
                content=tool_text,
                priority=70,
                token_estimate=self._estimate_tokens(tool_text),
            ))

        # Constraints
        if constraints:
            blocks.append(PromptBlock(
                section=PromptSection.CONSTRAINTS,
                content=constraints,
                priority=90,
                token_estimate=self._estimate_tokens(constraints),
                required=True,
            ))

        # Examples
        for example in (examples or []):
            blocks.append(PromptBlock(
                section=PromptSection.EXAMPLES,
                content=example,
                priority=40,
                token_estimate=self._estimate_tokens(example),
            ))

        # History
        if history:
            blocks.append(PromptBlock(
                section=PromptSection.HISTORY,
                content=history,
                priority=50,
                token_estimate=self._estimate_tokens(history),
            ))

        # Task (required)
        blocks.append(PromptBlock(
            section=PromptSection.TASK,
            content=task,
            priority=95,
            token_estimate=self._estimate_tokens(task),
            required=True,
        ))

        # Budget-aware assembly
        return self._assemble(blocks, fmt)

    def _assemble(
        self,
        blocks: list[PromptBlock],
        fmt: PromptFormat,
    ) -> CompiledPrompt:
        """Assemble blocks into a compiled prompt within budget."""
        # Sort by priority (highest first)
        sorted_blocks = sorted(blocks, key=lambda b: b.priority, reverse=True)

        included: list[PromptBlock] = []
        dropped: list[PromptBlock] = []
        total_tokens = 0

        for block in sorted_blocks:
            if total_tokens + block.token_estimate <= self._max_tokens or block.required:
                included.append(block)
                total_tokens += block.token_estimate
            else:
                dropped.append(block)

        # Build system prompt from system/role/knowledge/constraints/tools
        system_parts = []
        user_parts = []

        for block in sorted(included, key=lambda b: b.priority, reverse=True):
            if block.section in (PromptSection.SYSTEM, PromptSection.ROLE, PromptSection.CONSTRAINTS):
                system_parts.append(block.content)
            elif block.section in (PromptSection.KNOWLEDGE, PromptSection.TOOLS):
                system_parts.append(block.content)
            else:
                user_parts.append(block.content)

        system_prompt = "\n\n".join(system_parts)
        user_prompt = "\n\n".join(user_parts)

        return CompiledPrompt(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            format_used=fmt,
            total_tokens_estimate=total_tokens,
            sections_included=[b.section.value for b in included],
            sections_dropped=[b.section.value for b in dropped],
        )

    def _build_tool_docs(self, tool_names: list[str]) -> str:
        """Build tool documentation section."""
        lines = ["## Available Tools\n"]
        for name in tool_names:
            doc = TOOL_DOCS.get(name)
            if doc:
                lines.append(f"- {doc}")
        return "\n".join(lines)

    def _estimate_tokens(self, text: str) -> int:
        """Estimate token count (rough: ~4 chars per token)."""
        return len(text) // 4

    def format_for_model(
        self,
        system: str,
        user: str,
        model_id: str = "",
    ) -> str:
        """Format prompt for specific model."""
        fmt = MODEL_FORMATS.get(model_id, PromptFormat.CHATML)

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
            return f"[INST] {system}\n\n{user} [/INST]"
        elif fmt == PromptFormat.PHI:
            return (
                f"<|system|>\n{system}<|end|>\n"
                f"<|user|>\n{user}<|end|>\n"
                f"<|assistant|>\n"
            )
        elif fmt == PromptFormat.DEEPSEEK:
            return (
                f"<|begin▁of▁sentence|>{system}\n"
                f"User: {user}\n"
                f"Assistant:"
            )
        else:
            return f"{system}\n\n{user}"
