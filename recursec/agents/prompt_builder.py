"""Prompt builder — dynamic, context-aware prompt construction.

Instead of static prompt templates, this engine builds prompts dynamically:
1. Selects appropriate system persona based on task
2. Injects relevant context from working memory
3. Structures user prompt with task decomposition
4. Adds few-shot examples from learning history
5. Includes relevant knowledge from the knowledge graph
6. Formats output constraints (JSON, structured, etc.)
7. Applies chain-of-thought scaffolding
8. Manages token budget for context window

The prompt builder is model-aware: it adjusts prompt format
for different model architectures (ChatML, Llama, Mistral, etc.).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class PromptFormat(str, Enum):
    CHATML = "chatml"        # ChatML format (Qwen, Hermes, etc.)
    LLAMA = "llama"          # Llama 2/3 format
    MISTRAL = "mistral"      # Mistral instruct format
    DEEPSEEK = "deepseek"    # DeepSeek format
    GENERIC = "generic"      # Generic chat format


class TaskPersona(str, Enum):
    SECURITY_ANALYST = "security_analyst"
    PENTEST_EXPERT = "pentest_expert"
    CODE_AUDITOR = "code_auditor"
    NETWORK_ANALYST = "network_analyst"
    FORENSICS_EXPERT = "forensics_expert"
    THREAT_MODELER = "threat_modeler"
    OSINT_SPECIALIST = "osint_specialist"
    EXPLOIT_DEVELOPER = "exploit_developer"
    BLUE_TEAM = "blue_team"
    RED_TEAM = "red_team"
    GENERAL = "general"


@dataclass
class PromptContext:
    """Context to inject into prompt."""
    working_memory: str = ""       # From working memory
    knowledge: str = ""            # From knowledge graph
    history: list[str] = field(default_factory=list)  # Past relevant actions
    few_shot_examples: list[dict[str, str]] = field(default_factory=list)
    constraints: list[str] = field(default_factory=list)
    tools_available: list[str] = field(default_factory=list)
    findings_so_far: list[str] = field(default_factory=list)


@dataclass
class BuiltPrompt:
    """A constructed prompt ready for the LLM."""
    messages: list[dict[str, str]] = field(default_factory=list)
    estimated_tokens: int = 0
    persona: TaskPersona = TaskPersona.GENERAL
    format_used: PromptFormat = PromptFormat.CHATML
    metadata: dict[str, Any] = field(default_factory=dict)


# ── Persona System Prompts ──────────────────────────────────

PERSONAS: dict[str, str] = {
    "security_analyst": """You are an expert security analyst with deep knowledge of:
- Web application security (OWASP Top 10, CWE)
- Network security (protocols, firewalls, IDS/IPS)
- Cryptography (algorithms, implementations, weaknesses)
- Infrastructure security (servers, cloud, containers)
- Mobile and IoT security

You are methodical, thorough, and precise. You always:
- Provide evidence for your claims
- Rate confidence in your findings
- Consider false positives
- Follow responsible disclosure principles""",

    "pentest_expert": """You are an expert penetration tester with extensive experience in:
- Black box, grey box, and white box testing
- Exploitation of web, network, and system vulnerabilities
- Post-exploitation and privilege escalation
- Social engineering assessments
- Red team operations

You think like an attacker but operate ethically. You:
- Prioritize findings by exploitability and impact
- Chain vulnerabilities for maximum impact
- Document reproduction steps clearly
- Consider business context""",

    "code_auditor": """You are an expert code auditor specializing in:
- Static analysis (pattern matching, taint analysis, data flow)
- Identifying injection flaws (SQL, XSS, command, template)
- Authentication and authorization logic bugs
- Cryptographic implementation errors
- Race conditions and concurrency bugs
- Memory safety issues (buffer overflows, use-after-free)
- Business logic vulnerabilities

You review code with extreme attention to detail and always
provide specific line references and proof-of-concept examples.""",

    "network_analyst": """You are an expert network security analyst with deep knowledge of:
- Network protocols (TCP/IP, DNS, HTTP, TLS, etc.)
- Network reconnaissance and mapping
- Traffic analysis and anomaly detection
- Firewall and IDS/IPS evasion
- Wireless network security
- Network forensics

You analyze network data systematically and identify
security implications of network configurations.""",

    "forensics_expert": """You are a digital forensics expert specializing in:
- Incident response and evidence collection
- Memory forensics and disk analysis
- Log analysis and timeline reconstruction
- Malware analysis and reverse engineering
- Network forensics and traffic analysis

You maintain strict chain of custody principles and
document findings with forensic precision.""",

    "threat_modeler": """You are an expert threat modeler using STRIDE, DREAD, and PASTA methodologies.
You identify:
- Attack surfaces and entry points
- Trust boundaries and data flows
- Threat actors and their capabilities
- Attack vectors and kill chains
- Risk ratings and prioritization

You produce actionable threat models that guide security testing.""",

    "osint_specialist": """You are an OSINT specialist skilled in:
- Domain and subdomain enumeration
- Email and credential discovery
- Social media intelligence
- Technology fingerprinting
- Organizational mapping
- Dark web monitoring

You gather intelligence ethically and systematically.""",

    "exploit_developer": """You are an exploit developer with expertise in:
- Vulnerability analysis and root cause identification
- Proof-of-concept development
- Exploit reliability and weaponization
- Bypass techniques for security controls
- Shellcode and payload development

You create reliable exploits while maintaining operational security.""",

    "blue_team": """You are a blue team security expert focused on:
- Security monitoring and alerting
- Incident detection and response
- Security architecture review
- Hardening recommendations
- Compliance and best practices

You provide defensive recommendations with implementation details.""",

    "red_team": """You are a red team operator skilled in:
- Adversary simulation and emulation
- MITRE ATT&CK framework tactics
- Stealth and evasion techniques
- Multi-stage attack campaigns
- Physical and social engineering

You think creatively about attack paths and chaining techniques.""",

    "general": """You are a knowledgeable security professional.
Analyze the given information and provide clear, actionable insights.""",
}


# ── Output Format Templates ─────────────────────────────────

OUTPUT_FORMATS = {
    "json": """Respond ONLY with valid JSON. No markdown, no explanation outside the JSON.
Format: {schema}""",

    "structured": """Respond in this structured format:
{schema}""",

    "analysis": """Structure your response as:
## Summary
Brief overview of findings.

## Findings
For each finding:
- **Title**: Descriptive name
- **Severity**: Critical/High/Medium/Low/Info
- **Evidence**: Proof
- **Impact**: What this means
- **Recommendation**: How to fix

## Conclusion
Overall assessment.""",

    "concise": "Respond concisely. Be specific and actionable. No filler text.",
}


# ── Model Format Templates ──────────────────────────────────

MODEL_FORMATS: dict[str, dict[str, str]] = {
    "chatml": {
        "system_start": "<|im_start|>system\n",
        "system_end": "<|im_end|>\n",
        "user_start": "<|im_start|>user\n",
        "user_end": "<|im_end|>\n",
        "assistant_start": "<|im_start|>assistant\n",
        "assistant_end": "<|im_end|>\n",
    },
    "llama": {
        "system_start": "<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n\n",
        "system_end": "<|eot_id|>",
        "user_start": "<|start_header_id|>user<|end_header_id|>\n\n",
        "user_end": "<|eot_id|>",
        "assistant_start": "<|start_header_id|>assistant<|end_header_id|>\n\n",
        "assistant_end": "<|eot_id|>",
    },
    "mistral": {
        "system_start": "[INST] ",
        "system_end": " ",
        "user_start": "",
        "user_end": " [/INST]",
        "assistant_start": "",
        "assistant_end": "</s>",
    },
}

# Model name → preferred format
MODEL_FORMAT_MAP: dict[str, PromptFormat] = {
    "whiterabbitneo": PromptFormat.CHATML,
    "qwen": PromptFormat.CHATML,
    "codellama": PromptFormat.LLAMA,
    "deepseek": PromptFormat.DEEPSEEK,
    "yi": PromptFormat.CHATML,
    "hermes": PromptFormat.CHATML,
    "llama": PromptFormat.LLAMA,
    "dolphin": PromptFormat.CHATML,
    "mistral": PromptFormat.MISTRAL,
    "phi": PromptFormat.CHATML,
    "functiongemma": PromptFormat.GENERIC,
}

# Task persona mapping
TASK_TO_PERSONA: dict[str, TaskPersona] = {
    "security": TaskPersona.SECURITY_ANALYST,
    "pentest": TaskPersona.PENTEST_EXPERT,
    "code": TaskPersona.CODE_AUDITOR,
    "code_audit": TaskPersona.CODE_AUDITOR,
    "network": TaskPersona.NETWORK_ANALYST,
    "forensics": TaskPersona.FORENSICS_EXPERT,
    "threat_model": TaskPersona.THREAT_MODELER,
    "osint": TaskPersona.OSINT_SPECIALIST,
    "exploit": TaskPersona.EXPLOIT_DEVELOPER,
    "defense": TaskPersona.BLUE_TEAM,
    "red_team": TaskPersona.RED_TEAM,
    "recon": TaskPersona.OSINT_SPECIALIST,
    "vuln_scan": TaskPersona.SECURITY_ANALYST,
    "web_scan": TaskPersona.PENTEST_EXPERT,
}


class PromptBuilder:
    """Builds context-aware prompts for agent LLM calls.

    Dynamically constructs prompts with:
    - Appropriate persona for the task
    - Relevant context from memory/knowledge
    - Few-shot examples from learning history
    - Output format constraints
    - Token budget management
    """

    def __init__(self, max_context_tokens: int = 4096) -> None:
        self._max_tokens = max_context_tokens
        self._log = logger.bind(component="prompt_builder")

    def build(
        self,
        task: str,
        task_type: str = "general",
        context: PromptContext | None = None,
        output_format: str = "",
        output_schema: str = "",
        model_name: str = "",
        include_cot: bool = False,
        additional_instructions: str = "",
    ) -> BuiltPrompt:
        """Build a complete prompt for an LLM call."""
        ctx = context or PromptContext()

        # Select persona
        persona = TASK_TO_PERSONA.get(task_type, TaskPersona.GENERAL)
        system_prompt = PERSONAS.get(persona.value, PERSONAS["general"])

        # Build system message
        system_parts = [system_prompt]

        if ctx.tools_available:
            system_parts.append(f"\nAvailable tools: {', '.join(ctx.tools_available[:20])}")

        if ctx.constraints:
            system_parts.append("\nConstraints:\n" + "\n".join(f"- {c}" for c in ctx.constraints))

        # Build user message
        user_parts = [task]

        # Add context from working memory
        if ctx.working_memory:
            user_parts.append(f"\n--- Context ---\n{ctx.working_memory[:2000]}")

        # Add knowledge
        if ctx.knowledge:
            user_parts.append(f"\n--- Relevant Knowledge ---\n{ctx.knowledge[:1500]}")

        # Add history
        if ctx.history:
            user_parts.append("\n--- Recent Actions ---\n" + "\n".join(ctx.history[-5:]))

        # Add findings
        if ctx.findings_so_far:
            user_parts.append("\n--- Findings So Far ---\n" + "\n".join(ctx.findings_so_far[:5]))

        # Add output format
        if output_format:
            fmt_template = OUTPUT_FORMATS.get(output_format, "")
            if fmt_template:
                user_parts.append(f"\n--- Output Format ---\n{fmt_template.format(schema=output_schema or '{}')}")

        # Add chain-of-thought scaffolding
        if include_cot:
            user_parts.append("\nThink step by step. Show your reasoning at each step before giving a final answer.")

        # Additional instructions
        if additional_instructions:
            user_parts.append(f"\n{additional_instructions}")

        # Construct messages
        messages = [
            {"role": "system", "content": "\n".join(system_parts)},
        ]

        # Add few-shot examples
        for example in ctx.few_shot_examples[:3]:
            messages.append({"role": "user", "content": example.get("input", "")})
            messages.append({"role": "assistant", "content": example.get("output", "")})

        messages.append({"role": "user", "content": "\n".join(user_parts)})

        # Estimate tokens
        total_chars = sum(len(m["content"]) for m in messages)
        estimated_tokens = total_chars // 4

        # Trim if over budget
        if estimated_tokens > self._max_tokens:
            messages = self._trim_to_budget(messages)
            total_chars = sum(len(m["content"]) for m in messages)
            estimated_tokens = total_chars // 4

        return BuiltPrompt(
            messages=messages,
            estimated_tokens=estimated_tokens,
            persona=persona,
            format_used=self._get_model_format(model_name),
        )

    def build_tool_call(
        self,
        task: str,
        tools: list[dict[str, Any]],
        context: str = "",
    ) -> BuiltPrompt:
        """Build a prompt optimized for tool calling."""
        tools_desc = "\n".join(
            f"- {t.get('name', '')}: {t.get('description', '')[:100]}"
            for t in tools[:20]
        )

        system = f"""You are a security tool orchestrator. Select and use tools to accomplish tasks.

Available tools:
{tools_desc}

Always respond with a tool call in JSON format:
{{"tool": "tool_name", "args": {{...}}, "reasoning": "why this tool"}}"""

        user = task
        if context:
            user = f"{task}\n\nContext: {context}"

        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]

        return BuiltPrompt(
            messages=messages,
            estimated_tokens=len(system + user) // 4,
            persona=TaskPersona.GENERAL,
        )

    def build_reflection(
        self,
        action: str,
        result: str,
        goal: str,
    ) -> BuiltPrompt:
        """Build a prompt for self-reflection."""
        messages = [
            {"role": "system", "content": PERSONAS["security_analyst"]},
            {"role": "user", "content": f"""Reflect on this action:

Action: {action}
Result: {result}
Goal: {goal}

Was this effective? What should change? Respond as JSON:
{{"effective": true/false, "insight": "...", "adjustment": "..."}}"""},
        ]

        return BuiltPrompt(
            messages=messages,
            estimated_tokens=len(str(messages)) // 4,
        )

    def _get_model_format(self, model_name: str) -> PromptFormat:
        """Determine the prompt format for a model."""
        name_lower = model_name.lower()
        for key, fmt in MODEL_FORMAT_MAP.items():
            if key in name_lower:
                return fmt
        return PromptFormat.CHATML

    def _trim_to_budget(self, messages: list[dict[str, str]]) -> list[dict[str, str]]:
        """Trim messages to fit within token budget."""
        # Keep system and last user, trim middle
        if len(messages) <= 2:
            # Trim content of last message
            messages[-1]["content"] = messages[-1]["content"][:self._max_tokens * 4]
            return messages

        # Keep first (system) and last (user), trim few-shot examples
        return [messages[0], messages[-1]]
