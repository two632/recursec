"""Prompt compiler — builds optimized prompts tailored to each model's strengths.

Implements:
1. Model-specific prompt formatting
2. System prompt library for different roles
3. Few-shot example injection
4. Context window management within prompts
5. Dynamic prompt assembly from components
6. Prompt versioning and A/B testing integration
7. Chain-of-thought instruction insertion
8. Output format specification
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class PromptComponent:
    """A reusable prompt component."""
    component_id: str = ""
    name: str = ""
    content: str = ""
    category: str = ""           # system, context, instruction, example, output_format
    model_affinity: list[str] = field(default_factory=list)
    token_estimate: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.component_id,
            "name": self.name[:25],
            "category": self.category[:15],
            "tokens": self.token_estimate,
        }


@dataclass
class CompiledPrompt:
    """A fully compiled prompt ready for inference."""
    prompt_id: str = ""
    model_id: str = ""
    system_prompt: str = ""
    messages: list[dict[str, str]] = field(default_factory=list)
    estimated_tokens: int = 0
    components_used: list[str] = field(default_factory=list)
    compiled_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.prompt_id,
            "model": self.model_id[:20],
            "messages": len(self.messages),
            "est_tokens": self.estimated_tokens,
            "components": len(self.components_used),
        }


# ── System Prompts ────────────────────────────────────────────

SYSTEM_PROMPTS: dict[str, str] = {
    "security_analyst": (
        "You are an expert security analyst conducting an authorized security assessment. "
        "Analyze the provided data for vulnerabilities, misconfigurations, and security risks. "
        "For each finding, provide: title, severity (critical/high/medium/low), description, "
        "evidence, and remediation. Be thorough but avoid false positives. "
        "Only report findings you have evidence for. "
        "Go beyond basic vulnerability scanning — look for emergent complexity bugs "
        "(cache desync, consistency windows, cross-service races), timing side channels, "
        "business logic flaws (price manipulation, workflow skipping, IDOR), "
        "AI/LLM vulnerabilities (prompt injection, RAG poisoning, excessive agency), "
        "supply chain risks (dependency confusion, typosquatting), "
        "and cloud-specific misconfigurations (SSRF to metadata, IAM escalation). "
        "These advanced attack surfaces are often missed by traditional scanners."
    ),
    "code_auditor": (
        "You are an expert code security auditor. Review the provided code for security "
        "vulnerabilities including injection flaws, authentication issues, authorization "
        "bypasses, cryptographic weaknesses, and unsafe deserialization. "
        "Trace data flow from user inputs to sensitive operations. "
        "Provide specific line numbers, CWE IDs, and remediation for each finding."
    ),
    "recon_analyst": (
        "You are a reconnaissance specialist. Analyze the provided reconnaissance data "
        "to build a comprehensive picture of the target. Go beyond basic port/service detection: "
        "(1) Map full infrastructure topology including CDNs, WAFs, load balancers, reverse proxies. "
        "(2) Discover hidden attack surface: forgotten subdomains, debug endpoints, dev environments, "
        "exposed git repos, backup files, API docs (swagger/graphql). "
        "(3) Deep tech fingerprinting: exact framework versions, auth mechanisms (JWT vs session), "
        "database backend, caching layer, API style. "
        "(4) Look for cloud resource exposure: S3 buckets, Azure blobs, GCS. "
        "(5) Check certificate transparency for internal hostnames in SANs. "
        "(6) Identify microservice boundaries from URL patterns and API versioning. "
        "Each technology has known vulnerability patterns — identify the full stack to guide testing."
    ),
    "exploit_analyst": (
        "You are an exploitation specialist. Given the vulnerabilities and target information, "
        "determine the most effective exploitation approach. Think about CHAINING findings: "
        "(1) SSRF → cloud metadata → IAM creds → full account compromise. "
        "(2) XSS → CSRF → admin password change → account takeover. "
        "(3) IDOR → info disclosure → password reset → account takeover. "
        "(4) SQLi → admin creds → RCE via admin panel. "
        "Individual findings may be low severity but CHAINED they become critical. "
        "For validation, use SAFE techniques: read-only SQLi, DNS callbacks for SSRF/RCE, "
        "alert(document.domain) for XSS. Prove exploitation without causing damage. "
        "After initial access, assess lateral movement: what internal services, databases, "
        "cloud resources, and other accounts can be reached from this foothold?"
    ),
    "planner": (
        "You are a security assessment planner. Create a detailed plan for the security "
        "assessment. Consider scope, tools, and strategy selection based on TARGET TYPE: "
        "For web apps: test business logic (price manipulation, workflow bypass, IDOR), "
        "timing/race conditions, API gateway bypasses, crypto weaknesses, supply chain. "
        "For microservices: focus on emergent complexity (cache desync, consistency windows, "
        "cross-service races, cascading failures). "
        "For AI/LLM features: prompt injection, RAG poisoning, tool abuse, info disclosure. "
        "For cloud: SSRF to metadata, IAM misconfig, public storage, container escape. "
        "For e-commerce: financial logic abuse, double-spend races, coupon stacking. "
        "Prioritize by: (1) High-impact, easy to exploit, (2) Chained attacks, "
        "(3) Advanced surfaces that scanners miss. Think step by step."
    ),
    "validator": (
        "You are a finding validator. Critically evaluate the reported vulnerability. "
        "Consider: Is the evidence sufficient? Could this be a false positive? "
        "What additional testing would confirm or refute this finding? "
        "For emergent/timing bugs: Was the race condition reliably reproduced? "
        "For business logic: Does the behavior actually violate business rules? "
        "For AI/LLM findings: Did the injection actually change model behavior? "
        "For supply chain: Is the vulnerable dependency actually reachable? "
        "Be especially skeptical of: informational findings presented as vulns, "
        "theoretical attacks without PoC, and findings that rely on unlikely preconditions. "
        "Rate your confidence 0-1 and explain your reasoning."
    ),
    "reasoning": (
        "You are a deep reasoning engine. Think through problems step by step. "
        "Consider multiple hypotheses, evaluate evidence for and against each, "
        "and reach well-supported conclusions. Use <thinking> tags for your "
        "internal reasoning process."
    ),
}

# ── Model-specific Formatting ─────────────────────────────────

MODEL_FORMATS: dict[str, dict[str, str]] = {
    "whiterabbitneo-7b": {
        "cot_prefix": "Let me analyze this from a security perspective:\n",
        "output_prefix": "## Security Analysis\n",
    },
    "deepseek-r1-7b": {
        "cot_prefix": "<think>\n",
        "cot_suffix": "</think>\n",
        "output_prefix": "After careful reasoning:\n",
    },
    "qwen-coder-14b": {
        "cot_prefix": "Let me review this code systematically:\n",
        "output_prefix": "## Code Review Findings\n",
    },
    "hermes-14b": {
        "cot_prefix": "Let me think through this step by step:\n",
        "output_prefix": "Based on my analysis:\n",
    },
}

# ── Few-Shot Examples ─────────────────────────────────────────

FEW_SHOT_EXAMPLES: dict[str, list[dict[str, str]]] = {
    "finding_report": [
        {
            "role": "user",
            "content": "Analyze this nmap output:\n22/tcp open ssh OpenSSH 7.2p2\n80/tcp open http Apache 2.4.18",
        },
        {
            "role": "assistant",
            "content": '{"findings": [{"title": "Outdated OpenSSH 7.2p2", "severity": "high", '
                        '"description": "SSH server running OpenSSH 7.2p2 which has known vulnerabilities '
                        'including CVE-2016-10009 (agent forwarding) and CVE-2016-10012 (privilege escalation)", '
                        '"evidence": "nmap service detection: 22/tcp open ssh OpenSSH 7.2p2", '
                        '"remediation": "Upgrade OpenSSH to latest version (9.x)"}]}',
        },
    ],
    "tool_selection": [
        {
            "role": "user",
            "content": "Target has port 80 (Apache) and 443 (nginx) open. What tools should I use?",
        },
        {
            "role": "assistant",
            "content": '{"tools": ["nuclei -u https://target -severity critical,high", '
                        '"nikto -h http://target", "ffuf -u https://target/FUZZ -w /usr/share/wordlists/dirb/common.txt", '
                        '"whatweb https://target"], '
                        '"reasoning": "Mix of active scanning (nuclei, nikto) and content discovery (ffuf) '
                        'with technology fingerprinting (whatweb)"}',
        },
    ],
}


class PromptCompiler:
    """Builds optimized prompts tailored to each model's strengths.

    Assembles system prompts, few-shot examples, context,
    advanced strategy knowledge, and instructions into
    model-optimized prompts.
    """

    def __init__(self) -> None:
        self._components: dict[str, PromptComponent] = {}
        self._compile_counter = 0
        self._component_counter = 0
        self._strategy_kb: Any = None
        self._log = logger.bind(component="prompt_compiler")

    def set_strategy_kb(self, strategy_kb: Any) -> None:
        """Set the advanced strategy knowledge base for prompt injection."""
        self._strategy_kb = strategy_kb

    def compile(
        self,
        role: str,
        task: str,
        model_id: str = "",
        context: str = "",
        data: str = "",
        include_examples: bool = True,
        include_cot: bool = True,
        output_format: str = "json",
        max_tokens: int = 4096,
        target_type: str = "",
        phase: str = "",
    ) -> CompiledPrompt:
        """Compile a full prompt for a specific model and task."""
        self._compile_counter += 1

        # Get system prompt
        system_prompt = SYSTEM_PROMPTS.get(role, SYSTEM_PROMPTS.get("security_analyst", ""))

        # Build messages
        messages: list[dict[str, str]] = []
        components_used: list[str] = [f"system:{role}"]

        # Add few-shot examples if requested
        if include_examples:
            examples = self._select_examples(task)
            messages.extend(examples)
            if examples:
                components_used.append("few_shot")

        # Inject strategy knowledge if available
        strategy_context = ""
        if self._strategy_kb and (target_type or phase):
            strategy_phase = phase
            if not strategy_phase:
                role_phase_map = {
                    "recon_analyst": "recon",
                    "security_analyst": "discovery",
                    "code_auditor": "discovery",
                    "exploit_analyst": "exploitation",
                    "planner": "recon",
                    "validator": "discovery",
                }
                strategy_phase = role_phase_map.get(role, "")
            if strategy_phase:
                strategy_context = self._strategy_kb.build_phase_prompt(
                    phase=strategy_phase,
                    target_type=target_type,
                    max_fragments=3,
                )

        # Build user message
        user_content = self._build_user_message(
            task=task,
            context=context,
            data=data,
            model_id=model_id,
            include_cot=include_cot,
            output_format=output_format,
            strategy_context=strategy_context,
        )

        messages.append({"role": "user", "content": user_content})

        # Estimate tokens (rough: 4 chars per token)
        total_chars = len(system_prompt) + sum(len(m["content"]) for m in messages)
        estimated_tokens = total_chars // 4

        # Truncate if over budget
        if estimated_tokens > max_tokens * 0.8:
            messages, estimated_tokens = self._truncate_messages(
                messages, max_tokens, system_prompt
            )

        return CompiledPrompt(
            prompt_id=f"cp-{self._compile_counter}",
            model_id=model_id,
            system_prompt=system_prompt,
            messages=messages,
            estimated_tokens=estimated_tokens,
            components_used=components_used,
        )

    def _build_user_message(
        self,
        task: str,
        context: str,
        data: str,
        model_id: str,
        include_cot: bool,
        output_format: str,
        strategy_context: str = "",
    ) -> str:
        """Build the user message content."""
        parts = []

        # Model-specific CoT prefix
        if include_cot:
            model_fmt = MODEL_FORMATS.get(model_id, {})
            cot_prefix = model_fmt.get("cot_prefix", "Think step by step:\n")
            parts.append(cot_prefix)

        # Context
        if context:
            parts.append(f"Context:\n{context}\n")

        # Inject advanced strategy knowledge
        if strategy_context:
            parts.append(f"{strategy_context}\n")

        # Task
        parts.append(f"Task: {task}\n")

        # Data
        if data:
            parts.append(f"Data:\n{data}\n")

        # Output format
        if output_format == "json":
            parts.append("\nRespond in JSON format.")
        elif output_format == "structured":
            parts.append("\nProvide a structured response with clear sections.")

        return "\n".join(parts)

    @staticmethod
    def _select_examples(task: str) -> list[dict[str, str]]:
        """Select relevant few-shot examples."""
        task_lower = task.lower()

        if any(kw in task_lower for kw in ("finding", "vulnerability", "analyze")):
            return FEW_SHOT_EXAMPLES.get("finding_report", [])

        if any(kw in task_lower for kw in ("tool", "scan", "what to use")):
            return FEW_SHOT_EXAMPLES.get("tool_selection", [])

        return []

    @staticmethod
    def _truncate_messages(
        messages: list[dict[str, str]],
        max_tokens: int,
        system_prompt: str,
    ) -> tuple[list[dict[str, str]], int]:
        """Truncate messages to fit within token budget."""
        budget = max_tokens - len(system_prompt) // 4

        truncated = []
        used = 0

        for msg in messages:
            msg_tokens = len(msg["content"]) // 4
            if used + msg_tokens > budget:
                # Truncate this message
                remaining = (budget - used) * 4
                truncated.append({
                    "role": msg["role"],
                    "content": msg["content"][:remaining],
                })
                used = budget
                break
            else:
                truncated.append(msg)
                used += msg_tokens

        return truncated, used

    def register_component(
        self,
        name: str,
        content: str,
        category: str = "instruction",
        model_affinity: list[str] | None = None,
    ) -> PromptComponent:
        """Register a reusable prompt component."""
        self._component_counter += 1
        component = PromptComponent(
            component_id=f"pc-{self._component_counter}",
            name=name,
            content=content,
            category=category,
            model_affinity=model_affinity or [],
            token_estimate=len(content) // 4,
        )
        self._components[component.component_id] = component
        return component

    def get_stats(self) -> dict[str, Any]:
        return {
            "compiled": self._compile_counter,
            "components": len(self._components),
            "system_prompts": len(SYSTEM_PROMPTS),
            "examples": len(FEW_SHOT_EXAMPLES),
        }
