"""Prompt compiler — builds optimized prompts for LLM agents.

Implements:
1. Template-based prompt generation
2. Context injection into prompts
3. Few-shot example management
4. Prompt optimization (length, clarity)
5. Role-specific prompt generation
6. Tool-use prompt formatting
7. Chain-of-thought prompt construction
8. Prompt caching and reuse
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class PromptTemplate:
    """A reusable prompt template."""
    template_id: str = ""
    name: str = ""
    template: str = ""
    variables: list[str] = field(default_factory=list)
    role: str = ""
    category: str = ""        # system, task, analysis, tool_use, validation
    tokens_estimate: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.template_id, "name": self.name[:40],
            "vars": self.variables[:5], "role": self.role,
            "tokens": self.tokens_estimate,
        }


@dataclass
class FewShotExample:
    """A few-shot example for in-context learning."""
    input_text: str = ""
    output_text: str = ""
    task_type: str = ""
    quality_score: float = 0.8

    def to_dict(self) -> dict[str, Any]:
        return {
            "task": self.task_type,
            "input_len": len(self.input_text),
            "output_len": len(self.output_text),
        }


@dataclass
class CompiledPrompt:
    """A compiled prompt ready for model inference."""
    system_prompt: str = ""
    user_prompt: str = ""
    total_tokens: int = 0
    template_used: str = ""
    examples_included: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "tokens": self.total_tokens,
            "template": self.template_used[:40],
            "examples": self.examples_included,
        }


# ── Default Templates ─────────────────────────────────────────

SYSTEM_TEMPLATES: dict[str, str] = {
    "security_analyst": (
        "You are an expert security analyst performing a vulnerability assessment. "
        "Analyze the following data carefully and identify security vulnerabilities. "
        "For each finding, provide: severity (critical/high/medium/low), description, "
        "evidence, and remediation steps. Be precise and avoid false positives."
    ),
    "recon_agent": (
        "You are a reconnaissance specialist. Analyze the target information and "
        "identify: subdomains, open ports, services, technologies, and potential "
        "attack vectors. Prioritize findings by exploitability."
    ),
    "exploit_analyst": (
        "You are an exploitation specialist. Given the vulnerabilities found, "
        "determine which are exploitable, build exploitation chains, and "
        "assess the real-world impact. Focus on critical and high severity findings."
    ),
    "code_auditor": (
        "You are a code security auditor. Review the following code for security "
        "vulnerabilities including but not limited to: injection flaws, authentication "
        "issues, authorization bypasses, cryptographic weaknesses, and information "
        "disclosure. Provide specific line references and remediation."
    ),
    "validator": (
        "You are a finding validator. Your job is to critically evaluate security "
        "findings and determine if they are true positives, false positives, or "
        "need further investigation. Be skeptical and look for evidence that "
        "contradicts the finding."
    ),
    "planner": (
        "You are a security assessment planner. Given the target and initial "
        "reconnaissance data, create an optimal assessment plan. Consider: "
        "available tools, time constraints, target type, and discovered technologies."
    ),
}

TASK_TEMPLATES: dict[str, str] = {
    "analyze_scan": (
        "Analyze the following scan results from {tool}:\n\n"
        "{output}\n\n"
        "Target: {target}\n"
        "Identify all security findings. For each, provide:\n"
        "1. Title\n2. Severity\n3. Description\n4. Evidence\n5. Remediation"
    ),
    "plan_assessment": (
        "Plan a security assessment for the following target:\n\n"
        "Target: {target}\n"
        "Type: {target_type}\n"
        "Technologies: {technologies}\n"
        "Open Ports: {ports}\n\n"
        "Available tools: {tools}\n"
        "Time budget: {time_budget}\n\n"
        "Create a phased plan with tool assignments and time allocation."
    ),
    "validate_finding": (
        "Validate the following security finding:\n\n"
        "Title: {title}\n"
        "Severity: {severity}\n"
        "Description: {description}\n"
        "Evidence: {evidence}\n\n"
        "Is this a true positive, false positive, or needs more investigation? "
        "Provide your reasoning."
    ),
    "build_exploit_chain": (
        "Given these findings on {target}:\n\n"
        "{findings}\n\n"
        "Build exploitation chains that link these vulnerabilities together. "
        "For each chain, describe:\n"
        "1. Entry point\n2. Exploitation steps\n3. Final impact\n"
        "4. Success probability\n5. Required tools"
    ),
    "analyze_code": (
        "Analyze the following code for security vulnerabilities:\n\n"
        "```{language}\n{code}\n```\n\n"
        "Focus on: injection, authentication, authorization, "
        "cryptography, and information disclosure issues."
    ),
    "summarize_assessment": (
        "Summarize the following security assessment results:\n\n"
        "Target: {target}\n"
        "Duration: {duration}\n"
        "Total Findings: {total_findings}\n"
        "Critical: {critical}\n"
        "High: {high}\n"
        "Medium: {medium}\n"
        "Low: {low}\n\n"
        "Findings:\n{findings}\n\n"
        "Provide an executive summary with key risks and top recommendations."
    ),
}


class PromptCompiler:
    """Builds optimized prompts for LLM agents.

    Manages templates, few-shot examples, and
    context injection for prompt generation.
    """

    def __init__(self, max_prompt_tokens: int = 4096) -> None:
        self._templates: dict[str, PromptTemplate] = {}
        self._examples: dict[str, list[FewShotExample]] = defaultdict(list)
        self._cache: dict[str, CompiledPrompt] = {}
        self._max_tokens = max_prompt_tokens
        self._compile_count = 0
        self._cache_hits = 0
        self._log = logger.bind(component="prompt_compiler")

        self._init_templates()

    def _init_templates(self) -> None:
        """Initialize default templates."""
        for name, template in SYSTEM_TEMPLATES.items():
            self._templates[f"system:{name}"] = PromptTemplate(
                template_id=f"system:{name}",
                name=name,
                template=template,
                role=name,
                category="system",
                tokens_estimate=len(template) // 4,
            )

        for name, template in TASK_TEMPLATES.items():
            variables = re.findall(r"\{(\w+)\}", template)
            self._templates[f"task:{name}"] = PromptTemplate(
                template_id=f"task:{name}",
                name=name,
                template=template,
                variables=variables,
                category="task",
                tokens_estimate=len(template) // 4,
            )

    def add_example(
        self,
        task_type: str,
        input_text: str,
        output_text: str,
        quality_score: float = 0.8,
    ) -> None:
        """Add a few-shot example."""
        example = FewShotExample(
            input_text=input_text[:2000],
            output_text=output_text[:2000],
            task_type=task_type,
            quality_score=quality_score,
        )
        self._examples[task_type].append(example)

        # Keep best examples
        if len(self._examples[task_type]) > 10:
            self._examples[task_type].sort(key=lambda e: e.quality_score, reverse=True)
            self._examples[task_type] = self._examples[task_type][:10]

    def compile(
        self,
        role: str,
        task_template: str,
        variables: dict[str, str] | None = None,
        context: str = "",
        include_examples: bool = True,
        max_examples: int = 3,
    ) -> CompiledPrompt:
        """Compile a prompt from template and context."""
        self._compile_count += 1
        result = CompiledPrompt()

        # Get system prompt
        system_key = f"system:{role}"
        if system_key in self._templates:
            result.system_prompt = self._templates[system_key].template
        else:
            result.system_prompt = SYSTEM_TEMPLATES.get("security_analyst", "")

        # Get task template
        task_key = f"task:{task_template}"
        if task_key in self._templates:
            template = self._templates[task_key].template
            if variables:
                for var_name, var_value in variables.items():
                    template = template.replace(f"{{{var_name}}}", str(var_value)[:500])
            result.user_prompt = template
            result.template_used = task_template
        else:
            result.user_prompt = task_template

        # Add context
        if context:
            result.user_prompt = f"Context:\n{context[:1000]}\n\n{result.user_prompt}"

        # Add few-shot examples
        if include_examples and task_template in self._examples:
            examples = self._examples[task_template][:max_examples]
            if examples:
                example_text = "\n\nExamples:\n"
                for i, ex in enumerate(examples):
                    example_text += f"\nExample {i + 1}:\n"
                    example_text += f"Input: {ex.input_text[:300]}\n"
                    example_text += f"Output: {ex.output_text[:300]}\n"

                result.user_prompt = example_text + "\n\n" + result.user_prompt
                result.examples_included = len(examples)

        # Estimate tokens
        total_text = result.system_prompt + result.user_prompt
        result.total_tokens = len(total_text) // 4

        # Truncate if too long
        if result.total_tokens > self._max_tokens:
            max_chars = self._max_tokens * 4
            result.user_prompt = result.user_prompt[:max_chars - len(result.system_prompt)]
            result.total_tokens = self._max_tokens

        return result

    def compile_chain_of_thought(
        self,
        role: str,
        task: str,
        steps: list[str] | None = None,
    ) -> CompiledPrompt:
        """Compile a chain-of-thought prompt."""
        cot_prefix = (
            "Think through this step-by-step:\n\n"
        )

        if steps:
            for i, step in enumerate(steps):
                cot_prefix += f"Step {i + 1}: {step}\n"
            cot_prefix += "\nNow, following these steps:\n\n"

        return self.compile(
            role=role,
            task_template=cot_prefix + task,
            include_examples=False,
        )

    def compile_tool_use(
        self,
        available_tools: list[dict[str, str]],
        task: str,
    ) -> CompiledPrompt:
        """Compile a tool-use prompt."""
        tool_desc = "Available tools:\n\n"
        for tool in available_tools[:20]:
            tool_desc += f"- {tool.get('name', '')}: {tool.get('description', '')[:100]}\n"

        tool_desc += (
            "\nTo use a tool, respond with:\n"
            "TOOL: <tool_name>\n"
            "ARGS: <arguments>\n\n"
        )

        return self.compile(
            role="planner",
            task_template=tool_desc + task,
            include_examples=False,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "templates": len(self._templates),
            "examples": sum(len(v) for v in self._examples.values()),
            "compiles": self._compile_count,
            "cache_hits": self._cache_hits,
        }


