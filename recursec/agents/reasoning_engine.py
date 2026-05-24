"""Core reasoning engine — the brain that drives LLM interactions.

This is the central intelligence that makes the agent understand
what to do at every step. It implements:

1. Multi-strategy reasoning (Mythos-style hypothesis generation)
2. Chain-of-thought with self-correction
3. Tool-use reasoning (decide which tool, why, what params)
4. Finding analysis and severity assessment
5. Attack chain construction from individual findings
6. Autonomous decision loops (when to go deeper, pivot, or stop)
7. Multi-model debate for high-confidence decisions
8. Context-aware prompt construction per reasoning step
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ReasoningMode(str, Enum):
    CHAIN_OF_THOUGHT = "chain_of_thought"
    HYPOTHESIS_TEST = "hypothesis_test"
    TOOL_SELECTION = "tool_selection"
    OUTPUT_ANALYSIS = "output_analysis"
    ATTACK_PLANNING = "attack_planning"
    FINDING_ASSESSMENT = "finding_assessment"
    STRATEGY_SELECTION = "strategy_selection"
    SELF_CORRECTION = "self_correction"
    MULTI_MODEL_DEBATE = "multi_model_debate"
    AUTONOMOUS_DECISION = "autonomous_decision"


class ReasoningOutcome(str, Enum):
    CONTINUE = "continue"
    GO_DEEPER = "go_deeper"
    PIVOT = "pivot"
    VALIDATE = "validate"
    REPORT = "report"
    STOP = "stop"
    ESCALATE = "escalate"
    RETRY = "retry"


class ConfidenceLevel(str, Enum):
    VERY_HIGH = "very_high"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    VERY_LOW = "very_low"


@dataclass
class ReasoningStep:
    """A single reasoning step with thought process."""
    step_id: int = 0
    mode: ReasoningMode = ReasoningMode.CHAIN_OF_THOUGHT
    thought: str = ""
    observation: str = ""
    action: str = ""
    action_params: dict[str, Any] = field(default_factory=dict)
    result: str = ""
    confidence: float = 0.0
    model_used: str = ""
    tokens_used: int = 0
    duration_s: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step_id,
            "mode": self.mode.value[:12],
            "action": self.action[:20],
            "confidence": f"{self.confidence:.2f}",
            "tokens": self.tokens_used,
        }


@dataclass
class Hypothesis:
    """A vulnerability hypothesis to test."""
    hypothesis_id: str = ""
    description: str = ""
    target: str = ""
    vulnerability_type: str = ""
    test_method: str = ""
    test_tool: str = ""
    test_command: str = ""
    expected_outcome: str = ""
    actual_outcome: str = ""
    confirmed: bool = False
    confidence: float = 0.0
    severity: str = "medium"
    evidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.hypothesis_id[:8],
            "type": self.vulnerability_type[:15],
            "confirmed": self.confirmed,
            "severity": self.severity[:4],
            "confidence": f"{self.confidence:.2f}",
        }


@dataclass
class AttackChain:
    """A chain of vulnerabilities leading to higher impact."""
    chain_id: str = ""
    name: str = ""
    steps: list[dict[str, Any]] = field(default_factory=list)
    total_severity: str = "critical"
    success_probability: float = 0.0
    impact: str = ""
    mitre_techniques: list[str] = field(default_factory=list)
    prerequisites: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.chain_id[:8],
            "name": self.name[:20],
            "steps": len(self.steps),
            "severity": self.total_severity[:4],
            "prob": f"{self.success_probability:.2f}",
        }


@dataclass
class DebatePosition:
    """A position in a multi-model debate."""
    model_id: str = ""
    position: str = ""
    reasoning: str = ""
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)
    counter_arguments: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"model": self.model_id[:12], "confidence": f"{self.confidence:.2f}"}


# Reasoning prompt templates for each mode
REASONING_PROMPTS: dict[ReasoningMode, str] = {
    ReasoningMode.CHAIN_OF_THOUGHT: (
        "Think step by step about this security task.\n\n"
        "For each step, provide:\n"
        "THOUGHT: What am I thinking about?\n"
        "OBSERVATION: What do I notice?\n"
        "ACTION: What should I do next?\n"
        "REASON: Why this action?\n\n"
        "Continue until you reach a conclusion or need to execute a tool."
    ),
    ReasoningMode.HYPOTHESIS_TEST: (
        "Generate vulnerability hypotheses for this target.\n\n"
        "For each hypothesis:\n"
        "HYPOTHESIS: What vulnerability might exist?\n"
        "EVIDENCE: What suggests this vulnerability?\n"
        "TEST: How to confirm/deny this hypothesis?\n"
        "TOOL: Which tool to use for testing?\n"
        "COMMAND: Exact command to run\n"
        "EXPECTED: What would confirm the vulnerability?\n\n"
        "Generate at least 3 hypotheses ranked by likelihood."
    ),
    ReasoningMode.TOOL_SELECTION: (
        "Select the optimal tool for this task.\n\n"
        "Consider:\n"
        "1. TASK: What exactly needs to be done?\n"
        "2. TARGET: What type is the target (web/network/host/code)?\n"
        "3. OPTIONS: Available tools and their strengths\n"
        "4. CONSTRAINTS: Time, stealth, accuracy requirements\n"
        "5. DECISION: Best tool with exact parameters\n"
        "6. FALLBACK: Alternative if primary tool fails\n\n"
        "Output a specific tool command ready to execute."
    ),
    ReasoningMode.OUTPUT_ANALYSIS: (
        "Analyze this tool output for security findings.\n\n"
        "For each finding:\n"
        "FINDING: What was discovered?\n"
        "SEVERITY: Critical/High/Medium/Low/Info (with justification)\n"
        "CONFIDENCE: How certain are we? (with reasoning)\n"
        "EVIDENCE: Specific output lines proving the finding\n"
        "IMPACT: What can an attacker do with this?\n"
        "NEXT: What should we investigate further?\n"
        "FALSE_POS: Could this be a false positive? Why?\n\n"
        "Be thorough but skeptical. Eliminate false positives."
    ),
    ReasoningMode.ATTACK_PLANNING: (
        "Plan the attack approach for this target.\n\n"
        "OBJECTIVE: What are we trying to achieve?\n"
        "SURFACE: Map the attack surface\n"
        "VECTORS: List all possible entry points\n"
        "PRIORITIZE: Rank vectors by likelihood of success\n"
        "SEQUENCE: Optimal order of testing\n"
        "TOOLS: Specific tools per vector\n"
        "BUDGET: Time and token allocation\n"
        "CONTINGENCY: What if primary approach fails?\n"
        "DEPTH: When to go deeper vs move on?\n"
    ),
    ReasoningMode.FINDING_ASSESSMENT: (
        "Assess this security finding.\n\n"
        "VULNERABILITY: Describe the vulnerability\n"
        "CVSS_BASE: Rate using CVSS v3.1 metrics\n"
        "  - Attack Vector: Network/Adjacent/Local/Physical\n"
        "  - Attack Complexity: Low/High\n"
        "  - Privileges Required: None/Low/High\n"
        "  - User Interaction: None/Required\n"
        "  - Scope: Unchanged/Changed\n"
        "  - Confidentiality: None/Low/High\n"
        "  - Integrity: None/Low/High\n"
        "  - Availability: None/Low/High\n"
        "EXPLOITABILITY: How easy to exploit?\n"
        "IMPACT: Business impact if exploited\n"
        "REMEDIATION: How to fix\n"
        "CHAIN: Can this be chained with other findings?\n"
    ),
    ReasoningMode.STRATEGY_SELECTION: (
        "Select the optimal strategy for this phase.\n\n"
        "Available strategies:\n{strategies}\n\n"
        "Consider:\n"
        "1. Past performance of each strategy\n"
        "2. Target characteristics\n"
        "3. Time/resource budget remaining\n"
        "4. Findings so far\n"
        "5. Coverage gaps\n\n"
        "SELECT: Best strategy with reasoning\n"
        "PARAMS: Specific parameters for this strategy\n"
    ),
    ReasoningMode.SELF_CORRECTION: (
        "Review your previous reasoning for errors.\n\n"
        "Previous reasoning:\n{previous_reasoning}\n\n"
        "Check for:\n"
        "1. LOGIC_ERRORS: Flawed reasoning or assumptions\n"
        "2. MISSED_FINDINGS: Anything overlooked in the output?\n"
        "3. FALSE_POSITIVES: Did we report anything incorrectly?\n"
        "4. SEVERITY_ERRORS: Are severity ratings accurate?\n"
        "5. COVERAGE_GAPS: What did we not test?\n"
        "6. BETTER_APPROACH: Is there a better strategy?\n\n"
        "CORRECTIONS: List specific corrections needed\n"
        "CONFIDENCE_ADJUSTMENT: Adjust confidence levels\n"
    ),
    ReasoningMode.MULTI_MODEL_DEBATE: (
        "You are participating in a multi-model debate about this finding.\n\n"
        "Other models have provided these positions:\n{positions}\n\n"
        "YOUR TASK:\n"
        "1. STATE your position (agree/disagree/modify)\n"
        "2. REASONING: Why do you hold this position?\n"
        "3. EVIDENCE: What supports your view?\n"
        "4. COUNTER: Address other models' arguments\n"
        "5. CONFIDENCE: Your confidence level (0-1)\n"
    ),
    ReasoningMode.AUTONOMOUS_DECISION: (
        "Make an autonomous decision about next steps.\n\n"
        "Current state:\n"
        "- Findings so far: {findings_count}\n"
        "- Tokens remaining: {tokens_remaining}\n"
        "- Time elapsed: {time_elapsed}\n"
        "- Coverage: {coverage}\n\n"
        "DECIDE:\n"
        "- CONTINUE: Keep testing current vector\n"
        "- GO_DEEPER: Investigate a finding more deeply\n"
        "- PIVOT: Switch to different attack vector\n"
        "- VALIDATE: Verify existing findings\n"
        "- REPORT: Generate report with current findings\n"
        "- STOP: Assessment is complete\n\n"
        "DECISION: Your choice with detailed reasoning\n"
    ),
}

# Model routing for reasoning modes
MODE_MODEL_MAP: dict[ReasoningMode, str] = {
    ReasoningMode.CHAIN_OF_THOUGHT: "deepseek-r1",  # Best at step-by-step reasoning
    ReasoningMode.HYPOTHESIS_TEST: "whiterabbit",  # Security specialist
    ReasoningMode.TOOL_SELECTION: "functiongemma",  # Fast tool routing
    ReasoningMode.OUTPUT_ANALYSIS: "qwen-coder-14b",  # Best at parsing structured output
    ReasoningMode.ATTACK_PLANNING: "whiterabbit",  # Security planning
    ReasoningMode.FINDING_ASSESSMENT: "deepseek-r1",  # Careful reasoning
    ReasoningMode.STRATEGY_SELECTION: "hermes-4-14b",  # Good at instruction following
    ReasoningMode.SELF_CORRECTION: "deepseek-r1",  # Self-reflection
    ReasoningMode.MULTI_MODEL_DEBATE: "mistral-7b",  # Debate participant
    ReasoningMode.AUTONOMOUS_DECISION: "deepseek-r1",  # Decision making
}

# Severity scoring matrix
SEVERITY_MATRIX: dict[str, dict[str, float]] = {
    "critical": {"base_score": 9.0, "exploit_weight": 1.0, "impact_weight": 1.0},
    "high": {"base_score": 7.0, "exploit_weight": 0.8, "impact_weight": 0.9},
    "medium": {"base_score": 4.0, "exploit_weight": 0.6, "impact_weight": 0.6},
    "low": {"base_score": 2.0, "exploit_weight": 0.3, "impact_weight": 0.3},
    "info": {"base_score": 0.5, "exploit_weight": 0.1, "impact_weight": 0.1},
}


class ReasoningEngine:
    """Core reasoning engine that drives all LLM interactions."""

    def __init__(self) -> None:
        self._steps: list[ReasoningStep] = []
        self._hypotheses: list[Hypothesis] = []
        self._chains: list[AttackChain] = []
        self._debates: list[list[DebatePosition]] = []
        self._step_counter = 0
        self._hypothesis_counter = 0
        self._chain_counter = 0
        self._log = logger.bind(component="reasoning_engine")

    def get_reasoning_prompt(
        self,
        mode: ReasoningMode,
        context: dict[str, Any] | None = None,
    ) -> str:
        """Get the reasoning prompt for a mode with context filled in."""
        template = REASONING_PROMPTS.get(mode, "Think step by step.")
        ctx = context or {}
        # Fill in template variables
        for key, value in ctx.items():
            placeholder = "{" + key + "}"
            if placeholder in template:
                template = template.replace(placeholder, str(value))
        return template

    def get_model_for_mode(self, mode: ReasoningMode) -> str:
        """Get the recommended model for a reasoning mode."""
        return MODE_MODEL_MAP.get(mode, "mistral-7b")

    def create_step(
        self,
        mode: ReasoningMode,
        thought: str = "",
        observation: str = "",
        action: str = "",
        action_params: dict[str, Any] | None = None,
    ) -> ReasoningStep:
        """Create a new reasoning step."""
        self._step_counter += 1
        step = ReasoningStep(
            step_id=self._step_counter,
            mode=mode,
            thought=thought,
            observation=observation,
            action=action,
            action_params=action_params or {},
        )
        self._steps.append(step)
        if len(self._steps) > 2000:
            self._steps = self._steps[-1000:]
        return step

    def create_hypothesis(
        self,
        description: str,
        target: str,
        vulnerability_type: str,
        test_method: str = "",
        test_tool: str = "",
        test_command: str = "",
        expected_outcome: str = "",
    ) -> Hypothesis:
        """Create a vulnerability hypothesis."""
        self._hypothesis_counter += 1
        hyp = Hypothesis(
            hypothesis_id=f"hyp-{self._hypothesis_counter}",
            description=description,
            target=target,
            vulnerability_type=vulnerability_type,
            test_method=test_method,
            test_tool=test_tool,
            test_command=test_command,
            expected_outcome=expected_outcome,
        )
        self._hypotheses.append(hyp)
        return hyp

    def confirm_hypothesis(
        self,
        hypothesis_id: str,
        actual_outcome: str,
        confirmed: bool,
        confidence: float,
        severity: str = "medium",
        evidence: str = "",
    ) -> None:
        """Record the result of testing a hypothesis."""
        for hyp in self._hypotheses:
            if hyp.hypothesis_id == hypothesis_id:
                hyp.actual_outcome = actual_outcome
                hyp.confirmed = confirmed
                hyp.confidence = confidence
                hyp.severity = severity
                hyp.evidence = evidence
                break

    def build_attack_chain(
        self,
        findings: list[dict[str, Any]],
    ) -> AttackChain | None:
        """Build an attack chain from individual findings."""
        if len(findings) < 2:
            return None

        self._chain_counter += 1
        # Sort by phase (recon → exploit → post-exploit)
        phase_order = {"recon": 0, "scanning": 1, "enumeration": 2, "exploitation": 3, "post_exploit": 4}
        sorted_findings = sorted(
            findings,
            key=lambda f: phase_order.get(f.get("phase", ""), 99),
        )

        chain = AttackChain(
            chain_id=f"chain-{self._chain_counter}",
            name=f"Attack chain: {sorted_findings[0].get('title', 'Unknown')} → {sorted_findings[-1].get('title', 'Unknown')}",
            steps=[
                {
                    "order": i,
                    "finding": f.get("title", ""),
                    "severity": f.get("severity", ""),
                    "enables": sorted_findings[i + 1].get("title", "") if i < len(sorted_findings) - 1 else "objective",
                }
                for i, f in enumerate(sorted_findings)
            ],
            total_severity="critical" if any(f.get("severity") == "critical" for f in findings) else "high",
            success_probability=min(f.get("confidence", 0.5) for f in findings),
            impact=sorted_findings[-1].get("impact", ""),
        )
        self._chains.append(chain)
        return chain

    def assess_severity(
        self,
        finding: dict[str, Any],
    ) -> dict[str, Any]:
        """Assess finding severity using CVSS-like scoring."""
        vuln_type = finding.get("type", "").lower()
        evidence_strength = finding.get("confidence", 0.5)

        # Default to medium
        base_severity = "medium"
        base_score = 4.0

        # Heuristic severity from vulnerability type
        critical_types = ["rce", "sqli", "command_injection", "ssrf_internal", "auth_bypass", "privesc"]
        high_types = ["xss_stored", "idor", "path_traversal", "xxe", "deserialization", "ssti"]
        medium_types = ["xss_reflected", "csrf", "open_redirect", "info_disclosure", "cors"]
        low_types = ["xss_dom", "clickjacking", "verbose_errors", "directory_listing"]

        for ct in critical_types:
            if ct in vuln_type:
                base_severity = "critical"
                base_score = 9.0
                break
        else:
            for ht in high_types:
                if ht in vuln_type:
                    base_severity = "high"
                    base_score = 7.0
                    break
            else:
                for mt in medium_types:
                    if mt in vuln_type:
                        base_severity = "medium"
                        base_score = 4.0
                        break
                else:
                    for lt in low_types:
                        if lt in vuln_type:
                            base_severity = "low"
                            base_score = 2.0
                            break

        # Adjust by confidence
        adjusted_score = base_score * evidence_strength

        return {
            "severity": base_severity,
            "base_score": base_score,
            "adjusted_score": adjusted_score,
            "confidence": evidence_strength,
        }

    def decide_next_action(
        self,
        findings_count: int,
        tokens_remaining: int,
        time_elapsed_s: float,
        coverage_pct: float,
        current_phase: str,
    ) -> ReasoningOutcome:
        """Autonomous decision about what to do next."""
        # Out of budget → report
        if tokens_remaining < 500:
            return ReasoningOutcome.REPORT

        # Time limit → report
        if time_elapsed_s > 3000:
            return ReasoningOutcome.REPORT

        # Good coverage and findings → validate then report
        if coverage_pct > 0.8 and findings_count > 5:
            return ReasoningOutcome.VALIDATE

        # Low coverage → continue
        if coverage_pct < 0.3:
            return ReasoningOutcome.CONTINUE

        # Found critical findings → go deeper
        if findings_count > 0 and tokens_remaining > 2000:
            return ReasoningOutcome.GO_DEEPER

        # No findings and tried enough → pivot
        if findings_count == 0 and time_elapsed_s > 300:
            return ReasoningOutcome.PIVOT

        return ReasoningOutcome.CONTINUE

    def build_reasoning_context(
        self,
        task_description: str,
        target: str,
        findings: list[dict[str, Any]] | None = None,
        tool_outputs: list[str] | None = None,
        previous_steps: int = 5,
    ) -> str:
        """Build context string from recent reasoning for LLM."""
        parts = [
            f"Task: {task_description}",
            f"Target: {target}",
        ]

        if findings:
            parts.append(f"\nFindings so far ({len(findings)}):")
            for f in findings[:5]:
                parts.append(f"  [{f.get('severity', '?')}] {f.get('title', 'Untitled')}")

        if tool_outputs:
            parts.append(f"\nRecent tool outputs ({len(tool_outputs)}):")
            for out in tool_outputs[-3:]:
                parts.append(f"  {out[:200]}")

        # Recent reasoning steps
        recent = self._steps[-previous_steps:] if self._steps else []
        if recent:
            parts.append(f"\nRecent reasoning ({len(recent)} steps):")
            for step in recent:
                parts.append(f"  [{step.mode.value}] {step.thought[:100]}")
                if step.action:
                    parts.append(f"    → {step.action[:80]}")

        # Confirmed hypotheses
        confirmed = [h for h in self._hypotheses if h.confirmed]
        if confirmed:
            parts.append(f"\nConfirmed hypotheses ({len(confirmed)}):")
            for h in confirmed[-5:]:
                parts.append(f"  [{h.severity}] {h.description[:80]}")

        return "\n".join(parts)

    def get_stats(self) -> dict[str, Any]:
        """Get engine statistics."""
        mode_counts: dict[str, int] = {}
        for step in self._steps:
            key = step.mode.value
            mode_counts[key] = mode_counts.get(key, 0) + 1

        return {
            "total_steps": len(self._steps),
            "hypotheses": len(self._hypotheses),
            "confirmed": len([h for h in self._hypotheses if h.confirmed]),
            "chains": len(self._chains),
            "debates": len(self._debates),
            "by_mode": mode_counts,
        }

    def build_reasoning_prompt(self) -> str:
        """Build LLM prompt summarizing reasoning state."""
        stats = self.get_stats()
        lines = ["## Reasoning Engine State"]
        lines.append(f"Steps: {stats['total_steps']}")
        lines.append(f"Hypotheses: {stats['hypotheses']} (confirmed: {stats['confirmed']})")
        lines.append(f"Attack Chains: {stats['chains']}")
        if self._steps:
            last = self._steps[-1]
            lines.append(f"Last step: [{last.mode.value}] {last.thought[:60]}")
        return "\n".join(lines)
