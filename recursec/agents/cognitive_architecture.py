"""Cognitive architecture — unified intelligence framework.

This is the top-level brain that integrates ALL intelligence components:
1. Perception: receives inputs (user commands, tool outputs, model responses)
2. Working Memory: maintains current task context
3. Long-term Memory: episodic + semantic + procedural
4. Reasoning: chain-of-thought, hypothesis testing, meta-reasoning
5. Planning: workflow generation, task decomposition, strategy selection
6. Action: tool execution, model queries, agent spawning
7. Learning: experience replay, strategy optimization, belief updates
8. Self-monitoring: stuck detection, confidence calibration, escalation

Based on ACT-R, SOAR, and modern agent architecture research.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class PerceptionType(str, Enum):
    USER_INPUT = "user_input"
    TOOL_OUTPUT = "tool_output"
    MODEL_RESPONSE = "model_response"
    AGENT_MESSAGE = "agent_message"
    SYSTEM_EVENT = "system_event"
    ERROR = "error"
    FINDING = "finding"


class CognitivePhase(str, Enum):
    PERCEIVE = "perceive"
    COMPREHEND = "comprehend"
    PLAN = "plan"
    DECIDE = "decide"
    ACT = "act"
    MONITOR = "monitor"
    LEARN = "learn"
    REFLECT = "reflect"


class AttentionPriority(str, Enum):
    URGENT = "urgent"
    HIGH = "high"
    NORMAL = "normal"
    LOW = "low"
    BACKGROUND = "background"


@dataclass
class Perception:
    """An input to the cognitive system."""
    perception_id: str = ""
    ptype: PerceptionType = PerceptionType.USER_INPUT
    content: str = ""
    source: str = ""
    priority: AttentionPriority = AttentionPriority.NORMAL
    timestamp: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.ptype.value[:8],
            "source": self.source[:10],
            "priority": self.priority.value[:6],
            "content_len": len(self.content),
        }


@dataclass
class WorkingMemory:
    """Current task context — what the agent is thinking about RIGHT NOW."""
    current_goal: str = ""
    current_phase: CognitivePhase = CognitivePhase.PERCEIVE
    current_target: str = ""
    current_model: str = ""
    active_tools: list[str] = field(default_factory=list)
    active_kbs: list[str] = field(default_factory=list)
    recent_perceptions: list[Perception] = field(default_factory=list)
    pending_actions: list[dict[str, Any]] = field(default_factory=list)
    scratch_pad: dict[str, Any] = field(default_factory=dict)
    attention_focus: str = ""
    confidence: float = 0.5
    tokens_used: int = 0
    tokens_budget: int = 32768

    @property
    def tokens_remaining(self) -> int:
        return max(0, self.tokens_budget - self.tokens_used)

    def to_dict(self) -> dict[str, Any]:
        return {
            "goal": self.current_goal[:30],
            "phase": self.current_phase.value[:8],
            "target": self.current_target[:15],
            "model": self.current_model[:12],
            "tools": len(self.active_tools),
            "kbs": len(self.active_kbs),
            "tokens": f"{self.tokens_used}/{self.tokens_budget}",
            "confidence": f"{self.confidence:.2f}",
        }


@dataclass
class ProceduralMemory:
    """Learned procedures for common tasks."""
    procedure_id: str = ""
    name: str = ""
    trigger: str = ""
    steps: list[str] = field(default_factory=list)
    success_count: int = 0
    failure_count: int = 0
    last_used: float = 0.0

    @property
    def reliability(self) -> float:
        total = self.success_count + self.failure_count
        return self.success_count / max(total, 1)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name[:15],
            "trigger": self.trigger[:15],
            "steps": len(self.steps),
            "reliability": f"{self.reliability:.2f}",
        }


@dataclass
class Goal:
    """A goal in the goal stack."""
    goal_id: str = ""
    description: str = ""
    parent_goal_id: str = ""
    subgoals: list[str] = field(default_factory=list)
    status: str = "active"
    priority: int = 5
    progress: float = 0.0
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.goal_id[:8],
            "desc": self.description[:20],
            "status": self.status[:6],
            "progress": f"{self.progress:.0%}",
            "subgoals": len(self.subgoals),
        }


# Predefined procedures
BUILTIN_PROCEDURES: list[dict[str, Any]] = [
    {
        "name": "Web App Full Scan",
        "trigger": "web_vuln_scan",
        "steps": [
            "1. Profile target (type, tech stack, attack surface)",
            "2. Load KBs: web_vuln, xss, ssrf, business_logic, api_gateway",
            "3. Run recon: subfinder, whatweb, dig",
            "4. Run port scan: nmap -sV -sC",
            "5. Run web scan: nuclei -severity critical,high,medium",
            "6. Run directory fuzz: ffuf common wordlist",
            "7. Analyze results with WhiteRabbitNeo",
            "8. For each finding: validate with secondary tool",
            "9. Correlate findings into attack chains",
            "10. Generate report with remediation",
        ],
    },
    {
        "name": "Network Pentest",
        "trigger": "network_pentest",
        "steps": [
            "1. Host discovery: nmap -sn",
            "2. Full port scan: masscan or nmap -p-",
            "3. Service enumeration: nmap -sV -sC",
            "4. Vulnerability scan: nuclei network templates",
            "5. SMB/RPC enumeration: crackmapexec, enum4linux",
            "6. Analyze with WhiteRabbitNeo for exploitation paths",
            "7. Validate critical findings",
            "8. Check for lateral movement paths",
            "9. Correlate and report",
        ],
    },
    {
        "name": "Code Security Review",
        "trigger": "code_audit",
        "steps": [
            "1. Clone and analyze repository structure",
            "2. Run secret scanner: gitleaks",
            "3. Run SAST: semgrep with security rulesets",
            "4. Run dependency scan: trivy fs",
            "5. LLM deep review with Qwen-Coder-14B (focus on injection, auth, crypto)",
            "6. Check git history for security-relevant changes",
            "7. Correlate tool findings with LLM analysis",
            "8. Generate severity-ranked report",
        ],
    },
    {
        "name": "API Security Test",
        "trigger": "api_security",
        "steps": [
            "1. Discover API endpoints (swagger, openapi, crawl)",
            "2. Load KBs: api_gateway, business_logic, web_vuln",
            "3. Test authentication/authorization (BOLA, broken auth)",
            "4. Fuzz parameters for injection (SQLi, NoSQLi, command)",
            "5. Test rate limiting and mass assignment",
            "6. Check CORS, SSRF, and data exposure",
            "7. LLM analysis of API design patterns",
            "8. Report with OWASP API Top 10 mapping",
        ],
    },
]


# Phase transition rules
PHASE_TRANSITIONS: dict[CognitivePhase, list[CognitivePhase]] = {
    CognitivePhase.PERCEIVE: [CognitivePhase.COMPREHEND],
    CognitivePhase.COMPREHEND: [CognitivePhase.PLAN, CognitivePhase.ACT],
    CognitivePhase.PLAN: [CognitivePhase.DECIDE],
    CognitivePhase.DECIDE: [CognitivePhase.ACT, CognitivePhase.PLAN],
    CognitivePhase.ACT: [CognitivePhase.MONITOR],
    CognitivePhase.MONITOR: [CognitivePhase.LEARN, CognitivePhase.PERCEIVE, CognitivePhase.ACT],
    CognitivePhase.LEARN: [CognitivePhase.REFLECT, CognitivePhase.PERCEIVE],
    CognitivePhase.REFLECT: [CognitivePhase.PERCEIVE, CognitivePhase.PLAN],
}


class CognitiveArchitecture:
    """The unified cognitive system."""

    def __init__(self) -> None:
        self._working_memory = WorkingMemory()
        self._procedures: dict[str, ProceduralMemory] = {}
        self._goals: dict[str, Goal] = {}
        self._goal_stack: list[str] = []
        self._perception_buffer: list[Perception] = []
        self._perc_counter = 0
        self._goal_counter = 0
        self._proc_counter = 0
        self._phase_history: list[tuple[CognitivePhase, float]] = []
        self._log = logger.bind(component="cognitive_architecture")

        # Load builtin procedures
        for proc_def in BUILTIN_PROCEDURES:
            self._proc_counter += 1
            proc = ProceduralMemory(
                procedure_id=f"proc-{self._proc_counter}",
                name=proc_def["name"],
                trigger=proc_def["trigger"],
                steps=proc_def["steps"],
            )
            self._procedures[proc.trigger] = proc

    @property
    def working_memory(self) -> WorkingMemory:
        return self._working_memory

    @property
    def current_phase(self) -> CognitivePhase:
        return self._working_memory.current_phase

    def perceive(self, perception: Perception) -> None:
        """Process a new perception."""
        self._perc_counter += 1
        perception.perception_id = f"perc-{self._perc_counter}"
        self._perception_buffer.append(perception)
        self._working_memory.recent_perceptions.append(perception)
        # Keep buffer bounded
        if len(self._working_memory.recent_perceptions) > 20:
            self._working_memory.recent_perceptions = self._working_memory.recent_perceptions[-10:]
        if len(self._perception_buffer) > 100:
            self._perception_buffer = self._perception_buffer[-50:]

    def transition_phase(self, new_phase: CognitivePhase) -> bool:
        """Transition to a new cognitive phase."""
        valid_next = PHASE_TRANSITIONS.get(self._working_memory.current_phase, [])
        if new_phase not in valid_next:
            return False
        self._phase_history.append((self._working_memory.current_phase, time.time()))
        self._working_memory.current_phase = new_phase
        return True

    def push_goal(self, description: str, parent_id: str = "", priority: int = 5) -> Goal:
        """Push a new goal onto the goal stack."""
        self._goal_counter += 1
        goal = Goal(
            goal_id=f"goal-{self._goal_counter}",
            description=description,
            parent_goal_id=parent_id,
            priority=priority,
        )
        self._goals[goal.goal_id] = goal
        self._goal_stack.append(goal.goal_id)
        if parent_id and parent_id in self._goals:
            self._goals[parent_id].subgoals.append(goal.goal_id)
        return goal

    def pop_goal(self) -> Goal | None:
        """Pop the current goal from the stack."""
        if not self._goal_stack:
            return None
        goal_id = self._goal_stack.pop()
        goal = self._goals.get(goal_id)
        if goal:
            goal.status = "completed"
            goal.progress = 1.0
        return goal

    def get_current_goal(self) -> Goal | None:
        """Get the current top goal."""
        if not self._goal_stack:
            return None
        return self._goals.get(self._goal_stack[-1])

    def get_procedure(self, trigger: str) -> ProceduralMemory | None:
        """Get a procedure by trigger."""
        return self._procedures.get(trigger)

    def update_confidence(self, delta: float) -> None:
        """Update working memory confidence."""
        self._working_memory.confidence = max(0.0, min(1.0, self._working_memory.confidence + delta))

    def set_attention(self, focus: str) -> None:
        """Set the attention focus."""
        self._working_memory.attention_focus = focus

    def get_stats(self) -> dict[str, Any]:
        return {
            "phase": self._working_memory.current_phase.value,
            "goal_stack_depth": len(self._goal_stack),
            "current_goal": self.get_current_goal().description[:20] if self.get_current_goal() else "none",
            "procedures": len(self._procedures),
            "perceptions": len(self._perception_buffer),
            "confidence": f"{self._working_memory.confidence:.2f}",
            "tokens": f"{self._working_memory.tokens_used}/{self._working_memory.tokens_budget}",
        }

    def build_cognitive_prompt(self) -> str:
        """Build LLM prompt with full cognitive state.

        This is the master prompt builder that gives the LLM
        complete self-awareness about the agent's cognitive state.
        """
        lines = ["## Cognitive State"]

        # Current phase and goal
        lines.append(f"Phase: {self._working_memory.current_phase.value}")
        current = self.get_current_goal()
        if current:
            lines.append(f"Goal: {current.description}")
            lines.append(f"Progress: {current.progress:.0%}")

        # Goal stack
        if len(self._goal_stack) > 1:
            lines.append(f"\nGoal stack ({len(self._goal_stack)} deep):")
            for gid in reversed(self._goal_stack[:5]):
                goal = self._goals.get(gid)
                if goal:
                    lines.append(f"  → {goal.description[:40]}")

        # Working memory
        wm = self._working_memory
        lines.append(f"\nAttention: {wm.attention_focus or 'unfocused'}")
        lines.append(f"Confidence: {wm.confidence:.0%}")
        lines.append(f"Target: {wm.current_target}")
        if wm.active_tools:
            lines.append(f"Active tools: {', '.join(wm.active_tools[:5])}")
        if wm.active_kbs:
            lines.append(f"Active KBs: {', '.join(wm.active_kbs[:5])}")

        # Token budget
        lines.append(f"\nTokens: {wm.tokens_used}/{wm.tokens_budget} ({wm.tokens_remaining} remaining)")

        # Recent perceptions
        if wm.recent_perceptions:
            lines.append(f"\nRecent inputs ({len(wm.recent_perceptions)}):")
            for perc in wm.recent_perceptions[-3:]:
                lines.append(f"  [{perc.ptype.value}] {perc.content[:50]}")

        # Available procedure
        if wm.current_goal:
            for trigger, proc in self._procedures.items():
                if trigger in wm.current_goal.lower():
                    lines.append(f"\nMatching procedure: {proc.name}")
                    for step in proc.steps[:5]:
                        lines.append(f"  {step}")
                    break

        return "\n".join(lines)
