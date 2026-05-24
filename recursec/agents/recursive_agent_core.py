"""Recursive agent core — the heart of the recursive multi-agent system.

This is the central module that implements:
1. Dynamic agent instantiation with role/tools/context per task
2. Recursive task decomposition with bounded depth (max 5)
3. Step/token budgets per agent and total execution
4. Inter-agent message bus with typed messages
5. Result aggregation from child agents to parent
6. Convergence detection to prevent infinite loops
7. Agent pool with reuse for efficiency
8. State management across recursion levels
9. Parallel child execution for independent sub-tasks
10. Audit logging of all agent actions

This module replaces the simpler agent_spawner.py with a full
recursive architecture inspired by LangGraph's cyclic workflows
and AutoGen's multi-agent conversations.
"""

from __future__ import annotations

import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


# ─── Agent Roles ───

class AgentRole(str, Enum):
    COORDINATOR = "coordinator"
    RECON = "recon"
    SCANNER = "scanner"
    EXPLOIT = "exploit"
    CODE_AUDIT = "code_audit"
    NETWORK = "network"
    WEB = "web"
    OSINT = "osint"
    CLOUD = "cloud"
    MOBILE = "mobile"
    FORENSICS = "forensics"
    VALIDATOR = "validator"
    REPORTER = "reporter"
    PLANNER = "planner"
    RESEARCHER = "researcher"


class AgentState(str, Enum):
    IDLE = "idle"
    PLANNING = "planning"
    EXECUTING = "executing"
    WAITING_CHILDREN = "waiting_children"
    AGGREGATING = "aggregating"
    COMPLETED = "completed"
    FAILED = "failed"
    TERMINATED = "terminated"


class MessageType(str, Enum):
    TASK_ASSIGN = "task_assign"
    TASK_RESULT = "task_result"
    TASK_FAILED = "task_failed"
    STATUS_UPDATE = "status_update"
    CONTEXT_SHARE = "context_share"
    CONVERGENCE_CHECK = "convergence_check"
    BUDGET_WARNING = "budget_warning"
    TERMINATE = "terminate"


# ─── Data Structures ───

@dataclass
class AgentMessage:
    """Typed message between agents."""
    msg_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    msg_type: MessageType = MessageType.STATUS_UPDATE
    sender_id: str = ""
    receiver_id: str = ""
    payload: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.msg_id,
            "type": self.msg_type.value,
            "from": self.sender_id[:8],
            "to": self.receiver_id[:8],
        }


@dataclass
class TokenBudget:
    """Token budget tracking for an agent."""
    max_input_tokens: int = 8000
    max_output_tokens: int = 4000
    max_total_tokens: int = 50000
    used_input: int = 0
    used_output: int = 0
    used_total: int = 0

    @property
    def remaining_input(self) -> int:
        return max(0, self.max_input_tokens - self.used_input)

    @property
    def remaining_output(self) -> int:
        return max(0, self.max_output_tokens - self.used_output)

    @property
    def remaining_total(self) -> int:
        return max(0, self.max_total_tokens - self.used_total)

    @property
    def exhausted(self) -> bool:
        return self.remaining_total <= 0

    def consume(self, input_tokens: int = 0, output_tokens: int = 0) -> None:
        self.used_input += input_tokens
        self.used_output += output_tokens
        self.used_total += input_tokens + output_tokens

    def to_dict(self) -> dict[str, Any]:
        return {
            "used": self.used_total,
            "max": self.max_total_tokens,
            "pct": f"{self.used_total / max(self.max_total_tokens, 1):.0%}",
        }


@dataclass
class StepBudget:
    """Step budget tracking."""
    max_steps: int = 50
    used_steps: int = 0
    max_tool_calls: int = 30
    used_tool_calls: int = 0
    max_llm_calls: int = 20
    used_llm_calls: int = 0

    @property
    def exhausted(self) -> bool:
        return self.used_steps >= self.max_steps

    def step(self) -> None:
        self.used_steps += 1

    def tool_call(self) -> None:
        self.used_tool_calls += 1

    def llm_call(self) -> None:
        self.used_llm_calls += 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "steps": f"{self.used_steps}/{self.max_steps}",
            "tools": f"{self.used_tool_calls}/{self.max_tool_calls}",
            "llm": f"{self.used_llm_calls}/{self.max_llm_calls}",
        }


@dataclass
class AgentContext:
    """Context inherited from parent + task-specific."""
    target: str = ""
    phase: str = "recon"
    depth: int = 0
    parent_findings: list[dict[str, Any]] = field(default_factory=list)
    shared_context: dict[str, Any] = field(default_factory=dict)
    kb_domains: list[str] = field(default_factory=list)
    available_tools: list[str] = field(default_factory=list)
    model_preference: str = ""
    constraints: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target[:20] if self.target else "",
            "phase": self.phase,
            "depth": self.depth,
            "parent_findings": len(self.parent_findings),
            "kb_domains": len(self.kb_domains),
            "tools": len(self.available_tools),
        }


@dataclass
class AgentResult:
    """Structured result from an agent."""
    agent_id: str = ""
    role: AgentRole = AgentRole.COORDINATOR
    success: bool = False
    findings: list[dict[str, Any]] = field(default_factory=list)
    summary: str = ""
    recommendations: list[str] = field(default_factory=list)
    child_results: list[AgentResult] = field(default_factory=list)
    steps_taken: int = 0
    tokens_used: int = 0
    duration_s: float = 0.0
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent_id[:8],
            "role": self.role.value[:10],
            "ok": self.success,
            "findings": len(self.findings),
            "children": len(self.child_results),
            "duration": f"{self.duration_s:.1f}s",
        }


@dataclass
class RecursiveAgent:
    """A single agent in the recursive hierarchy."""
    agent_id: str = field(default_factory=lambda: f"agent-{uuid.uuid4().hex[:8]}")
    role: AgentRole = AgentRole.COORDINATOR
    goal: str = ""
    state: AgentState = AgentState.IDLE
    depth: int = 0
    parent_id: str = ""
    children: list[str] = field(default_factory=list)
    context: AgentContext = field(default_factory=AgentContext)
    token_budget: TokenBudget = field(default_factory=TokenBudget)
    step_budget: StepBudget = field(default_factory=StepBudget)
    messages: deque[AgentMessage] = field(default_factory=lambda: deque(maxlen=100))
    findings: list[dict[str, Any]] = field(default_factory=list)
    started_at: float = 0.0
    completed_at: float = 0.0
    last_action: str = ""
    action_history: list[str] = field(default_factory=list)

    @property
    def elapsed_s(self) -> float:
        if not self.started_at:
            return 0.0
        end = self.completed_at if self.completed_at else time.time()
        return end - self.started_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.agent_id[:8],
            "role": self.role.value[:10],
            "state": self.state.value[:10],
            "depth": self.depth,
            "children": len(self.children),
            "findings": len(self.findings),
            "elapsed": f"{self.elapsed_s:.1f}s",
        }


# ─── Role Configuration ───

ROLE_CONFIG: dict[AgentRole, dict[str, Any]] = {
    AgentRole.COORDINATOR: {
        "description": "Master coordinator that decomposes tasks and delegates",
        "can_spawn": [AgentRole.RECON, AgentRole.SCANNER, AgentRole.EXPLOIT, AgentRole.CODE_AUDIT, AgentRole.NETWORK, AgentRole.WEB, AgentRole.OSINT, AgentRole.CLOUD, AgentRole.MOBILE, AgentRole.FORENSICS, AgentRole.VALIDATOR],
        "kb_domains": ["advanced_discovery", "advanced_strategy"],
        "preferred_model": "deepseek-r1",
        "max_children": 8,
        "tools": [],
        "budget_multiplier": 2.0,
    },
    AgentRole.RECON: {
        "description": "Reconnaissance and information gathering",
        "can_spawn": [AgentRole.OSINT],
        "kb_domains": ["network", "dns", "web_vuln"],
        "preferred_model": "hermes-4-14b",
        "max_children": 3,
        "tools": ["nmap", "subfinder", "amass", "whois", "dig", "dnsrecon"],
        "budget_multiplier": 1.0,
    },
    AgentRole.SCANNER: {
        "description": "Vulnerability scanning and detection",
        "can_spawn": [AgentRole.VALIDATOR],
        "kb_domains": ["web_vuln", "network", "cloud"],
        "preferred_model": "whiterabbit",
        "max_children": 2,
        "tools": ["nuclei", "nikto", "nessus", "openvas", "trivy"],
        "budget_multiplier": 1.0,
    },
    AgentRole.EXPLOIT: {
        "description": "Exploitation and post-exploitation",
        "can_spawn": [AgentRole.VALIDATOR],
        "kb_domains": ["binary_exploitation", "web_vuln", "privesc", "lateral_movement"],
        "preferred_model": "whiterabbit",
        "max_children": 2,
        "tools": ["metasploit", "sqlmap", "burp", "hydra"],
        "budget_multiplier": 1.5,
    },
    AgentRole.CODE_AUDIT: {
        "description": "Source code security review",
        "can_spawn": [AgentRole.VALIDATOR],
        "kb_domains": ["deserialization", "web_vuln", "supply_chain"],
        "preferred_model": "qwen-coder-14b",
        "max_children": 2,
        "tools": ["semgrep", "bandit", "codeql", "trufflehog"],
        "budget_multiplier": 1.0,
    },
    AgentRole.NETWORK: {
        "description": "Network-level analysis and attacks",
        "can_spawn": [],
        "kb_domains": ["network", "lateral_movement", "dns"],
        "preferred_model": "hermes-4-14b",
        "max_children": 1,
        "tools": ["nmap", "masscan", "wireshark", "tcpdump", "arp-scan"],
        "budget_multiplier": 1.0,
    },
    AgentRole.WEB: {
        "description": "Web application security testing",
        "can_spawn": [AgentRole.VALIDATOR],
        "kb_domains": ["web_vuln", "xss", "ssrf", "api_gateway", "business_logic"],
        "preferred_model": "whiterabbit",
        "max_children": 3,
        "tools": ["burp", "zap", "ffuf", "gobuster", "wpscan", "sqlmap"],
        "budget_multiplier": 1.5,
    },
    AgentRole.OSINT: {
        "description": "Open source intelligence gathering",
        "can_spawn": [],
        "kb_domains": ["social_engineering", "threat_intel"],
        "preferred_model": "hermes-4-14b",
        "max_children": 0,
        "tools": ["theHarvester", "maltego", "sherlock", "recon-ng"],
        "budget_multiplier": 0.8,
    },
    AgentRole.CLOUD: {
        "description": "Cloud infrastructure security",
        "can_spawn": [AgentRole.VALIDATOR],
        "kb_domains": ["cloud", "container_k8s", "serverless"],
        "preferred_model": "hermes-4-14b",
        "max_children": 2,
        "tools": ["prowler", "scout", "pacu", "trivy", "kube-hunter"],
        "budget_multiplier": 1.0,
    },
    AgentRole.MOBILE: {
        "description": "Mobile application security",
        "can_spawn": [],
        "kb_domains": ["mobile"],
        "preferred_model": "qwen-coder-14b",
        "max_children": 1,
        "tools": ["frida", "objection", "jadx", "apktool", "mobsf"],
        "budget_multiplier": 1.0,
    },
    AgentRole.FORENSICS: {
        "description": "Digital forensics and incident analysis",
        "can_spawn": [],
        "kb_domains": ["forensics", "incident_response"],
        "preferred_model": "deepseek-r1",
        "max_children": 0,
        "tools": ["volatility", "autopsy", "sleuthkit", "yara"],
        "budget_multiplier": 1.0,
    },
    AgentRole.VALIDATOR: {
        "description": "Validates findings to eliminate false positives",
        "can_spawn": [],
        "kb_domains": [],
        "preferred_model": "codellama-13b",
        "max_children": 0,
        "tools": ["curl", "python", "nuclei"],
        "budget_multiplier": 0.5,
    },
    AgentRole.REPORTER: {
        "description": "Generates security reports from findings",
        "can_spawn": [],
        "kb_domains": ["compliance"],
        "preferred_model": "hermes-4-14b",
        "max_children": 0,
        "tools": [],
        "budget_multiplier": 0.5,
    },
    AgentRole.PLANNER: {
        "description": "Plans attack strategies and sequences",
        "can_spawn": [],
        "kb_domains": ["advanced_discovery", "advanced_strategy", "red_team"],
        "preferred_model": "deepseek-r1",
        "max_children": 0,
        "tools": [],
        "budget_multiplier": 0.8,
    },
    AgentRole.RESEARCHER: {
        "description": "Researches new techniques and methodologies",
        "can_spawn": [],
        "kb_domains": ["ai_ml_security", "quantum", "automotive", "satellite", "rf", "scada"],
        "preferred_model": "yi-9b-200k",
        "max_children": 0,
        "tools": [],
        "budget_multiplier": 1.0,
    },
}


# ─── Convergence Detection ───

@dataclass
class ConvergenceTracker:
    """Detects when agents are going in circles or not making progress."""
    window_size: int = 10
    action_history: deque[str] = field(default_factory=lambda: deque(maxlen=50))
    finding_counts: deque[int] = field(default_factory=lambda: deque(maxlen=20))
    last_progress_time: float = field(default_factory=time.time)
    stale_threshold_s: float = 300.0

    def record_action(self, action: str) -> None:
        self.action_history.append(action)

    def record_findings(self, count: int) -> None:
        self.finding_counts.append(count)
        if count > 0:
            self.last_progress_time = time.time()

    @property
    def is_stuck(self) -> bool:
        """Check if the agent appears stuck."""
        if len(self.action_history) < self.window_size:
            return False
        # Check for repeated actions
        recent = list(self.action_history)[-self.window_size:]
        unique = len(set(recent))
        if unique <= 2:
            return True
        # Check for stale progress
        if time.time() - self.last_progress_time > self.stale_threshold_s:
            return True
        return False

    @property
    def is_converged(self) -> bool:
        """Check if findings have converged (not finding new things)."""
        if len(self.finding_counts) < 5:
            return False
        recent = list(self.finding_counts)[-5:]
        return all(c == 0 for c in recent)


# ─── Message Bus ───

class MessageBus:
    """Inter-agent message passing system."""

    def __init__(self) -> None:
        self._queues: dict[str, deque[AgentMessage]] = {}
        self._history: list[AgentMessage] = []
        self._log = logger.bind(component="message_bus")

    def register(self, agent_id: str) -> None:
        """Register an agent with the message bus."""
        if agent_id not in self._queues:
            self._queues[agent_id] = deque(maxlen=200)

    def send(self, msg: AgentMessage) -> None:
        """Send a message to an agent."""
        if msg.receiver_id in self._queues:
            self._queues[msg.receiver_id].append(msg)
        self._history.append(msg)

    def receive(self, agent_id: str) -> AgentMessage | None:
        """Receive next message for an agent."""
        queue = self._queues.get(agent_id)
        if queue:
            try:
                return queue.popleft()
            except IndexError:
                return None
        return None

    def receive_all(self, agent_id: str) -> list[AgentMessage]:
        """Receive all pending messages for an agent."""
        queue = self._queues.get(agent_id)
        if not queue:
            return []
        msgs = list(queue)
        queue.clear()
        return msgs

    def broadcast(self, sender_id: str, msg_type: MessageType, payload: dict[str, Any]) -> None:
        """Send to all registered agents."""
        for agent_id in self._queues:
            if agent_id != sender_id:
                self.send(AgentMessage(
                    msg_type=msg_type,
                    sender_id=sender_id,
                    receiver_id=agent_id,
                    payload=payload,
                ))

    def get_history(self, limit: int = 50) -> list[dict[str, Any]]:
        return [m.to_dict() for m in self._history[-limit:]]


# ─── Agent Pool ───

class AgentPool:
    """Pool of reusable agents to avoid re-creation overhead."""

    def __init__(self, max_pool_size: int = 20) -> None:
        self._pool: dict[AgentRole, list[RecursiveAgent]] = {}
        self._max_pool_size = max_pool_size
        self._total_created = 0

    def acquire(self, role: AgentRole) -> RecursiveAgent | None:
        """Get a recycled agent from the pool, or None."""
        if role in self._pool and self._pool[role]:
            agent = self._pool[role].pop()
            agent.state = AgentState.IDLE
            agent.findings = []
            agent.children = []
            agent.action_history = []
            agent.started_at = 0.0
            agent.completed_at = 0.0
            agent.messages = deque(maxlen=100)
            return agent
        return None

    def release(self, agent: RecursiveAgent) -> None:
        """Return an agent to the pool."""
        if agent.role not in self._pool:
            self._pool[agent.role] = []
        pool = self._pool[agent.role]
        if len(pool) < self._max_pool_size:
            pool.append(agent)

    @property
    def stats(self) -> dict[str, int]:
        return {role.value: len(agents) for role, agents in self._pool.items() if agents}


# ─── Result Aggregator ───

class ResultAggregator:
    """Aggregates results from child agents into parent result."""

    def __init__(self) -> None:
        self._log = logger.bind(component="result_aggregator")

    def aggregate(self, child_results: list[AgentResult]) -> AgentResult:
        """Combine multiple child results into a single parent result."""
        all_findings: list[dict[str, Any]] = []
        all_recs: list[str] = []
        total_tokens = 0
        total_duration = 0.0
        any_success = False

        for child in child_results:
            if child.success:
                any_success = True
            all_findings.extend(child.findings)
            all_recs.extend(child.recommendations)
            total_tokens += child.tokens_used
            total_duration += child.duration_s

        # Deduplicate findings by comparing key fields
        deduped = self._deduplicate_findings(all_findings)

        # Sort findings by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        deduped.sort(key=lambda f: severity_order.get(f.get("severity", "info"), 5))

        summary_parts = []
        if deduped:
            by_sev: dict[str, int] = {}
            for f in deduped:
                s = f.get("severity", "info")
                by_sev[s] = by_sev.get(s, 0) + 1
            summary_parts.append(f"Found {len(deduped)} unique findings: " + ", ".join(f"{c} {s}" for s, c in by_sev.items()))
        summary_parts.append(f"Aggregated from {len(child_results)} agents")

        return AgentResult(
            success=any_success,
            findings=deduped,
            summary=". ".join(summary_parts),
            recommendations=list(dict.fromkeys(all_recs))[:20],
            child_results=child_results,
            tokens_used=total_tokens,
            duration_s=total_duration,
        )

    def _deduplicate_findings(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Remove duplicate findings based on key fields."""
        seen: set[str] = set()
        unique: list[dict[str, Any]] = []
        for f in findings:
            # Create dedup key from type + target + location
            key = f"{f.get('type', '')}:{f.get('target', '')}:{f.get('location', '')}:{f.get('title', '')}"
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique


# ─── Audit Logger ───

@dataclass
class AuditEntry:
    """A single audit log entry."""
    timestamp: float = field(default_factory=time.time)
    agent_id: str = ""
    action: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ts": f"{self.timestamp:.0f}",
            "agent": self.agent_id[:8],
            "action": self.action[:30],
        }


class AuditLog:
    """Tracks all agent actions for accountability."""

    def __init__(self, max_entries: int = 10000) -> None:
        self._entries: deque[AuditEntry] = deque(maxlen=max_entries)

    def log(self, agent_id: str, action: str, details: dict[str, Any] | None = None) -> None:
        self._entries.append(AuditEntry(agent_id=agent_id, action=action, details=details or {}))

    def get_entries(self, agent_id: str = "", limit: int = 100) -> list[dict[str, Any]]:
        entries = list(self._entries)
        if agent_id:
            entries = [e for e in entries if e.agent_id == agent_id]
        return [e.to_dict() for e in entries[-limit:]]


# ─── Recursive Agent Manager ───

class RecursiveAgentManager:
    """Manages the full recursive agent hierarchy.

    This is the primary interface for the agent system. It handles:
    - Creating root agents for new tasks
    - Spawning child agents from parent agents
    - Managing execution state across all agents
    - Enforcing budgets and depth limits
    - Aggregating results up the tree
    - Detecting convergence and terminating stuck agents
    """

    MAX_DEPTH = 5
    MAX_TOTAL_AGENTS = 50

    def __init__(self) -> None:
        self._agents: dict[str, RecursiveAgent] = {}
        self._bus = MessageBus()
        self._pool = AgentPool()
        self._aggregator = ResultAggregator()
        self._audit = AuditLog()
        self._convergence: dict[str, ConvergenceTracker] = {}
        self._total_created = 0
        self._log = logger.bind(component="recursive_agent_manager")

    def create_root_agent(
        self,
        goal: str,
        target: str = "",
        role: AgentRole = AgentRole.COORDINATOR,
    ) -> RecursiveAgent:
        """Create the root agent for a new task."""
        config = ROLE_CONFIG.get(role, ROLE_CONFIG[AgentRole.COORDINATOR])

        agent = RecursiveAgent(
            role=role,
            goal=goal,
            depth=0,
            context=AgentContext(
                target=target,
                kb_domains=config.get("kb_domains", []),
                available_tools=config.get("tools", []),
                model_preference=config.get("preferred_model", "hermes-4-14b"),
            ),
            token_budget=TokenBudget(
                max_total_tokens=int(50000 * config.get("budget_multiplier", 1.0)),
            ),
            step_budget=StepBudget(max_steps=50),
        )
        agent.started_at = time.time()

        self._agents[agent.agent_id] = agent
        self._bus.register(agent.agent_id)
        self._convergence[agent.agent_id] = ConvergenceTracker()
        self._total_created += 1

        self._audit.log(agent.agent_id, "created", {"role": role.value, "goal": goal[:50]})
        return agent

    def spawn_child(
        self,
        parent_id: str,
        role: AgentRole,
        goal: str,
        context_override: dict[str, Any] | None = None,
    ) -> RecursiveAgent | None:
        """Spawn a child agent from a parent."""
        parent = self._agents.get(parent_id)
        if not parent:
            return None

        # Check depth limit
        if parent.depth + 1 > self.MAX_DEPTH:
            self._log.warning("max_depth_reached", parent=parent_id, depth=parent.depth)
            return None

        # Check total agent limit
        if len(self._agents) >= self.MAX_TOTAL_AGENTS:
            self._log.warning("max_agents_reached", total=len(self._agents))
            return None

        # Check if parent can spawn this role
        parent_config = ROLE_CONFIG.get(parent.role, {})
        allowed = parent_config.get("can_spawn", [])
        if allowed and role not in allowed:
            self._log.warning("role_not_allowed", parent_role=parent.role.value, child_role=role.value)
            return None

        # Check parent's children limit
        max_children = parent_config.get("max_children", 5)
        if len(parent.children) >= max_children:
            self._log.warning("max_children_reached", parent=parent_id)
            return None

        # Try to get from pool
        agent = self._pool.acquire(role)
        child_config = ROLE_CONFIG.get(role, {})

        if not agent:
            agent = RecursiveAgent(role=role)
            self._total_created += 1

        agent.goal = goal
        agent.depth = parent.depth + 1
        agent.parent_id = parent_id
        agent.started_at = time.time()

        # Inherit + override context
        agent.context = AgentContext(
            target=parent.context.target,
            phase=parent.context.phase,
            depth=agent.depth,
            parent_findings=parent.findings[:10],
            shared_context=parent.context.shared_context.copy(),
            kb_domains=child_config.get("kb_domains", []),
            available_tools=child_config.get("tools", []),
            model_preference=child_config.get("preferred_model", "hermes-4-14b"),
        )
        if context_override:
            for k, v in context_override.items():
                if hasattr(agent.context, k):
                    setattr(agent.context, k, v)

        # Child gets fraction of parent's remaining budget
        parent_remaining = parent.token_budget.remaining_total
        child_budget = int(parent_remaining * 0.3 * child_config.get("budget_multiplier", 1.0))
        agent.token_budget = TokenBudget(max_total_tokens=max(child_budget, 5000))
        agent.step_budget = StepBudget(max_steps=int(parent.step_budget.max_steps * 0.5))

        self._agents[agent.agent_id] = agent
        self._bus.register(agent.agent_id)
        self._convergence[agent.agent_id] = ConvergenceTracker()
        parent.children.append(agent.agent_id)

        # Send task assignment
        self._bus.send(AgentMessage(
            msg_type=MessageType.TASK_ASSIGN,
            sender_id=parent_id,
            receiver_id=agent.agent_id,
            payload={"goal": goal, "target": parent.context.target},
        ))

        self._audit.log(agent.agent_id, "spawned", {
            "parent": parent_id[:8],
            "role": role.value,
            "depth": agent.depth,
        })
        return agent

    def complete_agent(self, agent_id: str, result: AgentResult) -> None:
        """Mark an agent as completed and send results to parent."""
        agent = self._agents.get(agent_id)
        if not agent:
            return

        agent.state = AgentState.COMPLETED
        agent.completed_at = time.time()
        result.agent_id = agent_id
        result.role = agent.role
        result.duration_s = agent.elapsed_s
        result.tokens_used = agent.token_budget.used_total

        # Send result to parent
        if agent.parent_id:
            self._bus.send(AgentMessage(
                msg_type=MessageType.TASK_RESULT,
                sender_id=agent_id,
                receiver_id=agent.parent_id,
                payload={"result": result.to_dict(), "findings": result.findings[:20]},
            ))

        self._audit.log(agent_id, "completed", {
            "findings": len(result.findings),
            "duration": f"{result.duration_s:.1f}s",
        })

        # Return to pool
        self._pool.release(agent)

    def fail_agent(self, agent_id: str, error: str) -> None:
        """Mark an agent as failed."""
        agent = self._agents.get(agent_id)
        if not agent:
            return

        agent.state = AgentState.FAILED
        agent.completed_at = time.time()

        if agent.parent_id:
            self._bus.send(AgentMessage(
                msg_type=MessageType.TASK_FAILED,
                sender_id=agent_id,
                receiver_id=agent.parent_id,
                payload={"error": error},
            ))

        self._audit.log(agent_id, "failed", {"error": error[:100]})

    def check_convergence(self, agent_id: str) -> bool:
        """Check if an agent has converged or is stuck."""
        tracker = self._convergence.get(agent_id)
        if not tracker:
            return False
        return tracker.is_converged or tracker.is_stuck

    def record_action(self, agent_id: str, action: str) -> None:
        """Record an agent action for convergence tracking."""
        tracker = self._convergence.get(agent_id)
        if tracker:
            tracker.record_action(action)
        agent = self._agents.get(agent_id)
        if agent:
            agent.last_action = action
            agent.action_history.append(action)
            agent.step_budget.step()

    def record_findings(self, agent_id: str, count: int) -> None:
        """Record finding count for convergence."""
        tracker = self._convergence.get(agent_id)
        if tracker:
            tracker.record_findings(count)

    def aggregate_children(self, parent_id: str) -> AgentResult:
        """Aggregate results from all children of a parent."""
        parent = self._agents.get(parent_id)
        if not parent:
            return AgentResult()

        child_results = []
        for child_id in parent.children:
            child = self._agents.get(child_id)
            if child and child.state == AgentState.COMPLETED:
                child_results.append(AgentResult(
                    agent_id=child_id,
                    role=child.role,
                    success=True,
                    findings=child.findings,
                    duration_s=child.elapsed_s,
                    tokens_used=child.token_budget.used_total,
                ))

        return self._aggregator.aggregate(child_results)

    def get_execution_tree(self) -> dict[str, Any]:
        """Get the full execution tree for visualization."""
        roots = [a for a in self._agents.values() if not a.parent_id]
        if not roots:
            return {}

        def build_tree(agent: RecursiveAgent) -> dict[str, Any]:
            node = agent.to_dict()
            node["children_data"] = []
            for child_id in agent.children:
                child = self._agents.get(child_id)
                if child:
                    node["children_data"].append(build_tree(child))
            return node

        return build_tree(roots[0]) if roots else {}

    def get_stats(self) -> dict[str, Any]:
        active = sum(1 for a in self._agents.values() if a.state in (AgentState.PLANNING, AgentState.EXECUTING, AgentState.WAITING_CHILDREN))
        completed = sum(1 for a in self._agents.values() if a.state == AgentState.COMPLETED)
        failed = sum(1 for a in self._agents.values() if a.state == AgentState.FAILED)
        total_findings = sum(len(a.findings) for a in self._agents.values())
        max_depth = max((a.depth for a in self._agents.values()), default=0)

        return {
            "total_agents": len(self._agents),
            "total_created": self._total_created,
            "active": active,
            "completed": completed,
            "failed": failed,
            "max_depth": max_depth,
            "total_findings": total_findings,
            "pool_stats": self._pool.stats,
            "message_history": len(self._audit._entries),
        }

    def build_hierarchy_prompt(self, agent_id: str) -> str:
        """Build a prompt describing the current agent hierarchy for LLM context."""
        agent = self._agents.get(agent_id)
        if not agent:
            return ""

        lines = ["## Agent Hierarchy Context"]
        lines.append(f"Your role: {agent.role.value}")
        lines.append(f"Your goal: {agent.goal}")
        lines.append(f"Depth: {agent.depth}/{self.MAX_DEPTH}")
        lines.append(f"Budget: {agent.token_budget.to_dict()}")
        lines.append(f"Steps: {agent.step_budget.to_dict()}")

        if agent.parent_id:
            parent = self._agents.get(agent.parent_id)
            if parent:
                lines.append(f"\nParent: {parent.role.value} (goal: {parent.goal[:40]})")
                if agent.context.parent_findings:
                    lines.append(f"Parent findings so far: {len(agent.context.parent_findings)}")

        if agent.children:
            lines.append(f"\nChildren ({len(agent.children)}):")
            for cid in agent.children:
                child = self._agents.get(cid)
                if child:
                    lines.append(f"  - {child.role.value}: {child.state.value} ({len(child.findings)} findings)")

        # Convergence status
        tracker = self._convergence.get(agent_id)
        if tracker and tracker.is_stuck:
            lines.append("\n⚠ STUCK DETECTED: Consider changing strategy or terminating")

        return "\n".join(lines)
