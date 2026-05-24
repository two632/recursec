"""Recursive task decomposition engine.

Decomposes complex security tasks into sub-tasks recursively:
1. Takes a high-level goal and breaks it into atomic sub-tasks
2. Each sub-task can be further decomposed (bounded recursion)
3. Maps sub-tasks to optimal tools, models, and KBs
4. Tracks dependencies between sub-tasks
5. Generates execution plans that the workflow engine can run
6. Learns from past decompositions to improve future ones

This is the "divide and conquer" brain of the agent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class TaskGranularity(str, Enum):
    STRATEGIC = "strategic"
    TACTICAL = "tactical"
    OPERATIONAL = "operational"
    ATOMIC = "atomic"


class TaskDomain(str, Enum):
    RECON = "recon"
    SCANNING = "scanning"
    ENUMERATION = "enumeration"
    EXPLOITATION = "exploitation"
    POST_EXPLOIT = "post_exploit"
    ANALYSIS = "analysis"
    VALIDATION = "validation"
    REPORTING = "reporting"


@dataclass
class SubTask:
    """A sub-task produced by decomposition."""
    task_id: str = ""
    description: str = ""
    domain: TaskDomain = TaskDomain.RECON
    granularity: TaskGranularity = TaskGranularity.ATOMIC
    parent_id: str = ""
    children: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    model_id: str = ""
    kb_domains: list[str] = field(default_factory=list)
    estimated_duration_s: float = 60.0
    depth: int = 0
    max_depth: int = 4
    priority: int = 5

    @property
    def is_leaf(self) -> bool:
        return len(self.children) == 0

    @property
    def can_decompose(self) -> bool:
        return self.depth < self.max_depth and self.granularity != TaskGranularity.ATOMIC

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.task_id[:8],
            "desc": self.description[:25],
            "domain": self.domain.value[:6],
            "granularity": self.granularity.value[:6],
            "depth": self.depth,
            "children": len(self.children),
            "tools": len(self.tools),
        }


# Decomposition rules: how to break down strategic tasks
DECOMPOSITION_RULES: dict[str, list[dict[str, Any]]] = {
    "full_security_assessment": [
        {"desc": "Passive reconnaissance", "domain": "recon", "granularity": "tactical", "tools": ["theHarvester", "subfinder", "whois"], "kb": ["dns", "advanced_discovery"]},
        {"desc": "Active reconnaissance", "domain": "recon", "granularity": "tactical", "tools": ["nmap", "masscan"], "kb": ["network"]},
        {"desc": "Vulnerability scanning", "domain": "scanning", "granularity": "tactical", "tools": ["nuclei", "nikto"], "kb": ["web_vuln"]},
        {"desc": "Deep vulnerability analysis", "domain": "analysis", "granularity": "tactical", "model": "whiterabbit", "kb": ["web_vuln", "business_logic"]},
        {"desc": "Exploitation validation", "domain": "exploitation", "granularity": "tactical", "tools": ["sqlmap", "metasploit"], "kb": ["evasion"]},
        {"desc": "Post-exploitation assessment", "domain": "post_exploit", "granularity": "tactical", "kb": ["lateral_movement", "privesc"]},
        {"desc": "Report generation", "domain": "reporting", "granularity": "operational", "model": "hermes-4-14b"},
    ],
    "passive_recon": [
        {"desc": "DNS enumeration", "domain": "recon", "granularity": "operational", "tools": ["dig", "host"], "kb": ["dns"]},
        {"desc": "Subdomain discovery", "domain": "recon", "granularity": "operational", "tools": ["subfinder", "amass"], "kb": ["dns"]},
        {"desc": "WHOIS lookup", "domain": "recon", "granularity": "atomic", "tools": ["whois"]},
        {"desc": "Certificate transparency", "domain": "recon", "granularity": "atomic", "tools": ["crt.sh"]},
        {"desc": "Wayback Machine crawl", "domain": "recon", "granularity": "atomic", "tools": ["waybackurls"]},
        {"desc": "Technology fingerprinting", "domain": "recon", "granularity": "operational", "tools": ["whatweb", "wappalyzer"]},
        {"desc": "OSINT gathering", "domain": "recon", "granularity": "operational", "tools": ["theHarvester"], "kb": ["advanced_discovery"]},
    ],
    "active_recon": [
        {"desc": "Host discovery", "domain": "recon", "granularity": "atomic", "tools": ["nmap"]},
        {"desc": "Full port scan", "domain": "scanning", "granularity": "atomic", "tools": ["masscan", "nmap"]},
        {"desc": "Service version detection", "domain": "enumeration", "granularity": "atomic", "tools": ["nmap"]},
        {"desc": "OS fingerprinting", "domain": "enumeration", "granularity": "atomic", "tools": ["nmap"]},
        {"desc": "Script scanning", "domain": "scanning", "granularity": "atomic", "tools": ["nmap"]},
    ],
    "web_vuln_assessment": [
        {"desc": "Directory enumeration", "domain": "scanning", "granularity": "operational", "tools": ["ffuf", "gobuster"]},
        {"desc": "Injection testing", "domain": "scanning", "granularity": "tactical", "tools": ["sqlmap", "nuclei"], "kb": ["web_vuln"]},
        {"desc": "XSS testing", "domain": "scanning", "granularity": "operational", "tools": ["dalfox", "nuclei"], "kb": ["xss"]},
        {"desc": "Authentication testing", "domain": "scanning", "granularity": "operational", "tools": ["hydra", "nuclei"], "kb": ["business_logic"]},
        {"desc": "Business logic testing", "domain": "analysis", "granularity": "operational", "model": "whiterabbit", "kb": ["business_logic"]},
        {"desc": "API testing", "domain": "scanning", "granularity": "operational", "tools": ["nuclei", "ffuf"], "kb": ["api_gateway"]},
        {"desc": "SSRF testing", "domain": "scanning", "granularity": "operational", "tools": ["nuclei"], "kb": ["ssrf"]},
    ],
    "network_pentest": [
        {"desc": "Network mapping", "domain": "recon", "granularity": "operational", "tools": ["nmap", "masscan"]},
        {"desc": "Service enumeration", "domain": "enumeration", "granularity": "operational", "tools": ["nmap"]},
        {"desc": "SMB enumeration", "domain": "enumeration", "granularity": "atomic", "tools": ["crackmapexec", "enum4linux"]},
        {"desc": "LDAP enumeration", "domain": "enumeration", "granularity": "atomic", "tools": ["ldapsearch"], "kb": ["active_directory"]},
        {"desc": "SNMP enumeration", "domain": "enumeration", "granularity": "atomic", "tools": ["snmpwalk"]},
        {"desc": "Vulnerability exploitation", "domain": "exploitation", "granularity": "tactical", "tools": ["metasploit"], "kb": ["network"]},
        {"desc": "Lateral movement", "domain": "post_exploit", "granularity": "tactical", "kb": ["lateral_movement"]},
    ],
}


class RecursiveDecomposer:
    """Recursively decomposes tasks into sub-tasks."""

    def __init__(self, max_depth: int = 4) -> None:
        self._tasks: dict[str, SubTask] = {}
        self._task_counter = 0
        self._max_depth = max_depth
        self._log = logger.bind(component="recursive_decomposer")

    def decompose(
        self,
        description: str,
        domain: TaskDomain = TaskDomain.RECON,
        target: str = "",
        depth: int = 0,
        parent_id: str = "",
    ) -> SubTask:
        """Decompose a task recursively."""
        self._task_counter += 1
        task = SubTask(
            task_id=f"subtask-{self._task_counter}",
            description=description,
            domain=domain,
            parent_id=parent_id,
            depth=depth,
            max_depth=self._max_depth,
        )

        # Determine granularity
        if depth == 0:
            task.granularity = TaskGranularity.STRATEGIC
        elif depth == 1:
            task.granularity = TaskGranularity.TACTICAL
        elif depth == 2:
            task.granularity = TaskGranularity.OPERATIONAL
        else:
            task.granularity = TaskGranularity.ATOMIC

        self._tasks[task.task_id] = task

        # Try to find matching decomposition rules
        rule_key = self._match_rule(description, domain)
        if rule_key and task.can_decompose:
            rules = DECOMPOSITION_RULES[rule_key]
            for rule in rules:
                child = self.decompose(
                    description=rule["desc"],
                    domain=TaskDomain(rule.get("domain", "recon")),
                    target=target,
                    depth=depth + 1,
                    parent_id=task.task_id,
                )
                child.tools = rule.get("tools", [])
                child.model_id = rule.get("model", "")
                child.kb_domains = rule.get("kb", [])
                task.children.append(child.task_id)

        return task

    def _match_rule(self, description: str, domain: TaskDomain) -> str:
        """Match a task description to decomposition rules."""
        desc_lower = description.lower()
        # Direct keyword matching
        for rule_key in DECOMPOSITION_RULES:
            rule_words = rule_key.replace("_", " ").split()
            if all(word in desc_lower for word in rule_words):
                return rule_key

        # Domain-based matching
        domain_rules = {
            TaskDomain.RECON: "passive_recon",
            TaskDomain.SCANNING: "web_vuln_assessment",
            TaskDomain.EXPLOITATION: "network_pentest",
        }
        if domain in domain_rules:
            return domain_rules[domain]
        return ""

    def get_execution_plan(self, root_task_id: str) -> list[list[SubTask]]:
        """Get a layered execution plan from a decomposed task tree."""
        root = self._tasks.get(root_task_id)
        if not root:
            return []

        # Collect all leaf tasks
        leaves = self._collect_leaves(root_task_id)
        if not leaves:
            return [[root]]

        # Group by depth (deeper = later)
        depth_groups: dict[int, list[SubTask]] = {}
        for task in leaves:
            depth_groups.setdefault(task.depth, []).append(task)

        # Return ordered layers
        return [depth_groups[d] for d in sorted(depth_groups.keys())]

    def _collect_leaves(self, task_id: str) -> list[SubTask]:
        """Collect all leaf tasks from a tree."""
        task = self._tasks.get(task_id)
        if not task:
            return []
        if task.is_leaf:
            return [task]
        leaves = []
        for child_id in task.children:
            leaves.extend(self._collect_leaves(child_id))
        return leaves

    def get_stats(self) -> dict[str, Any]:
        atomic = sum(1 for t in self._tasks.values() if t.is_leaf)
        return {
            "total_tasks": len(self._tasks),
            "atomic_tasks": atomic,
            "max_depth_used": max((t.depth for t in self._tasks.values()), default=0),
            "rules": list(DECOMPOSITION_RULES.keys()),
        }

    def build_decomposition_prompt(self, root_task_id: str = "") -> str:
        """Build LLM prompt showing the decomposition tree."""
        if not root_task_id or root_task_id not in self._tasks:
            return f"## Task Decomposer\nAvailable rules: {', '.join(DECOMPOSITION_RULES.keys())}"

        lines = ["## Task Decomposition"]
        self._build_tree_lines(root_task_id, lines, indent=0)
        return "\n".join(lines)

    def _build_tree_lines(self, task_id: str, lines: list[str], indent: int) -> None:
        task = self._tasks.get(task_id)
        if not task:
            return
        prefix = "  " * indent + ("└─ " if indent > 0 else "")
        tools_str = f" [{', '.join(task.tools)}]" if task.tools else ""
        model_str = f" model={task.model_id}" if task.model_id else ""
        lines.append(f"{prefix}{task.description}{tools_str}{model_str}")
        for child_id in task.children:
            self._build_tree_lines(child_id, lines, indent + 1)
