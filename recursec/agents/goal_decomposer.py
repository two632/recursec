"""Goal decomposer — recursively decomposes high-level goals into actionable sub-goals.

Implements:
1. AND/OR goal trees
2. Goal precondition checking
3. Goal achievement verification
4. Recursive sub-goal generation
5. Goal priority assignment
6. Dependency tracking between goals
7. Goal state machine (proposed → active → achieved/failed/abandoned)
8. Goal selection heuristics (most achievable, highest impact)
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class GoalStatus(str, Enum):
    PROPOSED = "proposed"
    ACTIVE = "active"
    ACHIEVED = "achieved"
    FAILED = "failed"
    ABANDONED = "abandoned"
    BLOCKED = "blocked"


class GoalType(str, Enum):
    AND = "and"     # All sub-goals must be achieved
    OR = "or"       # Any sub-goal achieves this goal
    LEAF = "leaf"   # Directly actionable


@dataclass
class Goal:
    """A goal in the goal tree."""
    goal_id: str = ""
    description: str = ""
    goal_type: GoalType = GoalType.LEAF
    status: GoalStatus = GoalStatus.PROPOSED
    priority: float = 0.5          # 0.0-1.0
    impact: float = 0.5            # Expected impact if achieved
    achievability: float = 0.5     # Estimated probability of success
    parent_id: str = ""
    sub_goal_ids: list[str] = field(default_factory=list)
    preconditions: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)    # For leaf goals
    result: dict[str, Any] = field(default_factory=dict)
    depth: int = 0
    created_at: float = field(default_factory=time.time)
    achieved_at: float = 0.0

    @property
    def utility(self) -> float:
        """Expected utility = impact * achievability * priority."""
        return self.impact * self.achievability * self.priority

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.goal_id,
            "desc": self.description[:60],
            "type": self.goal_type.value,
            "status": self.status.value,
            "priority": round(self.priority, 2),
            "utility": round(self.utility, 2),
            "sub_goals": len(self.sub_goal_ids),
            "depth": self.depth,
        }


# ── Goal Templates ────────────────────────────────────────────

GOAL_TEMPLATES: dict[str, dict[str, Any]] = {
    "assess_web_target": {
        "desc": "Complete web application security assessment",
        "type": "and",
        "sub_goals": [
            {
                "desc": "Enumerate attack surface",
                "type": "and",
                "sub_goals": [
                    {"desc": "Discover subdomains", "type": "leaf",
                     "actions": ["subfinder", "amass"], "impact": 0.6},
                    {"desc": "Identify open ports", "type": "leaf",
                     "actions": ["nmap", "masscan"], "impact": 0.7},
                    {"desc": "Fingerprint technologies", "type": "leaf",
                     "actions": ["whatweb", "httpx"], "impact": 0.5},
                ],
            },
            {
                "desc": "Find vulnerabilities",
                "type": "and",
                "sub_goals": [
                    {"desc": "Scan for known CVEs", "type": "leaf",
                     "actions": ["nuclei"], "impact": 0.8},
                    {"desc": "Test for injection flaws", "type": "or",
                     "sub_goals": [
                         {"desc": "Test SQL injection", "type": "leaf",
                          "actions": ["sqlmap"], "impact": 0.9},
                         {"desc": "Test XSS", "type": "leaf",
                          "actions": ["dalfox"], "impact": 0.7},
                         {"desc": "Test command injection", "type": "leaf",
                          "actions": ["manual_test"], "impact": 0.9},
                     ]},
                    {"desc": "Check authentication", "type": "leaf",
                     "actions": ["manual_test"], "impact": 0.8},
                ],
            },
            {
                "desc": "Validate findings",
                "type": "leaf",
                "actions": ["cross_validate"],
                "preconditions": ["Find vulnerabilities"],
                "impact": 0.7,
            },
        ],
    },
    "assess_network_target": {
        "desc": "Complete network security assessment",
        "type": "and",
        "sub_goals": [
            {"desc": "Discover live hosts", "type": "leaf",
             "actions": ["nmap"], "impact": 0.6},
            {"desc": "Scan all ports on live hosts", "type": "leaf",
             "actions": ["nmap", "masscan"], "impact": 0.7},
            {"desc": "Enumerate services", "type": "leaf",
             "actions": ["nmap"], "impact": 0.7},
            {"desc": "Scan for vulnerabilities", "type": "leaf",
             "actions": ["nuclei", "nmap"], "impact": 0.8},
            {"desc": "Test credentials", "type": "leaf",
             "actions": ["hydra"], "impact": 0.8},
        ],
    },
}


class GoalDecomposer:
    """Recursively decomposes high-level goals into actionable sub-goals.

    Uses AND/OR goal trees with utility-based selection
    and precondition checking.
    """

    def __init__(self, max_depth: int = 5) -> None:
        self._goals: dict[str, Goal] = {}
        self._goal_counter = 0
        self._max_depth = max_depth
        self._log = logger.bind(component="goal_decomposer")

    def decompose(
        self,
        description: str,
        template: str = "",
        depth: int = 0,
        parent_id: str = "",
    ) -> Goal:
        """Decompose a goal using a template or manually."""
        self._goal_counter += 1
        goal_id = f"goal-{self._goal_counter}"

        template_data = GOAL_TEMPLATES.get(template, {})
        if template_data:
            return self._build_from_template(
                template_data, depth=depth, parent_id=parent_id,
            )

        goal = Goal(
            goal_id=goal_id,
            description=description,
            depth=depth,
            parent_id=parent_id,
        )
        self._goals[goal_id] = goal
        return goal

    def _build_from_template(
        self,
        template: dict[str, Any],
        depth: int = 0,
        parent_id: str = "",
    ) -> Goal:
        """Build goal tree from template."""
        if depth > self._max_depth:
            return Goal()

        self._goal_counter += 1
        goal_id = f"goal-{self._goal_counter}"

        goal = Goal(
            goal_id=goal_id,
            description=template.get("desc", ""),
            goal_type=GoalType(template.get("type", "leaf")),
            impact=template.get("impact", 0.5),
            achievability=template.get("achievability", 0.7),
            priority=template.get("priority", 0.5),
            preconditions=template.get("preconditions", []),
            actions=template.get("actions", []),
            depth=depth,
            parent_id=parent_id,
        )

        self._goals[goal_id] = goal

        # Recurse into sub-goals
        for sub_template in template.get("sub_goals", []):
            sub_goal = self._build_from_template(
                sub_template, depth=depth + 1, parent_id=goal_id,
            )
            goal.sub_goal_ids.append(sub_goal.goal_id)

        return goal

    def add_sub_goal(
        self,
        parent_id: str,
        description: str,
        goal_type: GoalType = GoalType.LEAF,
        actions: list[str] | None = None,
        impact: float = 0.5,
    ) -> Goal:
        """Add a sub-goal to an existing goal."""
        parent = self._goals.get(parent_id)
        if not parent:
            return Goal()

        self._goal_counter += 1
        goal = Goal(
            goal_id=f"goal-{self._goal_counter}",
            description=description,
            goal_type=goal_type,
            actions=actions or [],
            impact=impact,
            depth=parent.depth + 1,
            parent_id=parent_id,
        )

        self._goals[goal.goal_id] = goal
        parent.sub_goal_ids.append(goal.goal_id)

        # If parent was leaf, make it AND
        if parent.goal_type == GoalType.LEAF:
            parent.goal_type = GoalType.AND

        return goal

    def select_next(self) -> Goal | None:
        """Select the next goal to work on (highest utility leaf)."""
        candidates = [
            g for g in self._goals.values()
            if g.status == GoalStatus.PROPOSED
            and g.goal_type == GoalType.LEAF
            and self._preconditions_met(g)
        ]

        if not candidates:
            # Try active goals
            candidates = [
                g for g in self._goals.values()
                if g.status == GoalStatus.ACTIVE
                and g.goal_type == GoalType.LEAF
            ]

        if not candidates:
            return None

        return max(candidates, key=lambda g: g.utility)

    def achieve(
        self,
        goal_id: str,
        result: dict[str, Any] | None = None,
    ) -> None:
        """Mark a goal as achieved and propagate up."""
        goal = self._goals.get(goal_id)
        if not goal:
            return

        goal.status = GoalStatus.ACHIEVED
        goal.achieved_at = time.time()
        goal.result = result or {}

        # Propagate to parent
        if goal.parent_id:
            self._check_parent_completion(goal.parent_id)

    def fail_goal(self, goal_id: str) -> None:
        """Mark a goal as failed and propagate."""
        goal = self._goals.get(goal_id)
        if not goal:
            return

        goal.status = GoalStatus.FAILED

        # For AND parent, this fails the parent
        if goal.parent_id:
            parent = self._goals.get(goal.parent_id)
            if parent and parent.goal_type == GoalType.AND:
                parent.status = GoalStatus.FAILED

    def _check_parent_completion(self, parent_id: str) -> None:
        """Check if parent goal is completed based on sub-goals."""
        parent = self._goals.get(parent_id)
        if not parent:
            return

        sub_goals = [self._goals.get(sid) for sid in parent.sub_goal_ids]
        sub_goals = [s for s in sub_goals if s is not None]

        if parent.goal_type == GoalType.AND:
            if all(s.status == GoalStatus.ACHIEVED for s in sub_goals):
                parent.status = GoalStatus.ACHIEVED
                parent.achieved_at = time.time()
                if parent.parent_id:
                    self._check_parent_completion(parent.parent_id)

        elif parent.goal_type == GoalType.OR:
            if any(s.status == GoalStatus.ACHIEVED for s in sub_goals):
                parent.status = GoalStatus.ACHIEVED
                parent.achieved_at = time.time()
                # Abandon other sub-goals
                for sub in sub_goals:
                    if sub.status not in (GoalStatus.ACHIEVED, GoalStatus.FAILED):
                        sub.status = GoalStatus.ABANDONED
                if parent.parent_id:
                    self._check_parent_completion(parent.parent_id)

    def _preconditions_met(self, goal: Goal) -> bool:
        """Check if goal preconditions are met."""
        for precond in goal.preconditions:
            # Search for matching achieved goal
            found = False
            for other in self._goals.values():
                if precond.lower() in other.description.lower() and other.status == GoalStatus.ACHIEVED:
                    found = True
                    break
            if not found:
                return False
        return True

    def get_tree(self, root_id: str = "") -> dict[str, Any]:
        """Get goal tree starting from root."""
        if not root_id:
            roots = [g for g in self._goals.values() if not g.parent_id]
            if not roots:
                return {}
            root_id = roots[0].goal_id

        return self._build_tree(root_id)

    def _build_tree(self, goal_id: str) -> dict[str, Any]:
        goal = self._goals.get(goal_id)
        if not goal:
            return {}

        tree = goal.to_dict()
        tree["sub_goals"] = [
            self._build_tree(sid) for sid in goal.sub_goal_ids
        ]
        return tree

    def get_stats(self) -> dict[str, Any]:
        status_counts: dict[str, int] = defaultdict(int)
        for goal in self._goals.values():
            status_counts[goal.status.value] += 1

        return {
            "total_goals": len(self._goals),
            "status": dict(status_counts),
            "max_depth": max((g.depth for g in self._goals.values()), default=0),
        }
