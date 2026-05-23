"""Tree-of-Thought reasoning — explore multiple reasoning paths simultaneously.

Instead of single-chain reasoning, Tree-of-Thought (ToT):
1. Generates multiple possible next steps at each node
2. Evaluates each branch's promise using a heuristic
3. Explores the most promising branches (BFS or DFS)
4. Prunes dead-end branches early
5. Backtracks when a branch fails
6. Returns the best complete reasoning path

This enables:
- More thorough vulnerability analysis
- Better exploit chain discovery
- Robust strategy selection under uncertainty
- Creative attack path generation

Search strategies:
- BFS-ToT: Breadth-first exploration (wider but shallower)
- DFS-ToT: Depth-first exploration (deeper but narrower)
- MCTS-ToT: Monte Carlo Tree Search (balanced exploration/exploitation)
- Beam search: Keep top-k candidates at each level
"""

from __future__ import annotations

import json
import math
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from recursec.llm.router import ModelRouter

logger = structlog.get_logger()


class SearchStrategy(str, Enum):
    BFS = "bfs"
    DFS = "dfs"
    MCTS = "mcts"
    BEAM = "beam"


@dataclass
class ThoughtNode:
    """A single node in the thought tree."""
    node_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    thought: str = ""
    parent_id: str = ""
    children: list[str] = field(default_factory=list)
    depth: int = 0

    # Evaluation
    value: float = 0.0         # How promising (0.0-1.0)
    confidence: float = 0.5
    is_terminal: bool = False
    is_solution: bool = False

    # MCTS stats
    visits: int = 0
    total_reward: float = 0.0

    # Metadata
    action: str = ""           # What action this thought represents
    result: str = ""           # What happened when we explored this
    reasoning: str = ""

    @property
    def ucb1_score(self) -> float:
        """Upper Confidence Bound for MCTS."""
        if self.visits == 0:
            return float("inf")
        exploitation = self.total_reward / self.visits
        exploration = math.sqrt(2 * math.log(max(1, self.visits + 1)) / self.visits)
        return exploitation + 1.41 * exploration

    @property
    def average_reward(self) -> float:
        if self.visits == 0:
            return 0.0
        return self.total_reward / self.visits

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.node_id,
            "thought": self.thought[:200],
            "depth": self.depth,
            "value": round(self.value, 3),
            "visits": self.visits,
            "children": len(self.children),
            "terminal": self.is_terminal,
            "solution": self.is_solution,
        }


@dataclass
class ThoughtPath:
    """A complete path through the thought tree."""
    nodes: list[ThoughtNode] = field(default_factory=list)
    total_value: float = 0.0
    depth: int = 0

    def to_text(self) -> str:
        return " → ".join(n.thought[:50] for n in self.nodes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "depth": self.depth,
            "value": round(self.total_value, 3),
            "steps": [n.to_dict() for n in self.nodes],
        }


@dataclass
class ToTResult:
    """Result of Tree-of-Thought reasoning."""
    question: str = ""
    best_path: ThoughtPath | None = None
    all_paths: list[ThoughtPath] = field(default_factory=list)
    nodes_explored: int = 0
    nodes_pruned: int = 0
    max_depth_reached: int = 0
    time_ms: float = 0.0
    strategy: SearchStrategy = SearchStrategy.BFS

    @property
    def best_answer(self) -> str:
        if self.best_path and self.best_path.nodes:
            return self.best_path.nodes[-1].thought
        return ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "question": self.question[:200],
            "strategy": self.strategy.value,
            "nodes_explored": self.nodes_explored,
            "nodes_pruned": self.nodes_pruned,
            "max_depth": self.max_depth_reached,
            "time_ms": round(self.time_ms, 1),
            "paths_found": len(self.all_paths),
            "best_value": round(self.best_path.total_value, 3) if self.best_path else 0.0,
        }


# ── Prompt Templates ────────────────────────────────────────

GENERATE_THOUGHTS_PROMPT = """You are exploring possible approaches to a security problem.

Problem: {problem}
Current reasoning so far: {current_path}
Current depth: {depth}/{max_depth}

Generate {num_thoughts} distinct next steps or thoughts. Each should be a different approach.
For each, explain the reasoning and estimate how promising it is.

Respond as JSON:
{{
  "thoughts": [
    {{
      "thought": "what to do/think next",
      "action": "specific action to take",
      "reasoning": "why this is a good approach",
      "promise": 0.X
    }}
  ]
}}"""

EVALUATE_THOUGHT_PROMPT = """Evaluate this reasoning step in a security assessment.

Problem: {problem}
Path so far: {path}
Current thought: {thought}

Rate this thought on:
1. Relevance: Does it move toward solving the problem?
2. Feasibility: Can this actually be done?
3. Information gain: Will we learn something useful?
4. Risk: What could go wrong?

Respond as JSON:
{{
  "value": 0.X,
  "reasoning": "...",
  "is_terminal": true/false,
  "is_solution": true/false
}}"""


class TreeOfThought:
    """Tree-of-Thought reasoning engine.

    Explores multiple reasoning paths simultaneously to find
    the best approach to complex security problems.
    """

    def __init__(self, model_router: ModelRouter) -> None:
        self._router = model_router
        self._log = logger.bind(component="tree_of_thought")

    async def reason(
        self,
        problem: str,
        strategy: SearchStrategy = SearchStrategy.BFS,
        max_depth: int = 4,
        branching_factor: int = 3,
        beam_width: int = 3,
        max_nodes: int = 50,
        prune_threshold: float = 0.2,
    ) -> ToTResult:
        """Run Tree-of-Thought reasoning."""
        start = time.time()

        if strategy == SearchStrategy.BFS:
            result = await self._bfs(problem, max_depth, branching_factor, beam_width, max_nodes, prune_threshold)
        elif strategy == SearchStrategy.DFS:
            result = await self._dfs(problem, max_depth, branching_factor, max_nodes, prune_threshold)
        elif strategy == SearchStrategy.MCTS:
            result = await self._mcts(problem, max_depth, branching_factor, max_nodes)
        else:
            result = await self._bfs(problem, max_depth, branching_factor, beam_width, max_nodes, prune_threshold)

        result.strategy = strategy
        result.time_ms = (time.time() - start) * 1000

        self._log.info(
            "tot_complete",
            strategy=strategy.value,
            explored=result.nodes_explored,
            pruned=result.nodes_pruned,
            paths=len(result.all_paths),
        )

        return result

    async def _bfs(
        self,
        problem: str,
        max_depth: int,
        branching: int,
        beam_width: int,
        max_nodes: int,
        prune_threshold: float,
    ) -> ToTResult:
        """BFS with beam search — explore level by level, keep top-k."""
        result = ToTResult(question=problem)
        nodes: dict[str, ThoughtNode] = {}

        # Root node
        root = ThoughtNode(thought=problem, depth=0, value=1.0)
        nodes[root.node_id] = root
        current_level = [root]

        for depth in range(1, max_depth + 1):
            if not current_level or result.nodes_explored >= max_nodes:
                break

            next_level: list[ThoughtNode] = []

            for parent in current_level:
                # Generate children
                children = await self._generate_thoughts(
                    problem, self._get_path(nodes, parent), depth, max_depth, branching,
                )

                for child_data in children:
                    child = ThoughtNode(
                        thought=child_data.get("thought", ""),
                        parent_id=parent.node_id,
                        depth=depth,
                        action=child_data.get("action", ""),
                        reasoning=child_data.get("reasoning", ""),
                        value=child_data.get("promise", 0.5),
                    )

                    # Evaluate
                    eval_result = await self._evaluate_thought(
                        problem, self._get_path_text(nodes, parent), child.thought,
                    )
                    child.value = eval_result.get("value", child.value)
                    child.is_terminal = eval_result.get("is_terminal", False)
                    child.is_solution = eval_result.get("is_solution", False)

                    nodes[child.node_id] = child
                    parent.children.append(child.node_id)
                    result.nodes_explored += 1

                    # Prune low-value branches
                    if child.value < prune_threshold:
                        result.nodes_pruned += 1
                        continue

                    if child.is_terminal or child.is_solution:
                        path = self._build_path(nodes, child)
                        result.all_paths.append(path)
                    else:
                        next_level.append(child)

            # Beam: keep only top-k nodes for next level
            next_level.sort(key=lambda n: -n.value)
            current_level = next_level[:beam_width]
            result.max_depth_reached = depth

        # Find best path
        if result.all_paths:
            result.best_path = max(result.all_paths, key=lambda p: p.total_value)
        elif nodes:
            # No solution found, return best leaf
            best_leaf = max(nodes.values(), key=lambda n: n.value)
            result.best_path = self._build_path(nodes, best_leaf)

        return result

    async def _dfs(
        self,
        problem: str,
        max_depth: int,
        branching: int,
        max_nodes: int,
        prune_threshold: float,
    ) -> ToTResult:
        """DFS — explore one branch deeply before trying others."""
        result = ToTResult(question=problem)
        nodes: dict[str, ThoughtNode] = {}

        root = ThoughtNode(thought=problem, depth=0, value=1.0)
        nodes[root.node_id] = root

        stack = [root]

        while stack and result.nodes_explored < max_nodes:
            current = stack.pop()

            if current.depth >= max_depth:
                path = self._build_path(nodes, current)
                result.all_paths.append(path)
                continue

            children = await self._generate_thoughts(
                problem, self._get_path(nodes, current),
                current.depth + 1, max_depth, branching,
            )

            for child_data in children:
                child = ThoughtNode(
                    thought=child_data.get("thought", ""),
                    parent_id=current.node_id,
                    depth=current.depth + 1,
                    action=child_data.get("action", ""),
                    value=child_data.get("promise", 0.5),
                )

                eval_result = await self._evaluate_thought(
                    problem, self._get_path_text(nodes, current), child.thought,
                )
                child.value = eval_result.get("value", child.value)
                child.is_terminal = eval_result.get("is_terminal", False)
                child.is_solution = eval_result.get("is_solution", False)

                nodes[child.node_id] = child
                current.children.append(child.node_id)
                result.nodes_explored += 1

                if child.value < prune_threshold:
                    result.nodes_pruned += 1
                    continue

                if child.is_solution:
                    path = self._build_path(nodes, child)
                    result.all_paths.append(path)
                elif not child.is_terminal:
                    stack.append(child)

            result.max_depth_reached = max(result.max_depth_reached, current.depth)

        if result.all_paths:
            result.best_path = max(result.all_paths, key=lambda p: p.total_value)

        return result

    async def _mcts(
        self,
        problem: str,
        max_depth: int,
        branching: int,
        max_iterations: int,
    ) -> ToTResult:
        """Monte Carlo Tree Search — balance exploration and exploitation."""
        result = ToTResult(question=problem)
        nodes: dict[str, ThoughtNode] = {}

        root = ThoughtNode(thought=problem, depth=0, value=1.0, visits=1)
        nodes[root.node_id] = root

        for iteration in range(max_iterations):
            # Selection: walk tree using UCB1
            current = root
            path_nodes = [current]

            while current.children and not current.is_terminal:
                child_nodes = [nodes[cid] for cid in current.children if cid in nodes]
                if not child_nodes:
                    break
                current = max(child_nodes, key=lambda n: n.ucb1_score)
                path_nodes.append(current)

            # Expansion: if not terminal and not at max depth
            if not current.is_terminal and current.depth < max_depth:
                children = await self._generate_thoughts(
                    problem, self._get_path(nodes, current),
                    current.depth + 1, max_depth, branching,
                )

                if children:
                    child_data = children[0]  # Take first child for expansion
                    child = ThoughtNode(
                        thought=child_data.get("thought", ""),
                        parent_id=current.node_id,
                        depth=current.depth + 1,
                        action=child_data.get("action", ""),
                        value=child_data.get("promise", 0.5),
                    )
                    nodes[child.node_id] = child
                    current.children.append(child.node_id)
                    current = child
                    path_nodes.append(current)
                    result.nodes_explored += 1

            # Simulation: evaluate the leaf
            eval_result = await self._evaluate_thought(
                problem, self._get_path_text(nodes, path_nodes[-2] if len(path_nodes) > 1 else root),
                current.thought,
            )
            reward = eval_result.get("value", 0.5)
            current.is_terminal = eval_result.get("is_terminal", False)
            current.is_solution = eval_result.get("is_solution", False)

            # Backpropagation: update all nodes in path
            for node in path_nodes:
                node.visits += 1
                node.total_reward += reward

            if current.is_solution:
                path = self._build_path(nodes, current)
                result.all_paths.append(path)

            result.max_depth_reached = max(result.max_depth_reached, current.depth)

        # Find best path by following most-visited children
        best_leaf = root
        while best_leaf.children:
            child_nodes = [nodes[cid] for cid in best_leaf.children if cid in nodes]
            if not child_nodes:
                break
            best_leaf = max(child_nodes, key=lambda n: n.visits)

        result.best_path = self._build_path(nodes, best_leaf)

        if result.all_paths:
            best_solution = max(result.all_paths, key=lambda p: p.total_value)
            if best_solution.total_value > (result.best_path.total_value if result.best_path else 0):
                result.best_path = best_solution

        return result

    # ── LLM Integration ──────────────────────────────────

    async def _generate_thoughts(
        self,
        problem: str,
        current_path: str,
        depth: int,
        max_depth: int,
        num_thoughts: int,
    ) -> list[dict[str, Any]]:
        """Generate candidate next thoughts."""
        prompt = GENERATE_THOUGHTS_PROMPT.format(
            problem=problem,
            current_path=current_path or "(start)",
            depth=depth, max_depth=max_depth,
            num_thoughts=num_thoughts,
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="reasoning",
            temperature=0.5,  # Higher temp for diversity
            max_tokens=1024,
        )

        data = self._parse_json(response)
        return data.get("thoughts", [])

    async def _evaluate_thought(
        self,
        problem: str,
        path: str,
        thought: str,
    ) -> dict[str, Any]:
        """Evaluate a single thought node."""
        prompt = EVALUATE_THOUGHT_PROMPT.format(
            problem=problem,
            path=path or "(start)",
            thought=thought,
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="reasoning",
            temperature=0.1,
            max_tokens=256,
        )

        return self._parse_json(response)

    # ── Tree Utilities ───────────────────────────────────

    def _get_path(self, nodes: dict[str, ThoughtNode], node: ThoughtNode) -> str:
        """Get path from root to node as text."""
        path_nodes = []
        current = node
        while current:
            path_nodes.append(current.thought[:100])
            parent_id = current.parent_id
            current = nodes.get(parent_id) if parent_id else None
        return " → ".join(reversed(path_nodes))

    def _get_path_text(self, nodes: dict[str, ThoughtNode], node: ThoughtNode) -> str:
        return self._get_path(nodes, node)

    def _build_path(self, nodes: dict[str, ThoughtNode], leaf: ThoughtNode) -> ThoughtPath:
        """Build a ThoughtPath from root to leaf."""
        path_nodes = []
        current: ThoughtNode | None = leaf
        while current:
            path_nodes.append(current)
            parent_id = current.parent_id
            current = nodes.get(parent_id) if parent_id else None
        path_nodes.reverse()

        total_value = sum(n.value for n in path_nodes) / max(1, len(path_nodes))
        return ThoughtPath(
            nodes=path_nodes,
            total_value=total_value,
            depth=len(path_nodes) - 1,
        )

    def _parse_json(self, text: str) -> dict[str, Any]:
        try:
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]
            return json.loads(text.strip())
        except (json.JSONDecodeError, IndexError):
            return {}
