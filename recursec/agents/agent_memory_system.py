"""Agent memory system — multi-tier memory for persistent agent intelligence.

Implements three-tier memory architecture:
1. Working Memory — current task context, active findings, tool outputs (fast, ephemeral)
2. Episodic Memory — past task episodes with outcomes, indexed by similarity
3. Semantic Memory — learned facts, patterns, tool effectiveness (persistent knowledge)
4. Procedural Memory — learned procedures and strategies
5. Knowledge Graph — entity-relationship graph of discovered information

The memory system lets agents learn from past experiences,
avoid repeating failed approaches, and build up knowledge
across multiple assessments.
"""

from __future__ import annotations

import hashlib
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class MemoryType(str, Enum):
    WORKING = "working"
    EPISODIC = "episodic"
    SEMANTIC = "semantic"
    PROCEDURAL = "procedural"


class ImportanceLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    TRIVIAL = "trivial"


@dataclass
class MemoryEntry:
    """A single memory entry."""
    memory_id: str = ""
    memory_type: MemoryType = MemoryType.WORKING
    content: str = ""
    summary: str = ""
    importance: ImportanceLevel = ImportanceLevel.MEDIUM
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    access_count: int = 0
    last_accessed: float = field(default_factory=time.time)
    created_at: float = field(default_factory=time.time)
    decay_rate: float = 0.01
    embedding_vector: list[float] = field(default_factory=list)

    @property
    def content_hash(self) -> str:
        return hashlib.md5(self.content.encode()).hexdigest()[:12]

    @property
    def age_hours(self) -> float:
        return (time.time() - self.created_at) / 3600.0

    @property
    def relevance_score(self) -> float:
        """Score combining importance, recency, and access frequency."""
        importance_weights = {
            ImportanceLevel.CRITICAL: 1.0,
            ImportanceLevel.HIGH: 0.8,
            ImportanceLevel.MEDIUM: 0.5,
            ImportanceLevel.LOW: 0.3,
            ImportanceLevel.TRIVIAL: 0.1,
        }
        base = importance_weights.get(self.importance, 0.5)
        recency = 1.0 / (1.0 + self.age_hours * self.decay_rate)
        frequency = min(1.0, self.access_count / 10.0)
        return base * 0.5 + recency * 0.3 + frequency * 0.2

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.memory_id[:8],
            "type": self.memory_type.value[:6],
            "summary": self.summary[:30] or self.content[:30],
            "importance": self.importance.value[:6],
            "relevance": f"{self.relevance_score:.2f}",
            "accesses": self.access_count,
        }


@dataclass
class Episode:
    """A complete task episode for episodic memory."""
    episode_id: str = ""
    task_goal: str = ""
    target: str = ""
    agent_role: str = ""
    tools_used: list[str] = field(default_factory=list)
    models_used: list[str] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    actions_taken: list[str] = field(default_factory=list)
    outcome: str = ""
    success: bool = False
    duration_s: float = 0.0
    lessons_learned: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.episode_id[:8],
            "goal": self.task_goal[:25],
            "target": self.target[:15],
            "tools": len(self.tools_used),
            "findings": len(self.findings),
            "success": self.success,
        }


@dataclass
class SemanticFact:
    """A learned fact for semantic memory."""
    fact_id: str = ""
    subject: str = ""
    predicate: str = ""
    obj: str = ""
    confidence: float = 0.5
    source: str = ""
    verified: bool = False
    times_confirmed: int = 1

    def to_triple(self) -> tuple[str, str, str]:
        return (self.subject, self.predicate, self.obj)

    def to_dict(self) -> dict[str, Any]:
        return {
            "fact": f"{self.subject[:10]} → {self.predicate[:10]} → {self.obj[:10]}",
            "conf": f"{self.confidence:.0%}",
            "confirmed": self.times_confirmed,
        }


@dataclass
class Procedure:
    """A learned procedure for procedural memory."""
    procedure_id: str = ""
    name: str = ""
    description: str = ""
    steps: list[str] = field(default_factory=list)
    preconditions: list[str] = field(default_factory=list)
    expected_outcome: str = ""
    success_rate: float = 0.5
    times_used: int = 0
    times_succeeded: int = 0
    applicable_to: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name[:20],
            "steps": len(self.steps),
            "success": f"{self.success_rate:.0%}",
            "used": self.times_used,
        }


@dataclass
class KnowledgeEntity:
    """An entity in the knowledge graph."""
    entity_id: str = ""
    name: str = ""
    entity_type: str = ""
    properties: dict[str, Any] = field(default_factory=dict)
    relationships: list[tuple[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name[:20],
            "type": self.entity_type[:10],
            "props": len(self.properties),
            "rels": len(self.relationships),
        }


class WorkingMemory:
    """Fast, ephemeral memory for current task context."""

    def __init__(self, max_entries: int = 100) -> None:
        self._entries: dict[str, MemoryEntry] = {}
        self._max = max_entries
        self._counter = 0

    def store(self, content: str, importance: ImportanceLevel = ImportanceLevel.MEDIUM, tags: list[str] | None = None) -> str:
        self._counter += 1
        entry = MemoryEntry(
            memory_id=f"wm-{self._counter}",
            memory_type=MemoryType.WORKING,
            content=content,
            importance=importance,
            tags=tags or [],
        )
        self._entries[entry.memory_id] = entry

        # Evict low-importance entries if full
        if len(self._entries) > self._max:
            self._evict()

        return entry.memory_id

    def recall(self, query: str = "", tags: list[str] | None = None, limit: int = 10) -> list[MemoryEntry]:
        """Recall memories matching query or tags."""
        candidates = list(self._entries.values())

        if tags:
            candidates = [e for e in candidates if any(t in e.tags for t in tags)]
        if query:
            query_lower = query.lower()
            candidates = [e for e in candidates if query_lower in e.content.lower()]

        # Sort by relevance
        candidates.sort(key=lambda e: e.relevance_score, reverse=True)

        for entry in candidates[:limit]:
            entry.access_count += 1
            entry.last_accessed = time.time()

        return candidates[:limit]

    def _evict(self) -> None:
        """Evict least relevant entries."""
        sorted_entries = sorted(self._entries.values(), key=lambda e: e.relevance_score)
        to_remove = len(self._entries) - self._max + 10
        for entry in sorted_entries[:to_remove]:
            del self._entries[entry.memory_id]

    def clear(self) -> None:
        self._entries.clear()

    @property
    def size(self) -> int:
        return len(self._entries)


class EpisodicMemory:
    """Stores past task episodes for experience-based learning."""

    def __init__(self, max_episodes: int = 1000) -> None:
        self._episodes: list[Episode] = []
        self._max = max_episodes
        self._counter = 0

    def record_episode(
        self,
        goal: str,
        target: str = "",
        role: str = "",
        tools: list[str] | None = None,
        models: list[str] | None = None,
        findings: list[dict[str, Any]] | None = None,
        actions: list[str] | None = None,
        outcome: str = "",
        success: bool = False,
        duration_s: float = 0.0,
        lessons: list[str] | None = None,
    ) -> Episode:
        self._counter += 1
        episode = Episode(
            episode_id=f"ep-{self._counter}",
            task_goal=goal,
            target=target,
            agent_role=role,
            tools_used=tools or [],
            models_used=models or [],
            findings=findings or [],
            actions_taken=actions or [],
            outcome=outcome,
            success=success,
            duration_s=duration_s,
            lessons_learned=lessons or [],
        )
        self._episodes.append(episode)

        if len(self._episodes) > self._max:
            self._episodes = self._episodes[-self._max:]

        return episode

    def recall_similar(self, goal: str, limit: int = 5) -> list[Episode]:
        """Recall episodes with similar goals."""
        goal_lower = goal.lower()
        scored = []
        for ep in self._episodes:
            # Simple keyword overlap scoring
            ep_words = set(ep.task_goal.lower().split())
            goal_words = set(goal_lower.split())
            overlap = len(ep_words & goal_words) / max(len(ep_words | goal_words), 1)
            scored.append((ep, overlap))

        scored.sort(key=lambda x: x[1], reverse=True)
        return [ep for ep, _ in scored[:limit]]

    def get_tool_effectiveness(self) -> dict[str, dict[str, float]]:
        """Calculate effectiveness of each tool across episodes."""
        tool_stats: dict[str, dict[str, int]] = defaultdict(lambda: {"used": 0, "successful": 0})
        for ep in self._episodes:
            for tool in ep.tools_used:
                tool_stats[tool]["used"] += 1
                if ep.success:
                    tool_stats[tool]["successful"] += 1

        return {
            tool: {"rate": stats["successful"] / max(stats["used"], 1)}
            for tool, stats in tool_stats.items()
        }

    @property
    def size(self) -> int:
        return len(self._episodes)


class SemanticMemory:
    """Persistent knowledge store of learned facts."""

    def __init__(self) -> None:
        self._facts: dict[str, SemanticFact] = {}
        self._by_subject: dict[str, list[str]] = defaultdict(list)
        self._counter = 0

    def store_fact(
        self,
        subject: str,
        predicate: str,
        obj: str,
        confidence: float = 0.5,
        source: str = "",
    ) -> SemanticFact:
        # Check for existing matching fact
        for fact in self._facts.values():
            if fact.subject == subject and fact.predicate == predicate and fact.obj == obj:
                fact.times_confirmed += 1
                fact.confidence = min(1.0, fact.confidence + 0.1)
                return fact

        self._counter += 1
        fact = SemanticFact(
            fact_id=f"fact-{self._counter}",
            subject=subject,
            predicate=predicate,
            obj=obj,
            confidence=confidence,
            source=source,
        )
        self._facts[fact.fact_id] = fact
        self._by_subject[subject].append(fact.fact_id)
        return fact

    def query(self, subject: str = "", predicate: str = "") -> list[SemanticFact]:
        """Query facts by subject and/or predicate."""
        results = list(self._facts.values())
        if subject:
            results = [f for f in results if f.subject == subject]
        if predicate:
            results = [f for f in results if f.predicate == predicate]
        return results

    def get_facts_about(self, subject: str) -> list[SemanticFact]:
        """Get all facts about a subject."""
        fact_ids = self._by_subject.get(subject, [])
        return [self._facts[fid] for fid in fact_ids if fid in self._facts]

    @property
    def size(self) -> int:
        return len(self._facts)


class ProceduralMemory:
    """Stores learned procedures and strategies."""

    def __init__(self) -> None:
        self._procedures: dict[str, Procedure] = {}
        self._counter = 0

    def store_procedure(
        self,
        name: str,
        description: str = "",
        steps: list[str] | None = None,
        preconditions: list[str] | None = None,
        expected_outcome: str = "",
        applicable_to: list[str] | None = None,
    ) -> Procedure:
        self._counter += 1
        proc = Procedure(
            procedure_id=f"proc-{self._counter}",
            name=name,
            description=description,
            steps=steps or [],
            preconditions=preconditions or [],
            expected_outcome=expected_outcome,
            applicable_to=applicable_to or [],
        )
        self._procedures[proc.procedure_id] = proc
        return proc

    def find_procedure(self, task_type: str) -> list[Procedure]:
        """Find procedures applicable to a task type."""
        results = []
        for proc in self._procedures.values():
            if task_type in proc.applicable_to:
                results.append(proc)
        results.sort(key=lambda p: p.success_rate, reverse=True)
        return results

    def record_outcome(self, procedure_id: str, success: bool) -> None:
        proc = self._procedures.get(procedure_id)
        if proc:
            proc.times_used += 1
            if success:
                proc.times_succeeded += 1
            proc.success_rate = proc.times_succeeded / max(proc.times_used, 1)

    @property
    def size(self) -> int:
        return len(self._procedures)


class AgentKnowledgeGraph:
    """Entity-relationship graph for discovered information."""

    def __init__(self) -> None:
        self._entities: dict[str, KnowledgeEntity] = {}
        self._edges: list[tuple[str, str, str]] = []
        self._counter = 0

    def add_entity(self, name: str, entity_type: str, properties: dict[str, Any] | None = None) -> KnowledgeEntity:
        # Check existing
        for entity in self._entities.values():
            if entity.name == name and entity.entity_type == entity_type:
                if properties:
                    entity.properties.update(properties)
                return entity

        self._counter += 1
        entity = KnowledgeEntity(
            entity_id=f"ent-{self._counter}",
            name=name,
            entity_type=entity_type,
            properties=properties or {},
        )
        self._entities[entity.entity_id] = entity
        return entity

    def add_relationship(self, from_entity: str, relation: str, to_entity: str) -> None:
        self._edges.append((from_entity, relation, to_entity))
        # Update entity relationship lists
        for entity in self._entities.values():
            if entity.name == from_entity:
                entity.relationships.append((relation, to_entity))

    def query_neighbors(self, entity_name: str) -> list[tuple[str, str]]:
        """Get all entities related to this entity."""
        neighbors = []
        for from_e, rel, to_e in self._edges:
            if from_e == entity_name:
                neighbors.append((rel, to_e))
            elif to_e == entity_name:
                neighbors.append((rel, from_e))
        return neighbors

    @property
    def size(self) -> tuple[int, int]:
        return len(self._entities), len(self._edges)


class AgentMemorySystem:
    """Unified memory system combining all memory tiers."""

    def __init__(self) -> None:
        self.working = WorkingMemory(max_entries=200)
        self.episodic = EpisodicMemory(max_episodes=1000)
        self.semantic = SemanticMemory()
        self.procedural = ProceduralMemory()
        self.knowledge_graph = AgentKnowledgeGraph()
        self._log = logger.bind(component="memory_system")

    def build_memory_prompt(self, goal: str = "", tags: list[str] | None = None) -> str:
        """Build LLM prompt with relevant memories."""
        lines = ["## Agent Memory Context"]

        # Working memory
        working = self.working.recall(query=goal, tags=tags, limit=5)
        if working:
            lines.append("\n### Current Context:")
            for entry in working:
                lines.append(f"  - [{entry.importance.value[:4]}] {entry.content[:80]}")

        # Episodic — similar past tasks
        if goal:
            similar = self.episodic.recall_similar(goal, limit=3)
            if similar:
                lines.append("\n### Similar Past Tasks:")
                for ep in similar:
                    status = "success" if ep.success else "failed"
                    lines.append(f"  - [{status}] {ep.task_goal[:50]}")
                    if ep.lessons_learned:
                        lines.append(f"    Lessons: {ep.lessons_learned[0][:60]}")

        # Semantic — relevant facts
        if goal:
            words = goal.split()[:3]
            for word in words:
                facts = self.semantic.query(subject=word)
                for fact in facts[:2]:
                    lines.append(f"  - Fact: {fact.subject} {fact.predicate} {fact.obj}")

        # Tool effectiveness
        tool_eff = self.episodic.get_tool_effectiveness()
        if tool_eff:
            lines.append("\n### Tool Effectiveness:")
            sorted_tools = sorted(tool_eff.items(), key=lambda x: x[1]["rate"], reverse=True)
            for tool, stats in sorted_tools[:5]:
                lines.append(f"  - {tool}: {stats['rate']:.0%} success rate")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        entities, edges = self.knowledge_graph.size
        return {
            "working": self.working.size,
            "episodic": self.episodic.size,
            "semantic": self.semantic.size,
            "procedural": self.procedural.size,
            "kg_entities": entities,
            "kg_edges": edges,
        }
