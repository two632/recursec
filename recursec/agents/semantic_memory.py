"""Semantic memory — stores and retrieves factual knowledge and concepts.

Unlike episodic memory (events/episodes), semantic memory stores
general facts, relationships, and concepts. Implements:
1. Concept storage and retrieval
2. Hierarchical concept organization
3. Concept similarity scoring
4. Fact confidence tracking
5. Concept linking and relationships
6. Semantic search over knowledge
7. Knowledge decay and refresh
8. Concept generalization from episodes
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ConceptType(str, Enum):
    FACT = "fact"                 # A known fact
    RULE = "rule"                 # A learned rule/heuristic
    PATTERN = "pattern"          # A recognized pattern
    TAXONOMY = "taxonomy"        # Category/classification
    RELATIONSHIP = "relationship"  # Relationship between concepts
    PROCEDURE = "procedure"      # How to do something


class RelationType(str, Enum):
    IS_A = "is_a"                # X is a Y
    PART_OF = "part_of"          # X is part of Y
    CAUSES = "causes"            # X causes Y
    REQUIRES = "requires"        # X requires Y
    LEADS_TO = "leads_to"        # X often leads to Y
    MITIGATED_BY = "mitigated_by"  # X is mitigated by Y
    RELATED_TO = "related_to"    # General relation
    CONTRADICTS = "contradicts"  # X contradicts Y


@dataclass
class Concept:
    """A concept in semantic memory."""
    concept_id: str = ""
    name: str = ""
    concept_type: ConceptType = ConceptType.FACT
    description: str = ""
    properties: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.5
    source_count: int = 1
    tags: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    access_count: int = 0

    @property
    def strength(self) -> float:
        """How strong this concept is in memory."""
        recency = 1.0 / (1.0 + (time.time() - self.updated_at) / 3600.0)
        reinforcement = min(1.0, self.source_count / 5.0)
        return self.confidence * (recency * 0.3 + reinforcement * 0.4 + 0.3)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.concept_id,
            "name": self.name[:30],
            "type": self.concept_type.value,
            "confidence": round(self.confidence, 2),
            "strength": round(self.strength, 3),
            "sources": self.source_count,
        }


@dataclass
class ConceptRelation:
    """A relationship between two concepts."""
    relation_id: str = ""
    source_id: str = ""
    target_id: str = ""
    relation_type: RelationType = RelationType.RELATED_TO
    strength: float = 0.5
    evidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.relation_id,
            "source": self.source_id[:15],
            "target": self.target_id[:15],
            "type": self.relation_type.value,
            "strength": round(self.strength, 2),
        }


# ── Default Security Knowledge ────────────────────────────────

DEFAULT_CONCEPTS: list[dict[str, Any]] = [
    # Vulnerability types
    {"name": "SQL Injection", "type": "taxonomy", "tags": ["vuln", "web"],
     "desc": "Injection of SQL code via untrusted input", "conf": 1.0},
    {"name": "XSS", "type": "taxonomy", "tags": ["vuln", "web"],
     "desc": "Cross-site scripting via injected client-side code", "conf": 1.0},
    {"name": "CSRF", "type": "taxonomy", "tags": ["vuln", "web"],
     "desc": "Cross-site request forgery via forged requests", "conf": 1.0},
    {"name": "SSRF", "type": "taxonomy", "tags": ["vuln", "web"],
     "desc": "Server-side request forgery via manipulated server requests", "conf": 1.0},
    {"name": "RCE", "type": "taxonomy", "tags": ["vuln", "critical"],
     "desc": "Remote code execution vulnerability", "conf": 1.0},
    {"name": "LFI", "type": "taxonomy", "tags": ["vuln", "web"],
     "desc": "Local file inclusion via path traversal", "conf": 1.0},
    {"name": "IDOR", "type": "taxonomy", "tags": ["vuln", "web"],
     "desc": "Insecure direct object reference", "conf": 1.0},
    {"name": "XXE", "type": "taxonomy", "tags": ["vuln", "web"],
     "desc": "XML external entity injection", "conf": 1.0},
    # Rules
    {"name": "Open port 22 suggests SSH", "type": "rule", "tags": ["recon", "network"],
     "desc": "If port 22 is open, SSH service is likely running", "conf": 0.9},
    {"name": "Port 80/443 indicates web server", "type": "rule", "tags": ["recon", "web"],
     "desc": "Open HTTP/HTTPS ports indicate web service", "conf": 0.95},
    {"name": "Default credentials are common", "type": "rule", "tags": ["auth", "vuln"],
     "desc": "Many services use default credentials that are not changed", "conf": 0.7},
    {"name": "WAF evasion may require encoding", "type": "rule", "tags": ["exploitation"],
     "desc": "Web application firewalls can often be bypassed with encoding", "conf": 0.6},
    # Patterns
    {"name": "Apache/Nginx version disclosure", "type": "pattern", "tags": ["recon", "web"],
     "desc": "Server headers often reveal software version", "conf": 0.8},
    {"name": "Error messages reveal internals", "type": "pattern", "tags": ["recon", "web"],
     "desc": "Verbose error messages can reveal stack traces and paths", "conf": 0.75},
    # Procedures
    {"name": "Web reconnaissance workflow", "type": "procedure", "tags": ["recon", "web"],
     "desc": "subdomain enum → port scan → service detection → tech fingerprint → directory brute", "conf": 0.9},
    {"name": "SQL injection testing", "type": "procedure", "tags": ["exploitation", "web"],
     "desc": "Detect input points → test with quotes → confirm with boolean → extract data", "conf": 0.85},
]

DEFAULT_RELATIONS: list[dict[str, Any]] = [
    {"source": "SQL Injection", "target": "RCE", "type": "leads_to", "str": 0.3},
    {"source": "LFI", "target": "RCE", "type": "leads_to", "str": 0.5},
    {"source": "SSRF", "target": "RCE", "type": "leads_to", "str": 0.4},
    {"source": "XXE", "target": "SSRF", "type": "leads_to", "str": 0.6},
    {"source": "XSS", "target": "CSRF", "type": "related_to", "str": 0.5},
    {"source": "SQL Injection", "target": "SQL injection testing", "type": "related_to", "str": 0.8},
]


class SemanticMemory:
    """Stores and retrieves factual knowledge and concepts.

    General facts, rules, patterns, and procedures that the
    agent has learned, organized hierarchically with relationships.
    """

    def __init__(self) -> None:
        self._concepts: dict[str, Concept] = {}
        self._relations: list[ConceptRelation] = []
        self._name_index: dict[str, str] = {}  # name → concept_id
        self._tag_index: dict[str, list[str]] = defaultdict(list)
        self._concept_counter = 0
        self._relation_counter = 0
        self._log = logger.bind(component="semantic_memory")

        self._initialize_knowledge()

    def _initialize_knowledge(self) -> None:
        """Initialize default security knowledge."""
        concept_ids: dict[str, str] = {}

        for data in DEFAULT_CONCEPTS:
            concept = self.store(
                name=data["name"],
                concept_type=ConceptType(data["type"]),
                description=data["desc"],
                confidence=data["conf"],
                tags=data.get("tags", []),
            )
            concept_ids[data["name"]] = concept.concept_id

        for rel in DEFAULT_RELATIONS:
            source_id = concept_ids.get(rel["source"])
            target_id = concept_ids.get(rel["target"])
            if source_id and target_id:
                self.relate(
                    source_id=source_id,
                    target_id=target_id,
                    relation_type=RelationType(rel["type"]),
                    strength=rel["str"],
                )

    def store(
        self,
        name: str,
        concept_type: ConceptType = ConceptType.FACT,
        description: str = "",
        properties: dict[str, Any] | None = None,
        confidence: float = 0.5,
        tags: list[str] | None = None,
    ) -> Concept:
        """Store a new concept or reinforce existing one."""
        # Check if concept already exists
        existing_id = self._name_index.get(name.lower())
        if existing_id and existing_id in self._concepts:
            existing = self._concepts[existing_id]
            existing.source_count += 1
            existing.confidence = min(1.0, existing.confidence + 0.05)
            existing.updated_at = time.time()
            if description:
                existing.description = description
            return existing

        self._concept_counter += 1
        concept = Concept(
            concept_id=f"sem-{self._concept_counter}",
            name=name,
            concept_type=concept_type,
            description=description,
            properties=properties or {},
            confidence=confidence,
            tags=tags or [],
        )

        self._concepts[concept.concept_id] = concept
        self._name_index[name.lower()] = concept.concept_id

        for tag in concept.tags:
            self._tag_index[tag].append(concept.concept_id)

        return concept

    def relate(
        self,
        source_id: str,
        target_id: str,
        relation_type: RelationType = RelationType.RELATED_TO,
        strength: float = 0.5,
        evidence: str = "",
    ) -> ConceptRelation:
        """Create a relationship between concepts."""
        self._relation_counter += 1
        relation = ConceptRelation(
            relation_id=f"rel-{self._relation_counter}",
            source_id=source_id,
            target_id=target_id,
            relation_type=relation_type,
            strength=strength,
            evidence=evidence,
        )
        self._relations.append(relation)
        return relation

    def retrieve(self, name: str) -> Concept | None:
        """Retrieve a concept by name."""
        concept_id = self._name_index.get(name.lower())
        if concept_id:
            concept = self._concepts.get(concept_id)
            if concept:
                concept.access_count += 1
                return concept
        return None

    def search(
        self,
        query: str,
        concept_type: ConceptType | None = None,
        tags: list[str] | None = None,
        min_confidence: float = 0.0,
        limit: int = 10,
    ) -> list[Concept]:
        """Search for concepts."""
        query_lower = query.lower()
        results = []

        for concept in self._concepts.values():
            if concept_type and concept.concept_type != concept_type:
                continue

            if concept.confidence < min_confidence:
                continue

            if tags:
                if not set(tags) & set(concept.tags):
                    continue

            # Relevance scoring
            score = 0.0
            if query_lower in concept.name.lower():
                score += 0.5
            if query_lower in concept.description.lower():
                score += 0.3
            for tag in concept.tags:
                if query_lower in tag:
                    score += 0.1

            if score > 0:
                results.append((score * concept.strength, concept))

        results.sort(key=lambda x: x[0], reverse=True)
        return [c for _, c in results[:limit]]

    def get_related(
        self,
        concept_id: str,
        relation_type: RelationType | None = None,
    ) -> list[tuple[ConceptRelation, Concept]]:
        """Get concepts related to a given concept."""
        results = []

        for rel in self._relations:
            if rel.source_id == concept_id or rel.target_id == concept_id:
                if relation_type and rel.relation_type != relation_type:
                    continue

                other_id = rel.target_id if rel.source_id == concept_id else rel.source_id
                other = self._concepts.get(other_id)
                if other:
                    results.append((rel, other))

        return results

    def get_by_tag(self, tag: str, limit: int = 20) -> list[Concept]:
        """Get concepts by tag."""
        concept_ids = self._tag_index.get(tag, [])
        concepts = []
        for cid in concept_ids[:limit]:
            concept = self._concepts.get(cid)
            if concept:
                concepts.append(concept)
        return concepts

    def generalize_from_episodes(
        self,
        episodes: list[dict[str, Any]],
    ) -> list[Concept]:
        """Generalize new concepts from episodes."""
        new_concepts = []

        # Count tool-outcome pairs
        tool_outcomes: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for episode in episodes:
            outcome = episode.get("outcome", "unknown")
            for tool in episode.get("tools_used", []):
                tool_outcomes[tool][outcome] += 1

        # Create rules from strong patterns
        for tool, outcomes in tool_outcomes.items():
            total = sum(outcomes.values())
            if total >= 3:
                success_rate = outcomes.get("success", 0) / total
                if success_rate > 0.7:
                    concept = self.store(
                        name=f"{tool} is effective",
                        concept_type=ConceptType.RULE,
                        description=f"{tool} has {success_rate:.0%} success rate over {total} episodes",
                        confidence=success_rate,
                        tags=["learned", "tool_effectiveness"],
                    )
                    new_concepts.append(concept)

        return new_concepts

    def get_stats(self) -> dict[str, Any]:
        type_counts: dict[str, int] = defaultdict(int)
        for concept in self._concepts.values():
            type_counts[concept.concept_type.value] += 1

        return {
            "concepts": len(self._concepts),
            "relations": len(self._relations),
            "types": dict(type_counts),
            "tags": len(self._tag_index),
        }
