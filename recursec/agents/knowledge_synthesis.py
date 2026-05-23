"""Knowledge synthesis engine — builds and maintains a growing knowledge base.

As agents discover information about targets, this engine:
1. Extracts structured knowledge from unstructured data
2. Links related discoveries (knowledge graph)
3. Identifies patterns across findings
4. Generates attack narratives from connected findings
5. Maintains a searchable knowledge store
6. Enables agents to query accumulated knowledge
7. Detects contradictions in the knowledge base

Knowledge types:
- TargetKnowledge: Facts about the target (services, tech stack, etc.)
- VulnKnowledge: Vulnerability patterns and characteristics
- TechKnowledge: Technology-specific knowledge (versions, configs)
- RelationKnowledge: Relationships between entities
- TacticKnowledge: Effective attack tactics and patterns
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from recursec.llm.router import ModelRouter

logger = structlog.get_logger()


class KnowledgeType(str, Enum):
    TARGET = "target"
    VULNERABILITY = "vulnerability"
    TECHNOLOGY = "technology"
    RELATION = "relation"
    TACTIC = "tactic"
    CREDENTIAL = "credential"
    NETWORK = "network"
    CONFIGURATION = "configuration"


class ConfidenceLevel(str, Enum):
    CONFIRMED = "confirmed"      # Verified by multiple sources
    HIGH = "high"                # Strong evidence
    MEDIUM = "medium"            # Some evidence
    LOW = "low"                  # Weak evidence / inference
    SPECULATIVE = "speculative"  # Educated guess


class RelationType(str, Enum):
    RUNS_ON = "runs_on"
    CONNECTS_TO = "connects_to"
    AUTHENTICATES_WITH = "authenticates_with"
    DEPENDS_ON = "depends_on"
    EXPLOITS = "exploits"
    CONTAINS = "contains"
    EXPOSES = "exposes"
    RESOLVES_TO = "resolves_to"
    SIMILAR_TO = "similar_to"
    LEADS_TO = "leads_to"


@dataclass
class KnowledgeFact:
    """A single fact in the knowledge base."""
    fact_id: str = ""
    knowledge_type: KnowledgeType = KnowledgeType.TARGET
    subject: str = ""      # What this fact is about
    predicate: str = ""    # The relationship/attribute
    obj: str = ""          # The value/target
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    source: str = ""       # Where this fact came from
    evidence: str = ""     # Supporting evidence
    timestamp: float = field(default_factory=time.time)
    tags: list[str] = field(default_factory=list)
    contradicts: list[str] = field(default_factory=list)  # fact_ids that contradict this

    def __post_init__(self) -> None:
        if not self.fact_id:
            content = f"{self.subject}:{self.predicate}:{self.obj}"
            self.fact_id = hashlib.md5(content.encode()).hexdigest()[:10]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.fact_id, "type": self.knowledge_type.value,
            "subject": self.subject, "predicate": self.predicate,
            "object": self.obj, "confidence": self.confidence.value,
            "source": self.source, "tags": self.tags,
        }

    def to_triple(self) -> str:
        """Return as a knowledge triple string."""
        return f"({self.subject}) --[{self.predicate}]--> ({self.obj})"


@dataclass
class KnowledgeEntity:
    """An entity in the knowledge graph."""
    entity_id: str = ""
    name: str = ""
    entity_type: str = ""  # host, service, technology, user, etc.
    properties: dict[str, str] = field(default_factory=dict)
    facts: list[str] = field(default_factory=list)  # fact_ids about this entity
    related_entities: list[tuple[str, str]] = field(default_factory=list)  # (entity_id, relation_type)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.entity_id, "name": self.name,
            "type": self.entity_type,
            "properties": self.properties,
            "facts_count": len(self.facts),
            "relations": len(self.related_entities),
        }


@dataclass
class KnowledgePattern:
    """A pattern detected across multiple facts."""
    pattern_id: str = ""
    description: str = ""
    supporting_facts: list[str] = field(default_factory=list)
    confidence: float = 0.0
    implications: list[str] = field(default_factory=list)
    category: str = ""  # vuln_pattern, config_pattern, tech_pattern

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id, "description": self.description[:200],
            "facts": len(self.supporting_facts),
            "confidence": round(self.confidence, 2),
            "implications": self.implications[:3],
            "category": self.category,
        }


# ── Prompt Templates ────────────────────────────────────────

EXTRACT_KNOWLEDGE_PROMPT = """Extract structured knowledge from this security data.

Source: {source}
Data: {data}

Extract facts as subject-predicate-object triples. Be specific and precise.

Respond as JSON:
{{
  "facts": [
    {{
      "subject": "specific entity",
      "predicate": "relationship or attribute",
      "object": "value or target entity",
      "confidence": "confirmed|high|medium|low|speculative",
      "type": "target|vulnerability|technology|relation|credential|network|configuration"
    }}
  ],
  "entities": [
    {{
      "name": "entity name",
      "type": "host|service|technology|user|database|endpoint",
      "properties": {{}}
    }}
  ]
}}"""

DETECT_PATTERNS_PROMPT = """Analyze these knowledge facts and detect patterns.

Facts:
{facts}

Look for:
1. Common vulnerability patterns (e.g., multiple SQL injection points)
2. Configuration patterns (e.g., consistent misconfigurations)
3. Technology patterns (e.g., outdated software versions)
4. Attack surface patterns (e.g., similar exposed services)

Respond as JSON:
{{
  "patterns": [
    {{
      "description": "pattern description",
      "supporting_fact_ids": ["..."],
      "confidence": 0.X,
      "implications": ["what this pattern means"],
      "category": "vuln_pattern|config_pattern|tech_pattern|surface_pattern"
    }}
  ]
}}"""

DETECT_CONTRADICTIONS_PROMPT = """Check these facts for contradictions.

Facts:
{facts}

Are there any facts that contradict each other? For example:
- Different version numbers for the same software
- Conflicting open/closed port status
- Contradictory vulnerability presence/absence

Respond as JSON:
{{
  "contradictions": [
    {{
      "fact_a_id": "...",
      "fact_b_id": "...",
      "description": "what contradicts",
      "resolution": "which is more likely correct and why"
    }}
  ]
}}"""

GENERATE_NARRATIVE_PROMPT = """Generate an attack narrative from these connected findings.

Target: {target}
Knowledge graph (relevant facts):
{facts}

Construct a narrative that describes:
1. How an attacker could chain these findings
2. The most likely attack path
3. The maximum achievable impact
4. Recommended remediation order

Respond as JSON:
{{
  "narrative": "descriptive attack narrative",
  "attack_chain": ["step 1", "step 2", "..."],
  "max_impact": "critical|high|medium|low",
  "remediation_priority": ["highest priority fix", "next", "..."]
}}"""


class KnowledgeSynthesizer:
    """Builds and maintains a growing knowledge base from agent discoveries.

    The synthesizer:
    1. Extracts structured knowledge from raw data
    2. Maintains a knowledge graph of entities and relationships
    3. Detects patterns across accumulated knowledge
    4. Generates attack narratives from connected findings
    5. Enables semantic search over the knowledge base
    """

    def __init__(self, model_router: ModelRouter) -> None:
        self._router = model_router
        self._facts: dict[str, KnowledgeFact] = {}
        self._entities: dict[str, KnowledgeEntity] = {}
        self._patterns: list[KnowledgePattern] = []
        self._entity_name_index: dict[str, str] = {}  # name → entity_id
        self._log = logger.bind(component="knowledge_synth")

    async def ingest(self, source: str, data: str) -> list[KnowledgeFact]:
        """Ingest raw data and extract knowledge facts."""
        prompt = EXTRACT_KNOWLEDGE_PROMPT.format(
            source=source, data=data[:4000],
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="reasoning",
            temperature=0.2,
            max_tokens=2048,
        )

        parsed = self._parse_json(response)
        new_facts: list[KnowledgeFact] = []

        # Process extracted facts
        for fact_data in parsed.get("facts", []):
            fact = KnowledgeFact(
                knowledge_type=self._parse_knowledge_type(fact_data.get("type", "target")),
                subject=fact_data.get("subject", ""),
                predicate=fact_data.get("predicate", ""),
                obj=fact_data.get("object", ""),
                confidence=self._parse_confidence(fact_data.get("confidence", "medium")),
                source=source,
            )

            # Check for duplicates
            if fact.fact_id not in self._facts:
                self._facts[fact.fact_id] = fact
                new_facts.append(fact)
            else:
                # Update confidence if new source confirms existing fact
                existing = self._facts[fact.fact_id]
                existing.confidence = self._upgrade_confidence(
                    existing.confidence, fact.confidence,
                )

        # Process extracted entities
        for entity_data in parsed.get("entities", []):
            name = entity_data.get("name", "")
            if name and name not in self._entity_name_index:
                entity = KnowledgeEntity(
                    entity_id=hashlib.md5(name.encode()).hexdigest()[:10],
                    name=name,
                    entity_type=entity_data.get("type", "unknown"),
                    properties=entity_data.get("properties", {}),
                )
                self._entities[entity.entity_id] = entity
                self._entity_name_index[name] = entity.entity_id

        # Link facts to entities
        for fact in new_facts:
            subject_eid = self._entity_name_index.get(fact.subject)
            obj_eid = self._entity_name_index.get(fact.obj)
            if subject_eid and subject_eid in self._entities:
                self._entities[subject_eid].facts.append(fact.fact_id)
            if obj_eid and obj_eid in self._entities:
                self._entities[obj_eid].facts.append(fact.fact_id)
            if subject_eid and obj_eid:
                self._entities[subject_eid].related_entities.append(
                    (obj_eid, fact.predicate)
                )

        self._log.info("knowledge_ingested", source=source, new_facts=len(new_facts))
        return new_facts

    def add_fact(self, fact: KnowledgeFact) -> None:
        """Directly add a fact to the knowledge base."""
        self._facts[fact.fact_id] = fact

    def query(
        self,
        subject: str = "",
        predicate: str = "",
        obj: str = "",
        knowledge_type: KnowledgeType | None = None,
        min_confidence: ConfidenceLevel = ConfidenceLevel.SPECULATIVE,
    ) -> list[KnowledgeFact]:
        """Query the knowledge base."""
        confidence_order = {
            ConfidenceLevel.SPECULATIVE: 0, ConfidenceLevel.LOW: 1,
            ConfidenceLevel.MEDIUM: 2, ConfidenceLevel.HIGH: 3,
            ConfidenceLevel.CONFIRMED: 4,
        }
        min_level = confidence_order.get(min_confidence, 0)

        results = []
        for fact in self._facts.values():
            if subject and subject.lower() not in fact.subject.lower():
                continue
            if predicate and predicate.lower() not in fact.predicate.lower():
                continue
            if obj and obj.lower() not in fact.obj.lower():
                continue
            if knowledge_type and fact.knowledge_type != knowledge_type:
                continue
            if confidence_order.get(fact.confidence, 0) < min_level:
                continue
            results.append(fact)

        return sorted(results, key=lambda f: -confidence_order.get(f.confidence, 0))

    def get_entity(self, name: str) -> KnowledgeEntity | None:
        """Get an entity by name."""
        eid = self._entity_name_index.get(name)
        return self._entities.get(eid) if eid else None

    def get_entity_facts(self, entity_name: str) -> list[KnowledgeFact]:
        """Get all facts about an entity."""
        return self.query(subject=entity_name)

    def get_related_entities(self, entity_name: str) -> list[tuple[KnowledgeEntity, str]]:
        """Get entities related to the given entity."""
        entity = self.get_entity(entity_name)
        if not entity:
            return []
        result = []
        for related_id, relation in entity.related_entities:
            related = self._entities.get(related_id)
            if related:
                result.append((related, relation))
        return result

    async def detect_patterns(self) -> list[KnowledgePattern]:
        """Detect patterns across accumulated knowledge."""
        if len(self._facts) < 5:
            return []

        facts_text = "\n".join(
            f"[{f.fact_id}] {f.to_triple()} (confidence: {f.confidence.value})"
            for f in list(self._facts.values())[:50]
        )

        prompt = DETECT_PATTERNS_PROMPT.format(facts=facts_text)

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="reasoning",
            temperature=0.3,
            max_tokens=2048,
        )

        parsed = self._parse_json(response)
        new_patterns = []

        for pat_data in parsed.get("patterns", []):
            pattern = KnowledgePattern(
                pattern_id=hashlib.md5(pat_data.get("description", "").encode()).hexdigest()[:10],
                description=pat_data.get("description", ""),
                supporting_facts=pat_data.get("supporting_fact_ids", []),
                confidence=pat_data.get("confidence", 0.5),
                implications=pat_data.get("implications", []),
                category=pat_data.get("category", ""),
            )
            new_patterns.append(pattern)

        self._patterns.extend(new_patterns)
        return new_patterns

    async def detect_contradictions(self) -> list[dict[str, Any]]:
        """Detect contradictions in the knowledge base."""
        if len(self._facts) < 3:
            return []

        facts_text = "\n".join(
            f"[{f.fact_id}] {f.to_triple()} (source: {f.source})"
            for f in list(self._facts.values())[:40]
        )

        prompt = DETECT_CONTRADICTIONS_PROMPT.format(facts=facts_text)

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="reasoning",
            temperature=0.2,
            max_tokens=1024,
        )

        parsed = self._parse_json(response)
        contradictions = parsed.get("contradictions", [])

        # Mark contradictions in facts
        for contradiction in contradictions:
            fact_a = self._facts.get(contradiction.get("fact_a_id", ""))
            fact_b = self._facts.get(contradiction.get("fact_b_id", ""))
            if fact_a and fact_b:
                fact_a.contradicts.append(fact_b.fact_id)
                fact_b.contradicts.append(fact_a.fact_id)

        return contradictions

    async def generate_narrative(
        self,
        target: str,
        focus_entity: str = "",
    ) -> dict[str, Any]:
        """Generate an attack narrative from connected knowledge."""
        if focus_entity:
            relevant_facts = self.get_entity_facts(focus_entity)
        else:
            relevant_facts = list(self._facts.values())[:30]

        facts_text = "\n".join(f.to_triple() for f in relevant_facts)

        prompt = GENERATE_NARRATIVE_PROMPT.format(
            target=target, facts=facts_text,
        )

        response = await self._router.generate(
            messages=[{"role": "user", "content": prompt}],
            task_type="security",
            temperature=0.3,
            max_tokens=2048,
        )

        return self._parse_json(response)

    def get_context_for_agent(self, agent_role: str, max_facts: int = 30) -> str:
        """Get relevant knowledge context for a specific agent role."""
        role_relevance = {
            "recon": [KnowledgeType.TARGET, KnowledgeType.NETWORK],
            "vuln_scan": [KnowledgeType.VULNERABILITY, KnowledgeType.TECHNOLOGY],
            "exploit": [KnowledgeType.VULNERABILITY, KnowledgeType.CREDENTIAL],
            "code_audit": [KnowledgeType.TECHNOLOGY, KnowledgeType.CONFIGURATION],
        }

        relevant_types = role_relevance.get(agent_role, list(KnowledgeType))
        facts = [
            f for f in self._facts.values()
            if f.knowledge_type in relevant_types
        ]
        facts.sort(key=lambda f: -f.timestamp)
        facts = facts[:max_facts]

        if not facts:
            return "No relevant knowledge accumulated yet."

        lines = ["Accumulated knowledge:"]
        for f in facts:
            lines.append(f"- {f.to_triple()} [{f.confidence.value}]")
        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        by_type: dict[str, int] = defaultdict(int)
        by_confidence: dict[str, int] = defaultdict(int)
        for f in self._facts.values():
            by_type[f.knowledge_type.value] += 1
            by_confidence[f.confidence.value] += 1
        return {
            "total_facts": len(self._facts),
            "total_entities": len(self._entities),
            "total_patterns": len(self._patterns),
            "by_type": dict(by_type),
            "by_confidence": dict(by_confidence),
            "contradictions": sum(1 for f in self._facts.values() if f.contradicts),
        }

    def _upgrade_confidence(
        self,
        current: ConfidenceLevel,
        new: ConfidenceLevel,
    ) -> ConfidenceLevel:
        """Upgrade confidence when multiple sources agree."""
        order = [ConfidenceLevel.SPECULATIVE, ConfidenceLevel.LOW,
                 ConfidenceLevel.MEDIUM, ConfidenceLevel.HIGH, ConfidenceLevel.CONFIRMED]
        curr_idx = order.index(current) if current in order else 2
        new_idx = order.index(new) if new in order else 2
        # Bump up by one level when confirmed by another source
        upgraded = min(len(order) - 1, max(curr_idx, new_idx) + 1)
        return order[upgraded]

    def _parse_knowledge_type(self, text: str) -> KnowledgeType:
        try:
            return KnowledgeType(text)
        except ValueError:
            return KnowledgeType.TARGET

    def _parse_confidence(self, text: str) -> ConfidenceLevel:
        try:
            return ConfidenceLevel(text)
        except ValueError:
            return ConfidenceLevel.MEDIUM

    def _parse_json(self, text: str) -> dict[str, Any]:
        try:
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]
            return json.loads(text.strip())
        except (json.JSONDecodeError, IndexError):
            return {}
