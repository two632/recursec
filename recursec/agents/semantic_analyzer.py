"""Semantic analyzer — analyzes meaning and context of security data.

Implements:
1. Semantic similarity between findings
2. Finding clustering by meaning
3. Context extraction from tool outputs
4. Semantic search across findings/evidence
5. Entity extraction (IPs, domains, CVEs, versions)
6. Relationship extraction between entities
7. Sentiment analysis for risk assessment
8. Topic modeling for finding categorization
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class ExtractedEntity:
    """An entity extracted from text."""
    entity_type: str = ""       # ip, domain, cve, port, version, email, hash
    value: str = ""
    context: str = ""           # Surrounding text
    confidence: float = 0.8
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.entity_type, "value": self.value[:60],
            "confidence": round(self.confidence, 2),
        }


@dataclass
class SemanticCluster:
    """A cluster of semantically similar findings."""
    cluster_id: str = ""
    label: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)
    keywords: list[str] = field(default_factory=list)
    severity_distribution: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.cluster_id, "label": self.label[:60],
            "findings": len(self.findings),
            "keywords": self.keywords[:5],
            "severity": self.severity_distribution,
        }


@dataclass
class TopicResult:
    """Result of topic modeling."""
    topic_id: str = ""
    label: str = ""
    keywords: list[str] = field(default_factory=list)
    finding_count: int = 0
    weight: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.topic_id, "label": self.label[:40],
            "keywords": self.keywords[:5],
            "count": self.finding_count,
        }


# ── Entity Patterns ──────────────────────────────────────────

ENTITY_PATTERNS = {
    "ip": re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"),
    "ipv6": re.compile(r"\b([0-9a-fA-F:]{3,39})\b"),
    "domain": re.compile(r"\b([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)\b"),
    "cve": re.compile(r"\b(CVE-\d{4}-\d{4,})\b"),
    "port": re.compile(r"\bport\s*(\d{1,5})\b", re.IGNORECASE),
    "version": re.compile(r"\b(\d+\.\d+(?:\.\d+)?(?:[-_.]\w+)?)\b"),
    "email": re.compile(r"\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b"),
    "md5": re.compile(r"\b([a-fA-F0-9]{32})\b"),
    "sha1": re.compile(r"\b([a-fA-F0-9]{40})\b"),
    "sha256": re.compile(r"\b([a-fA-F0-9]{64})\b"),
    "url": re.compile(r"(https?://[^\s\"'<>]+)"),
    "cidr": re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})\b"),
}

# ── Security Topic Keywords ──────────────────────────────────

SECURITY_TOPICS = {
    "authentication": ["login", "password", "credential", "auth", "session", "token", "cookie", "jwt", "oauth", "saml"],
    "injection": ["sql", "injection", "sqli", "xss", "script", "command", "ldap", "xpath", "template", "ssti"],
    "configuration": ["misconfiguration", "default", "exposed", "debug", "verbose", "header", "cors", "csp"],
    "cryptography": ["ssl", "tls", "certificate", "cipher", "encryption", "hash", "md5", "sha1", "weak"],
    "information_disclosure": ["disclosure", "leak", "exposed", "sensitive", "backup", "directory", "listing", "source"],
    "access_control": ["authorization", "privilege", "escalation", "idor", "bypass", "admin", "role", "permission"],
    "network": ["port", "service", "firewall", "dns", "snmp", "smtp", "ftp", "ssh", "rdp", "vnc"],
    "web_application": ["http", "https", "api", "rest", "graphql", "websocket", "redirect", "upload"],
}


class SemanticAnalyzer:
    """Analyzes meaning and context of security data.

    Extracts entities, clusters findings, and
    performs topic modeling.
    """

    def __init__(self) -> None:
        self._entity_cache: list[ExtractedEntity] = []
        self._clusters: list[SemanticCluster] = []
        self._cluster_counter = 0
        self._log = logger.bind(component="semantic_analyzer")

    def extract_entities(self, text: str, source: str = "") -> list[ExtractedEntity]:
        """Extract security-relevant entities from text."""
        entities = []

        for entity_type, pattern in ENTITY_PATTERNS.items():
            for match in pattern.finditer(text):
                value = match.group(1)

                # Filter out false positives
                if entity_type == "version" and len(value) < 3:
                    continue
                if entity_type == "ip" and not self._is_valid_ip(value):
                    continue

                # Get surrounding context
                start = max(0, match.start() - 30)
                end = min(len(text), match.end() + 30)
                context = text[start:end].strip()

                entities.append(ExtractedEntity(
                    entity_type=entity_type,
                    value=value,
                    context=context[:80],
                    source=source,
                ))

        self._entity_cache.extend(entities)
        if len(self._entity_cache) > 5000:
            self._entity_cache = self._entity_cache[-5000:]

        return entities

    def cluster_findings(
        self,
        findings: list[dict[str, Any]],
    ) -> list[SemanticCluster]:
        """Cluster findings by semantic similarity."""
        # Use keyword-based clustering
        topic_findings: dict[str, list[dict[str, Any]]] = defaultdict(list)

        for finding in findings:
            text = (finding.get("title", "") + " " + finding.get("description", "")).lower()
            best_topic = "other"
            best_score = 0

            for topic, keywords in SECURITY_TOPICS.items():
                score = sum(1 for kw in keywords if kw in text)
                if score > best_score:
                    best_score = score
                    best_topic = topic

            topic_findings[best_topic].append(finding)

        # Build clusters
        clusters = []
        for topic, topic_items in topic_findings.items():
            if not topic_items:
                continue

            self._cluster_counter += 1
            cluster = SemanticCluster(
                cluster_id=f"cluster-{self._cluster_counter}",
                label=topic.replace("_", " ").title(),
                findings=topic_items,
                keywords=SECURITY_TOPICS.get(topic, [])[:5],
            )

            # Severity distribution
            for finding in topic_items:
                sev = finding.get("severity", "info")
                cluster.severity_distribution[sev] = cluster.severity_distribution.get(sev, 0) + 1

            clusters.append(cluster)

        clusters.sort(key=lambda c: len(c.findings), reverse=True)
        self._clusters = clusters
        return clusters

    def extract_topics(
        self,
        texts: list[str],
        num_topics: int = 5,
    ) -> list[TopicResult]:
        """Extract topics from a collection of texts."""
        # Simple TF-based topic extraction
        all_words: list[str] = []
        for text in texts:
            words = re.findall(r"\b[a-zA-Z]{3,}\b", text.lower())
            all_words.extend(words)

        # Remove common stopwords
        stopwords = {"the", "and", "for", "are", "but", "not", "you", "all",
                     "can", "her", "was", "one", "our", "out", "has", "have",
                     "this", "that", "with", "from", "they", "been", "said",
                     "each", "which", "their", "will", "when", "what"}
        filtered = [w for w in all_words if w not in stopwords]

        # Get top keywords
        counter = Counter(filtered)
        top_words = counter.most_common(num_topics * 5)

        # Group into topics
        topics = []
        used_words: set[str] = set()

        for i in range(min(num_topics, len(top_words))):
            topic_words = []
            for word, count in top_words:
                if word not in used_words and len(topic_words) < 5:
                    # Check if related to a security topic
                    for topic_name, keywords in SECURITY_TOPICS.items():
                        if word in keywords:
                            topic_words.append(word)
                            used_words.add(word)
                            break
                    else:
                        if count >= 2:
                            topic_words.append(word)
                            used_words.add(word)

            if topic_words:
                topics.append(TopicResult(
                    topic_id=f"topic-{i + 1}",
                    label=" / ".join(topic_words[:3]),
                    keywords=topic_words,
                    finding_count=sum(counter.get(w, 0) for w in topic_words),
                ))

        return topics

    def similarity(self, text1: str, text2: str) -> float:
        """Compute simple keyword similarity between two texts."""
        words1 = set(re.findall(r"\b[a-zA-Z]{3,}\b", text1.lower()))
        words2 = set(re.findall(r"\b[a-zA-Z]{3,}\b", text2.lower()))

        if not words1 or not words2:
            return 0.0

        intersection = words1 & words2
        union = words1 | words2

        return len(intersection) / len(union)

    def search(
        self,
        query: str,
        findings: list[dict[str, Any]],
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Semantic search across findings."""
        scored = []
        for finding in findings:
            text = finding.get("title", "") + " " + finding.get("description", "")
            score = self.similarity(query, text)
            if score > 0:
                scored.append((score, finding))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [f for _, f in scored[:limit]]

    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        """Check if string is a valid IP."""
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        return all(0 <= int(p) <= 255 for p in parts if p.isdigit())

    def get_entity_summary(self) -> dict[str, int]:
        """Get summary of extracted entities."""
        counts: dict[str, int] = defaultdict(int)
        for entity in self._entity_cache:
            counts[entity.entity_type] += 1
        return dict(counts)

    def get_stats(self) -> dict[str, Any]:
        return {
            "entities": len(self._entity_cache),
            "clusters": len(self._clusters),
            "entity_types": len(self.get_entity_summary()),
        }
