"""Context synthesis — build rich context for agent reasoning.

When an agent needs to make a decision or generate a response,
it needs relevant context from multiple sources. This module:

1. Gathers context from working memory, semantic memory, episodic memory
2. Filters to relevant information based on the current task
3. Compresses context to fit within token budgets
4. Structures context for optimal LLM comprehension
5. Injects domain knowledge appropriate to the task
6. Manages context windows across multiple turns
7. Tracks what context was used for each decision
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ContextPriority(str, Enum):
    CRITICAL = "critical"       # Must include
    HIGH = "high"               # Include if space allows
    MEDIUM = "medium"           # Include if budget permits
    LOW = "low"                 # Only if plenty of room
    BACKGROUND = "background"   # Rarely included


class ContextSource(str, Enum):
    GOAL = "goal"
    WORKING_MEMORY = "working_memory"
    SEMANTIC_MEMORY = "semantic_memory"
    EPISODIC_MEMORY = "episodic_memory"
    TOOL_OUTPUT = "tool_output"
    FINDING = "finding"
    PARENT_AGENT = "parent_agent"
    DOMAIN_KNOWLEDGE = "domain_knowledge"
    RECENT_ACTIONS = "recent_actions"
    REFLECTION = "reflection"


@dataclass
class ContextBlock:
    """A block of context information."""
    block_id: str = ""
    source: ContextSource = ContextSource.GOAL
    content: str = ""
    priority: ContextPriority = ContextPriority.MEDIUM
    relevance_score: float = 0.5
    token_estimate: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        if not self.token_estimate:
            self.token_estimate = len(self.content.split()) * 2  # Rough estimate

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.block_id,
            "source": self.source.value,
            "priority": self.priority.value,
            "relevance": round(self.relevance_score, 3),
            "tokens": self.token_estimate,
            "content_preview": self.content[:100],
        }


@dataclass
class SynthesizedContext:
    """The final synthesized context ready for LLM consumption."""
    blocks: list[ContextBlock] = field(default_factory=list)
    total_tokens: int = 0
    budget_used: float = 0.0    # Fraction of budget used
    sources_used: list[str] = field(default_factory=list)
    blocks_dropped: int = 0     # Number of blocks that didn't fit

    def to_text(self, separator: str = "\n\n") -> str:
        """Convert to text for LLM prompt."""
        return separator.join(b.content for b in self.blocks)

    def to_sections(self) -> dict[str, str]:
        """Convert to named sections."""
        sections: dict[str, str] = {}
        for block in self.blocks:
            key = block.source.value
            if key in sections:
                sections[key] += "\n" + block.content
            else:
                sections[key] = block.content
        return sections

    def to_dict(self) -> dict[str, Any]:
        return {
            "blocks": len(self.blocks),
            "total_tokens": self.total_tokens,
            "budget_used": round(self.budget_used, 2),
            "sources": self.sources_used,
            "dropped": self.blocks_dropped,
        }


# ── Domain Knowledge Templates ──────────────────────────────

DOMAIN_KNOWLEDGE: dict[str, dict[str, str]] = {
    "web": {
        "common_vulns": (
            "Common web vulnerabilities: SQL injection, XSS (reflected/stored/DOM), "
            "CSRF, SSRF, XXE, IDOR, path traversal, file inclusion, "
            "authentication bypass, session fixation, CORS misconfiguration, "
            "open redirect, clickjacking, SSTI, deserialization, "
            "HTTP request smuggling, cache poisoning."
        ),
        "testing_methodology": (
            "Web testing phases: 1) Map application (crawl, discover endpoints) "
            "2) Identify entry points (forms, APIs, headers) "
            "3) Test each entry point for injection "
            "4) Check authentication and session management "
            "5) Test authorization (IDOR, privilege escalation) "
            "6) Check configuration (headers, error handling, debug endpoints)"
        ),
    },
    "network": {
        "common_vulns": (
            "Common network vulnerabilities: open ports, default credentials, "
            "unencrypted services, SMB signing disabled, SNMP community strings, "
            "DNS zone transfer, weak TLS, anonymous FTP/SMB, "
            "LLMNR/NBT-NS poisoning, unpatched services."
        ),
        "testing_methodology": (
            "Network testing phases: 1) Host discovery (ping sweep, ARP scan) "
            "2) Port scanning (SYN scan, full TCP, UDP top ports) "
            "3) Service version detection "
            "4) Vulnerability scanning "
            "5) Manual exploitation "
            "6) Post-exploitation and lateral movement"
        ),
    },
    "code": {
        "common_vulns": (
            "Common code vulnerabilities: injection flaws, buffer overflows, "
            "use-after-free, integer overflow, race conditions, "
            "hardcoded secrets, insecure deserialization, "
            "broken access control, cryptographic failures, "
            "insecure random, XXE, path traversal."
        ),
        "testing_methodology": (
            "Code review phases: 1) Identify high-risk areas (auth, crypto, input handling) "
            "2) Run SAST tools (semgrep, bandit, codeql) "
            "3) Check dependencies (trivy, grype) "
            "4) Manual review of critical paths "
            "5) Check for secrets and sensitive data "
            "6) Validate data flow from sources to sinks"
        ),
    },
    "cloud": {
        "common_vulns": (
            "Common cloud vulnerabilities: overly permissive IAM, "
            "public S3 buckets, exposed metadata service, "
            "unencrypted data at rest/transit, default credentials, "
            "missing MFA, overprivileged service accounts, "
            "publicly accessible databases, weak network segmentation."
        ),
    },
}


class ContextSynthesizer:
    """Builds rich context for agent reasoning.

    Gathers information from multiple sources, filters by relevance,
    compresses to fit token budgets, and structures for optimal
    LLM comprehension.
    """

    def __init__(self, default_token_budget: int = 4000) -> None:
        self._default_budget = default_token_budget
        self._context_history: list[dict[str, Any]] = []
        self._log = logger.bind(component="context_synthesis")

    def synthesize(
        self,
        task_description: str,
        domain: str = "",
        goal: str = "",
        working_memory_items: list[dict[str, Any]] | None = None,
        semantic_results: list[dict[str, Any]] | None = None,
        episodic_lessons: list[str] | None = None,
        tool_outputs: list[dict[str, str]] | None = None,
        findings: list[dict[str, Any]] | None = None,
        parent_context: str = "",
        recent_actions: list[str] | None = None,
        reflection_notes: list[str] | None = None,
        token_budget: int = 0,
    ) -> SynthesizedContext:
        """Synthesize context from multiple sources."""
        budget = token_budget or self._default_budget
        blocks: list[ContextBlock] = []
        block_counter = 0

        # 1. Goal (always included, critical priority)
        if goal:
            blocks.append(ContextBlock(
                block_id=f"ctx-{block_counter}",
                source=ContextSource.GOAL,
                content=f"Goal: {goal}",
                priority=ContextPriority.CRITICAL,
                relevance_score=1.0,
            ))
            block_counter += 1

        # 2. Task description (critical)
        if task_description:
            blocks.append(ContextBlock(
                block_id=f"ctx-{block_counter}",
                source=ContextSource.GOAL,
                content=f"Current task: {task_description}",
                priority=ContextPriority.CRITICAL,
                relevance_score=1.0,
            ))
            block_counter += 1

        # 3. Parent context (high priority)
        if parent_context:
            blocks.append(ContextBlock(
                block_id=f"ctx-{block_counter}",
                source=ContextSource.PARENT_AGENT,
                content=f"Parent agent context: {parent_context[:500]}",
                priority=ContextPriority.HIGH,
                relevance_score=0.8,
            ))
            block_counter += 1

        # 4. Domain knowledge
        if domain and domain in DOMAIN_KNOWLEDGE:
            for key, knowledge in DOMAIN_KNOWLEDGE[domain].items():
                blocks.append(ContextBlock(
                    block_id=f"ctx-{block_counter}",
                    source=ContextSource.DOMAIN_KNOWLEDGE,
                    content=f"[{key}] {knowledge}",
                    priority=ContextPriority.MEDIUM,
                    relevance_score=0.6,
                ))
                block_counter += 1

        # 5. Working memory (high priority, already curated)
        for item in (working_memory_items or []):
            blocks.append(ContextBlock(
                block_id=f"ctx-{block_counter}",
                source=ContextSource.WORKING_MEMORY,
                content=str(item.get("content", ""))[:300],
                priority=ContextPriority.HIGH,
                relevance_score=item.get("relevance", 0.5),
            ))
            block_counter += 1

        # 6. Semantic memory results (medium priority)
        for result in (semantic_results or []):
            blocks.append(ContextBlock(
                block_id=f"ctx-{block_counter}",
                source=ContextSource.SEMANTIC_MEMORY,
                content=str(result.get("content", ""))[:300],
                priority=ContextPriority.MEDIUM,
                relevance_score=result.get("score", 0.5),
            ))
            block_counter += 1

        # 7. Episodic lessons (medium priority)
        for lesson in (episodic_lessons or []):
            blocks.append(ContextBlock(
                block_id=f"ctx-{block_counter}",
                source=ContextSource.EPISODIC_MEMORY,
                content=f"Past lesson: {lesson[:200]}",
                priority=ContextPriority.MEDIUM,
                relevance_score=0.6,
            ))
            block_counter += 1

        # 8. Recent tool outputs (high priority — fresh info)
        for output in (tool_outputs or [])[-5:]:  # Last 5 only
            blocks.append(ContextBlock(
                block_id=f"ctx-{block_counter}",
                source=ContextSource.TOOL_OUTPUT,
                content=f"[{output.get('tool', '')}] {output.get('output', '')[:500]}",
                priority=ContextPriority.HIGH,
                relevance_score=0.7,
            ))
            block_counter += 1

        # 9. Current findings (medium priority)
        for finding in (findings or [])[-10:]:  # Last 10
            blocks.append(ContextBlock(
                block_id=f"ctx-{block_counter}",
                source=ContextSource.FINDING,
                content=f"Finding: {finding.get('title', '')} ({finding.get('severity', '')})",
                priority=ContextPriority.MEDIUM,
                relevance_score=0.5,
            ))
            block_counter += 1

        # 10. Recent actions (low priority)
        for action in (recent_actions or [])[-5:]:
            blocks.append(ContextBlock(
                block_id=f"ctx-{block_counter}",
                source=ContextSource.RECENT_ACTIONS,
                content=f"Recent: {action[:100]}",
                priority=ContextPriority.LOW,
                relevance_score=0.4,
            ))
            block_counter += 1

        # 11. Reflection notes (medium priority)
        for note in (reflection_notes or []):
            blocks.append(ContextBlock(
                block_id=f"ctx-{block_counter}",
                source=ContextSource.REFLECTION,
                content=f"Reflection: {note[:200]}",
                priority=ContextPriority.MEDIUM,
                relevance_score=0.6,
            ))
            block_counter += 1

        # Select blocks that fit within budget
        synthesized = self._select_and_compress(blocks, budget)

        # Record for history
        self._context_history.append(synthesized.to_dict())
        if len(self._context_history) > 100:
            self._context_history = self._context_history[-100:]

        return synthesized

    def _select_and_compress(
        self,
        blocks: list[ContextBlock],
        budget: int,
    ) -> SynthesizedContext:
        """Select blocks that fit within the token budget."""
        # Sort by: priority (critical first), then relevance
        priority_order = {
            ContextPriority.CRITICAL: 0,
            ContextPriority.HIGH: 1,
            ContextPriority.MEDIUM: 2,
            ContextPriority.LOW: 3,
            ContextPriority.BACKGROUND: 4,
        }

        blocks.sort(key=lambda b: (
            priority_order.get(b.priority, 4),
            -b.relevance_score,
        ))

        selected: list[ContextBlock] = []
        total_tokens = 0
        dropped = 0
        sources: set[str] = set()

        for block in blocks:
            if total_tokens + block.token_estimate <= budget:
                selected.append(block)
                total_tokens += block.token_estimate
                sources.add(block.source.value)
            else:
                # Try to compress
                compressed = self._compress_block(block, budget - total_tokens)
                if compressed and compressed.token_estimate > 0:
                    selected.append(compressed)
                    total_tokens += compressed.token_estimate
                    sources.add(compressed.source.value)
                else:
                    dropped += 1

        return SynthesizedContext(
            blocks=selected,
            total_tokens=total_tokens,
            budget_used=total_tokens / max(1, budget),
            sources_used=sorted(sources),
            blocks_dropped=dropped,
        )

    def _compress_block(
        self,
        block: ContextBlock,
        remaining_tokens: int,
    ) -> ContextBlock | None:
        """Try to compress a block to fit remaining budget."""
        if remaining_tokens < 20:
            return None

        # Simple truncation with context preservation
        max_chars = remaining_tokens * 3  # Rough char-to-token ratio
        if max_chars < 50:
            return None

        compressed_content = block.content[:max_chars]
        if len(compressed_content) < len(block.content):
            compressed_content = compressed_content[:max_chars - 3] + "..."

        return ContextBlock(
            block_id=block.block_id,
            source=block.source,
            content=compressed_content,
            priority=block.priority,
            relevance_score=block.relevance_score * 0.9,  # Slight penalty for compression
            metadata=block.metadata,
        )

    def get_stats(self) -> dict[str, Any]:
        if not self._context_history:
            return {"total_syntheses": 0}
        source_freq: dict[str, int] = defaultdict(int)
        for entry in self._context_history:
            for source in entry.get("sources", []):
                source_freq[source] += 1
        return {
            "total_syntheses": len(self._context_history),
            "avg_budget_used": round(
                sum(e.get("budget_used", 0) for e in self._context_history) /
                max(1, len(self._context_history)), 2,
            ),
            "source_frequency": dict(source_freq),
        }
