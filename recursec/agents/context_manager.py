"""Context manager — manages multi-turn state across recursion levels.

Implements:
1. Hierarchical context (parent → child inheritance)
2. Context scoping (what each level can see)
3. Working memory management (recent N turns)
4. Context compression (summarize old turns)
5. Cross-agent context sharing
6. Context snapshot and restore
7. Context prompt for LLM
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class MessageRole(str, Enum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"
    PARENT = "parent"
    CHILD = "child"


class ContextScope(str, Enum):
    LOCAL = "local"            # Only this agent
    INHERITED = "inherited"    # From parent
    SHARED = "shared"          # Cross-agent
    GLOBAL = "global"          # All agents


@dataclass
class ContextMessage:
    """A single message in the context."""
    role: MessageRole = MessageRole.USER
    content: str = ""
    scope: ContextScope = ContextScope.LOCAL
    agent_id: str = ""
    timestamp: float = field(default_factory=time.time)
    token_estimate: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role.value[:6],
            "agent": self.agent_id[:10],
            "scope": self.scope.value[:6],
            "tokens": self.token_estimate,
        }


@dataclass
class AgentContext:
    """Context for a single agent."""
    agent_id: str = ""
    parent_id: str = ""
    depth: int = 0
    role: str = ""
    messages: list[ContextMessage] = field(default_factory=list)
    working_memory: list[str] = field(default_factory=list)
    inherited_context: list[ContextMessage] = field(default_factory=list)
    shared_context: list[ContextMessage] = field(default_factory=list)
    max_working_memory: int = 10
    max_messages: int = 50
    total_tokens: int = 0
    created_at: float = field(default_factory=time.time)

    @property
    def all_messages(self) -> list[ContextMessage]:
        """All messages in chronological order."""
        all_msgs = self.inherited_context + self.shared_context + self.messages
        all_msgs.sort(key=lambda m: m.timestamp)
        return all_msgs

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.agent_id[:10],
            "depth": self.depth,
            "msgs": len(self.messages),
            "inherited": len(self.inherited_context),
            "tokens": self.total_tokens,
        }


class ContextManager:
    """Manages multi-turn conversation state across agents.

    Handles context inheritance (parent → child),
    cross-agent sharing, working memory, and
    context compression.
    """

    def __init__(
        self,
        max_context_tokens: int = 6000,
        chars_per_token: float = 3.5,
    ) -> None:
        self._contexts: dict[str, AgentContext] = {}
        self._max_tokens = max_context_tokens
        self._chars_per_token = chars_per_token
        self._shared_pool: list[ContextMessage] = []
        self._log = logger.bind(component="context_manager")

    def _estimate_tokens(self, text: str) -> int:
        return int(len(text) / self._chars_per_token)

    def create_context(
        self,
        agent_id: str,
        parent_id: str = "",
        role: str = "",
        depth: int = 0,
    ) -> AgentContext:
        """Create a new agent context."""
        ctx = AgentContext(
            agent_id=agent_id,
            parent_id=parent_id,
            depth=depth,
            role=role,
        )

        # Inherit from parent
        if parent_id and parent_id in self._contexts:
            parent = self._contexts[parent_id]
            # Inherit recent messages from parent
            recent_parent = parent.messages[-5:]
            for msg in recent_parent:
                inherited = ContextMessage(
                    role=MessageRole.PARENT,
                    content=msg.content,
                    scope=ContextScope.INHERITED,
                    agent_id=parent_id,
                    timestamp=msg.timestamp,
                    token_estimate=msg.token_estimate,
                )
                ctx.inherited_context.append(inherited)

            # Inherit working memory
            ctx.working_memory = list(parent.working_memory)

        # Add shared context
        ctx.shared_context = [
            msg for msg in self._shared_pool
            if msg.agent_id != agent_id
        ][-3:]

        self._contexts[agent_id] = ctx
        return ctx

    def add_message(
        self,
        agent_id: str,
        role: MessageRole,
        content: str,
        scope: ContextScope = ContextScope.LOCAL,
        metadata: dict[str, Any] | None = None,
    ) -> ContextMessage | None:
        """Add a message to agent's context."""
        ctx = self._contexts.get(agent_id)
        if not ctx:
            return None

        tokens = self._estimate_tokens(content)
        msg = ContextMessage(
            role=role,
            content=content,
            scope=scope,
            agent_id=agent_id,
            token_estimate=tokens,
            metadata=metadata or {},
        )

        ctx.messages.append(msg)
        ctx.total_tokens += tokens

        # Share if scope is shared/global
        if scope in (ContextScope.SHARED, ContextScope.GLOBAL):
            self._shared_pool.append(msg)

        # Compress if over limit
        if ctx.total_tokens > self._max_tokens:
            self._compress_context(agent_id)

        # Trim if too many messages
        if len(ctx.messages) > ctx.max_messages:
            self._trim_messages(agent_id)

        return msg

    def add_to_working_memory(
        self,
        agent_id: str,
        item: str,
    ) -> None:
        """Add item to working memory."""
        ctx = self._contexts.get(agent_id)
        if not ctx:
            return

        ctx.working_memory.append(item)

        # Trim to max
        while len(ctx.working_memory) > ctx.max_working_memory:
            ctx.working_memory.pop(0)

    def _compress_context(self, agent_id: str) -> None:
        """Compress context by summarizing old messages."""
        ctx = self._contexts.get(agent_id)
        if not ctx or len(ctx.messages) < 10:
            return

        # Keep last 5 messages, summarize the rest
        old_messages = ctx.messages[:-5]
        recent_messages = ctx.messages[-5:]

        # Create summary
        summary_parts: list[str] = []
        for msg in old_messages:
            if msg.role == MessageRole.TOOL:
                summary_parts.append(f"[Tool output: {msg.content[:50]}...]")
            elif msg.role == MessageRole.ASSISTANT:
                summary_parts.append(f"[Agent action: {msg.content[:50]}...]")
            else:
                summary_parts.append(f"[{msg.role.value}: {msg.content[:30]}...]")

        summary = "CONTEXT SUMMARY:\n" + "\n".join(summary_parts[-10:])
        tokens = self._estimate_tokens(summary)

        summary_msg = ContextMessage(
            role=MessageRole.SYSTEM,
            content=summary,
            scope=ContextScope.LOCAL,
            agent_id=agent_id,
            token_estimate=tokens,
        )

        ctx.messages = [summary_msg] + recent_messages
        ctx.total_tokens = sum(m.token_estimate for m in ctx.messages)

    def _trim_messages(self, agent_id: str) -> None:
        """Trim excess messages."""
        ctx = self._contexts.get(agent_id)
        if not ctx:
            return

        while len(ctx.messages) > ctx.max_messages:
            removed = ctx.messages.pop(0)
            ctx.total_tokens -= removed.token_estimate

    def get_context_for_prompt(
        self,
        agent_id: str,
        max_tokens: int = 0,
    ) -> list[dict[str, str]]:
        """Get context formatted for LLM prompt."""
        ctx = self._contexts.get(agent_id)
        if not ctx:
            return []

        budget = max_tokens or self._max_tokens
        messages: list[dict[str, str]] = []
        used_tokens = 0

        # Working memory first
        if ctx.working_memory:
            wm_text = "WORKING MEMORY:\n" + "\n".join(f"- {m}" for m in ctx.working_memory)
            wm_tokens = self._estimate_tokens(wm_text)
            if used_tokens + wm_tokens <= budget:
                messages.append({"role": "system", "content": wm_text})
                used_tokens += wm_tokens

        # Then all messages (most recent first for budget fitting)
        all_msgs = ctx.all_messages
        for msg in reversed(all_msgs):
            if used_tokens + msg.token_estimate > budget:
                continue
            role_map = {
                MessageRole.SYSTEM: "system",
                MessageRole.USER: "user",
                MessageRole.ASSISTANT: "assistant",
                MessageRole.TOOL: "user",
                MessageRole.PARENT: "system",
                MessageRole.CHILD: "user",
            }
            messages.insert(0, {
                "role": role_map.get(msg.role, "user"),
                "content": msg.content,
            })
            used_tokens += msg.token_estimate

        return messages

    def propagate_to_parent(
        self,
        child_id: str,
        summary: str,
    ) -> None:
        """Send child results back to parent context."""
        child = self._contexts.get(child_id)
        if not child or not child.parent_id:
            return

        self.add_message(
            agent_id=child.parent_id,
            role=MessageRole.CHILD,
            content=f"[Child agent {child.role} result]: {summary}",
            scope=ContextScope.LOCAL,
        )

    def snapshot(self, agent_id: str) -> dict[str, Any] | None:
        """Snapshot agent context for persistence."""
        ctx = self._contexts.get(agent_id)
        if not ctx:
            return None

        return {
            "agent_id": ctx.agent_id,
            "parent_id": ctx.parent_id,
            "depth": ctx.depth,
            "role": ctx.role,
            "working_memory": list(ctx.working_memory),
            "total_tokens": ctx.total_tokens,
            "message_count": len(ctx.messages),
        }

    def build_context_prompt(self, agent_id: str = "") -> str:
        """Build context manager status prompt."""
        lines = ["## Context State\n"]

        lines.append(f"Active contexts: {len(self._contexts)}")
        lines.append(f"Shared pool: {len(self._shared_pool)} messages")

        if agent_id and agent_id in self._contexts:
            ctx = self._contexts[agent_id]
            lines.append(f"\nCurrent agent: {ctx.agent_id[:12]}")
            lines.append(f"Depth: {ctx.depth}")
            lines.append(f"Messages: {len(ctx.messages)}")
            lines.append(f"Tokens: {ctx.total_tokens}/{self._max_tokens}")
            lines.append(f"Working memory: {len(ctx.working_memory)} items")

            if ctx.working_memory:
                lines.append("WM:")
                for item in ctx.working_memory[-3:]:
                    lines.append(f"  - {item[:50]}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        total_msgs = sum(len(c.messages) for c in self._contexts.values())
        total_tokens = sum(c.total_tokens for c in self._contexts.values())
        depths = [c.depth for c in self._contexts.values()]

        return {
            "active_contexts": len(self._contexts),
            "total_messages": total_msgs,
            "total_tokens": total_tokens,
            "shared_pool": len(self._shared_pool),
            "max_depth": max(depths) if depths else 0,
        }
