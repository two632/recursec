"""Conversation manager — manages multi-turn LLM interactions.

This is how the agent actually TALKS to the LLMs. Implements:
1. Multi-turn conversation with context management
2. System prompt injection with KB context
3. Tool-call parsing from LLM responses
4. Auto-summarization when context is full
5. Conversation branching (multiple parallel threads)
6. Response quality scoring
7. Retry with different model on failure
"""

from __future__ import annotations

import re
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


class ConversationStatus(str, Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class Message:
    """A message in a conversation."""
    role: MessageRole = MessageRole.USER
    content: str = ""
    timestamp: float = field(default_factory=time.time)
    token_count: int = 0
    model_id: str = ""
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    quality_score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role.value,
            "content": self.content[:100],
            "tokens": self.token_count,
        }

    def to_llm_format(self) -> dict[str, str]:
        """Convert to format expected by llama.cpp /v1/chat/completions."""
        return {"role": self.role.value, "content": self.content}


@dataclass
class Conversation:
    """A multi-turn conversation with an LLM."""
    conversation_id: str = ""
    model_id: str = ""
    messages: list[Message] = field(default_factory=list)
    status: ConversationStatus = ConversationStatus.ACTIVE
    total_tokens: int = 0
    max_tokens: int = 8192
    started_at: float = field(default_factory=time.time)
    purpose: str = ""
    parent_conversation_id: str = ""
    tool_results: list[dict[str, Any]] = field(default_factory=list)

    @property
    def remaining_tokens(self) -> int:
        return max(0, self.max_tokens - self.total_tokens)

    @property
    def message_count(self) -> int:
        return len(self.messages)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.conversation_id[:8],
            "model": self.model_id[:12],
            "messages": len(self.messages),
            "tokens": f"{self.total_tokens}/{self.max_tokens}",
            "status": self.status.value[:6],
        }

    def get_llm_messages(self) -> list[dict[str, str]]:
        """Get all messages in LLM-compatible format."""
        return [m.to_llm_format() for m in self.messages]


@dataclass
class ToolCall:
    """A parsed tool call from LLM response."""
    tool_name: str = ""
    arguments: dict[str, Any] = field(default_factory=dict)
    raw_text: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"tool": self.tool_name, "args": self.arguments}


# Tool call patterns to parse from LLM responses
TOOL_CALL_PATTERNS: list[dict[str, Any]] = [
    {
        "name": "json_action",
        "pattern": r'\{\s*"action"\s*:\s*"([^"]+)"\s*,\s*"(?:params|arguments|args)"\s*:\s*(\{[^}]+\})',
        "extract": lambda m: (m.group(1), m.group(2)),
    },
    {
        "name": "bash_command",
        "pattern": r'```(?:bash|sh|shell)\n((?:(?!```)[\s\S])*)\n```',
        "extract": lambda m: ("bash", m.group(1)),
    },
    {
        "name": "tool_tag",
        "pattern": r'<tool(?:_call)?>\s*(\w+)\s*(?:\((.*?)\))?\s*</tool(?:_call)?>',
        "extract": lambda m: (m.group(1), m.group(2) or ""),
    },
    {
        "name": "run_command",
        "pattern": r'(?:RUN|EXECUTE|COMMAND):\s*`?([^`\n]+)`?',
        "extract": lambda m: ("bash", m.group(1)),
    },
]

# Response quality indicators
QUALITY_POSITIVE: list[str] = [
    "step 1", "step 2", "therefore", "because", "evidence",
    "finding:", "severity:", "recommendation:", "confidence:",
    "the vulnerability", "this indicates", "based on",
]

QUALITY_NEGATIVE: list[str] = [
    "i cannot", "i don't know", "as an ai", "i'm sorry",
    "i don't have access", "this is hypothetical",
    "without more information", "it depends",
]


class ConversationManager:
    """Manages conversations with LLMs."""

    def __init__(self, default_max_tokens: int = 8192) -> None:
        self._conversations: dict[str, Conversation] = {}
        self._conv_counter = 0
        self._default_max_tokens = default_max_tokens
        self._log = logger.bind(component="conversation_manager")

    def create_conversation(
        self,
        model_id: str,
        system_prompt: str = "",
        purpose: str = "",
        max_tokens: int = 0,
        parent_id: str = "",
    ) -> Conversation:
        """Create a new conversation."""
        self._conv_counter += 1
        max_tok = max_tokens or self._default_max_tokens

        conv = Conversation(
            conversation_id=f"conv-{self._conv_counter}",
            model_id=model_id,
            max_tokens=max_tok,
            purpose=purpose,
            parent_conversation_id=parent_id,
        )

        if system_prompt:
            msg = Message(
                role=MessageRole.SYSTEM,
                content=system_prompt,
                token_count=len(system_prompt) // 4,
            )
            conv.messages.append(msg)
            conv.total_tokens += msg.token_count

        self._conversations[conv.conversation_id] = conv
        return conv

    def add_user_message(
        self,
        conversation_id: str,
        content: str,
    ) -> Message | None:
        """Add a user message to a conversation."""
        conv = self._conversations.get(conversation_id)
        if not conv or conv.status != ConversationStatus.ACTIVE:
            return None

        msg = Message(
            role=MessageRole.USER,
            content=content,
            token_count=len(content) // 4,
        )

        # Check if we need to summarize
        if conv.total_tokens + msg.token_count > conv.max_tokens * 0.8:
            self._summarize_conversation(conv)

        conv.messages.append(msg)
        conv.total_tokens += msg.token_count
        return msg

    def add_assistant_message(
        self,
        conversation_id: str,
        content: str,
        model_id: str = "",
    ) -> Message | None:
        """Add an assistant (LLM) response to a conversation."""
        conv = self._conversations.get(conversation_id)
        if not conv:
            return None

        msg = Message(
            role=MessageRole.ASSISTANT,
            content=content,
            token_count=len(content) // 4,
            model_id=model_id or conv.model_id,
            quality_score=self.score_response_quality(content),
        )

        # Parse tool calls from response
        tool_calls = self.parse_tool_calls(content)
        if tool_calls:
            msg.tool_calls = [tc.to_dict() for tc in tool_calls]

        conv.messages.append(msg)
        conv.total_tokens += msg.token_count
        return msg

    def add_tool_result(
        self,
        conversation_id: str,
        tool_name: str,
        result: str,
    ) -> Message | None:
        """Add a tool execution result to the conversation."""
        conv = self._conversations.get(conversation_id)
        if not conv:
            return None

        content = f"Tool '{tool_name}' output:\n{result}"
        msg = Message(
            role=MessageRole.TOOL,
            content=content,
            token_count=len(content) // 4,
        )

        conv.messages.append(msg)
        conv.total_tokens += msg.token_count
        conv.tool_results.append({"tool": tool_name, "result": result[:500]})
        return msg

    def parse_tool_calls(self, response: str) -> list[ToolCall]:
        """Parse tool calls from LLM response text."""
        calls: list[ToolCall] = []

        for pattern_info in TOOL_CALL_PATTERNS:
            for match in re.finditer(pattern_info["pattern"], response, re.MULTILINE | re.DOTALL):
                try:
                    tool_name, args_raw = pattern_info["extract"](match)
                    args: dict[str, Any] = {}
                    if args_raw and args_raw.strip().startswith("{"):
                        import json
                        args = json.loads(args_raw)
                    elif args_raw:
                        args = {"command": args_raw.strip()}

                    calls.append(ToolCall(
                        tool_name=tool_name.strip(),
                        arguments=args,
                        raw_text=match.group(0)[:200],
                    ))
                except (ValueError, IndexError):
                    continue

        return calls

    def score_response_quality(self, response: str) -> float:
        """Score the quality of an LLM response (0-1)."""
        if not response or len(response) < 20:
            return 0.1

        score = 0.5
        response_lower = response.lower()

        # Positive indicators
        for indicator in QUALITY_POSITIVE:
            if indicator in response_lower:
                score += 0.05

        # Negative indicators
        for indicator in QUALITY_NEGATIVE:
            if indicator in response_lower:
                score -= 0.1

        # Length bonus (good responses tend to be detailed)
        if len(response) > 500:
            score += 0.1
        if len(response) > 2000:
            score += 0.1

        # Structure bonus (numbered lists, headers)
        if re.search(r'\d+\.\s', response):
            score += 0.05
        if re.search(r'^#+\s', response, re.MULTILINE):
            score += 0.05

        return max(0.0, min(1.0, score))

    def _summarize_conversation(self, conv: Conversation) -> None:
        """Summarize older messages to free up context."""
        if len(conv.messages) < 4:
            return

        # Keep system prompt (first) and last 3 messages
        system_msgs = [m for m in conv.messages if m.role == MessageRole.SYSTEM]
        recent = conv.messages[-3:]
        middle = conv.messages[len(system_msgs):-3]

        if not middle:
            return

        # Create summary of middle messages
        summary_parts = []
        for m in middle:
            if m.role == MessageRole.ASSISTANT:
                # Extract key findings from assistant messages
                lines = m.content.split("\n")
                key_lines = [ln for ln in lines if any(kw in ln.lower() for kw in ["finding", "severity", "vulnerability", "port", "service", "critical", "high"])]
                if key_lines:
                    summary_parts.extend(key_lines[:3])
            elif m.role == MessageRole.TOOL:
                summary_parts.append(f"[Tool output: {m.content[:100]}]")

        summary_content = "Previous conversation summary:\n" + "\n".join(summary_parts[:10])
        summary_msg = Message(
            role=MessageRole.USER,
            content=summary_content,
            token_count=len(summary_content) // 4,
        )

        conv.messages = system_msgs + [summary_msg] + recent
        conv.total_tokens = sum(m.token_count for m in conv.messages)

    def get_conversation(self, conversation_id: str) -> Conversation | None:
        """Get a conversation by ID."""
        return self._conversations.get(conversation_id)

    def build_llm_request(
        self,
        conversation_id: str,
        temperature: float = 0.7,
        max_response_tokens: int = 2048,
    ) -> dict[str, Any] | None:
        """Build a request payload for llama.cpp /v1/chat/completions."""
        conv = self._conversations.get(conversation_id)
        if not conv:
            return None

        return {
            "model": conv.model_id,
            "messages": conv.get_llm_messages(),
            "temperature": temperature,
            "max_tokens": min(max_response_tokens, conv.remaining_tokens),
            "stream": False,
        }

    def get_stats(self) -> dict[str, Any]:
        active = sum(1 for c in self._conversations.values() if c.status == ConversationStatus.ACTIVE)
        return {
            "total_conversations": len(self._conversations),
            "active": active,
            "total_messages": sum(c.message_count for c in self._conversations.values()),
            "total_tokens": sum(c.total_tokens for c in self._conversations.values()),
        }

    def build_manager_prompt(self) -> str:
        """Build LLM prompt with conversation state."""
        stats = self.get_stats()
        lines = ["## Conversation State"]
        lines.append(f"Active: {stats['active']}, Total: {stats['total_conversations']}")
        lines.append(f"Messages: {stats['total_messages']}, Tokens: {stats['total_tokens']}")
        return "\n".join(lines)
