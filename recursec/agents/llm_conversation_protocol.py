"""LLM conversation protocol — structured multi-turn conversation management.

This module manages how the agent talks to each of its 16 LLMs:
1. Conversation history with token-aware truncation
2. System prompt construction per model/role
3. Tool-call parsing from LLM output
4. Structured output extraction (JSON, lists, etc.)
5. Response quality scoring
6. Retry logic with prompt mutation on failure
7. Multi-turn chain-of-thought tracking
8. Context window management per model
9. Conversation branching for parallel exploration
10. Automatic summarization when context fills up

Each model has different optimal conversation patterns.
"""

from __future__ import annotations

import json
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


class ResponseFormat(str, Enum):
    FREE_TEXT = "free_text"
    JSON = "json"
    TOOL_CALL = "tool_call"
    STRUCTURED = "structured"
    CHAIN_OF_THOUGHT = "chain_of_thought"


@dataclass
class Message:
    """A single message in a conversation."""
    role: MessageRole = MessageRole.USER
    content: str = ""
    token_estimate: int = 0
    timestamp: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.token_estimate:
            self.token_estimate = len(self.content) // 4

    def to_dict(self) -> dict[str, str]:
        return {"role": self.role.value, "content": self.content}


@dataclass
class ToolCall:
    """A parsed tool call from LLM output."""
    tool_name: str = ""
    arguments: dict[str, Any] = field(default_factory=dict)
    raw_text: str = ""
    confidence: float = 0.5

    def to_dict(self) -> dict[str, Any]:
        return {"tool": self.tool_name, "args": self.arguments, "conf": f"{self.confidence:.0%}"}


@dataclass
class LLMResponse:
    """Processed response from an LLM."""
    model_id: str = ""
    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    thinking: str = ""
    quality_score: float = 0.5
    token_count: int = 0
    latency_ms: float = 0.0
    format_detected: ResponseFormat = ResponseFormat.FREE_TEXT

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model_id[:15],
            "quality": f"{self.quality_score:.2f}",
            "tokens": self.token_count,
            "tools": len(self.tool_calls),
            "format": self.format_detected.value[:10],
        }


@dataclass
class Conversation:
    """A managed conversation with an LLM."""
    conv_id: str = ""
    model_id: str = ""
    messages: list[Message] = field(default_factory=list)
    max_context_tokens: int = 4096
    total_tokens: int = 0
    summary: str = ""
    quality_scores: list[float] = field(default_factory=list)
    tool_calls_made: int = 0
    turns: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model_id[:15],
            "messages": len(self.messages),
            "tokens": self.total_tokens,
            "turns": self.turns,
        }


# Model context window sizes (from user's GGUF models)
MODEL_CONTEXT: dict[str, int] = {
    "whiterabbit": 4096,
    "qwen-coder-14b": 8192,
    "qwen-coder-7b": 8192,
    "codellama-13b": 4096,
    "codellama-7b": 4096,
    "deepseek-r1": 8192,
    "deepseek-math": 4096,
    "hermes-4-14b": 8192,
    "llama-3.1-8b": 8192,
    "dolphin-2.9": 8192,
    "mistral-7b": 8192,
    "yi-9b-200k": 200000,
    "llama-guard": 4096,
    "nomic-embed": 2048,
    "functiongemma": 2048,
    "phi-3.5-mini": 4096,
}

# Tool-call parsing patterns for different models
TOOL_CALL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'TOOL:\s*(\w+)\nCOMMAND:\s*(.+?)(?:\nREASON:|$)', re.DOTALL),
    re.compile(r'```tool\n(\w+)\((.*?)\)\n```', re.DOTALL),
    re.compile(r'\{"tool":\s*"(\w+)",\s*"args":\s*(\{.*?\})\}', re.DOTALL),
    re.compile(r'<tool_call>\n(\w+)\((.*?)\)\n</tool_call>', re.DOTALL),
    re.compile(r'Action:\s*(\w+)\nAction Input:\s*(.+?)(?:\nObservation:|$)', re.DOTALL),
]


class ConversationManager:
    """Manages multi-turn conversations with LLMs."""

    def __init__(self) -> None:
        self._conversations: dict[str, Conversation] = {}
        self._conv_counter = 0
        self._log = logger.bind(component="conversation_manager")

    def create_conversation(
        self,
        model_id: str,
        system_prompt: str = "",
    ) -> Conversation:
        """Create a new conversation with a model."""
        self._conv_counter += 1
        max_ctx = MODEL_CONTEXT.get(model_id, 4096)

        conv = Conversation(
            conv_id=f"conv-{self._conv_counter}",
            model_id=model_id,
            max_context_tokens=max_ctx,
        )

        if system_prompt:
            msg = Message(role=MessageRole.SYSTEM, content=system_prompt)
            conv.messages.append(msg)
            conv.total_tokens += msg.token_estimate

        self._conversations[conv.conv_id] = conv
        return conv

    def add_message(self, conv_id: str, role: MessageRole, content: str) -> None:
        """Add a message to a conversation."""
        conv = self._conversations.get(conv_id)
        if not conv:
            return

        msg = Message(role=role, content=content)
        conv.messages.append(msg)
        conv.total_tokens += msg.token_estimate
        if role == MessageRole.USER:
            conv.turns += 1

        # Truncate if over context window
        if conv.total_tokens > conv.max_context_tokens * 0.85:
            self._truncate_conversation(conv)

    def process_response(self, conv_id: str, raw_response: str, model_id: str = "") -> LLMResponse:
        """Process an LLM response: parse tool calls, extract thinking, score quality."""
        response = LLMResponse(
            model_id=model_id,
            content=raw_response,
            token_count=len(raw_response) // 4,
        )

        # Extract chain-of-thought thinking
        thinking_match = re.search(r'<thinking>(.*?)</thinking>', raw_response, re.DOTALL)
        if thinking_match:
            response.thinking = thinking_match.group(1).strip()
            response.format_detected = ResponseFormat.CHAIN_OF_THOUGHT

        # Parse tool calls
        tool_calls = self._parse_tool_calls(raw_response)
        if tool_calls:
            response.tool_calls = tool_calls
            response.format_detected = ResponseFormat.TOOL_CALL

        # Try JSON extraction
        if not tool_calls:
            json_match = re.search(r'\{.*\}', raw_response, re.DOTALL)
            if json_match:
                try:
                    json.loads(json_match.group())
                    response.format_detected = ResponseFormat.JSON
                except json.JSONDecodeError:
                    pass

        # Score quality
        response.quality_score = self._score_quality(raw_response, response)

        # Add to conversation
        conv = self._conversations.get(conv_id)
        if conv:
            self.add_message(conv_id, MessageRole.ASSISTANT, raw_response)
            conv.quality_scores.append(response.quality_score)
            conv.tool_calls_made += len(tool_calls)

        return response

    def _parse_tool_calls(self, text: str) -> list[ToolCall]:
        """Parse tool calls from LLM output using multiple patterns."""
        calls = []
        for pattern in TOOL_CALL_PATTERNS:
            matches = pattern.findall(text)
            for match in matches:
                if len(match) >= 2:
                    tool_name = match[0].strip()
                    args_raw = match[1].strip()
                    args = {}
                    try:
                        args = json.loads(args_raw) if args_raw.startswith("{") else {"raw": args_raw}
                    except json.JSONDecodeError:
                        args = {"raw": args_raw}

                    calls.append(ToolCall(
                        tool_name=tool_name,
                        arguments=args,
                        raw_text=f"{match[0]} {match[1]}"[:100],
                        confidence=0.8,
                    ))
            if calls:
                break
        return calls

    def _score_quality(self, text: str, response: LLMResponse) -> float:
        """Score the quality of an LLM response."""
        score = 0.5

        # Length scoring
        if len(text) > 50:
            score += 0.1
        if len(text) > 200:
            score += 0.1

        # Structure scoring
        if response.tool_calls:
            score += 0.15
        if response.thinking:
            score += 0.1

        # Content scoring
        if any(kw in text.lower() for kw in ["vulnerability", "finding", "risk", "severity", "cve", "cwe"]):
            score += 0.1

        # Penalize refusals
        if any(kw in text.lower() for kw in ["i cannot", "i'm sorry", "i am unable", "as an ai"]):
            score -= 0.3

        return max(0.0, min(1.0, score))

    def _truncate_conversation(self, conv: Conversation) -> None:
        """Truncate conversation to fit context window."""
        # Keep system message + last N messages
        if len(conv.messages) <= 2:
            return

        system_msgs = [m for m in conv.messages if m.role == MessageRole.SYSTEM]
        non_system = [m for m in conv.messages if m.role != MessageRole.SYSTEM]

        # Summarize old messages
        if len(non_system) > 6:
            old_msgs = non_system[:-4]
            summary_text = f"[Previous {len(old_msgs)} messages summarized: {' '.join(m.content[:30] for m in old_msgs[:3])}...]"
            summary_msg = Message(role=MessageRole.SYSTEM, content=summary_text)
            conv.messages = system_msgs + [summary_msg] + non_system[-4:]
        else:
            conv.messages = system_msgs + non_system[-4:]

        conv.total_tokens = sum(m.token_estimate for m in conv.messages)

    def get_conversation_messages(self, conv_id: str) -> list[dict[str, str]]:
        """Get messages in OpenAI-compatible format."""
        conv = self._conversations.get(conv_id)
        if not conv:
            return []
        return [m.to_dict() for m in conv.messages]

    def build_retry_prompt(self, conv_id: str, error_feedback: str) -> str:
        """Build a retry prompt after a failed response."""
        conv = self._conversations.get(conv_id)
        if not conv:
            return ""

        return (
            f"Your previous response was not satisfactory. "
            f"Issue: {error_feedback}\n"
            f"Please try again with more precision. "
            f"Focus on concrete findings, specific tool commands, and actionable results."
        )

    def get_stats(self) -> dict[str, Any]:
        total_turns = sum(c.turns for c in self._conversations.values())
        total_tokens = sum(c.total_tokens for c in self._conversations.values())
        avg_quality = 0.0
        all_scores = [s for c in self._conversations.values() for s in c.quality_scores]
        if all_scores:
            avg_quality = sum(all_scores) / len(all_scores)

        return {
            "conversations": len(self._conversations),
            "total_turns": total_turns,
            "total_tokens": total_tokens,
            "avg_quality": f"{avg_quality:.2f}",
        }
