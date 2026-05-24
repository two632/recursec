"""Context compression engine — reduce tokens.

Implements:
1. Text summarization heuristics
2. Redundancy removal
3. Priority-based truncation
4. Key information extraction
5. Progressive compression levels
6. Compression prompt for LLM
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class CompressionLevel(str, Enum):
    NONE = "none"           # No compression
    LIGHT = "light"         # Remove whitespace, comments
    MODERATE = "moderate"   # Summarize verbose sections
    HEAVY = "heavy"         # Keep only key facts
    EXTREME = "extreme"     # Minimal tokens


class ContentType(str, Enum):
    TOOL_OUTPUT = "tool_output"    # Raw tool output
    FINDING = "finding"            # Vulnerability finding
    CONVERSATION = "conversation"  # Chat history
    KNOWLEDGE = "knowledge"        # KB content
    CODE = "code"                  # Source code
    LOG = "log"                    # Log data


@dataclass
class CompressionResult:
    """Result of a compression operation."""
    original_tokens: int = 0
    compressed_tokens: int = 0
    compression_ratio: float = 0.0
    level: CompressionLevel = CompressionLevel.NONE
    content: str = ""
    key_facts: list[str] = field(default_factory=list)

    @property
    def savings_pct(self) -> float:
        if self.original_tokens == 0:
            return 0.0
        return (1.0 - self.compression_ratio) * 100

    def to_dict(self) -> dict[str, Any]:
        return {
            "ratio": f"{self.compression_ratio:.2f}",
            "saved": f"{self.savings_pct:.0f}%",
            "tokens": f"{self.original_tokens}→{self.compressed_tokens}",
        }


def _estimate_tokens(text: str) -> int:
    """Estimate token count (rough: ~4 chars per token)."""
    return max(1, len(text) // 4)


# Patterns to remove in light compression
NOISE_PATTERNS = [
    r'\n{3,}',           # Excessive newlines
    r'[ \t]{2,}',        # Excessive spaces
    r'#{3,}',            # Excessive comment markers
    r'={3,}',            # Separator lines
    r'-{3,}',            # Separator lines
    r'\*{3,}',           # Separator lines
]

# Low-value lines in tool output
LOW_VALUE_PREFIXES = [
    "starting ", "scanning ", "loading ",
    "connecting ", "timing ", "debug:",
    "verbose:", "info:", "[*]",
    "copyright ", "version ", "license ",
    "warning: ", "note: ",
]


class ContextCompressor:
    """Compress context to fit token budgets.

    Applies progressive compression to
    maximize information per token.
    """

    def __init__(self) -> None:
        self._total_original = 0
        self._total_compressed = 0
        self._compressions = 0
        self._log = logger.bind(component="compressor")

    def compress(
        self,
        text: str,
        target_tokens: int = 0,
        content_type: ContentType = ContentType.TOOL_OUTPUT,
        level: CompressionLevel = CompressionLevel.NONE,
    ) -> CompressionResult:
        """Compress text to target token count."""
        original_tokens = _estimate_tokens(text)

        # Auto-select level if none specified
        if level == CompressionLevel.NONE and target_tokens > 0:
            ratio = target_tokens / max(1, original_tokens)
            if ratio >= 1.0:
                level = CompressionLevel.NONE
            elif ratio >= 0.7:
                level = CompressionLevel.LIGHT
            elif ratio >= 0.4:
                level = CompressionLevel.MODERATE
            elif ratio >= 0.2:
                level = CompressionLevel.HEAVY
            else:
                level = CompressionLevel.EXTREME

        # Apply compression
        compressed = text
        key_facts: list[str] = []

        if level in (CompressionLevel.LIGHT, CompressionLevel.MODERATE, CompressionLevel.HEAVY, CompressionLevel.EXTREME):
            compressed = self._light_compress(compressed)

        if level in (CompressionLevel.MODERATE, CompressionLevel.HEAVY, CompressionLevel.EXTREME):
            compressed = self._moderate_compress(compressed, content_type)

        if level in (CompressionLevel.HEAVY, CompressionLevel.EXTREME):
            compressed, key_facts = self._heavy_compress(
                compressed, content_type,
            )

        if level == CompressionLevel.EXTREME:
            compressed = self._extreme_compress(compressed, key_facts)

        # Final truncation if still over budget
        if target_tokens > 0:
            compressed_tokens = _estimate_tokens(compressed)
            if compressed_tokens > target_tokens:
                char_limit = target_tokens * 4
                compressed = compressed[:char_limit] + "\n[truncated]"

        compressed_tokens = _estimate_tokens(compressed)
        ratio = compressed_tokens / max(1, original_tokens)

        self._total_original += original_tokens
        self._total_compressed += compressed_tokens
        self._compressions += 1

        return CompressionResult(
            original_tokens=original_tokens,
            compressed_tokens=compressed_tokens,
            compression_ratio=ratio,
            level=level,
            content=compressed,
            key_facts=key_facts,
        )

    def _light_compress(self, text: str) -> str:
        """Remove noise and whitespace."""
        result = text
        for pattern in NOISE_PATTERNS:
            if pattern == r'\n{3,}':
                result = re.sub(pattern, '\n\n', result)
            elif pattern == r'[ \t]{2,}':
                result = re.sub(pattern, ' ', result)
            else:
                result = re.sub(pattern, '', result)

        # Remove trailing whitespace on each line
        lines = result.split('\n')
        lines = [line.rstrip() for line in lines]
        return '\n'.join(lines)

    def _moderate_compress(
        self,
        text: str,
        content_type: ContentType,
    ) -> str:
        """Remove low-value content."""
        lines = text.split('\n')
        filtered: list[str] = []

        for line in lines:
            lower = line.lower().strip()

            # Skip empty lines
            if not lower:
                if filtered and filtered[-1]:
                    filtered.append("")
                continue

            # Skip low-value lines for tool output
            if content_type == ContentType.TOOL_OUTPUT:
                if any(lower.startswith(p) for p in LOW_VALUE_PREFIXES):
                    continue

            # Skip pure comment lines in code
            if content_type == ContentType.CODE:
                if lower.startswith('#') and len(lower) < 5:
                    continue

            filtered.append(line)

        return '\n'.join(filtered)

    def _heavy_compress(
        self,
        text: str,
        content_type: ContentType,
    ) -> tuple[str, list[str]]:
        """Extract key facts and compress heavily."""
        key_facts: list[str] = []
        lines = text.split('\n')

        # Extract key facts based on content type
        if content_type == ContentType.FINDING:
            for line in lines:
                lower = line.lower().strip()
                if any(kw in lower for kw in [
                    'critical', 'high', 'vulnerability', 'exploit',
                    'cve-', 'rce', 'injection', 'bypass',
                ]):
                    key_facts.append(line.strip()[:60])

        elif content_type == ContentType.TOOL_OUTPUT:
            for line in lines:
                lower = line.lower().strip()
                if any(kw in lower for kw in [
                    'open', 'found', 'detected', 'vulnerable',
                    'critical', 'high', 'medium', 'exploit',
                    'port', 'service', 'version',
                ]):
                    key_facts.append(line.strip()[:60])

        # Keep only key lines
        important: list[str] = []
        for line in lines:
            lower = line.lower().strip()
            if not lower:
                continue
            if any(kw in lower for kw in [
                'found', 'detected', 'open', 'vulnerable',
                'critical', 'high', 'medium', 'error',
                'fail', 'success', 'total', 'summary',
            ]):
                important.append(line)

        compressed = '\n'.join(important) if important else text[:500]
        return compressed, key_facts[:10]

    def _extreme_compress(
        self,
        text: str,
        key_facts: list[str],
    ) -> str:
        """Extreme compression — key facts only."""
        if key_facts:
            return "KEY FACTS:\n" + "\n".join(
                f"- {f}" for f in key_facts[:5]
            )

        # Fallback: first and last lines
        lines = [ln for ln in text.split('\n') if ln.strip()]
        if len(lines) <= 3:
            return text

        return '\n'.join(lines[:2] + ["..."] + lines[-1:])

    def build_compression_prompt(self) -> str:
        """Build compression stats for LLM."""
        lines = ["## Compression\n"]
        lines.append(f"Operations: {self._compressions}")
        if self._total_original > 0:
            overall_ratio = self._total_compressed / self._total_original
            savings = (1.0 - overall_ratio) * 100
            lines.append(f"Overall savings: {savings:.0f}%")
            lines.append(
                f"Tokens: {self._total_original}→{self._total_compressed}"
            )
        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        ratio = 0.0
        if self._total_original > 0:
            ratio = self._total_compressed / self._total_original

        return {
            "compressions": self._compressions,
            "total_original": self._total_original,
            "total_compressed": self._total_compressed,
            "overall_ratio": f"{ratio:.2f}",
        }
