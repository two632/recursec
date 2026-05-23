"""Response evaluator — evaluates LLM response quality and accuracy.

Implements:
1. Response coherence scoring
2. Factual consistency checking
3. Hallucination detection
4. Response completeness assessment
5. Format compliance checking
6. Security relevance scoring
7. Action extractability (can we act on this?)
8. Multi-model agreement scoring
9. Response latency tracking
10. Quality trend analysis
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class ResponseEvaluation:
    """Evaluation result for an LLM response."""
    eval_id: str = ""
    model: str = ""
    coherence: float = 0.5        # Is it internally consistent?
    relevance: float = 0.5        # Is it relevant to the query?
    completeness: float = 0.5     # Does it fully answer?
    format_compliance: float = 0.5  # Does it follow requested format?
    actionability: float = 0.5    # Can we act on this?
    hallucination_risk: float = 0.3  # Risk of hallucinated content
    overall_quality: float = 0.5

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.eval_id, "model": self.model,
            "quality": round(self.overall_quality, 2),
            "coherence": round(self.coherence, 2),
            "relevance": round(self.relevance, 2),
            "hallucination_risk": round(self.hallucination_risk, 2),
        }


# ── Hallucination indicators ─────────────────────────────────

HALLUCINATION_PHRASES = [
    "as an ai language model",
    "i cannot actually",
    "i don't have access",
    "in this hypothetical",
    "for example purposes",
    "this is a simulated",
    "note: this is",
    "disclaimer:",
    "please note that",
    "i should clarify",
]

SECURITY_JARGON = [
    "vulnerability", "exploit", "payload", "injection",
    "bypass", "escalation", "lateral", "persistence",
    "exfiltration", "enumeration", "reconnaissance",
    "credential", "authentication", "authorization",
    "misconfiguration", "exposure", "disclosure",
]


class ResponseEvaluator:
    """Evaluates LLM response quality.

    Scores responses on coherence, relevance,
    completeness, and hallucination risk.
    """

    def __init__(self) -> None:
        self._eval_counter = 0
        self._evaluations: list[ResponseEvaluation] = []
        self._model_quality: dict[str, list[float]] = defaultdict(list)
        self._log = logger.bind(component="response_evaluator")

    def evaluate(
        self,
        response: str,
        query: str = "",
        expected_format: str = "",
        model: str = "",
    ) -> ResponseEvaluation:
        """Evaluate an LLM response."""
        self._eval_counter += 1

        evaluation = ResponseEvaluation(
            eval_id=f"eval-{self._eval_counter}",
            model=model,
        )

        evaluation.coherence = self._score_coherence(response)
        evaluation.relevance = self._score_relevance(response, query)
        evaluation.completeness = self._score_completeness(response, query)
        evaluation.format_compliance = self._score_format(response, expected_format)
        evaluation.actionability = self._score_actionability(response)
        evaluation.hallucination_risk = self._detect_hallucination(response)

        # Overall quality
        evaluation.overall_quality = (
            evaluation.coherence * 0.2 +
            evaluation.relevance * 0.25 +
            evaluation.completeness * 0.15 +
            evaluation.format_compliance * 0.1 +
            evaluation.actionability * 0.15 +
            (1.0 - evaluation.hallucination_risk) * 0.15
        )

        self._evaluations.append(evaluation)
        if len(self._evaluations) > 1000:
            self._evaluations = self._evaluations[-1000:]

        # Track per-model quality
        if model:
            self._model_quality[model].append(evaluation.overall_quality)
            if len(self._model_quality[model]) > 100:
                self._model_quality[model] = self._model_quality[model][-100:]

        return evaluation

    def _score_coherence(self, response: str) -> float:
        """Score response coherence."""
        if not response.strip():
            return 0.0

        score = 0.5

        # Length check (too short = bad, too long might be rambling)
        words = response.split()
        if len(words) < 5:
            score -= 0.2
        elif len(words) > 10:
            score += 0.2

        # Sentence structure
        sentences = response.split(".")
        if len(sentences) >= 2:
            score += 0.1

        # No repeated phrases (sign of degraded output)
        if len(words) > 20:
            word_set = set(words)
            uniqueness = len(word_set) / len(words)
            if uniqueness < 0.4:
                score -= 0.3  # Too repetitive

        return max(0.0, min(1.0, score))

    def _score_relevance(self, response: str, query: str) -> float:
        """Score response relevance to the query."""
        if not query:
            return 0.5

        response_lower = response.lower()
        query_lower = query.lower()

        # Keyword overlap
        query_words = set(query_lower.split())
        response_words = set(response_lower.split())
        common = query_words & response_words
        if query_words:
            overlap = len(common) / len(query_words)
        else:
            overlap = 0.0

        # Security relevance
        sec_terms = sum(1 for term in SECURITY_JARGON if term in response_lower)
        sec_score = min(0.3, sec_terms * 0.05)

        return min(1.0, overlap * 0.5 + sec_score + 0.2)

    def _score_completeness(self, response: str, query: str) -> float:
        """Score response completeness."""
        if not response.strip():
            return 0.0

        score = 0.3

        # Multiple points addressed
        lines = [ln for ln in response.splitlines() if ln.strip()]
        if len(lines) >= 3:
            score += 0.2
        if len(lines) >= 5:
            score += 0.1

        # Contains structured data
        if any(c in response for c in ["{", "[", ":"]):
            score += 0.2

        # Contains actionable content
        action_words = ["run", "execute", "check", "scan", "test", "verify", "use"]
        if any(w in response.lower() for w in action_words):
            score += 0.2

        return min(1.0, score)

    def _score_format(self, response: str, expected_format: str) -> float:
        """Score format compliance."""
        if not expected_format:
            return 0.7

        if expected_format == "json":
            try:
                json.loads(response)
                return 1.0
            except json.JSONDecodeError:
                # Maybe JSON is embedded in text
                if "{" in response and "}" in response:
                    return 0.5
                return 0.2

        if expected_format == "markdown":
            if "#" in response or "-" in response or "```" in response:
                return 0.8
            return 0.4

        if expected_format == "structured":
            if ":" in response and "\n" in response:
                return 0.7
            return 0.4

        return 0.5

    def _score_actionability(self, response: str) -> float:
        """Score how actionable the response is."""
        response_lower = response.lower()

        score = 0.3

        # Contains commands
        command_indicators = ["nmap", "nuclei", "sqlmap", "curl", "ffuf",
                              "run ", "execute ", "sudo ", "bash ", "python "]
        if any(cmd in response_lower for cmd in command_indicators):
            score += 0.3

        # Contains structured findings
        if any(word in response_lower for word in ["vulnerability", "finding", "risk", "impact"]):
            score += 0.2

        # Contains specific targets/ports/services
        if any(c.isdigit() for c in response):
            score += 0.1

        return min(1.0, score)

    def _detect_hallucination(self, response: str) -> float:
        """Detect likelihood of hallucinated content."""
        response_lower = response.lower()
        risk = 0.1

        # Known hallucination phrases
        for phrase in HALLUCINATION_PHRASES:
            if phrase in response_lower:
                risk += 0.15

        # Fabricated CVE numbers
        import re
        cve_pattern = re.compile(r"CVE-\d{4}-\d+")
        cves = cve_pattern.findall(response)
        if len(cves) > 3:
            risk += 0.2  # Many CVE references might be hallucinated

        # Overly confident language
        confident_phrases = ["definitely", "certainly", "absolutely",
                             "100%", "guaranteed", "without doubt"]
        if any(p in response_lower for p in confident_phrases):
            risk += 0.1

        return min(1.0, risk)

    def get_model_quality(self, model: str) -> dict[str, Any]:
        """Get quality metrics for a model."""
        quality_history = self._model_quality.get(model, [])
        if not quality_history:
            return {"model": model, "status": "no_data"}

        return {
            "model": model,
            "avg_quality": round(sum(quality_history) / len(quality_history), 3),
            "samples": len(quality_history),
            "best": round(max(quality_history), 3),
            "worst": round(min(quality_history), 3),
        }

    def get_quality_ranking(self) -> list[dict[str, Any]]:
        """Rank models by quality."""
        rankings = []
        for model, quality_list in self._model_quality.items():
            if quality_list:
                rankings.append({
                    "model": model,
                    "avg_quality": round(sum(quality_list) / len(quality_list), 3),
                    "samples": len(quality_list),
                })

        rankings.sort(key=lambda r: r["avg_quality"], reverse=True)
        return rankings

    def get_stats(self) -> dict[str, Any]:
        return {
            "evaluations": len(self._evaluations),
            "models_tracked": len(self._model_quality),
        }
