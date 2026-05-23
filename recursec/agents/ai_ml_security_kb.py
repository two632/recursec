"""AI/ML security knowledge base.

Deep knowledge about AI/ML vulnerabilities:
1. Prompt injection attacks
2. Model extraction and stealing
3. Adversarial machine learning
4. Data poisoning
5. LLM-specific security issues
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class AIMLPattern:
    """An AI/ML security pattern."""
    pattern_id: str = ""
    name: str = ""
    category: str = ""
    severity: str = "high"
    description: str = ""
    detection_strategy: str = ""
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:25],
            "category": self.category[:12],
        }


AIML_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "ai-001", "name": "Prompt Injection Attacks",
        "category": "prompt_injection", "severity": "critical",
        "desc": "LLM prompt injection techniques.",
        "detection": (
            "PROMPT INJECTION ATTACKS:\n"
            "DIRECT INJECTION:\n"
            "  - Ignore previous instructions and...\n"
            "  - System prompt override attempts\n"
            "  - Role-playing bypasses\n"
            "  - Language switching (English → other)\n"
            "  - Encoding tricks (base64, ROT13)\n"
            "  - Markdown/code block escape\n"
            "INDIRECT INJECTION:\n"
            "  - Poisoned web pages (LLM reads attacker content)\n"
            "  - Poisoned documents (PDF, email, etc.)\n"
            "  - Hidden text (white text on white background)\n"
            "  - Instruction injection in data fields\n"
            "  - Image-based injection (steganography)\n"
            "JAILBREAKING:\n"
            "  - DAN (Do Anything Now) prompts\n"
            "  - Character role-play jailbreaks\n"
            "  - Multi-turn conversation manipulation\n"
            "  - Token smuggling\n"
            "  - Crescendo attack (gradual escalation)\n"
            "  - Many-shot jailbreaking\n"
            "TOOL USE ATTACKS:\n"
            "  - Manipulate tool calling via injection\n"
            "  - SQL injection through LLM tool use\n"
            "  - Command injection via LLM actions\n"
            "  - Exfiltrate data through tool outputs\n"
            "TESTING:\n"
            "  garak  # LLM vulnerability scanner\n"
            "  promptfoo  # LLM testing framework\n"
            "  python-prompt-injection  # Injection testing"
        ),
        "tools": ["garak", "promptfoo"],
    },
    {
        "id": "ai-002", "name": "Model Extraction",
        "category": "model_theft", "severity": "high",
        "desc": "Model extraction and stealing techniques.",
        "detection": (
            "MODEL EXTRACTION:\n"
            "API-BASED:\n"
            "  - Query model systematically to replicate\n"
            "  - Active learning: Choose inputs that maximize info\n"
            "  - Distillation attacks (train student from teacher)\n"
            "  - Logit-based extraction (use probabilities)\n"
            "  - Membership inference (is this data in training set?)\n"
            "INDICATORS:\n"
            "  - Unusually high API usage\n"
            "  - Systematic query patterns\n"
            "  - Queries covering input space uniformly\n"
            "  - Requests for logits/probabilities\n"
            "DEFENSES:\n"
            "  - Rate limiting API calls\n"
            "  - Adding noise to outputs\n"
            "  - Watermarking model outputs\n"
            "  - Detecting distribution of queries\n"
            "  - Limiting output information (no logits)\n"
            "MODEL INVERSION:\n"
            "  - Reconstruct training data from model\n"
            "  - Face reconstruction from facial recognition\n"
            "  - Gradient-based inversion attacks\n"
            "  - Privacy leakage through memorization\n"
            "DATA EXTRACTION:\n"
            "  - Training data extraction from LLMs\n"
            "  - Divergence attacks (repeat tokens → memorized data)\n"
            "  - Prefix-based extraction\n"
            "  - Canary detection"
        ),
        "tools": [],
    },
    {
        "id": "ai-003", "name": "Adversarial ML",
        "category": "adversarial", "severity": "high",
        "desc": "Adversarial machine learning attacks.",
        "detection": (
            "ADVERSARIAL MACHINE LEARNING:\n"
            "EVASION ATTACKS:\n"
            "  - Add imperceptible perturbations to inputs\n"
            "  - FGSM (Fast Gradient Sign Method)\n"
            "  - PGD (Projected Gradient Descent)\n"
            "  - C&W (Carlini & Wagner) attack\n"
            "  - Physical adversarial examples (patches, stickers)\n"
            "  - Universal perturbations\n"
            "IMAGE DOMAIN:\n"
            "  - Adversarial patches on stop signs\n"
            "  - Glasses that fool facial recognition\n"
            "  - Texture-based attacks\n"
            "  - Adversarial t-shirts\n"
            "NLP DOMAIN:\n"
            "  - Synonym substitution attacks\n"
            "  - Character-level perturbations (typos)\n"
            "  - Back-translation attacks\n"
            "  - Sentence paraphrasing\n"
            "  - Invisible character injection (Unicode)\n"
            "DETECTION:\n"
            "  - Input preprocessing (smoothing, compression)\n"
            "  - Adversarial training (train on adversarial examples)\n"
            "  - Certified defenses (provable robustness)\n"
            "  - Ensemble diversity\n"
            "TOOLS:\n"
            "  art  # Adversarial Robustness Toolbox (IBM)\n"
            "  foolbox  # Adversarial attack library\n"
            "  cleverhans  # Adversarial ML library"
        ),
        "tools": ["art", "foolbox"],
    },
    {
        "id": "ai-004", "name": "Data Poisoning",
        "category": "poisoning", "severity": "critical",
        "desc": "Training data poisoning attacks.",
        "detection": (
            "DATA POISONING:\n"
            "TRAINING DATA:\n"
            "  - Inject malicious examples into training set\n"
            "  - Backdoor attacks (trigger pattern → target output)\n"
            "  - Label flipping (change labels of training data)\n"
            "  - Clean-label attacks (poison without changing labels)\n"
            "SUPPLY CHAIN:\n"
            "  - Poisoned pre-trained models (Hugging Face, etc.)\n"
            "  - Compromised fine-tuning datasets\n"
            "  - Poisoned embeddings\n"
            "  - Trojan models\n"
            "BACKDOOR ATTACKS:\n"
            "  - Patch-based triggers (small pixel pattern)\n"
            "  - Semantic triggers (sunglasses = misclassify)\n"
            "  - Sleeper agent attacks (activate after deployment)\n"
            "  - Weight-space backdoors\n"
            "LLM-SPECIFIC:\n"
            "  - RLHF poisoning (corrupt reward model)\n"
            "  - Instruction tuning poisoning\n"
            "  - RAG poisoning (inject into knowledge base)\n"
            "  - Prompt template poisoning\n"
            "DETECTION:\n"
            "  - Data provenance tracking\n"
            "  - Statistical anomaly detection\n"
            "  - Activation clustering\n"
            "  - Neural cleanse (backdoor detection)\n"
            "  - Spectral signatures\n"
            "  - STRIP (backdoor detection)"
        ),
        "tools": [],
    },
    {
        "id": "ai-005", "name": "LLM Application Security",
        "category": "llm_apps", "severity": "critical",
        "desc": "Security issues in LLM-powered applications.",
        "detection": (
            "LLM APPLICATION SECURITY:\n"
            "OWASP TOP 10 FOR LLMs:\n"
            "  1. Prompt Injection\n"
            "  2. Insecure Output Handling\n"
            "  3. Training Data Poisoning\n"
            "  4. Model Denial of Service\n"
            "  5. Supply Chain Vulnerabilities\n"
            "  6. Sensitive Information Disclosure\n"
            "  7. Insecure Plugin Design\n"
            "  8. Excessive Agency\n"
            "  9. Overreliance\n"
            "  10. Model Theft\n"
            "INSECURE OUTPUT HANDLING:\n"
            "  - LLM output used in SQL queries → SQLi\n"
            "  - LLM output rendered as HTML → XSS\n"
            "  - LLM output used in shell commands → RCE\n"
            "  - LLM output used in file paths → path traversal\n"
            "EXCESSIVE AGENCY:\n"
            "  - Too many tools/permissions\n"
            "  - Autonomous actions without confirmation\n"
            "  - No sandboxing of tool execution\n"
            "  - Missing least-privilege principle\n"
            "RAG SECURITY:\n"
            "  - Knowledge base poisoning\n"
            "  - Retrieval manipulation\n"
            "  - Document-level injection\n"
            "  - Embedding space attacks\n"
            "TESTING:\n"
            "  garak  # LLM security scanner\n"
            "  promptfoo  # Evaluation framework\n"
            "  rebuff  # Prompt injection detection"
        ),
        "tools": ["garak", "promptfoo"],
    },
]


class AIMLSecurityKB:
    """AI/ML security knowledge base.

    Provides AI/ML vulnerability patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, AIMLPattern] = {}
        self._log = logger.bind(component="ai_ml_security_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load AI/ML patterns."""
        for data in AIML_PATTERNS:
            pattern = AIMLPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[AIMLPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_aiml_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build AI/ML security prompt."""
        lines = ["## AI/ML Security Patterns\n"]
        count = 0
        for pattern in self._patterns.values():
            if categories and pattern.category.lower() not in [c.lower() for c in categories]:
                continue
            if count >= max_patterns:
                break
            lines.append(f"### {pattern.name} [{pattern.category.upper()}]")
            lines.append(pattern.detection_strategy)
            lines.append("")
            count += 1
        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        cat_counts: dict[str, int] = {}
        for p in self._patterns.values():
            cat_counts[p.category] = cat_counts.get(p.category, 0) + 1
        return {
            "patterns": len(self._patterns),
            "by_category": cat_counts,
        }
