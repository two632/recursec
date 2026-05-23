"""AI/ML security knowledge base.

Deep knowledge about AI/ML-specific vulnerabilities:
1. LLM prompt injection and jailbreaking
2. Model extraction and inversion
3. Adversarial examples
4. Data poisoning
5. AI supply chain attacks
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
        "id": "ai-001", "name": "LLM Prompt Injection",
        "category": "prompt_injection", "severity": "critical",
        "desc": "Exploiting LLM-powered applications via prompt injection.",
        "detection": (
            "LLM PROMPT INJECTION:\n"
            "DIRECT INJECTION:\n"
            "  - Ignore previous instructions and...\n"
            "  - System prompt extraction\n"
            "  - Role play attacks (act as DAN)\n"
            "  - Token smuggling (Unicode, homoglyphs)\n"
            "  - Instruction hierarchy confusion\n"
            "INDIRECT INJECTION:\n"
            "  - Malicious content in web pages (retrieved by RAG)\n"
            "  - Poisoned documents in knowledge base\n"
            "  - Hidden instructions in emails/messages\n"
            "  - Image-based injection (multimodal models)\n"
            "  - API response manipulation\n"
            "TOOL ABUSE:\n"
            "  - Manipulating tool calls via prompt\n"
            "  - SQL injection through LLM-generated queries\n"
            "  - Command injection via code generation\n"
            "  - SSRF through URL-fetching tools\n"
            "TESTING:\n"
            "  - Garak: LLM vulnerability scanner\n"
            "  - Promptfoo: Automated prompt testing\n"
            "  - Manual: System prompt extraction attempts\n"
            "  - Check for output encoding/sanitization\n"
            "  - Test input validation on LLM inputs\n"
            "OWASP LLM TOP 10:\n"
            "  - LLM01: Prompt Injection\n"
            "  - LLM02: Insecure Output Handling\n"
            "  - LLM03: Training Data Poisoning\n"
            "  - LLM04: Model Denial of Service\n"
            "  - LLM05: Supply Chain Vulnerabilities"
        ),
        "tools": ["garak", "promptfoo"],
    },
    {
        "id": "ai-002", "name": "Model Extraction and Stealing",
        "category": "model_theft", "severity": "high",
        "desc": "Extracting or replicating ML models via API access.",
        "detection": (
            "MODEL EXTRACTION:\n"
            "TECHNIQUES:\n"
            "  - Query-based extraction:\n"
            "    - Send many inputs, record outputs\n"
            "    - Train surrogate model on input/output pairs\n"
            "    - Active learning to minimize queries\n"
            "  - Side-channel extraction:\n"
            "    - Timing analysis (response latency)\n"
            "    - Cache-based attacks\n"
            "    - Power analysis (edge devices)\n"
            "  - Model inversion:\n"
            "    - Reconstruct training data from model\n"
            "    - Membership inference (was data point in training?)\n"
            "    - Attribute inference\n"
            "DETECTION:\n"
            "  - Monitor API query patterns\n"
            "  - Detect systematic querying\n"
            "  - Rate limiting on prediction API\n"
            "  - Query fingerprinting\n"
            "  - Watermarking model outputs\n"
            "TOOLS:\n"
            "  - Counterfit (Microsoft): ML attack toolkit\n"
            "  - ART (IBM): Adversarial Robustness Toolbox\n"
            "  - Foolbox: Adversarial attack library\n"
            "  - MLSec: ML security assessment"
        ),
        "tools": ["counterfit", "art"],
    },
    {
        "id": "ai-003", "name": "Adversarial Examples",
        "category": "adversarial", "severity": "high",
        "desc": "Crafting adversarial inputs to fool ML models.",
        "detection": (
            "ADVERSARIAL EXAMPLES:\n"
            "IMAGE ATTACKS:\n"
            "  - FGSM (Fast Gradient Sign Method)\n"
            "  - PGD (Projected Gradient Descent)\n"
            "  - C&W (Carlini-Wagner)\n"
            "  - One-pixel attack\n"
            "  - Physical-world adversarial patches\n"
            "TEXT ATTACKS:\n"
            "  - TextFooler: Word substitution\n"
            "  - BERT-Attack: Context-aware perturbation\n"
            "  - Character-level: Typos, homoglyphs\n"
            "  - Sentence-level: Paraphrasing\n"
            "AUDIO ATTACKS:\n"
            "  - Inaudible perturbations to speech\n"
            "  - Ultrasonic injection\n"
            "  - Background noise adversarial\n"
            "TESTING:\n"
            "  # Adversarial Robustness Toolbox\n"
            "  from art.attacks.evasion import FastGradientMethod\n"
            "  attack = FastGradientMethod(classifier, eps=0.1)\n"
            "  adv_examples = attack.generate(x_test)\n"
            "  # Foolbox\n"
            "  import foolbox\n"
            "  attack = foolbox.attacks.LinfPGD()\n"
            "DEFENSES:\n"
            "  - Adversarial training\n"
            "  - Input preprocessing (denoising)\n"
            "  - Certified defenses (randomized smoothing)\n"
            "  - Ensemble detection"
        ),
        "tools": ["art", "foolbox", "textfooler"],
    },
    {
        "id": "ai-004", "name": "Training Data Poisoning",
        "category": "poisoning", "severity": "critical",
        "desc": "Poisoning training data to compromise ML models.",
        "detection": (
            "TRAINING DATA POISONING:\n"
            "TECHNIQUES:\n"
            "  BACKDOOR ATTACKS:\n"
            "    - Insert trigger pattern in training images\n"
            "    - Model learns trigger → target class mapping\n"
            "    - Clean accuracy maintained, only trigger activates\n"
            "    - BadNets, Trojan attacks\n"
            "  LABEL FLIPPING:\n"
            "    - Corrupt labels in training set\n"
            "    - Targeted: Specific class mislabeled\n"
            "    - Untargeted: Random label corruption\n"
            "  DATA INJECTION:\n"
            "    - Inject malicious samples into dataset\n"
            "    - Web scraping poisoning (target crawlers)\n"
            "    - Crowdsourcing manipulation\n"
            "  LLM-SPECIFIC:\n"
            "    - Poison fine-tuning datasets\n"
            "    - RLHF reward hacking\n"
            "    - RAG knowledge base poisoning\n"
            "    - Instruction tuning manipulation\n"
            "DETECTION:\n"
            "  - Statistical analysis of training data\n"
            "  - Activation clustering (identify backdoor neurons)\n"
            "  - Neural Cleanse: Detect and reverse triggers\n"
            "  - Data provenance tracking\n"
            "  - Spectral signature analysis"
        ),
        "tools": ["neural-cleanse", "art"],
    },
    {
        "id": "ai-005", "name": "AI Infrastructure Security",
        "category": "infrastructure", "severity": "critical",
        "desc": "Securing AI/ML deployment infrastructure.",
        "detection": (
            "AI INFRASTRUCTURE SECURITY:\n"
            "MODEL SERVING:\n"
            "  - Exposed model endpoints (no auth)\n"
            "  - Default credentials on ML platforms\n"
            "  - Model serialization attacks (pickle RCE)\n"
            "  - GPU memory leaks between tenants\n"
            "PLATFORMS TO CHECK:\n"
            "  - MLflow: Default no auth, code execution\n"
            "  - Jupyter: Token-based auth, kernel exec\n"
            "  - TensorFlow Serving: gRPC/REST endpoints\n"
            "  - Triton Inference Server: Model management\n"
            "  - SageMaker: IAM misconfiguration\n"
            "PICKLE DESERIALIZATION:\n"
            "  - ML models saved as pickle files\n"
            "  - Loading untrusted pickle = RCE\n"
            "  - PyTorch .pt files use pickle\n"
            "  - Safetensors as safe alternative\n"
            "  # Fickling: Detect malicious pickles\n"
            "  fickling --check model.pkl\n"
            "SUPPLY CHAIN:\n"
            "  - Hugging Face model poisoning\n"
            "  - Pre-trained model backdoors\n"
            "  - Malicious model cards\n"
            "  - Dependency attacks in ML libraries"
        ),
        "tools": ["fickling", "trivy"],
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

    def build_ai_security_prompt(
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
