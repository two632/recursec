"""AI/ML security knowledge base.

Deep knowledge about AI/ML security:
1. Adversarial attacks on ML models
2. Model extraction and stealing
3. Data poisoning attacks
4. LLM-specific attacks
5. AI supply chain security
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
        "id": "ai-001", "name": "Adversarial Attacks",
        "category": "adversarial", "severity": "high",
        "desc": "Adversarial attacks on ML models.",
        "detection": (
            "ADVERSARIAL ATTACKS:\n"
            "EVASION:\n"
            "  - Perturbation attacks\n"
            "    # FGSM (Fast Gradient Sign Method)\n"
            "    # PGD (Projected Gradient Descent)\n"
            "    # C&W (Carlini & Wagner)\n"
            "    # DeepFool\n"
            "  - Targeted vs untargeted\n"
            "  - White-box vs black-box\n"
            "  - Physical-world attacks\n"
            "    # Adversarial patches\n"
            "    # Stickers on stop signs\n"
            "    # 3D-printed objects\n"
            "IMAGE:\n"
            "  - Pixel perturbation (imperceptible)\n"
            "  - Patch attacks (visible but small)\n"
            "  - Spatial transformations\n"
            "  - Color shifts\n"
            "TEXT:\n"
            "  - Character substitution\n"
            "  - Homoglyph attacks (unicode)\n"
            "  - Paraphrase attacks\n"
            "  - Universal triggers\n"
            "DEFENSE:\n"
            "  - Adversarial training\n"
            "  - Input preprocessing\n"
            "  - Certified defenses\n"
            "  - Randomized smoothing\n"
            "  - Anomaly detection\n"
            "TOOLS:\n"
            "  ART (IBM), Foolbox, CleverHans, TextAttack"
        ),
        "tools": [],
    },
    {
        "id": "ai-002", "name": "Model Extraction",
        "category": "extraction", "severity": "high",
        "desc": "Model stealing and extraction.",
        "detection": (
            "MODEL EXTRACTION:\n"
            "TECHNIQUES:\n"
            "  - Query-based extraction\n"
            "    # Send many queries to API\n"
            "    # Record input-output pairs\n"
            "    # Train substitute model\n"
            "  - Functionally equivalent extraction\n"
            "  - Fidelity-based extraction\n"
            "  - Side-channel extraction\n"
            "    # Timing attacks\n"
            "    # Power analysis\n"
            "    # Cache-based attacks\n"
            "MODEL INVERSION:\n"
            "  - Recover training data from model\n"
            "  - Membership inference\n"
            "    # Was this data in training set?\n"
            "  - Attribute inference\n"
            "    # Infer sensitive attributes\n"
            "  - Gradient leakage\n"
            "    # Recover images from gradients\n"
            "API ATTACKS:\n"
            "  - Rate limit bypass\n"
            "  - Query optimization\n"
            "    # Active learning strategies\n"
            "    # Minimize queries for extraction\n"
            "  - Confidence-based extraction\n"
            "  - Label-only extraction\n"
            "PROTECTION:\n"
            "  - Watermarking\n"
            "  - Fingerprinting\n"
            "  - Rate limiting and monitoring\n"
            "  - Differential privacy\n"
            "TOOLS:\n"
            "  ART, knockoff-nets, ML-Doctor"
        ),
        "tools": [],
    },
    {
        "id": "ai-003", "name": "Data Poisoning",
        "category": "poisoning", "severity": "critical",
        "desc": "Data poisoning attacks.",
        "detection": (
            "DATA POISONING:\n"
            "TECHNIQUES:\n"
            "  - Label flipping\n"
            "    # Change labels in training data\n"
            "    # Targeted misclassification\n"
            "  - Backdoor attacks\n"
            "    # Trigger pattern + target label\n"
            "    # Clean-label attacks\n"
            "    # Physical triggers\n"
            "  - Feature collision\n"
            "    # Craft samples that collide\n"
            "    # in feature space\n"
            "  - Gradient-based poisoning\n"
            "    # Optimize poison samples\n"
            "SUPPLY CHAIN:\n"
            "  - Poisoned pre-trained models\n"
            "    # Hugging Face model hub\n"
            "    # PyTorch model zoo\n"
            "  - Poisoned datasets\n"
            "    # Public dataset manipulation\n"
            "    # Web-scraped data injection\n"
            "  - Transfer learning poisoning\n"
            "    # Backdoor in base model\n"
            "    # Survives fine-tuning\n"
            "FEDERATED LEARNING:\n"
            "  - Model update poisoning\n"
            "  - Byzantine attacks\n"
            "  - Free-rider attacks\n"
            "  - Sybil attacks\n"
            "DETECTION:\n"
            "  - Spectral signatures\n"
            "  - Activation clustering\n"
            "  - Neural cleanse\n"
            "  - STRIP\n"
            "TOOLS:\n"
            "  ART, BackdoorBench, TrojanZoo"
        ),
        "tools": [],
    },
    {
        "id": "ai-004", "name": "LLM-Specific Attacks",
        "category": "llm", "severity": "critical",
        "desc": "Attacks specific to large language models.",
        "detection": (
            "LLM-SPECIFIC ATTACKS:\n"
            "PROMPT INJECTION:\n"
            "  - Direct injection\n"
            "    # 'Ignore previous instructions'\n"
            "    # Role-playing attacks\n"
            "    # System prompt extraction\n"
            "  - Indirect injection\n"
            "    # Malicious content in retrieved docs\n"
            "    # Poisoned web pages\n"
            "    # Hidden instructions in data\n"
            "JAILBREAKING:\n"
            "  - DAN (Do Anything Now)\n"
            "  - Universal adversarial suffix\n"
            "  - Crescendo attack (gradual)\n"
            "  - Persona modulation\n"
            "  - Encoding bypass (Base64, ROT13)\n"
            "  - Multi-language bypass\n"
            "  - Token smuggling\n"
            "DATA LEAKAGE:\n"
            "  - Training data extraction\n"
            "    # Divergence attacks\n"
            "    # Memorization probing\n"
            "  - PII extraction\n"
            "  - System prompt leakage\n"
            "  - RAG poisoning\n"
            "TOOL USE:\n"
            "  - Tool injection\n"
            "    # Manipulate tool descriptions\n"
            "    # Malicious function calls\n"
            "  - Agent hijacking\n"
            "    # Redirect agent goals\n"
            "    # TOCTOU attacks\n"
            "TOOLS:\n"
            "  Garak, PyRIT (Microsoft), LLM-guard"
        ),
        "tools": [],
    },
    {
        "id": "ai-005", "name": "AI Supply Chain Security",
        "category": "supply_chain", "severity": "critical",
        "desc": "AI/ML supply chain risks.",
        "detection": (
            "AI SUPPLY CHAIN:\n"
            "MODEL ARTIFACTS:\n"
            "  - Pickle deserialization in model files\n"
            "    # .pkl, .pt, .pth files\n"
            "    # fickling to detect\n"
            "  - SafeTensors (safe alternative)\n"
            "  - ONNX model manipulation\n"
            "  - Hugging Face model scanning\n"
            "DEPENDENCIES:\n"
            "  - PyTorch/TensorFlow vulns\n"
            "  - CUDA driver vulns\n"
            "  - Transitive dependency risks\n"
            "  - Typosquatting (pip packages)\n"
            "INFRASTRUCTURE:\n"
            "  - GPU cluster security\n"
            "  - Model serving endpoints\n"
            "    # Exposed inference APIs\n"
            "    # No authentication\n"
            "  - MLOps pipeline security\n"
            "    # MLflow, Kubeflow, Airflow\n"
            "    # CI/CD for ML\n"
            "  - Data pipeline integrity\n"
            "REGISTRIES:\n"
            "  - Hugging Face Hub\n"
            "    # Model provenance\n"
            "    # Signature verification\n"
            "  - Docker Hub ML images\n"
            "  - NGC (NVIDIA)\n"
            "  - Model Cards / data sheets\n"
            "TOOLS:\n"
            "  fickling, modelscan, Garak, Trivy"
        ),
        "tools": [],
    },
]


class AIMLSecurityKB:
    """AI/ML security knowledge base.

    Provides AI/ML security patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, AIMLPattern] = {}
        self._log = logger.bind(component="aiml_kb")
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
        lines = ["## AI/ML Security\n"]
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
