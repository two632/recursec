"""AI/ML security knowledge base.

Deep knowledge about AI/ML security:
1. Adversarial attacks on models
2. Model extraction and stealing
3. Data poisoning
4. LLM-specific attacks
5. ML pipeline security
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
        "id": "ai-001", "name": "Adversarial Attacks on Models",
        "category": "adversarial", "severity": "high",
        "desc": "Adversarial attacks against ML models.",
        "detection": (
            "ADVERSARIAL ATTACKS:\n"
            "EVASION:\n"
            "  - Adversarial examples (perturbed inputs)\n"
            "  - FGSM (Fast Gradient Sign Method)\n"
            "  - PGD (Projected Gradient Descent)\n"
            "  - C&W (Carlini & Wagner L2)\n"
            "  - DeepFool\n"
            "  - AutoAttack (ensemble)\n"
            "  - Physical-world attacks (stop signs, patches)\n"
            "TRANSFERABILITY:\n"
            "  - Black-box attacks via surrogate model\n"
            "  - Cross-model transfer\n"
            "  - Ensemble-based generation\n"
            "  - Query-based attacks (limited API)\n"
            "BACKDOOR:\n"
            "  - Trojan trigger patterns\n"
            "  - Clean-label attacks\n"
            "  - Neural cleanse detection\n"
            "  - Activation clustering detection\n"
            "DEFENSES:\n"
            "  - Adversarial training\n"
            "  - Input preprocessing\n"
            "  - Certified defenses (randomized smoothing)\n"
            "  - Ensemble methods\n"
            "  - Feature squeezing\n"
            "TOOLS:\n"
            "  ART (Adversarial Robustness Toolbox),\n"
            "  CleverHans, Foolbox, SecML"
        ),
        "tools": [],
    },
    {
        "id": "ai-002", "name": "Model Extraction",
        "category": "extraction", "severity": "high",
        "desc": "Model extraction and stealing.",
        "detection": (
            "MODEL EXTRACTION:\n"
            "TECHNIQUES:\n"
            "  - Query-based extraction\n"
            "    # Send queries, collect responses\n"
            "    # Train surrogate model\n"
            "    # Minimize query budget\n"
            "  - Learning-based extraction\n"
            "    # Knowledge distillation approach\n"
            "    # Active learning for efficiency\n"
            "  - Side-channel extraction\n"
            "    # Timing attacks (model complexity)\n"
            "    # Memory access patterns\n"
            "    # Cache attacks on GPU\n"
            "  - Model inversion\n"
            "    # Reconstruct training data\n"
            "    # Face reconstruction from API\n"
            "    # Membership inference\n"
            "DETECTION:\n"
            "  - Query pattern analysis\n"
            "  - Rate limiting\n"
            "  - Watermarking (model fingerprinting)\n"
            "  - Output perturbation\n"
            "  - Differential privacy\n"
            "  - Canary inputs\n"
            "MEMBERSHIP INFERENCE:\n"
            "  - Determine if data was in training set\n"
            "  - Confidence-based attacks\n"
            "  - Shadow model attacks\n"
            "  - Privacy implications (GDPR)\n"
            "TOOLS:\n"
            "  ML Privacy Meter, ART, Counterfit (Azure)"
        ),
        "tools": [],
    },
    {
        "id": "ai-003", "name": "Data Poisoning",
        "category": "poisoning", "severity": "critical",
        "desc": "Training data poisoning attacks.",
        "detection": (
            "DATA POISONING:\n"
            "LABEL FLIPPING:\n"
            "  - Change labels in training data\n"
            "  - Targeted misclassification\n"
            "  - Random noise (degrade accuracy)\n"
            "BACKDOOR POISONING:\n"
            "  - Insert trigger pattern + target label\n"
            "  - Clean-label attacks (no label change)\n"
            "  - Semantic triggers (natural features)\n"
            "  - Example: pixel patch → misclassify\n"
            "GRADIENT ATTACKS:\n"
            "  - Gradient-based poison generation\n"
            "  - Witches' Brew\n"
            "  - MetaPoison\n"
            "  - Influence functions\n"
            "SUPPLY CHAIN:\n"
            "  - Pre-trained model poisoning\n"
            "  - Transfer learning vulnerabilities\n"
            "  - Hugging Face model repo attacks\n"
            "  - Dataset repository poisoning\n"
            "  - Federated learning poisoning\n"
            "DETECTION:\n"
            "  - Statistical anomaly in data\n"
            "  - Activation clustering\n"
            "  - Spectral signatures\n"
            "  - Neural cleanse (backdoor detection)\n"
            "  - Data provenance tracking\n"
            "  - RONI (Reject On Negative Impact)\n"
            "TOOLS:\n"
            "  ART, SecML, TrojAI, Neural Cleanse"
        ),
        "tools": [],
    },
    {
        "id": "ai-004", "name": "LLM-Specific Attacks",
        "category": "llm", "severity": "critical",
        "desc": "LLM-specific attack techniques.",
        "detection": (
            "LLM-SPECIFIC ATTACKS:\n"
            "PROMPT INJECTION:\n"
            "  - Direct injection (user input → system)\n"
            "  - Indirect injection (data → prompt)\n"
            "  - Jailbreaking (bypass safety)\n"
            "  - DAN (Do Anything Now) patterns\n"
            "  - Role-play exploitation\n"
            "  - Encoding-based bypass\n"
            "    # Base64, ROT13, Unicode\n"
            "DATA EXFILTRATION:\n"
            "  - Training data extraction\n"
            "  - System prompt extraction\n"
            "  - RAG data extraction\n"
            "  - Tool/API key extraction\n"
            "  - Context window content leak\n"
            "TOOL ABUSE:\n"
            "  - Function calling manipulation\n"
            "  - Code execution escape\n"
            "  - File system access via tools\n"
            "  - Network access via tools\n"
            "  - Privilege escalation via agent\n"
            "HALLUCINATION:\n"
            "  - Fabricated vulnerabilities\n"
            "  - Non-existent CVEs\n"
            "  - Incorrect remediation advice\n"
            "  - Confidence without evidence\n"
            "  Detection: cross-validation, grounding\n"
            "RAG POISONING:\n"
            "  - Inject malicious documents\n"
            "  - Override system instructions\n"
            "  - Bias retrieval results\n"
            "  - Hidden instruction in documents\n"
            "TOOLS:\n"
            "  Garak, PyRIT (Microsoft), Rebuff"
        ),
        "tools": [],
    },
    {
        "id": "ai-005", "name": "ML Pipeline Security",
        "category": "pipeline", "severity": "high",
        "desc": "ML pipeline and infrastructure security.",
        "detection": (
            "ML PIPELINE SECURITY:\n"
            "MODEL SERVING:\n"
            "  - Exposed inference endpoints\n"
            "  - Missing authentication on API\n"
            "  - Model version confusion\n"
            "  - Denial of service (large inputs)\n"
            "  - Model file deserialization (pickle)\n"
            "TRAINING:\n"
            "  - Jupyter notebook exposure\n"
            "  - GPU cluster access\n"
            "  - Training data access control\n"
            "  - Experiment tracking (MLflow, W&B)\n"
            "  - Secret leakage in notebooks\n"
            "SERIALIZATION:\n"
            "  - Pickle RCE (Python)\n"
            "    # pickle.loads(malicious_data)\n"
            "  - PyTorch save/load (uses pickle)\n"
            "  - TensorFlow SavedModel\n"
            "  - ONNX model loading\n"
            "  - Safetensors (safe alternative)\n"
            "SUPPLY CHAIN:\n"
            "  - Hugging Face model hub\n"
            "  - Model zoo poisoning\n"
            "  - Pre-trained weight tampering\n"
            "  - Dependency confusion (ML libs)\n"
            "  - Docker image for ML workloads\n"
            "MONITORING:\n"
            "  - Model drift detection\n"
            "  - Input validation\n"
            "  - Output monitoring\n"
            "  - Audit logging\n"
            "  - Anomaly detection on queries\n"
            "TOOLS:\n"
            "  Fickling, ModelScan, NB Defense, Garak"
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
