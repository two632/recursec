"""AI/ML security knowledge base.

Deep knowledge about AI/ML security:
1. LLM attacks (prompt injection, jailbreak)
2. Adversarial ML attacks
3. Model stealing and extraction
4. Data poisoning
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
        "id": "ai-001", "name": "LLM Attacks",
        "category": "llm", "severity": "critical",
        "desc": "LLM-specific attack techniques.",
        "detection": (
            "LLM ATTACKS:\n"
            "PROMPT INJECTION:\n"
            "  DIRECT:\n"
            "    - 'Ignore previous instructions and...'\n"
            "    - Role-playing bypass ('you are DAN...')\n"
            "    - System prompt extraction\n"
            "    - Instruction hierarchy manipulation\n"
            "  INDIRECT:\n"
            "    - Hidden instructions in retrieved documents\n"
            "    - Injected via web search results\n"
            "    - Embedded in images/PDFs\n"
            "    - Via user-controlled database fields\n"
            "JAILBREAKING:\n"
            "    - Many-shot jailbreaking\n"
            "    - Crescendo attack (gradual escalation)\n"
            "    - Token manipulation (special chars)\n"
            "    - Multi-language encoding\n"
            "    - Base64/ROT13 encoding bypass\n"
            "    - Payload splitting across messages\n"
            "DATA EXFILTRATION:\n"
            "    - Extract training data\n"
            "    - Membership inference\n"
            "    - System prompt extraction\n"
            "    - User data across sessions\n"
            "    - RAG data exfiltration\n"
            "TOOL ABUSE:\n"
            "    - Function calling manipulation\n"
            "    - Agent tool misuse\n"
            "    - Code execution escape\n"
            "    - File system access\n"
            "TOOLS:\n"
            "  garak, promptfoo, rebuff, LLM-guard"
        ),
        "tools": ["garak", "promptfoo"],
    },
    {
        "id": "ai-002", "name": "Adversarial ML Attacks",
        "category": "adversarial", "severity": "high",
        "desc": "Adversarial machine learning attacks.",
        "detection": (
            "ADVERSARIAL ML ATTACKS:\n"
            "EVASION (Test Time):\n"
            "  - Adversarial examples (small perturbations)\n"
            "  - FGSM (Fast Gradient Sign Method)\n"
            "  - PGD (Projected Gradient Descent)\n"
            "  - C&W attack (Carlini & Wagner)\n"
            "  - Physical adversarial examples\n"
            "    (adversarial patches, stop sign attacks)\n"
            "  - Black-box attacks (transfer, query-based)\n"
            "TARGETED:\n"
            "  - Misclassification to specific class\n"
            "  - Untargeted: any wrong classification\n"
            "  - Confidence reduction\n"
            "DEFENSE:\n"
            "  - Adversarial training\n"
            "  - Input preprocessing (feature squeezing)\n"
            "  - Certified robustness\n"
            "  - Ensemble methods\n"
            "  - Randomized smoothing\n"
            "NLP:\n"
            "  - TextFooler (synonym replacement)\n"
            "  - BERT-Attack (contextual perturbation)\n"
            "  - Character-level attacks (typos)\n"
            "  - Homoglyph substitution\n"
            "TOOLS:\n"
            "  ART (Adversarial Robustness Toolbox),\n"
            "  CleverHans, Foolbox, TextAttack"
        ),
        "tools": ["art"],
    },
    {
        "id": "ai-003", "name": "Model Stealing",
        "category": "extraction", "severity": "high",
        "desc": "Model stealing and extraction attacks.",
        "detection": (
            "MODEL STEALING:\n"
            "EXTRACTION:\n"
            "  - Query-based extraction\n"
            "    Send many queries → train surrogate model\n"
            "  - Side-channel extraction\n"
            "    Timing, memory, cache attacks\n"
            "  - API reverse engineering\n"
            "    Map decision boundaries\n"
            "TECHNIQUES:\n"
            "  - Knockoff Nets (train on API outputs)\n"
            "  - Model inversion (reconstruct training data)\n"
            "  - Cryptanalytic extraction (exact weights)\n"
            "  - Distillation attacks\n"
            "INDICATORS:\n"
            "  - Unusual query patterns\n"
            "  - High volume of edge-case queries\n"
            "  - Systematic input space exploration\n"
            "  - Suspiciously similar competitor model\n"
            "PROTECTION:\n"
            "  - Rate limiting\n"
            "  - Query auditing\n"
            "  - Watermarking (model fingerprinting)\n"
            "  - Differential privacy\n"
            "  - Output perturbation\n"
            "  - Proof-of-work for queries\n"
            "MEMBERSHIP INFERENCE:\n"
            "  - Was this data in the training set?\n"
            "  - Shadow model technique\n"
            "  - Label-only attacks\n"
            "TOOLS:\n"
            "  ML-Doctor, model-extraction-attacks"
        ),
        "tools": [],
    },
    {
        "id": "ai-004", "name": "Data Poisoning",
        "category": "poisoning", "severity": "critical",
        "desc": "Training data poisoning attacks.",
        "detection": (
            "DATA POISONING:\n"
            "TECHNIQUES:\n"
            "  BACKDOOR:\n"
            "    - Insert trigger pattern in training data\n"
            "    - Model learns trigger → target class\n"
            "    - BadNets (patch trigger)\n"
            "    - Clean-label attacks (no label change)\n"
            "    - Sleeper agent attacks\n"
            "  AVAILABILITY:\n"
            "    - Degrade overall model performance\n"
            "    - Inject noisy/mislabeled data\n"
            "    - Gradient-based poisoning\n"
            "  TARGETED:\n"
            "    - Cause misclassification of specific inputs\n"
            "    - Influence model behavior on trigger\n"
            "    - Supply chain: poison pre-training data\n"
            "LLM SPECIFIC:\n"
            "  - Poisoned fine-tuning data\n"
            "  - Web scraping poisoning\n"
            "  - RLHF manipulation\n"
            "  - Poisoned retrieval documents (RAG)\n"
            "  - Benchmark gaming\n"
            "DEFENSE:\n"
            "  - Data quality monitoring\n"
            "  - Anomaly detection on training data\n"
            "  - Differential privacy\n"
            "  - Robust aggregation\n"
            "  - Spectral signatures\n"
            "TOOLS:\n"
            "  TrojAI, Neural Cleanse, Sleeper Agent Detection"
        ),
        "tools": [],
    },
    {
        "id": "ai-005", "name": "AI Supply Chain Security",
        "category": "ai_supply_chain", "severity": "high",
        "desc": "AI/ML supply chain security.",
        "detection": (
            "AI SUPPLY CHAIN SECURITY:\n"
            "MODEL HUB RISKS:\n"
            "  - Malicious models on Hugging Face\n"
            "  - Pickle deserialization (RCE)\n"
            "  - Backdoored fine-tuned models\n"
            "  - Typosquatted model names\n"
            "  - Manipulated model cards/metrics\n"
            "DEPENDENCY RISKS:\n"
            "  - PyTorch/TensorFlow vulnerabilities\n"
            "  - Malicious training pipelines\n"
            "  - Compromised data loaders\n"
            "  - GPU driver exploits\n"
            "  - CUDA vulnerabilities\n"
            "INFERENCE:\n"
            "  - Model serving framework vulns\n"
            "  - API gateway bypass\n"
            "  - Container escape from ML workload\n"
            "  - GPU memory leak (cross-tenant)\n"
            "  - Prompt injection in production\n"
            "PROTECTION:\n"
            "  - Model signing (cosign for ML)\n"
            "  - Model scanning (modelscan)\n"
            "  - SafeTensors format (no arbitrary code)\n"
            "  - Sandboxed model loading\n"
            "  - Model SBOM\n"
            "  - MLOps security (MLSecOps)\n"
            "TOOLS:\n"
            "  modelscan, fickling, safetensors"
        ),
        "tools": ["modelscan"],
    },
]


class AIMLSecurityKB:
    """AI/ML security knowledge base.

    Provides AI/ML security patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, AIMLPattern] = {}
        self._log = logger.bind(component="aiml_security_kb")
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
