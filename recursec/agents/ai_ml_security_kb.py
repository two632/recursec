"""AI/ML security knowledge base — adversarial attacks, model extraction, LLM attacks."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
import structlog
logger = structlog.get_logger()

class AIAttackType(str, Enum):
    ADVERSARIAL = "adversarial"
    MODEL_EXTRACTION = "model_extraction"
    DATA_POISONING = "data_poisoning"
    PROMPT_INJECTION = "prompt_injection"
    MODEL_INVERSION = "model_inversion"

@dataclass
class AISecurityPattern:
    name: str = ""
    attack_type: AIAttackType = AIAttackType.ADVERSARIAL
    description: str = ""
    techniques: list[str] = field(default_factory=list)
    detection: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    severity: str = "high"
    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "type": self.attack_type.value, "severity": self.severity}

AI_SECURITY_PATTERNS: list[AISecurityPattern] = [
    AISecurityPattern(name="Adversarial Input Attacks", attack_type=AIAttackType.ADVERSARIAL, description="Generate inputs that fool ML models: FGSM (Fast Gradient Sign Method), PGD (Projected Gradient Descent), C&W attack, DeepFool, physical-world adversarial patches, adversarial audio, backdoor triggers.", techniques=["FGSM: single-step gradient perturbation (fast, low cost)", "PGD: iterative gradient perturbation (stronger, Madry et al.)", "C&W: optimization-based attack (most effective, Carlini & Wagner)", "DeepFool: minimal perturbation to cross decision boundary", "Physical patches: adversarial stickers/overlays for real-world objects", "Universal adversarial perturbations: single perturbation fools all inputs", "Black-box transfer attacks: craft on surrogate model, transfer to target", "Adversarial audio: imperceptible noise that changes speech recognition"], detection=["Input preprocessing (JPEG compression, spatial smoothing)", "Adversarial training (train on adversarial examples)", "Certified defenses (randomized smoothing)", "Feature squeezing and input denoising", "Model ensemble disagreement detection"], tools=["foolbox", "cleverhans", "art-ibm", "adversarial-robustness-toolbox"], commands=["python -c 'from art.attacks.evasion import FastGradientMethod; # generate adversarial'", "python -c 'import foolbox as fb; model = fb.PyTorchModel(net, bounds=(0,1)); # attack'"], severity="high"),
    AISecurityPattern(name="Model Extraction / Stealing", attack_type=AIAttackType.MODEL_EXTRACTION, description="Extract model parameters or decision boundaries through API queries: functionally equivalent model cloning, hyperparameter stealing, architecture inference, side-channel extraction.", techniques=["Query-based extraction: systematic API queries to clone model", "Knockoff nets: train substitute on target predictions", "Equation-solving attacks: solve for model weights (linear models)", "Side-channel: timing attacks to infer architecture depth", "Membership inference: determine if sample was in training data", "Model watermark removal after extraction", "Distillation-based extraction: use target as teacher"], detection=["Query rate limiting and anomaly detection", "Model watermarking (verify ownership)", "Prediction perturbation (add noise to outputs)", "Monitor query distribution for extraction patterns", "Fingerprinting: unique model responses to canary inputs"], tools=["knockoffnets", "deepjudge", "modelguard"], commands=["python -c 'import knockoff; # extract model via API queries'"], severity="high"),
    AISecurityPattern(name="Data Poisoning", attack_type=AIAttackType.DATA_POISONING, description="Corrupt training data to compromise model: backdoor attacks (trojan triggers), clean-label poisoning, gradient-based poisoning, federated learning poisoning.", techniques=["Backdoor injection: add trigger pattern to training samples", "Clean-label poisoning: modify training without changing labels", "Gradient-based poisoning: optimize poison samples via gradients", "Federated learning: malicious participant sends poisoned gradients", "Data augmentation poisoning: corrupt augmentation pipeline", "Label flipping: change labels of key training samples", "Influence function attacks: identify most influential training points"], detection=["Neural cleanse: detect backdoor triggers", "Spectral signatures: analyze activation covariance", "STRIP: perturbation-based trigger detection at inference", "Activation clustering: identify poisoned samples", "Meta neural analysis: train detector on model internals"], tools=["trojannn", "neural-cleanse", "backdoor-toolbox"], commands=["python -c 'from trojannn import TrojanNN; # inject backdoor'"], severity="critical"),
    AISecurityPattern(name="Prompt Injection & LLM Attacks", attack_type=AIAttackType.PROMPT_INJECTION, description="Attack LLM-based systems: direct prompt injection, indirect injection via retrieved content, jailbreaking, prompt leaking, training data extraction, agent tool abuse.", techniques=["Direct prompt injection: override system prompt with user input", "Indirect injection: embed instructions in retrieved documents/emails", "Jailbreaking: bypass safety filters (DAN, roleplay, encoding tricks)", "Prompt leaking: extract system prompt via reflection techniques", "Training data extraction: make model regurgitate memorized data", "Agent manipulation: trick agent into executing harmful tool calls", "Context window stuffing: overflow context to push out safety instructions", "Encoding attacks: use base64/rot13/unicode to bypass filters", "Multi-turn manipulation: gradually shift model behavior across turns"], detection=["Input/output content filtering", "Instruction hierarchy (system > user > retrieved)", "Canary token detection in system prompts", "Perplexity-based injection detection", "Output validation against allowed actions"], tools=["garak", "promptfoo", "rebuff"], commands=["garak --model_type openai --probes all", "promptfoo eval --config promptfoo.yaml"], severity="critical"),
    AISecurityPattern(name="Model Inversion & Privacy", attack_type=AIAttackType.MODEL_INVERSION, description="Reconstruct training data or private information from model: model inversion attacks, membership inference, attribute inference, gradient leakage in federated learning.", techniques=["Model inversion: reconstruct training samples from model outputs", "Membership inference: determine if a specific sample was used in training", "Attribute inference: infer sensitive attributes from model behavior", "Gradient leakage: reconstruct training data from shared gradients (federated)", "Property inference: learn aggregate properties of training data", "Memorization attacks: extract memorized sequences from language models"], detection=["Differential privacy in training (DP-SGD)", "Secure aggregation in federated learning", "Output perturbation (confidence masking)", "Regularization to reduce memorization", "Membership inference resistance testing"], tools=["ml-privacy-meter", "opacus", "tensorflow-privacy"], commands=["python -c 'from opacus import PrivacyEngine; # add differential privacy'"], severity="high"),
]

def build_ai_ml_security_prompt(focus_type: AIAttackType | None = None, max_patterns: int = 5) -> str:
    lines = ["## AI/ML Security Knowledge\n"]
    patterns = AI_SECURITY_PATTERNS if not focus_type else [p for p in AI_SECURITY_PATTERNS if p.attack_type == focus_type]
    for p in patterns[:max_patterns]:
        lines.append(f"### {p.name} [{p.severity}]")
        lines.append(p.description)
        lines.append("\nTechniques:")
        for t in p.techniques[:4]:
            lines.append(f"  - {t}")
        lines.append("")
    return "\n".join(lines)
