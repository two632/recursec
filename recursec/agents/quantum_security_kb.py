"""Quantum computing security knowledge base — post-quantum crypto, quantum attacks."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

class QuantumAttackType(str, Enum):
    CRYPTO_BREAK = "crypto_break"
    PQC_TRANSITION = "pqc_transition"
    QKD = "qkd"
    HYBRID = "hybrid"
    HARVEST_NOW = "harvest_now"

@dataclass
class QuantumPattern:
    name: str = ""
    attack_type: QuantumAttackType = QuantumAttackType.CRYPTO_BREAK
    description: str = ""
    techniques: list[str] = field(default_factory=list)
    detection: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    severity: str = "critical"
    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "type": self.attack_type.value, "severity": self.severity}

QUANTUM_PATTERNS: list[QuantumPattern] = [
    QuantumPattern(name="Quantum Cryptographic Breaks", attack_type=QuantumAttackType.CRYPTO_BREAK, description="Quantum computers breaking current cryptography: Shor's algorithm (RSA, ECC, DH), Grover's (AES, hashing).", techniques=["Shor's algorithm: factor RSA modulus in polynomial time", "Shor's for ECDLP: break elliptic curve in polynomial time", "Grover's search: reduce AES-256 to AES-128 security level", "Quantum period-finding for Diffie-Hellman", "Harvest-now-decrypt-later: capture encrypted traffic for future quantum decryption", "Quantum side-channel: exploit quantum computer error correction", "Quantum random number generation attacks"], detection=["Inventory all cryptographic algorithms in use", "Identify RSA/ECC/DH key sizes below quantum-safe threshold", "Catalog data retention periods vs quantum timeline", "Map certificate chains for quantum vulnerability"], tools=["qiskit", "cirq", "nist-pqc-reference", "oqs-openssl"], severity="critical"),
    QuantumPattern(name="Post-Quantum Cryptography Transition", attack_type=QuantumAttackType.PQC_TRANSITION, description="Transitioning to quantum-resistant algorithms: NIST PQC standards, hybrid schemes, migration planning.", techniques=["Crypto agility assessment: ability to swap algorithms without redesign", "NIST PQC standard deployment: ML-KEM (Kyber), ML-DSA (Dilithium), SLH-DSA (SPHINCS+)", "Hybrid key exchange: combine classical + PQC (e.g., X25519+ML-KEM)", "TLS 1.3 + PQC: deploy post-quantum TLS cipher suites", "Code signing migration to quantum-resistant signatures", "PKI infrastructure upgrade for larger PQC key sizes", "Performance impact assessment: PQC algorithms are slower/larger"], detection=["Audit TLS configurations for PQC support", "Check certificate chains for quantum-resistant signatures", "Verify key exchange algorithms include PQC options", "Test application performance with PQC algorithms"], tools=["oqs-openssl", "liboqs", "bouncycastle-pqc", "wolfssl-pqc"], severity="high"),
    QuantumPattern(name="Quantum Key Distribution", attack_type=QuantumAttackType.QKD, description="QKD security analysis: BB84 protocol, implementation vulnerabilities, detector attacks.", techniques=["Photon-number-splitting attack on weak coherent sources", "Detector blinding attack: control Bob's detectors with bright light", "Trojan horse attack: probe Alice's source with light", "Time-shift attack: exploit timing differences in detectors", "Fake-state attack: manipulate Bob's measurement basis", "Implementation loophole exploitation (detector efficiency mismatch)", "Device-independent QKD verification"], detection=["Monitor QBER (Quantum Bit Error Rate) for anomalies", "Detector calibration verification", "Source characterization and monitoring", "Privacy amplification verification"], tools=["qkd-sim", "quantum-optics-tools"], severity="high"),
    QuantumPattern(name="Harvest-Now-Decrypt-Later", attack_type=QuantumAttackType.HARVEST_NOW, description="Adversaries recording encrypted data today for future quantum decryption. Critical for long-term secrets.", techniques=["Mass interception of TLS-encrypted traffic at ISP level", "Targeting high-value encrypted communications (government, military)", "Storing encrypted VPN tunnels for future decryption", "Capturing encrypted backups and archives", "Recording SSH sessions protected by RSA/ECDH", "Intercepting encrypted emails for future quantum attack", "Estimating quantum computer timeline for attack planning"], detection=["Classify data by sensitivity and retention period", "Identify communications using quantum-vulnerable algorithms", "Map network traffic to encryption algorithm inventory", "Assess adversary capability and timeline estimates"], tools=["wireshark", "tshark", "network-miner"], severity="critical"),
]

def build_quantum_security_prompt(focus_type: QuantumAttackType | None = None, max_patterns: int = 5) -> str:
    lines = ["## Quantum Security Knowledge\n"]
    patterns = QUANTUM_PATTERNS if not focus_type else [p for p in QUANTUM_PATTERNS if p.attack_type == focus_type]
    for p in patterns[:max_patterns]:
        lines.append(f"### {p.name} [{p.severity}]")
        lines.append(p.description)
        lines.append("\nTechniques:")
        for t in p.techniques[:4]:
            lines.append(f"  - {t}")
        lines.append("")
    return "\n".join(lines)
