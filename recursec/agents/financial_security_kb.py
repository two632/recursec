"""Financial systems security knowledge base — SWIFT, PCI, trading, fintech."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

class FinancialAttackType(str, Enum):
    SWIFT = "swift"
    TRADING = "trading"
    PAYMENT = "payment"
    CRYPTO_DEFI = "crypto_defi"
    BANKING = "banking"

@dataclass
class FinancialPattern:
    name: str = ""
    attack_type: FinancialAttackType = FinancialAttackType.SWIFT
    description: str = ""
    techniques: list[str] = field(default_factory=list)
    detection: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    severity: str = "critical"
    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "type": self.attack_type.value, "severity": self.severity}

FINANCIAL_PATTERNS: list[FinancialPattern] = [
    FinancialPattern(name="SWIFT Network Attacks", attack_type=FinancialAttackType.SWIFT, description="Attacks on SWIFT financial messaging: Bangladesh Bank heist techniques.", techniques=["SWIFT Alliance Access server compromise", "Fraudulent MT103 (payment) message injection", "MT199 cancellation message suppression", "Operator credential theft for Alliance Lite2", "PDF report manipulation to hide fraudulent transfers", "SWIFT transaction log tampering", "Correspondent banking relationship abuse"], detection=["SWIFT CSP (Customer Security Programme) controls", "Transaction anomaly detection (amount, timing, destination)", "Operator behavior monitoring", "Real-time MT103 validation against limits", "PDF report integrity checking"], tools=["nmap", "metasploit", "wireshark"], severity="critical"),
    FinancialPattern(name="Trading System Exploitation", attack_type=FinancialAttackType.TRADING, description="HFT, market manipulation, algorithmic trading attacks.", techniques=["FIX protocol message injection (spoofed orders)", "Quote stuffing (flood order book for latency arbitrage)", "Layering/spoofing (place then cancel orders)", "Dark pool information leakage exploitation", "Market data feed manipulation", "Co-location timing attacks (microsecond advantage)", "Cross-exchange arbitrage exploitation via latency"], detection=["FIX message validation and rate limiting", "Order pattern anomaly detection", "Cross-market surveillance", "Latency monitoring for co-location abuse", "Order-to-trade ratio monitoring"], tools=["wireshark", "fix-analyzer", "custom-trading-tools"], severity="critical"),
    FinancialPattern(name="Payment System Attacks", attack_type=FinancialAttackType.PAYMENT, description="Card processing, POS, ATM, mobile payment attacks.", techniques=["EMV chip relay attack (card-present fraud)", "ATM jackpotting (malware-based cash dispensing)", "POS RAM scraping for card data", "Contactless/NFC relay attack (Apple Pay, Google Pay)", "Payment gateway API exploitation", "3D Secure bypass techniques", "Virtual card number generation exploitation"], detection=["EMV transaction velocity monitoring", "ATM software integrity verification", "POS network segmentation monitoring", "NFC transaction distance validation", "3D Secure challenge rate monitoring"], tools=["nmap", "burpsuite", "custom-emv-tools"], severity="critical"),
    FinancialPattern(name="DeFi/Smart Contract Attacks", attack_type=FinancialAttackType.CRYPTO_DEFI, description="Decentralized finance smart contract exploitation.", techniques=["Flash loan attack (borrow → manipulate → profit → repay in one tx)", "Reentrancy attack (recursive withdraw before balance update)", "Oracle manipulation (price feed exploitation)", "Front-running (MEV: sandwich attacks on DEX trades)", "Governance attack (flash loan → vote → profit)", "Integer overflow/underflow in token contracts", "Delegatecall vulnerability exploitation", "Cross-chain bridge exploitation"], detection=["Smart contract formal verification", "Transaction pattern monitoring", "Oracle price deviation detection", "MEV detection and protection (Flashbots)", "Governance vote anomaly detection"], tools=["slither", "mythril", "echidna", "foundry", "hardhat"], severity="critical"),
    FinancialPattern(name="Banking Application Attacks", attack_type=FinancialAttackType.BANKING, description="Online banking, mobile banking, open banking API attacks.", techniques=["Mobile banking app reverse engineering", "Open Banking API (PSD2) abuse via account aggregation", "Session fixation on online banking", "OTP/2FA bypass via SS7 or SIM swap", "Screen overlay attack on mobile banking", "API parameter tampering for unauthorized transfers", "Deposit slip manipulation"], detection=["Mobile app integrity verification", "API rate limiting and anomaly detection", "Session management monitoring", "2FA delivery channel monitoring", "Transaction pattern analysis"], tools=["frida", "burpsuite", "apktool", "mobsf"], severity="critical"),
]

def build_financial_security_prompt(focus_type: FinancialAttackType | None = None, max_patterns: int = 5) -> str:
    lines = ["## Financial Systems Security Knowledge\n"]
    patterns = FINANCIAL_PATTERNS if not focus_type else [p for p in FINANCIAL_PATTERNS if p.attack_type == focus_type]
    for p in patterns[:max_patterns]:
        lines.append(f"### {p.name} [{p.severity}]")
        lines.append(p.description)
        lines.append("\nTechniques:")
        for t in p.techniques[:4]:
            lines.append(f"  - {t}")
        lines.append("")
    return "\n".join(lines)
