"""Blockchain and Web3 security knowledge base.

Attack patterns, techniques, and detection strategies for:
- Smart contract vulnerabilities (reentrancy, overflow, access control)
- DeFi protocol attacks (flash loans, oracle manipulation, MEV)
- Bridge and cross-chain vulnerabilities
- Wallet and key management attacks
- Consensus mechanism exploits
- NFT marketplace vulnerabilities
- DAO governance attacks
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class BlockchainAttackPattern:
    name: str = ""
    category: str = ""
    severity: str = "high"
    description: str = ""
    techniques: list[str] = field(default_factory=list)
    detection: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    mitre_id: str = ""
    cwe: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "cat": self.category, "sev": self.severity}


BLOCKCHAIN_ATTACK_PATTERNS: list[BlockchainAttackPattern] = [
    BlockchainAttackPattern(
        name="Reentrancy Attack",
        category="smart_contract",
        severity="critical",
        description="Exploit recursive calls to drain funds before state update",
        techniques=[
            "Cross-function reentrancy via shared state",
            "Cross-contract reentrancy through callback chains",
            "Read-only reentrancy exploiting view functions",
            "Single-function reentrancy on ETH transfer",
            "ERC-777 token hooks for reentrancy vectors",
        ],
        detection=[
            "Static analysis: detect external calls before state updates",
            "Check for checks-effects-interactions pattern violations",
            "Monitor for unusual recursive call patterns on-chain",
            "Slither reentrancy detectors (reentrancy-eth, reentrancy-no-eth)",
            "Test with reentrancy attack contracts in fork environment",
        ],
        tools=["slither", "mythril", "echidna", "foundry"],
        cwe="CWE-841",
    ),
    BlockchainAttackPattern(
        name="Flash Loan Attack",
        category="defi",
        severity="critical",
        description="Borrow massive amounts, manipulate markets, profit, repay in single transaction",
        techniques=[
            "Oracle price manipulation via flash loan volume",
            "Liquidity pool imbalance exploitation",
            "Governance vote manipulation with borrowed tokens",
            "Collateral ratio manipulation for liquidation",
            "Arbitrage across DEXes with zero capital risk",
        ],
        detection=[
            "Monitor for unusually large single-transaction volumes",
            "Detect price deviations across oracles in same block",
            "Track flash loan origination patterns",
            "Alert on governance proposals with sudden vote changes",
            "Check for same-block borrow-and-repay patterns",
        ],
        tools=["tenderly", "foundry", "hardhat"],
    ),
    BlockchainAttackPattern(
        name="Front-Running / MEV",
        category="defi",
        severity="high",
        description="Extract value by reordering or inserting transactions",
        techniques=[
            "Sandwich attacks on DEX swaps",
            "Generalized front-running of profitable transactions",
            "Backrunning of oracle updates",
            "Time-bandit attacks via block reordering",
            "Just-in-time liquidity provision",
        ],
        detection=[
            "Monitor mempool for pending profitable transactions",
            "Detect sandwich patterns (buy-target-sell in same block)",
            "Track MEV builder activity and extraction rates",
            "Analyze transaction ordering anomalies",
        ],
        tools=["flashbots", "mev-inspect", "eigenphi"],
    ),
    BlockchainAttackPattern(
        name="Bridge Exploit",
        category="cross_chain",
        severity="critical",
        description="Exploit cross-chain bridge vulnerabilities for asset theft",
        techniques=[
            "Fake deposit proof generation",
            "Validator key compromise for bridge signing",
            "Replay attacks across chains",
            "Race condition in finality confirmation",
            "Oracle manipulation for cross-chain price feeds",
        ],
        detection=[
            "Monitor bridge TVL for sudden drops",
            "Validate all cross-chain messages cryptographically",
            "Track validator set changes and key rotations",
            "Alert on unusual withdrawal patterns from bridge",
        ],
        tools=["tenderly", "forta"],
    ),
    BlockchainAttackPattern(
        name="Access Control Bypass",
        category="smart_contract",
        severity="critical",
        description="Bypass authorization checks in smart contracts",
        techniques=[
            "tx.origin authentication bypass",
            "Uninitialized proxy implementation exploit",
            "Delegatecall to attacker-controlled contract",
            "Missing access control on critical functions",
            "Role-based access control misconfiguration",
        ],
        detection=[
            "Static analysis for tx.origin usage",
            "Check proxy initialization status",
            "Verify all critical functions have access modifiers",
            "Audit delegatecall targets for user-controllable addresses",
        ],
        tools=["slither", "mythril", "certora"],
        cwe="CWE-284",
    ),
    BlockchainAttackPattern(
        name="Integer Overflow/Underflow",
        category="smart_contract",
        severity="high",
        description="Exploit arithmetic overflow in older Solidity versions",
        techniques=[
            "Underflow to generate infinite token balance",
            "Overflow in token transfer calculations",
            "Unchecked math in fee calculations",
            "Timestamp manipulation via overflow",
        ],
        detection=[
            "Check Solidity version (< 0.8.0 vulnerable by default)",
            "Verify SafeMath library usage in older contracts",
            "Static analysis for unchecked arithmetic blocks",
            "Fuzz test arithmetic operations with extreme values",
        ],
        tools=["slither", "mythril", "echidna"],
        cwe="CWE-190",
    ),
    BlockchainAttackPattern(
        name="Oracle Manipulation",
        category="defi",
        severity="critical",
        description="Manipulate price oracles to exploit DeFi protocols",
        techniques=[
            "Spot price manipulation on single DEX",
            "TWAP oracle manipulation across multiple blocks",
            "Chainlink feed delay exploitation",
            "Centralized oracle compromise",
            "AMM reserve ratio manipulation",
        ],
        detection=[
            "Compare price across multiple oracle sources",
            "Detect sudden price deviations from TWAP",
            "Monitor oracle update frequency and freshness",
            "Alert on price deviations exceeding threshold",
        ],
        tools=["chainlink", "uniswap-oracle", "foundry"],
    ),
]

DOMAIN_META = {
    "domain": "blockchain_security",
    "patterns": len(BLOCKCHAIN_ATTACK_PATTERNS),
    "categories": ["smart_contract", "defi", "cross_chain", "governance"],
    "tools": ["slither", "mythril", "echidna", "foundry", "tenderly", "forta"],
}


def build_blockchain_kb_prompt() -> str:
    """Build LLM prompt with blockchain security knowledge."""
    lines = ["## Blockchain & Web3 Security Knowledge"]
    lines.append(f"Patterns: {len(BLOCKCHAIN_ATTACK_PATTERNS)}")
    for pat in BLOCKCHAIN_ATTACK_PATTERNS:
        lines.append(f"\n### {pat.name} [{pat.severity}]")
        lines.append(f"Category: {pat.category}")
        lines.append(f"Description: {pat.description}")
        lines.append("Techniques:")
        for t in pat.techniques[:3]:
            lines.append(f"  - {t}")
        lines.append("Detection:")
        for d in pat.detection[:2]:
            lines.append(f"  - {d}")
        if pat.cwe:
            lines.append(f"CWE: {pat.cwe}")
    return "\n".join(lines)
