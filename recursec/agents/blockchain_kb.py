"""Blockchain and smart contract security knowledge base.

Deep knowledge about blockchain security:
1. Smart contract vulnerabilities
2. DeFi protocol attacks
3. Wallet and key security
4. Consensus and node attacks
5. Bridge and cross-chain attacks
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class BlockchainPattern:
    """A blockchain security pattern."""
    pattern_id: str = ""
    name: str = ""
    category: str = ""
    severity: str = "critical"
    description: str = ""
    detection_strategy: str = ""
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:25],
            "category": self.category[:12],
        }


BLOCKCHAIN_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "bc-001", "name": "Smart Contract Vulnerabilities",
        "category": "smart_contract", "severity": "critical",
        "desc": "Solidity/EVM smart contract vulns.",
        "detection": (
            "SMART CONTRACT VULNERABILITIES:\n"
            "REENTRANCY:\n"
            "  - External call before state update\n"
            "    # contract.call{value: amount}('')\n"
            "    # Fallback function re-enters\n"
            "  - Cross-function reentrancy\n"
            "  - Cross-contract reentrancy\n"
            "  - Read-only reentrancy (view functions)\n"
            "  # Prevention: checks-effects-interactions\n"
            "  # ReentrancyGuard modifier\n"
            "INTEGER OVERFLOW/UNDERFLOW:\n"
            "  - Solidity <0.8.0 (no built-in checks)\n"
            "  - Unchecked blocks in >=0.8.0\n"
            "  - uint256 wrap-around\n"
            "ACCESS CONTROL:\n"
            "  - Missing onlyOwner modifiers\n"
            "  - tx.origin vs msg.sender\n"
            "  - Unprotected selfdestruct\n"
            "  - Unprotected delegatecall\n"
            "FRONT-RUNNING:\n"
            "  - Transaction ordering dependence\n"
            "  - Sandwich attacks\n"
            "  - Mempool observation\n"
            "LOGIC BUGS:\n"
            "  - Oracle manipulation\n"
            "  - Flash loan attacks\n"
            "  - Storage collision (proxy)\n"
            "  - Uninitialized storage pointer\n"
            "TOOLS:\n"
            "  Slither, Mythril, Echidna, Foundry, Certora"
        ),
        "tools": [],
    },
    {
        "id": "bc-002", "name": "DeFi Protocol Attacks",
        "category": "defi", "severity": "critical",
        "desc": "DeFi-specific attack vectors.",
        "detection": (
            "DEFI PROTOCOL ATTACKS:\n"
            "FLASH LOAN:\n"
            "  - Borrow without collateral\n"
            "  - Manipulate price oracles\n"
            "  - Execute arbitrage in one tx\n"
            "  - Drain liquidity pools\n"
            "  # Aave, dYdX flash loan providers\n"
            "PRICE ORACLE MANIPULATION:\n"
            "  - Spot price manipulation\n"
            "    # Large swap → price change\n"
            "    # Use manipulated price\n"
            "    # Swap back\n"
            "  - TWAP oracle gaming\n"
            "  - Chainlink stale price\n"
            "LIQUIDITY POOL:\n"
            "  - Impermanent loss exploitation\n"
            "  - Sandwich attack\n"
            "    # Front-run user swap\n"
            "    # Back-run user swap\n"
            "  - JIT (Just-In-Time) liquidity\n"
            "  - LP token manipulation\n"
            "GOVERNANCE:\n"
            "  - Flash loan governance attack\n"
            "    # Borrow tokens → vote → return\n"
            "  - Proposal manipulation\n"
            "  - Timelock bypass\n"
            "YIELD:\n"
            "  - Vault share manipulation\n"
            "  - Donation attacks\n"
            "  - Reward distribution bugs\n"
            "TOOLS:\n"
            "  Foundry (forge), Hardhat, Tenderly, DeFiHackLabs"
        ),
        "tools": [],
    },
    {
        "id": "bc-003", "name": "Wallet and Key Security",
        "category": "wallet", "severity": "critical",
        "desc": "Wallet and private key security.",
        "detection": (
            "WALLET & KEY SECURITY:\n"
            "PRIVATE KEY EXPOSURE:\n"
            "  - Hardcoded in source code\n"
            "    # grep -rn 'private' *.sol *.js\n"
            "    # Check .env files\n"
            "  - Git history leaks\n"
            "    # trufflehog, gitleaks\n"
            "  - Insecure generation\n"
            "    # Weak entropy\n"
            "    # Predictable seeds\n"
            "  - Clipboard exposure\n"
            "  - Memory dumps\n"
            "SIGNATURE ATTACKS:\n"
            "  - Signature replay\n"
            "    # Missing nonce or chainId\n"
            "  - Signature malleability\n"
            "  - ecrecover issues\n"
            "    # v value manipulation\n"
            "    # Zero address return\n"
            "  - EIP-712 implementation flaws\n"
            "WALLET ATTACKS:\n"
            "  - Phishing approvals\n"
            "    # Unlimited token approval\n"
            "    # approve(spender, MAX_UINT)\n"
            "  - Address poisoning\n"
            "  - Fake token airdrop\n"
            "  - Browser extension injection\n"
            "  - Supply chain (NPM packages)\n"
            "MULTISIG:\n"
            "  - Threshold bypass\n"
            "  - Signer compromise\n"
            "  - Transaction replay\n"
            "TOOLS:\n"
            "  Etherscan, MyCrypto, Rabby"
        ),
        "tools": [],
    },
    {
        "id": "bc-004", "name": "Consensus and Node Attacks",
        "category": "consensus", "severity": "high",
        "desc": "Blockchain consensus and node attacks.",
        "detection": (
            "CONSENSUS & NODE ATTACKS:\n"
            "51% ATTACK:\n"
            "  - Hash rate majority\n"
            "  - Double spending\n"
            "  - Transaction censorship\n"
            "  - Selfish mining\n"
            "  # Small PoW chains most vulnerable\n"
            "NODE ATTACKS:\n"
            "  - Eclipse attack\n"
            "    # Isolate node from network\n"
            "    # Feed false blockchain data\n"
            "  - Sybil attack\n"
            "    # Many fake nodes\n"
            "    # Influence routing/consensus\n"
            "  - BGP hijacking of node traffic\n"
            "  - RPC endpoint exposure\n"
            "    # Open JSON-RPC\n"
            "    # eth_accounts, eth_sendTransaction\n"
            "    # No authentication\n"
            "MEV (Miner Extractable Value):\n"
            "  - Transaction reordering\n"
            "  - Sandwich attacks (validators)\n"
            "  - Block builder manipulation\n"
            "  - PBS (Proposer-Builder Separation)\n"
            "VALIDATOR:\n"
            "  - Slashing conditions\n"
            "  - Key management\n"
            "  - Client diversity risks\n"
            "  - Liveness vs safety\n"
            "TOOLS:\n"
            "  Geth, Erigon, mev-inspect, Flashbots"
        ),
        "tools": [],
    },
    {
        "id": "bc-005", "name": "Bridge and Cross-Chain Attacks",
        "category": "bridge", "severity": "critical",
        "desc": "Cross-chain bridge security.",
        "detection": (
            "BRIDGE & CROSS-CHAIN ATTACKS:\n"
            "BRIDGE VULNERABILITIES:\n"
            "  - Validator compromise\n"
            "    # Multi-sig bridges\n"
            "    # Threshold signature\n"
            "    # Validator key theft\n"
            "  - Message verification bypass\n"
            "    # Fake cross-chain messages\n"
            "    # Proof forgery\n"
            "  - Deposit/withdrawal mismatch\n"
            "  - Replay across chains\n"
            "HISTORICAL EXPLOITS:\n"
            "  - Ronin ($625M): validator keys\n"
            "  - Wormhole ($320M): signature bypass\n"
            "  - Nomad ($190M): proof verification\n"
            "  - Harmony ($100M): multisig keys\n"
            "ATTACK PATTERNS:\n"
            "  - Lock-and-mint exploitation\n"
            "    # Fake lock event on source\n"
            "    # Mint on destination\n"
            "  - Liquidity drain\n"
            "  - Oracle manipulation across chains\n"
            "  - Finality assumptions\n"
            "    # Source chain reorg\n"
            "    # Destination already minted\n"
            "DETECTION:\n"
            "  - Monitor bridge TVL changes\n"
            "  - Verify proof mechanisms\n"
            "  - Audit validator set changes\n"
            "  - Cross-chain message integrity\n"
            "TOOLS:\n"
            "  Foundry, custom monitors, Forta"
        ),
        "tools": [],
    },
]


class BlockchainKB:
    """Blockchain security knowledge base.

    Provides blockchain patterns injected
    into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, BlockchainPattern] = {}
        self._log = logger.bind(component="blockchain_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load blockchain patterns."""
        for data in BLOCKCHAIN_PATTERNS:
            pattern = BlockchainPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "critical"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[BlockchainPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_blockchain_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build blockchain prompt."""
        lines = ["## Blockchain Security\n"]
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
