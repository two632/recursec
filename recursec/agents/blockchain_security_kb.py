"""Blockchain and smart contract security knowledge base."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
import structlog
logger = structlog.get_logger()

class BlockchainAttackType(str, Enum):
    SMART_CONTRACT = "smart_contract"
    DEFI = "defi"
    WALLET = "wallet"
    CONSENSUS = "consensus"
    BRIDGE = "bridge"

@dataclass
class BlockchainPattern:
    name: str = ""
    attack_type: BlockchainAttackType = BlockchainAttackType.SMART_CONTRACT
    description: str = ""
    vulnerabilities: list[str] = field(default_factory=list)
    detection: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    severity: str = "critical"
    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "type": self.attack_type.value, "severity": self.severity}

BLOCKCHAIN_PATTERNS: list[BlockchainPattern] = [
    BlockchainPattern(name="Smart Contract Vulnerabilities", attack_type=BlockchainAttackType.SMART_CONTRACT, description="Solidity/EVM vulnerabilities: reentrancy, integer overflow, access control, delegatecall, tx.origin, front-running, flash loan manipulation.", vulnerabilities=["Reentrancy: external call before state update (The DAO hack pattern)", "Integer overflow/underflow (pre-SafeMath)", "Access control: missing onlyOwner/role checks", "Delegatecall to untrusted contract (proxy pattern abuse)", "tx.origin vs msg.sender confusion", "Uninitialized storage pointers", "Front-running via mempool monitoring", "Unchecked return values from low-level calls", "Self-destruct to force ETH into contract", "Block timestamp manipulation for randomness"], detection=["Static analysis with Slither/Mythril", "Formal verification with Certora/K Framework", "Fuzz testing with Echidna/Foundry", "Manual code review for logic bugs", "Check for known vulnerability patterns"], tools=["slither", "mythril", "echidna", "foundry", "certora", "manticore"], commands=["slither . --detect reentrancy-eth,reentrancy-no-eth", "myth analyze contract.sol --execution-timeout 300", "echidna-test . --contract TestContract --config echidna.yaml", "forge test --fuzz-runs 10000"], severity="critical"),
    BlockchainPattern(name="DeFi Protocol Attacks", attack_type=BlockchainAttackType.DEFI, description="DeFi-specific attacks: flash loan manipulation, oracle manipulation, sandwich attacks, liquidity pool exploitation, governance attacks.", vulnerabilities=["Flash loan attacks: borrow→manipulate→profit→repay in single tx", "Oracle manipulation: TWAP, Chainlink stale prices, spot price", "Sandwich attacks: front-run and back-run user swaps", "Impermanent loss exploitation in AMM pools", "Governance attacks: flash loan voting power", "Yield farming exploits: reward calculation manipulation", "Cross-protocol composability risks", "Price slippage exploitation"], detection=["Monitor for flash loan transactions", "Check oracle freshness and deviation thresholds", "Analyze mempool for sandwich patterns", "Verify governance voting power snapshots", "Audit reward calculation formulas", "Check for price manipulation resistance"], tools=["tenderly", "dune-analytics", "flashbots-protect", "forta"], commands=["cast call $ORACLE 'latestRoundData()' --rpc-url $RPC", "forge script SimulateFlashLoan --broadcast"], severity="critical"),
    BlockchainPattern(name="Wallet Security", attack_type=BlockchainAttackType.WALLET, description="Wallet attacks: private key extraction, seed phrase phishing, approval hijacking, malicious token transfers, clipboard hijacking.", vulnerabilities=["Private key stored unencrypted in browser/disk", "Seed phrase phishing via fake wallet sites", "Unlimited token approval exploitation", "Malicious contract draining via approve+transferFrom", "Address poisoning (similar-looking addresses)", "Clipboard hijacking replacing crypto addresses", "Hardware wallet supply chain attacks", "Multisig key compromise (social engineering)"], detection=["Check for unlimited token approvals", "Monitor for approval transactions to unknown contracts", "Detect address poisoning in transaction history", "Verify hardware wallet firmware integrity", "Audit multisig signer list and thresholds"], tools=["revoke.cash", "etherscan", "gnosis-safe"], commands=["cast call $TOKEN 'allowance(address,address)' $USER $SPENDER --rpc-url $RPC", "etherscan api: module=account&action=txlist&address=$WALLET"], severity="high"),
    BlockchainPattern(name="Consensus Attacks", attack_type=BlockchainAttackType.CONSENSUS, description="Consensus-level attacks: 51% attacks, selfish mining, long-range attacks, nothing-at-stake, eclipse attacks on nodes.", vulnerabilities=["51% attack: control majority hash rate to double-spend", "Selfish mining: withhold blocks for strategic advantage", "Long-range attack on PoS: rewrite history from genesis", "Nothing-at-stake: validate on multiple forks for free", "Eclipse attack: isolate node from honest peers", "Time-warp attack: manipulate difficulty adjustment", "Block withholding in mining pools", "MEV (Maximal Extractable Value) extraction"], detection=["Monitor network hash rate distribution", "Track block propagation times", "Detect peer isolation patterns", "Monitor for chain reorganizations", "Check validator stake distribution"], tools=["ethstats", "beaconcha.in", "mev-boost"], commands=["geth attach --exec 'eth.mining; eth.hashrate; eth.syncing'"], severity="critical"),
    BlockchainPattern(name="Cross-Chain Bridge Attacks", attack_type=BlockchainAttackType.BRIDGE, description="Bridge vulnerabilities: validator key compromise, message verification bypass, replay attacks, liquidity pool draining, wrapped token depegging.", vulnerabilities=["Validator/relayer private key compromise", "Message verification bypass (insufficient signature checks)", "Replay attacks across chains", "Liquidity pool draining via fake deposit proofs", "Wrapped token depegging from manipulation", "Race condition in cross-chain message processing", "Insufficient finality confirmation", "Admin key compromise for bridge upgrades"], detection=["Audit bridge validator set and key management", "Verify message verification logic completeness", "Check replay protection mechanisms", "Monitor bridge TVL for sudden changes", "Audit upgrade mechanisms and admin keys", "Verify finality requirements per chain"], tools=["certora", "slither", "forta-bridge-monitor"], commands=["slither bridge_contract.sol --detect arbitrary-send-eth", "forge test --match-contract BridgeTest"], severity="critical"),
]

def build_blockchain_prompt(focus_type: BlockchainAttackType | None = None, max_patterns: int = 5) -> str:
    lines = ["## Blockchain Security Knowledge\n"]
    patterns = BLOCKCHAIN_PATTERNS if not focus_type else [p for p in BLOCKCHAIN_PATTERNS if p.attack_type == focus_type]
    for p in patterns[:max_patterns]:
        lines.append(f"### {p.name} [{p.severity}]")
        lines.append(p.description)
        lines.append("\nVulnerabilities:")
        for v in p.vulnerabilities[:4]:
            lines.append(f"  - {v}")
        lines.append("")
    return "\n".join(lines)
