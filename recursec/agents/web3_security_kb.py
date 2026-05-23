"""Web3 / blockchain security knowledge base.

Deep knowledge about blockchain and smart contract security:
1. Smart contract vulnerabilities (Solidity/Vyper)
2. DeFi attack patterns
3. Bridge and cross-chain attacks
4. NFT security issues
5. Wallet security
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class Web3VulnPattern:
    """A Web3 vulnerability pattern."""
    pattern_id: str = ""
    name: str = ""
    category: str = ""
    severity: str = "high"
    swc_id: str = ""             # Smart Contract Weakness Classification
    description: str = ""
    testing_methodology: str = ""
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:30],
            "swc": self.swc_id[:8],
        }


WEB3_VULN_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "w3-001", "name": "Smart Contract Vulnerabilities",
        "category": "smart_contract", "severity": "critical",
        "swc_id": "SWC-100+",
        "desc": "Common Solidity smart contract vulnerabilities.",
        "testing": (
            "SMART CONTRACT VULNERABILITIES:\n"
            "1. REENTRANCY (SWC-107):\n"
            "   - Pattern: External call before state update\n"
            "   - Classic: The DAO hack (2016, $60M)\n"
            "   - Detection:\n"
            "     * Look for .call{value: amount}('') before state changes\n"
            "     * Check for CEI pattern violation (Check-Effects-Interactions)\n"
            "     * Cross-function reentrancy: Function A calls external → re-enters Function B\n"
            "   - Tools:\n"
            "     slither contract.sol --detect reentrancy-eth\n"
            "     mythril analyze contract.sol\n"
            "   - Fix: Use OpenZeppelin ReentrancyGuard, follow CEI pattern\n"
            "2. INTEGER OVERFLOW/UNDERFLOW (SWC-101):\n"
            "   - Pre-Solidity 0.8: No built-in overflow checks\n"
            "   - uint256 max = 2^256-1, overflow wraps to 0\n"
            "   - Check: uint balances + amounts, token transfer calculations\n"
            "   - Fix: SafeMath library (pre-0.8), unchecked{} blocks (0.8+)\n"
            "3. ACCESS CONTROL (SWC-105):\n"
            "   - Missing onlyOwner/role checks on sensitive functions\n"
            "   - tx.origin vs msg.sender confusion\n"
            "   - Uninitialized proxy admin\n"
            "   - Default visibility (public by default for functions)\n"
            "   - Check: Who can call initialize(), mint(), pause(), selfdestruct()\n"
            "4. FLASH LOAN ATTACKS:\n"
            "   - Borrow large amount → manipulate oracle/price → profit → repay\n"
            "   - Check: Oracle dependence, single-block price manipulation\n"
            "   - Target: DEX pools, lending protocols, yield aggregators\n"
            "5. DELEGATECALL (SWC-112):\n"
            "   - delegatecall executes in caller's storage context\n"
            "   - Storage slot collision between proxy and implementation\n"
            "   - Uninitialized implementation contract (can be selfdestruct)\n"
            "6. FRONT-RUNNING (SWC-114):\n"
            "   - MEV bots monitor mempool for profitable transactions\n"
            "   - Sandwich attacks on DEX swaps\n"
            "   - Check: commit-reveal schemes, private mempools\n"
            "7. STATIC ANALYSIS:\n"
            "   slither . --detect all\n"
            "   mythril analyze contracts/Token.sol\n"
            "   securify2 contracts/\n"
            "   solhint contracts/**/*.sol"
        ),
        "tools": ["Slither", "Mythril", "Securify2", "Solhint", "Foundry"],
    },
    {
        "id": "w3-002", "name": "DeFi Protocol Attacks",
        "category": "defi", "severity": "critical",
        "swc_id": "N/A",
        "desc": "DeFi-specific attack patterns.",
        "testing": (
            "DEFI PROTOCOL ATTACKS:\n"
            "1. ORACLE MANIPULATION:\n"
            "   - Spot price oracles (DEX TWAP manipulation)\n"
            "   - Chainlink feed staleness check\n"
            "   - Check: priceOracle.getPrice() — is it manipulable in one tx?\n"
            "   - Attack: Flash loan → swap in DEX → manipulate price → borrow against inflated collateral\n"
            "   - Example: Cream Finance ($130M), Mango Markets ($114M)\n"
            "2. GOVERNANCE ATTACKS:\n"
            "   - Flash loan → acquire voting tokens → pass malicious proposal\n"
            "   - Timelock bypass: Emergency execute without delay\n"
            "   - Delegate vote concentration\n"
            "   - Check: Quorum requirements, voting period, timelock delay\n"
            "3. LIQUIDITY POOL ATTACKS:\n"
            "   - Impermanent loss exploitation\n"
            "   - Sandwich attacks on large swaps:\n"
            "     * Front-run: Buy before victim's large buy\n"
            "     * Back-run: Sell after victim's transaction\n"
            "   - JIT (Just-In-Time) liquidity: Add liquidity before large trade, remove after\n"
            "4. LENDING PROTOCOL:\n"
            "   - Collateral factor manipulation\n"
            "   - Liquidation cascading\n"
            "   - Interest rate manipulation\n"
            "   - Bad debt accumulation\n"
            "5. YIELD AGGREGATOR:\n"
            "   - Vault share inflation attack:\n"
            "     * Deposit 1 wei → donate large amount → dilute next depositor\n"
            "   - Strategy migration exploit\n"
            "   - Harvest timing manipulation\n"
            "6. TESTING APPROACH:\n"
            "   - Fork mainnet with Foundry:\n"
            "     forge test --fork-url https://eth-mainnet.alchemyapi.io/v2/KEY\n"
            "   - Write PoC exploits as test cases\n"
            "   - Simulate flash loan attacks"
        ),
        "tools": ["Foundry", "Hardhat", "Echidna", "Medusa"],
    },
    {
        "id": "w3-003", "name": "Bridge & Cross-Chain Attacks",
        "category": "bridge", "severity": "critical",
        "swc_id": "N/A",
        "desc": "Cross-chain bridge vulnerabilities.",
        "testing": (
            "BRIDGE & CROSS-CHAIN ATTACKS:\n"
            "1. MESSAGE VERIFICATION:\n"
            "   - Insufficient signature validation\n"
            "   - Missing chain ID in signed messages\n"
            "   - Replay attacks across chains\n"
            "   - Example: Ronin Bridge ($625M) — compromised 5/9 validators\n"
            "2. VALIDATOR SET:\n"
            "   - Centralized validator set (few signers)\n"
            "   - Compromised multisig (Ronin, Harmony)\n"
            "   - Check: How many validators needed to approve transfer?\n"
            "   - Check: Are validator keys properly secured (HSM)?\n"
            "3. TOKEN MAPPING:\n"
            "   - Fake token deposit on source chain\n"
            "   - Wrapped token minting without burn proof\n"
            "   - Example: Wormhole ($320M) — signature verification bypass\n"
            "4. RELAY MANIPULATION:\n"
            "   - Malicious relayer submitting fake proofs\n"
            "   - Light client header manipulation\n"
            "   - Check: Proof verification logic, challenge period\n"
            "5. TESTING:\n"
            "   - Review bridge contracts on both chains\n"
            "   - Check validator/relayer architecture\n"
            "   - Verify message format and signing scheme\n"
            "   - Test replay protection"
        ),
        "tools": ["Slither", "Foundry", "Manual Review"],
    },
    {
        "id": "w3-004", "name": "NFT & Token Security",
        "category": "nft", "severity": "high",
        "swc_id": "N/A",
        "desc": "NFT and ERC20/721/1155 token vulnerabilities.",
        "testing": (
            "NFT & TOKEN SECURITY:\n"
            "1. ERC20 ISSUES:\n"
            "   - Approval race condition (front-run approve change)\n"
            "   - Fee-on-transfer tokens breaking protocols\n"
            "   - Rebasing tokens (elastic supply)\n"
            "   - Transfer hooks (ERC777 reentrancy via tokensReceived)\n"
            "   - Blacklist/pause functionality abuse\n"
            "2. ERC721/1155 ISSUES:\n"
            "   - Unchecked return value of onERC721Received\n"
            "   - Reentrancy via onERC721Received callback\n"
            "   - Token ID enumeration and sniping\n"
            "   - Metadata manipulation (off-chain storage)\n"
            "3. MINT ATTACKS:\n"
            "   - Free mint: Bypass payment check\n"
            "   - Over-mint: Exceed max supply\n"
            "   - Contract mint: Bypass isContract check (constructor call)\n"
            "   - Signature replay for whitelist mints\n"
            "4. MARKETPLACE ATTACKS:\n"
            "   - Listing manipulation (change listing while bid pending)\n"
            "   - Royalty bypass (direct transfer instead of marketplace)\n"
            "   - Phishing: setApprovalForAll to attacker\n"
            "5. TESTING:\n"
            "   - Verify mint restrictions\n"
            "   - Check approval/transfer functions\n"
            "   - Test marketplace integration\n"
            "   - Verify metadata immutability or access control"
        ),
        "tools": ["Slither", "Foundry", "OpenZeppelin Defender"],
    },
]


class Web3SecurityKB:
    """Web3 / blockchain security knowledge base.

    Provides deep smart contract and DeFi security
    methodology injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, Web3VulnPattern] = {}
        self._log = logger.bind(component="web3_security_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load Web3 vulnerability patterns."""
        for data in WEB3_VULN_PATTERNS:
            pattern = Web3VulnPattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                swc_id=data.get("swc_id", ""),
                description=data.get("desc", ""),
                testing_methodology=data.get("testing", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_patterns_for_category(
        self,
        category: str,
    ) -> list[Web3VulnPattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category == category
        ]

    def build_web3_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 3,
    ) -> str:
        """Build Web3 security prompt."""
        lines = ["## Web3 / Blockchain Security\n"]
        count = 0
        for pattern in self._patterns.values():
            if categories and pattern.category not in categories:
                continue
            if count >= max_patterns:
                break
            lines.append(f"### {pattern.name} [{pattern.severity.upper()}]")
            if pattern.swc_id:
                lines.append(f"SWC: {pattern.swc_id}")
            lines.append(pattern.testing_methodology)
            lines.append("")
            count += 1
        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        cat_counts: dict[str, int] = defaultdict(int)
        for p in self._patterns.values():
            cat_counts[p.category] += 1
        return {
            "patterns": len(self._patterns),
            "by_category": dict(cat_counts),
        }
