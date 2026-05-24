"""Gaming and anti-cheat security knowledge base."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

class GamingAttackType(str, Enum):
    CLIENT = "client"
    SERVER = "server"
    NETWORK = "network"
    ECONOMY = "economy"
    ANTI_CHEAT = "anti_cheat"

@dataclass
class GamingPattern:
    name: str = ""
    attack_type: GamingAttackType = GamingAttackType.CLIENT
    description: str = ""
    techniques: list[str] = field(default_factory=list)
    detection: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    severity: str = "high"
    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "type": self.attack_type.value, "severity": self.severity}

GAMING_PATTERNS: list[GamingPattern] = [
    GamingPattern(name="Client-Side Exploitation", attack_type=GamingAttackType.CLIENT, description="Game client modification: memory editing, DLL injection, asset manipulation.", techniques=["Memory scanning and editing (Cheat Engine, game guardians)", "DLL injection for function hooking", "Game asset/texture modification (wallhacks)", "Client binary patching (unlock features)", "Shader modification for ESP/visual cheats", "Input simulation for aimbots (mouse/keyboard hooking)", "Game file integrity bypass"], detection=["Client integrity verification (hash checking)", "Memory scanning for known cheat signatures", "Kernel-level anti-cheat drivers", "Behavioral analysis (aim patterns, reaction time)"], tools=["cheat-engine", "ida-pro", "x64dbg", "ghidra"], severity="high"),
    GamingPattern(name="Server Exploitation", attack_type=GamingAttackType.SERVER, description="Game server attacks: command injection, privilege escalation, data manipulation.", techniques=["Game server command injection (RCON abuse)", "SQL injection in leaderboard/profile systems", "Server-side item/currency duplication glitches", "Admin panel exploitation", "Docker container escape from game server", "Game server DDoS (amplification via game protocols)", "Matchmaking system manipulation"], detection=["RCON authentication and rate limiting", "Server-side validation of all game state changes", "Transaction logging for economy operations", "DDoS protection and rate limiting"], tools=["nmap", "sqlmap", "burpsuite"], severity="critical"),
    GamingPattern(name="Network Protocol Attacks", attack_type=GamingAttackType.NETWORK, description="Game network protocol exploitation: packet manipulation, desync, prediction abuse.", techniques=["Packet sniffing for game state information", "Packet replay for action duplication", "Speed hacking via packet timing manipulation", "Desynchronization attacks (teleporting)", "Man-in-the-middle on game traffic (proxy)", "UDP amplification via game server protocol", "Netcode exploitation (favor-the-shooter abuse)"], detection=["Server-side movement validation", "Packet sequence number verification", "Encryption of game protocol traffic", "Server-side rate limiting of actions"], tools=["wireshark", "nmap", "custom-game-proxy"], severity="high"),
    GamingPattern(name="Game Economy Attacks", attack_type=GamingAttackType.ECONOMY, description="Virtual economy exploitation: duplication, RMT, market manipulation.", techniques=["Item duplication via race conditions", "Gold farming automation (botting)", "Real Money Trading (RMT) infrastructure", "Auction house price manipulation", "Cryptocurrency mining via game client", "Gift/trade system abuse for money laundering", "Gacha/lootbox probability manipulation verification"], detection=["Economic anomaly detection (inflation, deflation)", "Bot detection via behavioral analysis", "Trade pattern monitoring", "Velocity checks on virtual currency"], tools=["custom-bot-detection", "data-analytics"], severity="medium"),
    GamingPattern(name="Anti-Cheat Bypass", attack_type=GamingAttackType.ANTI_CHEAT, description="Bypassing anti-cheat systems: EAC, BattlEye, Vanguard, VAC.", techniques=["Kernel driver exploitation for anti-cheat bypass", "Hypervisor-based cheating (run cheat below anti-cheat)", "DMA (Direct Memory Access) hardware cheating", "Manual mapping to evade module detection", "Syscall hooking to intercept anti-cheat queries", "Virtual machine detection evasion", "Anti-cheat driver vulnerability exploitation (CVEs)"], detection=["Kernel integrity verification", "Hypervisor detection", "DMA detection via IOMMU", "Hardware attestation", "Behavioral analysis as fallback"], tools=["ida-pro", "windbg", "hypervisor-tools"], severity="high"),
]

def build_gaming_security_prompt(focus_type: GamingAttackType | None = None, max_patterns: int = 5) -> str:
    lines = ["## Gaming & Anti-Cheat Security Knowledge\n"]
    patterns = GAMING_PATTERNS if not focus_type else [p for p in GAMING_PATTERNS if p.attack_type == focus_type]
    for p in patterns[:max_patterns]:
        lines.append(f"### {p.name} [{p.severity}]")
        lines.append(p.description)
        lines.append("\nTechniques:")
        for t in p.techniques[:4]:
            lines.append(f"  - {t}")
        lines.append("")
    return "\n".join(lines)
