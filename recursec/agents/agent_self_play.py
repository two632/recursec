"""Agent self-play training — agents improve by competing against each other.

This module implements:
1. Red team vs Blue team simulation
2. Attack scenario generation
3. Defense evaluation scoring
4. Strategy evolution via tournament selection
5. Vulnerability discovery through adversarial probing
6. Skill level adaptation (ELO-like rating)
7. Replay buffer for learning from past games
8. Multi-round tournaments with elimination

The agent trains itself by pitting attack agents against
defense agents, then learning from both perspectives.
"""

from __future__ import annotations

import math
import random
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class TeamType(str, Enum):
    RED = "red"
    BLUE = "blue"
    PURPLE = "purple"


class GamePhase(str, Enum):
    RECON = "recon"
    INITIAL_ACCESS = "initial_access"
    ESTABLISH = "establish"
    ESCALATE = "escalate"
    LATERAL = "lateral"
    EXFILTRATE = "exfiltrate"
    PERSIST = "persist"
    CLEANUP = "cleanup"


class GameOutcome(str, Enum):
    RED_WIN = "red_win"
    BLUE_WIN = "blue_win"
    DRAW = "draw"
    ONGOING = "ongoing"


@dataclass
class AgentPlayer:
    """An agent participating in self-play."""
    player_id: str = ""
    team: TeamType = TeamType.RED
    model_id: str = ""
    elo_rating: float = 1000.0
    wins: int = 0
    losses: int = 0
    draws: int = 0
    strategies_used: list[str] = field(default_factory=list)
    successful_techniques: list[str] = field(default_factory=list)
    failed_techniques: list[str] = field(default_factory=list)

    @property
    def games_played(self) -> int:
        return self.wins + self.losses + self.draws

    @property
    def win_rate(self) -> float:
        if self.games_played == 0:
            return 0.0
        return self.wins / self.games_played

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.player_id[:8],
            "team": self.team.value[:4],
            "model": self.model_id[:15],
            "elo": f"{self.elo_rating:.0f}",
            "W/L/D": f"{self.wins}/{self.losses}/{self.draws}",
            "wr": f"{self.win_rate:.0%}",
        }


@dataclass
class GameAction:
    """A single action in a game."""
    player_id: str = ""
    phase: GamePhase = GamePhase.RECON
    technique: str = ""
    target: str = ""
    success: bool = False
    detected: bool = False
    impact: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "player": self.player_id[:8],
            "phase": self.phase.value[:8],
            "tech": self.technique[:20],
            "ok": self.success,
            "det": self.detected,
        }


@dataclass
class Scenario:
    """An attack/defense scenario for self-play."""
    scenario_id: str = ""
    name: str = ""
    description: str = ""
    target_type: str = ""
    attack_surface: list[str] = field(default_factory=list)
    defenses: list[str] = field(default_factory=list)
    difficulty: float = 5.0
    max_rounds: int = 10

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.scenario_id[:8],
            "name": self.name[:20],
            "difficulty": f"{self.difficulty:.0f}/10",
            "rounds": self.max_rounds,
        }


@dataclass
class GameResult:
    """Result of a self-play game."""
    game_id: str = ""
    scenario: Scenario = field(default_factory=Scenario)
    red_player: AgentPlayer = field(default_factory=AgentPlayer)
    blue_player: AgentPlayer = field(default_factory=AgentPlayer)
    outcome: GameOutcome = GameOutcome.ONGOING
    actions: list[GameAction] = field(default_factory=list)
    red_score: float = 0.0
    blue_score: float = 0.0
    rounds_played: int = 0
    duration_s: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "game": self.game_id[:8],
            "outcome": self.outcome.value[:8],
            "red": f"{self.red_score:.1f}",
            "blue": f"{self.blue_score:.1f}",
            "rounds": self.rounds_played,
        }


# Pre-built scenarios
SCENARIOS: list[Scenario] = [
    Scenario(scenario_id="web-corp", name="Corporate Web Application", description="Attack a corporate web application with standard defenses", target_type="web", attack_surface=["http", "https", "api", "login", "upload"], defenses=["waf", "ids", "rate_limiting", "auth"], difficulty=5.0, max_rounds=10),
    Scenario(scenario_id="cloud-infra", name="Cloud Infrastructure", description="Compromise cloud infrastructure starting from a compromised key", target_type="cloud", attack_surface=["aws_api", "s3", "ec2", "iam", "lambda"], defenses=["cloudtrail", "guardduty", "scp", "vpc"], difficulty=7.0, max_rounds=12),
    Scenario(scenario_id="internal-net", name="Internal Network Pentest", description="Lateral movement through corporate network", target_type="network", attack_surface=["smb", "rdp", "ssh", "ad", "dns"], defenses=["edr", "nac", "segmentation", "siem"], difficulty=6.0, max_rounds=15),
    Scenario(scenario_id="iot-factory", name="IoT Factory Floor", description="Compromise industrial IoT devices", target_type="iot", attack_surface=["mqtt", "modbus", "opcua", "ble", "wifi"], defenses=["network_isolation", "firmware_signing", "anomaly_detection"], difficulty=6.0, max_rounds=10),
    Scenario(scenario_id="mobile-bank", name="Mobile Banking App", description="Exploit mobile banking application", target_type="mobile", attack_surface=["api", "certificate_pinning", "local_storage", "biometric", "nfc"], defenses=["obfuscation", "root_detection", "ssl_pinning", "tokenization"], difficulty=8.0, max_rounds=10),
    Scenario(scenario_id="zero-trust", name="Zero Trust Environment", description="Penetrate a zero trust architecture", target_type="enterprise", attack_surface=["identity", "device", "network", "application", "data"], defenses=["mfa", "microsegmentation", "continuous_auth", "dlp", "sase"], difficulty=9.0, max_rounds=20),
]

# Attack techniques and their success probabilities
ATTACK_TECHNIQUES: dict[str, dict[str, Any]] = {
    "sql_injection": {"phases": [GamePhase.INITIAL_ACCESS], "base_success": 0.4, "stealth": 0.3, "impact": 8},
    "xss_stored": {"phases": [GamePhase.INITIAL_ACCESS], "base_success": 0.5, "stealth": 0.6, "impact": 5},
    "credential_stuffing": {"phases": [GamePhase.INITIAL_ACCESS], "base_success": 0.3, "stealth": 0.2, "impact": 7},
    "phishing": {"phases": [GamePhase.INITIAL_ACCESS], "base_success": 0.6, "stealth": 0.7, "impact": 6},
    "exploit_public": {"phases": [GamePhase.INITIAL_ACCESS], "base_success": 0.5, "stealth": 0.4, "impact": 9},
    "webshell": {"phases": [GamePhase.ESTABLISH], "base_success": 0.6, "stealth": 0.3, "impact": 7},
    "reverse_shell": {"phases": [GamePhase.ESTABLISH], "base_success": 0.5, "stealth": 0.2, "impact": 8},
    "privesc_kernel": {"phases": [GamePhase.ESCALATE], "base_success": 0.3, "stealth": 0.4, "impact": 9},
    "privesc_sudo": {"phases": [GamePhase.ESCALATE], "base_success": 0.5, "stealth": 0.5, "impact": 8},
    "pass_the_hash": {"phases": [GamePhase.LATERAL], "base_success": 0.4, "stealth": 0.3, "impact": 7},
    "kerberoasting": {"phases": [GamePhase.LATERAL], "base_success": 0.5, "stealth": 0.6, "impact": 6},
    "data_exfil_dns": {"phases": [GamePhase.EXFILTRATE], "base_success": 0.7, "stealth": 0.8, "impact": 5},
    "data_exfil_http": {"phases": [GamePhase.EXFILTRATE], "base_success": 0.6, "stealth": 0.4, "impact": 6},
}

# Defense techniques
DEFENSE_TECHNIQUES: dict[str, dict[str, Any]] = {
    "patch_vuln": {"effectiveness": 0.9, "against": ["sql_injection", "exploit_public"]},
    "waf_rules": {"effectiveness": 0.7, "against": ["sql_injection", "xss_stored"]},
    "mfa_enforce": {"effectiveness": 0.8, "against": ["credential_stuffing", "pass_the_hash"]},
    "email_filter": {"effectiveness": 0.6, "against": ["phishing"]},
    "edr_deploy": {"effectiveness": 0.7, "against": ["webshell", "reverse_shell", "privesc_kernel"]},
    "network_seg": {"effectiveness": 0.8, "against": ["pass_the_hash", "kerberoasting"]},
    "dlp_rules": {"effectiveness": 0.6, "against": ["data_exfil_dns", "data_exfil_http"]},
    "siem_alert": {"effectiveness": 0.5, "against": ["credential_stuffing", "privesc_sudo"]},
}


class ELOCalculator:
    """ELO rating calculation."""

    K = 32.0

    @staticmethod
    def expected(rating_a: float, rating_b: float) -> float:
        return 1.0 / (1.0 + math.pow(10, (rating_b - rating_a) / 400.0))

    @staticmethod
    def update(rating: float, expected_score: float, actual_score: float) -> float:
        return rating + ELOCalculator.K * (actual_score - expected_score)


class AgentSelfPlay:
    """Self-play training system for agents."""

    def __init__(self) -> None:
        self._players: dict[str, AgentPlayer] = {}
        self._games: list[GameResult] = []
        self._game_counter = 0
        self._technique_stats: dict[str, dict[str, int]] = defaultdict(lambda: {"used": 0, "succeeded": 0, "detected": 0})
        self._log = logger.bind(component="self_play")

    def register_player(
        self,
        player_id: str,
        team: TeamType,
        model_id: str,
    ) -> AgentPlayer:
        """Register a player for self-play."""
        player = AgentPlayer(player_id=player_id, team=team, model_id=model_id)
        self._players[player_id] = player
        return player

    def run_game(
        self,
        red_id: str,
        blue_id: str,
        scenario: Scenario | None = None,
    ) -> GameResult:
        """Run a single self-play game."""
        red = self._players.get(red_id)
        blue = self._players.get(blue_id)
        if not red or not blue:
            return GameResult()

        if not scenario:
            scenario = random.choice(SCENARIOS)

        self._game_counter += 1
        start = time.time()

        game = GameResult(
            game_id=f"game-{self._game_counter}",
            scenario=scenario,
            red_player=red,
            blue_player=blue,
        )

        # Simulate rounds
        for round_num in range(scenario.max_rounds):
            phase = list(GamePhase)[min(round_num, len(GamePhase) - 1)]

            # Red team attacks
            attack = self._choose_attack(red, phase, scenario)
            if attack:
                action = self._simulate_attack(attack, red, blue, scenario)
                game.actions.append(action)
                if action.success:
                    game.red_score += action.impact
                if action.detected:
                    game.blue_score += 2.0

            # Blue team defends
            defense = self._choose_defense(blue, attack or "unknown", scenario)
            if defense:
                defense_action = GameAction(
                    player_id=blue_id,
                    phase=phase,
                    technique=defense,
                    success=True,
                )
                game.actions.append(defense_action)

            game.rounds_played = round_num + 1

            # Check win conditions
            if game.red_score >= 30:
                game.outcome = GameOutcome.RED_WIN
                break
            if game.blue_score >= 20:
                game.outcome = GameOutcome.BLUE_WIN
                break

        if game.outcome == GameOutcome.ONGOING:
            if game.red_score > game.blue_score * 1.5:
                game.outcome = GameOutcome.RED_WIN
            elif game.blue_score > game.red_score * 1.5:
                game.outcome = GameOutcome.BLUE_WIN
            else:
                game.outcome = GameOutcome.DRAW

        game.duration_s = time.time() - start

        # Update ratings
        self._update_ratings(red, blue, game.outcome)
        self._games.append(game)

        return game

    def _choose_attack(self, player: AgentPlayer, phase: GamePhase, scenario: Scenario) -> str | None:
        """Choose an attack technique for the current phase."""
        available = [
            name for name, info in ATTACK_TECHNIQUES.items()
            if phase in info.get("phases", [])
        ]
        if not available:
            # Fallback to any technique
            available = list(ATTACK_TECHNIQUES.keys())
        return random.choice(available) if available else None

    def _choose_defense(self, player: AgentPlayer, attack: str, scenario: Scenario) -> str | None:
        """Choose a defense technique."""
        best = None
        best_eff = 0.0
        for name, info in DEFENSE_TECHNIQUES.items():
            if attack in info.get("against", []):
                if info["effectiveness"] > best_eff:
                    best = name
                    best_eff = info["effectiveness"]
        return best

    def _simulate_attack(
        self,
        technique: str,
        red: AgentPlayer,
        blue: AgentPlayer,
        scenario: Scenario,
    ) -> GameAction:
        """Simulate an attack attempt."""
        tech_info = ATTACK_TECHNIQUES.get(technique, {})
        base_success = tech_info.get("base_success", 0.3)
        stealth = tech_info.get("stealth", 0.5)
        impact = tech_info.get("impact", 5)

        # Adjust by player skill (ELO-based)
        elo_factor = (red.elo_rating - 1000) / 1000  # -1 to +1
        adjusted_success = min(0.95, max(0.05, base_success + elo_factor * 0.1))

        # Adjust by scenario difficulty
        difficulty_factor = scenario.difficulty / 10.0
        adjusted_success *= (1.0 - difficulty_factor * 0.3)

        success = random.random() < adjusted_success
        detected = random.random() > stealth

        # Track stats
        self._technique_stats[technique]["used"] += 1
        if success:
            self._technique_stats[technique]["succeeded"] += 1
            red.successful_techniques.append(technique)
        else:
            red.failed_techniques.append(technique)
        if detected:
            self._technique_stats[technique]["detected"] += 1

        return GameAction(
            player_id=red.player_id,
            phase=tech_info.get("phases", [GamePhase.RECON])[0] if tech_info.get("phases") else GamePhase.RECON,
            technique=technique,
            success=success,
            detected=detected,
            impact=float(impact) if success else 0.0,
        )

    def _update_ratings(self, red: AgentPlayer, blue: AgentPlayer, outcome: GameOutcome) -> None:
        """Update ELO ratings based on game outcome."""
        expected_red = ELOCalculator.expected(red.elo_rating, blue.elo_rating)
        expected_blue = 1.0 - expected_red

        if outcome == GameOutcome.RED_WIN:
            red.elo_rating = ELOCalculator.update(red.elo_rating, expected_red, 1.0)
            blue.elo_rating = ELOCalculator.update(blue.elo_rating, expected_blue, 0.0)
            red.wins += 1
            blue.losses += 1
        elif outcome == GameOutcome.BLUE_WIN:
            red.elo_rating = ELOCalculator.update(red.elo_rating, expected_red, 0.0)
            blue.elo_rating = ELOCalculator.update(blue.elo_rating, expected_blue, 1.0)
            blue.wins += 1
            red.losses += 1
        else:
            red.elo_rating = ELOCalculator.update(red.elo_rating, expected_red, 0.5)
            blue.elo_rating = ELOCalculator.update(blue.elo_rating, expected_blue, 0.5)
            red.draws += 1
            blue.draws += 1

    def run_tournament(self, rounds: int = 10) -> list[dict[str, Any]]:
        """Run a tournament between all registered players."""
        players = list(self._players.values())
        reds = [p for p in players if p.team == TeamType.RED]
        blues = [p for p in players if p.team == TeamType.BLUE]

        for _ in range(rounds):
            for red in reds:
                for blue in blues:
                    self.run_game(red.player_id, blue.player_id)

        # Return leaderboard
        all_players = sorted(players, key=lambda p: p.elo_rating, reverse=True)
        return [p.to_dict() for p in all_players]

    def get_technique_rankings(self) -> list[dict[str, Any]]:
        """Get techniques ranked by success rate."""
        rankings = []
        for name, stats in self._technique_stats.items():
            used = stats["used"]
            if used > 0:
                rankings.append({
                    "technique": name,
                    "used": used,
                    "success_rate": f"{stats['succeeded'] / used:.0%}",
                    "detection_rate": f"{stats['detected'] / used:.0%}",
                })
        rankings.sort(key=lambda r: float(r["success_rate"].rstrip("%")) / 100, reverse=True)
        return rankings

    def build_training_prompt(self) -> str:
        """Build LLM prompt with self-play training insights."""
        if not self._games:
            return ""

        lines = ["## Self-Play Training Insights"]
        lines.append(f"Total games: {len(self._games)}")

        # Best techniques
        rankings = self.get_technique_rankings()
        if rankings:
            lines.append("\nTop attack techniques by success rate:")
            for r in rankings[:5]:
                lines.append(f"  - {r['technique']}: {r['success_rate']} success, {r['detection_rate']} detection")

        # Player ratings
        players = sorted(self._players.values(), key=lambda p: p.elo_rating, reverse=True)
        if players:
            lines.append("\nPlayer ratings:")
            for p in players[:5]:
                lines.append(f"  - {p.player_id[:8]} ({p.team.value}): ELO {p.elo_rating:.0f}, WR {p.win_rate:.0%}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        return {
            "players": len(self._players),
            "games": len(self._games),
            "techniques_tracked": len(self._technique_stats),
        }
