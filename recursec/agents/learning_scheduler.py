"""Learning scheduler — adaptive learning rate and strategy adjustment.

Implements:
1. Learning rate scheduling (warm-up, cosine decay, cyclical)
2. Exploration/exploitation balance over time
3. Strategy adaptation based on performance
4. Curiosity-driven exploration
5. Skill mastery tracking
6. Learning phase management
7. Knowledge retention scoring
8. Curriculum learning (easy → hard)
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class LearningPhase(str, Enum):
    WARM_UP = "warm_up"          # Initial exploration
    ACTIVE = "active"            # Active learning
    CONSOLIDATION = "consolidation"  # Consolidating knowledge
    MASTERY = "mastery"          # Mastered, minimal learning
    PLATEAU = "plateau"          # Learning has stalled


class ScheduleType(str, Enum):
    CONSTANT = "constant"
    LINEAR_DECAY = "linear_decay"
    COSINE_DECAY = "cosine_decay"
    STEP_DECAY = "step_decay"
    WARM_UP_COSINE = "warm_up_cosine"
    CYCLICAL = "cyclical"


@dataclass
class LearningState:
    """Current learning state for a skill/area."""
    area: str = ""
    phase: LearningPhase = LearningPhase.WARM_UP
    current_rate: float = 0.5
    total_attempts: int = 0
    total_successes: int = 0
    streak: int = 0                  # Consecutive successes
    longest_streak: int = 0
    last_success_time: float = 0.0
    mastery_score: float = 0.0
    curiosity_score: float = 1.0     # Desire to explore this area

    @property
    def success_rate(self) -> float:
        if self.total_attempts == 0:
            return 0.0
        return self.total_successes / self.total_attempts

    @property
    def retention_score(self) -> float:
        """How well knowledge is retained over time."""
        if self.last_success_time == 0:
            return 0.0
        elapsed = time.time() - self.last_success_time
        # Exponential decay with ~1 hour half-life
        return math.exp(-elapsed / 3600.0) * self.mastery_score

    def to_dict(self) -> dict[str, Any]:
        return {
            "area": self.area[:25],
            "phase": self.phase.value,
            "rate": round(self.current_rate, 3),
            "success": round(self.success_rate, 2),
            "mastery": round(self.mastery_score, 2),
            "curiosity": round(self.curiosity_score, 2),
            "streak": self.streak,
        }


@dataclass
class CurriculumItem:
    """An item in the learning curriculum."""
    item_id: str = ""
    area: str = ""
    difficulty: float = 0.5          # 0=easy, 1=hard
    description: str = ""
    prerequisite_areas: list[str] = field(default_factory=list)
    completed: bool = False
    attempts: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.item_id,
            "area": self.area[:20],
            "difficulty": round(self.difficulty, 2),
            "completed": self.completed,
        }


# ── Default Curriculum ────────────────────────────────────────

DEFAULT_CURRICULUM: list[dict[str, Any]] = [
    # Easy: Basic reconnaissance
    {"area": "port_scanning", "difficulty": 0.1, "desc": "Basic port scanning"},
    {"area": "subdomain_enum", "difficulty": 0.15, "desc": "Subdomain enumeration"},
    {"area": "service_detection", "difficulty": 0.2, "desc": "Service fingerprinting"},
    # Medium: Analysis
    {"area": "web_vuln_scanning", "difficulty": 0.3, "desc": "Web vulnerability scanning"},
    {"area": "config_analysis", "difficulty": 0.35, "desc": "Configuration analysis"},
    {"area": "code_review", "difficulty": 0.4, "desc": "Code review for vulnerabilities"},
    {"area": "api_testing", "difficulty": 0.45, "desc": "API security testing"},
    # Hard: Exploitation
    {"area": "exploit_verification", "difficulty": 0.6, "desc": "Exploit verification"},
    {"area": "chain_building", "difficulty": 0.7, "desc": "Attack chain building"},
    {"area": "lateral_movement", "difficulty": 0.8, "desc": "Lateral movement planning"},
    # Expert: Advanced
    {"area": "zero_day_discovery", "difficulty": 0.9, "desc": "Zero-day discovery"},
    {"area": "evasion_analysis", "difficulty": 0.95, "desc": "Defense evasion analysis"},
]


class LearningScheduler:
    """Adaptive learning rate and strategy adjustment.

    Manages exploration/exploitation balance, tracks skill
    mastery, and implements curriculum learning.
    """

    def __init__(
        self,
        schedule_type: ScheduleType = ScheduleType.WARM_UP_COSINE,
        initial_rate: float = 0.5,
        min_rate: float = 0.05,
        warm_up_steps: int = 10,
        total_steps: int = 100,
    ) -> None:
        self._states: dict[str, LearningState] = {}
        self._curriculum: list[CurriculumItem] = []
        self._schedule_type = schedule_type
        self._initial_rate = initial_rate
        self._min_rate = min_rate
        self._warm_up_steps = warm_up_steps
        self._total_steps = total_steps
        self._global_step = 0
        self._item_counter = 0
        self._log = logger.bind(component="learning_scheduler")

        self._initialize_curriculum()

    def _initialize_curriculum(self) -> None:
        """Initialize the learning curriculum."""
        for data in DEFAULT_CURRICULUM:
            self._item_counter += 1
            item = CurriculumItem(
                item_id=f"ci-{self._item_counter}",
                area=data["area"],
                difficulty=data["difficulty"],
                description=data["desc"],
            )
            self._curriculum.append(item)

    def get_learning_rate(self, area: str = "") -> float:
        """Get the current learning rate."""
        self._global_step += 1

        if self._schedule_type == ScheduleType.CONSTANT:
            rate = self._initial_rate
        elif self._schedule_type == ScheduleType.LINEAR_DECAY:
            rate = self._linear_decay()
        elif self._schedule_type == ScheduleType.COSINE_DECAY:
            rate = self._cosine_decay()
        elif self._schedule_type == ScheduleType.STEP_DECAY:
            rate = self._step_decay()
        elif self._schedule_type == ScheduleType.WARM_UP_COSINE:
            rate = self._warm_up_cosine()
        elif self._schedule_type == ScheduleType.CYCLICAL:
            rate = self._cyclical()
        else:
            rate = self._initial_rate

        # Area-specific adjustment
        if area:
            state = self._get_state(area)
            state.current_rate = rate
            # Reduce rate if mastered
            if state.mastery_score > 0.8:
                rate *= 0.3

        return max(self._min_rate, rate)

    def record_attempt(
        self,
        area: str,
        success: bool,
    ) -> LearningState:
        """Record a learning attempt."""
        state = self._get_state(area)
        state.total_attempts += 1

        if success:
            state.total_successes += 1
            state.streak += 1
            state.longest_streak = max(state.longest_streak, state.streak)
            state.last_success_time = time.time()
        else:
            state.streak = 0

        # Update mastery
        state.mastery_score = self._calculate_mastery(state)

        # Update curiosity
        state.curiosity_score = self._calculate_curiosity(state)

        # Update phase
        state.phase = self._determine_phase(state)

        # Update curriculum
        self._update_curriculum(area, success)

        return state

    def get_exploration_rate(self) -> float:
        """Get the current exploration rate (epsilon for epsilon-greedy)."""
        # Start high (explore), decay over time
        base = 1.0 - (self._global_step / max(1, self._total_steps))
        return max(0.05, base * 0.5)

    def get_next_curriculum_item(self) -> CurriculumItem | None:
        """Get the next item in the curriculum."""
        # Find the lowest-difficulty uncompleted item
        # where prerequisites are met
        available = []
        completed_areas = {
            item.area for item in self._curriculum if item.completed
        }

        for item in self._curriculum:
            if item.completed:
                continue

            # Check prerequisites
            prereqs_met = all(
                p in completed_areas
                for p in item.prerequisite_areas
            )
            if prereqs_met:
                available.append(item)

        if not available:
            return None

        # Sort by difficulty (easy first) with curiosity boost
        return min(
            available,
            key=lambda i: i.difficulty - self._get_state(i.area).curiosity_score * 0.1,
        )

    def _calculate_mastery(self, state: LearningState) -> float:
        """Calculate mastery score."""
        if state.total_attempts == 0:
            return 0.0

        success_factor = state.success_rate
        streak_factor = min(1.0, state.longest_streak / 5.0)
        volume_factor = min(1.0, state.total_attempts / 20.0)

        return (success_factor * 0.5 + streak_factor * 0.3 + volume_factor * 0.2)

    def _calculate_curiosity(self, state: LearningState) -> float:
        """Calculate curiosity — higher for new/unseen areas."""
        if state.total_attempts == 0:
            return 1.0

        # Curiosity decreases with attempts
        base_curiosity = 1.0 / (1.0 + state.total_attempts * 0.1)

        # But increases with time since last attempt
        if state.last_success_time > 0:
            elapsed = time.time() - state.last_success_time
            time_boost = min(0.3, elapsed / 3600.0)
            base_curiosity += time_boost

        return min(1.0, base_curiosity)

    def _determine_phase(self, state: LearningState) -> LearningPhase:
        """Determine the learning phase."""
        if state.total_attempts < 3:
            return LearningPhase.WARM_UP

        if state.mastery_score > 0.8:
            return LearningPhase.MASTERY

        if state.mastery_score > 0.5:
            return LearningPhase.CONSOLIDATION

        # Check for plateau
        if state.total_attempts > 10 and state.success_rate < 0.3:
            return LearningPhase.PLATEAU

        return LearningPhase.ACTIVE

    def _update_curriculum(self, area: str, success: bool) -> None:
        """Update curriculum based on performance."""
        for item in self._curriculum:
            if item.area == area:
                item.attempts += 1
                if success and item.attempts >= 3:
                    item.completed = True

    def _get_state(self, area: str) -> LearningState:
        if area not in self._states:
            self._states[area] = LearningState(area=area)
        return self._states[area]

    # ── Schedule Functions ─────────────────────────────────────

    def _linear_decay(self) -> float:
        progress = self._global_step / max(1, self._total_steps)
        return self._initial_rate * (1.0 - progress)

    def _cosine_decay(self) -> float:
        progress = self._global_step / max(1, self._total_steps)
        return self._min_rate + (self._initial_rate - self._min_rate) * \
            0.5 * (1 + math.cos(math.pi * progress))

    def _step_decay(self) -> float:
        steps = self._global_step // max(1, self._total_steps // 4)
        return self._initial_rate * (0.5 ** steps)

    def _warm_up_cosine(self) -> float:
        if self._global_step < self._warm_up_steps:
            return self._initial_rate * (self._global_step / max(1, self._warm_up_steps))
        return self._cosine_decay()

    def _cyclical(self) -> float:
        cycle_length = max(1, self._total_steps // 5)
        position = self._global_step % cycle_length
        progress = position / cycle_length
        return self._min_rate + (self._initial_rate - self._min_rate) * \
            0.5 * (1 + math.cos(math.pi * progress))

    def get_curriculum(self) -> list[dict[str, Any]]:
        return [i.to_dict() for i in self._curriculum]

    def get_stats(self) -> dict[str, Any]:
        mastered = sum(1 for s in self._states.values() if s.phase == LearningPhase.MASTERY)
        completed_items = sum(1 for i in self._curriculum if i.completed)
        return {
            "global_step": self._global_step,
            "areas": len(self._states),
            "mastered": mastered,
            "curriculum_progress": f"{completed_items}/{len(self._curriculum)}",
            "exploration_rate": round(self.get_exploration_rate(), 3),
        }
