"""Strategy evolution engine — adapts strategies from outcomes.

Implements:
1. Strategy genome (parameters that define approach)
2. Fitness scoring from assessment outcomes
3. Mutation and crossover operators
4. Population management (top strategies)
5. Environmental pressure (target-adaptive)
6. Strategy evolution prompt for LLM
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class StrategyGenome:
    """A strategy encoded as a genome of parameters."""
    genome_id: str = ""
    name: str = ""
    generation: int = 0
    parent_ids: list[str] = field(default_factory=list)

    # Strategy parameters (0-1 range)
    aggression: float = 0.5          # How aggressive vs stealthy
    breadth: float = 0.5             # Wide scan vs deep focus
    parallelism: float = 0.5         # How many parallel agents
    tool_diversity: float = 0.5      # How many different tools
    validation_rigor: float = 0.5    # How thorough validation
    exploitation_depth: float = 0.5  # How deep to exploit
    recon_depth: float = 0.5         # How thorough recon
    model_diversity: float = 0.5     # How many models to use
    time_allocation_recon: float = 0.3
    time_allocation_exploit: float = 0.4
    time_allocation_postex: float = 0.3

    # Fitness tracking
    fitness: float = 0.0
    assessments: int = 0
    findings_total: int = 0
    critical_findings: int = 0
    false_positive_rate: float = 0.0
    avg_time_to_finding_s: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.genome_id[:10],
            "gen": self.generation,
            "fitness": f"{self.fitness:.2f}",
            "findings": self.findings_total,
            "fp_rate": f"{self.false_positive_rate:.1%}",
        }


class StrategyEvolution:
    """Evolutionary strategy optimization.

    Evolves assessment strategies based on
    outcomes — selects best approaches and
    adapts them via mutation/crossover.
    """

    def __init__(
        self,
        population_size: int = 20,
        mutation_rate: float = 0.1,
        crossover_rate: float = 0.3,
        elitism: int = 3,
    ) -> None:
        self._population: dict[str, StrategyGenome] = {}
        self._genome_counter = 0
        self._generation = 0
        self._population_size = population_size
        self._mutation_rate = mutation_rate
        self._crossover_rate = crossover_rate
        self._elitism = elitism
        self._rng = random.Random(42)
        self._log = logger.bind(component="strategy_evo")

        # Seed initial population
        self._seed_population()

    def _seed_population(self) -> None:
        """Create initial random population."""
        archetypes = [
            ("aggressive_broad", {"aggression": 0.8, "breadth": 0.8, "parallelism": 0.7}),
            ("stealthy_deep", {"aggression": 0.2, "breadth": 0.3, "exploitation_depth": 0.9}),
            ("balanced", {"aggression": 0.5, "breadth": 0.5, "validation_rigor": 0.7}),
            ("recon_heavy", {"recon_depth": 0.9, "breadth": 0.8, "time_allocation_recon": 0.5}),
            ("exploit_focused", {"exploitation_depth": 0.9, "aggression": 0.7, "time_allocation_exploit": 0.6}),
        ]

        for name, params in archetypes:
            genome = self._create_genome(name=name)
            for key, value in params.items():
                setattr(genome, key, value)

        # Fill remaining with random
        while len(self._population) < self._population_size:
            self._create_genome(name=f"random-{len(self._population)}")

    def _create_genome(
        self,
        name: str = "",
        parent_ids: list[str] | None = None,
    ) -> StrategyGenome:
        """Create a new genome."""
        self._genome_counter += 1
        genome = StrategyGenome(
            genome_id=f"strat-{self._genome_counter}",
            name=name or f"gen{self._generation}-{self._genome_counter}",
            generation=self._generation,
            parent_ids=parent_ids or [],
            aggression=self._rng.random(),
            breadth=self._rng.random(),
            parallelism=self._rng.random(),
            tool_diversity=self._rng.random(),
            validation_rigor=self._rng.random(),
            exploitation_depth=self._rng.random(),
            recon_depth=self._rng.random(),
            model_diversity=self._rng.random(),
        )

        # Normalize time allocations
        total = genome.time_allocation_recon + genome.time_allocation_exploit + genome.time_allocation_postex
        if total > 0:
            genome.time_allocation_recon /= total
            genome.time_allocation_exploit /= total
            genome.time_allocation_postex /= total

        self._population[genome.genome_id] = genome
        return genome

    def record_outcome(
        self,
        genome_id: str,
        findings: int = 0,
        critical: int = 0,
        false_positives: int = 0,
        time_to_finding_s: float = 0.0,
    ) -> None:
        """Record assessment outcome for a strategy."""
        genome = self._population.get(genome_id)
        if not genome:
            return

        genome.assessments += 1
        genome.findings_total += findings
        genome.critical_findings += critical

        total_reports = findings + false_positives
        if total_reports > 0:
            genome.false_positive_rate = false_positives / total_reports

        if time_to_finding_s > 0:
            n = genome.assessments
            genome.avg_time_to_finding_s = (
                genome.avg_time_to_finding_s * (n - 1) + time_to_finding_s
            ) / n

        # Calculate fitness
        genome.fitness = self._calculate_fitness(genome)

    def _calculate_fitness(self, genome: StrategyGenome) -> float:
        """Calculate fitness score."""
        if genome.assessments == 0:
            return 0.0

        # Weighted scoring
        finding_score = min(1.0, genome.findings_total / max(1, genome.assessments * 10))
        critical_score = min(1.0, genome.critical_findings / max(1, genome.assessments * 3))
        fp_penalty = genome.false_positive_rate
        speed_score = max(0, 1.0 - genome.avg_time_to_finding_s / 3600)

        fitness = (
            finding_score * 0.3
            + critical_score * 0.3
            + (1 - fp_penalty) * 0.2
            + speed_score * 0.2
        )

        return max(0.0, min(1.0, fitness))

    def evolve(self) -> list[StrategyGenome]:
        """Run one generation of evolution."""
        self._generation += 1

        # Sort by fitness
        ranked = sorted(
            self._population.values(),
            key=lambda g: g.fitness,
            reverse=True,
        )

        # Keep elite
        new_pop: dict[str, StrategyGenome] = {}
        for genome in ranked[:self._elitism]:
            new_pop[genome.genome_id] = genome

        # Generate offspring
        while len(new_pop) < self._population_size:
            if self._rng.random() < self._crossover_rate and len(ranked) >= 2:
                # Crossover
                parent_a = self._tournament_select(ranked)
                parent_b = self._tournament_select(ranked)
                child = self._crossover(parent_a, parent_b)
            else:
                # Mutation of random parent
                parent = self._tournament_select(ranked)
                child = self._mutate(parent)

            new_pop[child.genome_id] = child

        self._population = new_pop
        return list(new_pop.values())

    def _tournament_select(
        self,
        ranked: list[StrategyGenome],
        k: int = 3,
    ) -> StrategyGenome:
        """Tournament selection."""
        tournament = self._rng.sample(ranked[:max(k, len(ranked))], min(k, len(ranked)))
        return max(tournament, key=lambda g: g.fitness)

    def _crossover(
        self,
        parent_a: StrategyGenome,
        parent_b: StrategyGenome,
    ) -> StrategyGenome:
        """Crossover two genomes."""
        child = self._create_genome(
            name=f"cross-{self._genome_counter}",
            parent_ids=[parent_a.genome_id, parent_b.genome_id],
        )

        # Uniform crossover for each parameter
        params = [
            "aggression", "breadth", "parallelism", "tool_diversity",
            "validation_rigor", "exploitation_depth", "recon_depth",
            "model_diversity",
        ]
        for param in params:
            if self._rng.random() < 0.5:
                setattr(child, param, getattr(parent_a, param))
            else:
                setattr(child, param, getattr(parent_b, param))

        return child

    def _mutate(self, parent: StrategyGenome) -> StrategyGenome:
        """Mutate a genome."""
        child = self._create_genome(
            name=f"mut-{self._genome_counter}",
            parent_ids=[parent.genome_id],
        )

        # Copy parent params and mutate
        params = [
            "aggression", "breadth", "parallelism", "tool_diversity",
            "validation_rigor", "exploitation_depth", "recon_depth",
            "model_diversity",
        ]
        for param in params:
            value = getattr(parent, param)
            if self._rng.random() < self._mutation_rate:
                delta = self._rng.gauss(0, 0.15)
                value = max(0.0, min(1.0, value + delta))
            setattr(child, param, value)

        return child

    def get_best_strategy(self) -> StrategyGenome | None:
        """Get highest fitness strategy."""
        if not self._population:
            return None
        return max(self._population.values(), key=lambda g: g.fitness)

    def get_strategy_for_target(
        self,
        target_type: str = "",
    ) -> StrategyGenome | None:
        """Get best strategy for a target type."""
        # For now, return best overall
        return self.get_best_strategy()

    def build_evolution_prompt(self) -> str:
        """Build evolution context for LLM."""
        lines = ["## Strategy Evolution\n"]
        lines.append(f"Generation: {self._generation}")
        lines.append(f"Population: {len(self._population)}")

        best = self.get_best_strategy()
        if best:
            lines.append(f"\nBest: {best.name} (fitness={best.fitness:.2f})")
            lines.append(f"  Aggression: {best.aggression:.0%}")
            lines.append(f"  Breadth: {best.breadth:.0%}")
            lines.append(f"  Exploit depth: {best.exploitation_depth:.0%}")
            lines.append(f"  Findings: {best.findings_total} ({best.critical_findings} critical)")
            lines.append(f"  FP rate: {best.false_positive_rate:.1%}")

        # Top 3
        ranked = sorted(
            self._population.values(),
            key=lambda g: g.fitness,
            reverse=True,
        )[:3]
        if len(ranked) > 1:
            lines.append("\nTop strategies:")
            for g in ranked:
                lines.append(f"  {g.name[:15]}: {g.fitness:.2f}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        fitnesses = [g.fitness for g in self._population.values()]
        return {
            "generation": self._generation,
            "population": len(self._population),
            "avg_fitness": sum(fitnesses) / max(1, len(fitnesses)),
            "max_fitness": max(fitnesses) if fitnesses else 0.0,
        }
