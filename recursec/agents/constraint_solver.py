"""Constraint solver — formal reasoning about security constraints.

Implements:
1. Constraint specification and validation
2. Variable domain management
3. Arc consistency (AC-3 algorithm)
4. Backtracking search with constraint propagation
5. Security-specific constraints (network, auth, access)
6. Attack path as constraint satisfaction problem
7. Reachability analysis
8. Configuration constraint checking
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ConstraintType(str, Enum):
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    LESS_THAN = "less_than"
    GREATER_THAN = "greater_than"
    IN_SET = "in_set"
    NOT_IN_SET = "not_in_set"
    IMPLIES = "implies"              # If A then B
    MUTUALLY_EXCLUSIVE = "mutually_exclusive"
    REQUIRES = "requires"            # A requires B
    REACHABLE = "reachable"          # Network reachability
    CUSTOM = "custom"


class SolveStatus(str, Enum):
    UNSOLVED = "unsolved"
    SATISFIABLE = "satisfiable"
    UNSATISFIABLE = "unsatisfiable"
    TIMEOUT = "timeout"
    PARTIAL = "partial"


@dataclass
class Variable:
    """A variable in the constraint system."""
    var_id: str = ""
    name: str = ""
    domain: list[Any] = field(default_factory=list)
    value: Any = None
    is_assigned: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.var_id,
            "name": self.name[:20],
            "domain_size": len(self.domain),
            "assigned": self.is_assigned,
        }


@dataclass
class Constraint:
    """A constraint between variables."""
    constraint_id: str = ""
    constraint_type: ConstraintType = ConstraintType.EQUALS
    variables: list[str] = field(default_factory=list)
    parameters: dict[str, Any] = field(default_factory=dict)
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.constraint_id,
            "type": self.constraint_type.value,
            "vars": len(self.variables),
            "desc": self.description[:30],
        }


@dataclass
class SolveResult:
    """Result of constraint solving."""
    status: SolveStatus = SolveStatus.UNSOLVED
    assignments: dict[str, Any] = field(default_factory=dict)
    violations: list[str] = field(default_factory=list)
    steps: int = 0
    duration_s: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "assignments": len(self.assignments),
            "violations": len(self.violations),
            "steps": self.steps,
        }


# ── Security Constraint Templates ─────────────────────────────

SECURITY_CONSTRAINTS: list[dict[str, Any]] = [
    # Network reachability
    {"name": "internet_to_dmz", "type": "reachable", "desc": "Internet can reach DMZ services"},
    {"name": "dmz_to_internal", "type": "reachable", "desc": "DMZ services can reach internal on specific ports"},
    {"name": "internal_not_internet", "type": "not_in_set", "desc": "Internal services not reachable from internet"},
    # Auth constraints
    {"name": "admin_requires_mfa", "type": "requires", "desc": "Admin access requires MFA"},
    {"name": "api_requires_auth", "type": "requires", "desc": "API endpoints require authentication"},
    {"name": "sensitive_requires_encryption", "type": "requires", "desc": "Sensitive data requires encryption in transit"},
    # Access control
    {"name": "least_privilege", "type": "not_in_set", "desc": "Users should not have wildcard permissions"},
    {"name": "separation_of_duties", "type": "mutually_exclusive", "desc": "Approve and request roles are separate"},
]


class ConstraintSolver:
    """Formal constraint solver for security analysis.

    Models security properties as constraints and checks
    satisfiability. Useful for access control analysis,
    network reachability, and configuration validation.
    """

    def __init__(self) -> None:
        self._variables: dict[str, Variable] = {}
        self._constraints: list[Constraint] = []
        self._var_counter = 0
        self._constraint_counter = 0
        self._log = logger.bind(component="constraint_solver")

    def add_variable(
        self,
        name: str,
        domain: list[Any],
    ) -> Variable:
        """Add a variable with its domain."""
        self._var_counter += 1
        var = Variable(
            var_id=f"var-{self._var_counter}",
            name=name,
            domain=list(domain),
        )
        self._variables[var.var_id] = var
        return var

    def add_constraint(
        self,
        constraint_type: ConstraintType,
        variables: list[str],
        parameters: dict[str, Any] | None = None,
        description: str = "",
    ) -> Constraint:
        """Add a constraint between variables."""
        self._constraint_counter += 1
        constraint = Constraint(
            constraint_id=f"cst-{self._constraint_counter}",
            constraint_type=constraint_type,
            variables=variables,
            parameters=parameters or {},
            description=description,
        )
        self._constraints.append(constraint)
        return constraint

    def solve(self, timeout_s: float = 30.0) -> SolveResult:
        """Solve the constraint problem using backtracking with AC-3."""
        start = time.time()
        result = SolveResult()

        # First run AC-3 to reduce domains
        if not self._ac3():
            result.status = SolveStatus.UNSATISFIABLE
            result.violations = self._find_empty_domains()
            result.duration_s = time.time() - start
            return result

        # Backtracking search
        assignment: dict[str, Any] = {}
        steps = [0]

        success = self._backtrack(assignment, steps, start, timeout_s)

        result.steps = steps[0]
        result.duration_s = time.time() - start

        if success:
            result.status = SolveStatus.SATISFIABLE
            result.assignments = assignment
        elif time.time() - start >= timeout_s:
            result.status = SolveStatus.TIMEOUT
            result.assignments = assignment
        else:
            result.status = SolveStatus.UNSATISFIABLE
            result.violations = self._find_violations(assignment)

        return result

    def check_constraints(
        self,
        assignments: dict[str, Any],
    ) -> list[str]:
        """Check which constraints are violated by given assignments."""
        violations = []

        for constraint in self._constraints:
            if not self._evaluate_constraint(constraint, assignments):
                violations.append(
                    f"{constraint.constraint_id}: {constraint.description}"
                )

        return violations

    def _ac3(self) -> bool:
        """Arc Consistency 3 algorithm to prune domains."""
        queue: deque[tuple[str, str]] = deque()

        # Build arcs from binary constraints
        for constraint in self._constraints:
            if len(constraint.variables) == 2:
                var_a, var_b = constraint.variables
                queue.append((var_a, var_b))
                queue.append((var_b, var_a))

        while queue:
            xi, xj = queue.popleft()
            if self._revise(xi, xj):
                var_i = self._variables.get(xi)
                if not var_i or not var_i.domain:
                    return False

                # Add all arcs (xk, xi) where xk != xj
                for constraint in self._constraints:
                    if xi in constraint.variables and len(constraint.variables) == 2:
                        other = [v for v in constraint.variables if v != xi]
                        for xk in other:
                            if xk != xj:
                                queue.append((xk, xi))

        return True

    def _revise(self, xi: str, xj: str) -> bool:
        """Revise domain of xi based on constraint with xj."""
        var_i = self._variables.get(xi)
        var_j = self._variables.get(xj)
        if not var_i or not var_j:
            return False

        revised = False
        to_remove = []

        for val_i in var_i.domain:
            # Check if there exists any value in xj's domain that satisfies
            # all constraints between xi and xj
            satisfiable = False
            for val_j in var_j.domain:
                test_assign = {xi: val_i, xj: val_j}
                if all(
                    self._evaluate_constraint(c, test_assign)
                    for c in self._constraints
                    if set(c.variables) == {xi, xj}
                ):
                    satisfiable = True
                    break

            if not satisfiable:
                to_remove.append(val_i)
                revised = True

        for val in to_remove:
            var_i.domain.remove(val)

        return revised

    def _backtrack(
        self,
        assignment: dict[str, Any],
        steps: list[int],
        start: float,
        timeout_s: float,
    ) -> bool:
        """Backtracking search with constraint propagation."""
        if len(assignment) == len(self._variables):
            return True

        if time.time() - start > timeout_s:
            return False

        steps[0] += 1

        # Select unassigned variable (MRV heuristic)
        unassigned = [
            v for v in self._variables.values()
            if v.var_id not in assignment
        ]
        unassigned.sort(key=lambda v: len(v.domain))

        if not unassigned:
            return True

        var = unassigned[0]

        for value in var.domain:
            assignment[var.var_id] = value

            if self._is_consistent(assignment):
                if self._backtrack(assignment, steps, start, timeout_s):
                    return True

            del assignment[var.var_id]

        return False

    def _is_consistent(self, assignment: dict[str, Any]) -> bool:
        """Check if current partial assignment is consistent."""
        for constraint in self._constraints:
            # Only check constraints where all variables are assigned
            if all(v in assignment for v in constraint.variables):
                if not self._evaluate_constraint(constraint, assignment):
                    return False
        return True

    def _evaluate_constraint(
        self,
        constraint: Constraint,
        assignment: dict[str, Any],
    ) -> bool:
        """Evaluate a single constraint."""
        values = [assignment.get(v) for v in constraint.variables]

        if any(val is None for val in values):
            return True  # Not yet assigned, skip

        ct = constraint.constraint_type

        if ct == ConstraintType.EQUALS:
            return values[0] == values[1] if len(values) >= 2 else True

        if ct == ConstraintType.NOT_EQUALS:
            return values[0] != values[1] if len(values) >= 2 else True

        if ct == ConstraintType.LESS_THAN:
            return values[0] < values[1] if len(values) >= 2 else True

        if ct == ConstraintType.GREATER_THAN:
            return values[0] > values[1] if len(values) >= 2 else True

        if ct == ConstraintType.IN_SET:
            allowed = constraint.parameters.get("set", [])
            return values[0] in allowed

        if ct == ConstraintType.NOT_IN_SET:
            forbidden = constraint.parameters.get("set", [])
            return values[0] not in forbidden

        if ct == ConstraintType.IMPLIES:
            # If A=true then B must be true
            return not values[0] or values[1] if len(values) >= 2 else True

        if ct == ConstraintType.MUTUALLY_EXCLUSIVE:
            # At most one can be true
            true_count = sum(1 for v in values if v)
            return true_count <= 1

        if ct == ConstraintType.REQUIRES:
            # If A then B must exist/be true
            return not values[0] or values[1] if len(values) >= 2 else True

        if ct == ConstraintType.REACHABLE:
            # Custom: value must be in reachable set
            reachable_set = constraint.parameters.get("reachable_from", [])
            return values[0] in reachable_set

        return True

    def _find_empty_domains(self) -> list[str]:
        """Find variables with empty domains after AC-3."""
        return [
            f"Variable '{var.name}' has empty domain"
            for var in self._variables.values()
            if not var.domain
        ]

    def _find_violations(self, assignment: dict[str, Any]) -> list[str]:
        """Find constraint violations in assignment."""
        violations = []
        for constraint in self._constraints:
            if all(v in assignment for v in constraint.variables):
                if not self._evaluate_constraint(constraint, assignment):
                    violations.append(constraint.description or constraint.constraint_id)
        return violations

    def get_stats(self) -> dict[str, Any]:
        return {
            "variables": len(self._variables),
            "constraints": len(self._constraints),
            "avg_domain_size": round(
                sum(len(v.domain) for v in self._variables.values()) /
                max(1, len(self._variables)),
                1,
            ),
        }
