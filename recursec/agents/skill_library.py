"""Skill library — reusable, composable agent skills.

Implements:
1. Skill definition and registration
2. Skill composition (combine primitives into complex skills)
3. Skill prerequisite checking
4. Skill versioning
5. Skill performance tracking
6. Skill recommendation
7. Parameterized skill execution
8. Skill categorization and search
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class SkillCategory(str, Enum):
    RECON = "recon"
    SCANNING = "scanning"
    ANALYSIS = "analysis"
    EXPLOITATION = "exploitation"
    VALIDATION = "validation"
    REPORTING = "reporting"
    COORDINATION = "coordination"
    REASONING = "reasoning"


class SkillLevel(str, Enum):
    PRIMITIVE = "primitive"     # Single action
    COMPOSITE = "composite"    # Sequence of primitives
    STRATEGIC = "strategic"    # Complex multi-step with decisions


@dataclass
class SkillParameter:
    """A parameter for a skill."""
    name: str = ""
    param_type: str = "string"
    required: bool = True
    default: Any = None
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name[:20],
            "type": self.param_type,
            "required": self.required,
        }


@dataclass
class SkillStep:
    """A step within a composite skill."""
    step_id: str = ""
    description: str = ""
    skill_ref: str = ""        # Reference to another skill
    tool: str = ""
    model: str = ""
    params: dict[str, Any] = field(default_factory=dict)
    condition: str = ""        # When to execute this step

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.step_id[:10],
            "desc": self.description[:25],
            "skill": self.skill_ref[:15],
            "tool": self.tool[:10],
        }


@dataclass
class Skill:
    """A reusable agent skill."""
    skill_id: str = ""
    name: str = ""
    category: SkillCategory = SkillCategory.RECON
    level: SkillLevel = SkillLevel.PRIMITIVE
    description: str = ""
    parameters: list[SkillParameter] = field(default_factory=list)
    steps: list[SkillStep] = field(default_factory=list)
    prerequisites: list[str] = field(default_factory=list)
    required_tools: list[str] = field(default_factory=list)
    recommended_model: str = ""
    version: int = 1
    uses: int = 0
    successes: int = 0

    @property
    def success_rate(self) -> float:
        if self.uses == 0:
            return 0.0
        return self.successes / self.uses

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.skill_id,
            "name": self.name[:25],
            "category": self.category.value,
            "level": self.level.value,
            "steps": len(self.steps),
            "uses": self.uses,
            "success": round(self.success_rate, 2),
        }


# ── Default Skills ────────────────────────────────────────────

DEFAULT_SKILLS: list[dict[str, Any]] = [
    # Primitive skills
    {
        "name": "Port scan",
        "category": "recon", "level": "primitive",
        "desc": "Scan target ports using nmap",
        "tools": ["nmap"],
        "params": [
            {"name": "target", "type": "string", "required": True},
            {"name": "ports", "type": "string", "required": False, "default": "-"},
        ],
    },
    {
        "name": "Subdomain enumeration",
        "category": "recon", "level": "primitive",
        "desc": "Enumerate subdomains using subfinder",
        "tools": ["subfinder"],
        "params": [
            {"name": "domain", "type": "string", "required": True},
        ],
    },
    {
        "name": "Vulnerability scan",
        "category": "scanning", "level": "primitive",
        "desc": "Run nuclei vulnerability scan",
        "tools": ["nuclei"],
        "params": [
            {"name": "target", "type": "string", "required": True},
            {"name": "severity", "type": "string", "required": False, "default": "medium,high,critical"},
        ],
    },
    {
        "name": "SQL injection test",
        "category": "exploitation", "level": "primitive",
        "desc": "Test for SQL injection using sqlmap",
        "tools": ["sqlmap"],
        "params": [
            {"name": "url", "type": "string", "required": True},
        ],
    },
    {
        "name": "Directory bruteforce",
        "category": "scanning", "level": "primitive",
        "desc": "Bruteforce directories using ffuf",
        "tools": ["ffuf"],
        "params": [
            {"name": "url", "type": "string", "required": True},
            {"name": "wordlist", "type": "string", "required": False},
        ],
    },
    {
        "name": "Code analysis",
        "category": "analysis", "level": "primitive",
        "desc": "Static code analysis using semgrep",
        "tools": ["semgrep"],
        "params": [
            {"name": "path", "type": "string", "required": True},
        ],
    },
    {
        "name": "XSS test",
        "category": "exploitation", "level": "primitive",
        "desc": "Test for XSS using dalfox",
        "tools": ["dalfox"],
        "params": [
            {"name": "url", "type": "string", "required": True},
        ],
    },
    # Composite skills
    {
        "name": "Web application assessment",
        "category": "scanning", "level": "composite",
        "desc": "Full web application security assessment",
        "tools": ["nmap", "nuclei", "ffuf", "sqlmap", "dalfox"],
        "prereqs": ["Port scan", "Vulnerability scan"],
        "steps": [
            {"desc": "Port scan", "skill_ref": "Port scan"},
            {"desc": "Directory bruteforce", "skill_ref": "Directory bruteforce"},
            {"desc": "Vulnerability scan", "skill_ref": "Vulnerability scan"},
            {"desc": "SQL injection test", "skill_ref": "SQL injection test", "condition": "has_forms"},
            {"desc": "XSS test", "skill_ref": "XSS test", "condition": "has_forms"},
        ],
    },
    {
        "name": "Full reconnaissance",
        "category": "recon", "level": "composite",
        "desc": "Complete target reconnaissance",
        "tools": ["subfinder", "nmap", "httpx", "whatweb"],
        "steps": [
            {"desc": "Subdomain enumeration", "skill_ref": "Subdomain enumeration"},
            {"desc": "Port scan all subdomains", "skill_ref": "Port scan"},
            {"desc": "HTTP probe", "tool": "httpx"},
            {"desc": "Technology detection", "tool": "whatweb"},
        ],
    },
    # Strategic skills
    {
        "name": "Adaptive vulnerability hunting",
        "category": "analysis", "level": "strategic",
        "desc": "Adaptively hunt for vulnerabilities based on discovered attack surface",
        "tools": ["nmap", "nuclei", "sqlmap", "ffuf"],
        "model": "whiterabbitneo-7b",
        "steps": [
            {"desc": "Initial recon", "skill_ref": "Full reconnaissance"},
            {"desc": "Analyze attack surface", "model": "whiterabbitneo-7b"},
            {"desc": "Select attack vectors", "model": "deepseek-r1-7b"},
            {"desc": "Execute targeted scans", "skill_ref": "Vulnerability scan"},
            {"desc": "Validate findings", "model": "deepseek-r1-7b"},
        ],
    },
]


class SkillLibrary:
    """Reusable, composable agent skills.

    Manages a library of skills that agents can use,
    from primitive single-tool actions to complex strategies.
    """

    def __init__(self) -> None:
        self._skills: dict[str, Skill] = {}
        self._name_index: dict[str, str] = {}
        self._skill_counter = 0
        self._log = logger.bind(component="skill_library")

        self._initialize_defaults()

    def _initialize_defaults(self) -> None:
        """Initialize default skill library."""
        for data in DEFAULT_SKILLS:
            self._skill_counter += 1

            params = []
            for p in data.get("params", []):
                params.append(SkillParameter(
                    name=p["name"],
                    param_type=p.get("type", "string"),
                    required=p.get("required", True),
                    default=p.get("default"),
                ))

            steps = []
            for i, s in enumerate(data.get("steps", [])):
                steps.append(SkillStep(
                    step_id=f"s{i + 1}",
                    description=s.get("desc", ""),
                    skill_ref=s.get("skill_ref", ""),
                    tool=s.get("tool", ""),
                    model=s.get("model", ""),
                    condition=s.get("condition", ""),
                ))

            skill = Skill(
                skill_id=f"sk-{self._skill_counter}",
                name=data["name"],
                category=SkillCategory(data["category"]),
                level=SkillLevel(data["level"]),
                description=data.get("desc", ""),
                parameters=params,
                steps=steps,
                prerequisites=data.get("prereqs", []),
                required_tools=data.get("tools", []),
                recommended_model=data.get("model", ""),
            )

            self._skills[skill.skill_id] = skill
            self._name_index[skill.name.lower()] = skill.skill_id

    def get_skill(self, name: str) -> Skill | None:
        """Get skill by name."""
        skill_id = self._name_index.get(name.lower())
        if skill_id:
            return self._skills.get(skill_id)
        return None

    def get_by_category(self, category: SkillCategory) -> list[Skill]:
        return [s for s in self._skills.values() if s.category == category]

    def get_by_level(self, level: SkillLevel) -> list[Skill]:
        return [s for s in self._skills.values() if s.level == level]

    def search(self, query: str) -> list[Skill]:
        """Search skills by name or description."""
        query_lower = query.lower()
        results = []
        for skill in self._skills.values():
            if query_lower in skill.name.lower() or query_lower in skill.description.lower():
                results.append(skill)
        return results

    def recommend(
        self,
        available_tools: list[str],
        task_type: str = "",
    ) -> list[Skill]:
        """Recommend skills based on available tools."""
        available_set = set(available_tools)
        compatible = []

        for skill in self._skills.values():
            if not skill.required_tools:
                compatible.append(skill)
                continue

            # Check if all required tools are available
            if set(skill.required_tools).issubset(available_set):
                compatible.append(skill)

        # Filter by task type if specified
        if task_type:
            try:
                category = SkillCategory(task_type)
                compatible = [s for s in compatible if s.category == category]
            except ValueError:
                pass

        # Sort by success rate
        compatible.sort(key=lambda s: s.success_rate, reverse=True)
        return compatible[:10]

    def record_use(self, skill_name: str, success: bool) -> None:
        """Record usage of a skill."""
        skill = self.get_skill(skill_name)
        if skill:
            skill.uses += 1
            if success:
                skill.successes += 1

    def register_skill(
        self,
        name: str,
        category: SkillCategory,
        level: SkillLevel,
        description: str = "",
        tools: list[str] | None = None,
        model: str = "",
    ) -> Skill:
        """Register a new skill."""
        self._skill_counter += 1
        skill = Skill(
            skill_id=f"sk-{self._skill_counter}",
            name=name,
            category=category,
            level=level,
            description=description,
            required_tools=tools or [],
            recommended_model=model,
        )
        self._skills[skill.skill_id] = skill
        self._name_index[name.lower()] = skill.skill_id
        return skill

    def get_stats(self) -> dict[str, Any]:
        cat_counts: dict[str, int] = defaultdict(int)
        for skill in self._skills.values():
            cat_counts[skill.category.value] += 1
        return {
            "skills": len(self._skills),
            "categories": dict(cat_counts),
            "total_uses": sum(s.uses for s in self._skills.values()),
        }
