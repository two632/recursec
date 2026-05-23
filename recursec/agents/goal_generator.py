"""Goal generator — autonomous goal and hypothesis generation.

Implements:
1. Target-based goal decomposition
2. Phase-appropriate goal selection
3. Finding-driven goal refinement
4. Hypothesis generation for vulnerability testing
5. Goal prioritization by risk/feasibility
6. Goal dependency tracking
7. Coverage-based gap analysis
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class GoalType(str, Enum):
    DISCOVER = "discover"           # Find new information
    VERIFY = "verify"               # Verify a hypothesis
    EXPLOIT = "exploit"             # Attempt exploitation
    ESCALATE = "escalate"           # Escalate access
    ENUMERATE = "enumerate"          # Enumerate component
    ANALYZE = "analyze"             # Analyze a finding
    VALIDATE = "validate"           # Validate a vulnerability


class GoalStatus(str, Enum):
    PENDING = "pending"
    ACTIVE = "active"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"
    SKIPPED = "skipped"


class HypothesisConfidence(str, Enum):
    HIGH = "high"           # Strong evidence
    MEDIUM = "medium"       # Some indicators
    LOW = "low"             # Speculative
    UNKNOWN = "unknown"


@dataclass
class Goal:
    """An agent goal."""
    goal_id: str = ""
    name: str = ""
    goal_type: GoalType = GoalType.DISCOVER
    status: GoalStatus = GoalStatus.PENDING
    description: str = ""
    target: str = ""
    priority: float = 0.5      # 0-1
    estimated_tokens: int = 0
    dependencies: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    model_preference: str = ""
    created_at: float = field(default_factory=time.time)
    completed_at: float = 0.0
    result: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.goal_id[:10],
            "name": self.name[:25],
            "type": self.goal_type.value,
            "status": self.status.value,
            "priority": round(self.priority, 2),
        }


@dataclass
class Hypothesis:
    """A vulnerability hypothesis to test."""
    hypothesis_id: str = ""
    statement: str = ""
    target: str = ""
    vuln_type: str = ""
    confidence: HypothesisConfidence = HypothesisConfidence.MEDIUM
    evidence: list[str] = field(default_factory=list)
    test_plan: list[str] = field(default_factory=list)
    tested: bool = False
    confirmed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.hypothesis_id[:10],
            "statement": self.statement[:30],
            "confidence": self.confidence.value,
            "tested": self.tested,
            "confirmed": self.confirmed,
        }


# ── Phase goal templates ─────────────────────────────────────

PHASE_GOAL_TEMPLATES: dict[str, list[dict[str, Any]]] = {
    "reconnaissance": [
        {"name": "DNS enumeration", "type": "enumerate", "priority": 0.9,
         "desc": "Enumerate DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA)",
         "tools": ["dig", "dnsrecon", "amass"]},
        {"name": "Subdomain discovery", "type": "discover", "priority": 0.9,
         "desc": "Discover subdomains via passive and active methods",
         "tools": ["subfinder", "amass", "httpx"]},
        {"name": "Port scanning", "type": "enumerate", "priority": 0.85,
         "desc": "Full TCP/UDP port scan to identify services",
         "tools": ["nmap", "masscan"]},
        {"name": "Technology fingerprinting", "type": "discover", "priority": 0.8,
         "desc": "Identify web technologies, frameworks, and versions",
         "tools": ["whatweb", "httpx", "wappalyzer"]},
        {"name": "Directory enumeration", "type": "enumerate", "priority": 0.75,
         "desc": "Discover hidden directories and files",
         "tools": ["ffuf", "gobuster", "feroxbuster"]},
        {"name": "WHOIS and registrar info", "type": "discover", "priority": 0.5,
         "desc": "Gather domain registration and ownership information",
         "tools": ["whois"]},
    ],
    "scanning": [
        {"name": "Automated vulnerability scan", "type": "discover", "priority": 0.9,
         "desc": "Run comprehensive vulnerability scanner",
         "tools": ["nuclei", "nikto"]},
        {"name": "Web application scan", "type": "discover", "priority": 0.85,
         "desc": "Scan for common web vulnerabilities",
         "tools": ["nuclei", "nikto", "dalfox"]},
        {"name": "SSL/TLS configuration check", "type": "verify", "priority": 0.7,
         "desc": "Check for SSL/TLS misconfigurations and weak ciphers",
         "tools": ["testssl"]},
        {"name": "CMS vulnerability scan", "type": "discover", "priority": 0.7,
         "desc": "Scan for CMS-specific vulnerabilities",
         "tools": ["wpscan", "nuclei"]},
        {"name": "Secret detection", "type": "discover", "priority": 0.6,
         "desc": "Scan for exposed secrets, API keys, tokens",
         "tools": ["trufflehog", "gitleaks"]},
    ],
    "exploitation": [
        {"name": "SQL injection exploitation", "type": "exploit", "priority": 0.9,
         "desc": "Exploit confirmed SQL injection vulnerabilities",
         "tools": ["sqlmap"]},
        {"name": "XSS exploitation", "type": "exploit", "priority": 0.7,
         "desc": "Exploit confirmed XSS vulnerabilities",
         "tools": ["dalfox"]},
        {"name": "Authentication bypass", "type": "exploit", "priority": 0.85,
         "desc": "Attempt authentication bypass techniques",
         "tools": ["hydra", "ffuf"]},
        {"name": "Known CVE exploitation", "type": "exploit", "priority": 0.8,
         "desc": "Exploit known CVEs found in vulnerable components",
         "tools": ["searchsploit"]},
    ],
    "validation": [
        {"name": "Finding validation", "type": "validate", "priority": 0.9,
         "desc": "Validate all findings with alternative tools/methods",
         "tools": ["nuclei", "curl"]},
        {"name": "False positive elimination", "type": "verify", "priority": 0.85,
         "desc": "Cross-verify findings to eliminate false positives",
         "tools": ["curl", "httpx"]},
        {"name": "Impact assessment", "type": "analyze", "priority": 0.8,
         "desc": "Determine real-world impact of confirmed vulnerabilities",
         "tools": []},
    ],
}

# ── Hypothesis templates ─────────────────────────────────────

HYPOTHESIS_TEMPLATES: list[dict[str, Any]] = [
    {
        "trigger": "open_port_80_443",
        "statement": "Web application may be vulnerable to common web attacks (SQLi, XSS, SSRF)",
        "vuln_type": "web",
        "confidence": "medium",
        "tests": ["Run nuclei web templates", "Test injection points", "Check for SSRF"],
    },
    {
        "trigger": "old_software_version",
        "statement": "Outdated software version may have known CVEs",
        "vuln_type": "cve",
        "confidence": "high",
        "tests": ["Search CVE databases", "Check exploit-db", "Run nuclei CVE templates"],
    },
    {
        "trigger": "login_form",
        "statement": "Login form may be vulnerable to brute force or credential stuffing",
        "vuln_type": "auth",
        "confidence": "medium",
        "tests": ["Check rate limiting", "Test default credentials", "Test password policy"],
    },
    {
        "trigger": "api_endpoint",
        "statement": "API endpoint may have authorization issues (BOLA, BFLA)",
        "vuln_type": "api",
        "confidence": "medium",
        "tests": ["Test IDOR via ID manipulation", "Test admin endpoints", "Check rate limits"],
    },
    {
        "trigger": "file_upload",
        "statement": "File upload functionality may allow malicious file upload",
        "vuln_type": "upload",
        "confidence": "high",
        "tests": ["Upload PHP/JSP webshell", "Test extension bypass", "Check content-type validation"],
    },
    {
        "trigger": "redirect_param",
        "statement": "URL redirect parameter may allow open redirect or SSRF",
        "vuln_type": "redirect",
        "confidence": "medium",
        "tests": ["Test open redirect", "Test SSRF via redirect", "Test protocol handler"],
    },
    {
        "trigger": "graphql_endpoint",
        "statement": "GraphQL endpoint may expose introspection or be vulnerable to DoS",
        "vuln_type": "graphql",
        "confidence": "high",
        "tests": ["Test introspection query", "Test nested query DoS", "Check authorization"],
    },
    {
        "trigger": "jwt_token",
        "statement": "JWT implementation may have algorithm confusion or weak signing",
        "vuln_type": "jwt",
        "confidence": "medium",
        "tests": ["Test none algorithm", "Test RS256→HS256 confusion", "Check token expiry"],
    },
    {
        "trigger": "smb_open",
        "statement": "SMB service may allow null session or anonymous access",
        "vuln_type": "smb",
        "confidence": "medium",
        "tests": ["Test null session", "Enumerate shares", "Check signing"],
    },
    {
        "trigger": "ssh_service",
        "statement": "SSH service may allow password authentication or have weak keys",
        "vuln_type": "ssh",
        "confidence": "low",
        "tests": ["Check auth methods", "Test common credentials", "Check key exchange algorithms"],
    },
]


class GoalGenerator:
    """Generates goals and hypotheses for autonomous operation.

    Produces phase-appropriate goals, generates
    vulnerability hypotheses from findings, and
    tracks goal completion.
    """

    def __init__(self) -> None:
        self._goals: dict[str, Goal] = {}
        self._hypotheses: dict[str, Hypothesis] = {}
        self._counter = 0
        self._log = logger.bind(component="goal_generator")

    def generate_phase_goals(
        self,
        phase: str,
        target: str,
    ) -> list[Goal]:
        """Generate goals for a given assessment phase."""
        templates = PHASE_GOAL_TEMPLATES.get(phase, [])
        goals = []

        for template in templates:
            self._counter += 1
            goal = Goal(
                goal_id=f"goal-{self._counter}",
                name=template["name"],
                goal_type=GoalType(template["type"]),
                description=template.get("desc", ""),
                target=target,
                priority=template.get("priority", 0.5),
                tools=template.get("tools", []),
            )
            self._goals[goal.goal_id] = goal
            goals.append(goal)

        return goals

    def generate_hypothesis(
        self,
        trigger: str,
        target: str,
        evidence: list[str] | None = None,
    ) -> Hypothesis | None:
        """Generate a hypothesis from a trigger."""
        for template in HYPOTHESIS_TEMPLATES:
            if template["trigger"] == trigger:
                self._counter += 1
                hyp = Hypothesis(
                    hypothesis_id=f"hyp-{self._counter}",
                    statement=template["statement"],
                    target=target,
                    vuln_type=template.get("vuln_type", ""),
                    confidence=HypothesisConfidence(template.get("confidence", "medium")),
                    evidence=evidence or [],
                    test_plan=template.get("tests", []),
                )
                self._hypotheses[hyp.hypothesis_id] = hyp
                return hyp

        return None

    def generate_from_finding(
        self,
        finding: dict[str, Any],
        target: str,
    ) -> list[Goal]:
        """Generate follow-up goals from a finding."""
        goals = []
        title = finding.get("title", "").lower()
        severity = finding.get("severity", "medium")

        # High/critical findings → exploitation goal
        if severity in ("critical", "high"):
            self._counter += 1
            exploit_goal = Goal(
                goal_id=f"goal-{self._counter}",
                name=f"Exploit: {finding.get('title', '')[:30]}",
                goal_type=GoalType.EXPLOIT,
                description=f"Attempt exploitation of {finding.get('title', '')}",
                target=target,
                priority=0.9 if severity == "critical" else 0.7,
            )
            self._goals[exploit_goal.goal_id] = exploit_goal
            goals.append(exploit_goal)

        # SQL injection → DB extraction
        if "sql" in title or "injection" in title:
            self._counter += 1
            goals.append(Goal(
                goal_id=f"goal-{self._counter}",
                name="Database extraction",
                goal_type=GoalType.EXPLOIT,
                description="Extract database schemas, tables, and sensitive data",
                target=target,
                priority=0.8,
                tools=["sqlmap"],
            ))
            self._goals[goals[-1].goal_id] = goals[-1]

        # RCE → privilege escalation
        if "rce" in title or "command" in title or "exec" in title:
            self._counter += 1
            goals.append(Goal(
                goal_id=f"goal-{self._counter}",
                name="Privilege escalation",
                goal_type=GoalType.ESCALATE,
                description="Attempt privilege escalation from RCE foothold",
                target=target,
                priority=0.85,
            ))
            self._goals[goals[-1].goal_id] = goals[-1]

        return goals

    def get_next_goal(self) -> Goal | None:
        """Get the highest priority pending goal."""
        pending = [
            g for g in self._goals.values()
            if g.status == GoalStatus.PENDING
        ]
        if not pending:
            return None

        # Check dependencies
        ready = []
        for goal in pending:
            deps_met = all(
                self._goals.get(dep_id, Goal()).status == GoalStatus.COMPLETED
                for dep_id in goal.dependencies
            )
            if deps_met:
                ready.append(goal)

        if not ready:
            return None

        return max(ready, key=lambda g: g.priority)

    def complete_goal(
        self,
        goal_id: str,
        result: str = "",
        success: bool = True,
    ) -> None:
        """Mark a goal as completed or failed."""
        goal = self._goals.get(goal_id)
        if goal:
            goal.status = GoalStatus.COMPLETED if success else GoalStatus.FAILED
            goal.completed_at = time.time()
            goal.result = result

    def get_coverage_gaps(self) -> list[str]:
        """Identify assessment coverage gaps."""
        completed_types = {
            g.goal_type for g in self._goals.values()
            if g.status == GoalStatus.COMPLETED
        }

        gaps = []
        if GoalType.ENUMERATE not in completed_types:
            gaps.append("Service enumeration not completed")
        if GoalType.DISCOVER not in completed_types:
            gaps.append("Discovery phase not completed")
        if GoalType.VERIFY not in completed_types:
            gaps.append("No findings verified yet")
        if GoalType.VALIDATE not in completed_types:
            gaps.append("Findings not validated")

        # Check untested hypotheses
        untested = sum(1 for h in self._hypotheses.values() if not h.tested)
        if untested > 0:
            gaps.append(f"{untested} hypotheses untested")

        return gaps

    def build_goals_prompt(self) -> str:
        """Build prompt with current goals."""
        active = [g for g in self._goals.values() if g.status in (GoalStatus.PENDING, GoalStatus.ACTIVE)]
        if not active:
            return ""

        lines = ["## Current Goals\n"]
        for goal in sorted(active, key=lambda g: g.priority, reverse=True)[:5]:
            lines.append(f"- [{goal.goal_type.value}] {goal.name} (priority={goal.priority:.1f})")
            if goal.tools:
                lines.append(f"  Tools: {', '.join(goal.tools[:3])}")

        gaps = self.get_coverage_gaps()
        if gaps:
            lines.append("\n## Coverage Gaps")
            for gap in gaps[:3]:
                lines.append(f"- {gap}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        status_counts: dict[str, int] = defaultdict(int)
        type_counts: dict[str, int] = defaultdict(int)

        for g in self._goals.values():
            status_counts[g.status.value] += 1
            type_counts[g.goal_type.value] += 1

        return {
            "goals": len(self._goals),
            "hypotheses": len(self._hypotheses),
            "by_status": dict(status_counts),
            "by_type": dict(type_counts),
            "coverage_gaps": len(self.get_coverage_gaps()),
        }
