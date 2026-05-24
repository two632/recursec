"""Prompt template library — reusable prompt templates.

Implements:
1. Phase-specific prompt templates (recon, exploit, etc.)
2. Variable interpolation (target, findings, context)
3. Template composition (combine multiple templates)
4. Token budget awareness
5. Template versioning
6. Template selection prompt
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class TemplatePhase(str, Enum):
    SYSTEM = "system"
    RECON = "recon"
    VULN_SCAN = "vuln_scan"
    WEB_AUDIT = "web_audit"
    EXPLOITATION = "exploitation"
    POST_EXPLOIT = "post_exploit"
    CODE_AUDIT = "code_audit"
    CLOUD_AUDIT = "cloud_audit"
    REASONING = "reasoning"
    VALIDATION = "validation"
    PLANNING = "planning"
    REPORTING = "reporting"


@dataclass
class PromptTemplate:
    """A reusable prompt template."""
    template_id: str = ""
    name: str = ""
    phase: TemplatePhase = TemplatePhase.SYSTEM
    version: int = 1
    template: str = ""
    variables: list[str] = field(default_factory=list)
    token_estimate: int = 0
    created_at: float = field(default_factory=time.time)

    def render(self, **kwargs: str) -> str:
        """Render template with variables."""
        result = self.template
        for var in self.variables:
            placeholder = f"{{{var}}}"
            value = kwargs.get(var, f"[{var}]")
            result = result.replace(placeholder, value)
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.template_id[:10],
            "name": self.name[:20],
            "phase": self.phase.value[:8],
            "tokens": self.token_estimate,
        }


# ── Pre-built prompt templates ──────────────────────────

TEMPLATES: list[dict[str, Any]] = [
    {
        "id": "tpl-system-001", "name": "Security Agent System",
        "phase": "system", "version": 1,
        "vars": ["role", "target", "scope"],
        "template": (
            "You are an autonomous security assessment agent.\n"
            "Role: {role}\n"
            "Target: {target}\n"
            "Scope: {scope}\n\n"
            "RULES:\n"
            "1. Stay within the defined scope at all times\n"
            "2. Document all findings with evidence\n"
            "3. Validate findings before reporting\n"
            "4. Use the least intrusive method first\n"
            "5. Escalate only when necessary\n"
            "6. Never modify target data\n"
            "7. Log all actions taken\n"
            "8. Report progress regularly\n\n"
            "You have access to external security tools.\n"
            "Think step-by-step before executing any action.\n"
            "Provide structured output in JSON format."
        ),
    },
    {
        "id": "tpl-recon-001", "name": "Reconnaissance Phase",
        "phase": "recon", "version": 1,
        "vars": ["target", "scope", "previous_findings"],
        "template": (
            "## Reconnaissance Phase\n\n"
            "Target: {target}\n"
            "Scope: {scope}\n\n"
            "Perform comprehensive reconnaissance:\n"
            "1. Subdomain enumeration (subfinder, amass)\n"
            "2. DNS analysis (records, zone transfers)\n"
            "3. Port scanning (top 1000, then full if needed)\n"
            "4. Service identification and versioning\n"
            "5. Web technology detection (httpx, Wappalyzer)\n"
            "6. Certificate transparency logs\n"
            "7. OSINT (email harvesting, employee enumeration)\n"
            "8. Cloud asset discovery\n\n"
            "Previous findings:\n{previous_findings}\n\n"
            "Output each finding as:\n"
            "```json\n"
            "{\"type\": \"recon\", \"target\": \"...\", "
            "\"data\": {...}, \"confidence\": 0.0-1.0}\n"
            "```"
        ),
    },
    {
        "id": "tpl-vuln-001", "name": "Vulnerability Scanning",
        "phase": "vuln_scan", "version": 1,
        "vars": ["target", "services", "tech_stack", "previous_findings"],
        "template": (
            "## Vulnerability Scanning Phase\n\n"
            "Target: {target}\n"
            "Services discovered:\n{services}\n"
            "Technology stack:\n{tech_stack}\n\n"
            "Run vulnerability assessment:\n"
            "1. Nuclei templates (critical, high, medium)\n"
            "2. Service-specific checks (version-based CVEs)\n"
            "3. Configuration auditing\n"
            "4. Default credential checks\n"
            "5. SSL/TLS assessment (testssl)\n"
            "6. Web vulnerability scanning (nikto)\n"
            "7. Known CVE matching against versions\n\n"
            "Previous findings:\n{previous_findings}\n\n"
            "For each vulnerability:\n"
            "```json\n"
            "{\"type\": \"vulnerability\", \"severity\": \"critical|high|medium|low\",\n"
            " \"title\": \"...\", \"cvss\": 0.0, \"cve\": \"CVE-...\",\n"
            " \"evidence\": \"...\", \"remediation\": \"...\"}\n"
            "```"
        ),
    },
    {
        "id": "tpl-web-001", "name": "Web Application Audit",
        "phase": "web_audit", "version": 1,
        "vars": ["target_url", "tech_stack", "endpoints", "previous_findings"],
        "template": (
            "## Web Application Audit Phase\n\n"
            "Target URL: {target_url}\n"
            "Technology: {tech_stack}\n"
            "Known endpoints:\n{endpoints}\n\n"
            "Test for:\n"
            "1. SQL Injection (error-based, blind, time-based)\n"
            "2. XSS (reflected, stored, DOM-based)\n"
            "3. CSRF\n"
            "4. SSRF\n"
            "5. File inclusion (LFI/RFI)\n"
            "6. File upload vulnerabilities\n"
            "7. Authentication flaws\n"
            "8. Authorization bypasses (IDOR)\n"
            "9. Business logic flaws\n"
            "10. API security issues\n"
            "11. Header injection\n"
            "12. Deserialization\n\n"
            "Previous findings:\n{previous_findings}\n\n"
            "Use sqlmap for confirmed injection points.\n"
            "Use ffuf for content discovery.\n"
            "Test each endpoint systematically."
        ),
    },
    {
        "id": "tpl-exploit-001", "name": "Exploitation Phase",
        "phase": "exploitation", "version": 1,
        "vars": ["target", "vulnerabilities", "credentials", "access_level"],
        "template": (
            "## Exploitation Phase\n\n"
            "Target: {target}\n"
            "Current access level: {access_level}\n\n"
            "Confirmed vulnerabilities:\n{vulnerabilities}\n\n"
            "Available credentials:\n{credentials}\n\n"
            "Exploitation strategy:\n"
            "1. Prioritize by severity and exploitability\n"
            "2. Attempt exploitation of highest-impact vulns first\n"
            "3. For each successful exploit, document:\n"
            "   - Pre-conditions\n"
            "   - Steps to reproduce\n"
            "   - Impact achieved\n"
            "   - Evidence (screenshots, output)\n"
            "4. If initial exploitation succeeds:\n"
            "   - Establish persistence (if in scope)\n"
            "   - Attempt privilege escalation\n"
            "   - Map internal network\n"
            "5. Validate every exploit before reporting\n\n"
            "Use Metasploit for known CVE exploits.\n"
            "Use manual techniques for logic flaws.\n"
            "NEVER cause service disruption."
        ),
    },
    {
        "id": "tpl-postexploit-001", "name": "Post-Exploitation",
        "phase": "post_exploit", "version": 1,
        "vars": ["target", "access_type", "current_user", "os_info"],
        "template": (
            "## Post-Exploitation Phase\n\n"
            "Target: {target}\n"
            "Access: {access_type}\n"
            "Current user: {current_user}\n"
            "OS: {os_info}\n\n"
            "Tasks:\n"
            "1. Situational awareness (whoami, hostname, network)\n"
            "2. Privilege escalation (if not already root/admin)\n"
            "3. Credential harvesting\n"
            "4. Internal network reconnaissance\n"
            "5. Sensitive data identification\n"
            "6. Lateral movement opportunities\n"
            "7. Persistence mechanisms (if in scope)\n\n"
            "For Windows: use mimikatz, SharpHound, PowerView\n"
            "For Linux: use LinPEAS, pspy, credential files\n\n"
            "Document the full attack chain."
        ),
    },
    {
        "id": "tpl-codeaudit-001", "name": "Code Audit",
        "phase": "code_audit", "version": 1,
        "vars": ["language", "framework", "code_snippet", "file_path"],
        "template": (
            "## Code Audit\n\n"
            "Language: {language}\n"
            "Framework: {framework}\n"
            "File: {file_path}\n\n"
            "Analyze the following code for security vulnerabilities:\n"
            "```\n{code_snippet}\n```\n\n"
            "Check for:\n"
            "1. Injection flaws (SQL, command, LDAP)\n"
            "2. XSS (output encoding)\n"
            "3. Authentication/authorization issues\n"
            "4. Cryptographic weaknesses\n"
            "5. Information disclosure\n"
            "6. Insecure deserialization\n"
            "7. SSRF\n"
            "8. Path traversal\n"
            "9. Race conditions\n"
            "10. Hardcoded secrets\n\n"
            "For each finding provide:\n"
            "- Vulnerability type and severity\n"
            "- Exact line numbers\n"
            "- Proof of concept\n"
            "- Recommended fix"
        ),
    },
    {
        "id": "tpl-reasoning-001", "name": "Chain-of-Thought Reasoning",
        "phase": "reasoning", "version": 1,
        "vars": ["situation", "findings", "hypothesis"],
        "template": (
            "## Reasoning\n\n"
            "Situation:\n{situation}\n\n"
            "Findings so far:\n{findings}\n\n"
            "Current hypothesis:\n{hypothesis}\n\n"
            "Think step-by-step:\n"
            "1. What evidence supports this hypothesis?\n"
            "2. What evidence contradicts it?\n"
            "3. What experiments would test this?\n"
            "4. What is the most likely explanation?\n"
            "5. What are alternative hypotheses?\n"
            "6. What is the confidence level (0-1)?\n"
            "7. What is the recommended next action?\n\n"
            "Be precise and evidence-based.\n"
            "Avoid hallucination — state uncertainty.\n"
            "Consider the full attack surface."
        ),
    },
    {
        "id": "tpl-validation-001", "name": "Finding Validation",
        "phase": "validation", "version": 1,
        "vars": ["finding", "evidence", "original_tool"],
        "template": (
            "## Validation\n\n"
            "Finding to validate:\n{finding}\n\n"
            "Original evidence:\n{evidence}\n\n"
            "Detected by: {original_tool}\n\n"
            "Validate this finding:\n"
            "1. Attempt reproduction with different tool/method\n"
            "2. Check for false positive indicators\n"
            "3. Verify the impact claim\n"
            "4. Confirm the severity rating\n"
            "5. Test remediation effectiveness\n\n"
            "Validation result:\n"
            "```json\n"
            "{\"validated\": true|false,\n"
            " \"confidence\": 0.0-1.0,\n"
            " \"method\": \"...\",\n"
            " \"notes\": \"...\"}\n"
            "```"
        ),
    },
    {
        "id": "tpl-planning-001", "name": "Assessment Planning",
        "phase": "planning", "version": 1,
        "vars": ["target", "scope", "constraints", "objectives"],
        "template": (
            "## Assessment Planning\n\n"
            "Target: {target}\n"
            "Scope: {scope}\n"
            "Constraints: {constraints}\n"
            "Objectives: {objectives}\n\n"
            "Create a detailed assessment plan:\n"
            "1. Identify attack surface areas\n"
            "2. Determine tools needed per phase\n"
            "3. Estimate time per phase\n"
            "4. Define success criteria\n"
            "5. Identify risks and mitigations\n"
            "6. Plan agent spawning strategy\n"
            "7. Determine model assignments\n"
            "8. Set token budgets per phase\n\n"
            "Output plan as:\n"
            "```json\n"
            "{\"phases\": [...], \"agents\": [...],\n"
            " \"estimated_time\": \"...\",\n"
            " \"risk_areas\": [...]}\n"
            "```"
        ),
    },
]


class PromptTemplateLibrary:
    """Library of reusable prompt templates.

    Provides phase-specific templates with
    variable interpolation and composition.
    """

    def __init__(self) -> None:
        self._templates: dict[str, PromptTemplate] = {}
        self._log = logger.bind(component="templates")
        self._load_templates()

    def _load_templates(self) -> None:
        """Load built-in templates."""
        for data in TEMPLATES:
            tpl = PromptTemplate(
                template_id=data["id"],
                name=data["name"],
                phase=TemplatePhase(data["phase"]),
                version=data.get("version", 1),
                template=data["template"],
                variables=data.get("vars", []),
                token_estimate=len(data["template"]) // 4,
            )
            self._templates[tpl.template_id] = tpl

    def get_template(self, template_id: str) -> PromptTemplate | None:
        """Get a template by ID."""
        return self._templates.get(template_id)

    def get_by_phase(self, phase: TemplatePhase) -> list[PromptTemplate]:
        """Get templates for a phase."""
        return [t for t in self._templates.values() if t.phase == phase]

    def render_template(self, template_id: str, **kwargs: str) -> str:
        """Render a template with variables."""
        tpl = self._templates.get(template_id)
        if not tpl:
            return ""
        return tpl.render(**kwargs)

    def compose(self, template_ids: list[str], separator: str = "\n\n---\n\n") -> str:
        """Compose multiple templates together."""
        parts = []
        for tid in template_ids:
            tpl = self._templates.get(tid)
            if tpl:
                parts.append(tpl.template)
        return separator.join(parts)

    def add_custom(
        self,
        name: str,
        phase: TemplatePhase,
        template: str,
        variables: list[str] | None = None,
    ) -> PromptTemplate:
        """Add a custom template."""
        tpl_id = f"tpl-custom-{len(self._templates) + 1}"
        tpl = PromptTemplate(
            template_id=tpl_id,
            name=name,
            phase=phase,
            template=template,
            variables=variables or [],
            token_estimate=len(template) // 4,
        )
        self._templates[tpl_id] = tpl
        return tpl

    def build_template_prompt(self) -> str:
        """Build template list for LLM."""
        lines = ["## Prompt Templates\n"]
        lines.append(f"Templates: {len(self._templates)}")

        by_phase: dict[str, list[str]] = {}
        for tpl in self._templates.values():
            p = tpl.phase.value
            by_phase.setdefault(p, []).append(tpl.name)

        for phase, names in by_phase.items():
            lines.append(f"\n{phase}:")
            for name in names:
                lines.append(f"  - {name}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        by_phase: dict[str, int] = {}
        for tpl in self._templates.values():
            p = tpl.phase.value
            by_phase[p] = by_phase.get(p, 0) + 1
        total_tokens = sum(t.token_estimate for t in self._templates.values())

        return {
            "templates": len(self._templates),
            "by_phase": by_phase,
            "total_token_estimate": total_tokens,
        }
