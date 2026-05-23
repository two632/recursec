"""Advanced prompt engineering engine for RecurSec agents.

Provides:
- Chain-of-thought templates for security reasoning
- Few-shot examples for vulnerability classification
- Tool selection prompts
- Output schema enforcement
- Context window management
- Prompt compression for long contexts
- Dynamic prompt assembly from templates
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


@dataclass
class PromptContext:
    """Context for building a prompt."""
    target: str = ""
    target_type: str = "host"
    objective: str = ""
    findings_so_far: list[dict[str, Any]] | None = None
    available_tools: list[str] | None = None
    model_capabilities: str = ""
    max_tokens: int = 4096
    recursion_depth: int = 0
    parent_context: str = ""
    knowledge_snippets: list[str] | None = None


# ── Chain-of-Thought Templates ─────────────────────────────

RECON_COT = """## Reconnaissance Analysis

I need to discover the attack surface for {target}.

**Step 1: Identify Target Type**
Target: {target}
Type: {target_type}

**Step 2: Select Discovery Methods**
Based on the target type, I should:
{recon_methods}

**Step 3: Analyze Results**
From the scan results, I will identify:
- Open ports and services
- Operating system / versions
- Potential entry points
- Misconfigurations
- Network topology

**Step 4: Prioritize Findings**
I'll rank findings by:
1. Directly exploitable services (critical)
2. Misconfigured services (high)
3. Outdated software with known CVEs (high)
4. Information disclosure (medium)
5. Default configurations (low)

**Step 5: Plan Next Actions**
Based on findings, delegate to:
- VulnScan for confirmed services
- WebScan for any web services found
- OSINT for additional intelligence
"""

VULN_ANALYSIS_COT = """## Vulnerability Analysis

Analyzing vulnerability scan results for {target}.

**Step 1: Categorize Findings**
Group by:
- Remote Code Execution (RCE) — CRITICAL
- Authentication Bypass — CRITICAL
- SQL Injection — HIGH/CRITICAL
- Cross-Site Scripting (XSS) — MEDIUM/HIGH
- Information Disclosure — LOW/MEDIUM
- Denial of Service — MEDIUM

**Step 2: Cross-Reference CVEs**
For each finding:
- Look up CVE ID in local NVD database
- Check CVSS score
- Verify affected version matches target
- Check if exploit is publicly available

**Step 3: Validate (Anti-Hallucination)**
For each potential vulnerability:
- Was it detected by the actual tool output? (not hallucinated)
- Does the service version match the vulnerable version?
- Is there confirming evidence from multiple tools?
- Could this be a false positive?

**Step 4: Risk Assessment**
Calculate risk = Severity × Exploitability × Impact
- Consider network position (internet-facing vs internal)
- Consider data sensitivity
- Consider existing mitigations

**Step 5: Recommend Actions**
{action_recommendations}
"""

EXPLOIT_PLANNING_COT = """## Exploitation Planning

Planning exploitation for: {finding_title}
Target: {target}
Vulnerability: {vuln_type}

**Step 1: Verify Exploitability**
Before attempting exploitation:
- Confirm vulnerability version match
- Check for mitigating controls (WAF, IPS, ASLR)
- Verify network accessibility
- Assess collateral damage risk

**Step 2: Select Exploit Strategy**
Available approaches:
{exploit_strategies}

**Step 3: Prepare Payload**
Payload requirements:
- Must match target architecture ({architecture})
- Must evade known defenses
- Should minimize detection footprint
- Must have reliable cleanup mechanism

**Step 4: Execute with Safety**
Execution checklist:
[ ] Verify target is in scope
[ ] Confirm authorization level
[ ] Set up monitoring for anomalies
[ ] Prepare rollback procedure
[ ] Execute exploit
[ ] Capture evidence
[ ] Clean up artifacts

**Step 5: Post-Exploitation Assessment**
If successful:
- Document exact reproduction steps
- Assess actual impact (data access, privilege level)
- Check for lateral movement opportunities
- Report with CVSS score and evidence
"""

CODE_AUDIT_COT = """## Code Audit Analysis

Analyzing code at: {target}

**Step 1: Identify Technology Stack**
- Language(s): {languages}
- Framework(s): {frameworks}
- Dependencies: Check for known vulnerable packages

**Step 2: Priority Checks**
1. Input validation (injection points)
2. Authentication/authorization logic
3. Cryptographic implementations
4. Session management
5. File operations (path traversal)
6. Deserialization
7. Command execution
8. SQL queries (parameterized?)
9. Output encoding (XSS prevention)
10. Secret management (hardcoded credentials?)

**Step 3: SAST Results Analysis**
Review findings from:
- semgrep rules (custom + community)
- bandit (Python-specific)
- Language-specific linters
Eliminate known false positives.

**Step 4: Risk Contextualization**
For each finding:
- Is the vulnerable code reachable from user input?
- What's the data flow from source to sink?
- Are there sanitization functions in between?
- What's the worst-case impact?

**Step 5: Remediation Guidance**
{remediation_guidance}
"""


# ── Few-Shot Examples ──────────────────────────────────────

FEW_SHOT_VULN_CLASSIFICATION = """
Example 1:
Tool Output: "nmap port 22 open, OpenSSH 7.6p1"
Classification: LOW — OpenSSH 7.6 has CVE-2018-15473 (username enumeration) but no RCE.
Confidence: 0.7

Example 2:
Tool Output: "nuclei detected CVE-2021-44228 (Log4Shell) on port 8080"
Classification: CRITICAL — Remote Code Execution via JNDI injection, CVSS 10.0.
Confidence: 0.95

Example 3:
Tool Output: "nikto found /admin accessible without authentication"
Classification: HIGH — Administrative interface exposed, potential full system compromise.
Confidence: 0.85

Example 4:
Tool Output: "sqlmap confirmed SQL injection on parameter 'id'"
Classification: CRITICAL — Confirmed SQL injection enables data extraction and potentially RCE.
Confidence: 0.95

Example 5:
Tool Output: "X-Powered-By header present: Express"
Classification: INFO — Information disclosure, no direct security impact.
Confidence: 0.9
"""

FEW_SHOT_TOOL_SELECTION = """
Scenario 1: "Scan target 192.168.1.1 for open ports"
Tools: nmap (quick SYN scan), masscan (if full range needed)
Reasoning: Start with nmap -sS for reliable service detection.

Scenario 2: "Test web application at https://target.com for vulnerabilities"
Tools: nuclei (template scan), nikto (server misconfig), sqlmap (if params found), ffuf (dir discovery)
Reasoning: nuclei covers broadest vulnerability set, nikto adds server-specific checks.

Scenario 3: "Audit the GitHub repository at /path/to/code"
Tools: semgrep (SAST), trufflehog (secrets), trivy (dependency vulns), bandit (if Python)
Reasoning: Multi-layer analysis catches different vulnerability classes.

Scenario 4: "Crack this NTLM hash: aad3b435b51404eeaad3b435b51404ee"
Tools: hashcat (GPU), john (CPU fallback)
Reasoning: NTLM mode 1000 in hashcat, use rockyou wordlist first.
"""


# ── Output Schema Templates ───────────────────────────────

STRUCTURED_FINDING_SCHEMA = {
    "type": "object",
    "properties": {
        "title": {"type": "string", "description": "Short descriptive title"},
        "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
        "cvss_score": {"type": "number", "minimum": 0, "maximum": 10},
        "cve_id": {"type": "string", "description": "CVE identifier if applicable"},
        "description": {"type": "string", "description": "Detailed description"},
        "evidence": {"type": "array", "items": {"type": "string"}},
        "affected_component": {"type": "string"},
        "remediation": {"type": "string"},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "false_positive_risk": {"type": "string", "enum": ["low", "medium", "high"]},
    },
    "required": ["title", "severity", "description", "confidence"],
}

TOOL_SELECTION_SCHEMA = {
    "type": "object",
    "properties": {
        "tool": {"type": "string", "description": "Tool name to execute"},
        "arguments": {"type": "object", "description": "Tool-specific arguments"},
        "reasoning": {"type": "string", "description": "Why this tool was selected"},
        "expected_output": {"type": "string", "description": "What to look for in output"},
        "timeout_s": {"type": "integer", "default": 300},
        "follow_up_tools": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["tool", "arguments", "reasoning"],
}

TASK_DECOMPOSITION_SCHEMA = {
    "type": "object",
    "properties": {
        "subtasks": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "description": {"type": "string"},
                    "agent_role": {"type": "string"},
                    "priority": {"type": "integer", "minimum": 1, "maximum": 10},
                    "dependencies": {"type": "array", "items": {"type": "string"}},
                    "tools_needed": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["description", "agent_role", "priority"],
            },
        },
    },
    "required": ["subtasks"],
}


class PromptEngine:
    """Builds and manages prompts for RecurSec agents."""

    def __init__(self) -> None:
        self._templates: dict[str, str] = {
            "recon_cot": RECON_COT,
            "vuln_analysis_cot": VULN_ANALYSIS_COT,
            "exploit_planning_cot": EXPLOIT_PLANNING_COT,
            "code_audit_cot": CODE_AUDIT_COT,
        }

    def build_recon_prompt(self, ctx: PromptContext) -> str:
        """Build a complete recon prompt with CoT."""
        methods = self._select_recon_methods(ctx.target_type)
        cot = self._templates["recon_cot"].format(
            target=ctx.target,
            target_type=ctx.target_type,
            recon_methods=methods,
        )

        return self._assemble_prompt(
            system="You are a reconnaissance specialist. Discover the complete attack surface.",
            cot=cot,
            tools=ctx.available_tools,
            output_schema=TOOL_SELECTION_SCHEMA,
            max_tokens=ctx.max_tokens,
        )

    def build_vuln_analysis_prompt(
        self, ctx: PromptContext, scan_results: str = ""
    ) -> str:
        """Build vulnerability analysis prompt."""
        cot = self._templates["vuln_analysis_cot"].format(
            target=ctx.target,
            action_recommendations="Prioritize remediations by risk score.",
        )

        return self._assemble_prompt(
            system="You are a vulnerability analyst. Classify and prioritize findings accurately.",
            cot=cot,
            few_shot=FEW_SHOT_VULN_CLASSIFICATION,
            context=scan_results,
            output_schema=STRUCTURED_FINDING_SCHEMA,
            max_tokens=ctx.max_tokens,
        )

    def build_exploit_prompt(
        self,
        ctx: PromptContext,
        finding_title: str = "",
        vuln_type: str = "",
    ) -> str:
        """Build exploitation planning prompt."""
        cot = self._templates["exploit_planning_cot"].format(
            finding_title=finding_title,
            target=ctx.target,
            vuln_type=vuln_type,
            exploit_strategies="1. Direct exploit\n2. Chained exploitation\n3. Social engineering",
            architecture="x86_64",
        )

        return self._assemble_prompt(
            system="You are an exploitation specialist. Plan and execute verified exploits safely.",
            cot=cot,
            tools=ctx.available_tools,
            max_tokens=ctx.max_tokens,
        )

    def build_code_audit_prompt(
        self, ctx: PromptContext, languages: str = "", frameworks: str = ""
    ) -> str:
        """Build code audit prompt."""
        cot = self._templates["code_audit_cot"].format(
            target=ctx.target,
            languages=languages or "auto-detected",
            frameworks=frameworks or "auto-detected",
            remediation_guidance="Provide specific code fixes with examples.",
        )

        return self._assemble_prompt(
            system="You are a code security auditor. Find vulnerabilities in source code.",
            cot=cot,
            few_shot=FEW_SHOT_VULN_CLASSIFICATION,
            output_schema=STRUCTURED_FINDING_SCHEMA,
            max_tokens=ctx.max_tokens,
        )

    def build_task_decomposition_prompt(self, ctx: PromptContext) -> str:
        """Build task decomposition prompt for the orchestrator."""
        return self._assemble_prompt(
            system="You are the orchestrator. Decompose this objective into specialized sub-tasks.",
            context=f"Objective: {ctx.objective}\nTarget: {ctx.target}\nType: {ctx.target_type}",
            output_schema=TASK_DECOMPOSITION_SCHEMA,
            few_shot=FEW_SHOT_TOOL_SELECTION,
            max_tokens=ctx.max_tokens,
        )

    def build_validation_prompt(
        self,
        finding: dict[str, Any],
        tool_outputs: list[str] | None = None,
    ) -> str:
        """Build finding validation prompt (anti-hallucination)."""
        context = f"Finding to validate:\n{json.dumps(finding, indent=2)}"
        if tool_outputs:
            context += "\n\nRaw tool outputs:\n" + "\n---\n".join(tool_outputs[:3])

        return self._assemble_prompt(
            system="""You are a finding validator. Your job is to determine if a security finding is:
1. VALID — confirmed by tool output evidence
2. FALSE POSITIVE — tool output doesn't actually confirm this
3. NEEDS VERIFICATION — inconclusive, requires additional testing

Be skeptical. Only mark as VALID if there is clear evidence in the tool output.
Common false positives: generic server headers, version-only detections without exploit confirmation,
informational findings classified as vulnerabilities.""",
            context=context,
            max_tokens=1024,
        )

    def _assemble_prompt(
        self,
        system: str = "",
        cot: str = "",
        few_shot: str = "",
        context: str = "",
        tools: list[str] | None = None,
        output_schema: dict[str, Any] | None = None,
        max_tokens: int = 4096,
    ) -> str:
        """Assemble a complete prompt from components."""
        parts = []

        if system:
            parts.append(f"[SYSTEM]\n{system}")

        if few_shot:
            parts.append(f"\n[EXAMPLES]\n{few_shot}")

        if cot:
            parts.append(f"\n[REASONING]\n{cot}")

        if context:
            # Truncate context if too long
            max_context = max_tokens * 3  # Rough char estimate
            if len(context) > max_context:
                context = context[:max_context] + "\n... [truncated]"
            parts.append(f"\n[CONTEXT]\n{context}")

        if tools:
            parts.append("\n[AVAILABLE TOOLS]\n" + ", ".join(tools))

        if output_schema:
            parts.append(f"\n[OUTPUT FORMAT]\nRespond with valid JSON matching this schema:\n{json.dumps(output_schema, indent=2)}")

        return "\n".join(parts)

    def _select_recon_methods(self, target_type: str) -> str:
        """Select appropriate recon methods based on target type."""
        methods: dict[str, str] = {
            "host": "1. Port scan (nmap/masscan)\n2. Service enumeration\n3. OS fingerprinting\n4. Banner grabbing",
            "url": "1. Technology fingerprinting\n2. Directory discovery\n3. Parameter enumeration\n4. Subdomain discovery\n5. WAF detection",
            "network_range": "1. Host discovery (ARP/ICMP)\n2. Top-port scan all live hosts\n3. Service enumeration on open ports\n4. Network topology mapping",
            "code_repo": "1. Technology stack identification\n2. Dependency listing\n3. Secret scanning\n4. Framework detection",
            "api": "1. Endpoint discovery\n2. Authentication testing\n3. Parameter fuzzing\n4. Rate limit testing\n5. Schema validation",
            "domain": "1. DNS enumeration\n2. Subdomain discovery\n3. Certificate transparency\n4. WHOIS lookup\n5. Email harvesting",
        }
        return methods.get(target_type, methods["host"])
