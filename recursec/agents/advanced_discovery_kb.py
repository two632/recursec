"""Advanced vulnerability discovery knowledge base.

Techniques from Mythos, Big Sleep, SAILOR, Qihoo 360:
1. Git History Mining — find pre-fix vulnerabilities via commit analysis
2. Variant Analysis — seed-based similar vulnerability hunting
3. Hypothesis-Driven Discovery — generate and test vulnerability hypotheses
4. Multi-Strategy Hybrid — fuzzing + static + symbolic + LLM reasoning
5. Exploit Chaining — chain individual vulns into full compromise paths
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class DiscoveryStrategy(str, Enum):
    GIT_HISTORY_MINING = "git_history_mining"
    VARIANT_ANALYSIS = "variant_analysis"
    HYPOTHESIS_DRIVEN = "hypothesis_driven"
    MULTI_STRATEGY_HYBRID = "multi_strategy_hybrid"
    EXPLOIT_CHAINING = "exploit_chaining"


@dataclass
class DiscoveryPattern:
    name: str = ""
    strategy: DiscoveryStrategy = DiscoveryStrategy.GIT_HISTORY_MINING
    description: str = ""
    methodology: list[str] = field(default_factory=list)
    llm_prompts: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    effectiveness: str = ""
    severity: str = "critical"

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "strategy": self.strategy.value, "severity": self.severity}


DISCOVERY_PATTERNS: list[DiscoveryPattern] = [
    DiscoveryPattern(
        name="Git History Mining (Mythos-style)",
        strategy=DiscoveryStrategy.GIT_HISTORY_MINING,
        description=(
            "Mine git commit history to find security-relevant changes. "
            "If a commit ADDS a bounds check or security fix, then code "
            "BEFORE that commit was vulnerable. Test against pre-fix "
            "versions to discover pre-patch vulnerabilities. This is how "
            "Mythos found a 27-year-old OpenBSD vulnerability and a "
            "16-year-old FFmpeg flaw that survived 5M automated scans."
        ),
        methodology=[
            "Clone target repository with full history (git clone --no-shallow)",
            "Search commit messages for security keywords: fix, patch, security, vulnerability, CVE, overflow, bounds check, sanitize, validate, bypass, injection",
            "For each security-relevant commit, extract the diff",
            "Identify what the fix ADDED (bounds check, validation, sanitization)",
            "Reason: if this check was added, code BEFORE was vulnerable",
            "Check out the pre-fix commit version",
            "Generate test cases targeting the unfixed code path",
            "Run tests to confirm vulnerability exists in pre-fix code",
            "Check if similar patterns exist ELSEWHERE in current codebase",
            "If variant exists in current code: confirmed 0-day",
        ],
        llm_prompts=[
            "Analyze this git commit diff. What security issue does it fix? What was the vulnerability BEFORE this fix?",
            "This commit adds a bounds check on line {line}. What input would have triggered an overflow BEFORE this fix?",
            "Search the codebase for similar code patterns to {vulnerable_function}. Are there other locations missing the same check?",
            "Generate a test case that would crash the pre-fix version of {function}. Target the specific missing check.",
            "This commit fixes {vulnerability_type}. Look for variant vulnerabilities in related functions.",
        ],
        tools=["git", "gdb", "afl++", "semgrep", "codeql"],
        commands=[
            "git log --all --oneline --grep='fix\\|patch\\|security\\|CVE\\|overflow\\|bounds' | head -50",
            "git log --all --oneline --diff-filter=M -- '*.c' '*.cpp' | head -100",
            "git show <commit_hash> -- <file> | grep -A5 -B5 'check\\|bound\\|valid'",
            "git checkout <pre_fix_commit> && make && ./run_test",
            "semgrep --config auto --lang c --pattern '$X = malloc($SIZE); ... memcpy($X, $SRC, $LEN);' .",
        ],
        effectiveness="Found 27-year-old OpenBSD vuln, 16-year-old FFmpeg flaw. 83.1% success rate.",
        severity="critical",
    ),
    DiscoveryPattern(
        name="Variant Analysis (Big Sleep-style)",
        strategy=DiscoveryStrategy.VARIANT_ANALYSIS,
        description=(
            "Start from a known vulnerability and find VARIANTS: similar "
            "patterns in the same or different codebases. Google Big Sleep "
            "found the first real-world AI-discovered 0-day in SQLite "
            "using this approach. Given a seed vulnerability, the LLM "
            "reasons about what made it vulnerable, then searches for "
            "identical patterns elsewhere."
        ),
        methodology=[
            "Obtain seed vulnerability: CVE description, root cause, affected function",
            "LLM analyzes: What SPECIFIC pattern makes this vulnerable?",
            "Extract the vulnerability signature (e.g., 'sentinel value -1 used without bounds check')",
            "Search entire codebase for same pattern using semantic search",
            "For each candidate match, LLM reasons: Is this exploitable?",
            "Generate targeted test cases for each candidate",
            "Run tests in sandbox to confirm",
            "If confirmed: new 0-day variant discovered",
            "Chain variants together if they affect related subsystems",
        ],
        llm_prompts=[
            "This CVE ({cve_id}) affects {function} due to {root_cause}. What is the EXACT code pattern that causes this?",
            "Search for functions that use the same pattern as {vulnerable_function}: {pattern_description}. List all matches.",
            "For this candidate function {candidate}, does it have the same vulnerability? Reason step by step.",
            "Generate a test case that would trigger the same class of bug in {candidate_function}.",
            "Given these {n} confirmed variants, can they be chained together for higher impact?",
        ],
        tools=["codeql", "semgrep", "joern", "gdb", "python"],
        commands=[
            "codeql query run --database=target_db variant_pattern.ql",
            "semgrep --config variant_rules.yaml --lang c .",
            "joern --script find_similar_patterns.scala",
            "grep -rn '{vulnerable_pattern}' --include='*.c' --include='*.cpp' .",
            "python3 -c 'import ast; # analyze Python code for similar patterns'",
        ],
        effectiveness="Found SQLite 0-day before release. 20+ vulns in FFmpeg/ImageMagick.",
        severity="critical",
    ),
    DiscoveryPattern(
        name="Hypothesis-Driven Discovery",
        strategy=DiscoveryStrategy.HYPOTHESIS_DRIVEN,
        description=(
            "Generate vulnerability hypotheses through multiple strategies, "
            "then systematically test each. Combines git mining, variant "
            "analysis, dangerous code pattern recognition, and dependency "
            "analysis. Each hypothesis is tested independently with "
            "targeted test cases. Iteratively refine based on results."
        ),
        methodology=[
            "Strategy A: Git History Mining → hypotheses from security commits",
            "Strategy B: Variant Analysis → hypotheses from known CVEs",
            "Strategy C: Dangerous Code Patterns → hypotheses from anti-patterns",
            "Strategy D: Dependency Analysis → hypotheses from vulnerable deps",
            "Strategy E: Attacker Mindset → hypotheses from attack surface analysis",
            "For each hypothesis: generate specific test case",
            "Run test in sandbox environment",
            "If crash/undefined behavior: analyze root cause",
            "Develop proof-of-concept exploit",
            "Calculate CVSS severity",
            "Check for exploit chaining opportunities",
        ],
        llm_prompts=[
            "Analyze this codebase. What are the 5 most likely vulnerability types based on the technology stack?",
            "For this function {func}, generate a hypothesis: What could go wrong with malicious input?",
            "Write a test case to prove or disprove this hypothesis: {hypothesis}",
            "This test caused a crash. Analyze the root cause and determine exploitability.",
            "Rate the severity of this confirmed vulnerability. What is the worst-case impact?",
        ],
        tools=["gdb", "afl++", "asan", "msan", "ubsan", "valgrind"],
        commands=[
            "gcc -fsanitize=address,undefined -g -o target target.c",
            "afl-fuzz -i corpus/ -o findings/ -- ./target @@",
            "valgrind --tool=memcheck ./target < malicious_input",
            "gdb -batch -ex 'run < crash_input' -ex 'bt full' ./target",
            "python3 generate_hypothesis_tests.py --target {binary}",
        ],
        effectiveness="SAILOR found 379 vulnerabilities (30x baseline). Systematic approach.",
        severity="critical",
    ),
    DiscoveryPattern(
        name="Multi-Strategy Hybrid",
        strategy=DiscoveryStrategy.MULTI_STRATEGY_HYBRID,
        description=(
            "Combine fuzzing (fast, broad), static analysis (pattern detection), "
            "symbolic execution (deep path exploration), and LLM reasoning "
            "(context understanding) for maximum coverage. Each technique "
            "compensates for the others' weaknesses. LLM orchestrates and "
            "prioritizes based on results from each technique."
        ),
        methodology=[
            "Phase 1 — Static Analysis: identify candidate vulnerable locations",
            "Phase 2 — LLM Triage: prioritize candidates by exploitability",
            "Phase 3 — Targeted Fuzzing: fuzz high-priority candidates",
            "Phase 4 — Symbolic Execution: explore deep paths fuzzing misses",
            "Phase 5 — LLM Analysis: understand crashes, determine root cause",
            "Phase 6 — Exploit Development: LLM writes proof of concept",
            "Phase 7 — Validation: confirm exploit in clean environment",
            "LLM-Augmented Fuzzing: LLM synthesizes inputs for uncovered branches",
            "Coverage feedback loop: LLM analyzes coverage gaps, generates targeted inputs",
        ],
        llm_prompts=[
            "Static analysis found {n} candidates. Rank them by likely exploitability.",
            "Fuzzing hit a coverage plateau. Analyze these uncovered branches and suggest inputs to reach them.",
            "This crash was found by fuzzing. Analyze the root cause and determine if it's exploitable.",
            "Symbolic execution found this path constraint. Is there a concrete input satisfying it?",
            "We have findings from static analysis, fuzzing, and symbolic execution. Correlate them into attack chains.",
        ],
        tools=["semgrep", "codeql", "afl++", "libfuzzer", "angr", "klee", "gdb"],
        commands=[
            "semgrep --config auto --severity ERROR --lang c .",
            "afl-fuzz -i corpus/ -o findings/ -m none -- ./target @@",
            "python3 -c 'import angr; proj = angr.Project(\"target\"); # symbolic execution'",
            "klee --emit-all-errors target.bc",
            "codeql database analyze target_db codeql/cpp-queries",
        ],
        effectiveness="Combined approach: 100x cost reduction vs manual. Hours not weeks.",
        severity="critical",
    ),
    DiscoveryPattern(
        name="Exploit Chaining (Full Compromise Paths)",
        strategy=DiscoveryStrategy.EXPLOIT_CHAINING,
        description=(
            "Don't just find single vulnerabilities — chain them into full "
            "compromise paths. Map trust boundaries, understand sandbox "
            "escapes, and combine multiple low-severity vulns into "
            "critical exploit chains. Mythos chained 4 separate browser "
            "vulnerabilities to achieve full system compromise."
        ),
        methodology=[
            "Map all trust boundaries in the target system",
            "Identify what each individual vulnerability gives you (read/write/exec)",
            "Determine exploitation primitives: arbitrary read, arbitrary write, code exec",
            "Map bypass capabilities: ASLR leak, DEP bypass (ROP), sandbox escape",
            "Build chains: vuln A (info leak) → vuln B (write primitive) → vuln C (code exec) → vuln D (sandbox escape)",
            "LLM reasons about chain feasibility: Can exploit A's output feed into B?",
            "Generate end-to-end proof of concept",
            "Test full chain in sandboxed environment",
            "Calculate aggregate severity (chain is higher than individual vulns)",
        ],
        llm_prompts=[
            "We found these individual vulnerabilities: {vulns}. Map the trust boundaries and identify chaining opportunities.",
            "Vulnerability A gives us {primitive_A}. How can we use this to enable exploitation of vulnerability B?",
            "We need to bypass {mitigation}. Given primitive {primitive}, what technique can we use?",
            "Generate a complete exploit chain from initial access to {objective}.",
            "Test this exploit chain step by step. What is the overall success probability?",
        ],
        tools=["gdb", "pwntools", "ropper", "one_gadget", "radare2", "ghidra"],
        commands=[
            "ropper --file target --search 'pop rdi'",
            "one_gadget /lib/x86_64-linux-gnu/libc.so.6",
            "python3 -c 'from pwn import *; # build exploit chain'",
            "r2 -A target -c 'afl; pdf @main'",
            "checksec --file target",
        ],
        effectiveness="Mythos: 181 browser exploits chaining multiple vulns. Full system compromise.",
        severity="critical",
    ),
]


# Emergent vulnerability patterns (next-gen approach from the attachment)
EMERGENT_PATTERNS: list[dict[str, Any]] = [
    {
        "name": "Distributed System Interaction Bugs",
        "desc": "Vulnerabilities that only appear when multiple services interact in specific sequences with specific timing",
        "detection": [
            "Map entire distributed architecture (microservices, queues, caches, DBs)",
            "Model all possible interaction sequences",
            "Identify dangerous state transitions across service boundaries",
            "Test race conditions between services",
            "Check eventual consistency exploitation",
        ],
    },
    {
        "name": "AI/ML Model Exploitation",
        "desc": "Attacking the AI models themselves: adversarial inputs, prompt injection, model extraction",
        "detection": [
            "Test model boundaries with adversarial inputs",
            "Check for prompt injection in LLM-powered features",
            "Test model extraction via query API",
            "Check for training data leakage",
            "Test AI decision boundary manipulation",
        ],
    },
    {
        "name": "Timing and Side-Channel Attacks",
        "desc": "Vulnerabilities exploiting implementation timing differences and cache behavior",
        "detection": [
            "Measure response time differences for valid vs invalid inputs",
            "Test for cache-based side channels (Spectre/Meltdown variants)",
            "Analyze power consumption patterns (if hardware access)",
            "Test for timing-based authentication bypass",
            "Check cryptographic implementations for timing leaks",
        ],
    },
    {
        "name": "Business Logic Through AI Lens",
        "desc": "Using LLM reasoning to understand business logic and find semantic vulnerabilities",
        "detection": [
            "LLM reads application docs/README to understand business logic",
            "Maps expected vs actual state transitions",
            "Identifies assumptions that can be violated",
            "Tests edge cases in business workflows",
            "Finds authorization bypass through logic understanding",
        ],
    },
    {
        "name": "Supply Chain Deep Inspection",
        "desc": "Going beyond dependency scanning to analyze actual transitive dependency behavior",
        "detection": [
            "Build complete dependency graph including transitive deps",
            "Analyze actual code of each dependency (not just version numbers)",
            "Check for dependency confusion across registries",
            "Test build reproducibility for supply chain integrity",
            "Monitor for dependency behavioral changes between versions",
        ],
    },
]


def build_advanced_discovery_prompt(
    focus_strategy: DiscoveryStrategy | None = None,
    include_emergent: bool = True,
    max_patterns: int = 5,
) -> str:
    """Build LLM prompt with advanced vulnerability discovery knowledge."""
    lines = ["## Advanced Vulnerability Discovery (Mythos/BigSleep/SAILOR-level)\n"]
    patterns = DISCOVERY_PATTERNS
    if focus_strategy:
        patterns = [p for p in patterns if p.strategy == focus_strategy]
    for pattern in patterns[:max_patterns]:
        lines.append(f"### {pattern.name}")
        lines.append(pattern.description)
        lines.append(f"\nEffectiveness: {pattern.effectiveness}")
        lines.append("\nMethodology:")
        for step in pattern.methodology[:5]:
            lines.append(f"  {step}")
        lines.append("\nLLM Prompts to Use:")
        for prompt in pattern.llm_prompts[:3]:
            lines.append(f"  → {prompt}")
        lines.append("\nCommands:")
        for cmd in pattern.commands[:3]:
            lines.append(f"  $ {cmd}")
        lines.append("")

    if include_emergent:
        lines.append("### Next-Gen: Emergent Vulnerability Patterns")
        for ep in EMERGENT_PATTERNS[:3]:
            lines.append(f"\n**{ep['name']}**: {ep['desc']}")
            for det in ep["detection"][:3]:
                lines.append(f"  - {det}")

    return "\n".join(lines)
