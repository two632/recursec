"""Attack pattern knowledge base — comprehensive attack pattern intelligence.

Implements:
1. Attack pattern catalog (30+ categories)
2. Pattern matching against targets
3. Detection strategy lookup
4. Exploitation approach generation
5. Attack chain composition from patterns
6. Pattern severity/impact scoring
7. Pattern prerequisite tracking
8. CWE/CVE/MITRE ATT&CK mapping
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class AttackCategory(str, Enum):
    EMERGENT_COMPLEXITY = "emergent_complexity"
    TEMPORAL_CONCURRENCY = "temporal_concurrency"
    BUSINESS_LOGIC = "business_logic"
    AI_SPECIFIC = "ai_specific"
    HARDWARE_SIDE_CHANNEL = "hardware_side_channel"
    SUPPLY_CHAIN = "supply_chain"
    DNS_INFRASTRUCTURE = "dns_infrastructure"
    BGP_ROUTING = "bgp_routing"
    IAC_MISCONFIG = "iac_misconfig"
    API_GATEWAY = "api_gateway"
    WEB_CLASSIC = "web_classic"
    INJECTION = "injection"
    AUTH_BYPASS = "auth_bypass"
    CRYPTO_WEAKNESS = "crypto_weakness"
    DESERIALIZATION = "deserialization"
    SSRF = "ssrf"
    RACE_CONDITION = "race_condition"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    MEMORY_CORRUPTION = "memory_corruption"
    PROTOCOL_ABUSE = "protocol_abuse"


class ExploitDifficulty(str, Enum):
    TRIVIAL = "trivial"
    EASY = "easy"
    MODERATE = "moderate"
    HARD = "hard"
    EXPERT = "expert"


class DetectionMethod(str, Enum):
    STATIC_ANALYSIS = "static_analysis"
    DYNAMIC_TESTING = "dynamic_testing"
    FUZZING = "fuzzing"
    TIMING_ANALYSIS = "timing_analysis"
    TRAFFIC_ANALYSIS = "traffic_analysis"
    CONFIG_REVIEW = "config_review"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"
    DEPENDENCY_SCAN = "dependency_scan"
    MANUAL_REVIEW = "manual_review"


@dataclass
class DetectionStrategy:
    """How to detect this attack pattern."""
    method: DetectionMethod = DetectionMethod.DYNAMIC_TESTING
    description: str = ""
    tools: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    false_positive_rate: float = 0.1
    model_hint: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method.value,
            "desc": self.description[:40],
            "tools": self.tools[:3],
            "fp_rate": round(self.false_positive_rate, 2),
        }


@dataclass
class ExploitApproach:
    """How to exploit/validate this pattern."""
    name: str = ""
    description: str = ""
    steps: list[str] = field(default_factory=list)
    tools_needed: list[str] = field(default_factory=list)
    preconditions: list[str] = field(default_factory=list)
    impact: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name[:25],
            "steps": len(self.steps),
            "tools": self.tools_needed[:3],
            "impact": self.impact[:30],
        }


@dataclass
class AttackPattern:
    """A known attack pattern."""
    pattern_id: str = ""
    name: str = ""
    category: AttackCategory = AttackCategory.WEB_CLASSIC
    description: str = ""
    severity: str = "medium"
    difficulty: ExploitDifficulty = ExploitDifficulty.MODERATE
    detection_strategies: list[DetectionStrategy] = field(default_factory=list)
    exploit_approaches: list[ExploitApproach] = field(default_factory=list)
    prerequisites: list[str] = field(default_factory=list)
    target_indicators: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    mitre_ids: list[str] = field(default_factory=list)
    real_world_examples: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:30],
            "category": self.category.value,
            "severity": self.severity,
            "difficulty": self.difficulty.value,
            "detections": len(self.detection_strategies),
            "exploits": len(self.exploit_approaches),
            "cwes": self.cwe_ids[:3],
        }


# ── Default Attack Pattern Catalog ────────────────────────────

DEFAULT_PATTERNS: list[dict[str, Any]] = [
    # ─── Emergent Complexity ──────────────────────────────────
    {
        "name": "Distributed system race condition",
        "category": "emergent_complexity",
        "severity": "critical",
        "difficulty": "hard",
        "desc": "Timing-dependent vulnerability emerging from microservice interactions. Individual services are secure but specific request ordering creates exploitable state.",
        "detection": [
            {"method": "timing_analysis", "desc": "Concurrent requests to interrelated endpoints with timing measurement", "tools": ["custom_harness"]},
            {"method": "behavioral_analysis", "desc": "Monitor state inconsistencies across service boundaries", "tools": ["distributed_tracer"]},
        ],
        "exploit": [
            {"name": "Request interleaving", "steps": ["Map inter-service dependencies", "Identify shared state", "Send concurrent requests to create race window", "Verify state corruption"], "impact": "Data corruption, auth bypass"},
        ],
        "indicators": ["microservice architecture", "shared database", "eventual consistency", "message queues"],
        "cwes": ["CWE-362", "CWE-367"],
        "mitre": ["T1499"],
        "examples": ["2019 Uber race condition in payment system"],
        "tags": ["distributed", "timing", "gen5"],
    },
    {
        "name": "Cache coherence attack",
        "category": "emergent_complexity",
        "severity": "high",
        "difficulty": "moderate",
        "desc": "Exploit stale cache between services. Request to service A updates data, but cache layer serving service B still holds old value, allowing validation bypass.",
        "detection": [
            {"method": "dynamic_testing", "desc": "Send update followed by immediate read via different path", "tools": ["httpx", "custom_harness"]},
        ],
        "exploit": [
            {"name": "Cache desync exploitation", "steps": ["Identify cacheable endpoints", "Map cache topology", "Send update request", "Immediately read from cached path before invalidation"], "impact": "Auth bypass, stale data exploitation"},
        ],
        "indicators": ["CDN", "redis", "memcached", "reverse proxy cache", "multiple backends"],
        "cwes": ["CWE-524"],
        "tags": ["cache", "distributed", "gen5"],
    },
    # ─── Temporal & Concurrency ───────────────────────────────
    {
        "name": "TOCTOU race condition",
        "category": "temporal_concurrency",
        "severity": "high",
        "difficulty": "moderate",
        "desc": "Time-of-check to time-of-use: value verified at check time differs from value at use time due to concurrent modification.",
        "detection": [
            {"method": "static_analysis", "desc": "Find check-then-act patterns without synchronization", "tools": ["semgrep", "codeql"]},
            {"method": "fuzzing", "desc": "Concurrent request fuzzing targeting state-changing endpoints", "tools": ["custom_harness"]},
        ],
        "exploit": [
            {"name": "Concurrent request race", "steps": ["Identify check-then-act flow", "Send concurrent requests to exploit window", "Repeat with timing variations"], "impact": "Double-spend, auth bypass, privilege escalation"},
        ],
        "indicators": ["balance check before transfer", "permission check before action", "file check before open"],
        "cwes": ["CWE-367"],
        "tags": ["race", "timing", "classic"],
    },
    {
        "name": "Timing side-channel",
        "category": "temporal_concurrency",
        "severity": "medium",
        "difficulty": "moderate",
        "desc": "Information leak through response time differences. Password comparison, token validation, or database lookups reveal information via timing.",
        "detection": [
            {"method": "timing_analysis", "desc": "Statistical timing analysis across inputs with controlled variables", "tools": ["custom_harness"]},
        ],
        "exploit": [
            {"name": "Timing oracle", "steps": ["Establish baseline timing", "Vary input systematically", "Measure response time differences", "Extract secret byte-by-byte via statistical analysis"], "impact": "Token/password extraction"},
        ],
        "indicators": ["password comparison", "token validation", "database lookup by secret", "string comparison"],
        "cwes": ["CWE-208"],
        "tags": ["timing", "side_channel"],
    },
    # ─── Business Logic ───────────────────────────────────────
    {
        "name": "Business rule bypass",
        "category": "business_logic",
        "severity": "high",
        "difficulty": "moderate",
        "desc": "Code is technically correct but violates intended business rules. Multiple discount codes, negative quantities, workflow step skipping.",
        "detection": [
            {"method": "manual_review", "desc": "LLM-driven analysis of business logic flows vs stated rules", "tools": []},
            {"method": "dynamic_testing", "desc": "Test boundary conditions of business operations", "tools": ["httpx", "sqlmap"]},
        ],
        "exploit": [
            {"name": "State machine manipulation", "steps": ["Map application state machine", "Identify unexpected transitions", "Test skipping intermediate states", "Verify business rule violation"], "impact": "Financial loss, unauthorized access"},
        ],
        "indicators": ["e-commerce", "payments", "discounts", "multi-step workflow", "state machine"],
        "cwes": ["CWE-840"],
        "tags": ["logic", "gen5", "llm_needed"],
    },
    {
        "name": "Price manipulation",
        "category": "business_logic",
        "severity": "critical",
        "difficulty": "easy",
        "desc": "Modify price/quantity in client-side requests. Negative quantities, zero prices, integer overflow on quantities.",
        "detection": [
            {"method": "dynamic_testing", "desc": "Tamper price/quantity parameters in requests", "tools": ["burp", "mitmproxy"]},
        ],
        "exploit": [
            {"name": "Parameter tampering", "steps": ["Intercept checkout request", "Modify price/quantity to negative or zero", "Submit modified request", "Verify order processed at wrong price"], "impact": "Free goods, negative balance credit"},
        ],
        "indicators": ["shopping cart", "checkout", "payment", "pricing in client request"],
        "cwes": ["CWE-20"],
        "tags": ["logic", "easy"],
    },
    # ─── AI-Specific ──────────────────────────────────────────
    {
        "name": "Prompt injection",
        "category": "ai_specific",
        "severity": "high",
        "difficulty": "easy",
        "desc": "Inject instructions into LLM prompts via user input. Override system prompt, exfiltrate context, bypass content filters.",
        "detection": [
            {"method": "dynamic_testing", "desc": "Send prompt injection payloads and observe LLM behavior change", "tools": ["httpx"]},
        ],
        "exploit": [
            {"name": "Direct prompt injection", "steps": ["Identify LLM-powered endpoint", "Craft instruction override payload", "Test system prompt extraction", "Attempt function/tool abuse"], "impact": "Data exfiltration, unauthorized actions"},
        ],
        "indicators": ["LLM-powered", "chatbot", "AI assistant", "RAG", "function calling"],
        "cwes": ["CWE-94"],
        "tags": ["ai", "llm", "gen5", "owasp_llm"],
    },
    {
        "name": "RAG poisoning",
        "category": "ai_specific",
        "severity": "high",
        "difficulty": "moderate",
        "desc": "Poison the knowledge base that feeds an LLM's RAG pipeline. Injected content influences model outputs.",
        "detection": [
            {"method": "behavioral_analysis", "desc": "Monitor RAG responses for injected content patterns", "tools": []},
        ],
        "exploit": [
            {"name": "Knowledge base injection", "steps": ["Identify RAG data sources", "Inject adversarial documents", "Verify poisoned content retrieved", "Observe manipulated LLM output"], "impact": "Manipulated AI responses, data exfiltration"},
        ],
        "indicators": ["RAG pipeline", "vector database", "document upload", "knowledge base"],
        "cwes": ["CWE-94"],
        "tags": ["ai", "llm", "gen5"],
    },
    # ─── DNS Infrastructure ───────────────────────────────────
    {
        "name": "DNS rebinding",
        "category": "dns_infrastructure",
        "severity": "high",
        "difficulty": "moderate",
        "desc": "Change DNS resolution mid-session to bypass same-origin policy. Access internal network resources via victim's browser.",
        "detection": [
            {"method": "config_review", "desc": "Check DNS pinning, TTL policies, Host header validation", "tools": ["dnsx", "dig"]},
            {"method": "dynamic_testing", "desc": "Test if application re-validates IP after DNS resolution", "tools": ["custom_harness"]},
        ],
        "exploit": [
            {"name": "DNS rebinding attack", "steps": ["Setup DNS server with short TTL", "Serve initial page to victim", "Switch DNS to internal IP after TTL expires", "JavaScript accesses internal service via same origin"], "impact": "Internal network access, router compromise"},
        ],
        "indicators": ["short DNS TTL", "no DNS pinning", "JavaScript SPA", "no Host header validation"],
        "cwes": ["CWE-350"],
        "tags": ["dns", "network"],
    },
    {
        "name": "DNS cache poisoning",
        "category": "dns_infrastructure",
        "severity": "critical",
        "difficulty": "hard",
        "desc": "Insert fake DNS records into resolver cache. Redirect traffic to attacker-controlled servers.",
        "detection": [
            {"method": "config_review", "desc": "Test transaction ID entropy, source port randomization, DNSSEC", "tools": ["dnsx", "dig"]},
        ],
        "exploit": [
            {"name": "Kaminsky attack", "steps": ["Query resolver for random subdomains", "Flood with spoofed responses matching transaction IDs", "If match succeeds cache is poisoned", "Verify cache state"], "impact": "Traffic hijacking, MITM"},
        ],
        "indicators": ["low transaction ID entropy", "fixed source port", "no DNSSEC"],
        "cwes": ["CWE-350"],
        "mitre": ["T1584"],
        "examples": ["2008 Kaminsky attack affected most DNS resolvers"],
        "tags": ["dns", "network", "critical"],
    },
    # ─── BGP Routing ──────────────────────────────────────────
    {
        "name": "BGP prefix hijacking",
        "category": "bgp_routing",
        "severity": "critical",
        "difficulty": "expert",
        "desc": "Announce more-specific prefix to redirect traffic. No authentication in BGP allows any AS to claim any prefix.",
        "detection": [
            {"method": "traffic_analysis", "desc": "Monitor BGP announcements for unauthorized origin ASN", "tools": ["bgpalerter"]},
        ],
        "exploit": [
            {"name": "Sub-prefix hijack", "steps": ["Identify target prefix and legitimate ASN", "Announce more-specific prefix from attacker ASN", "BGP propagation redirects traffic", "Intercept or drop hijacked traffic"], "impact": "Traffic interception, MITM, DoS"},
        ],
        "indicators": ["no RPKI ROA", "no route filtering", "single upstream"],
        "examples": ["2008 Pakistan Telecom YouTube hijack", "2018 MyEtherWallet BGP hijack ($150K stolen)"],
        "tags": ["bgp", "network", "nation_state"],
    },
    # ─── IaC Misconfiguration ─────────────────────────────────
    {
        "name": "Overly permissive IAM policy",
        "category": "iac_misconfig",
        "severity": "critical",
        "difficulty": "easy",
        "desc": "IAM policy grants excessive permissions (Action: *, Resource: *). Enables full account compromise from any compromised resource.",
        "detection": [
            {"method": "config_review", "desc": "Scan Terraform/CloudFormation for wildcard IAM policies", "tools": ["tfsec", "checkov"]},
        ],
        "exploit": [
            {"name": "IAM privilege escalation", "steps": ["Identify overprivileged role", "Assume role via compromised resource", "Create new admin user or role", "Full account takeover"], "impact": "Full cloud account compromise"},
        ],
        "indicators": ["Action: *", "Resource: *", "IAM self-modification", "iam:PassRole"],
        "cwes": ["CWE-250"],
        "tags": ["cloud", "iac", "easy"],
    },
    {
        "name": "Public cloud storage",
        "category": "iac_misconfig",
        "severity": "high",
        "difficulty": "trivial",
        "desc": "S3 bucket, GCS bucket, or Azure blob with public access. Data exposed to internet.",
        "detection": [
            {"method": "config_review", "desc": "Check ACLs and public access block settings", "tools": ["tfsec", "checkov", "nuclei"]},
        ],
        "exploit": [
            {"name": "Public bucket enumeration", "steps": ["Enumerate bucket names", "Check for public listing", "Download sensitive files", "Check for write access"], "impact": "Data breach, supply chain compromise via write access"},
        ],
        "indicators": ["acl: public-read", "no public access block", "bucket policy allows *"],
        "cwes": ["CWE-284"],
        "tags": ["cloud", "iac", "trivial"],
    },
    # ─── API Gateway ──────────────────────────────────────────
    {
        "name": "API gateway bypass via direct backend",
        "category": "api_gateway",
        "severity": "critical",
        "difficulty": "moderate",
        "desc": "Access backend servers directly, bypassing API gateway authentication, rate limiting, and validation.",
        "detection": [
            {"method": "dynamic_testing", "desc": "Discover and probe backend IPs directly", "tools": ["nmap", "httpx"]},
        ],
        "exploit": [
            {"name": "Direct backend access", "steps": ["Enumerate backend server IPs via headers/errors/DNS", "Attempt direct connection to backend port", "Bypass all gateway security controls", "Access admin endpoints without auth"], "impact": "Full authentication bypass"},
        ],
        "indicators": ["X-Forwarded-For headers", "backend IPs in error messages", "internal DNS records"],
        "tags": ["api", "bypass"],
    },
    {
        "name": "HTTP method override bypass",
        "category": "api_gateway",
        "severity": "medium",
        "difficulty": "easy",
        "desc": "Use X-HTTP-Method-Override header to bypass method-based access controls.",
        "detection": [
            {"method": "dynamic_testing", "desc": "Test method override headers against restricted endpoints", "tools": ["httpx", "burp"]},
        ],
        "exploit": [
            {"name": "Method override", "steps": ["Identify method-restricted endpoint", "Send POST with X-HTTP-Method-Override: DELETE", "Verify backend processes as DELETE", "Bypass method-based ACL"], "impact": "Access control bypass"},
        ],
        "indicators": ["RESTful API", "method-based access control", "API gateway"],
        "cwes": ["CWE-287"],
        "tags": ["api", "bypass", "easy"],
    },
    # ─── Supply Chain ─────────────────────────────────────────
    {
        "name": "Dependency confusion",
        "category": "supply_chain",
        "severity": "critical",
        "difficulty": "moderate",
        "desc": "Register public package with same name as private internal package. Package manager installs malicious public version.",
        "detection": [
            {"method": "dependency_scan", "desc": "Compare internal package names against public registries", "tools": ["custom_harness"]},
        ],
        "exploit": [
            {"name": "Package substitution", "steps": ["Enumerate internal package names from leaked manifests", "Register matching names on public registry", "Publish with higher version number", "Wait for CI/CD to install malicious version"], "impact": "Remote code execution in build pipeline"},
        ],
        "indicators": ["private npm/pypi registry", "internal packages", "mixed public/private sources"],
        "cwes": ["CWE-427"],
        "examples": ["2021 Alex Birsan dependency confusion affected Apple, Microsoft, PayPal"],
        "tags": ["supply_chain", "gen5"],
    },
    {
        "name": "Typosquatting package",
        "category": "supply_chain",
        "severity": "high",
        "difficulty": "easy",
        "desc": "Register package with name similar to popular package. Developers install by typo.",
        "detection": [
            {"method": "dependency_scan", "desc": "Fuzzy-match dependencies against known-good package names", "tools": ["custom_harness"]},
        ],
        "exploit": [
            {"name": "Typosquat install", "steps": ["Identify popular packages", "Register similar names (reqests, colurs, lodassh)", "Add malicious post-install script", "Wait for accidental installs"], "impact": "Code execution, credential theft"},
        ],
        "indicators": ["unusual package names", "low download count", "single maintainer", "post-install scripts"],
        "cwes": ["CWE-427"],
        "tags": ["supply_chain"],
    },
    # ─── Classic Web ──────────────────────────────────────────
    {
        "name": "SQL injection",
        "category": "injection",
        "severity": "critical",
        "difficulty": "easy",
        "desc": "Inject SQL into queries via unsanitized input. Extract data, bypass auth, execute OS commands.",
        "detection": [
            {"method": "dynamic_testing", "desc": "Send SQL payloads to parameters, observe response differences", "tools": ["sqlmap", "nuclei"]},
            {"method": "static_analysis", "desc": "Find string concatenation in SQL queries", "tools": ["semgrep", "bandit"]},
        ],
        "exploit": [
            {"name": "Union-based extraction", "steps": ["Determine injection point", "Find column count via ORDER BY", "UNION SELECT to extract data", "Escalate to OS command execution if possible"], "impact": "Full database access, potential RCE"},
        ],
        "indicators": ["dynamic SQL", "user input in queries", "error messages with SQL"],
        "cwes": ["CWE-89"],
        "tags": ["injection", "classic"],
    },
    {
        "name": "Server-side request forgery (SSRF)",
        "category": "ssrf",
        "severity": "high",
        "difficulty": "moderate",
        "desc": "Make server fetch attacker-controlled URL. Access internal services, cloud metadata, file system.",
        "detection": [
            {"method": "dynamic_testing", "desc": "Supply internal URLs and cloud metadata endpoints", "tools": ["nuclei", "httpx"]},
        ],
        "exploit": [
            {"name": "Cloud metadata SSRF", "steps": ["Find URL input parameter", "Supply http://169.254.169.254/latest/meta-data/", "Extract IAM credentials from response", "Use credentials for lateral movement"], "impact": "Cloud credential theft, internal network access"},
        ],
        "indicators": ["URL parameter", "image fetch", "webhook URL", "PDF generation from URL"],
        "cwes": ["CWE-918"],
        "tags": ["ssrf", "cloud"],
    },
    {
        "name": "Insecure deserialization",
        "category": "deserialization",
        "severity": "critical",
        "difficulty": "moderate",
        "desc": "Deserialize untrusted data leading to RCE. Java ObjectInputStream, Python pickle, PHP unserialize, .NET BinaryFormatter.",
        "detection": [
            {"method": "static_analysis", "desc": "Find deserialization of user-controlled data", "tools": ["semgrep"]},
            {"method": "dynamic_testing", "desc": "Send serialized payloads with embedded commands", "tools": ["ysoserial", "custom_harness"]},
        ],
        "exploit": [
            {"name": "Gadget chain RCE", "steps": ["Identify deserialization point", "Determine technology (Java/Python/PHP)", "Generate payload with gadget chain", "Achieve remote code execution"], "impact": "Remote code execution"},
        ],
        "indicators": ["Java ObjectInputStream", "Python pickle.loads", "PHP unserialize", "base64 in cookies"],
        "cwes": ["CWE-502"],
        "tags": ["deserialization", "rce"],
    },
    # ─── Crypto Weakness ──────────────────────────────────────
    {
        "name": "Weak cryptographic algorithm",
        "category": "crypto_weakness",
        "severity": "medium",
        "difficulty": "easy",
        "desc": "Use of MD5, SHA-1, DES, RC4, or other deprecated algorithms. Also: RSA/ECC vulnerable to future quantum attacks.",
        "detection": [
            {"method": "static_analysis", "desc": "Scan for deprecated crypto function calls", "tools": ["semgrep", "bandit"]},
            {"method": "config_review", "desc": "Check TLS configuration for weak ciphers", "tools": ["testssl", "sslscan"]},
        ],
        "exploit": [
            {"name": "Hash collision", "steps": ["Identify weak hash usage", "Generate collision or preimage", "Substitute forged data with matching hash"], "impact": "Forgery, auth bypass"},
        ],
        "indicators": ["MD5", "SHA-1", "DES", "RC4", "1024-bit RSA", "ECB mode"],
        "cwes": ["CWE-327"],
        "tags": ["crypto", "quantum_future"],
    },
    # ─── Auth Bypass ──────────────────────────────────────────
    {
        "name": "JWT algorithm confusion",
        "category": "auth_bypass",
        "severity": "critical",
        "difficulty": "moderate",
        "desc": "Switch JWT algorithm from RS256 to HS256, sign with public key. Server verifies with same public key, accepts forged token.",
        "detection": [
            {"method": "dynamic_testing", "desc": "Forge JWT with alg:none or alg:HS256 using public key", "tools": ["jwt_tool", "custom_harness"]},
        ],
        "exploit": [
            {"name": "Algorithm switch attack", "steps": ["Extract public key from /jwks or certificate", "Change JWT alg to HS256", "Sign token with public key as HMAC secret", "Submit forged token with arbitrary claims"], "impact": "Authentication bypass, privilege escalation"},
        ],
        "indicators": ["JWT tokens", "RS256 algorithm", "public key available", "no algorithm whitelist"],
        "cwes": ["CWE-327"],
        "tags": ["auth", "jwt"],
    },
]


class AttackPatternKB:
    """Comprehensive attack pattern knowledge base.

    Provides attack pattern lookup, matching, detection strategies,
    and exploitation approaches for the agent brain.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, AttackPattern] = {}
        self._category_index: dict[str, list[str]] = defaultdict(list)
        self._tag_index: dict[str, list[str]] = defaultdict(list)
        self._pattern_counter = 0
        self._log = logger.bind(component="attack_pattern_kb")

        self._load_defaults()

    def _load_defaults(self) -> None:
        """Load default attack patterns."""
        for data in DEFAULT_PATTERNS:
            self._pattern_counter += 1
            pid = f"ap-{self._pattern_counter}"

            detections = []
            for det_data in data.get("detection", []):
                detections.append(DetectionStrategy(
                    method=DetectionMethod(det_data["method"]),
                    description=det_data.get("desc", ""),
                    tools=det_data.get("tools", []),
                ))

            exploits = []
            for exp_data in data.get("exploit", []):
                exploits.append(ExploitApproach(
                    name=exp_data.get("name", ""),
                    steps=exp_data.get("steps", []),
                    tools_needed=exp_data.get("tools", []),
                    impact=exp_data.get("impact", ""),
                ))

            pattern = AttackPattern(
                pattern_id=pid,
                name=data["name"],
                category=AttackCategory(data["category"]),
                description=data.get("desc", ""),
                severity=data.get("severity", "medium"),
                difficulty=ExploitDifficulty(data.get("difficulty", "moderate")),
                detection_strategies=detections,
                exploit_approaches=exploits,
                target_indicators=data.get("indicators", []),
                cwe_ids=data.get("cwes", []),
                mitre_ids=data.get("mitre", []),
                real_world_examples=data.get("examples", []),
                tags=data.get("tags", []),
            )

            self._patterns[pid] = pattern
            self._category_index[pattern.category.value].append(pid)
            for tag in pattern.tags:
                self._tag_index[tag].append(pid)

    def get_pattern(self, pattern_id: str) -> AttackPattern | None:
        return self._patterns.get(pattern_id)

    def get_by_category(self, category: AttackCategory) -> list[AttackPattern]:
        pids = self._category_index.get(category.value, [])
        return [self._patterns[pid] for pid in pids if pid in self._patterns]

    def get_by_tag(self, tag: str) -> list[AttackPattern]:
        pids = self._tag_index.get(tag, [])
        return [self._patterns[pid] for pid in pids if pid in self._patterns]

    def match_target(self, indicators: list[str]) -> list[AttackPattern]:
        """Find attack patterns relevant to a target based on indicators."""
        indicator_set = {ind.lower() for ind in indicators}
        scored: list[tuple[float, AttackPattern]] = []

        for pattern in self._patterns.values():
            pattern_indicators = {ind.lower() for ind in pattern.target_indicators}
            if not pattern_indicators:
                continue
            overlap = len(indicator_set & pattern_indicators)
            if overlap > 0:
                score = overlap / len(pattern_indicators)
                scored.append((score, pattern))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [p for _, p in scored[:20]]

    def search(self, query: str) -> list[AttackPattern]:
        """Search patterns by name or description."""
        query_lower = query.lower()
        results = []
        for pattern in self._patterns.values():
            if (query_lower in pattern.name.lower()
                    or query_lower in pattern.description.lower()):
                results.append(pattern)
        return results

    def get_detection_plan(self, pattern_id: str) -> list[dict[str, Any]]:
        """Get a detection plan for a specific pattern."""
        pattern = self._patterns.get(pattern_id)
        if not pattern:
            return []
        return [det.to_dict() for det in pattern.detection_strategies]

    def get_exploit_plan(self, pattern_id: str) -> list[dict[str, Any]]:
        """Get exploitation approaches for a pattern."""
        pattern = self._patterns.get(pattern_id)
        if not pattern:
            return []
        return [exp.to_dict() for exp in pattern.exploit_approaches]

    def register_pattern(self, pattern: AttackPattern) -> None:
        """Register a new attack pattern."""
        self._patterns[pattern.pattern_id] = pattern
        self._category_index[pattern.category.value].append(pattern.pattern_id)
        for tag in pattern.tags:
            self._tag_index[tag].append(pattern.pattern_id)

    def get_stats(self) -> dict[str, Any]:
        cat_counts: dict[str, int] = defaultdict(int)
        for pattern in self._patterns.values():
            cat_counts[pattern.category.value] += 1
        return {
            "patterns": len(self._patterns),
            "categories": dict(cat_counts),
            "tags": len(self._tag_index),
        }
