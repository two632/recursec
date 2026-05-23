"""Code vulnerability knowledge base.

Deep knowledge about source code vulnerabilities:
1. Language-specific vulnerability patterns
2. Dangerous function lists
3. SAST rule patterns
4. Secure coding guidelines
5. Dependency vulnerability patterns
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class CodeVulnPattern:
    """A code vulnerability pattern."""
    pattern_id: str = ""
    name: str = ""
    language: str = ""
    cwe: str = ""
    severity: str = "medium"
    description: str = ""
    detection_strategy: str = ""
    dangerous_functions: list[str] = field(default_factory=list)
    safe_alternatives: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:25],
            "language": self.language[:10],
            "cwe": self.cwe[:10],
        }


CODE_VULN_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "code-001", "name": "Python Injection Vulnerabilities",
        "language": "python", "cwe": "CWE-78,CWE-94",
        "severity": "critical",
        "desc": "Python command and code injection patterns.",
        "detection": (
            "PYTHON INJECTION PATTERNS:\n"
            "COMMAND INJECTION (CWE-78):\n"
            "  Dangerous: os.system(), os.popen(), subprocess.call(shell=True)\n"
            "  Dangerous: subprocess.Popen(shell=True), commands.getoutput()\n"
            "  Safe: subprocess.run([cmd, arg], shell=False)\n"
            "  Detection: grep -rn 'os\\.system\\|os\\.popen\\|shell=True'\n"
            "CODE INJECTION (CWE-94):\n"
            "  Dangerous: eval(), exec(), compile()\n"
            "  Dangerous: __import__(), importlib with user input\n"
            "  Detection: grep -rn 'eval(\\|exec(\\|compile('\n"
            "TEMPLATE INJECTION (CWE-1336):\n"
            "  Dangerous: Jinja2 with autoescape=False\n"
            "  Dangerous: render_template_string(user_input)\n"
            "  Safe: Jinja2(autoescape=True), escape()\n"
            "PICKLE DESERIALIZATION (CWE-502):\n"
            "  Dangerous: pickle.loads(user_data), pickle.load(user_file)\n"
            "  Safe: json.loads(), yaml.safe_load()\n"
            "SQL INJECTION:\n"
            "  Dangerous: f'SELECT * FROM users WHERE id={user_id}'\n"
            "  Dangerous: cursor.execute('SELECT * FROM %s' % table)\n"
            "  Safe: cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))\n"
            "PATH TRAVERSAL (CWE-22):\n"
            "  Dangerous: open(user_path), os.path.join(base, user_input)\n"
            "  Safe: pathlib.Path(base).joinpath(user_input).resolve()"
        ),
        "dangerous_funcs": ["eval", "exec", "os.system", "os.popen", "pickle.loads", "subprocess.call(shell=True)"],
        "safe_alts": ["ast.literal_eval", "subprocess.run(shell=False)", "json.loads", "yaml.safe_load"],
        "tools": ["semgrep", "bandit"],
    },
    {
        "id": "code-002", "name": "JavaScript/Node.js Vulnerabilities",
        "language": "javascript", "cwe": "CWE-79,CWE-94,CWE-22",
        "severity": "high",
        "desc": "JavaScript and Node.js vulnerability patterns.",
        "detection": (
            "JAVASCRIPT VULNERABILITY PATTERNS:\n"
            "XSS (CWE-79):\n"
            "  Dangerous: innerHTML, document.write(), outerHTML\n"
            "  Dangerous: v-html (Vue), dangerouslySetInnerHTML (React)\n"
            "  Safe: textContent, createElement(), DOMPurify.sanitize()\n"
            "PROTOTYPE POLLUTION:\n"
            "  Dangerous: Object.assign(target, user_input)\n"
            "  Dangerous: lodash.merge(), deepmerge with user data\n"
            "  Detection: Check for __proto__, constructor.prototype in input\n"
            "COMMAND INJECTION:\n"
            "  Dangerous: child_process.exec(user_input)\n"
            "  Safe: child_process.execFile(cmd, [args])\n"
            "PATH TRAVERSAL:\n"
            "  Dangerous: path.join(base, req.params.file)\n"
            "  Safe: path.resolve() + validate within base directory\n"
            "INSECURE DEPENDENCIES:\n"
            "  npm audit, snyk test\n"
            "  Check for known malicious packages\n"
            "  Verify package integrity (npm signatures)\n"
            "SSRF:\n"
            "  Dangerous: axios.get(user_url), fetch(user_url)\n"
            "  Safe: URL allowlist, validate against private IP ranges\n"
            "REGEX DOS:\n"
            "  Dangerous: Complex regex with user input\n"
            "  Detection: safe-regex, regexp-tree\n"
            "  Safe: RE2 (linear time regex engine)"
        ),
        "dangerous_funcs": ["eval", "innerHTML", "document.write", "child_process.exec", "__proto__"],
        "safe_alts": ["textContent", "DOMPurify.sanitize", "child_process.execFile"],
        "tools": ["semgrep", "eslint-plugin-security", "npm audit"],
    },
    {
        "id": "code-003", "name": "Java Vulnerabilities",
        "language": "java", "cwe": "CWE-502,CWE-611,CWE-89",
        "severity": "critical",
        "desc": "Java-specific vulnerability patterns.",
        "detection": (
            "JAVA VULNERABILITY PATTERNS:\n"
            "DESERIALIZATION (CWE-502):\n"
            "  Dangerous: ObjectInputStream.readObject()\n"
            "  Dangerous: XMLDecoder, XStream, Java native serialization\n"
            "  Detection: ysoserial for gadget chain testing\n"
            "  Safe: JSON serialization, allowlist deserialization filters\n"
            "XML EXTERNAL ENTITY (CWE-611):\n"
            "  Dangerous: DocumentBuilderFactory without disabling XXE\n"
            "  Dangerous: SAXParser, XMLReader without feature flags\n"
            "  Safe: factory.setFeature('http://apache.org/xml/features/disallow-doctype-decl', true)\n"
            "SQL INJECTION:\n"
            "  Dangerous: Statement.execute(userInput)\n"
            "  Dangerous: String.format('SELECT * FROM %s', table)\n"
            "  Safe: PreparedStatement with parameterized queries\n"
            "LOG INJECTION (Log4Shell):\n"
            "  Dangerous: log.info(user_input) with JNDI lookup enabled\n"
            "  Detection: Check Log4j version < 2.17.0\n"
            "  Safe: Log4j >= 2.17.0, formatMsgNoLookups=true\n"
            "SPRING SECURITY:\n"
            "  - SpEL injection via @Value or expression parsing\n"
            "  - Mass assignment via @ModelAttribute\n"
            "  - Actuator exposure (/actuator/env, /actuator/heapdump)"
        ),
        "dangerous_funcs": ["ObjectInputStream.readObject", "Runtime.exec", "Statement.execute", "ProcessBuilder"],
        "safe_alts": ["PreparedStatement", "ObjectInputFilter", "DocumentBuilderFactory(XXE-disabled)"],
        "tools": ["semgrep", "spotbugs", "pmd"],
    },
    {
        "id": "code-004", "name": "Go Vulnerabilities",
        "language": "go", "cwe": "CWE-78,CWE-89,CWE-295",
        "severity": "high",
        "desc": "Go-specific vulnerability patterns.",
        "detection": (
            "GO VULNERABILITY PATTERNS:\n"
            "COMMAND INJECTION:\n"
            "  Dangerous: exec.Command('sh', '-c', userInput)\n"
            "  Safe: exec.Command(cmd, arg1, arg2) without shell\n"
            "SQL INJECTION:\n"
            "  Dangerous: db.Query('SELECT * FROM users WHERE id=' + id)\n"
            "  Safe: db.Query('SELECT * FROM users WHERE id=?', id)\n"
            "TLS VERIFICATION:\n"
            "  Dangerous: InsecureSkipVerify: true\n"
            "  Detection: grep -rn 'InsecureSkipVerify'\n"
            "RACE CONDITIONS:\n"
            "  - Concurrent map access without sync.Mutex\n"
            "  - go test -race for detection\n"
            "  - Use sync.Map or sync.RWMutex\n"
            "ERROR HANDLING:\n"
            "  - Unchecked errors: if err != nil missing\n"
            "  - errcheck linter for detection\n"
            "PATH TRAVERSAL:\n"
            "  Dangerous: filepath.Join(base, userInput) without Clean\n"
            "  Safe: filepath.Clean() + verify prefix match"
        ),
        "dangerous_funcs": ["exec.Command(sh,-c)", "InsecureSkipVerify", "fmt.Sprintf(SQL)"],
        "safe_alts": ["exec.Command(direct)", "crypto/tls(verified)", "db.Query(parameterized)"],
        "tools": ["semgrep", "gosec", "staticcheck"],
    },
    {
        "id": "code-005", "name": "C/C++ Memory Safety",
        "language": "c_cpp", "cwe": "CWE-119,CWE-120,CWE-416",
        "severity": "critical",
        "desc": "C/C++ memory safety vulnerability patterns.",
        "detection": (
            "C/C++ MEMORY SAFETY PATTERNS:\n"
            "BUFFER OVERFLOW (CWE-120):\n"
            "  Dangerous: strcpy(), strcat(), sprintf(), gets()\n"
            "  Safe: strncpy(), strncat(), snprintf(), fgets()\n"
            "  Detection: -fsanitize=address (ASAN)\n"
            "USE-AFTER-FREE (CWE-416):\n"
            "  - free(ptr) then dereference ptr\n"
            "  - Return pointer to local variable\n"
            "  Detection: -fsanitize=address, valgrind\n"
            "FORMAT STRING (CWE-134):\n"
            "  Dangerous: printf(user_input), syslog(priority, user_input)\n"
            "  Safe: printf('%s', user_input)\n"
            "INTEGER OVERFLOW (CWE-190):\n"
            "  - Unchecked arithmetic on user-controlled sizes\n"
            "  - malloc(size * count) without overflow check\n"
            "  Safe: Use safe integer arithmetic libraries\n"
            "DOUBLE FREE (CWE-415):\n"
            "  - Multiple free() calls on same pointer\n"
            "  Safe: Set pointer to NULL after free\n"
            "NULL DEREFERENCE (CWE-476):\n"
            "  - Missing NULL check after malloc/calloc\n"
            "  - Missing NULL check on function return"
        ),
        "dangerous_funcs": ["strcpy", "strcat", "sprintf", "gets", "printf(user)", "scanf"],
        "safe_alts": ["strncpy", "strncat", "snprintf", "fgets"],
        "tools": ["semgrep", "cppcheck", "clang-tidy", "valgrind"],
    },
    {
        "id": "code-006", "name": "PHP Vulnerabilities",
        "language": "php", "cwe": "CWE-78,CWE-89,CWE-98",
        "severity": "critical",
        "desc": "PHP-specific vulnerability patterns.",
        "detection": (
            "PHP VULNERABILITY PATTERNS:\n"
            "COMMAND INJECTION:\n"
            "  Dangerous: exec(), system(), passthru(), shell_exec()\n"
            "  Dangerous: backtick operator: `$cmd`\n"
            "  Safe: escapeshellarg(), escapeshellcmd()\n"
            "SQL INJECTION:\n"
            "  Dangerous: mysql_query('SELECT * FROM ' . $input)\n"
            "  Safe: PDO with prepared statements\n"
            "FILE INCLUSION (CWE-98):\n"
            "  Dangerous: include($user_input), require($user_path)\n"
            "  Dangerous: include('pages/' . $_GET['page'] . '.php')\n"
            "  Safe: Allowlist of valid include files\n"
            "OBJECT INJECTION:\n"
            "  Dangerous: unserialize(user_data)\n"
            "  Safe: json_decode(), implement __wakeup() guards\n"
            "TYPE JUGGLING:\n"
            "  - strcmp() == 0 with array input returns NULL\n"
            "  - == vs === comparison issues\n"
            "  - magic_hash: 0e... strings equal to 0\n"
            "FILE UPLOAD:\n"
            "  - Check file extension, MIME type, and magic bytes\n"
            "  - Store outside webroot\n"
            "  - Generate random filenames"
        ),
        "dangerous_funcs": ["eval", "exec", "system", "passthru", "shell_exec", "include", "unserialize"],
        "safe_alts": ["escapeshellarg", "PDO::prepare", "json_decode"],
        "tools": ["semgrep", "phpstan", "psalm"],
    },
]


class CodeVulnKB:
    """Code vulnerability knowledge base.

    Provides language-specific vulnerability patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, CodeVulnPattern] = {}
        self._log = logger.bind(component="code_vuln_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load code vulnerability patterns."""
        for data in CODE_VULN_PATTERNS:
            pattern = CodeVulnPattern(
                pattern_id=data["id"],
                name=data["name"],
                language=data.get("language", ""),
                cwe=data.get("cwe", ""),
                severity=data.get("severity", "medium"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                dangerous_functions=data.get("dangerous_funcs", []),
                safe_alternatives=data.get("safe_alts", []),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_language(self, language: str) -> list[CodeVulnPattern]:
        """Get patterns for a specific language."""
        return [
            p for p in self._patterns.values()
            if p.language.lower() == language.lower()
        ]

    def build_code_vuln_prompt(
        self,
        languages: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build code vulnerability prompt."""
        lines = ["## Code Vulnerability Patterns\n"]
        count = 0
        for pattern in self._patterns.values():
            if languages and pattern.language.lower() not in [lang.lower() for lang in languages]:
                continue
            if count >= max_patterns:
                break
            lines.append(f"### {pattern.name} [{pattern.cwe}]")
            lines.append(pattern.detection_strategy)
            lines.append("")
            count += 1
        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        lang_counts: dict[str, int] = {}
        for p in self._patterns.values():
            lang_counts[p.language] = lang_counts.get(p.language, 0) + 1
        return {
            "patterns": len(self._patterns),
            "by_language": lang_counts,
        }
