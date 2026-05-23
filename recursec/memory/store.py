"""Memory store — persistent state management for agents.

Supports:
- Short-term memory (conversation context per task)
- Long-term memory (findings, knowledge graph via SQLite + ChromaDB)
- Shared state across agents
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import aiosqlite
import structlog

from recursec.core.models import Vulnerability

logger = structlog.get_logger()


class MemoryStore:
    """Unified memory system for RecurSec agents."""

    def __init__(self, db_path: str = "recursec_memory.db", data_dir: str = "data"):
        self.db_path = db_path
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._db: aiosqlite.Connection | None = None
        self._context_cache: dict[str, dict[str, Any]] = {}

    async def initialize(self) -> None:
        """Initialize the database schema."""
        self._db = await aiosqlite.connect(self.db_path)
        await self._db.executescript("""
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                cvss_score REAL,
                cve_id TEXT,
                cwe_id TEXT,
                description TEXT,
                evidence TEXT,
                affected_component TEXT,
                confidence REAL DEFAULT 0.0,
                validated INTEGER DEFAULT 0,
                false_positive INTEGER DEFAULT 0,
                tool_source TEXT,
                discovered_at TEXT,
                raw_json TEXT,
                created_at REAL DEFAULT (strftime('%s', 'now'))
            );

            CREATE TABLE IF NOT EXISTS task_contexts (
                task_id TEXT PRIMARY KEY,
                context_json TEXT NOT NULL,
                updated_at REAL DEFAULT (strftime('%s', 'now'))
            );

            CREATE TABLE IF NOT EXISTS agent_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id TEXT NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                metadata_json TEXT,
                created_at REAL DEFAULT (strftime('%s', 'now'))
            );

            CREATE TABLE IF NOT EXISTS knowledge (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT NOT NULL UNIQUE,
                value TEXT NOT NULL,
                category TEXT DEFAULT 'general',
                created_at REAL DEFAULT (strftime('%s', 'now')),
                updated_at REAL DEFAULT (strftime('%s', 'now'))
            );

            CREATE TABLE IF NOT EXISTS attack_chains (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                steps_json TEXT,
                vulnerabilities_json TEXT,
                success INTEGER DEFAULT 0,
                impact TEXT,
                created_at REAL DEFAULT (strftime('%s', 'now'))
            );

            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                findings_count INTEGER DEFAULT 0,
                started_at REAL,
                completed_at REAL,
                config_json TEXT,
                result_json TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_findings_task ON findings(task_id);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
            CREATE INDEX IF NOT EXISTS idx_messages_task ON agent_messages(task_id);
            CREATE INDEX IF NOT EXISTS idx_scan_target ON scan_history(target);
        """)
        await self._db.commit()
        logger.info("memory_initialized", db_path=self.db_path)

    async def store_context(self, task_id: str, context: dict[str, Any]) -> None:
        """Store or update task context."""
        self._context_cache[task_id] = context
        if self._db:
            await self._db.execute(
                "INSERT OR REPLACE INTO task_contexts (task_id, context_json, updated_at) VALUES (?, ?, ?)",
                (task_id, json.dumps(context), time.time()),
            )
            await self._db.commit()

    async def get_context(self, task_id: str) -> dict[str, Any]:
        """Retrieve task context."""
        if task_id in self._context_cache:
            return self._context_cache[task_id]
        if self._db:
            async with self._db.execute(
                "SELECT context_json FROM task_contexts WHERE task_id = ?", (task_id,)
            ) as cursor:
                row = await cursor.fetchone()
                if row:
                    ctx = json.loads(row[0])
                    self._context_cache[task_id] = ctx
                    return ctx
        return {}

    async def store_finding(self, task_id: str, vuln: Vulnerability) -> None:
        """Store a vulnerability finding."""
        if self._db:
            await self._db.execute(
                """INSERT OR REPLACE INTO findings
                (id, task_id, title, severity, cvss_score, cve_id, cwe_id,
                 description, evidence, affected_component, confidence,
                 validated, false_positive, tool_source, discovered_at, raw_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    vuln.id, task_id, vuln.title, vuln.severity.value,
                    vuln.cvss_score, vuln.cve_id, vuln.cwe_id,
                    vuln.description, vuln.evidence, vuln.affected_component,
                    vuln.confidence, int(vuln.validated), int(vuln.false_positive),
                    vuln.tool_source, vuln.discovered_at.isoformat(),
                    json.dumps(vuln.model_dump(), default=str),
                ),
            )
            await self._db.commit()

    async def get_findings(
        self,
        task_id: str | None = None,
        severity: str | None = None,
        validated_only: bool = False,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Retrieve findings with optional filters."""
        if not self._db:
            return []
        conditions = []
        params: list[Any] = []
        if task_id:
            conditions.append("task_id = ?")
            params.append(task_id)
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if validated_only:
            conditions.append("validated = 1")
            conditions.append("false_positive = 0")

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        query = f"SELECT raw_json FROM findings {where} ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        results = []
        async with self._db.execute(query, params) as cursor:
            async for row in cursor:
                results.append(json.loads(row[0]))
        return results

    async def store_message(self, task_id: str, role: str, content: str, metadata: dict | None = None) -> None:
        """Store an agent message."""
        if self._db:
            await self._db.execute(
                "INSERT INTO agent_messages (task_id, role, content, metadata_json) VALUES (?, ?, ?, ?)",
                (task_id, role, content, json.dumps(metadata or {})),
            )
            await self._db.commit()

    async def store_knowledge(self, key: str, value: str, category: str = "general") -> None:
        """Store knowledge for long-term retrieval."""
        if self._db:
            await self._db.execute(
                """INSERT INTO knowledge (key, value, category, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at""",
                (key, value, category, time.time()),
            )
            await self._db.commit()

    async def search_knowledge(self, query: str, category: str | None = None, limit: int = 10) -> list[dict[str, Any]]:
        """Search knowledge base."""
        if not self._db:
            return []
        conditions = ["(key LIKE ? OR value LIKE ?)"]
        params: list[Any] = [f"%{query}%", f"%{query}%"]
        if category:
            conditions.append("category = ?")
            params.append(category)

        where = f"WHERE {' AND '.join(conditions)}"
        results = []
        async with self._db.execute(
            f"SELECT key, value, category FROM knowledge {where} LIMIT ?",
            [*params, limit],
        ) as cursor:
            async for row in cursor:
                results.append({"key": row[0], "value": row[1], "category": row[2]})
        return results

    async def store_scan(self, target: str, scan_type: str, config: dict | None = None) -> int:
        """Record a new scan."""
        if not self._db:
            return -1
        cursor = await self._db.execute(
            """INSERT INTO scan_history (target, scan_type, status, started_at, config_json)
            VALUES (?, ?, 'running', ?, ?)""",
            (target, scan_type, time.time(), json.dumps(config or {})),
        )
        await self._db.commit()
        return cursor.lastrowid or -1

    async def complete_scan(self, scan_id: int, findings_count: int, result: dict | None = None) -> None:
        """Mark a scan as complete."""
        if self._db:
            await self._db.execute(
                """UPDATE scan_history SET status='completed', findings_count=?,
                completed_at=?, result_json=? WHERE id=?""",
                (findings_count, time.time(), json.dumps(result or {}), scan_id),
            )
            await self._db.commit()

    async def get_stats(self) -> dict[str, Any]:
        """Get memory store statistics."""
        if not self._db:
            return {}
        stats = {}
        for table in ["findings", "agent_messages", "knowledge", "attack_chains", "scan_history"]:
            async with self._db.execute(f"SELECT COUNT(*) FROM {table}") as cursor:
                row = await cursor.fetchone()
                stats[f"{table}_count"] = row[0] if row else 0

        # Severity breakdown
        async with self._db.execute(
            "SELECT severity, COUNT(*) FROM findings GROUP BY severity"
        ) as cursor:
            stats["findings_by_severity"] = {}
            async for row in cursor:
                stats["findings_by_severity"][row[0]] = row[1]

        return stats

    async def close(self) -> None:
        if self._db:
            await self._db.close()
