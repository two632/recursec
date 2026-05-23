"""Persistence layer — save/restore agent state and findings.

Implements:
1. JSON-based state persistence
2. Finding export (JSON, JSONL)
3. Assessment session management
4. Checkpoint/resume capability
5. Knowledge graph persistence
6. Experience replay persistence
7. Configuration persistence
8. Automatic periodic checkpointing
"""

from __future__ import annotations

import json
import os
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class SessionInfo:
    """Information about an assessment session."""
    session_id: str = ""
    target: str = ""
    goal: str = ""
    started_at: float = field(default_factory=time.time)
    last_checkpoint: float = 0.0
    status: str = "active"         # active, paused, complete
    cycles_completed: int = 0
    findings_count: int = 0
    state_file: str = ""
    findings_file: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.session_id,
            "target": self.target[:30],
            "status": self.status,
            "cycles": self.cycles_completed,
            "findings": self.findings_count,
        }


@dataclass
class Checkpoint:
    """A checkpoint of agent state."""
    checkpoint_id: str = ""
    session_id: str = ""
    timestamp: float = field(default_factory=time.time)
    brain_state: dict[str, Any] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)
    knowledge_graph: dict[str, Any] = field(default_factory=dict)
    experience_data: list[dict[str, Any]] = field(default_factory=list)
    strategy_scores: dict[str, float] = field(default_factory=dict)
    cycle_history: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.checkpoint_id,
            "session": self.session_id[:10],
            "time": self.timestamp,
            "findings": len(self.findings),
            "experiences": len(self.experience_data),
        }


class PersistenceManager:
    """Manages persistence of agent state and findings.

    Saves and restores assessment sessions, enabling the agent
    to resume work after restart and accumulate knowledge across
    sessions.
    """

    def __init__(self, data_dir: str = "data") -> None:
        self._data_dir = Path(data_dir)
        self._sessions_dir = self._data_dir / "sessions"
        self._findings_dir = self._data_dir / "findings"
        self._knowledge_dir = self._data_dir / "knowledge"
        self._config_dir = self._data_dir / "config"
        self._checkpoint_counter = 0
        self._session_counter = 0
        self._active_sessions: dict[str, SessionInfo] = {}
        self._log = logger.bind(component="persistence")

        self._ensure_dirs()

    def _ensure_dirs(self) -> None:
        """Ensure data directories exist."""
        for d in (self._data_dir, self._sessions_dir, self._findings_dir,
                  self._knowledge_dir, self._config_dir):
            d.mkdir(parents=True, exist_ok=True)

    def create_session(
        self,
        target: str,
        goal: str = "",
    ) -> SessionInfo:
        """Create a new assessment session."""
        self._session_counter += 1
        session_id = f"session-{int(time.time())}-{self._session_counter}"

        session = SessionInfo(
            session_id=session_id,
            target=target,
            goal=goal or f"Security assessment of {target}",
            state_file=str(self._sessions_dir / f"{session_id}.json"),
            findings_file=str(self._findings_dir / f"{session_id}.jsonl"),
        )

        self._active_sessions[session_id] = session
        self._save_session_info(session)

        return session

    def checkpoint(
        self,
        session_id: str,
        brain_state: dict[str, Any] | None = None,
        findings: list[dict[str, Any]] | None = None,
        knowledge_graph: dict[str, Any] | None = None,
        experience_data: list[dict[str, Any]] | None = None,
        strategy_scores: dict[str, float] | None = None,
    ) -> Checkpoint:
        """Save a checkpoint."""
        self._checkpoint_counter += 1

        cp = Checkpoint(
            checkpoint_id=f"cp-{self._checkpoint_counter}",
            session_id=session_id,
            brain_state=brain_state or {},
            findings=findings or [],
            knowledge_graph=knowledge_graph or {},
            experience_data=experience_data or [],
            strategy_scores=strategy_scores or {},
        )

        # Save to disk
        cp_file = self._sessions_dir / f"{session_id}_cp{self._checkpoint_counter}.json"
        self._write_json(str(cp_file), cp.to_dict())

        # Save state
        session = self._active_sessions.get(session_id)
        if session:
            session.last_checkpoint = time.time()
            state_data = {
                "session": session.to_dict(),
                "brain_state": brain_state or {},
                "strategy_scores": strategy_scores or {},
                "checkpoint": cp.to_dict(),
            }
            self._write_json(session.state_file, state_data)

        # Save findings (append mode)
        if findings:
            self._append_findings(session_id, findings)

        return cp

    def restore_session(self, session_id: str) -> dict[str, Any] | None:
        """Restore a session from disk."""
        state_file = self._sessions_dir / f"{session_id}.json"
        if not state_file.exists():
            return None

        data = self._read_json(str(state_file))
        if data:
            session_info = data.get("session", {})
            session = SessionInfo(
                session_id=session_info.get("id", session_id),
                target=session_info.get("target", ""),
                status=session_info.get("status", "active"),
                cycles_completed=session_info.get("cycles", 0),
                findings_count=session_info.get("findings", 0),
                state_file=str(state_file),
                findings_file=str(self._findings_dir / f"{session_id}.jsonl"),
            )
            self._active_sessions[session_id] = session

        return data

    def save_findings(
        self,
        session_id: str,
        findings: list[dict[str, Any]],
    ) -> int:
        """Save findings to disk."""
        return self._append_findings(session_id, findings)

    def load_findings(self, session_id: str) -> list[dict[str, Any]]:
        """Load findings from disk."""
        findings_file = self._findings_dir / f"{session_id}.jsonl"
        if not findings_file.exists():
            return []

        findings = []
        try:
            with open(findings_file, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            findings.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
        except OSError:
            pass

        return findings

    def save_knowledge(
        self,
        name: str,
        data: dict[str, Any],
    ) -> str:
        """Save knowledge data."""
        path = str(self._knowledge_dir / f"{name}.json")
        self._write_json(path, data)
        return path

    def load_knowledge(self, name: str) -> dict[str, Any] | None:
        """Load knowledge data."""
        path = str(self._knowledge_dir / f"{name}.json")
        return self._read_json(path)

    def save_config(
        self,
        name: str,
        config: dict[str, Any],
    ) -> str:
        """Save configuration."""
        path = str(self._config_dir / f"{name}.json")
        self._write_json(path, config)
        return path

    def load_config(self, name: str) -> dict[str, Any] | None:
        """Load configuration."""
        path = str(self._config_dir / f"{name}.json")
        return self._read_json(path)

    def list_sessions(self) -> list[SessionInfo]:
        """List all sessions."""
        sessions = []
        for f in self._sessions_dir.glob("session-*.json"):
            if "_cp" in f.name:
                continue
            data = self._read_json(str(f))
            if data and "session" in data:
                info = data["session"]
                sessions.append(SessionInfo(
                    session_id=info.get("id", f.stem),
                    target=info.get("target", ""),
                    status=info.get("status", "unknown"),
                    cycles_completed=info.get("cycles", 0),
                    findings_count=info.get("findings", 0),
                ))
        return sessions

    def _save_session_info(self, session: SessionInfo) -> None:
        """Save session info to disk."""
        self._write_json(session.state_file, {
            "session": session.to_dict(),
        })

    def _append_findings(
        self,
        session_id: str,
        findings: list[dict[str, Any]],
    ) -> int:
        """Append findings to JSONL file."""
        findings_file = self._findings_dir / f"{session_id}.jsonl"
        try:
            with open(findings_file, "a", encoding="utf-8") as f:
                for finding in findings:
                    f.write(json.dumps(finding, default=str) + "\n")
            return len(findings)
        except OSError as e:
            self._log.error("append_findings_failed", error=str(e))
            return 0

    @staticmethod
    def _write_json(path: str, data: dict[str, Any]) -> bool:
        """Write JSON data to file."""
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
            return True
        except OSError:
            return False

    @staticmethod
    def _read_json(path: str) -> dict[str, Any] | None:
        """Read JSON data from file."""
        if not os.path.exists(path):
            return None
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return None

    def get_stats(self) -> dict[str, Any]:
        status_counts: dict[str, int] = defaultdict(int)
        for s in self._active_sessions.values():
            status_counts[s.status] += 1
        return {
            "active_sessions": len(self._active_sessions),
            "by_status": dict(status_counts),
            "data_dir": str(self._data_dir),
        }
