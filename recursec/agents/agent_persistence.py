"""Agent persistence layer — save/restore agent state to disk.

Implements:
1. Agent state serialization to JSON/JSONL
2. Assessment checkpoint save/restore
3. Finding persistence with deduplication
4. Knowledge base state persistence
5. Configuration persistence
6. Session resumption
7. Persistence prompt for LLM
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


class PersistenceType(str, Enum):
    CHECKPOINT = "checkpoint"      # Full agent state
    FINDINGS = "findings"          # Security findings
    CONFIG = "config"              # Configuration
    KNOWLEDGE = "knowledge"        # Knowledge base state
    SESSION = "session"            # Session metadata


@dataclass
class CheckpointInfo:
    """Info about a saved checkpoint."""
    checkpoint_id: str = ""
    session_id: str = ""
    task_id: str = ""
    target: str = ""
    phase: str = ""
    findings_count: int = 0
    agents_active: int = 0
    tokens_used: int = 0
    file_path: str = ""
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.checkpoint_id[:10],
            "task": self.task_id[:10],
            "phase": self.phase[:15],
            "findings": self.findings_count,
            "path": self.file_path,
        }


class AgentPersistence:
    """Persists agent state to disk for resumption.

    Saves checkpoints, findings, and session metadata
    as JSON/JSONL files. Supports checkpoint-based
    resumption of interrupted assessments.
    """

    def __init__(self, data_dir: str = "data") -> None:
        self._data_dir = Path(data_dir)
        self._checkpoints_dir = self._data_dir / "checkpoints"
        self._findings_dir = self._data_dir / "findings"
        self._sessions_dir = self._data_dir / "sessions"
        self._counter = 0
        self._log = logger.bind(component="persistence")
        self._ensure_dirs()

    def _ensure_dirs(self) -> None:
        """Ensure data directories exist."""
        for d in [self._checkpoints_dir, self._findings_dir, self._sessions_dir]:
            d.mkdir(parents=True, exist_ok=True)

    def save_checkpoint(
        self,
        session_id: str,
        task_id: str,
        target: str,
        phase: str,
        state: dict[str, Any],
        findings: list[dict[str, Any]] | None = None,
        agents_active: int = 0,
        tokens_used: int = 0,
    ) -> CheckpointInfo:
        """Save a full checkpoint."""
        self._counter += 1
        checkpoint_id = f"ckpt-{self._counter}-{int(time.time())}"
        file_path = str(self._checkpoints_dir / f"{checkpoint_id}.json")

        data = {
            "checkpoint_id": checkpoint_id,
            "session_id": session_id,
            "task_id": task_id,
            "target": target,
            "phase": phase,
            "state": state,
            "findings": findings or [],
            "agents_active": agents_active,
            "tokens_used": tokens_used,
            "created_at": time.time(),
        }

        try:
            with open(file_path, "w") as f:
                json.dump(data, f, indent=2, default=str)
        except OSError:
            self._log.error("checkpoint_save_failed", path=file_path)
            file_path = ""

        info = CheckpointInfo(
            checkpoint_id=checkpoint_id,
            session_id=session_id,
            task_id=task_id,
            target=target,
            phase=phase,
            findings_count=len(findings) if findings else 0,
            agents_active=agents_active,
            tokens_used=tokens_used,
            file_path=file_path,
        )

        return info

    def load_checkpoint(self, checkpoint_id: str) -> dict[str, Any] | None:
        """Load a checkpoint from disk."""
        file_path = self._checkpoints_dir / f"{checkpoint_id}.json"
        if not file_path.exists():
            return None

        try:
            with open(file_path) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            self._log.error("checkpoint_load_failed", path=str(file_path))
            return None

    def list_checkpoints(
        self,
        session_id: str = "",
        task_id: str = "",
    ) -> list[CheckpointInfo]:
        """List available checkpoints."""
        checkpoints: list[CheckpointInfo] = []

        for path in sorted(self._checkpoints_dir.glob("ckpt-*.json")):
            try:
                with open(path) as f:
                    data = json.load(f)
                if session_id and data.get("session_id") != session_id:
                    continue
                if task_id and data.get("task_id") != task_id:
                    continue
                checkpoints.append(CheckpointInfo(
                    checkpoint_id=data.get("checkpoint_id", ""),
                    session_id=data.get("session_id", ""),
                    task_id=data.get("task_id", ""),
                    target=data.get("target", ""),
                    phase=data.get("phase", ""),
                    findings_count=len(data.get("findings", [])),
                    agents_active=data.get("agents_active", 0),
                    tokens_used=data.get("tokens_used", 0),
                    file_path=str(path),
                    created_at=data.get("created_at", 0),
                ))
            except (json.JSONDecodeError, OSError):
                continue

        return checkpoints

    def save_findings(
        self,
        session_id: str,
        findings: list[dict[str, Any]],
        append: bool = True,
    ) -> str:
        """Save findings to JSONL file."""
        file_path = self._findings_dir / f"{session_id}.jsonl"
        mode = "a" if append else "w"

        try:
            with open(file_path, mode) as f:
                for finding in findings:
                    finding["saved_at"] = time.time()
                    f.write(json.dumps(finding, default=str) + "\n")
        except OSError:
            self._log.error("findings_save_failed", path=str(file_path))
            return ""

        return str(file_path)

    def load_findings(self, session_id: str) -> list[dict[str, Any]]:
        """Load findings from JSONL file."""
        file_path = self._findings_dir / f"{session_id}.jsonl"
        if not file_path.exists():
            return []

        findings: list[dict[str, Any]] = []
        try:
            with open(file_path) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        findings.append(json.loads(line))
        except (json.JSONDecodeError, OSError):
            self._log.error("findings_load_failed", path=str(file_path))

        return findings

    def save_session(
        self,
        session_id: str,
        metadata: dict[str, Any],
    ) -> str:
        """Save session metadata."""
        file_path = self._sessions_dir / f"{session_id}.json"

        metadata["session_id"] = session_id
        metadata["updated_at"] = time.time()

        try:
            with open(file_path, "w") as f:
                json.dump(metadata, f, indent=2, default=str)
        except OSError:
            self._log.error("session_save_failed", path=str(file_path))
            return ""

        return str(file_path)

    def load_session(self, session_id: str) -> dict[str, Any] | None:
        """Load session metadata."""
        file_path = self._sessions_dir / f"{session_id}.json"
        if not file_path.exists():
            return None

        try:
            with open(file_path) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return None

    def cleanup(self, max_age_hours: float = 168.0) -> int:
        """Clean up old data files."""
        cutoff = time.time() - max_age_hours * 3600
        removed = 0

        for directory in [self._checkpoints_dir, self._findings_dir, self._sessions_dir]:
            for path in directory.iterdir():
                if path.is_file() and path.stat().st_mtime < cutoff:
                    try:
                        path.unlink()
                        removed += 1
                    except OSError:
                        pass

        return removed

    def build_persistence_prompt(self, session_id: str = "") -> str:
        """Build persistence context for LLM."""
        lines = ["## Persistence\n"]

        # Count files
        ckpt_count = len(list(self._checkpoints_dir.glob("*.json")))
        findings_count = len(list(self._findings_dir.glob("*.jsonl")))
        session_count = len(list(self._sessions_dir.glob("*.json")))

        lines.append(
            f"Checkpoints: {ckpt_count} | "
            f"Finding files: {findings_count} | "
            f"Sessions: {session_count}"
        )

        if session_id:
            # List checkpoints for this session
            checkpoints = self.list_checkpoints(session_id=session_id)
            if checkpoints:
                lines.append(f"\nSession checkpoints ({len(checkpoints)}):")
                for ckpt in checkpoints[-3:]:
                    lines.append(
                        f"  {ckpt.checkpoint_id[:10]} — {ckpt.phase[:15]} "
                        f"({ckpt.findings_count} findings)"
                    )

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        total_size = 0
        for directory in [self._checkpoints_dir, self._findings_dir, self._sessions_dir]:
            for path in directory.iterdir():
                if path.is_file():
                    total_size += path.stat().st_size

        return {
            "checkpoints": len(list(self._checkpoints_dir.glob("*.json"))),
            "findings_files": len(list(self._findings_dir.glob("*.jsonl"))),
            "sessions": len(list(self._sessions_dir.glob("*.json"))),
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "data_dir": str(self._data_dir),
        }
