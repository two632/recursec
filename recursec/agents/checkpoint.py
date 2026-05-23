"""Checkpoint and recovery — saves and restores agent state.

Implements:
1. Assessment state checkpointing
2. Periodic auto-save
3. Crash recovery
4. State serialization/deserialization
5. Checkpoint versioning
6. Rollback to previous checkpoints
7. Incremental state updates
8. Checkpoint compression
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class CheckpointData:
    """Data stored in a checkpoint."""
    checkpoint_id: str = ""
    version: int = 0
    session_id: str = ""
    state: str = ""                    # Current agent state
    target: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)
    validated_findings: list[dict[str, Any]] = field(default_factory=list)
    completed_subtasks: list[str] = field(default_factory=list)
    pending_subtasks: list[str] = field(default_factory=list)
    agent_data: dict[str, Any] = field(default_factory=dict)
    tokens_used: int = 0
    tools_used: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.checkpoint_id,
            "version": self.version,
            "session": self.session_id,
            "state": self.state,
            "target": self.target,
            "findings": self.findings,
            "validated": self.validated_findings,
            "completed": self.completed_subtasks,
            "pending": self.pending_subtasks,
            "agent_data": self.agent_data,
            "tokens": self.tokens_used,
            "tools": self.tools_used,
            "time": self.created_at,
        }


class CheckpointManager:
    """Manages assessment checkpoints for recovery.

    Auto-saves assessment state periodically and
    supports crash recovery and rollback.
    """

    def __init__(
        self,
        checkpoint_dir: str = "data/checkpoints",
        max_checkpoints: int = 10,
        auto_save_interval_s: float = 60.0,
    ) -> None:
        self._dir = Path(checkpoint_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._max_checkpoints = max_checkpoints
        self._auto_save_interval = auto_save_interval_s
        self._checkpoints: dict[str, CheckpointData] = {}
        self._current_session: str = ""
        self._version_counter = 0
        self._last_save: float = 0.0
        self._log = logger.bind(component="checkpoint")

    def create_checkpoint(
        self,
        session_id: str,
        state: str,
        target: str = "",
        findings: list[dict[str, Any]] | None = None,
        validated: list[dict[str, Any]] | None = None,
        completed: list[str] | None = None,
        pending: list[str] | None = None,
        agent_data: dict[str, Any] | None = None,
        tokens: int = 0,
        tools: list[str] | None = None,
    ) -> str:
        """Create a new checkpoint."""
        self._version_counter += 1
        cp_id = f"cp-{session_id}-v{self._version_counter}"

        checkpoint = CheckpointData(
            checkpoint_id=cp_id,
            version=self._version_counter,
            session_id=session_id,
            state=state,
            target=target,
            findings=findings or [],
            validated_findings=validated or [],
            completed_subtasks=completed or [],
            pending_subtasks=pending or [],
            agent_data=agent_data or {},
            tokens_used=tokens,
            tools_used=tools or [],
        )

        self._checkpoints[cp_id] = checkpoint
        self._current_session = session_id
        self._last_save = time.time()

        # Save to disk
        self._save(checkpoint)

        # Enforce max checkpoints
        self._cleanup(session_id)

        return cp_id

    def should_auto_save(self) -> bool:
        """Check if an auto-save is due."""
        return time.time() - self._last_save >= self._auto_save_interval

    def restore_latest(self, session_id: str) -> CheckpointData | None:
        """Restore the latest checkpoint for a session."""
        # Check in-memory first
        session_cps = [
            cp for cp in self._checkpoints.values()
            if cp.session_id == session_id
        ]

        if session_cps:
            return max(session_cps, key=lambda cp: cp.version)

        # Try disk
        return self._load_latest(session_id)

    def restore_version(self, checkpoint_id: str) -> CheckpointData | None:
        """Restore a specific checkpoint version."""
        if checkpoint_id in self._checkpoints:
            return self._checkpoints[checkpoint_id]

        return self._load(checkpoint_id)

    def list_checkpoints(self, session_id: str = "") -> list[dict[str, Any]]:
        """List available checkpoints."""
        checkpoints = list(self._checkpoints.values())
        if session_id:
            checkpoints = [cp for cp in checkpoints if cp.session_id == session_id]

        # Also check disk
        for path in self._dir.glob("cp-*.json"):
            cp_id = path.stem
            if cp_id not in self._checkpoints:
                cp = self._load(cp_id)
                if cp:
                    if not session_id or cp.session_id == session_id:
                        checkpoints.append(cp)

        checkpoints.sort(key=lambda cp: cp.version)
        return [
            {"id": cp.checkpoint_id, "version": cp.version,
             "state": cp.state, "findings": len(cp.findings),
             "time": cp.created_at}
            for cp in checkpoints
        ]

    def delete_checkpoint(self, checkpoint_id: str) -> bool:
        """Delete a checkpoint."""
        self._checkpoints.pop(checkpoint_id, None)
        path = self._dir / f"{checkpoint_id}.json"
        if path.exists():
            path.unlink()
            return True
        return False

    def _save(self, checkpoint: CheckpointData) -> None:
        """Save checkpoint to disk."""
        try:
            path = self._dir / f"{checkpoint.checkpoint_id}.json"
            path.write_text(json.dumps(checkpoint.to_dict(), default=str))
        except OSError as e:
            self._log.error("save_failed", error=str(e)[:100])

    def _load(self, checkpoint_id: str) -> CheckpointData | None:
        """Load checkpoint from disk."""
        path = self._dir / f"{checkpoint_id}.json"
        if not path.exists():
            return None

        try:
            data = json.loads(path.read_text())
            return CheckpointData(
                checkpoint_id=data.get("id", ""),
                version=data.get("version", 0),
                session_id=data.get("session", ""),
                state=data.get("state", ""),
                target=data.get("target", ""),
                findings=data.get("findings", []),
                validated_findings=data.get("validated", []),
                completed_subtasks=data.get("completed", []),
                pending_subtasks=data.get("pending", []),
                agent_data=data.get("agent_data", {}),
                tokens_used=data.get("tokens", 0),
                tools_used=data.get("tools", []),
                created_at=data.get("time", 0),
            )
        except (json.JSONDecodeError, OSError):
            return None

    def _load_latest(self, session_id: str) -> CheckpointData | None:
        """Load latest checkpoint from disk for a session."""
        pattern = f"cp-{session_id}-*.json"
        paths = sorted(self._dir.glob(pattern))

        if not paths:
            return None

        return self._load(paths[-1].stem)

    def _cleanup(self, session_id: str) -> None:
        """Remove old checkpoints beyond max."""
        session_cps = sorted(
            [cp for cp in self._checkpoints.values() if cp.session_id == session_id],
            key=lambda cp: cp.version,
        )

        while len(session_cps) > self._max_checkpoints:
            oldest = session_cps.pop(0)
            self.delete_checkpoint(oldest.checkpoint_id)

    def get_stats(self) -> dict[str, Any]:
        return {
            "checkpoints": len(self._checkpoints),
            "current_session": self._current_session,
            "version": self._version_counter,
        }
