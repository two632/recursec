"""Notification engine — alerts and notifications for assessment events.

Implements:
1. Notification channels (console, file, webhook, custom)
2. Severity-based filtering
3. Rate limiting to prevent spam
4. Notification templates
5. Notification history
6. Critical finding alerts
7. Progress notifications
8. Completion notifications
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable

import structlog

logger = structlog.get_logger()


class NotificationLevel(str, Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"
    DEBUG = "debug"


class NotificationChannel(str, Enum):
    CONSOLE = "console"
    FILE = "file"
    WEBHOOK = "webhook"
    CUSTOM = "custom"


@dataclass
class Notification:
    """A notification."""
    notif_id: str = ""
    level: NotificationLevel = NotificationLevel.INFO
    title: str = ""
    message: str = ""
    channel: NotificationChannel = NotificationChannel.CONSOLE
    data: dict[str, Any] = field(default_factory=dict)
    sent_at: float = field(default_factory=time.time)
    delivered: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.notif_id, "level": self.level.value,
            "title": self.title[:60], "channel": self.channel.value,
            "delivered": self.delivered, "time": self.sent_at,
        }


@dataclass
class ChannelConfig:
    """Configuration for a notification channel."""
    channel: NotificationChannel = NotificationChannel.CONSOLE
    enabled: bool = True
    min_level: NotificationLevel = NotificationLevel.INFO
    rate_limit_per_minute: int = 30
    last_sent: float = 0.0
    sent_this_minute: int = 0
    handler: Any = None            # Custom handler callable
    config: dict[str, Any] = field(default_factory=dict)


LEVEL_ORDER = {
    NotificationLevel.DEBUG: 0,
    NotificationLevel.INFO: 1,
    NotificationLevel.WARNING: 2,
    NotificationLevel.CRITICAL: 3,
}


class NotificationEngine:
    """Manages alerts and notifications.

    Routes notifications to appropriate channels
    with rate limiting and severity filtering.
    """

    def __init__(self, log_dir: str = "data/notifications") -> None:
        self._channels: dict[str, ChannelConfig] = {}
        self._history: list[Notification] = []
        self._notif_counter = 0
        self._log_dir = Path(log_dir)
        self._log_dir.mkdir(parents=True, exist_ok=True)
        self._log = logger.bind(component="notification_engine")

        # Setup default channels
        self._channels["console"] = ChannelConfig(
            channel=NotificationChannel.CONSOLE,
            min_level=NotificationLevel.WARNING,
        )
        self._channels["file"] = ChannelConfig(
            channel=NotificationChannel.FILE,
            min_level=NotificationLevel.INFO,
        )

    def notify(
        self,
        title: str,
        message: str = "",
        level: NotificationLevel = NotificationLevel.INFO,
        data: dict[str, Any] | None = None,
    ) -> str:
        """Send a notification to all configured channels."""
        self._notif_counter += 1
        notif_id = f"notif-{self._notif_counter}"

        for channel_name, config in self._channels.items():
            if not config.enabled:
                continue

            # Level filter
            if LEVEL_ORDER.get(level, 0) < LEVEL_ORDER.get(config.min_level, 0):
                continue

            # Rate limit
            if not self._check_rate_limit(config):
                continue

            notif = Notification(
                notif_id=notif_id,
                level=level,
                title=title,
                message=message,
                channel=config.channel,
                data=data or {},
            )

            self._deliver(notif, config)
            self._history.append(notif)

        if len(self._history) > 1000:
            self._history = self._history[-1000:]

        return notif_id

    def notify_finding(self, finding: dict[str, Any]) -> str:
        """Send a notification about a finding."""
        severity = finding.get("severity", "info")
        title = finding.get("title", "New Finding")

        level_map = {
            "critical": NotificationLevel.CRITICAL,
            "high": NotificationLevel.WARNING,
            "medium": NotificationLevel.INFO,
            "low": NotificationLevel.INFO,
            "info": NotificationLevel.DEBUG,
        }

        return self.notify(
            title=f"[{severity.upper()}] {title}",
            message=finding.get("description", ""),
            level=level_map.get(severity, NotificationLevel.INFO),
            data=finding,
        )

    def notify_progress(self, phase: str, percent: float, details: str = "") -> str:
        """Send a progress notification."""
        return self.notify(
            title=f"Progress: {phase} ({percent:.0%})",
            message=details,
            level=NotificationLevel.INFO,
        )

    def notify_completion(self, findings: int, duration_s: float) -> str:
        """Send a completion notification."""
        return self.notify(
            title=f"Assessment Complete: {findings} findings in {duration_s:.0f}s",
            level=NotificationLevel.WARNING,
            data={"findings": findings, "duration_s": duration_s},
        )

    def add_channel(
        self,
        name: str,
        channel: NotificationChannel,
        min_level: NotificationLevel = NotificationLevel.INFO,
        handler: Callable[[Notification], None] | None = None,
        config: dict[str, Any] | None = None,
    ) -> None:
        """Add a notification channel."""
        self._channels[name] = ChannelConfig(
            channel=channel,
            min_level=min_level,
            handler=handler,
            config=config or {},
        )

    def remove_channel(self, name: str) -> bool:
        return self._channels.pop(name, None) is not None

    def _deliver(self, notif: Notification, config: ChannelConfig) -> None:
        """Deliver a notification through a channel."""
        try:
            if config.channel == NotificationChannel.CONSOLE:
                self._log.info(
                    "notification",
                    level=notif.level.value,
                    title=notif.title[:60],
                )

            elif config.channel == NotificationChannel.FILE:
                path = self._log_dir / "notifications.jsonl"
                with open(path, "a") as f:
                    f.write(json.dumps(notif.to_dict(), default=str) + "\n")

            elif config.channel == NotificationChannel.CUSTOM:
                if config.handler:
                    config.handler(notif)

            notif.delivered = True
            config.sent_this_minute += 1

        except Exception as e:
            self._log.error("deliver_failed", error=str(e)[:100])

    def _check_rate_limit(self, config: ChannelConfig) -> bool:
        """Check if channel rate limit allows sending."""
        now = time.time()
        if now - config.last_sent >= 60.0:
            config.sent_this_minute = 0
            config.last_sent = now

        return config.sent_this_minute < config.rate_limit_per_minute

    def get_history(self, limit: int = 50, level: str = "") -> list[dict[str, Any]]:
        history = self._history
        if level:
            try:
                lvl = NotificationLevel(level)
                history = [n for n in history if n.level == lvl]
            except ValueError:
                pass
        return [n.to_dict() for n in history[-limit:]]

    def get_stats(self) -> dict[str, Any]:
        return {
            "channels": len(self._channels),
            "total_sent": len(self._history),
            "delivered": sum(1 for n in self._history if n.delivered),
        }
