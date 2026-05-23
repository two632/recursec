"""Notification system — multi-channel alerting for RecurSec findings.

Channels:
- File-based (JSON log files)
- Webhook (generic HTTP POST)
- Slack-compatible webhook
- Discord-compatible webhook
- Email (via local SMTP)
- Syslog
- Desktop notification (via notify-send)
"""

from __future__ import annotations

import asyncio
import json
import shutil
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class Alert:
    """A security alert to be sent."""
    title: str
    message: str
    severity: str = "medium"  # critical, high, medium, low, info
    source: str = ""
    target: str = ""
    finding_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title, "message": self.message,
            "severity": self.severity, "source": self.source,
            "target": self.target, "finding_id": self.finding_id,
            "timestamp": self.timestamp,
        }


class NotificationChannel(ABC):
    """Base class for notification channels."""

    @abstractmethod
    async def send(self, alert: Alert) -> bool:
        """Send an alert. Returns True if successful."""

    @abstractmethod
    def is_configured(self) -> bool:
        """Check if the channel is properly configured."""


class FileChannel(NotificationChannel):
    """File-based notification channel — writes alerts to JSON log files."""

    def __init__(self, log_dir: str = "logs/alerts") -> None:
        self._log_dir = Path(log_dir)
        self._log_dir.mkdir(parents=True, exist_ok=True)

    async def send(self, alert: Alert) -> bool:
        try:
            log_file = self._log_dir / f"alerts_{time.strftime('%Y%m%d')}.jsonl"
            with open(log_file, "a") as f:
                f.write(json.dumps(alert.to_dict()) + "\n")
            return True
        except OSError as e:
            logger.error("file_notification_failed", error=str(e))
            return False

    def is_configured(self) -> bool:
        return self._log_dir.exists()


class WebhookChannel(NotificationChannel):
    """Generic webhook notification channel."""

    def __init__(self, url: str = "", headers: dict[str, str] | None = None) -> None:
        self._url = url
        self._headers = headers or {"Content-Type": "application/json"}

    async def send(self, alert: Alert) -> bool:
        if not self._url:
            return False
        try:
            import httpx
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(self._url, json=alert.to_dict(), headers=self._headers)
                return resp.status_code < 400
        except Exception as e:
            logger.error("webhook_failed", url=self._url, error=str(e))
            return False

    def is_configured(self) -> bool:
        return bool(self._url)


class SlackChannel(NotificationChannel):
    """Slack-compatible webhook channel."""

    SEVERITY_COLORS = {
        "critical": "#FF0000",
        "high": "#FF8800",
        "medium": "#FFCC00",
        "low": "#44BBFF",
        "info": "#88CC44",
    }

    def __init__(self, webhook_url: str = "") -> None:
        self._url = webhook_url

    async def send(self, alert: Alert) -> bool:
        if not self._url:
            return False

        color = self.SEVERITY_COLORS.get(alert.severity, "#808080")
        payload = {
            "attachments": [{
                "color": color,
                "title": f"[{alert.severity.upper()}] {alert.title}",
                "text": alert.message,
                "fields": [
                    {"title": "Source", "value": alert.source, "short": True},
                    {"title": "Target", "value": alert.target, "short": True},
                ],
                "ts": int(alert.timestamp),
            }],
        }

        try:
            import httpx
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(self._url, json=payload)
                return resp.status_code == 200
        except Exception as e:
            logger.error("slack_failed", error=str(e))
            return False

    def is_configured(self) -> bool:
        return bool(self._url)


class DiscordChannel(NotificationChannel):
    """Discord webhook channel."""

    SEVERITY_COLORS = {
        "critical": 0xFF0000,
        "high": 0xFF8800,
        "medium": 0xFFCC00,
        "low": 0x44BBFF,
        "info": 0x88CC44,
    }

    def __init__(self, webhook_url: str = "") -> None:
        self._url = webhook_url

    async def send(self, alert: Alert) -> bool:
        if not self._url:
            return False

        color = self.SEVERITY_COLORS.get(alert.severity, 0x808080)
        payload = {
            "embeds": [{
                "title": f"[{alert.severity.upper()}] {alert.title}",
                "description": alert.message,
                "color": color,
                "fields": [
                    {"name": "Source", "value": alert.source or "N/A", "inline": True},
                    {"name": "Target", "value": alert.target or "N/A", "inline": True},
                ],
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(alert.timestamp)),
            }],
        }

        try:
            import httpx
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(self._url, json=payload)
                return resp.status_code < 300
        except Exception as e:
            logger.error("discord_failed", error=str(e))
            return False

    def is_configured(self) -> bool:
        return bool(self._url)


class SyslogChannel(NotificationChannel):
    """Syslog notification channel."""

    def __init__(self, facility: str = "local0") -> None:
        self._facility = facility
        self._available = shutil.which("logger") is not None

    async def send(self, alert: Alert) -> bool:
        if not self._available:
            return False

        priority = {
            "critical": "crit", "high": "err",
            "medium": "warning", "low": "notice", "info": "info",
        }.get(alert.severity, "info")

        message = f"RecurSec [{alert.severity}] {alert.title}: {alert.message}"
        cmd = ["logger", "-p", f"{self._facility}.{priority}", "-t", "recursec", message[:1000]]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=5.0)
            return proc.returncode == 0
        except (asyncio.TimeoutError, FileNotFoundError):
            return False

    def is_configured(self) -> bool:
        return self._available


class DesktopChannel(NotificationChannel):
    """Desktop notification via notify-send."""

    def __init__(self) -> None:
        self._available = shutil.which("notify-send") is not None

    async def send(self, alert: Alert) -> bool:
        if not self._available:
            return False

        urgency = {"critical": "critical", "high": "critical", "medium": "normal"}.get(
            alert.severity, "low"
        )
        cmd = [
            "notify-send", "-u", urgency,
            f"RecurSec: {alert.title}",
            alert.message[:500],
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=5.0)
            return proc.returncode == 0
        except (asyncio.TimeoutError, FileNotFoundError):
            return False

    def is_configured(self) -> bool:
        return self._available


class NotificationManager:
    """Manages multiple notification channels with severity filtering."""

    def __init__(self) -> None:
        self._channels: dict[str, NotificationChannel] = {}
        self._severity_filter: dict[str, list[str]] = {}  # channel → allowed severities
        self._alert_history: list[Alert] = []
        self._max_history = 1000

    def add_channel(
        self, name: str, channel: NotificationChannel,
        severities: list[str] | None = None,
    ) -> None:
        """Add a notification channel."""
        self._channels[name] = channel
        if severities:
            self._severity_filter[name] = severities

    def remove_channel(self, name: str) -> None:
        self._channels.pop(name, None)
        self._severity_filter.pop(name, None)

    async def send_alert(self, alert: Alert) -> dict[str, bool]:
        """Send alert to all configured channels."""
        results: dict[str, bool] = {}
        self._alert_history.append(alert)
        if len(self._alert_history) > self._max_history:
            self._alert_history = self._alert_history[-self._max_history:]

        for name, channel in self._channels.items():
            if not channel.is_configured():
                results[name] = False
                continue

            # Check severity filter
            allowed = self._severity_filter.get(name)
            if allowed and alert.severity not in allowed:
                continue

            try:
                results[name] = await channel.send(alert)
            except Exception as e:
                logger.error("notification_failed", channel=name, error=str(e))
                results[name] = False

        return results

    async def send_finding_alert(self, finding: dict[str, Any]) -> dict[str, bool]:
        """Send alert for a security finding."""
        alert = Alert(
            title=finding.get("title", "Security Finding"),
            message=finding.get("description", ""),
            severity=finding.get("severity", "medium"),
            source=finding.get("source", ""),
            target=finding.get("target", ""),
            finding_id=finding.get("id", ""),
        )
        return await self.send_alert(alert)

    def get_configured_channels(self) -> list[str]:
        return [name for name, ch in self._channels.items() if ch.is_configured()]

    def get_alert_history(self, limit: int = 50) -> list[dict[str, Any]]:
        return [a.to_dict() for a in self._alert_history[-limit:]]
