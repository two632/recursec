"""Plugin system — extensible architecture for RecurSec.

Allows loading external plugins for:
- Custom scanners
- Custom tool integrations
- Custom agents
- Custom analyzers
- Custom report formats
- Custom notification channels
"""

from __future__ import annotations

import importlib
import importlib.util
import inspect
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


class PluginType:
    SCANNER = "scanner"
    TOOL = "tool"
    AGENT = "agent"
    ANALYZER = "analyzer"
    REPORTER = "reporter"
    NOTIFIER = "notifier"


@dataclass
class PluginMetadata:
    """Metadata about a loaded plugin."""
    name: str
    version: str = "0.0.1"
    author: str = ""
    description: str = ""
    plugin_type: str = ""
    dependencies: list[str] = field(default_factory=list)
    config_schema: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "version": self.version,
            "author": self.author, "description": self.description,
            "type": self.plugin_type,
        }


class BasePlugin(ABC):
    """Base class for all RecurSec plugins."""

    metadata: PluginMetadata

    @abstractmethod
    async def initialize(self, config: dict[str, Any]) -> None:
        """Initialize the plugin with configuration."""

    @abstractmethod
    async def execute(self, *args: Any, **kwargs: Any) -> Any:
        """Execute the plugin's main functionality."""

    async def cleanup(self) -> None:
        """Cleanup resources."""

    def get_metadata(self) -> PluginMetadata:
        return self.metadata


class ScannerPlugin(BasePlugin):
    """Base class for scanner plugins."""

    @abstractmethod
    async def scan(self, target: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        """Run the scanner against a target."""

    async def execute(self, *args: Any, **kwargs: Any) -> Any:
        target = kwargs.get("target", args[0] if args else "")
        config = kwargs.get("config", {})
        return await self.scan(target, config)


class ToolPlugin(BasePlugin):
    """Base class for tool integration plugins."""

    @abstractmethod
    def is_available(self) -> bool:
        """Check if the tool is installed."""

    @abstractmethod
    async def run(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        """Run the tool."""

    async def execute(self, *args: Any, **kwargs: Any) -> Any:
        return await self.run(*args, **kwargs)


class AgentPlugin(BasePlugin):
    """Base class for agent plugins."""

    @abstractmethod
    async def process_task(self, task: dict[str, Any]) -> dict[str, Any]:
        """Process a task assigned to this agent."""

    async def execute(self, *args: Any, **kwargs: Any) -> Any:
        task = kwargs.get("task", args[0] if args else {})
        return await self.process_task(task)


class AnalyzerPlugin(BasePlugin):
    """Base class for analyzer plugins."""

    @abstractmethod
    async def analyze(self, data: Any, config: dict[str, Any] | None = None) -> dict[str, Any]:
        """Analyze input data."""

    async def execute(self, *args: Any, **kwargs: Any) -> Any:
        data = kwargs.get("data", args[0] if args else None)
        return await self.analyze(data)


class PluginManager:
    """Manages plugin loading, registration, and lifecycle."""

    PLUGIN_BASE_CLASSES = {
        PluginType.SCANNER: ScannerPlugin,
        PluginType.TOOL: ToolPlugin,
        PluginType.AGENT: AgentPlugin,
        PluginType.ANALYZER: AnalyzerPlugin,
    }

    def __init__(self, plugin_dirs: list[str] | None = None) -> None:
        self._plugins: dict[str, BasePlugin] = {}
        self._metadata: dict[str, PluginMetadata] = {}
        self._plugin_dirs = plugin_dirs or []

    def register(self, plugin: BasePlugin) -> None:
        """Register a plugin instance."""
        meta = plugin.get_metadata()
        self._plugins[meta.name] = plugin
        self._metadata[meta.name] = meta
        logger.info("plugin_registered", name=meta.name, type=meta.plugin_type)

    def unregister(self, name: str) -> None:
        """Unregister a plugin."""
        self._plugins.pop(name, None)
        self._metadata.pop(name, None)

    def get_plugin(self, name: str) -> BasePlugin | None:
        """Get a registered plugin by name."""
        return self._plugins.get(name)

    def list_plugins(self, plugin_type: str = "") -> list[PluginMetadata]:
        """List all registered plugins."""
        if plugin_type:
            return [m for m in self._metadata.values() if m.plugin_type == plugin_type]
        return list(self._metadata.values())

    def load_from_directory(self, directory: str) -> int:
        """Load plugins from a directory."""
        loaded = 0
        path = Path(directory)
        if not path.exists():
            return 0

        for py_file in path.glob("*.py"):
            if py_file.name.startswith("_"):
                continue
            try:
                self._load_plugin_file(str(py_file))
                loaded += 1
            except Exception as e:
                logger.warning("plugin_load_failed", file=str(py_file), error=str(e))

        return loaded

    def _load_plugin_file(self, filepath: str) -> None:
        """Load a single plugin file."""
        spec = importlib.util.spec_from_file_location(
            f"recursec_plugin_{Path(filepath).stem}", filepath
        )
        if not spec or not spec.loader:
            return

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        # Find plugin classes in the module
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, BasePlugin) and obj is not BasePlugin:
                for base_type, base_class in self.PLUGIN_BASE_CLASSES.items():
                    if issubclass(obj, base_class) and obj is not base_class:
                        try:
                            instance = obj()
                            self.register(instance)
                        except Exception as e:
                            logger.warning("plugin_init_failed", name=name, error=str(e))

    def load_all(self) -> int:
        """Load plugins from all configured directories."""
        total = 0
        for directory in self._plugin_dirs:
            total += self.load_from_directory(directory)
        return total

    async def initialize_all(self, config: dict[str, Any] | None = None) -> None:
        """Initialize all loaded plugins."""
        for name, plugin in self._plugins.items():
            try:
                await plugin.initialize(config or {})
                logger.info("plugin_initialized", name=name)
            except Exception as e:
                logger.warning("plugin_init_failed", name=name, error=str(e))

    async def cleanup_all(self) -> None:
        """Cleanup all plugins."""
        for name, plugin in self._plugins.items():
            try:
                await plugin.cleanup()
            except Exception as e:
                logger.warning("plugin_cleanup_failed", name=name, error=str(e))
