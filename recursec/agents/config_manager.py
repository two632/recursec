"""Config manager — centralized configuration management for RecurSec.

Implements:
1. YAML/JSON config loading
2. Runtime config updates
3. Config validation
4. Default values with override hierarchy
5. Model configuration management
6. Tool configuration management
7. Agent configuration management
8. Config export and versioning
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class ModelConfig:
    """Configuration for a single LLM model."""
    name: str = ""
    host: str = "127.0.0.1"
    port: int = 8080
    capabilities: list[str] = field(default_factory=list)
    weight: float = 1.0
    context_length: int = 4096
    max_batch: int = 1
    temperature: float = 0.7
    top_p: float = 0.9
    enabled: bool = True
    system_prompt: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "host": self.host, "port": self.port,
            "capabilities": self.capabilities[:5],
            "weight": self.weight, "context": self.context_length,
            "enabled": self.enabled,
        }


@dataclass
class ToolConfig:
    """Configuration for a security tool."""
    name: str = ""
    enabled: bool = True
    command: str = ""
    timeout_s: float = 300.0
    max_concurrent: int = 1
    args: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "enabled": self.enabled,
            "timeout_s": self.timeout_s,
        }


@dataclass
class AgentConfig:
    """Configuration for an agent type."""
    role: str = ""
    enabled: bool = True
    model_hint: str = ""           # Preferred model
    max_tokens: int = 2048
    temperature: float = 0.7
    max_depth: int = 3
    timeout_s: float = 600.0
    system_prompt: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role, "enabled": self.enabled,
            "model": self.model_hint, "depth": self.max_depth,
        }


@dataclass
class RecurSecConfig:
    """Complete RecurSec configuration."""
    version: str = "1.0"
    models: list[ModelConfig] = field(default_factory=list)
    tools: list[ToolConfig] = field(default_factory=list)
    agents: list[AgentConfig] = field(default_factory=list)
    session_token_budget: int = 10_000_000
    max_agents: int = 50
    max_depth: int = 5
    max_time_s: float = 7200.0
    auto_save_interval_s: float = 60.0
    stealth_mode: bool = False
    validate_findings: bool = True
    deep_mode: bool = False
    rate_limit_rpm: int = 60
    log_level: str = "info"
    data_dir: str = "data"

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "models": len(self.models),
            "tools": len(self.tools),
            "agents": len(self.agents),
            "budget": self.session_token_budget,
            "max_time_s": self.max_time_s,
        }


# ── Default Model Configurations ─────────────────────────────

DEFAULT_MODELS: list[dict[str, Any]] = [
    {"name": "whiterabbit", "port": 8100,
     "capabilities": ["security", "exploit", "vuln_analysis"],
     "weight": 2.0, "context_length": 4096},
    {"name": "qwen-coder-14b", "port": 8101,
     "capabilities": ["code", "code_audit", "exploit_dev"],
     "weight": 1.5, "context_length": 8192},
    {"name": "qwen-coder-7b", "port": 8102,
     "capabilities": ["code", "code_audit"],
     "weight": 1.0, "context_length": 8192},
    {"name": "deepseek-r1", "port": 8103,
     "capabilities": ["reasoning", "planning", "analysis"],
     "weight": 1.5, "context_length": 8192},
    {"name": "deepseek-math", "port": 8104,
     "capabilities": ["math", "crypto", "analysis"],
     "weight": 0.8, "context_length": 4096},
    {"name": "hermes-14b", "port": 8105,
     "capabilities": ["general", "reasoning", "planning"],
     "weight": 1.2, "context_length": 4096},
    {"name": "llama-8b", "port": 8106,
     "capabilities": ["general", "reasoning"],
     "weight": 1.0, "context_length": 4096},
    {"name": "dolphin", "port": 8107,
     "capabilities": ["general", "security", "uncensored"],
     "weight": 1.2, "context_length": 4096},
    {"name": "mistral-7b", "port": 8108,
     "capabilities": ["general", "fast", "reasoning"],
     "weight": 1.0, "context_length": 4096},
    {"name": "codellama-13b", "port": 8109,
     "capabilities": ["code", "code_audit"],
     "weight": 1.3, "context_length": 4096},
    {"name": "codellama-7b", "port": 8110,
     "capabilities": ["code", "code_audit", "fast"],
     "weight": 0.8, "context_length": 4096},
    {"name": "yi-9b-200k", "port": 8111,
     "capabilities": ["long_context", "code_audit", "analysis"],
     "weight": 1.0, "context_length": 200000},
    {"name": "phi-3.5-mini", "port": 8112,
     "capabilities": ["fast", "general", "reasoning"],
     "weight": 0.6, "context_length": 4096},
    {"name": "llama-guard", "port": 8113,
     "capabilities": ["safety", "filter"],
     "weight": 0.5, "context_length": 4096},
    {"name": "nomic-embed", "port": 8114,
     "capabilities": ["embedding"],
     "weight": 1.0, "context_length": 2048},
    {"name": "functiongemma", "port": 8115,
     "capabilities": ["function_call", "tool_routing"],
     "weight": 0.5, "context_length": 2048},
]


class ConfigManager:
    """Centralized configuration management.

    Loads, validates, and provides access to all
    RecurSec configuration settings.
    """

    def __init__(self, config_path: str = "configs/recursec.yaml") -> None:
        self._config = RecurSecConfig()
        self._config_path = Path(config_path)
        self._overrides: dict[str, Any] = {}
        self._log = logger.bind(component="config_manager")

        self._init_defaults()

    def _init_defaults(self) -> None:
        """Initialize default configuration."""
        for model_data in DEFAULT_MODELS:
            self._config.models.append(ModelConfig(
                name=model_data["name"],
                port=model_data["port"],
                capabilities=model_data.get("capabilities", []),
                weight=model_data.get("weight", 1.0),
                context_length=model_data.get("context_length", 4096),
            ))

    def load(self, path: str = "") -> bool:
        """Load configuration from file."""
        config_path = Path(path) if path else self._config_path

        if not config_path.exists():
            return False

        try:
            content = config_path.read_text()

            if config_path.suffix in (".yaml", ".yml"):
                # Simple YAML-like parsing (key: value)
                data = {}
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if ":" in line:
                        key, value = line.split(":", 1)
                        data[key.strip()] = value.strip()
                self._apply_data(data)
            else:
                data = json.loads(content)
                self._apply_data(data)

            return True

        except Exception as e:
            self._log.error("config_load_failed", error=str(e)[:100])
            return False

    def _apply_data(self, data: dict[str, Any]) -> None:
        """Apply configuration data."""
        if "session_token_budget" in data:
            self._config.session_token_budget = int(data["session_token_budget"])
        if "max_agents" in data:
            self._config.max_agents = int(data["max_agents"])
        if "max_depth" in data:
            self._config.max_depth = int(data["max_depth"])
        if "max_time_s" in data:
            self._config.max_time_s = float(data["max_time_s"])
        if "stealth_mode" in data:
            self._config.stealth_mode = str(data["stealth_mode"]).lower() == "true"
        if "validate_findings" in data:
            self._config.validate_findings = str(data["validate_findings"]).lower() != "false"
        if "deep_mode" in data:
            self._config.deep_mode = str(data["deep_mode"]).lower() == "true"

    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value."""
        if key in self._overrides:
            return self._overrides[key]
        return getattr(self._config, key, default)

    def set(self, key: str, value: Any) -> None:
        """Set a runtime configuration override."""
        self._overrides[key] = value

    def get_model(self, name: str) -> ModelConfig | None:
        """Get model configuration by name."""
        for model in self._config.models:
            if model.name == name:
                return model
        return None

    def get_models(self, capability: str = "") -> list[ModelConfig]:
        """Get models, optionally filtered by capability."""
        models = [m for m in self._config.models if m.enabled]
        if capability:
            models = [m for m in models if capability in m.capabilities]
        return models

    def add_model(self, model: ModelConfig) -> None:
        """Add a model configuration."""
        # Replace if exists
        self._config.models = [m for m in self._config.models if m.name != model.name]
        self._config.models.append(model)

    def remove_model(self, name: str) -> bool:
        before = len(self._config.models)
        self._config.models = [m for m in self._config.models if m.name != name]
        return len(self._config.models) < before

    def save(self, path: str = "") -> bool:
        """Save configuration to file."""
        config_path = Path(path) if path else self._config_path
        config_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            data = {
                "version": self._config.version,
                "session_token_budget": self._config.session_token_budget,
                "max_agents": self._config.max_agents,
                "max_depth": self._config.max_depth,
                "max_time_s": self._config.max_time_s,
                "stealth_mode": self._config.stealth_mode,
                "validate_findings": self._config.validate_findings,
                "deep_mode": self._config.deep_mode,
                "models": [m.to_dict() for m in self._config.models],
            }
            config_path.write_text(json.dumps(data, indent=2, default=str))
            return True
        except OSError:
            return False

    def validate(self) -> list[str]:
        """Validate configuration."""
        errors = []

        if not self._config.models:
            errors.append("No models configured")

        for model in self._config.models:
            if model.port < 1 or model.port > 65535:
                errors.append(f"Invalid port for {model.name}: {model.port}")

        if self._config.max_depth < 1:
            errors.append("max_depth must be >= 1")

        if self._config.max_time_s < 60:
            errors.append("max_time_s must be >= 60")

        return errors

    @property
    def config(self) -> RecurSecConfig:
        return self._config

    def get_stats(self) -> dict[str, Any]:
        return self._config.to_dict()
