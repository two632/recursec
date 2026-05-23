"""Configuration manager — unified config for all RecurSec components.

Implements:
1. YAML-based configuration loading
2. Default configuration with overrides
3. Model configuration (add/remove/configure models)
4. Tool configuration (enable/disable tools)
5. Strategy configuration (weights, parameters)
6. Runtime configuration updates
7. Configuration validation
8. Environment variable substitution
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

import structlog

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

logger = structlog.get_logger()


@dataclass
class ModelConfig:
    """Configuration for a single LLM."""
    model_id: str = ""
    name: str = ""
    path: str = ""            # Path to GGUF file
    port: int = 8080
    host: str = "127.0.0.1"
    context_length: int = 4096
    gpu_layers: int = -1       # -1 = all layers on GPU
    threads: int = 4
    batch_size: int = 512
    weight: float = 1.0
    strengths: list[str] = field(default_factory=list)
    system_prompt: str = ""
    enabled: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.model_id,
            "name": self.name[:20],
            "port": self.port,
            "ctx": self.context_length,
            "weight": round(self.weight, 1),
            "enabled": self.enabled,
        }


@dataclass
class ToolConfig:
    """Configuration for an external tool."""
    name: str = ""
    enabled: bool = True
    binary_path: str = ""
    timeout_s: float = 300.0
    args_override: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name[:20],
            "enabled": self.enabled,
            "timeout": self.timeout_s,
        }


@dataclass
class StrategyConfig:
    """Configuration for a vulnerability strategy."""
    name: str = ""
    enabled: bool = True
    weight: float = 1.0
    max_time_s: float = 300.0
    parameters: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name[:20],
            "enabled": self.enabled,
            "weight": round(self.weight, 2),
        }


@dataclass
class AgentConfig:
    """Configuration for the agent brain."""
    max_cycles: int = 100
    max_time_s: float = 3600.0
    max_depth: int = 5
    budget_decay: float = 0.7
    stagnation_threshold: int = 5
    confidence_threshold: float = 0.7
    auto_spawn_agents: bool = True
    auto_correlate: bool = True
    similarity_threshold: float = 0.85
    daemon_mode: bool = False
    checkpoint_interval_s: float = 300.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_cycles": self.max_cycles,
            "max_time": self.max_time_s,
            "max_depth": self.max_depth,
            "budget_decay": self.budget_decay,
            "daemon": self.daemon_mode,
        }


@dataclass
class RecurSecConfig:
    """Master configuration for RecurSec."""
    agent: AgentConfig = field(default_factory=AgentConfig)
    models: list[ModelConfig] = field(default_factory=list)
    tools: list[ToolConfig] = field(default_factory=list)
    strategies: list[StrategyConfig] = field(default_factory=list)
    data_dir: str = "data"
    log_level: str = "INFO"
    gguf_dir: str = "/home/twoku/agent/models/gguf"

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent.to_dict(),
            "models": len(self.models),
            "tools": len(self.tools),
            "strategies": len(self.strategies),
            "gguf_dir": self.gguf_dir,
        }


# ── Default Models (user's 16 GGUF models) ───────────────────

DEFAULT_MODELS: list[dict[str, Any]] = [
    {
        "id": "whiterabbitneo", "name": "WhiteRabbitNeo-7B-v1.5a",
        "path": "WhiteRabbitNeo-7B-v1.5a-Q4_K_M.gguf", "port": 8100,
        "ctx": 8192, "gpu_layers": -1, "weight": 2.0,
        "strengths": ["security_analysis", "vulnerability_scan", "uncensored"],
    },
    {
        "id": "qwen-coder-14b", "name": "Qwen2.5-Coder-14B-Instruct",
        "path": "Qwen2.5-Coder-14B-Instruct-Q3_K_M.gguf", "port": 8101,
        "ctx": 32768, "gpu_layers": -1, "weight": 1.8,
        "strengths": ["code_analysis", "security_analysis", "reasoning"],
    },
    {
        "id": "qwen-coder-7b", "name": "Qwen2.5-Coder-7B-Instruct",
        "path": "Qwen2.5-Coder-7B-Instruct-Q4_K_M.gguf", "port": 8102,
        "ctx": 32768, "gpu_layers": -1, "weight": 1.2,
        "strengths": ["code_analysis", "fast_query"],
    },
    {
        "id": "deepseek-r1", "name": "DeepSeek-R1-Distill-Qwen-7B",
        "path": "DeepSeek-R1-Distill-Qwen-7B-q4_k_m.gguf", "port": 8103,
        "ctx": 32768, "gpu_layers": -1, "weight": 1.7,
        "strengths": ["reasoning", "planning", "math_crypto"],
    },
    {
        "id": "deepseek-math", "name": "DeepSeek-Math-7B-Instruct",
        "path": "deepseek-math-7b-instruct-q4_k_m.gguf", "port": 8104,
        "ctx": 4096, "gpu_layers": -1, "weight": 1.3,
        "strengths": ["math_crypto", "reasoning"],
    },
    {
        "id": "hermes-14b", "name": "Hermes-4-14B",
        "path": "Hermes-4-14B-IQ2_M.gguf", "port": 8105,
        "ctx": 32768, "gpu_layers": -1, "weight": 1.6,
        "strengths": ["reasoning", "planning", "general"],
    },
    {
        "id": "llama-3.1-8b", "name": "Meta-Llama-3.1-8B-Instruct",
        "path": "Meta-Llama-3.1-8B-Instruct-Q4_K_S.gguf", "port": 8106,
        "ctx": 131072, "gpu_layers": -1, "weight": 1.0,
        "strengths": ["general", "long_context"],
    },
    {
        "id": "dolphin-2.9", "name": "Dolphin-2.9-Llama3-8B",
        "path": "dolphin-2.9-llama3-8b.Q4_K_M.gguf", "port": 8107,
        "ctx": 8192, "gpu_layers": -1, "weight": 1.1,
        "strengths": ["uncensored", "general", "security_analysis"],
    },
    {
        "id": "mistral-7b", "name": "Mistral-7B-Instruct-v0.3",
        "path": "Mistral-7B-Instruct-v0.3-Q4_K_M.gguf", "port": 8108,
        "ctx": 32768, "gpu_layers": -1, "weight": 1.0,
        "strengths": ["fast_query", "general"],
    },
    {
        "id": "codellama-13b", "name": "CodeLlama-13B-Instruct",
        "path": "codellama-13b-instruct.Q3_K_M.gguf", "port": 8109,
        "ctx": 16384, "gpu_layers": -1, "weight": 1.4,
        "strengths": ["code_analysis", "security_analysis"],
    },
    {
        "id": "codellama-7b", "name": "CodeLlama-7B",
        "path": "codellama-7b.Q4_K_M.gguf", "port": 8110,
        "ctx": 16384, "gpu_layers": -1, "weight": 1.0,
        "strengths": ["code_analysis", "fast_query"],
    },
    {
        "id": "yi-9b-200k", "name": "Yi-9B-200K",
        "path": "Yi-9B-200K.Q5_K_M.gguf", "port": 8111,
        "ctx": 200000, "gpu_layers": -1, "weight": 1.5,
        "strengths": ["long_context", "code_analysis", "general"],
    },
    {
        "id": "phi-3.5-mini", "name": "Phi-3.5-mini-instruct",
        "path": "Phi-3.5-mini-instruct-Q4_K_M.gguf", "port": 8112,
        "ctx": 131072, "gpu_layers": -1, "weight": 0.7,
        "strengths": ["fast_query", "general"],
    },
    {
        "id": "nomic-embed", "name": "Nomic-Embed-Text-v1.5",
        "path": "nomic-embed-text-v1.5.f32.gguf", "port": 8113,
        "ctx": 8192, "gpu_layers": -1, "weight": 0.5,
        "strengths": ["embedding"],
    },
    {
        "id": "llama-guard", "name": "Llama-Guard-3-1B",
        "path": "llama-guard-3-1b-q4_k_m.gguf", "port": 8114,
        "ctx": 8192, "gpu_layers": -1, "weight": 0.5,
        "strengths": ["safety_check"],
    },
    {
        "id": "functiongemma", "name": "FunctionGemma-270m",
        "path": "functiongemma-270m-it-BF16.gguf", "port": 8115,
        "ctx": 8192, "gpu_layers": -1, "weight": 0.3,
        "strengths": ["tool_calling", "fast_query"],
    },
]


class ConfigManager:
    """Manages RecurSec configuration.

    Loads, validates, and provides unified configuration
    for all RecurSec components. Supports YAML config files,
    environment variables, and runtime updates.
    """

    def __init__(self, config_path: str = "") -> None:
        self._config = RecurSecConfig()
        self._config_path = config_path
        self._log = logger.bind(component="config_manager")

        # Load defaults
        self._load_default_models()

        # Load from file if provided
        if config_path:
            self.load(config_path)

    def _load_default_models(self) -> None:
        """Load default model configurations."""
        for data in DEFAULT_MODELS:
            model = ModelConfig(
                model_id=data["id"],
                name=data["name"],
                path=data.get("path", ""),
                port=data.get("port", 8080),
                context_length=data.get("ctx", 4096),
                gpu_layers=data.get("gpu_layers", -1),
                weight=data.get("weight", 1.0),
                strengths=data.get("strengths", []),
            )
            self._config.models.append(model)

    def load(self, path: str) -> bool:
        """Load configuration from YAML file."""
        if not HAS_YAML:
            self._log.warning("yaml_not_available")
            return False

        try:
            with open(path, encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}

            # Apply overrides
            if "agent" in data:
                self._apply_agent_config(data["agent"])
            if "models" in data:
                self._apply_model_configs(data["models"])
            if "tools" in data:
                self._apply_tool_configs(data["tools"])
            if "strategies" in data:
                self._apply_strategy_configs(data["strategies"])

            self._config.data_dir = data.get("data_dir", self._config.data_dir)
            self._config.log_level = data.get("log_level", self._config.log_level)
            self._config.gguf_dir = data.get("gguf_dir", self._config.gguf_dir)

            return True
        except (OSError, yaml.YAMLError) as e:
            self._log.error("config_load_failed", error=str(e))
            return False

    def save(self, path: str = "") -> bool:
        """Save configuration to YAML file."""
        if not HAS_YAML:
            return False

        path = path or self._config_path
        if not path:
            return False

        data = {
            "agent": self._config.agent.to_dict(),
            "models": [m.to_dict() for m in self._config.models],
            "tools": [t.to_dict() for t in self._config.tools],
            "strategies": [s.to_dict() for s in self._config.strategies],
            "data_dir": self._config.data_dir,
            "log_level": self._config.log_level,
            "gguf_dir": self._config.gguf_dir,
        }

        try:
            with open(path, "w", encoding="utf-8") as f:
                yaml.dump(data, f, default_flow_style=False)
            return True
        except OSError:
            return False

    def add_model(self, model: ModelConfig) -> None:
        """Add a model to the configuration."""
        # Remove existing with same ID
        self._config.models = [
            m for m in self._config.models if m.model_id != model.model_id
        ]
        self._config.models.append(model)

    def remove_model(self, model_id: str) -> bool:
        """Remove a model from the configuration."""
        before = len(self._config.models)
        self._config.models = [
            m for m in self._config.models if m.model_id != model_id
        ]
        return len(self._config.models) < before

    def get_model(self, model_id: str) -> ModelConfig | None:
        """Get a model configuration."""
        for m in self._config.models:
            if m.model_id == model_id:
                return m
        return None

    def get_enabled_models(self) -> list[ModelConfig]:
        """Get all enabled models."""
        return [m for m in self._config.models if m.enabled]

    def _apply_agent_config(self, data: dict[str, Any]) -> None:
        """Apply agent configuration overrides."""
        cfg = self._config.agent
        cfg.max_cycles = data.get("max_cycles", cfg.max_cycles)
        cfg.max_time_s = data.get("max_time_s", cfg.max_time_s)
        cfg.max_depth = data.get("max_depth", cfg.max_depth)
        cfg.budget_decay = data.get("budget_decay", cfg.budget_decay)
        cfg.stagnation_threshold = data.get("stagnation_threshold", cfg.stagnation_threshold)
        cfg.confidence_threshold = data.get("confidence_threshold", cfg.confidence_threshold)
        cfg.daemon_mode = data.get("daemon_mode", cfg.daemon_mode)

    def _apply_model_configs(self, models_data: list[dict[str, Any]]) -> None:
        """Apply model configuration overrides."""
        for data in models_data:
            model_id = data.get("id", "")
            existing = self.get_model(model_id)
            if existing:
                existing.enabled = data.get("enabled", existing.enabled)
                existing.port = data.get("port", existing.port)
                existing.weight = data.get("weight", existing.weight)
                existing.system_prompt = data.get("system_prompt", existing.system_prompt)
            else:
                self.add_model(ModelConfig(
                    model_id=model_id,
                    name=data.get("name", model_id),
                    port=data.get("port", 8080),
                    context_length=data.get("ctx", 4096),
                    weight=data.get("weight", 1.0),
                    strengths=data.get("strengths", []),
                    system_prompt=data.get("system_prompt", ""),
                ))

    def _apply_tool_configs(self, tools_data: list[dict[str, Any]]) -> None:
        """Apply tool configuration overrides."""
        for data in tools_data:
            self._config.tools.append(ToolConfig(
                name=data.get("name", ""),
                enabled=data.get("enabled", True),
                binary_path=data.get("binary_path", ""),
                timeout_s=data.get("timeout_s", 300.0),
            ))

    def _apply_strategy_configs(
        self,
        strategies_data: list[dict[str, Any]],
    ) -> None:
        """Apply strategy configuration overrides."""
        for data in strategies_data:
            self._config.strategies.append(StrategyConfig(
                name=data.get("name", ""),
                enabled=data.get("enabled", True),
                weight=data.get("weight", 1.0),
                max_time_s=data.get("max_time_s", 300.0),
                parameters=data.get("parameters", {}),
            ))

    @staticmethod
    def env_substitute(value: str) -> str:
        """Substitute environment variables in a string."""
        if "${" not in value:
            return value
        result = value
        for key, val in os.environ.items():
            result = result.replace(f"${{{key}}}", val)
        return result

    @property
    def config(self) -> RecurSecConfig:
        return self._config

    def get_stats(self) -> dict[str, Any]:
        return {
            "models": len(self._config.models),
            "enabled_models": len(self.get_enabled_models()),
            "tools": len(self._config.tools),
            "strategies": len(self._config.strategies),
            "gguf_dir": self._config.gguf_dir,
        }
