"""Settings — configurable settings for RecurSec.

Provides a comprehensive configuration system that supports:
1. YAML/JSON configuration files
2. Environment variable overrides
3. Runtime configuration updates
4. Model configuration (add/remove/configure LLMs)
5. System prompt customization
6. Tool configuration
7. Agent behavior settings
8. Assessment parameters
9. Safety/guardrail settings
10. Logging and output settings

All settings can be changed without restarting the agent.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class ModelConfig:
    """Configuration for a single LLM model."""
    name: str = ""
    model_path: str = ""        # Path to GGUF file
    backend: str = "llama_cpp"  # llama_cpp, vllm, sglang, litellm
    host: str = "127.0.0.1"
    port: int = 8100
    context_length: int = 4096
    max_tokens: int = 2048
    temperature: float = 0.2
    system_prompt: str = ""
    capabilities: list[str] = field(default_factory=list)  # security, code, reasoning, etc
    weight: float = 1.0
    max_concurrent: int = 4
    gpu_layers: int = -1        # -1 = auto
    enabled: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "port": self.port,
            "context": self.context_length,
            "capabilities": self.capabilities[:5],
            "weight": self.weight, "enabled": self.enabled,
        }


@dataclass
class ToolConfig:
    """Configuration for an external tool."""
    name: str = ""
    binary: str = ""
    path: str = ""
    enabled: bool = True
    timeout_s: float = 300.0
    max_concurrent: int = 2
    extra_args: list[str] = field(default_factory=list)
    environment: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "binary": self.binary,
            "enabled": self.enabled, "timeout": self.timeout_s,
        }


@dataclass
class AgentSettings:
    """Settings for agent behavior."""
    max_recursion_depth: int = 4
    max_total_agents: int = 50
    max_agent_steps: int = 100
    max_agent_tokens: int = 50000
    max_agent_time_s: float = 300.0
    default_strategy: str = "adaptive"
    risk_tolerance: float = 0.5
    validate_findings: bool = True
    stealth_mode: bool = False
    auto_refine_plan: bool = True
    max_plan_refinements: int = 3
    convergence_stall_s: float = 120.0
    budget_cascade_factor: float = 0.6

    def to_dict(self) -> dict[str, Any]:
        return {
            "depth": self.max_recursion_depth,
            "agents": self.max_total_agents,
            "steps": self.max_agent_steps,
            "tokens": self.max_agent_tokens,
            "strategy": self.default_strategy,
            "risk": self.risk_tolerance,
            "validate": self.validate_findings,
        }


@dataclass
class SafetySettings:
    """Safety and guardrail settings."""
    safety_model_enabled: bool = True
    safety_model_name: str = "llama-guard"
    check_prompts: bool = True
    check_responses: bool = True
    check_commands: bool = True
    blocked_commands: list[str] = field(default_factory=lambda: [
        "rm -rf /", "mkfs", "dd if=/dev/zero",
        "shutdown", "reboot", "halt",
    ])
    allowed_targets_only: bool = False
    allowed_targets: list[str] = field(default_factory=list)
    max_risk_level: float = 0.8
    require_scope_confirmation: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "safety_model": self.safety_model_enabled,
            "check_prompts": self.check_prompts,
            "check_commands": self.check_commands,
            "max_risk": self.max_risk_level,
        }


@dataclass
class OutputSettings:
    """Output and logging settings."""
    output_format: str = "json"     # json, markdown, terminal, sarif, csv
    output_dir: str = "data/output"
    log_level: str = "info"         # debug, info, warning, error
    log_file: str = "data/logs/recursec.log"
    save_tool_output: bool = True
    save_llm_conversations: bool = False
    verbose: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.output_format,
            "output_dir": self.output_dir,
            "log_level": self.log_level,
            "verbose": self.verbose,
        }


@dataclass
class ServerSettings:
    """Settings for the API/dashboard server."""
    host: str = "127.0.0.1"
    port: int = 8080
    enable_dashboard: bool = True
    enable_api: bool = True
    api_key: str = ""               # Empty = no auth
    cors_origins: list[str] = field(default_factory=lambda: ["*"])

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host, "port": self.port,
            "dashboard": self.enable_dashboard,
            "api": self.enable_api,
        }


class Settings:
    """Main settings manager for RecurSec.

    Loads configuration from YAML/JSON files, environment
    variables, and provides runtime updates.
    """

    def __init__(self, config_path: str = "") -> None:
        self._config_path = config_path or self._find_config()
        self._log = logger.bind(component="settings")

        # Initialize defaults
        self.models: dict[str, ModelConfig] = {}
        self.tools: dict[str, ToolConfig] = {}
        self.agent = AgentSettings()
        self.safety = SafetySettings()
        self.output = OutputSettings()
        self.server = ServerSettings()

        # Load configuration
        self._load_defaults()
        if self._config_path:
            self._load_file(self._config_path)
        self._load_env()

    def _find_config(self) -> str:
        """Find configuration file."""
        candidates = [
            "recursec.yaml", "recursec.yml", "recursec.json",
            "configs/recursec.yaml", "configs/recursec.yml",
            "configs/recursec.json",
        ]
        for candidate in candidates:
            if Path(candidate).exists():
                return candidate
        return ""

    def _load_defaults(self) -> None:
        """Load default model configurations."""
        default_models = [
            {"name": "whiterabbit", "port": 8100, "ctx": 4096,
             "caps": ["security", "exploit", "vuln_analysis"], "weight": 2.0,
             "prompt": "You are WhiteRabbitNeo, a security specialist AI."},
            {"name": "qwen-coder-14b", "port": 8101, "ctx": 32768,
             "caps": ["code", "code_audit", "exploit_dev"], "weight": 1.5,
             "prompt": "You are Qwen Coder, an expert code analysis AI."},
            {"name": "qwen-coder-7b", "port": 8102, "ctx": 32768,
             "caps": ["code", "code_review"], "weight": 1.0},
            {"name": "deepseek-r1", "port": 8103, "ctx": 32768,
             "caps": ["reasoning", "planning", "analysis"], "weight": 1.5,
             "prompt": "You are DeepSeek R1, a reasoning specialist."},
            {"name": "deepseek-math", "port": 8104, "ctx": 4096,
             "caps": ["math", "crypto", "analysis"], "weight": 1.0},
            {"name": "hermes", "port": 8105, "ctx": 4096,
             "caps": ["general", "chat", "instruction"], "weight": 1.2},
            {"name": "llama3", "port": 8106, "ctx": 8192,
             "caps": ["general", "reasoning"], "weight": 1.0},
            {"name": "dolphin", "port": 8107, "ctx": 8192,
             "caps": ["general", "security", "uncensored"], "weight": 1.2},
            {"name": "mistral", "port": 8108, "ctx": 32768,
             "caps": ["general", "fast", "instruction"], "weight": 1.0},
            {"name": "codellama-13b", "port": 8109, "ctx": 16384,
             "caps": ["code", "code_generation"], "weight": 1.2},
            {"name": "codellama-7b", "port": 8110, "ctx": 16384,
             "caps": ["code", "code_generation"], "weight": 0.8},
            {"name": "yi-200k", "port": 8111, "ctx": 200000,
             "caps": ["long_context", "code_audit", "analysis"], "weight": 1.0},
            {"name": "phi35", "port": 8112, "ctx": 4096,
             "caps": ["fast", "small_tasks", "classification"], "weight": 0.7},
            {"name": "llama-guard", "port": 8113, "ctx": 4096,
             "caps": ["safety", "moderation"], "weight": 0.5},
            {"name": "nomic-embed", "port": 8114, "ctx": 8192,
             "caps": ["embedding", "search"], "weight": 0.5},
            {"name": "functiongemma", "port": 8115, "ctx": 2048,
             "caps": ["function_call", "tool_routing"], "weight": 0.5},
        ]

        for m in default_models:
            self.models[m["name"]] = ModelConfig(
                name=m["name"],
                port=m["port"],
                context_length=m.get("ctx", 4096),
                capabilities=m.get("caps", []),
                weight=m.get("weight", 1.0),
                system_prompt=m.get("prompt", ""),
            )

    def _load_file(self, path: str) -> None:
        """Load configuration from a file."""
        file_path = Path(path)
        if not file_path.exists():
            return

        try:
            content = file_path.read_text()

            if path.endswith((".yaml", ".yml")):
                try:
                    import yaml
                    data = yaml.safe_load(content) or {}
                except ImportError:
                    self._log.warning("yaml_not_available")
                    return
            else:
                data = json.loads(content)

            self._apply_config(data)
            self._log.info("config_loaded", path=path)

        except (json.JSONDecodeError, OSError) as e:
            self._log.warning("config_load_failed", path=path, error=str(e))

    def _load_env(self) -> None:
        """Load settings from environment variables."""
        env_map = {
            "RECURSEC_LOG_LEVEL": ("output", "log_level"),
            "RECURSEC_OUTPUT_FORMAT": ("output", "output_format"),
            "RECURSEC_SERVER_HOST": ("server", "host"),
            "RECURSEC_SERVER_PORT": ("server", "port"),
            "RECURSEC_API_KEY": ("server", "api_key"),
            "RECURSEC_MAX_DEPTH": ("agent", "max_recursion_depth"),
            "RECURSEC_MAX_AGENTS": ("agent", "max_total_agents"),
            "RECURSEC_RISK_TOLERANCE": ("agent", "risk_tolerance"),
            "RECURSEC_STEALTH": ("agent", "stealth_mode"),
        }

        for env_key, (section, attr) in env_map.items():
            value = os.environ.get(env_key)
            if value is None:
                continue

            settings_obj = getattr(self, section, None)
            if not settings_obj:
                continue

            current = getattr(settings_obj, attr, None)
            if current is None:
                continue

            if isinstance(current, bool):
                setattr(settings_obj, attr, value.lower() in ("true", "1", "yes"))
            elif isinstance(current, int):
                try:
                    setattr(settings_obj, attr, int(value))
                except ValueError:
                    pass
            elif isinstance(current, float):
                try:
                    setattr(settings_obj, attr, float(value))
                except ValueError:
                    pass
            else:
                setattr(settings_obj, attr, value)

    def _apply_config(self, data: dict[str, Any]) -> None:
        """Apply a config dict to settings."""
        # Models
        for model_data in data.get("models", []):
            name = model_data.get("name", "")
            if not name:
                continue
            if name in self.models:
                model = self.models[name]
            else:
                model = ModelConfig(name=name)
                self.models[name] = model

            for key, value in model_data.items():
                if hasattr(model, key):
                    setattr(model, key, value)

        # Tools
        for tool_data in data.get("tools", []):
            name = tool_data.get("name", "")
            if name:
                self.tools[name] = ToolConfig(**{
                    k: v for k, v in tool_data.items()
                    if hasattr(ToolConfig, k)
                })

        # Agent settings
        agent_data = data.get("agent", {})
        for key, value in agent_data.items():
            if hasattr(self.agent, key):
                setattr(self.agent, key, value)

        # Safety
        safety_data = data.get("safety", {})
        for key, value in safety_data.items():
            if hasattr(self.safety, key):
                setattr(self.safety, key, value)

        # Output
        output_data = data.get("output", {})
        for key, value in output_data.items():
            if hasattr(self.output, key):
                setattr(self.output, key, value)

        # Server
        server_data = data.get("server", {})
        for key, value in server_data.items():
            if hasattr(self.server, key):
                setattr(self.server, key, value)

    # ── Runtime Configuration ────────────────────────────

    def add_model(self, config: ModelConfig) -> None:
        """Add a model at runtime."""
        self.models[config.name] = config
        self._log.info("model_added", name=config.name, port=config.port)

    def remove_model(self, name: str) -> bool:
        """Remove a model."""
        if name in self.models:
            del self.models[name]
            return True
        return False

    def update_model(self, name: str, **kwargs: Any) -> bool:
        """Update a model's settings."""
        model = self.models.get(name)
        if not model:
            return False
        for key, value in kwargs.items():
            if hasattr(model, key):
                setattr(model, key, value)
        return True

    def get_models_by_capability(self, capability: str) -> list[ModelConfig]:
        """Get models with a specific capability."""
        return [
            m for m in self.models.values()
            if m.enabled and capability in m.capabilities
        ]

    def save(self, path: str = "") -> None:
        """Save current settings to file."""
        save_path = Path(path or self._config_path or "recursec.json")
        data = {
            "models": [m.to_dict() for m in self.models.values()],
            "agent": self.agent.to_dict(),
            "safety": self.safety.to_dict(),
            "output": self.output.to_dict(),
            "server": self.server.to_dict(),
        }
        try:
            save_path.write_text(json.dumps(data, indent=2))
            self._log.info("settings_saved", path=str(save_path))
        except OSError as e:
            self._log.warning("save_failed", error=str(e))

    def to_dict(self) -> dict[str, Any]:
        return {
            "models": len(self.models),
            "models_enabled": sum(1 for m in self.models.values() if m.enabled),
            "agent": self.agent.to_dict(),
            "safety": self.safety.to_dict(),
            "output": self.output.to_dict(),
            "server": self.server.to_dict(),
        }
